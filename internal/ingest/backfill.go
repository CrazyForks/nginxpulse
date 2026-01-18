package ingest

import (
	"bufio"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"github.com/likaia/nginxpulse/internal/config"
	"github.com/likaia/nginxpulse/internal/store"
	"github.com/sirupsen/logrus"
)

type BackfillResult struct {
	ProcessedBytes   int64
	ProcessedEntries int
	CompletedFiles   int
}

type backfillBudget struct {
	deadline       time.Time
	hasDeadline    bool
	remainingBytes int64
	hasBytes       bool
}

func newBackfillBudget(maxDuration time.Duration, maxBytes int64) *backfillBudget {
	budget := &backfillBudget{}
	if maxDuration > 0 {
		budget.deadline = time.Now().Add(maxDuration)
		budget.hasDeadline = true
	}
	if maxBytes > 0 {
		budget.remainingBytes = maxBytes
		budget.hasBytes = true
	}
	return budget
}

func (b *backfillBudget) exhausted() bool {
	if b.hasDeadline && time.Now().After(b.deadline) {
		return true
	}
	if b.hasBytes && b.remainingBytes <= 0 {
		return true
	}
	return false
}

func (b *backfillBudget) consume(bytes int64) {
	if b.hasBytes {
		b.remainingBytes -= bytes
	}
}

func (p *LogParser) BackfillHistory(maxDuration time.Duration, maxBytes int64) BackfillResult {
	result := BackfillResult{}
	if p.demoMode {
		return result
	}
	if maxDuration <= 0 && maxBytes <= 0 {
		return result
	}
	if !startBackfillParsing() {
		return result
	}
	defer finishBackfillParsing()

	budget := newBackfillBudget(maxDuration, maxBytes)
	websiteIDs := config.GetAllWebsiteIDs()

	for _, websiteID := range websiteIDs {
		state, ok := p.states[websiteID]
		if !ok || state.Files == nil {
			continue
		}

		for filePath, fileState := range state.Files {
			if budget.exhausted() {
				break
			}
			if fileState.BackfillDone {
				continue
			}

			if isGzipFile(filePath) {
				processed, entries, err := p.backfillGzipFile(websiteID, filePath, &fileState, budget)
				if err != nil {
					logrus.Warnf("回填 gzip 日志文件 %s 失败: %v", filePath, err)
				} else {
					result.ProcessedBytes += processed
					result.ProcessedEntries += entries
					result.CompletedFiles++
				}
				p.setFileState(websiteID, filePath, fileState)
				continue
			}

			processed, entries, err := p.backfillPlainFile(websiteID, filePath, &fileState, budget)
			if err != nil {
				if !errors.Is(err, io.EOF) {
					logrus.Warnf("回填日志文件 %s 失败: %v", filePath, err)
				}
			}
			result.ProcessedBytes += processed
			result.ProcessedEntries += entries
			if fileState.BackfillDone {
				result.CompletedFiles++
			}
			p.setFileState(websiteID, filePath, fileState)
		}

		p.refreshWebsiteRanges(websiteID)
		if budget.exhausted() {
			break
		}
	}

	p.updateState()
	return result
}

func (p *LogParser) backfillPlainFile(
	websiteID, filePath string,
	state *FileState,
	budget *backfillBudget,
) (int64, int, error) {
	if state.BackfillEnd <= state.BackfillOffset || state.BackfillEnd == 0 {
		state.BackfillDone = true
		return 0, 0, nil
	}

	file, err := os.Open(filePath)
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()

	sectionLen := state.BackfillEnd - state.BackfillOffset
	reader := io.NewSectionReader(file, state.BackfillOffset, sectionLen)
	bufReader := bufio.NewReader(reader)

	cutoffTs := state.RecentCutoffTs
	if cutoffTs == 0 {
		cutoffTs = time.Now().AddDate(0, 0, -recentLogWindowDays).Unix()
	}
	window := parseWindow{maxTs: cutoffTs}

	batch := make([]store.NginxLogRecord, 0, backfillBatchSize)
	processBatch := func() {
		if len(batch) == 0 {
			return
		}
		p.fillBatchLocations(batch)
		if err := p.repo.BatchInsertLogsForWebsite(websiteID, batch); err != nil {
			logrus.Errorf("批量插入网站 %s 的日志记录失败: %v", websiteID, err)
		}
		batch = batch[:0]
	}

	var (
		bytesRead  int64
		entryCount int
		minTs      int64
		maxTs      int64
	)

	for {
		if budget.exhausted() {
			break
		}
		line, err := bufReader.ReadString('\n')
		if len(line) == 0 && err != nil {
			if err == io.EOF {
				state.BackfillDone = true
			}
			processBatch()
			state.BackfillOffset += bytesRead
			p.updateParsedRange(state, minTs, maxTs)
			return bytesRead, entryCount, err
		}
		bytesRead += int64(len(line))
		budget.consume(int64(len(line)))

		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			if err != nil {
				continue
			}
			continue
		}

		entry, parseErr := p.parseLogLine(websiteID, line)
		if parseErr != nil {
			if err != nil {
				continue
			}
			continue
		}
		ts := entry.Timestamp.Unix()
		if !window.allows(ts) {
			if err != nil {
				continue
			}
			continue
		}
		batch = append(batch, *entry)
		if minTs == 0 || ts < minTs {
			minTs = ts
		}
		if ts > maxTs {
			maxTs = ts
		}
		entryCount++

		if len(batch) >= backfillBatchSize {
			processBatch()
		}

		if err != nil {
			if err == io.EOF {
				state.BackfillDone = true
			}
			break
		}
	}

	processBatch()
	state.BackfillOffset += bytesRead
	if state.BackfillOffset >= state.BackfillEnd {
		state.BackfillDone = true
	}
	p.updateParsedRange(state, minTs, maxTs)
	return bytesRead, entryCount, nil
}

func (p *LogParser) backfillGzipFile(
	websiteID, filePath string,
	state *FileState,
	budget *backfillBudget,
) (int64, int, error) {
	if budget.exhausted() {
		return 0, 0, nil
	}

	info, err := os.Stat(filePath)
	if err != nil {
		return 0, 0, err
	}
	if budget.hasBytes && info.Size() > budget.remainingBytes {
		return 0, 0, nil
	}

	file, err := os.Open(filePath)
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return 0, 0, err
	}
	defer gzReader.Close()

	cutoffTs := state.RecentCutoffTs
	if cutoffTs == 0 {
		cutoffTs = time.Now().AddDate(0, 0, -recentLogWindowDays).Unix()
	}
	window := parseWindow{maxTs: cutoffTs}

	parserResult := EmptyParserResult("", "")
	entriesCount, bytesRead, minTs, maxTs := p.parseLogLines(gzReader, websiteID, &parserResult, window)
	budget.consume(bytesRead)
	state.BackfillDone = true
	p.updateParsedRange(state, minTs, maxTs)
	if maxTs > state.LastTimestamp {
		state.LastTimestamp = maxTs
	}

	return bytesRead, entriesCount, nil
}
