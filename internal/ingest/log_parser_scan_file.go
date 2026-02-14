package ingest

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/likaia/nginxpulse/internal/enrich"
	"github.com/likaia/nginxpulse/internal/store"
	"github.com/sirupsen/logrus"
)

func (p *LogParser) scanSingleFile(
	websiteID string, logPath string, parserResult *ParserResult) {
	file, err := os.Open(logPath)
	if err != nil {
		logrus.Errorf("无法打开日志文件 %s: %v", logPath, err)
		p.notifyFileIO(websiteID, logPath, "打开日志文件", err)
		return
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		logrus.Errorf("无法获取文件信息 %s: %v", logPath, err)
		p.notifyFileIO(websiteID, logPath, "读取日志文件信息", err)
		return
	}

	currentSize := fileInfo.Size()
	isGzip := isGzipFile(logPath)

	parser, err := p.getLineParser(websiteID)
	if err != nil {
		parserResult.Success = false
		parserResult.Error = err
		p.notifyLogParsing(websiteID, logPath, "日志解析配置", err)
		return
	}

	fileState, ok := p.getFileState(websiteID, logPath)
	if ok && currentSize < fileState.LastSize {
		logrus.Infof("检测到网站 %s 的日志文件 %s 已被轮转，从头开始扫描", websiteID, logPath)
		ok = false
		p.deleteFileState(websiteID, logPath)
	}

	if !ok {
		fileState = FileState{}
		cutoff := time.Now().AddDate(0, 0, -recentLogWindowDays)
		cutoffTs := cutoff.Unix()
		fileState.RecentCutoffTs = cutoffTs

		p.initFileRange(file, parser, fileInfo, isGzip, &fileState)

		if isGzip {
			if fileInfo.ModTime().After(cutoff) || fileInfo.ModTime().Equal(cutoff) {
				if _, err := file.Seek(0, 0); err == nil {
					if gzReader, err := gzip.NewReader(file); err == nil {
						entriesCount, _, minTs, maxTs := p.parseLogLines(
							gzReader, websiteID, "", parserResult, parseWindow{minTs: cutoffTs},
						)
						gzReader.Close()
						p.updateParsedRange(&fileState, minTs, maxTs)
						if maxTs > fileState.LastTimestamp {
							fileState.LastTimestamp = maxTs
						}
						if entriesCount > 0 {
							logrus.Infof("网站 %s 的 gzip 日志文件 %s 扫描完成，解析了 %d 条记录",
								websiteID, logPath, entriesCount)
						}
					} else {
						logrus.Errorf("无法解析 gzip 日志文件 %s: %v", logPath, err)
						p.notifyLogParsing(websiteID, logPath, "解析 gzip 日志文件", err)
					}
				} else {
					logrus.Errorf("无法重置 gzip 文件 %s: %v", logPath, err)
					p.notifyFileIO(websiteID, logPath, "重置 gzip 文件指针", err)
				}
			}

			fileState.LastSize = currentSize
			fileState.LastOffset = 0
			fileState.BackfillOffset = 0
			fileState.BackfillEnd = 0
			fileState.BackfillDone = fileState.FirstTimestamp > 0 && fileState.FirstTimestamp >= cutoffTs
			p.setFileState(websiteID, logPath, fileState)
			return
		}

		recentOffset, lastTs, err := p.findRecentOffset(file, parser, cutoff)
		backfillEnd := recentOffset
		if err != nil {
			logrus.Warnf("计算日志文件 %s 最近窗口失败: %v", logPath, err)
			p.notifyFileIO(websiteID, logPath, "计算日志文件最近窗口", err)
			backfillEnd = currentSize
			recentOffset = 0
		}
		if lastTs > 0 {
			fileState.LastTimestamp = lastTs
		}
		fileState.RecentOffset = recentOffset
		fileState.BackfillOffset = 0
		fileState.BackfillEnd = backfillEnd
		fileState.BackfillDone = err == nil && recentOffset == 0
		fileState.LastOffset = currentSize
		fileState.LastSize = currentSize

		if recentOffset < currentSize {
			if _, err := file.Seek(recentOffset, 0); err != nil {
				logrus.Errorf("无法设置文件读取位置 %s: %v", logPath, err)
				p.notifyFileIO(websiteID, logPath, "设置文件读取位置", err)
			} else {
				entriesCount, _, minTs, maxTs := p.parseLogLines(
					file, websiteID, "", parserResult, parseWindow{minTs: cutoffTs},
				)
				p.updateParsedRange(&fileState, minTs, maxTs)
				if maxTs > fileState.LastTimestamp {
					fileState.LastTimestamp = maxTs
				}
				if entriesCount > 0 {
					logrus.Infof("网站 %s 的日志文件 %s 扫描完成，解析了 %d 条记录",
						websiteID, logPath, entriesCount)
				}
			}
		}

		p.setFileState(websiteID, logPath, fileState)
		return
	}

	startOffset := p.determineStartOffset(websiteID, logPath, currentSize)
	if startOffset < 0 {
		return
	}
	if !isGzip && currentSize <= startOffset {
		return
	}

	var (
		reader io.Reader
		closer io.Closer
	)
	if isGzip {
		if _, err = file.Seek(0, 0); err != nil {
			logrus.Errorf("无法设置文件读取位置 %s: %v", logPath, err)
			p.notifyFileIO(websiteID, logPath, "设置文件读取位置", err)
			return
		}
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			logrus.Errorf("无法解析 gzip 日志文件 %s: %v", logPath, err)
			p.notifyLogParsing(websiteID, logPath, "解析 gzip 日志文件", err)
			return
		}
		if startOffset > 0 {
			if err := skipReaderBytes(gzReader, startOffset); err != nil {
				logrus.Warnf("跳过 gzip 历史内容失败，将重新解析文件 %s: %v", logPath, err)
				gzReader.Close()
				if _, err := file.Seek(0, 0); err != nil {
					logrus.Errorf("无法重置 gzip 文件 %s: %v", logPath, err)
					p.notifyFileIO(websiteID, logPath, "重置 gzip 文件指针", err)
					return
				}
				gzReader, err = gzip.NewReader(file)
				if err != nil {
					logrus.Errorf("无法重新解析 gzip 日志文件 %s: %v", logPath, err)
					p.notifyLogParsing(websiteID, logPath, "重新解析 gzip 日志文件", err)
					return
				}
				startOffset = 0
			}
		}
		reader = gzReader
		closer = gzReader
	} else {
		if _, err = file.Seek(startOffset, 0); err != nil {
			logrus.Errorf("无法设置文件读取位置 %s: %v", logPath, err)
			p.notifyFileIO(websiteID, logPath, "设置文件读取位置", err)
			return
		}
		reader = file
	}

	entriesCount, bytesRead, minTs, maxTs := p.parseLogLines(reader, websiteID, "", parserResult, parseWindow{})
	if closer != nil {
		closer.Close()
	}

	if isGzip {
		fileState.LastOffset = startOffset + bytesRead
	} else {
		fileState.LastOffset = currentSize
	}
	fileState.LastSize = currentSize
	p.updateParsedRange(&fileState, minTs, maxTs)
	if maxTs > fileState.LastTimestamp {
		fileState.LastTimestamp = maxTs
	}

	p.setFileState(websiteID, logPath, fileState)

	if entriesCount > 0 {
		logrus.Infof("网站 %s 的日志文件 %s 扫描完成，解析了 %d 条记录",
			websiteID, logPath, entriesCount)
	}
}

// determineStartOffset 确定扫描起始位置
func (p *LogParser) determineStartOffset(
	websiteID string, filePath string, currentSize int64) int64 {

	state, ok := p.states[websiteID]
	if !ok { // 网站没有扫描记录，创建新状态
		p.states[websiteID] = LogScanState{
			Files: make(map[string]FileState),
		}
		return 0
	}

	if state.Files == nil {
		state.Files = make(map[string]FileState)
		p.states[websiteID] = state
		return 0
	}

	normalizedPath := normalizeLogPath(filePath)
	fileState, ok := state.Files[normalizedPath]
	if !ok {
		return 0
	}

	// 文件是否被轮转
	if currentSize < fileState.LastSize {
		logrus.Infof("检测到网站 %s 的日志文件 %s 已被轮转，从头开始扫描", websiteID, filePath)
		return 0
	}

	if isGzipFile(filePath) {
		if currentSize == fileState.LastSize {
			return -1
		}
		return fileState.LastOffset
	}

	return fileState.LastOffset
}

func (p *LogParser) initFileRange(
	file *os.File,
	parser *logLineParser,
	info os.FileInfo,
	isGzip bool,
	state *FileState,
) {
	if state.FirstTimestamp == 0 {
		if firstTs, err := p.readFirstTimestamp(file, parser, isGzip); err == nil {
			state.FirstTimestamp = firstTs
		}
	}
	if state.LastTimestamp == 0 {
		state.LastTimestamp = info.ModTime().Unix()
	}
}

func (p *LogParser) updateParsedRange(state *FileState, minTs, maxTs int64) {
	if minTs > 0 && (state.ParsedMinTs == 0 || minTs < state.ParsedMinTs) {
		state.ParsedMinTs = minTs
	}
	if maxTs > 0 && maxTs > state.ParsedMaxTs {
		state.ParsedMaxTs = maxTs
	}
	if state.FirstTimestamp == 0 || (minTs > 0 && minTs < state.FirstTimestamp) {
		state.FirstTimestamp = minTs
	}
	if maxTs > 0 && maxTs > state.LastTimestamp {
		state.LastTimestamp = maxTs
	}
}

func (p *LogParser) readFirstTimestamp(
	file *os.File,
	parser *logLineParser,
	isGzip bool,
) (int64, error) {
	if _, err := file.Seek(0, 0); err != nil {
		return 0, err
	}

	var reader io.Reader = file
	var closer io.Closer
	if isGzip {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return 0, err
		}
		reader = gzReader
		closer = gzReader
	}

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		ts, err := p.parseLogTimestamp(parser, line)
		if err == nil {
			if closer != nil {
				closer.Close()
			}
			return ts.Unix(), nil
		}
	}

	if closer != nil {
		closer.Close()
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, errors.New("未找到有效的日志时间")
}

func (p *LogParser) findRecentOffset(
	file *os.File,
	parser *logLineParser,
	cutoff time.Time,
) (int64, int64, error) {
	info, err := file.Stat()
	if err != nil {
		return 0, 0, err
	}
	size := info.Size()
	if size == 0 {
		return 0, 0, nil
	}

	var (
		offset  = size
		carry   []byte
		lastTs  int64
		started bool
	)

	for offset > 0 {
		readSize := int64(recentScanChunkSize)
		if offset < readSize {
			readSize = offset
		}
		offset -= readSize

		buf := make([]byte, readSize)
		if _, err := file.ReadAt(buf, offset); err != nil && err != io.EOF {
			return 0, lastTs, err
		}

		data := append(buf, carry...)
		start := 0
		if offset > 0 {
			if idx := bytes.IndexByte(data, '\n'); idx >= 0 {
				carry = append([]byte{}, data[:idx]...)
				start = idx + 1
			} else {
				carry = append([]byte{}, data...)
				continue
			}
		} else {
			carry = nil
		}

		end := len(data)
		for end > start {
			lineEnd := end
			idx := bytes.LastIndexByte(data[start:end], '\n')
			lineStart := start
			if idx >= 0 {
				lineStart = start + idx + 1
				end = start + idx
			} else {
				end = start
			}
			line := bytes.TrimRight(data[lineStart:lineEnd], "\r")
			if len(line) == 0 {
				continue
			}
			ts, err := p.parseLogTimestamp(parser, string(line))
			if err != nil {
				continue
			}
			if !started {
				lastTs = ts.Unix()
				started = true
			}
			if ts.Before(cutoff) {
				nextOffset := offset + int64(lineEnd)
				if lineEnd < len(data) && data[lineEnd] == '\n' {
					nextOffset++
				}
				if nextOffset > size {
					nextOffset = size
				}
				return nextOffset, lastTs, nil
			}
		}
		if offset == 0 {
			break
		}
	}

	return 0, lastTs, nil
}

// parseLogLines 解析日志行并返回解析的记录数
func (p *LogParser) parseLogLines(
	reader io.Reader, websiteID, sourceID string, parserResult *ParserResult, window parseWindow) (int, int64, int64, int64) {
	scanner := bufio.NewScanner(reader)
	entriesCount := 0
	var minTs int64
	var maxTs int64
	parsedBuckets := make(map[int64]struct{})
	var whitelistHits map[string]*whitelistHit
	var batchWhitelistHits map[string]*whitelistHit

	// 批量插入相关
	batch := make([]store.NginxLogRecord, 0, p.parseBatchSize)

	// 处理一批数据
	processBatch := func() {
		if len(batch) == 0 {
			return
		}

		// 先把本批次 location 标记为“待解析”，确保日志落库后前端可见；
		// 再在日志成功落库后写入 ip_geo_pending，避免“先入队、后落库”导致回填命中空 ip_id 后把队列误删。
		p.markBatchIPGeoPending(batch)
		if err := p.repo.BatchInsertLogsForWebsite(websiteID, batch); err != nil {
			logrus.Errorf("批量插入网站 %s 的日志记录失败: %v", websiteID, err)
			p.notifyDatabaseWrite(websiteID, "写入日志批次", err)
		} else {
			p.enqueueBatchIPGeo(batch)
			whitelistHits = mergeWhitelistHits(whitelistHits, batchWhitelistHits)
		}

		batch = batch[:0] // 清空批次但保留容量
		batchWhitelistHits = nil
	}

	// 逐行处理
	const progressChunk = int64(64 * 1024)
	var pendingBytes int64
	var totalBytes int64
	for scanner.Scan() {
		line := scanner.Text()
		lineBytes := int64(len(line) + 1)
		pendingBytes += lineBytes
		totalBytes += lineBytes
		if pendingBytes >= progressChunk {
			addParsingProgress(pendingBytes)
			pendingBytes = 0
		}

		entry, err := p.parseLogLine(websiteID, sourceID, line)
		if err != nil {
			continue
		}
		ts := entry.Timestamp.Unix()
		if !window.allows(ts) {
			continue
		}
		if matcher := p.whitelistMatchers[websiteID]; matcher != nil && matcher.Enabled() {
			if match, ok := matcher.Match(entry.IP); ok {
				batchWhitelistHits = p.recordWhitelistHit(websiteID, *entry, match, batchWhitelistHits)
			}
		}
		batch = append(batch, *entry)
		bucket := (ts / 3600) * 3600
		parsedBuckets[bucket] = struct{}{}
		if minTs == 0 || ts < minTs {
			minTs = ts
		}
		if ts > maxTs {
			maxTs = ts
		}
		entriesCount++
		parserResult.TotalEntries++ // 累加到总结果中，而非赋值

		if len(batch) >= p.parseBatchSize {
			processBatch()
		}
	}

	processBatch() // 处理剩余的记录
	if pendingBytes > 0 {
		addParsingProgress(pendingBytes)
	}

	if err := scanner.Err(); err != nil {
		logrus.Errorf("扫描网站 %s 的文件时出错: %v", websiteID, err)
		p.notifyLogParsing(websiteID, "", "扫描日志文件", err)
	}
	p.flushWhitelistHits(whitelistHits)

	p.recordParsedHourBuckets(websiteID, parsedBuckets)
	return entriesCount, totalBytes, minTs, maxTs // 返回当前文件的日志条数
}

// IngestLines parses and inserts streamed log lines for a website/source.
func (p *LogParser) IngestLines(websiteID, sourceID string, lines []string) (int, int, error) {
	if websiteID == "" {
		return 0, 0, errors.New("websiteID 不能为空")
	}
	if len(lines) == 0 {
		return 0, 0, nil
	}
	if _, err := p.getLineParserForSource(websiteID, sourceID); err != nil {
		return 0, 0, err
	}

	batch := make([]store.NginxLogRecord, 0, p.parseBatchSize)
	accepted := 0
	deduped := 0
	var minTs int64
	var maxTs int64
	parsedBuckets := make(map[int64]struct{})
	var whitelistHits map[string]*whitelistHit
	var batchWhitelistHits map[string]*whitelistHit

	processBatch := func() error {
		if len(batch) == 0 {
			return nil
		}
		// 先标记 location 为“待解析”，再在成功落库后写入 ip_geo_pending（避免竞态导致“待解析”长期不变）
		p.markBatchIPGeoPending(batch)
		if err := p.repo.BatchInsertLogsForWebsite(websiteID, batch); err != nil {
			p.notifyDatabaseWrite(websiteID, "写入日志批次", err)
			return err
		}
		p.enqueueBatchIPGeo(batch)
		whitelistHits = mergeWhitelistHits(whitelistHits, batchWhitelistHits)
		batch = batch[:0]
		batchWhitelistHits = nil
		return nil
	}

	for _, line := range lines {
		entry, err := p.parseLogLine(websiteID, sourceID, line)
		if err != nil {
			continue
		}
		key := buildDedupKey(websiteID, sourceID, line)
		if p.dedup != nil && p.dedup.Seen(key) {
			deduped++
			continue
		}
		if matcher := p.whitelistMatchers[websiteID]; matcher != nil && matcher.Enabled() {
			if match, ok := matcher.Match(entry.IP); ok {
				batchWhitelistHits = p.recordWhitelistHit(websiteID, *entry, match, batchWhitelistHits)
			}
		}
		batch = append(batch, *entry)
		accepted++
		ts := entry.Timestamp.Unix()
		bucket := (ts / 3600) * 3600
		parsedBuckets[bucket] = struct{}{}
		if minTs == 0 || ts < minTs {
			minTs = ts
		}
		if ts > maxTs {
			maxTs = ts
		}

		if len(batch) >= p.parseBatchSize {
			if err := processBatch(); err != nil {
				return accepted, deduped, err
			}
		}
	}

	if err := processBatch(); err != nil {
		return accepted, deduped, err
	}
	p.flushWhitelistHits(whitelistHits)

	if accepted > 0 {
		p.recordParsedHourBuckets(websiteID, parsedBuckets)
		targetKey := buildTargetStateKey(sourceID, "stream")
		state, _ := p.getTargetState(websiteID, targetKey)
		if state.RecentCutoffTs == 0 {
			state.RecentCutoffTs = time.Now().AddDate(0, 0, -recentLogWindowDays).Unix()
		}
		updateTargetParsedRange(&state, minTs, maxTs)
		state.BackfillDone = true
		p.setTargetState(websiteID, targetKey, state)
		p.refreshWebsiteRanges(websiteID)
		p.updateState()
	}

	return accepted, deduped, nil
}

func buildDedupKey(websiteID, sourceID, line string) string {
	hash := sha1.Sum([]byte(line))
	if sourceID == "" {
		return fmt.Sprintf("%s:%x", websiteID, hash[:])
	}
	return fmt.Sprintf("%s:%s:%x", websiteID, sourceID, hash[:])
}

// markBatchIPGeoPending mutates the batch in-place to mark locations as "待解析"/"未知".
// 注意：该操作必须发生在日志入库之前，否则日志不会以“待解析”维度写入。
func (p *LogParser) markBatchIPGeoPending(batch []store.NginxLogRecord) {
	if len(batch) == 0 {
		return
	}
	for i := range batch {
		ip := strings.TrimSpace(batch[i].IP)
		if ip == "" {
			batch[i].DomesticLocation = "未知"
			batch[i].GlobalLocation = "未知"
			continue
		}
		batch[i].DomesticLocation = pendingLocationLabel
		batch[i].GlobalLocation = pendingLocationLabel
	}
}

// enqueueBatchIPGeo writes unique IPs from the batch into ip_geo_pending.
// 注意：该操作应在日志成功落库之后再执行，避免“先入队、后落库”导致回填命中空结果并清理 pending，进而让日志长期停留在“待解析”。
func (p *LogParser) enqueueBatchIPGeo(batch []store.NginxLogRecord) {
	if len(batch) == 0 || p.repo == nil || p.demoMode {
		return
	}
	unique := make([]string, 0, len(batch))
	seen := make(map[string]struct{}, len(batch))
	for _, entry := range batch {
		ip := strings.TrimSpace(entry.IP)
		if ip == "" {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		unique = append(unique, ip)
	}
	if len(unique) == 0 {
		return
	}

	cached := make(map[string]store.IPGeoCacheEntry)
	if entries, err := p.repo.GetIPGeoCache(unique); err != nil {
		logrus.WithError(err).Warn("读取 IP 归属地缓存失败")
	} else if len(entries) > 0 {
		unknownCached := make([]string, 0)
		for ip, entry := range entries {
			if entry.Domestic == "未知" && entry.Global == "未知" {
				unknownCached = append(unknownCached, ip)
				continue
			}
			cached[ip] = entry
		}
		if len(unknownCached) > 0 {
			if err := p.repo.DeleteIPGeoCache(unknownCached); err != nil {
				logrus.WithError(err).Warn("清理未知 IP 归属地缓存失败")
			}
			enrich.DeleteIPGeoCacheEntries(unknownCached)
		}
		if len(cached) > 0 {
			if err := p.repo.UpdateIPGeoLocations(cached, pendingLocationLabel); err != nil {
				logrus.WithError(err).Warn("回填缓存中的 IP 归属地失败")
			}
		}
	}

	missing := make([]string, 0, len(unique))
	for _, ip := range unique {
		if _, ok := cached[ip]; ok {
			continue
		}
		missing = append(missing, ip)
	}
	if len(missing) == 0 {
		return
	}

	if err := p.repo.UpsertIPGeoPending(missing); err != nil {
		logrus.WithError(err).Warn("写入 IP 归属地待解析队列失败")
	}
}
