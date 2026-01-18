package ingest

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/likaia/nginxpulse/internal/config"
	"github.com/likaia/nginxpulse/internal/enrich"
	"github.com/likaia/nginxpulse/internal/store"
	"github.com/sirupsen/logrus"
)

var (
	defaultNginxLogRegex = `^(?P<ip>\S+) - (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<url>[^"]+) HTTP/\d\.\d" (?P<status>\d+) (?P<bytes>\d+) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"`
	lastCleanupDate      = ""
	parsingMu            sync.RWMutex
	parsingMode          parseMode
)

const defaultNginxTimeLayout = "02/Jan/2006:15:04:05 -0700"

const (
	parseTypeRegex     = "regex"
	parseTypeCaddyJSON = "caddy_json"
)

const (
	recentLogWindowDays = 7
	recentScanChunkSize = 256 * 1024
	backfillBatchSize   = 100
)

var (
	ipAliases        = []string{"ip", "remote_addr", "client_ip"}
	timeAliases      = []string{"time", "time_local", "time_iso8601"}
	methodAliases    = []string{"method", "request_method"}
	urlAliases       = []string{"url", "request_uri", "uri", "path"}
	statusAliases    = []string{"status"}
	bytesAliases     = []string{"bytes", "body_bytes_sent", "bytes_sent"}
	refererAliases   = []string{"referer", "http_referer"}
	userAgentAliases = []string{"ua", "user_agent", "http_user_agent"}
	requestAliases   = []string{"request", "request_line"}
)

var ErrParsingInProgress = errors.New("日志解析中，请稍后重试")

// 解析结果
type ParserResult struct {
	WebName      string
	WebID        string
	TotalEntries int
	Duration     time.Duration
	Success      bool
	Error        error
}

type LogScanState struct {
	Files           map[string]FileState `json:"files"` // 每个文件的状态
	ParsedMinTs     int64                `json:"parsed_min_ts,omitempty"`
	ParsedMaxTs     int64                `json:"parsed_max_ts,omitempty"`
	LogMinTs        int64                `json:"log_min_ts,omitempty"`
	LogMaxTs        int64                `json:"log_max_ts,omitempty"`
	RecentCutoffTs  int64                `json:"recent_cutoff_ts,omitempty"`
	BackfillPending bool                 `json:"backfill_pending,omitempty"`
}

type FileState struct {
	LastOffset     int64 `json:"last_offset"`
	LastSize       int64 `json:"last_size"`
	RecentOffset   int64 `json:"recent_offset,omitempty"`
	BackfillOffset int64 `json:"backfill_offset,omitempty"`
	BackfillEnd    int64 `json:"backfill_end,omitempty"`
	BackfillDone   bool  `json:"backfill_done,omitempty"`
	FirstTimestamp int64 `json:"first_ts,omitempty"`
	LastTimestamp  int64 `json:"last_ts,omitempty"`
	ParsedMinTs    int64 `json:"parsed_min_ts,omitempty"`
	ParsedMaxTs    int64 `json:"parsed_max_ts,omitempty"`
	RecentCutoffTs int64 `json:"recent_cutoff_ts,omitempty"`
}

type parseMode int

const (
	parseModeNone parseMode = iota
	parseModeForeground
	parseModeBackfill
)

type parseWindow struct {
	minTs int64
	maxTs int64
}

func (w parseWindow) allows(ts int64) bool {
	if w.minTs > 0 && ts < w.minTs {
		return false
	}
	if w.maxTs > 0 && ts >= w.maxTs {
		return false
	}
	return true
}

type logLineParser struct {
	regex      *regexp.Regexp
	indexMap   map[string]int
	timeLayout string
	source     string
	parseType  string
}

type LogParser struct {
	repo          *store.Repository
	statePath     string
	states        map[string]LogScanState // 各网站的扫描状态，以网站ID为键
	demoMode      bool
	retentionDays int
	lineParsers   map[string]*logLineParser
}

// NewLogParser 创建新的日志解析器
func NewLogParser(userRepoPtr *store.Repository) *LogParser {
	statePath := filepath.Join(config.DataDir, "nginx_scan_state.json")
	cfg := config.ReadConfig()
	retentionDays := cfg.System.LogRetentionDays
	if retentionDays <= 0 {
		retentionDays = 30
	}
	parser := &LogParser{
		repo:          userRepoPtr,
		statePath:     statePath,
		states:        make(map[string]LogScanState),
		demoMode:      cfg.System.DemoMode,
		retentionDays: retentionDays,
		lineParsers:   make(map[string]*logLineParser),
	}
	parser.loadState()
	enrich.InitPVFilters()
	return parser
}

// loadState 加载上次扫描状态
func (p *LogParser) loadState() {
	data, err := os.ReadFile(p.statePath)
	if os.IsNotExist(err) {
		// 状态文件不存在，创建空状态映射
		p.states = make(map[string]LogScanState)
		return
	}

	if err != nil {
		logrus.Errorf("无法读取扫描状态文件: %v", err)
		p.states = make(map[string]LogScanState)
		return
	}

	if err := json.Unmarshal(data, &p.states); err != nil {
		logrus.Errorf("解析扫描状态失败: %v", err)
		p.states = make(map[string]LogScanState)
	}

	for websiteID := range p.states {
		p.refreshWebsiteRanges(websiteID)
	}
}

// updateState 更新并保存状态
func (p *LogParser) updateState() {
	data, err := json.Marshal(p.states)
	if err != nil {
		logrus.Errorf("保存扫描状态失败: %v", err)
		return
	}

	if err := os.WriteFile(p.statePath, data, 0644); err != nil {
		logrus.Errorf("保存扫描状态失败: %v", err)
	}
}

func (p *LogParser) ensureWebsiteState(websiteID string) LogScanState {
	state, ok := p.states[websiteID]
	if !ok {
		state = LogScanState{
			Files: make(map[string]FileState),
		}
	}
	if state.Files == nil {
		state.Files = make(map[string]FileState)
	}
	return state
}

func (p *LogParser) getFileState(websiteID, filePath string) (FileState, bool) {
	state, ok := p.states[websiteID]
	if !ok || state.Files == nil {
		return FileState{}, false
	}
	fileState, ok := state.Files[filePath]
	return fileState, ok
}

func (p *LogParser) setFileState(websiteID, filePath string, fileState FileState) {
	state := p.ensureWebsiteState(websiteID)
	state.Files[filePath] = fileState
	p.states[websiteID] = state
}

func (p *LogParser) deleteFileState(websiteID, filePath string) {
	state, ok := p.states[websiteID]
	if !ok || state.Files == nil {
		return
	}
	delete(state.Files, filePath)
	p.states[websiteID] = state
}

func (p *LogParser) refreshWebsiteRanges(websiteID string) {
	state, ok := p.states[websiteID]
	if !ok || state.Files == nil {
		return
	}

	var logMin, logMax int64
	var parsedMin, parsedMax int64
	var recentCutoff int64
	backfillPending := false

	for _, fileState := range state.Files {
		if fileState.FirstTimestamp > 0 {
			if logMin == 0 || fileState.FirstTimestamp < logMin {
				logMin = fileState.FirstTimestamp
			}
		}
		if fileState.LastTimestamp > 0 {
			if logMax == 0 || fileState.LastTimestamp > logMax {
				logMax = fileState.LastTimestamp
			}
		}
		if fileState.ParsedMinTs > 0 {
			if parsedMin == 0 || fileState.ParsedMinTs < parsedMin {
				parsedMin = fileState.ParsedMinTs
			}
		}
		if fileState.ParsedMaxTs > 0 {
			if parsedMax == 0 || fileState.ParsedMaxTs > parsedMax {
				parsedMax = fileState.ParsedMaxTs
			}
		}
		if fileState.RecentCutoffTs > 0 {
			if recentCutoff == 0 || fileState.RecentCutoffTs < recentCutoff {
				recentCutoff = fileState.RecentCutoffTs
			}
		}
		if !fileState.BackfillDone {
			if fileState.BackfillEnd > fileState.BackfillOffset || fileState.BackfillEnd == 0 {
				backfillPending = true
			}
		}
	}

	if logMin == 0 && parsedMin > 0 {
		logMin = parsedMin
	}
	if logMax == 0 && parsedMax > 0 {
		logMax = parsedMax
	}
	if parsedMin == 0 && recentCutoff > 0 {
		parsedMin = recentCutoff
	}

	state.LogMinTs = logMin
	state.LogMaxTs = logMax
	state.ParsedMinTs = parsedMin
	state.ParsedMaxTs = parsedMax
	state.RecentCutoffTs = recentCutoff
	state.BackfillPending = backfillPending
	p.states[websiteID] = state

	UpdateWebsiteParseStatus(websiteID, WebsiteParseStatus{
		LogMinTs:        logMin,
		LogMaxTs:        logMax,
		ParsedMinTs:     parsedMin,
		ParsedMaxTs:     parsedMax,
		RecentCutoffTs:  recentCutoff,
		BackfillPending: backfillPending,
	})
}

// CleanOldLogs 清理保留天数之前的日志数据
func (p *LogParser) CleanOldLogs() error {
	today := time.Now().Format("2006-01-02")
	currentHour := time.Now().Hour()

	shouldClean := lastCleanupDate == "" || (currentHour == 2 && lastCleanupDate != today)

	if !shouldClean {
		return nil
	}

	err := p.repo.CleanOldLogs()
	if err != nil {
		return err
	}

	lastCleanupDate = today

	return nil
}

// ScanNginxLogs 增量扫描Nginx日志文件
func (p *LogParser) ScanNginxLogs() []ParserResult {
	if p.demoMode {
		return []ParserResult{}
	}
	if !startIPParsing() {
		return []ParserResult{}
	}
	defer finishIPParsing()

	websiteIDs := config.GetAllWebsiteIDs()
	return p.scanNginxLogsInternal(websiteIDs)
}

// ScanNginxLogsForWebsite 扫描指定网站的日志文件
func (p *LogParser) ScanNginxLogsForWebsite(websiteID string) []ParserResult {
	if p.demoMode {
		return []ParserResult{}
	}
	if !startIPParsing() {
		return []ParserResult{}
	}
	defer finishIPParsing()

	return p.scanNginxLogsInternal([]string{websiteID})
}

// ResetScanState 重置日志扫描状态
func (p *LogParser) ResetScanState(websiteID string) {
	if websiteID == "" {
		p.states = make(map[string]LogScanState)
		ResetWebsiteParseStatus("")
	} else {
		delete(p.states, websiteID)
		ResetWebsiteParseStatus(websiteID)
	}
	p.updateState()
}

// TriggerReparse 清空指定网站的日志并触发重新解析
func (p *LogParser) TriggerReparse(websiteID string) error {
	if p.demoMode {
		var err error
		if websiteID == "" {
			err = p.repo.ClearAllLogs()
		} else {
			err = p.repo.ClearLogsForWebsite(websiteID)
		}
		if err != nil {
			return err
		}
		p.ResetScanState(websiteID)
		return nil
	}

	if !startIPParsing() {
		return ErrParsingInProgress
	}

	var ids []string
	if websiteID == "" {
		ids = config.GetAllWebsiteIDs()
	} else {
		ids = []string{websiteID}
	}

	var err error
	if websiteID == "" {
		err = p.repo.ClearAllLogs()
	} else {
		err = p.repo.ClearLogsForWebsite(websiteID)
	}
	if err != nil {
		finishIPParsing()
		return err
	}

	p.ResetScanState(websiteID)

	go func() {
		defer finishIPParsing()
		p.scanNginxLogsInternal(ids)
	}()

	return nil
}

func (p *LogParser) scanNginxLogsInternal(websiteIDs []string) []ParserResult {
	setParsingTotalBytes(p.calculateTotalBytesToScan(websiteIDs))
	parserResults := make([]ParserResult, len(websiteIDs))

	for i, id := range websiteIDs {
		startTime := time.Now()

		website, _ := config.GetWebsiteByID(id)
		parserResult := EmptyParserResult(website.Name, id)
		if _, err := p.getLineParser(id); err != nil {
			parserResult.Success = false
			parserResult.Error = err
			parserResults[i] = parserResult
			continue
		}

		logPath := website.LogPath
		if strings.Contains(logPath, "*") {
			matches, err := filepath.Glob(logPath)
			if err != nil {
				errstr := "解析日志路径模式 " + logPath + " 失败: " + err.Error()
				parserResult.Success = false
				parserResult.Error = errors.New(errstr)
			} else if len(matches) == 0 {
				errstr := "日志路径模式 " + logPath + " 未匹配到任何文件"
				parserResult.Success = false
				parserResult.Error = errors.New(errstr)
			} else {
				for _, matchPath := range matches {
					p.scanSingleFile(id, matchPath, &parserResult)
				}
			}
		} else {
			p.scanSingleFile(id, logPath, &parserResult)
		}

		p.refreshWebsiteRanges(id)
		parserResult.Duration = time.Since(startTime)
		parserResults[i] = parserResult
	}

	p.updateState()

	return parserResults
}

func (p *LogParser) calculateTotalBytesToScan(websiteIDs []string) int64 {
	var total int64

	for _, id := range websiteIDs {
		website, ok := config.GetWebsiteByID(id)
		if !ok {
			continue
		}

		logPath := website.LogPath
		if strings.Contains(logPath, "*") {
			matches, err := filepath.Glob(logPath)
			if err != nil {
				logrus.Warnf("解析日志路径模式 %s 失败: %v", logPath, err)
				continue
			}
			for _, matchPath := range matches {
				total += p.scanableBytes(id, matchPath)
			}
			continue
		}

		total += p.scanableBytes(id, logPath)
	}

	return total
}

func (p *LogParser) scanableBytes(websiteID, logPath string) int64 {
	fileInfo, err := os.Stat(logPath)
	if err != nil {
		return 0
	}

	currentSize := fileInfo.Size()
	startOffset := p.determineStartOffset(websiteID, logPath, currentSize)
	if isGzipFile(logPath) {
		if startOffset < 0 {
			return 0
		}
		return currentSize
	}
	if currentSize <= startOffset {
		return 0
	}
	return currentSize - startOffset
}

func startIPParsing() bool {
	parsingMu.Lock()
	defer parsingMu.Unlock()
	if parsingMode != parseModeNone {
		return false
	}
	parsingMode = parseModeForeground
	resetParsingProgress()
	return true
}

func finishIPParsing() {
	parsingMu.Lock()
	if parsingMode == parseModeForeground {
		parsingMode = parseModeNone
	}
	parsingMu.Unlock()
	finalizeParsingProgress()
}

func IsIPParsing() bool {
	parsingMu.RLock()
	defer parsingMu.RUnlock()
	return parsingMode == parseModeForeground
}

func startBackfillParsing() bool {
	parsingMu.Lock()
	defer parsingMu.Unlock()
	if parsingMode != parseModeNone {
		return false
	}
	parsingMode = parseModeBackfill
	return true
}

func finishBackfillParsing() {
	parsingMu.Lock()
	if parsingMode == parseModeBackfill {
		parsingMode = parseModeNone
	}
	parsingMu.Unlock()
}

func IsBackfillParsing() bool {
	parsingMu.RLock()
	defer parsingMu.RUnlock()
	return parsingMode == parseModeBackfill
}

// scanSingleFile 扫描单个日志文件
func (p *LogParser) scanSingleFile(
	websiteID string, logPath string, parserResult *ParserResult) {
	file, err := os.Open(logPath)
	if err != nil {
		logrus.Errorf("无法打开日志文件 %s: %v", logPath, err)
		return
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		logrus.Errorf("无法获取文件信息 %s: %v", logPath, err)
		return
	}

	currentSize := fileInfo.Size()
	isGzip := isGzipFile(logPath)

	parser, err := p.getLineParser(websiteID)
	if err != nil {
		parserResult.Success = false
		parserResult.Error = err
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
							gzReader, websiteID, parserResult, parseWindow{minTs: cutoffTs},
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
					}
				} else {
					logrus.Errorf("无法重置 gzip 文件 %s: %v", logPath, err)
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
			} else {
				entriesCount, _, minTs, maxTs := p.parseLogLines(
					file, websiteID, parserResult, parseWindow{minTs: cutoffTs},
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
			return
		}
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			logrus.Errorf("无法解析 gzip 日志文件 %s: %v", logPath, err)
			return
		}
		if startOffset > 0 {
			if err := skipReaderBytes(gzReader, startOffset); err != nil {
				logrus.Warnf("跳过 gzip 历史内容失败，将重新解析文件 %s: %v", logPath, err)
				gzReader.Close()
				if _, err := file.Seek(0, 0); err != nil {
					logrus.Errorf("无法重置 gzip 文件 %s: %v", logPath, err)
					return
				}
				gzReader, err = gzip.NewReader(file)
				if err != nil {
					logrus.Errorf("无法重新解析 gzip 日志文件 %s: %v", logPath, err)
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
			return
		}
		reader = file
	}

	entriesCount, bytesRead, minTs, maxTs := p.parseLogLines(reader, websiteID, parserResult, parseWindow{})
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

	fileState, ok := state.Files[filePath]
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
	reader io.Reader, websiteID string, parserResult *ParserResult, window parseWindow) (int, int64, int64, int64) {
	scanner := bufio.NewScanner(reader)
	entriesCount := 0
	var minTs int64
	var maxTs int64

	// 批量插入相关
	batch := make([]store.NginxLogRecord, 0, backfillBatchSize)

	// 处理一批数据
	processBatch := func() {
		if len(batch) == 0 {
			return
		}

		p.fillBatchLocations(batch)

		if err := p.repo.BatchInsertLogsForWebsite(websiteID, batch); err != nil {
			logrus.Errorf("批量插入网站 %s 的日志记录失败: %v", websiteID, err)
		}

		batch = batch[:0] // 清空批次但保留容量
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

		entry, err := p.parseLogLine(websiteID, line)
		if err != nil {
			continue
		}
		ts := entry.Timestamp.Unix()
		if !window.allows(ts) {
			continue
		}
		batch = append(batch, *entry)
		if minTs == 0 || ts < minTs {
			minTs = ts
		}
		if ts > maxTs {
			maxTs = ts
		}
		entriesCount++
		parserResult.TotalEntries++ // 累加到总结果中，而非赋值

		if len(batch) >= backfillBatchSize {
			processBatch()
		}
	}

	processBatch() // 处理剩余的记录
	if pendingBytes > 0 {
		addParsingProgress(pendingBytes)
	}

	if err := scanner.Err(); err != nil {
		logrus.Errorf("扫描网站 %s 的文件时出错: %v", websiteID, err)
	}

	return entriesCount, totalBytes, minTs, maxTs // 返回当前文件的日志条数
}

func (p *LogParser) fillBatchLocations(batch []store.NginxLogRecord) {
	ips := make([]string, 0, len(batch))
	for _, entry := range batch {
		ips = append(ips, entry.IP)
	}

	locations := enrich.GetIPLocationBatch(ips)
	for i := range batch {
		if location, ok := locations[batch[i].IP]; ok {
			batch[i].DomesticLocation = location.Domestic
			batch[i].GlobalLocation = location.Global
		} else {
			batch[i].DomesticLocation = "未知"
			batch[i].GlobalLocation = "未知"
		}
	}
}

func isGzipFile(filePath string) bool {
	return strings.HasSuffix(strings.ToLower(filePath), ".gz")
}

func skipReaderBytes(reader io.Reader, offset int64) error {
	if offset <= 0 {
		return nil
	}
	_, err := io.CopyN(io.Discard, reader, offset)
	return err
}

func (p *LogParser) getLineParser(websiteID string) (*logLineParser, error) {
	if parser, ok := p.lineParsers[websiteID]; ok {
		return parser, nil
	}

	website, ok := config.GetWebsiteByID(websiteID)
	if !ok {
		return nil, fmt.Errorf("未找到网站配置: %s", websiteID)
	}

	parser, err := newLogLineParser(website)
	if err != nil {
		return nil, err
	}

	p.lineParsers[websiteID] = parser
	return parser, nil
}

func newLogLineParser(website config.WebsiteConfig) (*logLineParser, error) {
	logType := strings.ToLower(strings.TrimSpace(website.LogType))
	if logType == "" {
		logType = "nginx"
	}

	pattern := defaultNginxLogRegex
	source := "default"
	parseType := parseTypeRegex

	if strings.TrimSpace(website.LogRegex) != "" {
		pattern = ensureAnchors(website.LogRegex)
		source = "logRegex"
	} else if strings.TrimSpace(website.LogFormat) != "" {
		compiled, err := buildRegexFromFormat(website.LogFormat)
		if err != nil {
			return nil, err
		}
		pattern = compiled
		source = "logFormat"
	} else if logType == "caddy" {
		return &logLineParser{
			timeLayout: website.TimeLayout,
			source:     "caddy",
			parseType:  parseTypeCaddyJSON,
		}, nil
	} else if logType != "nginx" {
		return nil, fmt.Errorf("不支持的日志类型: %s", logType)
	}

	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("日志格式正则无效 (%s): %w", source, err)
	}

	indexMap := make(map[string]int)
	for i, name := range regex.SubexpNames() {
		if name != "" {
			indexMap[name] = i
		}
	}

	if err := validateLogPattern(indexMap); err != nil {
		return nil, err
	}

	return &logLineParser{
		regex:      regex,
		indexMap:   indexMap,
		timeLayout: website.TimeLayout,
		source:     source,
		parseType:  parseType,
	}, nil
}

func ensureAnchors(pattern string) string {
	trimmed := strings.TrimSpace(pattern)
	if trimmed == "" {
		return trimmed
	}
	if !strings.HasPrefix(trimmed, "^") {
		trimmed = "^" + trimmed
	}
	if !strings.HasSuffix(trimmed, "$") {
		trimmed = trimmed + "$"
	}
	return trimmed
}

func buildRegexFromFormat(format string) (string, error) {
	if strings.TrimSpace(format) == "" {
		return "", errors.New("logFormat 不能为空")
	}

	varPattern := regexp.MustCompile(`\$\w+`)
	locations := varPattern.FindAllStringIndex(format, -1)
	if len(locations) == 0 {
		return "", errors.New("logFormat 未包含任何变量")
	}

	var builder strings.Builder
	usedNames := make(map[string]bool)
	last := 0
	for _, loc := range locations {
		literal := format[last:loc[0]]
		builder.WriteString(regexp.QuoteMeta(literal))

		varName := format[loc[0]+1 : loc[1]]
		builder.WriteString(tokenRegexForVar(varName, usedNames))
		last = loc[1]
	}
	builder.WriteString(regexp.QuoteMeta(format[last:]))

	return "^" + builder.String() + "$", nil
}

func tokenRegexForVar(name string, used map[string]bool) string {
	addGroup := func(group, pattern string) string {
		if used[group] {
			return pattern
		}
		used[group] = true
		return "(?P<" + group + ">" + pattern + ")"
	}

	switch name {
	case "remote_addr":
		return addGroup("ip", `\S+`)
	case "remote_user":
		return addGroup("user", `\S+`)
	case "time_local":
		return addGroup("time", `[^]]+`)
	case "time_iso8601":
		return addGroup("time", `\S+`)
	case "request":
		return addGroup("request", `[^"]+`)
	case "request_method":
		return addGroup("method", `\S+`)
	case "request_uri", "uri":
		return addGroup("url", `\S+`)
	case "status":
		return addGroup("status", `\d{3}`)
	case "body_bytes_sent", "bytes_sent":
		return addGroup("bytes", `\d+`)
	case "http_referer":
		return addGroup("referer", `[^"]*`)
	case "http_user_agent":
		return addGroup("ua", `[^"]*`)
	default:
		return `\S+`
	}
}

func validateLogPattern(indexMap map[string]int) error {
	if len(indexMap) == 0 {
		return errors.New("logRegex/logFormat 必须包含命名分组")
	}

	if !hasAnyField(indexMap, ipAliases) {
		return errors.New("日志格式缺少 IP 字段（ip/remote_addr）")
	}
	if !hasAnyField(indexMap, timeAliases) {
		return errors.New("日志格式缺少时间字段（time/time_local/time_iso8601）")
	}
	if !hasAnyField(indexMap, statusAliases) {
		return errors.New("日志格式缺少状态码字段（status）")
	}
	if !hasAnyField(indexMap, urlAliases) && !hasAnyField(indexMap, requestAliases) {
		return errors.New("日志格式缺少 URL 字段（url/request_uri 或 request）")
	}
	return nil
}

func hasAnyField(indexMap map[string]int, aliases []string) bool {
	for _, name := range aliases {
		if _, ok := indexMap[name]; ok {
			return true
		}
	}
	return false
}

// parseLogLine 解析单行日志
func (p *LogParser) parseLogLine(websiteID string, line string) (*store.NginxLogRecord, error) {
	parser, err := p.getLineParser(websiteID)
	if err != nil {
		return nil, err
	}

	switch parser.parseType {
	case parseTypeCaddyJSON:
		return p.parseCaddyJSONLine(line, parser)
	default:
		return p.parseRegexLogLine(parser, line)
	}
}

func (p *LogParser) parseLogTimestamp(parser *logLineParser, line string) (time.Time, error) {
	switch parser.parseType {
	case parseTypeCaddyJSON:
		decoder := json.NewDecoder(strings.NewReader(line))
		decoder.UseNumber()
		var payload map[string]interface{}
		if err := decoder.Decode(&payload); err != nil {
			return time.Time{}, err
		}
		return parseCaddyTime(payload, parser.timeLayout)
	default:
		return p.parseRegexLogTimestamp(parser, line)
	}
}

func (p *LogParser) parseRegexLogTimestamp(parser *logLineParser, line string) (time.Time, error) {
	matches := parser.regex.FindStringSubmatch(line)
	if len(matches) == 0 {
		return time.Time{}, errors.New("日志格式不匹配")
	}
	rawTime := extractField(matches, parser.indexMap, timeAliases)
	if rawTime == "" {
		return time.Time{}, errors.New("日志缺少时间字段")
	}
	return parseLogTime(rawTime, parser.timeLayout)
}

func (p *LogParser) parseRegexLogLine(parser *logLineParser, line string) (*store.NginxLogRecord, error) {
	matches := parser.regex.FindStringSubmatch(line)
	if len(matches) == 0 {
		return nil, errors.New("日志格式不匹配")
	}

	ip := extractField(matches, parser.indexMap, ipAliases)
	rawTime := extractField(matches, parser.indexMap, timeAliases)
	statusStr := extractField(matches, parser.indexMap, statusAliases)
	urlValue := extractField(matches, parser.indexMap, urlAliases)
	method := extractField(matches, parser.indexMap, methodAliases)
	requestLine := extractField(matches, parser.indexMap, requestAliases)

	if method == "" || urlValue == "" {
		if requestLine != "" {
			parsedMethod, parsedURL, err := parseRequestLine(requestLine)
			if err != nil {
				return nil, err
			}
			if method == "" {
				method = parsedMethod
			}
			if urlValue == "" {
				urlValue = parsedURL
			}
		}
	}

	if ip == "" || rawTime == "" || statusStr == "" || urlValue == "" {
		return nil, errors.New("日志缺少必要字段")
	}

	timestamp, err := parseLogTime(rawTime, parser.timeLayout)
	if err != nil {
		return nil, err
	}

	statusCode, err := strconv.Atoi(statusStr)
	if err != nil {
		return nil, err
	}

	bytesSent := 0
	bytesStr := extractField(matches, parser.indexMap, bytesAliases)
	if bytesStr != "" && bytesStr != "-" {
		if parsed, err := strconv.Atoi(bytesStr); err == nil {
			bytesSent = parsed
		}
	}

	referPath := extractField(matches, parser.indexMap, refererAliases)

	userAgent := extractField(matches, parser.indexMap, userAgentAliases)
	return p.buildLogRecord(ip, method, urlValue, referPath, userAgent, statusCode, bytesSent, timestamp)
}

func (p *LogParser) parseCaddyJSONLine(line string, parser *logLineParser) (*store.NginxLogRecord, error) {
	decoder := json.NewDecoder(strings.NewReader(line))
	decoder.UseNumber()

	var payload map[string]interface{}
	if err := decoder.Decode(&payload); err != nil {
		return nil, err
	}

	request := getMap(payload, "request")
	headers := getMap(request, "headers")

	ip := getString(request, "remote_ip")
	if ip == "" {
		ip = getString(request, "client_ip")
	}
	if ip == "" {
		ip = getString(payload, "remote_ip")
	}

	method := getString(request, "method")
	urlValue := getString(request, "uri")

	statusCode, ok := getInt(payload, "status")
	if !ok {
		return nil, errors.New("日志缺少状态码")
	}

	bytesSent, _ := getInt(payload, "size")
	referPath := getHeader(headers, "Referer")
	userAgent := getHeader(headers, "User-Agent")

	timestamp, err := parseCaddyTime(payload, parser.timeLayout)
	if err != nil {
		return nil, err
	}

	return p.buildLogRecord(ip, method, urlValue, referPath, userAgent, statusCode, bytesSent, timestamp)
}

func (p *LogParser) buildLogRecord(
	ip, method, urlValue, referer, userAgent string,
	statusCode, bytesSent int, timestamp time.Time) (*store.NginxLogRecord, error) {

	if ip == "" || method == "" || urlValue == "" {
		return nil, errors.New("日志缺少必要字段")
	}
	if statusCode <= 0 {
		return nil, errors.New("日志缺少状态码")
	}

	cutoffTime := time.Now().AddDate(0, 0, -p.retentionDays)
	if timestamp.Before(cutoffTime) {
		return nil, errors.New("日志超过保留天数")
	}

	decodedPath, err := url.QueryUnescape(urlValue)
	if err != nil {
		decodedPath = urlValue
	}

	referPath := referer
	if referPath != "" {
		if decodedRefer, err := url.QueryUnescape(referPath); err == nil {
			referPath = decodedRefer
		}
	}

	if userAgent == "" {
		userAgent = "-"
	}

	pageviewFlag := enrich.ShouldCountAsPageView(statusCode, decodedPath, ip)
	browser, os, device := enrich.ParseUserAgent(userAgent)

	return &store.NginxLogRecord{
		ID:               0,
		IP:               ip,
		PageviewFlag:     pageviewFlag,
		Timestamp:        timestamp,
		Method:           method,
		Url:              decodedPath,
		Status:           statusCode,
		BytesSent:        bytesSent,
		Referer:          referPath,
		UserBrowser:      browser,
		UserOs:           os,
		UserDevice:       device,
		DomesticLocation: "",
		GlobalLocation:   "",
	}, nil
}

func getMap(source map[string]interface{}, key string) map[string]interface{} {
	if source == nil {
		return nil
	}
	value, ok := source[key]
	if !ok {
		return nil
	}
	if mapped, ok := value.(map[string]interface{}); ok {
		return mapped
	}
	return nil
}

func getString(source map[string]interface{}, key string) string {
	if source == nil {
		return ""
	}
	value, ok := source[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	default:
		return fmt.Sprint(typed)
	}
}

func getInt(source map[string]interface{}, key string) (int, bool) {
	if source == nil {
		return 0, false
	}
	value, ok := source[key]
	if !ok || value == nil {
		return 0, false
	}
	switch typed := value.(type) {
	case json.Number:
		if parsed, err := typed.Int64(); err == nil {
			return int(parsed), true
		}
		if parsed, err := typed.Float64(); err == nil {
			return int(parsed), true
		}
	case float64:
		return int(typed), true
	case float32:
		return int(typed), true
	case int:
		return typed, true
	case int64:
		return int(typed), true
	case string:
		if parsed, err := strconv.Atoi(typed); err == nil {
			return parsed, true
		}
	}
	return 0, false
}

func getHeader(headers map[string]interface{}, name string) string {
	if headers == nil {
		return ""
	}
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			switch typed := value.(type) {
			case []interface{}:
				if len(typed) > 0 {
					return fmt.Sprint(typed[0])
				}
			case []string:
				if len(typed) > 0 {
					return typed[0]
				}
			case string:
				return typed
			default:
				return fmt.Sprint(typed)
			}
		}
	}
	return ""
}

func parseCaddyTime(payload map[string]interface{}, layout string) (time.Time, error) {
	if payload == nil {
		return time.Time{}, errors.New("日志缺少时间字段")
	}
	if value, ok := payload["ts"]; ok {
		if ts, err := parseAnyTime(value, layout); err == nil {
			return ts, nil
		}
	}
	if value, ok := payload["time"]; ok {
		if ts, err := parseAnyTime(value, layout); err == nil {
			return ts, nil
		}
	}
	if value, ok := payload["timestamp"]; ok {
		if ts, err := parseAnyTime(value, layout); err == nil {
			return ts, nil
		}
	}
	return time.Time{}, errors.New("日志缺少时间字段")
}

func parseAnyTime(value interface{}, layout string) (time.Time, error) {
	switch typed := value.(type) {
	case json.Number:
		if parsed, err := typed.Int64(); err == nil {
			return time.Unix(parsed, 0), nil
		}
		if parsed, err := typed.Float64(); err == nil {
			return parseFloatEpoch(parsed), nil
		}
	case float64:
		return parseFloatEpoch(typed), nil
	case float32:
		return parseFloatEpoch(float64(typed)), nil
	case int:
		return time.Unix(int64(typed), 0), nil
	case int64:
		return time.Unix(typed, 0), nil
	case string:
		return parseLogTime(typed, layout)
	}
	return time.Time{}, errors.New("时间格式不支持")
}

func parseFloatEpoch(value float64) time.Time {
	if value > 1e12 {
		value = value / 1000
	}
	sec := int64(value)
	nsec := int64((value - float64(sec)) * float64(time.Second))
	return time.Unix(sec, nsec)
}

func extractField(matches []string, indexMap map[string]int, aliases []string) string {
	for _, name := range aliases {
		if idx, ok := indexMap[name]; ok {
			if idx > 0 && idx < len(matches) {
				return matches[idx]
			}
		}
	}
	return ""
}

func parseRequestLine(line string) (string, string, error) {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return "", "", errors.New("无效的 request 格式")
	}
	return parts[0], parts[1], nil
}

func parseLogTime(raw, layout string) (time.Time, error) {
	if ts, ok := parseEpochTime(raw); ok {
		return ts, nil
	}

	layouts := make([]string, 0, 3)
	if layout != "" {
		layouts = append(layouts, layout)
	}
	layouts = append(layouts, defaultNginxTimeLayout, time.RFC3339, time.RFC3339Nano)

	var lastErr error
	for _, l := range layouts {
		parsed, err := time.Parse(l, raw)
		if err == nil {
			return parsed, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("时间解析失败")
	}
	return time.Time{}, lastErr
}

func parseEpochTime(raw string) (time.Time, bool) {
	if raw == "" {
		return time.Time{}, false
	}

	for _, r := range raw {
		if (r < '0' || r > '9') && r != '.' {
			return time.Time{}, false
		}
	}

	value, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return time.Time{}, false
	}

	if value > 1e12 {
		value = value / 1000
	}

	sec := int64(value)
	nsec := int64((value - float64(sec)) * float64(time.Second))
	return time.Unix(sec, nsec), true
}

// EmptyParserResult 生成空结果
func EmptyParserResult(name, id string) ParserResult {
	return ParserResult{
		WebName:      name,
		WebID:        id,
		TotalEntries: 0,
		Duration:     0,
		Success:      true,
		Error:        nil,
	}
}
