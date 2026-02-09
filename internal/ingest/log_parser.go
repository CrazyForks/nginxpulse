package ingest

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
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
	"github.com/likaia/nginxpulse/internal/ingest/dedup"
	"github.com/likaia/nginxpulse/internal/store"
	"github.com/sirupsen/logrus"
)

var (
	defaultNginxLogRegex        = `^(?P<ip>\S+) - (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<url>[^"]+) HTTP/\d\.\d" (?P<status>\d+) (?P<bytes>\d+) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"`
	defaultApacheLogRegex       = `^(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d{3}) (?P<bytes>\d+|-) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"`
	defaultTraefikLogRegex      = `^(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d{3}) (?P<bytes>\d+|-) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)" (?P<req_count>\d+) "(?P<router>[^"]*)" "(?P<server_url>[^"]*)" (?P<duration_ms>[0-9.]+)ms`
	defaultEnvoyLogRegex        = `^\[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d{3}) (?P<response_flags>\S+) (?P<bytes_received>\d+) (?P<bytes>\d+) (?P<duration>\d+) (?P<upstream_time>\S+) "(?P<ip>[^"]*)" "(?P<ua>[^"]*)" "(?P<request_id>[^"]*)" "(?P<authority>[^"]*)" "(?P<upstream_host>[^"]*)"`
	defaultHAProxyLogRegex      = `^(?:\w{3}\s+\d+\s+\d+:\d+:\d+\s+\S+\s+\S+\[\d+\]:\s+)?(?P<ip>\S+):\d+\s+\[(?P<time>[^\]]+)\]\s+\S+\s+\S+\s+-?\d+/-?\d+/-?\d+/-?\d+/-?\d+\s+(?P<status>\d{3})\s+(?P<bytes>\d+|-)\s+\S+\s+\S+\s+\S+\s+-?\d+/-?\d+/-?\d+/-?\d+/-?\d+\s+-?\d+/-?\d+(?:\s+(?:\{[^\}]*\}|-)){0,2}\s+\"(?P<request>[^\"]*)\"`
	defaultNginxIngressLogRegex = `^(?P<ip>\S+) - (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d{3}) (?P<bytes>\d+|-) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)" (?P<request_length>\d+) (?P<request_time>[0-9.]+) \[(?P<proxy_upstream_name>[^\]]*)\] \[(?P<proxy_alternative_upstream_name>[^\]]*)\] (?P<upstream_addr>[^ ]+(?:,\s*[^ ]+)*) (?P<upstream_response_length>[^ ]+(?:,\s*[^ ]+)*) (?P<upstream_response_time>[^ ]+(?:,\s*[^ ]+)*) (?P<upstream_status>[^ ]+(?:,\s*[^ ]+)*) (?P<req_id>\S+)`
	defaultIISW3CLogRegex       = `^(?P<time>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+(?P<method>\S+)\s+(?P<url>\S+)\s+(?P<query>\S+)\s+\S+\s+\S+\s+(?P<ip>\S+)\s+(?P<ua>\S+)\s+(?P<referer>\S+)\s+(?P<status>\d{3})(?:\s+\S+){3}\s*$`
	defaultNPMLogRegex          = `^\[(?P<time>[^\]]+)\] - (?P<status>\d+) (?P<upstream_status>\d+) - (?P<method>\S+) (?P<scheme>\S+) (?P<host>\S+) "(?P<path>[^"]+)" \[Client (?P<ip>[^\]]+)\] \[Length (?P<bytes>\d+)\] \[Gzip (?P<gzip>[^\]]+)\] \[Sent-to (?P<upstream>[^\]]+)\] "(?P<ua>[^"]+)" "(?P<referer>[^"]*)"`
	lastCleanupDate             = ""
	parsingMu                   sync.RWMutex
	parsingMode                 parseMode
)

const defaultNginxTimeLayout = "02/Jan/2006:15:04:05 -0700"
const defaultHAProxyTimeLayout = "02/Jan/2006:15:04:05.000"
const defaultIISTimeLayout = "2006-01-02 15:04:05"

const (
	parseTypeRegex     = "regex"
	parseTypeCaddyJSON = "caddy_json"
)

const (
	recentLogWindowDays   = 7
	recentScanChunkSize   = 256 * 1024
	defaultParseBatchSize = 100
)

var (
	ipAliases        = []string{"ip", "remote_addr", "client_ip", "http_x_forwarded_for"}
	timeAliases      = []string{"time", "time_local", "time_iso8601"}
	methodAliases    = []string{"method", "request_method"}
	urlAliases       = []string{"url", "request_uri", "uri", "path"}
	queryAliases     = []string{"query", "args", "query_string", "cs_uri_query"}
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
	Files             map[string]FileState   `json:"files"` // 每个文件的状态
	Targets           map[string]TargetState `json:"targets,omitempty"`
	ParsedHourBuckets map[int64]bool         `json:"parsed_hour_buckets,omitempty"`
	ParsedMinTs       int64                  `json:"parsed_min_ts,omitempty"`
	ParsedMaxTs       int64                  `json:"parsed_max_ts,omitempty"`
	LogMinTs          int64                  `json:"log_min_ts,omitempty"`
	LogMaxTs          int64                  `json:"log_max_ts,omitempty"`
	RecentCutoffTs    int64                  `json:"recent_cutoff_ts,omitempty"`
	BackfillPending   bool                   `json:"backfill_pending,omitempty"`
	InitialParsed     bool                   `json:"initial_parsed,omitempty"`
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

type TargetState struct {
	LastOffset     int64  `json:"last_offset"`
	LastSize       int64  `json:"last_size"`
	LastModTime    int64  `json:"last_mtime,omitempty"`
	LastETag       string `json:"last_etag,omitempty"`
	RecentOffset   int64  `json:"recent_offset,omitempty"`
	BackfillOffset int64  `json:"backfill_offset,omitempty"`
	BackfillEnd    int64  `json:"backfill_end,omitempty"`
	BackfillDone   bool   `json:"backfill_done,omitempty"`
	FirstTimestamp int64  `json:"first_ts,omitempty"`
	LastTimestamp  int64  `json:"last_ts,omitempty"`
	ParsedMinTs    int64  `json:"parsed_min_ts,omitempty"`
	ParsedMaxTs    int64  `json:"parsed_max_ts,omitempty"`
	RecentCutoffTs int64  `json:"recent_cutoff_ts,omitempty"`
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
	repo              *store.Repository
	statePath         string
	states            map[string]LogScanState // 各网站的扫描状态，以网站ID为键
	demoMode          bool
	retentionDays     int
	parseBatchSize    int
	ipGeoCacheLimit   int
	lineParsers       map[string]*logLineParser // key: websiteID or websiteID:sourceID
	dedup             *dedup.Cache
	whitelistMatchers map[string]*enrich.WhitelistMatcher
}

// NewLogParser 创建新的日志解析器
func NewLogParser(userRepoPtr *store.Repository) *LogParser {
	statePath := filepath.Join(config.DataDir, "nginx_scan_state.json")
	cfg := config.ReadConfig()
	retentionDays := cfg.System.LogRetentionDays
	if retentionDays <= 0 {
		retentionDays = 30
	}
	parseBatchSize := cfg.System.ParseBatchSize
	if parseBatchSize <= 0 {
		parseBatchSize = defaultParseBatchSize
	}
	ipGeoCacheLimit := cfg.System.IPGeoCacheLimit
	if ipGeoCacheLimit <= 0 {
		ipGeoCacheLimit = 1000000
	}
	parser := &LogParser{
		repo:              userRepoPtr,
		statePath:         statePath,
		states:            make(map[string]LogScanState),
		demoMode:          cfg.System.DemoMode,
		retentionDays:     retentionDays,
		parseBatchSize:    parseBatchSize,
		ipGeoCacheLimit:   ipGeoCacheLimit,
		lineParsers:       make(map[string]*logLineParser),
		dedup:             dedup.NewCache(100000, 10*time.Minute),
		whitelistMatchers: make(map[string]*enrich.WhitelistMatcher),
	}
	for _, websiteID := range config.GetAllWebsiteIDs() {
		if site, ok := config.GetWebsiteByID(websiteID); ok {
			if matcher := enrich.NewWhitelistMatcher(site.Whitelist); matcher != nil {
				parser.whitelistMatchers[websiteID] = matcher
			}
		}
	}
	parser.loadState()
	parser.resetStateIfEmptyDB()
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
		p.notifyFileIO("", p.statePath, "读取扫描状态文件", err)
		p.states = make(map[string]LogScanState)
		return
	}

	if err := json.Unmarshal(data, &p.states); err != nil {
		logrus.Errorf("解析扫描状态失败: %v", err)
		p.notifyFileIO("", p.statePath, "解析扫描状态文件", err)
		p.states = make(map[string]LogScanState)
	}

	for websiteID, state := range p.states {
		if state.Files == nil {
			state.Files = make(map[string]FileState)
		}
		normalizedFiles := make(map[string]FileState, len(state.Files))
		for path, fileState := range state.Files {
			normalizedFiles[normalizeLogPath(path)] = fileState
		}
		state.Files = normalizedFiles
		if state.Targets == nil {
			state.Targets = make(map[string]TargetState)
		}
		if state.ParsedHourBuckets == nil {
			state.ParsedHourBuckets = make(map[int64]bool)
		}
		p.states[websiteID] = state
		p.refreshWebsiteRanges(websiteID)
	}
}

// updateState 更新并保存状态
func (p *LogParser) updateState() {
	data, err := json.Marshal(p.states)
	if err != nil {
		logrus.Errorf("保存扫描状态失败: %v", err)
		p.notifyFileIO("", p.statePath, "序列化扫描状态文件", err)
		return
	}

	tmpPath := p.statePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		logrus.Errorf("保存扫描状态失败: %v", err)
		p.notifyFileIO("", p.statePath, "写入扫描状态文件", err)
		return
	}
	if err := os.Rename(tmpPath, p.statePath); err != nil {
		logrus.Errorf("保存扫描状态失败: %v", err)
		p.notifyFileIO("", p.statePath, "保存扫描状态文件", err)
	}
}

func (p *LogParser) resetStateIfEmptyDB() {
	if p.demoMode {
		return
	}

	websiteIDs := config.GetAllWebsiteIDs()
	if len(websiteIDs) == 0 {
		return
	}

	hasState := false
	for _, id := range websiteIDs {
		state, ok := p.states[id]
		if !ok {
			continue
		}
		if len(state.Files) > 0 || len(state.Targets) > 0 || len(state.ParsedHourBuckets) > 0 ||
			state.ParsedMaxTs > 0 || state.LogMaxTs > 0 {
			hasState = true
			break
		}
	}
	if !hasState {
		return
	}

	for _, id := range websiteIDs {
		hasLogs, err := p.repo.HasLogs(id)
		if err != nil {
			logrus.WithError(err).Warnf("检测网站 %s 日志数据失败，跳过自动清理扫描状态", id)
			return
		}
		if hasLogs {
			return
		}
	}

	logrus.Warn("检测到扫描状态已存在但数据库日志为空，自动清理扫描状态以便重新解析")
	p.ResetScanState("")
}

func (p *LogParser) ensureWebsiteState(websiteID string) LogScanState {
	state, ok := p.states[websiteID]
	if !ok {
		state = LogScanState{
			Files:   make(map[string]FileState),
			Targets: make(map[string]TargetState),
		}
	}
	if state.Files == nil {
		state.Files = make(map[string]FileState)
	}
	if state.Targets == nil {
		state.Targets = make(map[string]TargetState)
	}
	if state.ParsedHourBuckets == nil {
		state.ParsedHourBuckets = make(map[int64]bool)
	}
	return state
}

func (p *LogParser) hasUnparsedWebsite(websiteIDs []string) bool {
	for _, id := range websiteIDs {
		state, ok := p.states[id]
		if !ok || !state.InitialParsed {
			return true
		}
	}
	return false
}

func (p *LogParser) markInitialParsed(websiteID string) {
	state := p.ensureWebsiteState(websiteID)
	if state.InitialParsed {
		return
	}
	state.InitialParsed = true
	p.states[websiteID] = state
}

func (p *LogParser) getFileState(websiteID, filePath string) (FileState, bool) {
	state, ok := p.states[websiteID]
	if !ok || state.Files == nil {
		return FileState{}, false
	}
	fileState, ok := state.Files[normalizeLogPath(filePath)]
	return fileState, ok
}

func (p *LogParser) setFileState(websiteID, filePath string, fileState FileState) {
	state := p.ensureWebsiteState(websiteID)
	state.Files[normalizeLogPath(filePath)] = fileState
	p.states[websiteID] = state
}

func (p *LogParser) deleteFileState(websiteID, filePath string) {
	state, ok := p.states[websiteID]
	if !ok || state.Files == nil {
		return
	}
	delete(state.Files, normalizeLogPath(filePath))
	p.states[websiteID] = state
}

func (p *LogParser) recordParsedHourBuckets(websiteID string, buckets map[int64]struct{}) {
	if len(buckets) == 0 {
		return
	}
	state := p.ensureWebsiteState(websiteID)
	if state.ParsedHourBuckets == nil {
		state.ParsedHourBuckets = make(map[int64]bool)
	}
	for bucket := range buckets {
		state.ParsedHourBuckets[bucket] = true
	}
	p.states[websiteID] = state
}

func (p *LogParser) getTargetState(websiteID, targetKey string) (TargetState, bool) {
	state, ok := p.states[websiteID]
	if !ok || state.Targets == nil {
		return TargetState{}, false
	}
	targetState, ok := state.Targets[targetKey]
	return targetState, ok
}

func (p *LogParser) setTargetState(websiteID, targetKey string, targetState TargetState) {
	state := p.ensureWebsiteState(websiteID)
	state.Targets[targetKey] = targetState
	p.states[websiteID] = state
}

func (p *LogParser) deleteTargetState(websiteID, targetKey string) {
	state, ok := p.states[websiteID]
	if !ok || state.Targets == nil {
		return
	}
	delete(state.Targets, targetKey)
	p.states[websiteID] = state
}

func (p *LogParser) refreshWebsiteRanges(websiteID string) {
	state, ok := p.states[websiteID]
	if !ok || (state.Files == nil && state.Targets == nil) {
		return
	}

	var logMin, logMax int64
	var parsedMin, parsedMax int64
	var recentCutoff int64
	backfillPending := false
	var backfillTotalBytes int64
	var backfillProcessedBytes int64

	applyState := func(firstTs, lastTs, parsedMinTs, parsedMaxTs, recentCutoffTs int64, backfillDone bool, backfillEnd, backfillOffset int64) {
		if firstTs > 0 {
			if logMin == 0 || firstTs < logMin {
				logMin = firstTs
			}
		}
		if lastTs > 0 {
			if logMax == 0 || lastTs > logMax {
				logMax = lastTs
			}
		}
		if parsedMinTs > 0 {
			if parsedMin == 0 || parsedMinTs < parsedMin {
				parsedMin = parsedMinTs
			}
		}
		if parsedMaxTs > 0 {
			if parsedMax == 0 || parsedMaxTs > parsedMax {
				parsedMax = parsedMaxTs
			}
		}
		if recentCutoffTs > 0 {
			if recentCutoff == 0 || recentCutoffTs < recentCutoff {
				recentCutoff = recentCutoffTs
			}
		}
		if !backfillDone {
			if backfillEnd > backfillOffset || backfillEnd == 0 {
				backfillPending = true
			}
		}
	}
	accumulateBackfill := func(done bool, backfillEnd, backfillOffset, lastSize int64) {
		total, processed := computeBackfillBytes(done, backfillEnd, backfillOffset, lastSize)
		backfillTotalBytes += total
		backfillProcessedBytes += processed
	}

	for _, fileState := range state.Files {
		applyState(
			fileState.FirstTimestamp,
			fileState.LastTimestamp,
			fileState.ParsedMinTs,
			fileState.ParsedMaxTs,
			fileState.RecentCutoffTs,
			fileState.BackfillDone,
			fileState.BackfillEnd,
			fileState.BackfillOffset,
		)
		accumulateBackfill(fileState.BackfillDone, fileState.BackfillEnd, fileState.BackfillOffset, fileState.LastSize)
	}

	for _, targetState := range state.Targets {
		applyState(
			targetState.FirstTimestamp,
			targetState.LastTimestamp,
			targetState.ParsedMinTs,
			targetState.ParsedMaxTs,
			targetState.RecentCutoffTs,
			targetState.BackfillDone,
			targetState.BackfillEnd,
			targetState.BackfillOffset,
		)
		accumulateBackfill(targetState.BackfillDone, targetState.BackfillEnd, targetState.BackfillOffset, targetState.LastSize)
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
		LogMinTs:               logMin,
		LogMaxTs:               logMax,
		ParsedMinTs:            parsedMin,
		ParsedMaxTs:            parsedMax,
		RecentCutoffTs:         recentCutoff,
		BackfillPending:        backfillPending,
		BackfillTotalBytes:     backfillTotalBytes,
		BackfillProcessedBytes: backfillProcessedBytes,
		ParsedHourBuckets:      state.ParsedHourBuckets,
	})
}

func computeBackfillBytes(done bool, backfillEnd, backfillOffset, lastSize int64) (int64, int64) {
	if done {
		total := backfillEnd
		if total <= 0 {
			total = lastSize
		}
		if total <= 0 {
			return 0, 0
		}
		return total, total
	}
	if backfillEnd > 0 {
		processed := backfillOffset
		if processed < 0 {
			processed = 0
		}
		if processed > backfillEnd {
			processed = backfillEnd
		}
		return backfillEnd, processed
	}
	if lastSize > 0 {
		return lastSize, 0
	}
	return 0, 0
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
	websiteIDs := config.GetAllWebsiteIDs()
	stage := parseStagePeriodic
	if p.hasUnparsedWebsite(websiteIDs) {
		stage = parseStageInitial
	}
	if !startIPParsingWithStage(stage) {
		return []ParserResult{}
	}
	defer finishIPParsing()

	return p.scanNginxLogsInternal(websiteIDs)
}

// ScanNginxLogsForWebsite 扫描指定网站的日志文件
func (p *LogParser) ScanNginxLogsForWebsite(websiteID string) []ParserResult {
	if p.demoMode {
		return []ParserResult{}
	}
	stage := parseStagePeriodic
	if p.hasUnparsedWebsite([]string{websiteID}) {
		stage = parseStageInitial
	}
	if !startIPParsingWithStage(stage) {
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

	if !startIPParsingWithStage(parseStageReparse) {
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
		p.markInitialParsed(id)
		if len(website.Sources) > 0 {
			p.scanSources(id, website, &parserResult)
		} else {
			if _, err := p.getLineParser(id); err != nil {
				parserResult.Success = false
				parserResult.Error = err
				p.notifyLogParsing(id, "", "日志解析配置", err)
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
					p.notifyLogParsing(id, logPath, "解析日志路径模式", err)
				} else if len(matches) == 0 {
					errstr := "日志路径模式 " + logPath + " 未匹配到任何文件"
					parserResult.Success = false
					parserResult.Error = errors.New(errstr)
					p.notifyLogParsing(id, logPath, "日志路径未匹配到文件", errors.New(errstr))
				} else {
					for _, matchPath := range matches {
						p.scanSingleFile(id, matchPath, &parserResult)
					}
				}
			} else {
				p.scanSingleFile(id, logPath, &parserResult)
			}
		}

		p.refreshWebsiteRanges(id)
		p.updateState()
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

func startIPParsingWithStage(stage parseStage) bool {
	parsingMu.Lock()
	defer parsingMu.Unlock()
	if parsingMode != parseModeNone {
		return false
	}
	parsingMode = parseModeForeground
	setParseStage(stage)
	resetParsingProgress()
	return true
}

func finishIPParsing() {
	parsingMu.Lock()
	if parsingMode == parseModeForeground {
		parsingMode = parseModeNone
	}
	parsingMu.Unlock()
	resetParseStage()
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
	return p.getLineParserForSource(websiteID, "")
}

func (p *LogParser) getLineParserForSource(websiteID, sourceID string) (*logLineParser, error) {
	key := websiteID
	if sourceID != "" {
		key = websiteID + ":" + sourceID
	}
	if parser, ok := p.lineParsers[key]; ok {
		return parser, nil
	}

	website, ok := config.GetWebsiteByID(websiteID)
	if !ok {
		return nil, fmt.Errorf("未找到网站配置: %s", websiteID)
	}

	var sourceCfg *config.SourceConfig
	if sourceID != "" {
		for i := range website.Sources {
			if strings.TrimSpace(website.Sources[i].ID) == sourceID {
				sourceCfg = &website.Sources[i]
				break
			}
		}
	}

	parser, err := newLogLineParser(website, sourceCfg)
	if err != nil {
		return nil, err
	}

	p.lineParsers[key] = parser
	return parser, nil
}

func newLogLineParser(website config.WebsiteConfig, sourceCfg *config.SourceConfig) (*logLineParser, error) {
	logType := strings.ToLower(strings.TrimSpace(website.LogType))
	logFormat := website.LogFormat
	logRegex := website.LogRegex
	timeLayout := website.TimeLayout

	if sourceCfg != nil && sourceCfg.Parse != nil {
		parseOverride := sourceCfg.Parse
		if strings.TrimSpace(parseOverride.LogType) != "" {
			logType = strings.ToLower(strings.TrimSpace(parseOverride.LogType))
		}
		if strings.TrimSpace(parseOverride.LogFormat) != "" {
			logFormat = parseOverride.LogFormat
		}
		if strings.TrimSpace(parseOverride.LogRegex) != "" {
			logRegex = parseOverride.LogRegex
		}
		if strings.TrimSpace(parseOverride.TimeLayout) != "" {
			timeLayout = parseOverride.TimeLayout
		}
	}
	if logType == "" {
		logType = "nginx"
	}

	pattern := defaultNginxLogRegex
	source := "default"
	parseType := parseTypeRegex

	if strings.TrimSpace(logRegex) != "" {
		pattern = ensureAnchors(logRegex)
		source = "logRegex"
	} else if strings.TrimSpace(logFormat) != "" {
		compiled, err := buildRegexFromFormat(logFormat)
		if err != nil {
			return nil, err
		}
		pattern = compiled
		source = "logFormat"
	} else {
		switch logType {
		case "caddy":
			return &logLineParser{
				timeLayout: timeLayout,
				source:     "caddy",
				parseType:  parseTypeCaddyJSON,
			}, nil
		case "nginx":
			// default nginx pattern
		case "nginx-proxy-manager", "npm":
			pattern = defaultNPMLogRegex
			source = "nginx-proxy-manager"
		case "apache", "httpd", "apache-httpd":
			pattern = defaultApacheLogRegex
			source = "apache"
		case "tengine":
			pattern = defaultNginxLogRegex
			source = "tengine"
		case "traefik", "traefik-ingress":
			pattern = defaultTraefikLogRegex
			source = "traefik"
		case "envoy":
			pattern = defaultEnvoyLogRegex
			source = "envoy"
		case "nginx-ingress", "ingress-nginx":
			pattern = defaultNginxIngressLogRegex
			source = "nginx-ingress"
		case "haproxy", "haproxy-ingress":
			pattern = defaultHAProxyLogRegex
			source = "haproxy"
			if strings.TrimSpace(timeLayout) == "" {
				timeLayout = defaultHAProxyTimeLayout
			}
		case "iis", "iis-w3c", "w3c-iis":
			pattern = defaultIISW3CLogRegex
			source = "iis"
			if strings.TrimSpace(timeLayout) == "" {
				timeLayout = defaultIISTimeLayout
			}
		default:
			return nil, fmt.Errorf("不支持的日志类型: %s", logType)
		}
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
		timeLayout: timeLayout,
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
		quoted := isQuotedTokenBoundary(literal, format[loc[1]:])
		builder.WriteString(tokenRegexForVar(varName, usedNames, quoted))
		last = loc[1]
	}
	builder.WriteString(regexp.QuoteMeta(format[last:]))

	return "^" + builder.String() + "$", nil
}

func tokenRegexForVar(name string, used map[string]bool, quoted bool) string {
	addGroup := func(group, pattern string) string {
		if used[group] {
			return pattern
		}
		used[group] = true
		return "(?P<" + group + ">" + pattern + ")"
	}

	commaListPattern := `[^,\s]+(?:,\s*[^,\s]+)*`
	optionalTokenPattern := `\S*`
	optionalQuotedPattern := `[^"]*`
	requiredTokenPattern := `\S+`
	requiredQuotedPattern := `[^"]+`
	if quoted {
		optionalTokenPattern = optionalQuotedPattern
		requiredTokenPattern = requiredQuotedPattern
	}

	switch name {
	case "remote_addr":
		return addGroup("ip", requiredTokenPattern)
	case "http_x_forwarded_for":
		return addGroup("http_x_forwarded_for", commaListPattern)
	case "remote_user":
		return addGroup("user", optionalTokenPattern)
	case "time_local":
		return addGroup("time", `[^]]+`)
	case "time_iso8601":
		return addGroup("time", requiredTokenPattern)
	case "request":
		return addGroup("request", requiredTokenPattern)
	case "request_method":
		return addGroup("method", requiredTokenPattern)
	case "request_uri", "uri":
		return addGroup("url", requiredTokenPattern)
	case "args":
		return addGroup("args", optionalTokenPattern)
	case "query_string":
		return addGroup("query_string", optionalTokenPattern)
	case "status":
		return addGroup("status", `\d{3}`)
	case "body_bytes_sent", "bytes_sent":
		return addGroup("bytes", `\d+`)
	case "http_referer":
		return addGroup("referer", optionalTokenPattern)
	case "http_user_agent":
		return addGroup("ua", optionalTokenPattern)
	case "host":
		return addGroup("host", requiredTokenPattern)
	case "http_host":
		return addGroup("host", requiredTokenPattern)
	case "server_name":
		return addGroup("server_name", requiredTokenPattern)
	case "scheme":
		return addGroup("scheme", requiredTokenPattern)
	case "request_length":
		return addGroup("request_length", `\d+`)
	case "remote_port":
		return addGroup("remote_port", `\d+`)
	case "connection":
		return addGroup("connection", `\d+`)
	case "request_time_msec":
		return addGroup("request_time_msec", `\d+(?:\.\d+)?`)
	case "upstream_addr":
		return addGroup("upstream_addr", commaListPattern)
	case "upstream_status":
		return addGroup("upstream_status", commaListPattern)
	case "upstream_response_time":
		return addGroup("upstream_response_time", commaListPattern)
	case "upstream_connect_time":
		return addGroup("upstream_connect_time", commaListPattern)
	case "upstream_header_time":
		return addGroup("upstream_header_time", commaListPattern)
	default:
		return optionalTokenPattern
	}
}

func isQuotedTokenBoundary(prefix, suffix string) bool {
	prefixTrim := strings.TrimRight(prefix, " \t\r\n")
	if !strings.HasSuffix(prefixTrim, "\"") {
		return false
	}
	suffixTrim := strings.TrimLeft(suffix, " \t\r\n")
	return strings.HasPrefix(suffixTrim, "\"")
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
func (p *LogParser) parseLogLine(websiteID, sourceID string, line string) (*store.NginxLogRecord, error) {
	parser, err := p.getLineParserForSource(websiteID, sourceID)
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
	queryValue := extractField(matches, parser.indexMap, queryAliases)
	if urlValue != "" && queryValue != "" && queryValue != "-" && !strings.Contains(urlValue, "?") {
		if strings.HasPrefix(queryValue, "?") {
			urlValue += queryValue
		} else {
			urlValue += "?" + queryValue
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

	ip = normalizeIP(ip)
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

func normalizeIP(raw string) string {
	ip := strings.TrimSpace(raw)
	if ip == "" {
		return ip
	}
	if strings.Contains(ip, ",") {
		parts := strings.Split(ip, ",")
		if len(parts) > 0 {
			ip = strings.TrimSpace(parts[0])
		}
	}
	if strings.HasPrefix(ip, "[") {
		if end := strings.Index(ip, "]"); end > 0 {
			ip = ip[1:end]
		}
		return ip
	}
	if strings.Count(ip, ":") == 1 && strings.Contains(ip, ".") {
		if host, _, err := net.SplitHostPort(ip); err == nil {
			return host
		}
	}
	return ip
}

func normalizeLogPath(path string) string {
	cleaned := strings.TrimSpace(path)
	if cleaned == "" {
		return cleaned
	}
	cleaned = filepath.Clean(cleaned)
	if abs, err := filepath.Abs(cleaned); err == nil {
		return abs
	}
	return cleaned
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
