package ingest

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/likaia/nginxpulse/internal/enrich"
	"github.com/likaia/nginxpulse/internal/store"
)

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
