package analytics

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/likaia/nginxpulse/internal/ingest"
	"github.com/likaia/nginxpulse/internal/store"
	"github.com/likaia/nginxpulse/internal/timeutil"
)

// LogEntry 表示单条日志信息
type LogEntry struct {
	ID               int    `json:"id"`
	IP               string `json:"ip"`
	Timestamp        int64  `json:"timestamp"`
	Time             string `json:"time"` // 格式化后的时间字符串
	Method           string `json:"method"`
	URL              string `json:"url"`
	StatusCode       int    `json:"status_code"`
	BytesSent        int    `json:"bytes_sent"`
	Referer          string `json:"referer"`
	UserBrowser      string `json:"user_browser"`
	UserOS           string `json:"user_os"`
	UserDevice       string `json:"user_device"`
	DomesticLocation string `json:"domestic_location"`
	GlobalLocation   string `json:"global_location"`
	PageviewFlag     bool   `json:"pageview_flag"`
	IsNewVisitor     bool   `json:"is_new_visitor"`
}

// LogsStats 日志查询结果
type LogsStats struct {
	Logs                []LogEntry `json:"logs"`
	IPParsing           bool       `json:"ip_parsing"`
	IPParsingProgress   int        `json:"ip_parsing_progress"`
	ParsingPending      bool       `json:"parsing_pending"`
	ParsingPendingRange *TimeRange `json:"parsing_pending_range,omitempty"`
	Pagination          struct {
		Total    int `json:"total"`
		Page     int `json:"page"`
		PageSize int `json:"pageSize"`
		Pages    int `json:"pages"`
	} `json:"pagination"`
}

type TimeRange struct {
	Start int64 `json:"start"`
	End   int64 `json:"end"`
}

// GetType 实现 StatsResult 接口
func (s LogsStats) GetType() string {
	return "logs"
}

// LogsStatsManager 实现日志查询功能
type LogsStatsManager struct {
	repo *store.Repository
}

// NewLogsStatsManager 创建日志查询管理器
func NewLogsStatsManager(userRepoPtr *store.Repository) *LogsStatsManager {
	return &LogsStatsManager{
		repo: userRepoPtr,
	}
}

// Query 实现 StatsManager 接口
func (m *LogsStatsManager) Query(query StatsQuery) (StatsResult, error) {
	result := LogsStats{}
	result.IPParsing = ingest.IsIPParsing()
	result.IPParsingProgress = ingest.GetIPParsingProgress()

	// 从查询参数中获取分页和排序信息
	page := 1
	pageSize := 100
	sortField := "timestamp"
	sortOrder := "desc"
	var filter string
	var timeRange string
	var timeStart int64
	var timeEnd int64
	var statusCode int
	var statusClass string
	var excludeInternal bool
	var ipFilter string
	var locationFilter string
	var urlFilter string
	var pageviewOnly bool
	var newVisitorFilter string
	var includeNewVisitor bool
	var newRangeStart int64
	var newRangeEnd int64
	var distinctIP bool

	if pageVal, ok := query.ExtraParam["page"].(int); ok && pageVal > 0 {
		page = pageVal
	}

	if pageSizeVal, ok := query.ExtraParam["pageSize"].(int); ok && pageSizeVal > 0 {
		pageSize = pageSizeVal
		if pageSize > 1000 {
			pageSize = 1000 // 设置上限以防过大查询
		}
	}

	if field, ok := query.ExtraParam["sortField"].(string); ok && field != "" {
		// 验证字段名有效性，防止SQL注入
		validFields := map[string]bool{
			"timestamp": true, "ip": true, "url": true,
			"status_code": true, "bytes_sent": true,
		}
		if validFields[field] {
			sortField = field
		}
	}

	if order, ok := query.ExtraParam["sortOrder"].(string); ok {
		if order == "asc" || order == "desc" {
			sortOrder = order
		}
	}

	if filterVal, ok := query.ExtraParam["filter"].(string); ok {
		filter = filterVal
	}
	if timeRangeVal, ok := query.ExtraParam["timeRange"].(string); ok {
		timeRange = timeRangeVal
	}
	if timeStartVal, ok := query.ExtraParam["timeStart"].(string); ok {
		parsed, err := parseTimeFilter(timeStartVal)
		if err != nil {
			return result, fmt.Errorf("解析开始时间失败: %v", err)
		}
		timeStart = parsed
	}
	if timeEndVal, ok := query.ExtraParam["timeEnd"].(string); ok {
		parsed, err := parseTimeFilter(timeEndVal)
		if err != nil {
			return result, fmt.Errorf("解析结束时间失败: %v", err)
		}
		timeEnd = parsed
	}
	if statusCodeVal, ok := query.ExtraParam["statusCode"].(int); ok && statusCodeVal > 0 {
		statusCode = statusCodeVal
	}
	if statusClassVal, ok := query.ExtraParam["statusClass"].(string); ok {
		statusClass = statusClassVal
	}
	if excludeInternalVal, ok := query.ExtraParam["excludeInternal"].(bool); ok {
		excludeInternal = excludeInternalVal
	}
	if ipFilterVal, ok := query.ExtraParam["ipFilter"].(string); ok {
		ipFilter = strings.TrimSpace(ipFilterVal)
	}
	if locationFilterVal, ok := query.ExtraParam["locationFilter"].(string); ok {
		locationFilter = strings.TrimSpace(locationFilterVal)
	}
	if urlFilterVal, ok := query.ExtraParam["urlFilter"].(string); ok {
		urlFilter = strings.TrimSpace(urlFilterVal)
	}
	if pageviewOnlyVal, ok := query.ExtraParam["pageviewOnly"].(bool); ok {
		pageviewOnly = pageviewOnlyVal
	}
	if newVisitorVal, ok := query.ExtraParam["newVisitor"].(string); ok && newVisitorVal != "" {
		newVisitorFilter = newVisitorVal
		includeNewVisitor = true
	}
	if distinctVal, ok := query.ExtraParam["distinctIp"].(bool); ok {
		distinctIP = distinctVal
	}
	if includeNewVisitor {
		var err error
		newRangeStart, newRangeEnd, err = resolveNewVisitorRange(timeRange, timeStart, timeEnd)
		if err != nil {
			return result, err
		}
	}

	rangeStart, rangeEnd, err := resolveQueryRange(timeRange, timeStart, timeEnd)
	if err != nil {
		return result, err
	}
	if status, ok := ingest.GetWebsiteParseStatus(query.WebsiteID); ok {
		pending, pendingRange := computeParsingPending(status, rangeStart, rangeEnd)
		result.ParsingPending = pending
		result.ParsingPendingRange = pendingRange
	}

	// 计算分页
	offset := (page - 1) * pageSize
	tableName := fmt.Sprintf("%s_nginx_logs", query.WebsiteID)
	logAlias := "l"
	firstSeenJoin := fmt.Sprintf(`LEFT JOIN "%s_first_seen" fs ON fs.ip_id = %s.ip_id`, query.WebsiteID, logAlias)
	joinClause := fmt.Sprintf(`
        JOIN "%s_dim_ip" ip ON ip.id = %s.ip_id
        JOIN "%s_dim_url" u ON u.id = %s.url_id
        JOIN "%s_dim_referer" r ON r.id = %s.referer_id
        JOIN "%s_dim_ua" ua ON ua.id = %s.ua_id
        JOIN "%s_dim_location" loc ON loc.id = %s.location_id`,
		query.WebsiteID, logAlias,
		query.WebsiteID, logAlias,
		query.WebsiteID, logAlias,
		query.WebsiteID, logAlias,
		query.WebsiteID, logAlias,
	)
	column := func(name string) string {
		switch name {
		case "ip":
			return "ip.ip"
		case "url":
			return "u.url"
		case "referer":
			return "r.referer"
		case "user_browser":
			return "ua.browser"
		case "user_os":
			return "ua.os"
		case "user_device":
			return "ua.device"
		case "domestic_location":
			return "loc.domestic"
		case "global_location":
			return "loc.global"
		default:
			return fmt.Sprintf("%s.%s", logAlias, name)
		}
	}

	// 构建查询语句
	var queryBuilder strings.Builder
	var args []interface{}
	selectFields := []string{
		"id", "ip", "timestamp", "method", "url", "status_code",
		"bytes_sent", "referer", "user_browser", "user_os", "user_device",
		"domestic_location", "global_location", "pageview_flag",
	}
	selectColumns := make([]string, 0, len(selectFields))
	for _, field := range selectFields {
		selectColumns = append(selectColumns, fmt.Sprintf("%s AS %s", column(field), field))
	}
	selectColumnsWithAlias := strings.Join(selectColumns, ", ")
	selectColumnsRaw := strings.Join(selectFields, ", ")

	if !distinctIP {
		if includeNewVisitor {
			queryBuilder.WriteString(fmt.Sprintf(`
        SELECT
            %s,
            CASE WHEN fs.first_ts >= ? AND fs.first_ts < ? THEN 1 ELSE 0 END AS is_new_visitor
        FROM "%s" %s
        %s
        %s`,
				selectColumnsWithAlias, tableName, logAlias, joinClause, firstSeenJoin))
			args = append(args, newRangeStart, newRangeEnd)
		} else {
			queryBuilder.WriteString(fmt.Sprintf(`
        SELECT
            %s
        FROM "%s" %s
        %s`,
				selectColumnsWithAlias, tableName, logAlias, joinClause))
		}
	}

	// 添加过滤条件
	conditions := make([]string, 0, 2)
	if filter != "" {
		conditions = append(conditions, fmt.Sprintf("(%s LIKE ? OR %s LIKE ? OR %s LIKE ? OR %s LIKE ?)",
			column("url"), column("ip"), column("referer"), column("domestic_location")))
		filterArg := "%" + filter + "%"
		args = append(args, filterArg, filterArg, filterArg, filterArg)
	}
	if timeRange != "" {
		startTime, endTime, err := timeutil.TimePeriod(timeRange)
		if err != nil {
			return result, fmt.Errorf("解析时间范围失败: %v", err)
		}
		conditions = append(conditions, fmt.Sprintf("%s >= ? AND %s < ?", column("timestamp"), column("timestamp")))
		args = append(args, startTime.Unix(), endTime.Unix())
	}
	if timeStart > 0 {
		conditions = append(conditions, fmt.Sprintf("%s >= ?", column("timestamp")))
		args = append(args, timeStart)
	}
	if timeEnd > 0 {
		conditions = append(conditions, fmt.Sprintf("%s <= ?", column("timestamp")))
		args = append(args, timeEnd)
	}
	if ipFilter != "" {
		conditions = append(conditions, fmt.Sprintf("%s LIKE ?", column("ip")))
		args = append(args, "%"+ipFilter+"%")
	}
	if locationFilter != "" {
		conditions = append(conditions, fmt.Sprintf("(%s LIKE ? OR %s LIKE ?)",
			column("domestic_location"), column("global_location")))
		locationArg := "%" + locationFilter + "%"
		args = append(args, locationArg, locationArg)
	}
	if urlFilter != "" {
		conditions = append(conditions, fmt.Sprintf("%s LIKE ?", column("url")))
		args = append(args, "%"+urlFilter+"%")
	}
	if statusCode > 0 {
		conditions = append(conditions, fmt.Sprintf("%s = ?", column("status_code")))
		args = append(args, statusCode)
	} else if statusClass != "" {
		classLower := strings.ToLower(statusClass)
		switch classLower {
		case "2xx":
			conditions = append(conditions, fmt.Sprintf("%s >= 200 AND %s < 300", column("status_code"), column("status_code")))
		case "3xx":
			conditions = append(conditions, fmt.Sprintf("%s >= 300 AND %s < 400", column("status_code"), column("status_code")))
		case "4xx":
			conditions = append(conditions, fmt.Sprintf("%s >= 400 AND %s < 500", column("status_code"), column("status_code")))
		case "5xx":
			conditions = append(conditions, fmt.Sprintf("%s >= 500 AND %s < 600", column("status_code"), column("status_code")))
		}
	}
	if excludeInternal {
		internalCondition, internalArgs := buildInternalIPCondition(column("ip"))
		conditions = append(conditions, fmt.Sprintf("NOT %s", internalCondition))
		args = append(args, internalArgs...)
	}
	if pageviewOnly {
		conditions = append(conditions, fmt.Sprintf("%s = 1", column("pageview_flag")))
	}
	if includeNewVisitor {
		if newVisitorFilter == "new" {
			conditions = append(conditions, "fs.first_ts >= ? AND fs.first_ts < ?")
			args = append(args, newRangeStart, newRangeEnd)
		} else if newVisitorFilter == "returning" {
			conditions = append(conditions, "fs.first_ts < ?")
			args = append(args, newRangeStart)
		}
	}
	if distinctIP {
		var baseQuery strings.Builder
		if includeNewVisitor {
			baseQuery.WriteString(fmt.Sprintf(`
        WITH base AS (
            SELECT
                %s,
                CASE WHEN fs.first_ts >= ? AND fs.first_ts < ? THEN 1 ELSE 0 END AS is_new_visitor
            FROM "%s" %s
            %s
            %s`,
				selectColumnsWithAlias, tableName, logAlias, joinClause, firstSeenJoin))
			if len(conditions) > 0 {
				baseQuery.WriteString(" WHERE ")
				baseQuery.WriteString(strings.Join(conditions, " AND "))
			}
			baseQuery.WriteString("\n        )")
		} else {
			baseQuery.WriteString(fmt.Sprintf(`
        WITH base AS (
            SELECT
                %s
            FROM "%s" %s
            %s`,
				selectColumnsWithAlias, tableName, logAlias, joinClause))
			if len(conditions) > 0 {
				baseQuery.WriteString(" WHERE ")
				baseQuery.WriteString(strings.Join(conditions, " AND "))
			}
			baseQuery.WriteString("\n        )")
		}

		queryBuilder.WriteString(baseQuery.String())
		outerSelect := selectColumnsRaw
		if includeNewVisitor {
			outerSelect = outerSelect + ", is_new_visitor"
		}
		queryBuilder.WriteString(fmt.Sprintf(`
        SELECT %s FROM (
            SELECT base.*, ROW_NUMBER() OVER (PARTITION BY ip ORDER BY timestamp DESC, id DESC) AS rn
            FROM base
        )
        WHERE rn = 1`, outerSelect))
		queryBuilder.WriteString(fmt.Sprintf(" ORDER BY %s %s", sortField, sortOrder))
		queryBuilder.WriteString(" LIMIT ? OFFSET ?")
		if includeNewVisitor {
			args = append([]interface{}{newRangeStart, newRangeEnd}, args...)
		}
		args = append(args, pageSize, offset)
	} else {
		if len(conditions) > 0 {
			queryBuilder.WriteString(" WHERE ")
			queryBuilder.WriteString(strings.Join(conditions, " AND "))
		}

		// 添加排序
		orderField := column(sortField)
		queryBuilder.WriteString(fmt.Sprintf(" ORDER BY %s %s", orderField, sortOrder))

		// 添加分页
		queryBuilder.WriteString(" LIMIT ? OFFSET ?")
		args = append(args, pageSize, offset)
	}

	// 执行查询
	rows, err := m.repo.GetDB().Query(queryBuilder.String(), args...)
	if err != nil {
		return result, fmt.Errorf("查询日志失败: %v", err)
	}
	defer rows.Close()

	// 处理结果
	logs := make([]LogEntry, 0)
	for rows.Next() {
		var log LogEntry
		var pageviewFlag int
		var isNewVisitor int
		var err error

		if includeNewVisitor {
			err = rows.Scan(&log.ID, &log.IP, &log.Timestamp, &log.Method, &log.URL, &log.StatusCode,
				&log.BytesSent, &log.Referer, &log.UserBrowser, &log.UserOS, &log.UserDevice,
				&log.DomesticLocation, &log.GlobalLocation, &pageviewFlag, &isNewVisitor)
		} else {
			err = rows.Scan(&log.ID, &log.IP, &log.Timestamp, &log.Method, &log.URL, &log.StatusCode,
				&log.BytesSent, &log.Referer, &log.UserBrowser, &log.UserOS, &log.UserDevice,
				&log.DomesticLocation, &log.GlobalLocation, &pageviewFlag)
		}

		if err != nil {
			return result, fmt.Errorf("解析日志行失败: %v", err)
		}

		// 处理时间
		log.Time = time.Unix(log.Timestamp, 0).Format("2006-01-02 15:04:05")

		// 处理pageview_flag (SQLite中存储为0/1)
		log.PageviewFlag = pageviewFlag == 1
		if includeNewVisitor {
			log.IsNewVisitor = isNewVisitor == 1
		}

		logs = append(logs, log)
	}

	// 查询总记录数
	var countQuery strings.Builder
	needNewVisitorJoin := includeNewVisitor && newVisitorFilter != "all"
	if needNewVisitorJoin {
		countQuery.WriteString(fmt.Sprintf(`
        SELECT %s
        FROM "%s" %s
        %s
        %s`,
			countSelect(distinctIP), tableName, logAlias, joinClause, firstSeenJoin))
	} else {
		countQuery.WriteString(fmt.Sprintf(`SELECT %s FROM "%s" %s %s`, countSelect(distinctIP), tableName, logAlias, joinClause))
	}

	var countArgs []interface{}
	countConditions := make([]string, 0, 2)
	if filter != "" {
		countConditions = append(countConditions, fmt.Sprintf("(%s LIKE ? OR %s LIKE ? OR %s LIKE ? OR %s LIKE ?)",
			column("url"), column("ip"), column("referer"), column("domestic_location")))
		filterArg := "%" + filter + "%"
		countArgs = append(countArgs, filterArg, filterArg, filterArg, filterArg)
	}
	if timeRange != "" {
		startTime, endTime, err := timeutil.TimePeriod(timeRange)
		if err != nil {
			return result, fmt.Errorf("解析时间范围失败: %v", err)
		}
		countConditions = append(countConditions, fmt.Sprintf("%s >= ? AND %s < ?", column("timestamp"), column("timestamp")))
		countArgs = append(countArgs, startTime.Unix(), endTime.Unix())
	}
	if timeStart > 0 {
		countConditions = append(countConditions, fmt.Sprintf("%s >= ?", column("timestamp")))
		countArgs = append(countArgs, timeStart)
	}
	if timeEnd > 0 {
		countConditions = append(countConditions, fmt.Sprintf("%s <= ?", column("timestamp")))
		countArgs = append(countArgs, timeEnd)
	}
	if ipFilter != "" {
		countConditions = append(countConditions, fmt.Sprintf("%s LIKE ?", column("ip")))
		countArgs = append(countArgs, "%"+ipFilter+"%")
	}
	if locationFilter != "" {
		countConditions = append(countConditions, fmt.Sprintf("(%s LIKE ? OR %s LIKE ?)",
			column("domestic_location"), column("global_location")))
		locationArg := "%" + locationFilter + "%"
		countArgs = append(countArgs, locationArg, locationArg)
	}
	if urlFilter != "" {
		countConditions = append(countConditions, fmt.Sprintf("%s LIKE ?", column("url")))
		countArgs = append(countArgs, "%"+urlFilter+"%")
	}
	if statusCode > 0 {
		countConditions = append(countConditions, fmt.Sprintf("%s = ?", column("status_code")))
		countArgs = append(countArgs, statusCode)
	} else if statusClass != "" {
		classLower := strings.ToLower(statusClass)
		switch classLower {
		case "2xx":
			countConditions = append(countConditions, fmt.Sprintf("%s >= 200 AND %s < 300", column("status_code"), column("status_code")))
		case "3xx":
			countConditions = append(countConditions, fmt.Sprintf("%s >= 300 AND %s < 400", column("status_code"), column("status_code")))
		case "4xx":
			countConditions = append(countConditions, fmt.Sprintf("%s >= 400 AND %s < 500", column("status_code"), column("status_code")))
		case "5xx":
			countConditions = append(countConditions, fmt.Sprintf("%s >= 500 AND %s < 600", column("status_code"), column("status_code")))
		}
	}
	if excludeInternal {
		internalCondition, internalArgs := buildInternalIPCondition(column("ip"))
		countConditions = append(countConditions, fmt.Sprintf("NOT %s", internalCondition))
		countArgs = append(countArgs, internalArgs...)
	}
	if pageviewOnly {
		countConditions = append(countConditions, fmt.Sprintf("%s = 1", column("pageview_flag")))
	}
	if needNewVisitorJoin {
		if newVisitorFilter == "new" {
			countConditions = append(countConditions, "fs.first_ts >= ? AND fs.first_ts < ?")
			countArgs = append(countArgs, newRangeStart, newRangeEnd)
		} else if newVisitorFilter == "returning" {
			countConditions = append(countConditions, "fs.first_ts < ?")
			countArgs = append(countArgs, newRangeStart)
		}
	}
	if len(countConditions) > 0 {
		countQuery.WriteString(" WHERE ")
		countQuery.WriteString(strings.Join(countConditions, " AND "))
	}

	var total int
	err = m.repo.GetDB().QueryRow(countQuery.String(), countArgs...).Scan(&total)
	if err != nil {
		return result, fmt.Errorf("获取日志总数失败: %v", err)
	}

	// 设置返回结果
	result.Logs = logs
	result.Pagination.Total = total
	result.Pagination.Page = page
	result.Pagination.PageSize = pageSize
	result.Pagination.Pages = (total + pageSize - 1) / pageSize

	return result, nil
}

func countSelect(distinctIP bool) string {
	if distinctIP {
		return "COUNT(DISTINCT l.ip_id)"
	}
	return "COUNT(*)"
}

func parseTimeFilter(value string) (int64, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0, nil
	}
	if unixValue, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
		if unixValue > 1_000_000_000_000 {
			return unixValue / 1000, nil
		}
		return unixValue, nil
	}
	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04",
		"2006-01-02 15:04:05",
		"2006-01-02 15:04",
	}
	for _, layout := range layouts {
		parsed, err := time.ParseInLocation(layout, trimmed, time.Local)
		if err == nil {
			return parsed.Unix(), nil
		}
	}
	return 0, fmt.Errorf("不支持的时间格式")
}

func resolveNewVisitorRange(timeRange string, timeStart, timeEnd int64) (int64, int64, error) {
	if timeStart > 0 && timeEnd > 0 {
		return timeStart, timeEnd, nil
	}
	if timeRange != "" {
		startTime, endTime, err := timeutil.TimePeriod(timeRange)
		if err != nil {
			return 0, 0, fmt.Errorf("解析时间范围失败: %v", err)
		}
		return startTime.Unix(), endTime.Unix(), nil
	}
	if timeStart > 0 {
		return timeStart, time.Now().Unix(), nil
	}
	if timeEnd > 0 {
		return 0, timeEnd, nil
	}
	return 0, 0, nil
}

func resolveQueryRange(timeRange string, timeStart, timeEnd int64) (int64, int64, error) {
	var rangeStart int64
	var rangeEnd int64
	if timeRange != "" {
		startTime, endTime, err := timeutil.TimePeriod(timeRange)
		if err != nil {
			return 0, 0, fmt.Errorf("解析时间范围失败: %v", err)
		}
		rangeStart = startTime.Unix()
		rangeEnd = endTime.Unix()
	}
	if timeStart > 0 {
		if rangeStart == 0 || timeStart > rangeStart {
			rangeStart = timeStart
		}
	}
	if timeEnd > 0 {
		if rangeEnd == 0 || timeEnd < rangeEnd {
			rangeEnd = timeEnd
		}
	}
	return rangeStart, rangeEnd, nil
}

func computeParsingPending(
	status ingest.WebsiteParseStatus,
	rangeStart, rangeEnd int64,
) (bool, *TimeRange) {
	logMin := status.LogMinTs
	logMax := status.LogMaxTs
	if logMin <= 0 || logMax <= 0 || logMax < logMin {
		return false, nil
	}

	if rangeStart <= 0 {
		rangeStart = logMin
	}
	if rangeEnd <= 0 {
		rangeEnd = logMax
	}

	if rangeEnd < logMin || rangeStart > logMax {
		return false, nil
	}

	parsedMin := status.ParsedMinTs
	parsedMax := status.ParsedMaxTs
	if parsedMin == 0 && status.RecentCutoffTs > 0 {
		parsedMin = status.RecentCutoffTs
	}

	if parsedMin == 0 && parsedMax == 0 {
		return true, &TimeRange{Start: rangeStart, End: rangeEnd}
	}

	pending := false
	pendingStart := int64(0)
	pendingEnd := int64(0)

	if parsedMin > 0 && rangeStart < parsedMin {
		pending = true
		pendingStart = maxInt64(rangeStart, logMin)
		pendingEnd = minInt64(rangeEnd, parsedMin-1)
	}
	if parsedMax > 0 && rangeEnd > parsedMax {
		pending = true
		pendingStart = maxInt64(pendingStart, maxInt64(parsedMax+1, rangeStart))
		pendingEnd = maxInt64(pendingEnd, minInt64(rangeEnd, logMax))
	}

	if !pending {
		return false, nil
	}
	if pendingStart == 0 {
		pendingStart = rangeStart
	}
	if pendingEnd == 0 {
		pendingEnd = rangeEnd
	}
	if pendingEnd < pendingStart {
		return true, nil
	}
	return true, &TimeRange{Start: pendingStart, End: pendingEnd}
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func buildInternalIPCondition(column string) (string, []interface{}) {
	patterns := []string{
		"10.%", "127.%", "192.168.%",
		"172.16.%", "172.17.%", "172.18.%", "172.19.%", "172.20.%",
		"172.21.%", "172.22.%", "172.23.%", "172.24.%", "172.25.%",
		"172.26.%", "172.27.%", "172.28.%", "172.29.%", "172.30.%", "172.31.%",
		"fc%", "fd%", "fe80:%", "::1",
	}

	clauses := make([]string, 0, len(patterns))
	args := make([]interface{}, 0, len(patterns))
	for _, pattern := range patterns {
		if pattern == "::1" {
			clauses = append(clauses, fmt.Sprintf("%s = ?", column))
		} else {
			clauses = append(clauses, fmt.Sprintf("%s LIKE ?", column))
		}
		args = append(args, pattern)
	}
	return fmt.Sprintf("(%s)", strings.Join(clauses, " OR ")), args
}
