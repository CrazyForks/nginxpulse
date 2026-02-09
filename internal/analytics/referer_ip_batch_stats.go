package analytics

import (
	"fmt"

	"github.com/likaia/nginxpulse/internal/sqlutil"
	"github.com/likaia/nginxpulse/internal/store"
	"github.com/likaia/nginxpulse/internal/timeutil"
)

type RefererIPGroupStats struct {
	Key      []string  `json:"key"`
	UV       []int     `json:"uv"`
	Share    []float64 `json:"share"`
	Domestic []string  `json:"domestic"`
	Global   []string  `json:"global"`
	TotalUV  int       `json:"total_uv"`
}

type RefererIPBatchStats struct {
	All      RefererIPGroupStats `json:"all"`
	Search   RefererIPGroupStats `json:"search"`
	Direct   RefererIPGroupStats `json:"direct"`
	External RefererIPGroupStats `json:"external"`
}

func (s RefererIPBatchStats) GetType() string {
	return "referer_ip_batch"
}

type RefererIPBatchStatsManager struct {
	repo *store.Repository
}

func NewRefererIPBatchStatsManager(repo *store.Repository) *RefererIPBatchStatsManager {
	return &RefererIPBatchStatsManager{repo: repo}
}

func (m *RefererIPBatchStatsManager) Query(query StatsQuery) (StatsResult, error) {
	result := RefererIPBatchStats{}
	timeRange := query.ExtraParam["timeRange"].(string)
	limit, _ := query.ExtraParam["limit"].(int)
	if limit <= 0 {
		limit = 10
	}

	startTime, endTime, err := timeutil.TimePeriod(timeRange)
	if err != nil {
		return result, err
	}

	all, err := m.queryGroup(query.WebsiteID, startTime.Unix(), endTime.Unix(), limit, "all")
	if err != nil {
		return result, err
	}
	search, err := m.queryGroup(query.WebsiteID, startTime.Unix(), endTime.Unix(), limit, "search")
	if err != nil {
		return result, err
	}
	direct, err := m.queryGroup(query.WebsiteID, startTime.Unix(), endTime.Unix(), limit, "direct")
	if err != nil {
		return result, err
	}
	external, err := m.queryGroup(query.WebsiteID, startTime.Unix(), endTime.Unix(), limit, "external")
	if err != nil {
		return result, err
	}

	result.All = all
	result.Search = search
	result.Direct = direct
	result.External = external
	return result, nil
}

func (m *RefererIPBatchStatsManager) queryGroup(
	websiteID string,
	startUnix int64,
	endUnix int64,
	limit int,
	sourceKind string,
) (RefererIPGroupStats, error) {
	result := RefererIPGroupStats{
		Key:      make([]string, 0),
		UV:       make([]int, 0),
		Share:    make([]float64, 0),
		Domestic: make([]string, 0),
		Global:   make([]string, 0),
	}

	sourceCondition := buildRefererSourceCondition(sourceKind, "r.referer")
	extraCondition := ""
	if sourceCondition != "" {
		extraCondition = " AND " + sourceCondition
	}

	totalQuery := sqlutil.ReplacePlaceholders(fmt.Sprintf(`
        SELECT COUNT(*)
        FROM "%[1]s_nginx_logs" l
        JOIN "%[1]s_dim_referer" r ON r.id = l.referer_id
        WHERE l.pageview_flag = 1 AND l.timestamp >= ? AND l.timestamp < ?%[2]s`,
		websiteID, extraCondition))

	if err := m.repo.GetDB().QueryRow(totalQuery, startUnix, endUnix).Scan(&result.TotalUV); err != nil {
		return result, fmt.Errorf("查询来源IP总量失败: %v", err)
	}

	querySQL := sqlutil.ReplacePlaceholders(fmt.Sprintf(`
        WITH filtered AS (
            SELECT l.ip_id, ip.ip, l.location_id
            FROM "%[1]s_nginx_logs" l
            JOIN "%[1]s_dim_ip" ip ON ip.id = l.ip_id
            JOIN "%[1]s_dim_referer" r ON r.id = l.referer_id
            WHERE l.pageview_flag = 1 AND l.timestamp >= ? AND l.timestamp < ?%[2]s
        ),
        ip_counts AS (
            SELECT ip_id, ip, COUNT(*) AS uv
            FROM filtered
            GROUP BY ip_id, ip
        ),
        top_ips AS (
            SELECT ip_id, ip, uv
            FROM ip_counts
            ORDER BY uv DESC, ip ASC
            LIMIT ?
        ),
        location_rank AS (
            SELECT
                f.ip_id,
                COALESCE(loc.domestic, '-') AS domestic,
                COALESCE(loc.global, '-') AS global,
                COUNT(*) AS location_count,
                ROW_NUMBER() OVER (
                    PARTITION BY f.ip_id
                    ORDER BY COUNT(*) DESC, COALESCE(loc.global, '-') ASC, COALESCE(loc.domestic, '-') ASC
                ) AS rn
            FROM filtered f
            LEFT JOIN "%[1]s_dim_location" loc ON loc.id = f.location_id
            JOIN top_ips t ON t.ip_id = f.ip_id
            GROUP BY f.ip_id, COALESCE(loc.domestic, '-'), COALESCE(loc.global, '-')
        )
        SELECT
            t.ip,
            t.uv,
            COALESCE(lr.domestic, '-') AS domestic,
            COALESCE(lr.global, '-') AS global
        FROM top_ips t
        LEFT JOIN location_rank lr ON lr.ip_id = t.ip_id AND lr.rn = 1
        ORDER BY t.uv DESC, t.ip ASC`,
		websiteID, extraCondition))

	rows, err := m.repo.GetDB().Query(querySQL, startUnix, endUnix, limit)
	if err != nil {
		return result, fmt.Errorf("查询来源IP排行失败: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			ip       string
			uv       int
			domestic string
			global   string
		)
		if err := rows.Scan(&ip, &uv, &domestic, &global); err != nil {
			return result, fmt.Errorf("解析来源IP排行失败: %v", err)
		}
		result.Key = append(result.Key, ip)
		result.UV = append(result.UV, uv)
		result.Domestic = append(result.Domestic, domestic)
		result.Global = append(result.Global, global)
		if result.TotalUV <= 0 {
			result.Share = append(result.Share, 0)
		} else {
			result.Share = append(result.Share, float64(uv)/float64(result.TotalUV))
		}
	}
	if err := rows.Err(); err != nil {
		return result, fmt.Errorf("遍历来源IP排行失败: %v", err)
	}

	return result, nil
}
