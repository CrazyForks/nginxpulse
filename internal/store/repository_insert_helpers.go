package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/likaia/nginxpulse/internal/sqlutil"
)

func getOrCreateDimID(
	cache map[string]int64,
	insertStmt *sql.Stmt,
	selectStmt *sql.Stmt,
	cacheKey string,
	args ...any,
) (int64, error) {
	if id, ok := cache[cacheKey]; ok {
		return id, nil
	}
	if _, err := insertStmt.Exec(args...); err != nil {
		return 0, err
	}
	var id int64
	if err := selectStmt.QueryRow(args...).Scan(&id); err != nil {
		return 0, err
	}
	cache[cacheKey] = id
	return id, nil
}

func uaCacheKey(browser, osName, device string) string {
	return browser + "\x1f" + osName + "\x1f" + device
}

func locationCacheKey(domestic, global string) string {
	return domestic + "\x1f" + global
}

func fetchIPIDs(tx *sql.Tx, websiteID string, ips []string) (map[string]int64, error) {
	results := make(map[string]int64)
	if len(ips) == 0 {
		return results, nil
	}

	unique := make([]string, 0, len(ips))
	seen := make(map[string]struct{}, len(ips))
	for _, raw := range ips {
		ip := strings.TrimSpace(raw)
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
		return results, nil
	}

	placeholders := make([]string, len(unique))
	args := make([]interface{}, len(unique))
	for i, ip := range unique {
		placeholders[i] = "?"
		args[i] = ip
	}

	query := fmt.Sprintf(`SELECT id, ip FROM "%s_dim_ip" WHERE ip IN (%s)`, websiteID, strings.Join(placeholders, ","))
	rows, err := tx.Query(sqlutil.ReplacePlaceholders(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			id int64
			ip string
		)
		if err := rows.Scan(&id, &ip); err != nil {
			return nil, err
		}
		results[ip] = id
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

func (b *aggBatch) add(log NginxLogRecord, ipID int64) {
	if b == nil {
		return
	}
	hour := hourBucket(log.Timestamp)
	day := dayBucket(log.Timestamp)

	hourCounts := b.hourly[hour]
	if hourCounts == nil {
		hourCounts = &aggCounts{}
		b.hourly[hour] = hourCounts
	}
	dayCounts := b.daily[day]
	if dayCounts == nil {
		dayCounts = &aggCounts{}
		b.daily[day] = dayCounts
	}

	addCounts(hourCounts, log)
	addCounts(dayCounts, log)

	if log.PageviewFlag == 1 {
		if b.hourlyIPs[hour] == nil {
			b.hourlyIPs[hour] = make(map[int64]struct{})
		}
		b.hourlyIPs[hour][ipID] = struct{}{}
		if b.dailyIPs[day] == nil {
			b.dailyIPs[day] = make(map[int64]struct{})
		}
		b.dailyIPs[day][ipID] = struct{}{}
	}
}

func addCounts(counts *aggCounts, log NginxLogRecord) {
	if counts == nil {
		return
	}
	if log.PageviewFlag == 1 {
		counts.pv++
		counts.traffic += int64(log.BytesSent)
	}
	switch {
	case log.Status >= 200 && log.Status < 300:
		counts.s2xx++
	case log.Status >= 300 && log.Status < 400:
		counts.s3xx++
	case log.Status >= 400 && log.Status < 500:
		counts.s4xx++
	case log.Status >= 500 && log.Status < 600:
		counts.s5xx++
	default:
		counts.other++
	}
}

func updateSessionFromLog(
	stmts *sessionStatements,
	cache map[string]sessionState,
	sessionAggDaily map[string]int64,
	sessionAggEntry map[string]map[int64]int64,
	sessionUpdates map[int64]*pendingSessionUpdate,
	sessionStateUpserts map[string]pendingSessionStateUpsert,
	lockedSessionKeys map[string]struct{},
	ipID,
	uaID,
	locationID,
	urlID int64,
	timestamp int64,
) error {
	if stmts == nil {
		return nil
	}
	key := fmt.Sprintf("%d|%d", ipID, uaID)

	// 关键：按 (ip_id, ua_id) 串行化会话写入，避免多个并发事务同时更新同一会话链路导致 tuple/transactionid 锁等待甚至死锁。
	if stmts.lockSessionKey != nil && lockedSessionKeys != nil {
		if _, ok := lockedSessionKeys[key]; !ok {
			if _, err := stmts.lockSessionKey.Exec(ipID, uaID); err != nil {
				return err
			}
			lockedSessionKeys[key] = struct{}{}
		}
	}

	state, ok := cache[key]
	if !ok {
		var sessionID int64
		var lastTs int64
		if err := stmts.selectState.QueryRow(ipID, uaID).Scan(&sessionID, &lastTs); err == nil {
			state = sessionState{sessionID: sessionID, lastTs: lastTs}
		}
	}

	if state.sessionID != 0 && timestamp < state.lastTs {
		return nil
	}

	if state.sessionID == 0 || timestamp-state.lastTs > sessionGapSeconds {
		var sessionID int64
		if err := stmts.insertSession.QueryRow(
			ipID,
			uaID,
			locationID,
			timestamp,
			timestamp,
			urlID,
			urlID,
			1,
		).Scan(&sessionID); err != nil {
			return err
		}
		day := dayBucket(time.Unix(timestamp, 0))
		// 不在这里直接 upsert 聚合，避免高并发下反复争抢同一天的聚合行。
		// 改为“内存累加”，在事务提交前的收敛阶段一次性落库，并用 advisory lock 按天串行化。
		if sessionAggDaily != nil {
			sessionAggDaily[day]++
		}
		if sessionAggEntry != nil {
			if sessionAggEntry[day] == nil {
				sessionAggEntry[day] = make(map[int64]int64)
			}
			sessionAggEntry[day][urlID]++
		}
		state = sessionState{sessionID: sessionID, lastTs: timestamp}
	} else {
		// 不在循环里直接 UPDATE sessions：避免后续维表 INSERT/锁等待期间提前持有 session 行锁。
		// 这里改为按 session_id 累加更新：end_ts 取最后一次的 timestamp，exit_url_id 取最后一次 url_id，page_count 增量累加。
		if sessionUpdates != nil {
			upd := sessionUpdates[state.sessionID]
			if upd == nil {
				upd = &pendingSessionUpdate{}
				sessionUpdates[state.sessionID] = upd
			}
			upd.endTs = timestamp
			upd.exitURLID = urlID
			upd.pageCountDelta++
		}
		state.lastTs = timestamp
	}

	// session_state 同理：收敛到事务末尾一次性 upsert，降低写放大与锁竞争。
	if sessionStateUpserts != nil {
		sessionStateUpserts[key] = pendingSessionStateUpsert{
			ipID:      ipID,
			uaID:      uaID,
			sessionID: state.sessionID,
			lastTs:    state.lastTs,
		}
	}
	cache[key] = state
	return nil
}

func hourBucket(ts time.Time) int64 {
	local := ts.In(time.Local)
	start := time.Date(local.Year(), local.Month(), local.Day(), local.Hour(), 0, 0, 0, local.Location())
	return start.Unix()
}

func dayBucket(ts time.Time) string {
	return ts.In(time.Local).Format("2006-01-02")
}
