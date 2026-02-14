package store

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"

	"github.com/likaia/nginxpulse/internal/sqlutil"
)

type sqlExecer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

type dimStatements struct {
	insertIP       *sql.Stmt
	selectIP       *sql.Stmt
	insertURL      *sql.Stmt
	selectURL      *sql.Stmt
	insertReferer  *sql.Stmt
	selectReferer  *sql.Stmt
	insertUA       *sql.Stmt
	selectUA       *sql.Stmt
	insertLocation *sql.Stmt
	selectLocation *sql.Stmt
}

type dimCaches struct {
	ip       map[string]int64
	url      map[string]int64
	referer  map[string]int64
	ua       map[string]int64
	location map[string]int64
}

type aggStatements struct {
	upsertHourly   *sql.Stmt
	upsertDaily    *sql.Stmt
	insertHourlyIP *sql.Stmt
	insertDailyIP  *sql.Stmt
}

type sessionStatements struct {
	selectState         *sql.Stmt
	upsertState         *sql.Stmt
	insertSession       *sql.Stmt
	updateSession       *sql.Stmt
	lockSessionKey      *sql.Stmt
	lockAggSessionDaily *sql.Stmt
	upsertDaily         *sql.Stmt
	upsertEntryDaily    *sql.Stmt
}

type aggCounts struct {
	pv      int64
	traffic int64
	s2xx    int64
	s3xx    int64
	s4xx    int64
	s5xx    int64
	other   int64
}

type aggBatch struct {
	hourly    map[int64]*aggCounts
	daily     map[string]*aggCounts
	hourlyIPs map[int64]map[int64]struct{}
	dailyIPs  map[string]map[int64]struct{}
}

type sessionState struct {
	sessionID int64
	lastTs    int64
}

type pendingSessionUpdate struct {
	endTs          int64
	exitURLID      int64
	pageCountDelta int64
}

type pendingSessionStateUpsert struct {
	ipID      int64
	uaID      int64
	sessionID int64
	lastTs    int64
}

type logInsertRow struct {
	ipID         int64
	pageviewFlag int
	timestamp    int64
	method       string
	urlID        int64
	statusCode   int
	bytesSent    int
	refererID    int64
	uaID         int64
	locationID   int64
}

const sessionGapSeconds = int64(1800)

func newDimCaches() dimCaches {
	return dimCaches{
		ip:       make(map[string]int64),
		url:      make(map[string]int64),
		referer:  make(map[string]int64),
		ua:       make(map[string]int64),
		location: make(map[string]int64),
	}
}

func newAggBatch() *aggBatch {
	return &aggBatch{
		hourly:    make(map[int64]*aggCounts),
		daily:     make(map[string]*aggCounts),
		hourlyIPs: make(map[int64]map[int64]struct{}),
		dailyIPs:  make(map[string]map[int64]struct{}),
	}
}

func (d *dimStatements) Close() {
	closeStmt := func(stmt *sql.Stmt) {
		if stmt != nil {
			stmt.Close()
		}
	}
	closeStmt(d.insertIP)
	closeStmt(d.selectIP)
	closeStmt(d.insertURL)
	closeStmt(d.selectURL)
	closeStmt(d.insertReferer)
	closeStmt(d.selectReferer)
	closeStmt(d.insertUA)
	closeStmt(d.selectUA)
	closeStmt(d.insertLocation)
	closeStmt(d.selectLocation)
}

func (a *aggStatements) Close() {
	closeStmt := func(stmt *sql.Stmt) {
		if stmt != nil {
			stmt.Close()
		}
	}
	closeStmt(a.upsertHourly)
	closeStmt(a.upsertDaily)
	closeStmt(a.insertHourlyIP)
	closeStmt(a.insertDailyIP)
}

func (s *sessionStatements) Close() {
	closeStmt := func(stmt *sql.Stmt) {
		if stmt != nil {
			stmt.Close()
		}
	}
	closeStmt(s.selectState)
	closeStmt(s.upsertState)
	closeStmt(s.insertSession)
	closeStmt(s.updateSession)
	closeStmt(s.lockSessionKey)
	closeStmt(s.lockAggSessionDaily)
	closeStmt(s.upsertDaily)
	closeStmt(s.upsertEntryDaily)
}

func prepareDimStatements(tx *sql.Tx, websiteID string) (*dimStatements, error) {
	ipTable := fmt.Sprintf("%s_dim_ip", websiteID)
	urlTable := fmt.Sprintf("%s_dim_url", websiteID)
	refererTable := fmt.Sprintf("%s_dim_referer", websiteID)
	uaTable := fmt.Sprintf("%s_dim_ua", websiteID)
	locationTable := fmt.Sprintf("%s_dim_location", websiteID)

	insertIP, err := tx.Prepare(sqlutil.ReplacePlaceholders(
		fmt.Sprintf(`INSERT INTO "%s" (ip) VALUES (?) ON CONFLICT DO NOTHING`, ipTable),
	))
	if err != nil {
		return nil, err
	}
	selectIP, err := tx.Prepare(sqlutil.ReplacePlaceholders(
		fmt.Sprintf(`SELECT id FROM "%s" WHERE ip = ?`, ipTable),
	))
	if err != nil {
		insertIP.Close()
		return nil, err
	}

	insertURL, err := tx.Prepare(sqlutil.ReplacePlaceholders(
		fmt.Sprintf(`INSERT INTO "%s" (url) VALUES (?) ON CONFLICT DO NOTHING`, urlTable),
	))
	if err != nil {
		selectIP.Close()
		insertIP.Close()
		return nil, err
	}
	selectURL, err := tx.Prepare(sqlutil.ReplacePlaceholders(
		fmt.Sprintf(`SELECT id FROM "%s" WHERE url = ?`, urlTable),
	))
	if err != nil {
		insertURL.Close()
		selectIP.Close()
		insertIP.Close()
		return nil, err
	}

	insertReferer, err := tx.Prepare(sqlutil.ReplacePlaceholders(
		fmt.Sprintf(`INSERT INTO "%s" (referer) VALUES (?) ON CONFLICT DO NOTHING`, refererTable),
	))
	if err != nil {
		selectURL.Close()
		insertURL.Close()
		selectIP.Close()
		insertIP.Close()
		return nil, err
	}
	selectReferer, err := tx.Prepare(sqlutil.ReplacePlaceholders(
		fmt.Sprintf(`SELECT id FROM "%s" WHERE referer = ?`, refererTable),
	))
	if err != nil {
		insertReferer.Close()
		selectURL.Close()
		insertURL.Close()
		selectIP.Close()
		insertIP.Close()
		return nil, err
	}

	insertUA, err := tx.Prepare(sqlutil.ReplacePlaceholders(fmt.Sprintf(
		`INSERT INTO "%s" (browser, os, device) VALUES (?, ?, ?) ON CONFLICT DO NOTHING`, uaTable,
	)))
	if err != nil {
		selectReferer.Close()
		insertReferer.Close()
		selectURL.Close()
		insertURL.Close()
		selectIP.Close()
		insertIP.Close()
		return nil, err
	}
	selectUA, err := tx.Prepare(sqlutil.ReplacePlaceholders(fmt.Sprintf(
		`SELECT id FROM "%s" WHERE browser = ? AND os = ? AND device = ?`, uaTable,
	)))
	if err != nil {
		insertUA.Close()
		selectReferer.Close()
		insertReferer.Close()
		selectURL.Close()
		insertURL.Close()
		selectIP.Close()
		insertIP.Close()
		return nil, err
	}

	insertLocation, err := tx.Prepare(sqlutil.ReplacePlaceholders(fmt.Sprintf(
		`INSERT INTO "%s" (domestic, global) VALUES (?, ?) ON CONFLICT DO NOTHING`, locationTable,
	)))
	if err != nil {
		selectUA.Close()
		insertUA.Close()
		selectReferer.Close()
		insertReferer.Close()
		selectURL.Close()
		insertURL.Close()
		selectIP.Close()
		insertIP.Close()
		return nil, err
	}
	selectLocation, err := tx.Prepare(sqlutil.ReplacePlaceholders(fmt.Sprintf(
		`SELECT id FROM "%s" WHERE domestic = ? AND global = ?`, locationTable,
	)))
	if err != nil {
		insertLocation.Close()
		selectUA.Close()
		insertUA.Close()
		selectReferer.Close()
		insertReferer.Close()
		selectURL.Close()
		insertURL.Close()
		selectIP.Close()
		insertIP.Close()
		return nil, err
	}

	return &dimStatements{
		insertIP:       insertIP,
		selectIP:       selectIP,
		insertURL:      insertURL,
		selectURL:      selectURL,
		insertReferer:  insertReferer,
		selectReferer:  selectReferer,
		insertUA:       insertUA,
		selectUA:       selectUA,
		insertLocation: insertLocation,
		selectLocation: selectLocation,
	}, nil
}

func prepareAggStatements(tx *sql.Tx, websiteID string) (*aggStatements, error) {
	hourlyTable := fmt.Sprintf("%s_agg_hourly", websiteID)
	dailyTable := fmt.Sprintf("%s_agg_daily", websiteID)
	hourlyIPTable := fmt.Sprintf("%s_agg_hourly_ip", websiteID)
	dailyIPTable := fmt.Sprintf("%s_agg_daily_ip", websiteID)

	upsertHourly, err := tx.Prepare(sqlutil.ReplacePlaceholders(fmt.Sprintf(
		`INSERT INTO "%s" (bucket, pv, traffic, s2xx, s3xx, s4xx, s5xx, other)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(bucket) DO UPDATE SET
             pv = "%s".pv + excluded.pv,
             traffic = "%s".traffic + excluded.traffic,
             s2xx = "%s".s2xx + excluded.s2xx,
             s3xx = "%s".s3xx + excluded.s3xx,
             s4xx = "%s".s4xx + excluded.s4xx,
             s5xx = "%s".s5xx + excluded.s5xx,
             other = "%s".other + excluded.other`, hourlyTable, hourlyTable, hourlyTable, hourlyTable, hourlyTable, hourlyTable, hourlyTable, hourlyTable,
	)))
	if err != nil {
		return nil, err
	}

	upsertDaily, err := tx.Prepare(sqlutil.ReplacePlaceholders(fmt.Sprintf(
		`INSERT INTO "%s" (day, pv, traffic, s2xx, s3xx, s4xx, s5xx, other)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(day) DO UPDATE SET
             pv = "%s".pv + excluded.pv,
             traffic = "%s".traffic + excluded.traffic,
             s2xx = "%s".s2xx + excluded.s2xx,
             s3xx = "%s".s3xx + excluded.s3xx,
             s4xx = "%s".s4xx + excluded.s4xx,
             s5xx = "%s".s5xx + excluded.s5xx,
             other = "%s".other + excluded.other`, dailyTable, dailyTable, dailyTable, dailyTable, dailyTable, dailyTable, dailyTable, dailyTable,
	)))
	if err != nil {
		upsertHourly.Close()
		return nil, err
	}

	insertHourlyIP, err := tx.Prepare(sqlutil.ReplacePlaceholders(fmt.Sprintf(
		`INSERT INTO "%s" (bucket, ip_id) VALUES (?, ?) ON CONFLICT DO NOTHING`, hourlyIPTable,
	)))
	if err != nil {
		upsertDaily.Close()
		upsertHourly.Close()
		return nil, err
	}

	insertDailyIP, err := tx.Prepare(sqlutil.ReplacePlaceholders(fmt.Sprintf(
		`INSERT INTO "%s" (day, ip_id) VALUES (?, ?) ON CONFLICT DO NOTHING`, dailyIPTable,
	)))
	if err != nil {
		insertHourlyIP.Close()
		upsertDaily.Close()
		upsertHourly.Close()
		return nil, err
	}

	return &aggStatements{
		upsertHourly:   upsertHourly,
		upsertDaily:    upsertDaily,
		insertHourlyIP: insertHourlyIP,
		insertDailyIP:  insertDailyIP,
	}, nil
}

func prepareFirstSeenStatement(tx *sql.Tx, websiteID string) (*sql.Stmt, error) {
	table := fmt.Sprintf("%s_first_seen", websiteID)
	return tx.Prepare(sqlutil.ReplacePlaceholders(fmt.Sprintf(
		`INSERT INTO "%s" (ip_id, first_ts)
         VALUES (?, ?)
         ON CONFLICT (ip_id) DO UPDATE SET
             first_ts = CASE
                 WHEN excluded.first_ts < "%s".first_ts THEN excluded.first_ts
                 ELSE "%s".first_ts
             END`, table, table, table,
	)))
}

func prepareSessionStatements(tx *sql.Tx, websiteID string) (*sessionStatements, error) {
	stateTable := fmt.Sprintf("%s_session_state", websiteID)
	sessionTable := fmt.Sprintf("%s_sessions", websiteID)
	dailyTable := fmt.Sprintf("%s_agg_session_daily", websiteID)
	entryTable := fmt.Sprintf("%s_agg_entry_daily", websiteID)

	selectState, err := tx.Prepare(sqlutil.ReplacePlaceholders(fmt.Sprintf(
		`SELECT session_id, last_ts FROM "%s" WHERE ip_id = ? AND ua_id = ?`, stateTable,
	)))
	if err != nil {
		return nil, err
	}

	upsertState, err := tx.Prepare(sqlutil.ReplacePlaceholders(fmt.Sprintf(
		`INSERT INTO "%s" (ip_id, ua_id, session_id, last_ts)
         VALUES (?, ?, ?, ?)
         ON CONFLICT (ip_id, ua_id) DO UPDATE SET
             session_id = excluded.session_id,
             last_ts = excluded.last_ts`, stateTable,
	)))
	if err != nil {
		selectState.Close()
		return nil, err
	}

	insertSession, err := tx.Prepare(sqlutil.ReplacePlaceholders(fmt.Sprintf(
		`INSERT INTO "%s" (ip_id, ua_id, location_id, start_ts, end_ts, entry_url_id, exit_url_id, page_count)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         RETURNING id`, sessionTable,
	)))
	if err != nil {
		upsertState.Close()
		selectState.Close()
		return nil, err
	}

	updateSession, err := tx.Prepare(sqlutil.ReplacePlaceholders(fmt.Sprintf(
		`UPDATE "%s" SET end_ts = ?, exit_url_id = ?, page_count = page_count + ? WHERE id = ?`, sessionTable,
	)))
	if err != nil {
		insertSession.Close()
		upsertState.Close()
		selectState.Close()
		return nil, err
	}

	lockSessionKey, err := tx.Prepare(sqlutil.ReplacePlaceholders(fmt.Sprintf(
		`SELECT pg_advisory_xact_lock(hashtext('%s:session'), (hashint8(?) # hashint8(?)))`,
		websiteID,
	)))
	if err != nil {
		updateSession.Close()
		insertSession.Close()
		upsertState.Close()
		selectState.Close()
		return nil, err
	}

	lockAggSessionDaily, err := tx.Prepare(sqlutil.ReplacePlaceholders(fmt.Sprintf(
		`SELECT pg_advisory_xact_lock(hashtext('%s:agg_session_daily'), hashtext(?))`,
		websiteID,
	)))
	if err != nil {
		lockSessionKey.Close()
		updateSession.Close()
		insertSession.Close()
		upsertState.Close()
		selectState.Close()
		return nil, err
	}

	upsertDaily, err := tx.Prepare(sqlutil.ReplacePlaceholders(fmt.Sprintf(
		`INSERT INTO "%s" (day, sessions)
         VALUES (?, ?)
         ON CONFLICT (day) DO UPDATE SET
             sessions = "%s".sessions + excluded.sessions`, dailyTable, dailyTable,
	)))
	if err != nil {
		lockAggSessionDaily.Close()
		lockSessionKey.Close()
		updateSession.Close()
		insertSession.Close()
		upsertState.Close()
		selectState.Close()
		return nil, err
	}

	upsertEntryDaily, err := tx.Prepare(sqlutil.ReplacePlaceholders(fmt.Sprintf(
		`INSERT INTO "%s" (day, entry_url_id, count)
         VALUES (?, ?, ?)
         ON CONFLICT (day, entry_url_id) DO UPDATE SET
             count = "%s".count + excluded.count`, entryTable, entryTable,
	)))
	if err != nil {
		upsertDaily.Close()
		lockAggSessionDaily.Close()
		lockSessionKey.Close()
		updateSession.Close()
		insertSession.Close()
		upsertState.Close()
		selectState.Close()
		return nil, err
	}

	return &sessionStatements{
		selectState:         selectState,
		upsertState:         upsertState,
		insertSession:       insertSession,
		updateSession:       updateSession,
		lockSessionKey:      lockSessionKey,
		lockAggSessionDaily: lockAggSessionDaily,
		upsertDaily:         upsertDaily,
		upsertEntryDaily:    upsertEntryDaily,
	}, nil
}

func applySessionAggUpdatesWithLocks(
	stmts *sessionStatements,
	sessionAggDaily map[string]int64,
	sessionAggEntry map[string]map[int64]int64,
) error {
	if stmts == nil {
		return nil
	}
	if len(sessionAggDaily) == 0 && len(sessionAggEntry) == 0 {
		return nil
	}

	daySet := make(map[string]struct{}, len(sessionAggDaily)+len(sessionAggEntry))
	for day := range sessionAggDaily {
		daySet[day] = struct{}{}
	}
	for day := range sessionAggEntry {
		daySet[day] = struct{}{}
	}
	days := make([]string, 0, len(daySet))
	for day := range daySet {
		days = append(days, day)
	}
	sort.Strings(days)

	for _, day := range days {
		// 关键：按天加 advisory lock，确保不同事务对同一天聚合行的写入串行化，避免死锁。
		// 这里是“收敛阶段”才加锁，锁持有时间最短（只覆盖聚合落库这几条语句）。
		if stmts.lockAggSessionDaily != nil {
			if _, err := stmts.lockAggSessionDaily.Exec(day); err != nil {
				return err
			}
		}

		if stmts.upsertDaily != nil {
			if delta := sessionAggDaily[day]; delta > 0 {
				if _, err := stmts.upsertDaily.Exec(day, delta); err != nil {
					return err
				}
			}
		}

		if stmts.upsertEntryDaily != nil {
			entryDelta := sessionAggEntry[day]
			if len(entryDelta) > 0 {
				entryIDs := make([]int64, 0, len(entryDelta))
				for entryID := range entryDelta {
					entryIDs = append(entryIDs, entryID)
				}
				sort.Slice(entryIDs, func(i, j int) bool { return entryIDs[i] < entryIDs[j] })
				for _, entryID := range entryIDs {
					delta := entryDelta[entryID]
					if delta <= 0 {
						continue
					}
					if _, err := stmts.upsertEntryDaily.Exec(day, entryID, delta); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func applySessionUpdates(
	stmts *sessionStatements,
	updates map[int64]*pendingSessionUpdate,
) error {
	if stmts == nil || stmts.updateSession == nil || len(updates) == 0 {
		return nil
	}
	ids := make([]int64, 0, len(updates))
	for id := range updates {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		upd := updates[id]
		if upd == nil || upd.pageCountDelta <= 0 {
			continue
		}
		if _, err := stmts.updateSession.Exec(upd.endTs, upd.exitURLID, upd.pageCountDelta, id); err != nil {
			return err
		}
	}
	return nil
}

func applySessionStateUpserts(
	stmts *sessionStatements,
	upserts map[string]pendingSessionStateUpsert,
) error {
	if stmts == nil || stmts.upsertState == nil || len(upserts) == 0 {
		return nil
	}
	keys := make([]string, 0, len(upserts))
	for k := range upserts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		u := upserts[k]
		if u.ipID == 0 || u.uaID == 0 || u.sessionID == 0 || u.lastTs == 0 {
			continue
		}
		if _, err := stmts.upsertState.Exec(u.ipID, u.uaID, u.sessionID, u.lastTs); err != nil {
			return err
		}
	}
	return nil
}

func applyAggUpdates(aggs *aggStatements, batch *aggBatch) error {
	if aggs == nil || batch == nil {
		return nil
	}

	// 注意：map 遍历顺序是随机的，不同事务可能以不同顺序对相同 key 做 upsert，容易造成锁顺序不一致进而死锁。
	// 因此这里对 key 做排序，确保锁获取顺序稳定。
	if len(batch.hourly) > 0 {
		buckets := make([]int64, 0, len(batch.hourly))
		for bucket := range batch.hourly {
			buckets = append(buckets, bucket)
		}
		sort.Slice(buckets, func(i, j int) bool { return buckets[i] < buckets[j] })
		for _, bucket := range buckets {
			counts := batch.hourly[bucket]
			if counts == nil {
				continue
			}
			if _, err := aggs.upsertHourly.Exec(
				bucket,
				counts.pv,
				counts.traffic,
				counts.s2xx,
				counts.s3xx,
				counts.s4xx,
				counts.s5xx,
				counts.other,
			); err != nil {
				return err
			}
		}
	}

	if len(batch.daily) > 0 {
		days := make([]string, 0, len(batch.daily))
		for day := range batch.daily {
			days = append(days, day)
		}
		sort.Strings(days)
		for _, day := range days {
			counts := batch.daily[day]
			if counts == nil {
				continue
			}
			if _, err := aggs.upsertDaily.Exec(
				day,
				counts.pv,
				counts.traffic,
				counts.s2xx,
				counts.s3xx,
				counts.s4xx,
				counts.s5xx,
				counts.other,
			); err != nil {
				return err
			}
		}
	}

	if len(batch.hourlyIPs) > 0 {
		buckets := make([]int64, 0, len(batch.hourlyIPs))
		for bucket := range batch.hourlyIPs {
			buckets = append(buckets, bucket)
		}
		sort.Slice(buckets, func(i, j int) bool { return buckets[i] < buckets[j] })
		for _, bucket := range buckets {
			ips := batch.hourlyIPs[bucket]
			if len(ips) == 0 {
				continue
			}
			ipIDs := make([]int64, 0, len(ips))
			for ipID := range ips {
				ipIDs = append(ipIDs, ipID)
			}
			sort.Slice(ipIDs, func(i, j int) bool { return ipIDs[i] < ipIDs[j] })
			for _, ipID := range ipIDs {
				if _, err := aggs.insertHourlyIP.Exec(bucket, ipID); err != nil {
					return err
				}
			}
		}
	}

	if len(batch.dailyIPs) > 0 {
		days := make([]string, 0, len(batch.dailyIPs))
		for day := range batch.dailyIPs {
			days = append(days, day)
		}
		sort.Strings(days)
		for _, day := range days {
			ips := batch.dailyIPs[day]
			if len(ips) == 0 {
				continue
			}
			ipIDs := make([]int64, 0, len(ips))
			for ipID := range ips {
				ipIDs = append(ipIDs, ipID)
			}
			sort.Slice(ipIDs, func(i, j int) bool { return ipIDs[i] < ipIDs[j] })
			for _, ipID := range ipIDs {
				if _, err := aggs.insertDailyIP.Exec(day, ipID); err != nil {
					return err
				}
			}
		}
	}

	return nil

	// 旧实现（保留注释，便于回溯）：
	/*
		for bucket, counts := range batch.hourly {
			if counts == nil {
				continue
			}
			if _, err := aggs.upsertHourly.Exec(
				bucket,
				counts.pv,
				counts.traffic,
				counts.s2xx,
				counts.s3xx,
				counts.s4xx,
				counts.s5xx,
				counts.other,
			); err != nil {
				return err
			}
		}

		for day, counts := range batch.daily {
			if counts == nil {
				continue
			}
			if _, err := aggs.upsertDaily.Exec(
				day,
				counts.pv,
				counts.traffic,
				counts.s2xx,
				counts.s3xx,
				counts.s4xx,
				counts.s5xx,
				counts.other,
			); err != nil {
				return err
			}
		}

		for bucket, ips := range batch.hourlyIPs {
			for ipID := range ips {
				if _, err := aggs.insertHourlyIP.Exec(bucket, ipID); err != nil {
					return err
				}
			}
		}

		for day, ips := range batch.dailyIPs {
			for ipID := range ips {
				if _, err := aggs.insertDailyIP.Exec(day, ipID); err != nil {
					return err
				}
			}
		}

		return nil
	*/
}

func bulkInsertLogRows(tx *sql.Tx, logTable string, rows []logInsertRow) error {
	if len(rows) == 0 {
		return nil
	}

	const (
		columnCount = 10
		// PostgreSQL 参数上限是 65535，预留余量避免触边界。
		maxParams = 60000
	)
	chunkSize := maxParams / columnCount
	if chunkSize <= 0 {
		chunkSize = 1
	}

	for start := 0; start < len(rows); start += chunkSize {
		end := start + chunkSize
		if end > len(rows) {
			end = len(rows)
		}
		if err := bulkInsertLogRowsChunk(tx, logTable, rows[start:end]); err != nil {
			return err
		}
	}
	return nil
}

func bulkInsertLogRowsChunk(tx *sql.Tx, logTable string, rows []logInsertRow) error {
	if len(rows) == 0 {
		return nil
	}

	var query strings.Builder
	query.Grow(200 + len(rows)*32)
	query.WriteString(`INSERT INTO "`)
	query.WriteString(logTable)
	query.WriteString(`" (
        ip_id, pageview_flag, timestamp, method, url_id,
        status_code, bytes_sent, referer_id, ua_id, location_id
    ) VALUES `)

	args := make([]interface{}, 0, len(rows)*10)
	for i, row := range rows {
		if i > 0 {
			query.WriteString(",")
		}
		query.WriteString("(?,?,?,?,?,?,?,?,?,?)")
		args = append(
			args,
			row.ipID,
			row.pageviewFlag,
			row.timestamp,
			row.method,
			row.urlID,
			row.statusCode,
			row.bytesSent,
			row.refererID,
			row.uaID,
			row.locationID,
		)
	}

	_, err := tx.Exec(sqlutil.ReplacePlaceholders(query.String()), args...)
	return err
}
