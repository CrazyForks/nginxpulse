package ingest

import "sync"

type WebsiteParseStatus struct {
	LogMinTs        int64
	LogMaxTs        int64
	ParsedMinTs     int64
	ParsedMaxTs     int64
	RecentCutoffTs  int64
	BackfillPending bool
}

var (
	parseStatusMu sync.RWMutex
	parseStatus   = make(map[string]WebsiteParseStatus)
)

func UpdateWebsiteParseStatus(websiteID string, status WebsiteParseStatus) {
	if websiteID == "" {
		return
	}
	parseStatusMu.Lock()
	parseStatus[websiteID] = status
	parseStatusMu.Unlock()
}

func GetWebsiteParseStatus(websiteID string) (WebsiteParseStatus, bool) {
	parseStatusMu.RLock()
	status, ok := parseStatus[websiteID]
	parseStatusMu.RUnlock()
	return status, ok
}

func ResetWebsiteParseStatus(websiteID string) {
	parseStatusMu.Lock()
	defer parseStatusMu.Unlock()
	if websiteID == "" {
		parseStatus = make(map[string]WebsiteParseStatus)
		return
	}
	delete(parseStatus, websiteID)
}
