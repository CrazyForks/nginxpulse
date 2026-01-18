package worker

import (
	"context"
	"time"

	"github.com/likaia/nginxpulse/internal/ingest"
	"github.com/likaia/nginxpulse/internal/logging"
	"github.com/sirupsen/logrus"
)

// InitialScan performs an initial log scan after startup.
func InitialScan(parser *ingest.LogParser, interval time.Duration) {
	logrus.Info("****** 2 初始扫描 ******")
	ExecutePeriodicTasks(parser, interval)
}

// RunScheduler executes periodic tasks on a ticker until ctx is canceled.
func RunScheduler(ctx context.Context, parser *ingest.LogParser, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	iteration := 0

	for {
		select {
		case <-ticker.C:
			iteration++
			logrus.WithFields(logrus.Fields{"iteration": iteration}).Info("定期任务开始")
			ExecutePeriodicTasks(parser, interval)
		case <-ctx.Done():
			return
		}
	}
}

// ExecutePeriodicTasks runs log rotation, cleanup, and log scanning.
func ExecutePeriodicTasks(parser *ingest.LogParser, interval time.Duration) {
	{ // 1 日志轮转
		if err := logging.RotateLogFile(); err != nil {
			logrus.WithError(err).Warn("日志轮转失败")
		}
	}

	{ // 2 清理旧数据
		if err := parser.CleanOldLogs(); err != nil {
			logrus.WithError(err).Warn("清理数据库中过期日志数据失败")
		}
	}

	{ // 3 Nginx日志扫描
		startTime := time.Now()
		results := parser.ScanNginxLogs()
		totalDuration := time.Since(startTime)

		totalEntries := 0
		successCount := 0

		for _, result := range results {
			if result.WebName == "" {
				continue
			}

			totalEntries += result.TotalEntries

			if result.Success {
				successCount++
				if result.TotalEntries > 0 {
					logrus.Infof("网站 %s (%s) 扫描完成: %d 条记录, 耗时 %.2fs",
						result.WebName, result.WebID, result.TotalEntries, result.Duration.Seconds())
				}
			} else {
				logrus.Warnf("网站 %s (%s) 扫描失败: %s",
					result.WebName, result.WebID, result.Error)
			}
		}

		if totalEntries > 0 {
			logrus.Infof("Nginx日志扫描完成: %d/%d 个站点成功, 共 %d 条记录, 总耗时 %.2fs",
				successCount, len(results), totalEntries, totalDuration.Seconds())
		}
	}

	{ // 4 历史日志回填
		backfillDuration, backfillBytes := backfillBudget(interval)
		backfillResult := parser.BackfillHistory(backfillDuration, backfillBytes)
		if backfillResult.ProcessedBytes > 0 {
			logrus.Infof("历史日志回填完成: %d 条记录, %.2f MB",
				backfillResult.ProcessedEntries,
				float64(backfillResult.ProcessedBytes)/(1024*1024))
		}
	}
}

func backfillBudget(interval time.Duration) (time.Duration, int64) {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	duration := interval / 3
	if duration < 500*time.Millisecond {
		duration = 500 * time.Millisecond
	}
	if duration > 8*time.Second {
		duration = 8 * time.Second
	}
	const maxBytes = int64(32 * 1024 * 1024)
	return duration, maxBytes
}
