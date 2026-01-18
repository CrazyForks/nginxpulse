package app

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/likaia/nginxpulse/internal/analytics"
	"github.com/likaia/nginxpulse/internal/cli"
	"github.com/likaia/nginxpulse/internal/config"
	"github.com/likaia/nginxpulse/internal/enrich"
	"github.com/likaia/nginxpulse/internal/ingest"
	"github.com/likaia/nginxpulse/internal/logging"
	"github.com/likaia/nginxpulse/internal/server"
	"github.com/likaia/nginxpulse/internal/store"
	"github.com/likaia/nginxpulse/internal/version"
	"github.com/likaia/nginxpulse/internal/worker"
	"github.com/sirupsen/logrus"
)

// Run wires the application dependencies and blocks until shutdown.
func Run() error {
	if cli.ProcessCliCommands() {
		return nil
	}

	logging.ConfigureLogging()
	defer logging.CloseLogFile()

	logrus.Info("------ 服务启动成功 ------")
	logrus.Infof("版本: %s, 构建时间: %s, Git提交: %s", version.Version, version.BuildTime, version.GitCommit)
	defer logrus.Info("------ 服务已安全关闭 ------")

	if err := enrich.InitIPGeoLocation(); err != nil {
		return err
	}

	repository, err := initRepository()
	if err != nil {
		return err
	}
	defer repository.Close()

	logParser := ingest.NewLogParser(repository)
	statsFactory := analytics.NewStatsFactory(repository)

	cfg := config.ReadConfig()
	serverHandle := server.StartHTTPServer(statsFactory, logParser, cfg.Server.Port)
	printStartupNotice(cfg)

	go worker.InitialScan(logParser)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if cfg.System.DemoMode {
		go worker.RunDemoGenerator(ctx, repository, time.Minute)
	}

	interval := config.ParseInterval(cfg.System.TaskInterval, 5*time.Minute)
	go worker.RunScheduler(ctx, logParser, interval)

	return waitForShutdown(cancel, serverHandle)
}

func printStartupNotice(cfg *config.Config) {
	accessAddr := formatAccessAddr(cfg.Server.Port)
	configPath := resolveConfigPath()
	dataDir := resolveDataDir()
	accessKeyStatus := "否"
	if len(cfg.System.AccessKeys) > 0 {
		accessKeyStatus = fmt.Sprintf("是（%d）", len(cfg.System.AccessKeys))
	}

	fmt.Fprintln(os.Stdout, "====== NginxPulse 启动信息 ======")
	fmt.Fprintf(os.Stdout, "访问地址: %s\n", accessAddr)
	fmt.Fprintf(os.Stdout, "配置路径: %s\n", configPath)
	fmt.Fprintf(os.Stdout, "数据目录: %s\n", dataDir)
	fmt.Fprintf(os.Stdout, "密钥启用: %s\n", accessKeyStatus)
	fmt.Fprintln(os.Stdout, "================================")
}

func formatAccessAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "http://localhost"
	}

	host := ""
	port := ""
	if strings.Contains(addr, ":") {
		parsedHost, parsedPort, err := net.SplitHostPort(addr)
		if err == nil {
			host = parsedHost
			port = parsedPort
		} else if strings.HasPrefix(addr, ":") {
			port = strings.TrimPrefix(addr, ":")
		} else {
			last := strings.LastIndex(addr, ":")
			if last > -1 {
				host = addr[:last]
				port = addr[last+1:]
			}
		}
	} else {
		port = addr
	}

	host = strings.Trim(host, "[]")
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "localhost"
	}

	if port == "" {
		return "http://" + host
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("http://%s:%s", host, port)
}

func resolveConfigPath() string {
	if _, err := os.Stat(config.ConfigFile); err == nil {
		if abs, err := filepath.Abs(config.ConfigFile); err == nil {
			return abs
		}
		return config.ConfigFile
	}
	if config.HasEnvConfigSource() {
		return "CONFIG_JSON/WEBSITES (env)"
	}
	return config.ConfigFile
}

func resolveDataDir() string {
	if abs, err := filepath.Abs(config.DataDir); err == nil {
		return abs
	}
	return config.DataDir
}

func initRepository() (*store.Repository, error) {
	logrus.Info("****** 1 初始化数据 ******")
	repository, err := store.NewRepository()
	if err != nil {
		logrus.WithField("error", err).Error("Failed to create database file")
		return repository, err
	}

	if err := repository.Init(); err != nil {
		logrus.WithField("error", err).Error("Failed to create tables")
		return repository, err
	}

	return repository, nil
}

func waitForShutdown(cancel context.CancelFunc, serverHandle *http.Server) error {
	shutdownSignal := make(chan os.Signal, 1)
	signal.Notify(shutdownSignal, os.Interrupt, syscall.SIGTERM)
	<-shutdownSignal

	logrus.Info("开始关闭服务 ......")

	cancel()

	ctx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if serverHandle != nil {
		if err := serverHandle.Shutdown(ctx); err != nil {
			logrus.WithError(err).Warn("HTTP 服务器关闭异常")
		}
	}

	return nil
}
