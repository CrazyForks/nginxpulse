package ingest

import (
	"testing"
	"time"

	"github.com/likaia/nginxpulse/internal/config"
)

func TestIISDefaultParserParsesW3CLine(t *testing.T) {
	parser, err := newLogLineParser(config.WebsiteConfig{LogType: "iis"}, nil)
	if err != nil {
		t.Fatalf("newLogLineParser(iis) error: %v", err)
	}
	if parser.timeLayout != defaultIISTimeLayout {
		t.Fatalf("unexpected iis time layout: got %q want %q", parser.timeLayout, defaultIISTimeLayout)
	}

	now := time.Now().UTC().Truncate(time.Second)
	line := now.Format(defaultIISTimeLayout) +
		" 10.0.0.10 GET /index.html a=1&b=2 443 - 203.0.113.8 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64) https://example.com/ 200 0 0 36"

	p := &LogParser{retentionDays: 30}
	record, err := p.parseRegexLogLine(parser, line)
	if err != nil {
		t.Fatalf("parseRegexLogLine error: %v", err)
	}

	if record.IP != "203.0.113.8" {
		t.Fatalf("unexpected ip: %q", record.IP)
	}
	if record.Method != "GET" {
		t.Fatalf("unexpected method: %q", record.Method)
	}
	if record.Url != "/index.html?a=1&b=2" {
		t.Fatalf("unexpected url: %q", record.Url)
	}
	if record.Status != 200 {
		t.Fatalf("unexpected status: %d", record.Status)
	}
	if record.Timestamp.Unix() != now.Unix() {
		t.Fatalf("unexpected timestamp: got %d want %d", record.Timestamp.Unix(), now.Unix())
	}
}

func TestIISDefaultParserSkipsDashQuery(t *testing.T) {
	parser, err := newLogLineParser(config.WebsiteConfig{LogType: "iis-w3c"}, nil)
	if err != nil {
		t.Fatalf("newLogLineParser(iis-w3c) error: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	line := now.Format(defaultIISTimeLayout) +
		" 10.0.0.10 GET /health - 443 - 203.0.113.9 curl/8.0.1 - 204 0 0 1"

	p := &LogParser{retentionDays: 30}
	record, err := p.parseRegexLogLine(parser, line)
	if err != nil {
		t.Fatalf("parseRegexLogLine error: %v", err)
	}
	if record.Url != "/health" {
		t.Fatalf("unexpected url with dash query: %q", record.Url)
	}
}
