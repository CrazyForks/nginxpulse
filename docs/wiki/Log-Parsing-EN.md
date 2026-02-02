# Log Parsing

## Flow
1. Initial scan: parse recent window after startup.
2. Incremental scan: periodic scan by `system.taskInterval`.
3. Backfill: fill older logs in background.
4. IP geo backfill: resolve IP locations asynchronously.

## Incremental scan & state
- State file: `var/nginxpulse_data/nginx_scan_state.json`
- If current size < last size, the file is treated as rotated and re-parsed.
- Site ID is derived from `websites[].name`. Renaming creates a new site.

## Batch size
- `system.parseBatchSize` controls batch size (default 100).
- Can be overridden by `LOG_PARSE_BATCH_SIZE`.

## Progress & ETA
Endpoint: `GET /api/status`
- `log_parsing_progress`
- `log_parsing_estimated_remaining_seconds`
- `ip_geo_progress`
- `ip_geo_estimated_remaining_seconds`

Poll this endpoint to update progress in UI.

## 10G+ log optimization
- Parsing writes core fields first; IP geo is queued.
- IP geo is resolved in batches after parsing.
- For speed: increase `parseBatchSize`, use faster disk, or split logs by day.

## Retention
- `system.logRetentionDays` controls cleanup.
- Cleanup runs at 02:00 (system timezone).

## Mounting Multiple Log Files
`WEBSITES` is a **JSON array**, each item describes one site. `logPath` must be a **container-accessible path**.

Example:
```yaml
environment:
  WEBSITES: '[{"name":"Site 1","logPath":"/share/log/nginx/access-site1.log","domains":["www.kaisir.cn","kaisir.cn"]}, {"name":"Site 2","logPath":"/share/log/nginx/access-site2.log","domains":["home.kaisir.cn"]}]'
volumes:
  - ./nginx_data/logs/site1/access.log:/share/log/nginx/access-site1.log:ro
  - ./nginx_data/logs/site2/access.log:/share/log/nginx/access-site2.log:ro
```

If you have many sites, consider **mounting the entire log directory** and specify exact files in `WEBSITES`:
```yaml
environment:
  WEBSITES: '[{"name":"Site 1","logPath":"/share/log/nginx/access-site1.log","domains":["www.kaisir.cn","kaisir.cn"]}, {"name":"Site 2","logPath":"/share/log/nginx/access-site2.log","domains":["home.kaisir.cn"]}]'
volumes:
  - ./nginx_data/logs:/share/log/nginx/
```

> Tip: If logs are rotated daily, use `*` to replace the date, e.g. `{"logPath":"/share/log/nginx/site1.top-*.log"}`.

#### Compressed logs (.gz)
`.gz` logs are supported. `logPath` can point to a single `.gz` file or a glob:
```json
{"logPath": "/share/log/nginx/access-*.log.gz"}
```
There is a gzip sample in `var/log/gz-log-read-test/`.

## Remote Log Sources (sources)
When logs are not convenient to mount locally, you can use `sources` instead of `logPath`. Once `sources` is set, `logPath` is ignored.

`sources` is a **JSON array**. Each item defines a log source. This design allows:
1) Multiple sources per site (multiple machines/directories/buckets).
2) Different parsing/auth/polling strategies per source.
3) Easy extension for rotation/archival without changing old sources.

Common fields:
- `id`: unique source ID (recommend globally unique).
- `type`: `local` / `sftp` / `http` / `s3` / `agent`.
- `mode`:
  - `poll`: periodic pulling (default).
  - `stream`: streaming input only (currently Push Agent only).
  - `hybrid`: stream + polling fallback (only Push Agent streams; others still use `poll`).
- `pollInterval`: polling interval (e.g. `5s`).
- `pattern`: rotation glob (SFTP/Local/S3 use glob; HTTP uses index JSON).
- `compression`: `auto` / `gz` / `none`.
- `parse`: override parsing (see “Parsing Override”).
> `stream` mode is mainly for Push Agent; other sources still run as `poll`.

### Option 1: HTTP Exposed Logs
Best when you can provide HTTP access to log files (internal network or with auth).

Method A: Expose files via Nginx/Apache (lock it down to avoid leakage)
```nginx
location /logs/ {
  alias /var/log/nginx/;
  autoindex on;
  # Add basic auth / IP allowlist
}
```

Then configure `sources`:
```json
{
  "id": "http-main",
  "type": "http",
  "mode": "poll",
  "url": "https://logs.example.com/logs/access.log",
  "rangePolicy": "auto",
  "pollInterval": "10s"
}
```

`rangePolicy`:
- `auto`: prefer Range; fallback to full download (skips already-read bytes).
- `range`: force Range; error if not supported.
- `full`: always download full file.

Method B: JSON index API  
Good for rotated logs (daily/hourly) or `.gz` archives:
```json
{
  "index": {
    "url": "https://logs.example.com/index.json",
    "jsonMap": {
      "items": "items",
      "path": "path",
      "size": "size",
      "mtime": "mtime",
      "etag": "etag",
      "compressed": "compressed"
    }
  }
}
```

Recommended index contract:
1) Return a JSON with an array of log objects.
2) Each item must include `path` (a fetchable URL).
3) Provide `size` / `mtime` / `etag` to detect changes and avoid duplicates.
4) `mtime` supports RFC3339 / RFC3339Nano / `2006-01-02 15:04:05` / Unix seconds.

Example response:
```json
{
  "items": [
    {
      "path": "https://logs.example.com/access-2024-11-03.log.gz",
      "size": 123456,
      "mtime": "2024-11-03T13:00:00Z",
      "etag": "abc123",
      "compressed": true
    },
    {
      "path": "https://logs.example.com/access.log",
      "size": 98765,
      "mtime": 1730638800,
      "etag": "def456",
      "compressed": false
    }
  ]
}
```

If your fields differ, map them in `jsonMap`:
```json
{
  "index": {
    "url": "https://logs.example.com/index.json",
    "jsonMap": {
      "items": "data",
      "path": "url",
      "size": "length",
      "mtime": "updated_at",
      "etag": "hash",
      "compressed": "gz"
    }
  }
}
```

Notes:
- `path` must be a directly accessible log URL.
- For `.gz`, provide stable `etag` / `size` / `mtime` to avoid duplicate parsing.
- If HTTP Range is not supported, use `auto` or `full`.

### Option 2: SFTP Pull
Ideal when SSH/SFTP access is available, no extra HTTP service needed.
```json
{
  "id": "sftp-main",
  "type": "sftp",
  "mode": "poll",
  "host": "1.2.3.4",
  "port": 22,
  "user": "nginx",
  "auth": { "keyFile": "/secrets/id_rsa" },
  "path": "/var/log/nginx/access.log",
  "pattern": "/var/log/nginx/access-*.log.gz",
  "pollInterval": "5s"
}
```
> `auth` supports `keyFile` and `password`.

### Option 3: Object Storage (S3/OSS)
Best when logs are archived to OSS/S3 (Aliyun/Tencent/AWS compatible endpoints).
```json
{
  "id": "s3-main",
  "type": "s3",
  "mode": "poll",
  "endpoint": "https://oss-cn-hangzhou.aliyuncs.com",
  "bucket": "nginx-logs",
  "prefix": "prod/access/",
  "pollInterval": "30s"
}
```

### Parsing Override (sources[].parse)
If formats differ across sources, override parsing per source:
```json
{
  "parse": {
    "logType": "nginx",
    "logRegex": "^(?P<ip>\\S+) - (?P<user>\\S+) \\[(?P<time>[^\\]]+)\\] \"(?P<request>[^\"]+)\" (?P<status>\\d+) (?P<bytes>\\d+) \"(?P<referer>[^\"]*)\" \"(?P<ua>[^\"]*)\"$",
    "timeLayout": "02/Jan/2006:15:04:05 -0700"
  }
}
```

### Push Agent (Realtime)
Designed for internal networks or edge nodes. Logs are pushed in real time.

You need to set up **two machines**:

#### Parsing server (runs NginxPulse)
1) Start nginxpulse (ensure backend `:8089` is reachable).
2) Recommend enabling access keys: `ACCESS_KEYS` (or `system.accessKeys`).
3) Get `websiteID`: call `GET /api/websites`.
4) If you need a custom format for the agent, add a `type=agent` source for parse override:
```json
{
  "name": "Main Site",
  "sources": [
    {
      "id": "agent-main",
      "type": "agent",
      "parse": {
        "logFormat": "$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\""
      }
    }
  ]
}
```

#### Log server (stores logs)
1) Prepare the agent (build or use prebuilt).

Build:
```bash
go build -o bin/nginxpulse-agent ./cmd/nginxpulse-agent
```
Prebuilt binaries:
- `prebuilt/nginxpulse-agent-darwin-arm64`
- `prebuilt/nginxpulse-agent-linux-amd64`

2) Create agent config on the log server (fill in parsing server and `websiteID`).
   - Fetch `websiteID` from the parsing server:
     `curl http://<nginxpulse-server>:8089/api/websites`
     The `id` field is the `websiteID`.
```json
{
  "server": "http://<nginxpulse-server>:8089",
  "accessKey": "your-key",
  "websiteID": "abcd",
  "sourceID": "agent-main",
  "paths": ["/var/log/nginx/access.log"],
  "pollInterval": "1s",
  "batchSize": 200,
  "flushInterval": "2s"
}
```

3) Run the agent:
```bash
./bin/nginxpulse-agent -config configs/nginxpulse_agent.json
```

Notes:
- The log server must reach `http://<nginxpulse-server>:8089/api/ingest/logs`.
- To override parsing, set a `type=agent` source with `id=sourceID` and fill `parse`.
- The agent skips `.gz` files; if a log file shrinks (rotation), it restarts from the beginning.

## Notes
- If reparse happens on restart, make sure no stale process is running.
- Globs may match more files than expected.
- Gzip logs are parsed as full files based on metadata.
