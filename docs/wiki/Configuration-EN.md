# Configuration

## Config location
- Default: `configs/nginxpulse_config.json`
- Dev: `scripts/dev_local.sh` uses `configs/nginxpulse_config.dev.json`
- Env: `CONFIG_JSON` or `WEBSITES`

## Full example (copy & edit)
```json
{
  "websites": [
    {
      "name": "Main Site",
      "logPath": "/var/log/nginx/access.log",
      "domains": ["example.com", "www.example.com"],
      "logType": "nginx",
      "logFormat": "",
      "logRegex": "",
      "timeLayout": ""
    }
  ],
  "system": {
    "logDestination": "file",
    "taskInterval": "1m",
    "logRetentionDays": 30,
    "parseBatchSize": 100,
    "ipGeoCacheLimit": 1000000,
    "ipGeoApiUrl": "http://ip-api.com/batch",
    "demoMode": false,
    "accessKeys": [],
    "language": "zh-CN",
    "webBasePath": ""
  },
  "database": {
    "driver": "postgres",
    "dsn": "postgres://nginxpulse:nginxpulse@127.0.0.1:5432/nginxpulse?sslmode=disable",
    "maxOpenConns": 10,
    "maxIdleConns": 5,
    "connMaxLifetime": "30m"
  },
  "server": {
    "Port": ":8089"
  },
  "pvFilter": {
    "statusCodeInclude": [200],
    "excludePatterns": [
      "favicon.ico$",
      "robots.txt$",
      "sitemap.xml$",
      "^/health$",
      "^/_(?:nuxt|next)/",
      "rss.xml$",
      "feed.xml$",
      "atom.xml$"
    ],
    "excludeIPs": ["127.0.0.1", "::1"]
  }
}
```

## Must-edit fields after copy
- `websites[].name`: your site name (defines site ID).
- `websites[].logPath` or `websites[].sources`: log source.
- `websites[].domains`: your domains (recommended).
- `database.dsn`: PostgreSQL DSN.

## Field reference

### system runtime parameters
- `webBasePath` (string): Frontend base path (single segment only).
  - Example: `nginxpulse` → `/nginxpulse/`, mobile `/nginxpulse/m/`, API `/nginxpulse/api/`
  - Empty means root path `/`
  - Requires restart to take effect
  - Root path `/` is disabled once set

**Design principles**
1. **Runtime configurable**: `window.__NGINXPULSE_BASE_PATH__` is delivered via `/app-config.js`, so frontend routing and API base are resolved at runtime without rebuilding.
2. **Prefix isolation**: server middleware strips the `/<base>` prefix and rejects root-path requests; API is only available at `/<base>/api/*`.
3. **Static asset compatibility**: `/app-config.js` and assets are kept accessible so the frontend can boot correctly.

### Mobile Bottom Navigation (URL override)
On mobile (`/m/`), you can temporarily override navigation position via URL query parameters. This is useful for debugging, demos, or A/B checks:

- Priority: `tabbarBottom` overrides `tabbar`.
- Truthy values (bottom tabbar): `1`, `true`, `yes`, `on`, `bottom`.
- Falsy values (top navigation): `0`, `false`, `no`, `off`, `top`.
- When one of these URL params is present, the choice is persisted to local storage and remains effective across in-app navigation.
- Without parameters, default behavior applies (PWA defaults to bottom tabbar; non-PWA follows frontend default config).

Examples:
```bash
# force top navigation.
https://example.com/m/?tabbarBottom=true
# force bottom tabbar.
https://example.com/m/?tabbarBottom=false
```

### websites[]
- `name` (string, required): site name. ID is derived from this.
- `logPath` (string, required): log path, supports `*` glob.
- `domains` (string[]): domain list.
- `logType` (string): `nginx`, `caddy`, `nginx-proxy-manager` (`npm`), `apache` (`httpd`), `iis` (`iis-w3c`), `haproxy`, `traefik`, `envoy`, `tengine`, `nginx-ingress` (`ingress-nginx`), `traefik-ingress`, or `haproxy-ingress`, default `nginx`.
- `logFormat` (string): custom format with `$vars`.
- `logRegex` (string): custom regex with named groups.
- `timeLayout` (string): custom time layout.
- `sources` (array): multi-source inputs (replaces `logPath`).

### Log parsing fields
Named fields needed by the parser (aliases allowed):
- IP: `ip`, `remote_addr`, `client_ip`, `http_x_forwarded_for`
- Time: `time`, `time_local`, `time_iso8601`
- Method: `method`, `request_method`
- URL: `url`, `request_uri`, `uri`, `path`
- Status: `status`
- Bytes: `bytes`, `body_bytes_sent`, `bytes_sent`
- Referer: `referer`, `http_referer`
- UA: `ua`, `user_agent`, `http_user_agent`

Supported `logFormat` variables (common):
- `$remote_addr`, `$http_x_forwarded_for`, `$remote_user`, `$remote_port`, `$connection`
- `$time_local`, `$time_iso8601`
- `$request`, `$request_method`, `$request_uri`, `$uri`, `$args`, `$query_string`, `$request_length`, `$request_time_msec`
- `$host`, `$http_host`, `$server_name`, `$scheme`
- `$status`, `$body_bytes_sent`, `$bytes_sent`
- `$http_referer`, `$http_user_agent`
- `$upstream_addr`, `$upstream_status`, `$upstream_response_time`, `$upstream_connect_time`, `$upstream_header_time`

`logFormat` example:
```json
"logFormat": "$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\""
```

`logFormat` example (with proxy + upstream):
```json
"logFormat": "$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\" \"$http_x_forwarded_for\" $host $scheme $request_length $remote_port $upstream_addr $upstream_status $upstream_response_time $upstream_connect_time $upstream_header_time"
```

`logRegex` example:
```json
"logRegex": "^(?P<ip>\\S+) - (?P<user>\\S+) \\[(?P<time>[^\\]]+)\\] \"(?P<method>\\S+) (?P<url>[^\"]+) HTTP/\\d\\.\\d\" (?P<status>\\d+) (?P<bytes>\\d+) \"(?P<referer>[^\"]*)\" \"(?P<ua>[^\"]*)\"$"
```

### websites[].sources (optional)
When `sources` exists, `logPath` is ignored.

`sources` accepts a **JSON array**, where each item represents one log source. This design allows:
1) Multiple sources per site (multi-host, multi-path, multi-bucket).
2) Different parsing/auth/polling strategies per source for easy extension and rollout.
3) Clean separation for rotation/archival inputs without modifying existing sources.

Common fields:
- `id` (string, required): unique ID.
- `type` (string, required): `local` | `sftp` | `http` | `s3` | `agent`
- `mode` (string): `poll` | `stream` | `hybrid`, default `poll`.
- `pollInterval` (string): reserved, not used in current version.
- `compression` (string): `gz` | `none` | `auto` (auto uses file extension).
- `parse` (object): per-source overrides (logType/logFormat/logRegex/timeLayout).

#### local source
```json
{
  "id": "local-main",
  "type": "local",
  "path": "/var/log/nginx/access.log",
  "pattern": "",
  "compression": "auto"
}
```

#### sftp source
```json
{
  "id": "sftp-main",
  "type": "sftp",
  "host": "10.0.0.10",
  "port": 22,
  "user": "nginx",
  "auth": { "keyFile": "/path/to/id_rsa", "password": "" },
  "path": "/var/log/nginx/access.log",
  "pattern": "",
  "compression": "auto"
}
```

#### http source (single file)
```json
{
  "id": "http-main",
  "type": "http",
  "url": "https://example.com/logs/access.log",
  "headers": { "Authorization": "Bearer TOKEN" },
  "rangePolicy": "auto",
  "compression": "auto"
}
```

#### http source (index list)
```json
{
  "id": "http-index",
  "type": "http",
  "url": "https://example.com/logs/access.log",
  "index": {
    "url": "https://example.com/logs/index.json",
    "method": "GET",
    "headers": { "Authorization": "Bearer TOKEN" },
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

#### s3 source
```json
{
  "id": "s3-main",
  "type": "s3",
  "endpoint": "https://s3.amazonaws.com",
  "region": "ap-northeast-1",
  "bucket": "my-bucket",
  "prefix": "nginx/",
  "pattern": "*.log.gz",
  "accessKey": "AKIA...",
  "secretKey": "SECRET...",
  "compression": "gz"
}
```

#### agent source
```json
{
  "id": "agent-main",
  "type": "agent"
}
```

### system
- `logDestination`: `file` or `stdout`.
- `taskInterval`: interval for periodic tasks, default `1m`.
- `httpSourceTimeout`: timeout for remote HTTP log reads (Go duration), default `2m` (e.g. `30s`, `2m`).
- `logRetentionDays`: days to keep logs.
- `parseBatchSize`: log parse batch size.
- `ipGeoCacheLimit`: max IP cache entries.
- `ipGeoApiUrl`: remote IP geo API URL, default `http://ip-api.com/batch`. Note: custom APIs must follow the contract described in the IP Geo documentation.
- `demoMode`: demo mode on/off.
- `accessKeys`: access key list.
- `language`: `zh-CN` or `en-US`.

### database
- `driver`: `postgres` only.
- `dsn`: PostgreSQL DSN (required).
- `maxOpenConns`: max open connections.
- `maxIdleConns`: max idle connections.
- `connMaxLifetime`: max connection lifetime.

### server
- `Port`: API listen port.

### pvFilter
- `statusCodeInclude`: PV status codes (default `[200]`).
- `excludePatterns`: URL regex list to skip.
- `excludeIPs`: IP list to skip.

## Environment overrides
Supported env vars:
- `CONFIG_JSON`, `WEBSITES`
- `LOG_DEST`, `TASK_INTERVAL`, `LOG_RETENTION_DAYS`
- `HTTP_SOURCE_TIMEOUT`
- `LOG_PARSE_BATCH_SIZE`, `IP_GEO_CACHE_LIMIT`
- `IP_GEO_API_URL`
- `DEMO_MODE`, `ACCESS_KEYS`, `APP_LANGUAGE`
- `SERVER_PORT`
- `PV_STATUS_CODES`, `PV_EXCLUDE_PATTERNS`, `PV_EXCLUDE_IPS`
- `DB_DRIVER`, `DB_DSN`, `DB_MAX_OPEN_CONNS`, `DB_MAX_IDLE_CONNS`, `DB_CONN_MAX_LIFETIME`

Example:
```bash
export CONFIG_JSON="$(cat configs/nginxpulse_config.json)"
export LOG_PARSE_BATCH_SIZE=1000
export DB_DSN="postgres://nginxpulse:nginxpulse@127.0.0.1:5432/nginxpulse?sslmode=disable"
```
