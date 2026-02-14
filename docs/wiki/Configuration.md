# 配置说明

## 配置文件位置
- 默认配置: `configs/nginxpulse_config.json`
- 本地开发: `scripts/dev_local.sh` 会使用 `configs/nginxpulse_config.dev.json`
- 环境变量注入: `CONFIG_JSON` 或 `WEBSITES`

## 完整示例（可直接复制）
```json
{
  "websites": [
    {
      "name": "主站",
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

## 复制后必须修改的字段
- `websites[].name`: 你的站点名称（决定站点 ID）。
- `websites[].logPath` 或 `websites[].sources`: 日志来源。
- `websites[].domains`: 你的域名列表（可选但建议填写）。
- `database.dsn`: PostgreSQL 连接地址。

## 字段详解

### system 运行参数
- `webBasePath` (string): 前端访问前缀（仅支持单段路径）。
  - 示例：`nginxpulse` → 访问路径变为 `/nginxpulse/`，移动端为 `/nginxpulse/m/`，API 为 `/nginxpulse/api/`
  - 为空表示使用根路径 `/`
  - 修改后需要重启服务生效
  - 设置后根路径 `/` 将不可访问（符合前缀隔离需求）

**设计原理**
1. **运行期可改**：通过 `/app-config.js` 下发 `window.__NGINXPULSE_BASE_PATH__`，前端路由与 API 基地址在运行期读取，无需重新构建前端。
2. **强制前缀隔离**：服务端中间件会剥离 `/<base>` 前缀并拒绝根路径请求，API 仅允许 `/<base>/api/*` 访问。
3. **静态资源兼容**：`/app-config.js` 与静态资源不做前缀绑定，保证资源可被前端加载。

### 移动端底部导航栏（URL 参数覆盖）
移动端（`/m/`）支持通过地址栏参数临时覆盖导航栏位置，适合调试、演示或 A/B 对比：

- 参数优先级：`tabbarBottom` 高于 `tabbar`。
- 真值（底部导航）：`1`、`true`、`yes`、`on`、`bottom`。
- 假值（顶部导航）：`0`、`false`、`no`、`off`、`top`。
- 当 URL 中出现上述参数时，会写入本地存储并在后续页面跳转中持续生效。
- 未传参数时走默认逻辑（PWA 仍默认底部导航；非 PWA 走前端默认配置）。

示例：
```bash
# 强制顶部导航
https://example.com/m/?tabbarBottom=true
# 强制底部导航
https://example.com/m/?tabbarBottom=false
```

### websites[] 站点配置
- `name` (string, 必填): 站点名称，站点 ID 由该字段生成（改名会产生新站点）。
- `logPath` (string, 必填): 日志路径，支持通配符 `*`。
  - 示例: `/var/log/nginx/access.log`
  - 示例: `/var/log/nginx/access_*.log`
- `domains` (string[]): 站点域名列表。
- `logType` (string): 日志类型，支持 `nginx`、`caddy`、`nginx-proxy-manager`（或 `npm`）、`apache`（或 `httpd`）、`iis`（或 `iis-w3c`）、`haproxy`、`traefik`、`envoy`、`tengine`、`nginx-ingress`（或 `ingress-nginx`）、`traefik-ingress`、`haproxy-ingress`，默认 `nginx`。
- `logFormat` (string): 自定义日志格式（带 `$变量`）。
- `logRegex` (string): 自定义正则（需命名分组）。
- `timeLayout` (string): 时间解析格式，留空走默认。
- `sources` (array): 多源配置，启用后将替代 `logPath`。

### 日志解析字段说明
默认 Nginx 正则需要包含以下命名字段（可使用别名）：
- IP: `ip`, `remote_addr`, `client_ip`, `http_x_forwarded_for`
- 时间: `time`, `time_local`, `time_iso8601`
- 方法: `method`, `request_method`
- URL: `url`, `request_uri`, `uri`, `path`
- 状态码: `status`
- 字节: `bytes`, `body_bytes_sent`, `bytes_sent`
- Referer: `referer`, `http_referer`
- UA: `ua`, `user_agent`, `http_user_agent`

`logFormat` 支持的变量（常用）：
- `$remote_addr`, `$http_x_forwarded_for`, `$remote_user`, `$remote_port`, `$connection`
- `$time_local`, `$time_iso8601`
- `$request`, `$request_method`, `$request_uri`, `$uri`, `$args`, `$query_string`, `$request_length`, `$request_time_msec`
- `$host`, `$http_host`, `$server_name`, `$scheme`
- `$status`, `$body_bytes_sent`, `$bytes_sent`
- `$http_referer`, `$http_user_agent`
- `$upstream_addr`, `$upstream_status`, `$upstream_response_time`, `$upstream_connect_time`, `$upstream_header_time`

`logFormat` 示例：
```json
"logFormat": "$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\""
```

`logFormat` 示例（含转发与上游）：
```json
"logFormat": "$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\" \"$http_x_forwarded_for\" $host $scheme $request_length $remote_port $upstream_addr $upstream_status $upstream_response_time $upstream_connect_time $upstream_header_time"
```

`logRegex` 示例：
```json
"logRegex": "^(?P<ip>\\S+) - (?P<user>\\S+) \\[(?P<time>[^\\]]+)\\] \"(?P<method>\\S+) (?P<url>[^\"]+) HTTP/\\d\\.\\d\" (?P<status>\\d+) (?P<bytes>\\d+) \"(?P<referer>[^\"]*)\" \"(?P<ua>[^\"]*)\"$"
```

### websites[].sources 多源配置（可选）
当 `sources` 配置存在时，将按源拉取日志，不再使用 `logPath`。

`sources` 接受 **JSON 数组**，每一项代表一个日志来源配置。这样设计是为了：
1) 同一站点可接入多个来源（多台机器/多目录/多桶并行）。
2) 不同来源可使用不同解析/鉴权/轮询策略，方便扩展与灰度切换。
3) 轮转/归档场景可按来源拆分，后续新增来源无需改动旧配置。

通用字段：
- `id` (string, 必填): 唯一 ID，不能重复。
- `type` (string, 必填): `local` | `sftp` | `http` | `s3` | `agent`
- `mode` (string): `poll` | `stream` | `hybrid`，默认 `poll`。
- `pollInterval` (string): 轮询间隔（当前版本未启用，预留字段）。
- `compression` (string): `gz` | `none` | `auto`，默认 `auto`（按文件后缀自动判断）。
- `parse` (object): 覆盖当前 source 的解析规则（logType/logFormat/logRegex/timeLayout）。

#### local 源示例
字段要点：`path` 或 `pattern` 二选一。
```json
{
  "id": "local-main",
  "type": "local",
  "path": "/var/log/nginx/access.log",
  "pattern": "",
  "compression": "auto"
}
```

#### sftp 源示例
字段要点：`host`、`user` 必填；`auth` 支持 `keyFile` 或 `password`；`path` 或 `pattern` 二选一。
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

#### http 源示例（单文件）
字段要点：`url` 必填，`headers` 可选，`rangePolicy` 可选（`auto`/`range`/`full`）。
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

#### http 源示例（索引列表）
字段要点：`index.url` 返回一个包含文件列表的 JSON，`jsonMap` 用于映射字段名。
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

#### s3 源示例
字段要点：`bucket` 必填；`endpoint` 为空表示使用 AWS；`accessKey`/`secretKey` 可选。
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

#### agent 源示例
字段要点：用于接入 Agent 流式采集（当前版本不参与定期扫描）。
```json
{
  "id": "agent-main",
  "type": "agent"
}
```

### system 系统配置
- `logDestination`: `file` 或 `stdout`，默认 `file`。
- `taskInterval`: 定期任务间隔，默认 `1m`，最小 5s。
- `httpSourceTimeout`: 远程 HTTP 日志读取超时（Go duration），默认 `2m`，示例：`30s`、`2m`。
- `logRetentionDays`: 保留天数，默认 30。仅作用于“已解析入库”的访问数据（明细/聚合/会话）；超过天数的数据会被定时清理。不会删除原始 Nginx 日志文件，也不影响系统运行日志文件的轮转。
- `parseBatchSize`: 单批解析条数，默认 100。
- `ipGeoCacheLimit`: IP 缓存上限，默认 1000000。
- `ipGeoApiUrl`: IP 归属地远端 API 地址，默认 `http://ip-api.com/batch`。注意：自定义 API 必须严格遵循《IP 归属地解析》文档中的协议定义。
- `demoMode`: 是否演示模式，默认 `false`。
- `accessKeys`: 访问密钥列表，默认空。
- `language`: `zh-CN` 或 `en-US`，默认 `zh-CN`。

### database 数据库配置
- `driver`: 固定为 `postgres`。
- `dsn`: PostgreSQL DSN，必填。
- `maxOpenConns`: 最大连接数。
- `maxIdleConns`: 最大空闲连接数。
- `connMaxLifetime`: 连接最大生命周期（duration）。

### server 服务端口
- `Port`: API 监听端口，默认 `:8089`。

### pvFilter 过滤规则
- `statusCodeInclude`: 计入 PV 的状态码数组（默认 `[200]`）。
- `excludePatterns`: 排除的 URL 正则数组。
- `excludeIPs`: 排除的 IP 列表。

## 环境变量覆盖
以下环境变量可覆盖配置：
- `CONFIG_JSON`: 完整配置 JSON 字符串
- `WEBSITES`: 仅网站数组 JSON 字符串
- `LOG_DEST`
- `TASK_INTERVAL`
- `HTTP_SOURCE_TIMEOUT`
- `LOG_RETENTION_DAYS`
- `LOG_PARSE_BATCH_SIZE`
- `IP_GEO_CACHE_LIMIT`
- `IP_GEO_API_URL`
- `DEMO_MODE`
- `ACCESS_KEYS`
- `APP_LANGUAGE`
- `SERVER_PORT`
- `PV_STATUS_CODES`
- `PV_EXCLUDE_PATTERNS`
- `PV_EXCLUDE_IPS`
- `DB_DRIVER`
- `DB_DSN`
- `DB_MAX_OPEN_CONNS`
- `DB_MAX_IDLE_CONNS`
- `DB_CONN_MAX_LIFETIME`

示例：
```bash
export CONFIG_JSON="$(cat configs/nginxpulse_config.json)"
export LOG_PARSE_BATCH_SIZE=1000
export DB_DSN="postgres://nginxpulse:nginxpulse@127.0.0.1:5432/nginxpulse?sslmode=disable"
```
