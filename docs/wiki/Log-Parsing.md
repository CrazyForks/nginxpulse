# 日志解析机制

## 整体流程
1. 初始扫描：启动时先解析“最近窗口”日志。
2. 增量扫描：定时任务按 `system.taskInterval` 继续扫描新增内容。
3. 历史回填：在后台逐步补齐历史日志（不阻塞实时解析）。
4. IP 归属地回填：解析日志后异步解析 IP 归属地并回填。

## 增量解析与状态文件
- 状态文件: `var/nginxpulse_data/nginx_scan_state.json`
- 若文件大小小于上次记录大小，视为轮转，从头解析。
- 站点 ID 由 `websites[].name` 生成，改名会产生新站点并重新解析。

## 批次与性能
- `system.parseBatchSize` 控制批次大小，默认 100。
- 也可通过环境变量 `LOG_PARSE_BATCH_SIZE` 覆盖。

## 解析进度与预计剩余
接口: `GET /api/status`
- `log_parsing_progress`: 解析进度（0~1）
- `log_parsing_estimated_remaining_seconds`: 预计剩余秒数
- `ip_geo_progress`: IP 归属地解析进度（0~1）
- `ip_geo_estimated_remaining_seconds`: IP 归属地预计剩余秒数

前端可按固定间隔轮询该接口以刷新进度。

## 10G+ 大日志优化思路
- 解析日志时只写入基础字段，IP 归属地放入待解析队列。
- 归属地解析在后台批量回填，不阻塞主解析。
- 如需更快：调大 `parseBatchSize`、提高机器 IO 或将日志按天切分。

## 日志清理
- `system.logRetentionDays` 控制保留天数。
- 清理任务在系统时间凌晨 2 点触发（按系统时区）。

## 多个日志文件如何挂载？
`WEBSITES` 是一个 **JSON 数组**，每个元素描述一个网站。`logPath` 需要填写**容器内可访问的路径**，你可以按需指定。

参考示例：
```yaml
environment:
  WEBSITES: '[{"name":"网站1","logPath":"/share/log/nginx/access-site1.log","domains":["www.kaisir.cn","kaisir.cn"]}, {"name":"网站2","logPath":"/share/log/nginx/access-site2.log","domains":["home.kaisir.cn"]}]'
volumes:
  - ./nginx_data/logs/site1/access.log:/share/log/nginx/access-site1.log:ro
  - ./nginx_data/logs/site2/access.log:/share/log/nginx/access-site2.log:ro
```

如果站点很多，一个个挂载较繁琐，可以**直接挂载整个日志目录**，再在 `WEBSITES` 里指定具体文件：
```yaml
environment:
  WEBSITES: '[{"name":"网站1","logPath":"/share/log/nginx/access-site1.log","domains":["www.kaisir.cn","kaisir.cn"]}, {"name":"网站2","logPath":"/share/log/nginx/access-site2.log","domains":["home.kaisir.cn"]}]'
volumes:
  - ./nginx_data/logs:/share/log/nginx/
```

> 注意：如果 Nginx 日志按天切割，可用 `*` 替代日期，例如：`{"logPath":"/share/log/nginx/site1.top-*.log"}`。

#### 压缩日志（.gz）
支持直接解析 `.gz` 压缩日志，`logPath` 可指向单个 `.gz` 文件或使用通配符：
```json
{"logPath": "/share/log/nginx/access-*.log.gz"}
```
项目内提供 gzip 参考样例：`var/log/gz-log-read-test/`。

## 远端日志支持（sources）
当日志不方便挂载到本机或容器时，可在站点配置中使用 `sources` 替代 `logPath`。一旦配置 `sources`，`logPath` 会被忽略。

`sources` 接受 **JSON 数组**，每一项表示一个日志来源配置。这样设计是为了：
1) 同一站点可接入多个来源（多台机器/多目录/多桶并行）。
2) 不同来源可使用不同解析/鉴权/轮询策略，方便扩展与灰度切换。
3) 轮转/归档场景下按来源拆分，后续新增来源无需改动旧配置。

通用字段：
- `id`：来源唯一标识（建议全站唯一）。
- `type`：`local` / `sftp` / `http` / `s3` / `agent`。
- `mode`：
  - `poll`：按间隔拉取（默认）。
  - `stream`：仅流式输入（当前仅 Push Agent 生效）。
  - `hybrid`：流式 + 轮询兜底（当前仅 Push Agent 会流式，其它来源仍按 `poll`）。
- `pollInterval`：轮询间隔（如 `5s`）。
- `pattern`：轮转匹配（SFTP/Local/S3 使用 glob；HTTP 依赖 index JSON）。
- `compression`：`auto` / `gz` / `none`。
- `parse`：覆盖解析格式（见下文“解析覆盖”）。
> `stream` 模式目前主要用于 Push Agent，其它来源会按 `poll` 处理。

### 方案一：HTTP 服务暴露日志
适合你能在日志服务器上提供 HTTP 访问（内网或加鉴权）的场景。

方式 A：Nginx/Apache 直接暴露日志文件（务必限制访问，避免日志泄露）
```nginx
location /logs/ {
  alias /var/log/nginx/;
  autoindex on;
  # 建议加 basic auth / IP 白名单
}
```

然后在 `sources` 配置：
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

`rangePolicy` 说明：
- `auto`：优先 Range，不支持则自动回退为整包下载（会跳过已读字节）。
- `range`：强制 Range，不支持则报错。
- `full`：始终整包下载。

方式 B：自建 JSON 索引 API  
适合轮转日志（按天/按小时）或 `.gz` 归档：
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

更详细的索引 API 约定（建议）：
1) 索引接口返回一个 JSON，包含日志对象数组。
2) 每条对象至少提供 `path`（可访问 URL）。
3) 建议提供 `size` / `mtime` / `etag`，用于变更检测与避免重复解析。
4) `mtime` 支持 RFC3339 / RFC3339Nano / `2006-01-02 15:04:05` / Unix 秒时间戳。

推荐返回示例：
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

如果你的字段名不同，可以在 `jsonMap` 中映射：
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

注意事项：
- `path` 必须是可直接访问的日志 URL。
- `.gz` 文件建议提供稳定的 `etag` / `size` / `mtime`，否则可能重复解析。
- 如果 HTTP 服务不支持 Range，建议将 `rangePolicy` 设为 `auto` 或 `full`。

### 方案二：SFTP 直连拉取
适合你能开放 SSH/SFTP 端口的场景，无需额外 HTTP 服务。
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
> `auth` 支持 `keyFile` 和 `password` 两种方式。

### 方案三：对象存储（S3/OSS）
适合日志统一归档到 OSS/S3（支持阿里云/腾讯云/AWS 兼容端点）。
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

### 解析覆盖（sources[].parse）
当同一站点不同来源日志格式不一致时，可在 `sources[].parse` 内覆盖：
```json
{
  "parse": {
    "logType": "nginx",
    "logRegex": "^(?P<ip>\\S+) - (?P<user>\\S+) \\[(?P<time>[^\\]]+)\\] \"(?P<request>[^\"]+)\" (?P<status>\\d+) (?P<bytes>\\d+) \"(?P<referer>[^\"]*)\" \"(?P<ua>[^\"]*)\"$",
    "timeLayout": "02/Jan/2006:15:04:05 -0700"
  }
}
```

### Push Agent（实时推送）
适合内网或边缘节点场景，通过独立进程实时推送日志行。

你需要在 **两台机器** 上分别做以下事：

#### 解析服务器（运行 NginxPulse 的机器）
1) 启动 nginxpulse（确保后端 `:8089` 可访问）。
2) 建议启用访问密钥：设置 `ACCESS_KEYS`（或配置文件 `system.accessKeys`）。
3) 获取 `websiteID`：请求 `GET /api/websites`。
4) 如需为 agent 指定解析格式，在站点配置中添加 `type=agent` 的 source（仅用于解析覆盖）：
```json
{
  "name": "主站",
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

#### 日志服务器（存放日志的机器）
1) 准备 agent（构建或使用预构建）。

构建：
```bash
go build -o bin/nginxpulse-agent ./cmd/nginxpulse-agent
```
仓库已提供预构建二进制：
- `prebuilt/nginxpulse-agent-darwin-arm64`
- `prebuilt/nginxpulse-agent-linux-amd64`

2) 在日志服务器上创建配置文件（填写解析服务器地址与 `websiteID`）。
   - `websiteID` 在解析服务器上通过接口获取：
     `curl http://<nginxpulse-server>:8089/api/websites`
     返回的 `id` 字段就是 `websiteID`。
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

3) 运行 agent：
```bash
./bin/nginxpulse-agent -config configs/nginxpulse_agent.json
```

注意事项：
- 日志服务器需要能访问解析服务器的 `http://<nginxpulse-server>:8089/api/ingest/logs`。
- 如需为 agent 指定解析格式，可在 `sources` 内配置 `type=agent` 且 `id=sourceID`，并填写 `parse` 覆盖。
- agent 会跳过 `.gz` 文件；日志轮转导致文件变小会自动从头开始读取。

## 常见注意点
- 若重启后重复解析，请确认没有残留进程占用同一端口。
- 日志路径支持通配符，注意匹配到的文件数量。
- gzip 日志会按文件全量解析（基于文件元信息判断是否变更）。
