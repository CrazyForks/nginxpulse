<p align="center">
  <img src="docs/brand-mark.svg" alt="NginxPulse Logo" width="120" height="120">
</p>

<p align="center">
  <a href="README_EN.md">English</a> | 简体中文
</p>

# NginxPulse

轻量级 Nginx 访问日志分析与可视化面板，提供实时统计、PV 过滤、IP 归属地与客户端解析。

Wiki（详细文档与示例配置）：https://github.com/likaia/nginxpulse/wiki
Wiki 同步脚本：`bash scripts/push_wiki.sh`

![demo-img-1.png](docs/demo-img-1.png)

![demo-img-2.png](docs/demo-img-2.png)
## 目录
- [项目开发技术栈](#项目开发技术栈)
- [IP 归属地查询策略](#ip-归属地查询策略)
- [如何使用项目](#如何使用项目)
  - [1) Docker](#1-docker)
  - [2) Docker Compose](#2-docker-compose)
  - [时区设置（重要）](#时区设置重要)
  - [3) 手动构建（前端、后端）](#3-手动构建前端后端)
  - [4) 单体部署（单进程）](#4-单体部署单进程)
  - [5) Makefile 常用命令](#5-makefile-常用命令)
- [多个日志文件如何挂载？](#多个日志文件如何挂载)
- [远端日志支持（sources）](#远端日志支持sources)
- [Push Agent（实时推送）](#push-agent实时推送)
- [自定义日志格式](#自定义日志格式)
- [Caddy 日志支持](#caddy-日志支持)
- [访问密钥列表（ACCESS_KEYS）](#访问密钥列表access_keys)
- [常见问题](#常见问题)
- [二次开发注意事项](#二次开发注意事项)
- [目录结构与主要文件](#目录结构与主要文件)

## 项目开发技术栈
**重要提示（版本 > 1.5.3）**：已完全弃用 SQLite；单体部署必须自备 PostgreSQL 并配置 `DB_DSN`（或 `database.dsn`）。Docker 镜像内置 PostgreSQL。
- **后端**：`Go 1.24.x` · `Gin` · `Logrus`
- **数据**：`PostgreSQL (pgx)`
- **IP 归属地**：`ip2region`（本地库） + `ip-api.com`（远程批量）
- **前端**：`Vue 3` · `Vite` · `TypeScript` · `PrimeVue` · `ECharts/Chart.js` · `Scss`
- **容器**：`Docker / Docker Compose` · `Nginx`（前端静态部署）

## IP 归属地查询策略
1. **快速过滤**：空值/本地/回环地址返回“本地”，内网地址返回“内网/本地网络”。
2. **解析解耦**：日志解析阶段仅入库并标记“待解析”，IP 归属地由后台任务异步补齐并回填。
3. **缓存优先**：持久化缓存 + 内存缓存命中直接返回（默认上限 1,000,000 条）。
4. **本地优先（IPv4/IPv6）**：优先查 ip2region，本地结果可用时直接使用。
5. **远程补齐**：本地返回“未知”或解析失败时，调用远端 API（默认 `ip-api.com/batch`，可配置）批量查询（超时 1.2s，单批最多 100 个）。
6. **远程失败**：返回“未知”。

> 归属地解析未完成时，页面会显示“待解析”，地域统计可能不完整。

> 本地数据库 `ip2region_v4.xdb` 与 `ip2region_v6.xdb` 内嵌在二进制中，首次启动会自动解压到 `./var/nginxpulse_data/`，并尝试加载向量索引提升查询性能。

> 本项目会访问外网 IP 归属地 API（默认 `ip-api.com`），部署环境需放行该域名的出站访问。

## 自定义 IP 归属地 API
可通过 `system.ipGeoApiUrl` 或环境变量 `IP_GEO_API_URL` 指向自定义服务。
注意事项：编写 API 服务时，请务必严格按照本章节所述协议进行设计与返回，否则解析结果不可用。

请求协议：
- `POST` JSON，`Content-Type: application/json`
- 请求体为数组，每个元素包含：
  - `query`：IP 字符串
  - `fields`：返回字段列表（可忽略）
  - `lang`：语言（`zh-CN` / `en`，可忽略）

响应协议：
- 返回 JSON 数组（顺序与请求一致，或通过 `query` 回填）
- 每个元素必须包含以下字段（字段含义如下）：
  - `status`：`success` 表示成功，其他值视为失败
  - `message`：失败原因（可为空）
  - `query`：IP 字符串（用于匹配请求）
  - `country`：国家名称（用于全球维度）
  - `countryCode`：国家代码（如 `CN`、`US`）
  - `region`：区域代码（可为空）
  - `regionName`：省/州名称
  - `city`：城市名称
  - `isp`：运营商名称（可为空）

当 `status != success` 或地址字段为空时，会回填为“未知”。


## 如何使用项目

### 1) Docker
单镜像（前端 Nginx + 后端服务）：
> 镜像内置 PostgreSQL，启动时会自动初始化数据库。
> **必须挂载数据目录**：`/app/var/nginxpulse_data` 与 `/app/var/pgdata`。未挂载时容器会直接退出并报错。

使用远程镜像（Docker Hub）：

```bash
docker run -d --name nginxpulse \
  -p 8088:8088 \
  -p 8089:8089 \
  -e WEBSITES='[{"name":"主站","logPath":"/share/log/nginx/access.log","domains":["kaisir.cn","www.kaisir.cn"]}]' \
  -v ./nginx_data/logs/all/access.log:/share/log/nginx/access.log:ro \
  -v /etc/localtime:/etc/localtime:ro \
  -v "$(pwd)/var/nginxpulse_data:/app/var/nginxpulse_data" \
  -v "$(pwd)/var/pgdata:/app/var/pgdata" \
  magiccoders/nginxpulse:latest
```

一键启动（极简配置，首次启动进入初始化向导）：

```bash
docker run -d --name nginxpulse \
  -p 8088:8088 \
  -v ./docker_local/logs:/share/logs:ro \
  -v ./docker_local/nginxpulse_data:/app/var/nginxpulse_data \
  -v ./docker_local/pgdata:/app/var/pgdata \
  -v /etc/localtime:/etc/localtime:ro \
  magiccoders/nginxpulse:latest
```

本地构建运行：

```bash
docker build -t nginxpulse:local .
docker run -d --name nginxpulse \
  -p 8088:8088 \
  -p 8089:8089 \
  -e WEBSITES='[{"name":"主站","logPath":"/share/log/nginx/access.log","domains":["kaisir.cn","www.kaisir.cn"]}]' \
  -v ./nginx_data/logs/all/access.log:/share/log/nginx/access.log:ro \
  -v /etc/localtime:/etc/localtime:ro \
  -v "$(pwd)/var/nginxpulse_data:/app/var/nginxpulse_data" \
  -v "$(pwd)/var/pgdata:/app/var/pgdata" \
  nginxpulse:local
```

多架构镜像（amd64/arm64）构建与发布：

```bash
./scripts/publish_docker.sh -r <repo> -p linux/amd64,linux/arm64
```

仅本地构建指定架构示例：

```bash
docker buildx build --platform linux/arm64 -t nginxpulse:local --load .
```

GitHub Actions 自动发布（多架构镜像）：
- 在仓库 Secrets 中配置：
  - `DOCKERHUB_USERNAME`
  - `DOCKERHUB_TOKEN`
  - `DOCKERHUB_REPO`（例如：`username/nginxpulse`）
- 推送 `v*` tag 或发布 Release 时触发。

> 如果更偏好配置文件方式，可将 `configs/nginxpulse_config.json` 挂载到容器内的 `/app/configs/nginxpulse_config.json`。
> 若未提供配置文件/环境变量，首次启动会进入“初始化配置向导”。保存后会写入 `configs/nginxpulse_config.json`，需重启容器生效（建议挂载 `/app/configs` 以持久化）。

### 2) Docker Compose
使用远程镜像（Docker Hub）：将 `docker-compose.yml` 改为下方远程镜像版本，然后执行：

```bash
docker compose up -d
```

一键启动（极简配置，首次启动进入初始化向导）：

```bash
docker compose -f docker-compose-simple.yml up -d
```

本地构建运行（基于源码构建镜像）：保持仓库自带的 `docker-compose.yml`，执行：

```bash
docker compose up -d --build
```

示例 `docker-compose.yml`（远程镜像）：

```yml
version: "3.8"
services:
  nginxpulse:
    image: magiccoders/nginxpulse:latest
    container_name: nginxpulse
    ports:
      - "8088:8088"
      - "8089:8089"
    environment:
      WEBSITES: '[{"name":"主站","logPath":"/share/log/nginx/access.log","domains":["kaisir.cn","www.kaisir.cn"]}]'
    volumes:
      - ./nginx_data/logs/all/access.log:/share/log/nginx/access.log:ro
      - ./var/nginxpulse_data:/app/var/nginxpulse_data
      - ./var/pgdata:/app/var/pgdata
      - /etc/localtime:/etc/localtime:ro
    restart: unless-stopped
```

### 时区设置（重要）
本项目使用**系统时区**进行日志时间解析与统计，请确保运行环境时区正确。

**Docker / Docker Compose**
- 推荐挂载宿主机时区：`-v /etc/localtime:/etc/localtime:ro`（Linux）
- 若宿主机提供 `/etc/timezone`，可额外挂载：`-v /etc/timezone:/etc/timezone:ro`
- 若你只想指定时区，可设置 `TZ=Asia/Shanghai`，但需保证容器内有时区数据（例如安装 `tzdata` 或挂载 `/usr/share/zoneinfo`）

**单体部署（单进程）**
- 默认使用当前系统时区
- 可通过环境变量临时指定：`TZ=Asia/Shanghai ./nginxpulse`

示例 `docker-compose.yml`（本地构建）：

```yml
version: "3.8"
services:
  nginxpulse:
    image: nginxpulse:local
    build:
      context: .
    container_name: nginxpulse
    ports:
      - "8088:8088"
      - "8089:8089"
    environment:
      WEBSITES: '[{"name":"主站","logPath":"/share/log/nginx/access.log","domains":["kaisir.cn","www.kaisir.cn"]}]'
    volumes:
      - ./nginx_data/logs/all/access.log:/share/log/nginx/access.log:ro
      - ./var/nginxpulse_data:/app/var/nginxpulse_data
      - /etc/localtime:/etc/localtime:ro
    restart: unless-stopped
```

说明：
- `logPath` 必须是容器内路径，确保与挂载目录一致。
- `var/nginxpulse_data` 挂载用于持久化数据库和解析缓存，推荐保留。

参数说明（环境变量）：
- `WEBSITES`（必填，无配置文件时）
  - 网站列表 JSON 数组，字段：`name`、`logPath`、`sources`、`domains`（可选）。
  - 当配置 `sources` 时将忽略 `logPath`，并以远端来源作为日志输入。
  - `domains` 用于将 referer 归类为“站内访问”，不影响日志解析与 PV 过滤。
- `CONFIG_JSON`（可选）
  - 完整配置 JSON 字符串（等同于 `configs/nginxpulse_config.json` 内容）。
  - 设置后会忽略本地配置文件，其他环境变量仍可覆盖其中字段。
- `LOG_DEST`（可选，默认：`file`）
  - 日志输出位置：`file` 或 `stdout`。
- `TASK_INTERVAL`（可选，默认：`1m`）
  - 扫描间隔，支持 `5m`、`25s` 等 Go duration 格式。
- `LOG_RETENTION_DAYS`（可选，默认：`30`）
  - 日志保留天数，超过天数会清理数据库中的旧日志。
- `LOG_PARSE_BATCH_SIZE`（可选，默认：`100`）
  - 日志解析入库批量大小，过大可能占用更多内存。
- `IP_GEO_CACHE_LIMIT`（可选，默认：`1000000`）
  - IP 归属地缓存上限条数，超过会清理最早记录。
- `DEMO_MODE`（可选，默认：`false`）
  - 开启演示模式，定时生成模拟日志并直接写入数据库（不再解析日志文件）。
- `ACCESS_KEYS`（可选，默认：空）
  - 访问密钥列表（JSON 数组或逗号分隔），配置后将启用访问限制。
- `APP_LANGUAGE`（可选，默认：`zh-CN`）
  - 系统默认语言，支持 `zh-CN` / `en-US`（也接受 `zh`、`en`）。
  - 会同步影响 IP 归属地在线查询返回语言。
- `SERVER_PORT`（可选，默认：`:8089`）
  - 服务监听地址，可传 `:8089` 或 `8089`，不带冒号会自动补上。
- `PV_STATUS_CODES`（可选，默认：`[200]`）
  - 统计 PV 的状态码列表，可用 JSON 数组或逗号分隔值。
- `PV_EXCLUDE_PATTERNS`（可选，默认内置规则）
  - 全局 URL 排除正则数组（JSON 数组）。
- `PV_EXCLUDE_IPS`（可选，默认：空或配置文件）
  - 排除 IP 列表（JSON 数组或逗号分隔）。

访问：
- 前端：`http://localhost:8088`
- 后端：`http://localhost:8089`

前端语言：
- 默认语言由后端 `APP_LANGUAGE` / 配置文件 `system.language` 决定。
- 可通过 URL 参数覆盖：`?lang=en` 或 `?locale=en-US`。

> PV_EXCLUDE_PATTERNS和PV_EXCLUDE_IPS的具体格式请参考[nginxpulse_config.json](configs/nginxpulse_config.json)

### 3) 手动构建（前端、后端）
前端构建：

```bash
cd webapp
npm install
npm run build
```

后端构建：

```bash
go mod download
go build -o bin/nginxpulse ./cmd/nginxpulse/main.go
```

本地开发（前后端一起跑）：

```bash
./scripts/dev_local.sh
```

> 前端开发服务默认端口 8088，并会将 `/api` 代理到 `http://127.0.0.1:8089`。
> 本地开发前请准备好日志文件，放在 `var/log/` 下（或确保 `configs/nginxpulse_config.json` 的 `logPath` 指向对应文件）。

### 4) 单体部署（单进程）
**重要提示（版本 > 1.5.3）**：已彻底弃用 SQLite。单体部署必须自备 PostgreSQL 并配置 `DB_DSN`（或在 `configs/nginxpulse_config.json` 填好 `database.dsn`）。  
如果使用 Docker 镜像，则已内置 PostgreSQL，无需额外安装。

如果你希望只分发一个可执行文件（内置前端静态资源），可以使用：
```bash
./scripts/build_single.sh
```
执行后会生成单体可执行文件（已内置前端静态资源），启动后即可同时提供前后端服务：
- 前端：`http://localhost:8088`
- 后端：`http://localhost:8088/api/...`

默认会构建 `linux/amd64` 和 `linux/arm64`，产物在：
`bin/linux_amd64/nginxpulse` 与 `bin/linux_arm64/nginxpulse`。

指定目标平台示例：
```bash
GOOS=linux GOARCH=amd64 ./scripts/build_single.sh
GOOS=linux GOARCH=arm64 ./scripts/build_single.sh
```

#### 单体部署的配置方式
单体运行时读取配置有两种方式（任选其一）：

**方式 A：配置文件（默认）**
1. 在运行目录创建 `configs/`
2. 放入 `configs/nginxpulse_config.json`
3. 启动：`./nginxpulse`

**方式 B：环境变量注入（无需文件）**
```bash
CONFIG_JSON="$(cat /path/to/nginxpulse_config.json)" ./nginxpulse
```

注意事项：
- 配置文件路径为相对路径 `./configs/nginxpulse_config.json`，请确保运行时工作目录正确。
- 如果使用 systemd，请设置 `WorkingDirectory`，或改用 `CONFIG_JSON` 注入。
- 数据目录 `./var/nginxpulse_data` 也是相对路径；找不到目录时请先确认当前进程的工作目录。

### 5) Makefile 构建
此项目也支持了通过Makefile来构建相关资源，命令如下：
```bash
make frontend   # 构建前端 webapp/dist
make backend    # 构建后端 bin/nginxpulse（不内嵌前端）
make single     # 构建单体包（内嵌前端 + 复制配置与gzip示例）
make dev        # 启动本地开发（前端8088，后端8089）
make clean      # 清理构建产物
```

指定版本号示例：
```bash
VERSION=v0.4.8 make single
VERSION=v0.4.8 make backend
```

说明：
- `make single` 默认构建 `linux/amd64` 与 `linux/arm64`，产物在 `bin/linux_amd64/` 与 `bin/linux_arm64/`。
- 单平台构建时，产物在 `bin/nginxpulse`，配置在 `bin/configs/nginxpulse_config.json`（端口默认 `:8088`），gzip 示例在 `bin/var/log/gz-log-read-test/`。

## 多个日志文件如何挂载？
WEBSITES 它的值是个数组，参数对象中传入网站名、网址、日志路径（这个路径为容器内访问的路径，可按照需求随意指定）。
参考示例:
```yaml
environment:
  WEBSITES: '[{"name":"网站1","logPath":"/share/log/nginx/access-site1.log","domains":["www.kaisir.cn","kaisir.cn"]}, {"name":"网站2","logPath":"/share/log/nginx/access-site2.log","domains":["home.kaisir.cn"]}]'
volumes:
  - ./nginx_data/logs/site1/access.log:/share/log/nginx/access-site1.log:ro
  - ./nginx_data/logs/site2/access.log:/share/log/nginx/access-site2.log:ro
```

如果你有很多个网站要分析，一个个挂载太麻烦，你可以考虑将日志目录整体挂载进去，然后在WEBSITES里去指定具体的日志文件即可。

比如：
```yaml
environment:
  WEBSITES: '[{"name":"网站1","logPath":"/share/log/nginx/access-site1.log","domains":["www.kaisir.cn","kaisir.cn"]}, {"name":"网站2","logPath":"/share/log/nginx/access-site2.log","domains":["home.kaisir.cn"]}]'
volumes:
  - ./nginx_data/logs:/share/log/nginx/
```

> 注意：如果你的nginx日志是按天进行切割的，可以使用 * 来替代日期，比如：{"logPath": "/share/log/nginx/site1.top-*.log"}

#### 压缩日志（.gz）
支持直接解析 `.gz` 压缩日志，`logPath` 可指向单个 `.gz` 文件或使用通配符：
```json
{"logPath": "/share/log/nginx/access-*.log.gz"}
```
项目内提供了 gzip 参考样例：`var/log/gz-log-read-test/`。

## 远端日志支持（sources）
当日志不方便挂载到本机/容器时，可以在网站配置中使用 `sources` 替代 `logPath`。一旦配置 `sources`，`logPath` 会被忽略。

`sources` 接受 **JSON 数组**，每一项表示一个日志来源配置。这样设计是为了：
1) 同一站点可接入多个来源（多台机器/多目录/多桶并行）。
2) 不同来源可使用不同解析/鉴权/轮询策略，方便扩展与灰度切换。
3) 支持轮转/归档场景下按来源拆分，后续新增来源无需改动旧配置。

远端日志支持三种接入方式（按你现网条件选择）：
1) **HTTP 服务暴露日志**（自己部署或用 Nginx/Apache）
2) **SFTP 直连拉取**（无需额外 HTTP 服务）
3) **对象存储（S3/OSS）**（上传/归档到对象存储）

通用字段：
- `id`：来源唯一标识（建议全站唯一）。
- `type`：`local`/`sftp`/`http`/`s3`/`agent`。
- `mode`：
  - `poll`：按间隔拉取（默认）。
  - `stream`：仅流式输入（当前仅 Push Agent 生效）。
  - `hybrid`：流式 + 轮询兜底（当前仅 Push Agent 会流式，其它来源仍按 `poll`）。
- `pollInterval`：轮询间隔（如 `5s`）。
- `pattern`：轮转匹配（SFTP/Local/S3 使用 glob；HTTP 依赖 index JSON）。
- `compression`：`auto`/`gz`/`none`。
- `parse`：覆盖解析格式（见下文“解析覆盖”）。
> `stream` 模式目前主要用于 Push Agent，其它来源会按 `poll` 处理。

### 方案一：HTTP 服务暴露日志
适合你能在日志服务器上提供 HTTP 访问（内网或加鉴权）的场景。

方式 A：Nginx/Apache 直接暴露日志文件  
（需设置访问限制，避免日志泄露）
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
- `.gz` 文件建议提供稳定的 `etag`/`size`/`mtime`，否则可能重复解析。
- 如果 HTTP 服务不支持 Range，建议将 `rangePolicy` 设置为 `auto` 或 `full`。

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
> auth 支持 `keyFile` 和 `password` 两种方式

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

### 解析覆盖（source.parse）
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

## Push Agent（实时推送）
适合内网/边缘节点场景，通过独立进程实时推送日志行：

你需要在 **两台机器** 上分别做以下事：

### 解析服务器（运行 NginxPulse 的机器）
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

### 日志服务器（存放日志的机器）
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

## 自定义日志格式
支持为每个网站单独配置日志格式，也可以指定日志类型 `logType`（默认 `nginx`，Caddy 见下节）。

日志类型（`logType`）：
- `nginx`（默认）：按 Nginx access log 解析（兼容默认 combined 格式）。

**方式 A：logFormat（Nginx log_format 语法）**
```json
{
  "name": "主站",
  "logPath": "/share/log/nginx/access.log",
  "logType": "nginx",
  "logFormat": "$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\""
}
```

当前支持的变量：
`$remote_addr` `$remote_user` `$time_local` `$time_iso8601` `$request`
`$request_method` `$request_uri` `$uri` `$status` `$body_bytes_sent` `$bytes_sent`
`$http_referer` `$http_user_agent`

**方式 B：logRegex（正则，命名分组）**
```json
{
  "name": "主站",
  "logPath": "/share/log/nginx/access.log",
  "logType": "nginx",
  "logRegex": "^(?P<ip>\\S+) - (?P<user>\\S+) \\[(?P<time>[^\\]]+)\\] \"(?P<request>[^\"]+)\" (?P<status>\\d+) (?P<bytes>\\d+) \"(?P<referer>[^\"]*)\" \"(?P<ua>[^\"]*)\"$"
}
```

命名分组要求（至少包含）：
- IP：`ip` / `remote_addr`
- 时间：`time` / `time_local` / `time_iso8601`
- 状态码：`status`
- URL：`url` / `request_uri` / `uri` 或 `request`（会从 request 中拆 method + url）

可选时间解析格式（Go time layout）：
```json
{
  "timeLayout": "2006-01-02T15:04:05+08:00"
}
```
未配置时会自动尝试默认格式（`time_local`）、RFC3339/RFC3339Nano，以及时间戳（秒/毫秒）。

## Caddy 日志支持
支持 Caddy 默认 JSON access log（每行一条 JSON）。

示例配置：
```json
{
  "name": "Caddy 站点",
  "logPath": "/share/log/caddy/access.log",
  "logType": "caddy"
}
```

示例日志格式（单行 JSON）：
```json
{"ts":1705567800.123,"level":"info","logger":"http.log.access","msg":"handled request","request":{"remote_ip":"203.0.113.10","method":"GET","uri":"/","headers":{"User-Agent":["Mozilla/5.0"],"Referer":["-"]}},"status":200,"size":1234}
```

解析字段说明：
- 时间：`ts` / `time` / `timestamp`（支持秒/毫秒或 RFC3339 字符串）
- IP：`request.remote_ip` / `request.client_ip`
- 方法与路径：`request.method` + `request.uri`
- 状态码：`status`
- 大小：`size`（可选）
- UA/Referer：`request.headers.User-Agent` / `request.headers.Referer`（可选）

项目内示例文件：`var/log/nginx-pulse-demo/access_caddy.json`。

## 访问密钥列表（ACCESS_KEYS）
当 `accessKeys` 配置为非空数组时，访问 UI 和 API 都需要提供密钥。默认值为空数组

配置文件方式（推荐）：
```json
{
  "system": {
    "accessKeys": ["key-1", "key-2"]
  }
}
```

环境变量方式：
```bash
ACCESS_KEYS='["key-1","key-2"]' ./nginxpulse
```

Docker Compose 方式：
```yaml
services:
  nginxpulse:
    environment:
      ACCESS_KEYS: '["key-1","key-2"]'
```

请求头要求：
- API 请求需带 `X-NginxPulse-Key: <your-key>`。
- 前端访问会自动弹窗提示输入密钥（存储在localStorage中）。

关闭密钥：
- 不配置 `accessKeys` 或配置为空数组即可关闭。

## 常见问题

1) 日志明细无内容  
通常是容器内无权限访问宿主机日志文件。请尝试为宿主机日志目录与 `nginxpulse_data` 目录赋权：
```bash
chmod -R 777 /path/to/logs /path/to/nginxpulse_data
```
然后重启容器。

2) 日志存在，但 PV/UV 无法统计  
默认规则会排除内网 IP。若你希望统计内网流量，请将 `PV_EXCLUDE_IPS` 设为空数组并重启：
```bash
PV_EXCLUDE_IPS='[]'
```
重启后在“日志明细”页面点击“重新解析”按钮。

3) 日志时间不正确  
通常是运行环境时区未同步导致。请确认 Docker/系统时区正确，并按“时区设置（重要）”章节调整后重新解析日志。

## 二次开发注意事项

### 环境依赖
- Go 1.24.x（与 `go.mod` 保持一致）
- Node.js 20+ / npm
- Docker（可选，用于容器化）

### 配置与数据目录
- 配置文件：`configs/nginxpulse_config.json`
- 数据目录：`var/nginxpulse_data/`（相对当前工作目录）
  - `nginx_scan_state.json`：日志扫描游标
  - `ip2region_v4.xdb`：IPv4 本地库
  - `ip2region_v6.xdb`：IPv6 本地库
  - `nginxpulse.log`：应用运行日志（解析进度/告警等），不参与访问统计
  - `nginxpulse_backup.log`：运行日志轮转文件（超过 5MB 自动轮转）
- Docker 镜像内置 PostgreSQL，默认数据目录：`var/pgdata/`
- 数据库由 PostgreSQL 提供，不存放在数据目录内。
- 首次启动会自动创建数据库结构，并在清理日志时回收维表孤儿数据。
- 数据库内包含维表与聚合表（`*_dim_*`、`*_agg_*`），用于去重和统计加速。
- 环境变量覆盖：
  - `CONFIG_JSON` / `WEBSITES`
  - `LOG_DEST` / `TASK_INTERVAL` / `SERVER_PORT`
  - `LOG_RETENTION_DAYS` / `LOG_PARSE_BATCH_SIZE` / `IP_GEO_CACHE_LIMIT`
  - `IP_GEO_API_URL`
  - `PV_STATUS_CODES` / `PV_EXCLUDE_PATTERNS` / `PV_EXCLUDE_IPS`
  - `DB_DRIVER` / `DB_DSN`
  - `DB_MAX_OPEN_CONNS` / `DB_MAX_IDLE_CONNS` / `DB_CONN_MAX_LIFETIME`
  - `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB`
  - `POSTGRES_PORT` / `POSTGRES_LISTEN` / `POSTGRES_CONNECT_HOST` / `PGDATA`

### 大日志解析策略
- 默认先解析最近 7 天的数据，保证前台查询能尽快返回。
- 历史数据通过后台分批回填（按时间/字节预算），避免阻塞周期性扫描。
- 当前台查询的时间范围仍在回填中时，会提示“所选范围仍在解析中，数据可能不完整”。

### 大日志解析加速亮点（10G+）
- **解析与归属地解耦**：日志解析阶段只做结构化入库 + “待解析”占位，不再同步做 IP 归属地查询，大幅减少耗时瓶颈。
- **后台异步回填**：IP 归属地解析进入待处理队列，后台按批解析并回填 location，不阻塞主解析流程。
- **批量入库可配置**：支持 `LOG_PARSE_BATCH_SIZE` 控制批量入库大小，兼顾吞吐与内存占用。
- **冷热分层处理**：最近 7 天优先解析，历史数据回填按预算进行，避免单次扫描阻塞。
- **缓存命中优先**：IP 归属地缓存命中直接复用，减少远程查询次数。
  
### Nginx 日志格式
默认解析模式基于典型的 access log 格式：
```
<ip> - <user> [time] "METHOD /path HTTP/1.x" status bytes "referer" "ua"
```
如果你的 Nginx 使用自定义 `log_format`，请参考**自定义日志格式**章节

#### 示例日志：
```bash
4.213.160.187 - - [31/Dec/2025:15:40:45 +0800] "GET /wp-includes/index.php HTTP/1.1" 404 41912 "https://www.google.fr/" "Mozilla/5.0 (Linux; Android 13; SM-S908E) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36"
4.213.160.187 - - [31/Dec/2025:15:40:46 +0800] "GET /wp-includes/js/crop/cropper.php HTTP/1.1" 404 41912 "https://www.yahoo.com/" "Mozilla/5.0 (Linux; Android 12; 2201116SG) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36"
4.213.160.187 - - [31/Dec/2025:15:40:48 +0800] "GET /wp-includes/js/dist/ HTTP/1.1" 404 41912 "https://www.google.fr/" "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1"
10.10.0.1 - - [31/Dec/2025:15:40:48 +0800] "GET / HTTP/1.1" 200 19946 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 SafeLine-CE/v9-2-8"
4.213.160.187 - - [31/Dec/2025:15:40:49 +0800] "GET /wp-includes/js/index.php HTTP/1.1" 404 41905 "https://www.yahoo.com/" "Mozilla/5.0 (Linux; Android 13; M2101K6G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36"
4.213.160.187 - - [31/Dec/2025:15:40:50 +0800] "GET /wp-includes/widgets/autoload_classmap.php HTTP/1.1" 404 41905 "https://www.google.co.uk/" "Mozilla/5.0 (Linux; Android 10; LM-Q720) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36"
4.213.160.187 - - [31/Dec/2025:15:40:51 +0800] "GET /wp.php HTTP/1.1" 404 41905 "https://www.google.de/" "Mozilla/5.0 (Linux; Android 12; SM-A525F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Mobile Safari/537.36"
4.213.160.187 - - [31/Dec/2025:15:40:52 +0800] "GET /.well-known/rk2.php HTTP/1.1" 404 41905 "https://www.google.co.uk/" "Mozilla/5.0 (iPhone; CPU iPhone OS 15_7_9 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6.5 Mobile/15E148 Safari/604.1"
4.213.160.187 - - [31/Dec/2025:15:40:53 +0800] "GET /.well-known/x.php HTTP/1.1" 404 41905 "https://www.google.com/" "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36"
4.213.160.187 - - [31/Dec/2025:15:40:54 +0800] "GET /wp-admin/maint/chosen.php HTTP/1.1" 404 41905 "https://www.google.com/" "Mozilla/5.0 (Linux; Android 10; LM-Q720) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36"
4.213.160.187 - - [31/Dec/2025:15:40:55 +0800] "GET /wp-admin/network/autoload_classmap.php HTTP/1.1" 404 41912 "https://duckduckgo.com/" "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0.1 Mobile/15E148 Safari/604.1"
4.213.160.187 - - [31/Dec/2025:15:40:57 +0800] "GET /wp-admin/s.php HTTP/1.1" 404 41905 "https://www.google.de/" "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0.1 Mobile/15E148 Safari/604.1"
4.213.160.187 - - [31/Dec/2025:15:40:58 +0800] "GET /wp-admin/w.php HTTP/1.1" 404 41905 "https://www.google.co.uk/" "Mozilla/5.0 (Linux; Android 11; CPH2251) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36"
4.213.160.187 - - [31/Dec/2025:15:40:59 +0800] "GET /wp-admin/z.php HTTP/1.1" 404 41912 "https://www.google.com/" "Mozilla/5.0 (Linux; Android 13; SM-G991U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Mobile Safari/537.36"
192.168.30.21 - - [31/Dec/2025:15:40:59 +0800] "GET /morte.arm7 HTTP/1.0" 403 153 "-" "-"
192.168.30.21 - - [31/Dec/2025:15:41:23 +0800] "GET /morte.sh4 HTTP/1.0" 403 153 "-" "-"
14.212.15.74 - - [31/Dec/2025:15:41:36 +0800] "GET /api/content/posts?_r=1767166847811&page=0&size=10&keyword=&sort=topPriority%2CcreateTime%2Cdesc HTTP/1.1" 200 19530 "https://www.kaisir.cn/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
10.10.0.1 - - [31/Dec/2025:15:41:48 +0800] "GET / HTTP/1.1" 200 19948 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 SafeLine-CE/v9-2-8"
192.168.30.21 - - [31/Dec/2025:15:41:53 +0800] "GET /morte.mpsl HTTP/1.0" 403 153 "-" "-"
192.168.30.21 - - [31/Dec/2025:15:42:13 +0800] "GET /morte.spc HTTP/1.0" 403 153 "-" "-"
192.168.30.21 - - [31/Dec/2025:15:42:14 +0800] "GET /morte.i686 HTTP/1.0" 403 153 "-" "-"
192.168.30.21 - - [31/Dec/2025:15:42:40 +0800] "GET /morte.mips HTTP/1.0" 403 153 "-" "-"
10.10.0.1 - - [31/Dec/2025:15:42:48 +0800] "GET / HTTP/1.1" 200 19948 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 SafeLine-CE/v9-2-8"
180.97.250.103 - - [31/Dec/2025:15:42:57 +0800] "GET /sdk.51.la/js-sdk-pro.min.js HTTP/1.1" 404 239 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
192.168.30.21 - - [31/Dec/2025:15:43:11 +0800] "GET /LjEZs/uYtea.arm7 HTTP/1.0" 403 153 "-" "-"
192.168.30.21 - - [31/Dec/2025:15:43:13 +0800] "GET /LjEZs/uYtea.arm6 HTTP/1.0" 403 153 "-" "-"
10.10.0.1 - - [31/Dec/2025:15:43:48 +0800] "GET / HTTP/1.1" 200 19941 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 SafeLine-CE/v9-2-8"
192.168.30.21 - - [31/Dec/2025:15:44:05 +0800] "GET /LjEZs/uYtea.ppc HTTP/1.0" 403 153 "-" "-"
192.168.30.21 - - [31/Dec/2025:15:44:27 +0800] "GET /LjEZs/uYtea.sh4 HTTP/1.0" 403 153 "-" "-"
192.168.30.21 - - [31/Dec/2025:15:44:37 +0800] "GET /LjEZs/uYtea.m68k HTTP/1.0" 403 153 "-" "-"
10.10.0.1 - - [31/Dec/2025:15:44:48 +0800] "GET / HTTP/1.1" 200 19948 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 SafeLine-CE/v9-2-8"
192.168.30.21 - - [31/Dec/2025:15:45:19 +0800] "GET /LjEZs/uYtea.x86_64 HTTP/1.0" 403 153 "-" "-"
192.168.30.21 - - [31/Dec/2025:15:45:36 +0800] "GET /LjEZs/uYtea.spc HTTP/1.0" 403 153 "-" "-"
```

#### IP排除问题
默认会排除内网/保留地址 IP。如果你想把内网 IP 的访问也纳入 PV 统计，可以把 `PV_EXCLUDE_IPS` 传为空数组（`[]`），或在配置文件中将 `excludeIPs` 设置为空数组。

## 目录结构与主要文件

```
.
├── cmd/
│   └── nginxpulse/
│       └── main.go                 # 程序入口
├── internal/                       # 核心逻辑（解析、统计、存储、API）
│   ├── app/
│   │   └── app.go                  # 初始化、依赖装配、任务调度
│   ├── analytics/                  # 统计口径与聚合
│   ├── enrich/
│   │   ├── ip_geo.go               # IP 归属地（远程+本地）与缓存
│   │   └── pv_filter.go            # PV 过滤规则
│   ├── ingest/
│   │   └── log_parser.go           # 日志扫描、解析与入库
│   ├── server/
│   │   └── http.go                 # HTTP 服务与中间件
│   ├── store/
│   │   └── repository.go           # PostgreSQL 结构与写入
│   ├── version/
│   │   └── info.go                 # 版本信息注入
│   ├── webui/
│   │   └── dist/                   # 单体嵌入的前端静态资源
│   └── web/
│       └── handler.go              # API 路由
├── webapp/
│   └── src/
│       └── main.ts                 # 前端入口
├── configs/
│   ├── nginxpulse_config.json      # 核心配置入口
│   ├── nginxpulse_config.dev.json  # 本地开发配置
│   └── nginx_frontend.conf         # 内置 Nginx 配置
├── docs/
│   └── versioning.md               # 版本管理与发布说明
├── scripts/
│   ├── build_single.sh             # 单体构建脚本
│   ├── dev_local.sh                # 本地一键启动
│   └── publish_docker.sh           # 推送 Docker 镜像
├── var/                            # 数据目录（运行时生成/挂载）
│   └── log/
│       └── gz-log-read-test/       # gzip 参考日志
├── Dockerfile
└── docker-compose.yml
```

---

如需更详细的统计口径或 API 扩展，建议从 `internal/analytics/` 与 `internal/web/handler.go` 开始。

## 写在最后

本项目大部分代码通过codex生成，我投喂了很多开源项目和资料让他做参考，在此感谢大家对开源社区的贡献。

* [有没有好用的 nginx 日志看板展示项目](https://v2ex.com/t/1178789)
* [nixvis](https://github.com/BeyondXinXin/nixvis)
* [goaccess](https://github.com/allinurl/goaccess)
* [prometheus监控nginx的两种方式原创](https://blog.csdn.net/lvan_test/article/details/123579531)
* [通过nginx-prometheus-exporter监控nginx指标](https://maxidea.gitbook.io/k8s-testing/prometheus-he-grafana-de-dan-ji-bian-pai/tong-guo-nginxprometheusexporter-jian-kong-nginx)
* [Prometheus 监控nginx服务 ](https://www.cnblogs.com/zmh520/p/17758730.html)
* [Prometheus监控Nginx](https://zhuanlan.zhihu.com/p/460300628)
