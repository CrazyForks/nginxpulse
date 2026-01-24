# 部署方式

## 版本要求
- 版本 > 1.5.3 必须部署 PostgreSQL，SQLite 已弃用。

## Docker 单容器（内置 PostgreSQL）
镜像内已集成 PostgreSQL，推荐此方式。

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

示例（需挂载日志与数据目录）：
```bash
docker run -d --name nginxpulse \
  -p 8088:8088 -p 8089:8089 \
  -e WEBSITES='[{"name":"主站","logPath":"/share/log/nginx/access.log","domains":["example.com"]}]' \
  -v /path/to/nginx/access.log:/share/log/nginx/access.log:ro \
  -v /path/to/nginxpulse_data:/app/var/nginxpulse_data \
  -v /path/to/pgdata:/app/var/pgdata \
  -v /etc/localtime:/etc/localtime:ro \
  nginxpulse:latest
```

常用环境变量（容器内置 PG）：
- `POSTGRES_USER`/`POSTGRES_PASSWORD`/`POSTGRES_DB`: PG 账号与库名
- `POSTGRES_PORT`: PG 端口（默认 5432）
- `POSTGRES_LISTEN`: PG 监听地址（默认 127.0.0.1）
- `POSTGRES_CONNECT_HOST`: 应用连接 PG 的地址（默认 127.0.0.1）
- `DATA_DIR`: 数据目录（默认 `/app/var/nginxpulse_data`）
- `PGDATA`: PG 数据目录（默认 `/app/var/pgdata`）

如果你想外接自建 PG，可显式传入 `DB_DSN`，内置 PG 会被绕过。
此时不会启动内置 PG，`POSTGRES_*` 参数会被忽略，`/app/var/pgdata` 也无需挂载。

## Docker Compose
仓库根目录已提供 `docker-compose.yml`，可直接复制修改：
- 调整 `WEBSITES` 与日志挂载路径。
- 挂载 `nginxpulse_data` 保持数据持久化；如使用内置 PG 再挂载 `pgdata`。
- 保持 `/etc/localtime` 只读挂载，以确保时区一致。

一键启动（极简配置，首次启动进入初始化向导）：
```bash
docker compose -f docker-compose-simple.yml up -d
```

## 单体部署（非 Docker）
适用于裸机或自建服务环境。需要用户自行安装 PostgreSQL。

步骤建议：
1. 安装 PostgreSQL 并创建数据库与用户。
2. 配置 `configs/nginxpulse_config.json` 中的 `database.dsn`。
3. 启动服务（可使用 `scripts/build_single.sh` 构建后运行）。

`database.dsn` 示例：
```json
"database": {
  "driver": "postgres",
  "dsn": "postgres://nginxpulse:nginxpulse@127.0.0.1:5432/nginxpulse?sslmode=disable",
  "maxOpenConns": 10,
  "maxIdleConns": 5,
  "connMaxLifetime": "30m"
}
```

## 本地开发
使用 `scripts/dev_local.sh`：
- 默认启动本地 docker postgres（`nginxpulse-postgres`），数据落在 docker volume `nginxpulse_pgdata`。
- 如需全量重置：`docker volume rm nginxpulse_pgdata`。

## 端口说明
- 8088: 前端页面
- 8089: API 服务

## 时区设置
本项目使用系统时区进行日志解析与统计，请确保运行环境时区正确。
- Docker: 挂载 `/etc/localtime:/etc/localtime:ro`
- 裸机: 确保系统时区已配置（例如 `timedatectl set-timezone Asia/Shanghai`）
