# Deployment

## Version requirement
- Version > 1.5.3 requires PostgreSQL. SQLite is deprecated.

## Docker single-container (built-in PostgreSQL)
The image includes PostgreSQL. Recommended for most users.

One-click start (minimal config, first launch opens Setup Wizard):
```bash
docker run -d --name nginxpulse \
  -p 8088:8088 \
  -v ./docker_local/logs:/share/logs:ro \
  -v ./docker_local/nginxpulse_data:/app/var/nginxpulse_data \
  -v ./docker_local/pgdata:/app/var/pgdata \
  -v /etc/localtime:/etc/localtime:ro \
  magiccoders/nginxpulse:latest
```

Example:
```bash
docker run -d --name nginxpulse \
  -p 8088:8088 -p 8089:8089 \
  -e WEBSITES='[{"name":"Main","logPath":"/share/log/nginx/access.log","domains":["example.com"]}]' \
  -v /path/to/nginx/access.log:/share/log/nginx/access.log:ro \
  -v /path/to/nginxpulse_data:/app/var/nginxpulse_data \
  -v /path/to/pgdata:/app/var/pgdata \
  -v /etc/localtime:/etc/localtime:ro \
  nginxpulse:latest
```

Useful env vars (built-in PG):
- `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB`
- `POSTGRES_PORT` (default 5432)
- `POSTGRES_LISTEN` (default 127.0.0.1)
- `POSTGRES_CONNECT_HOST` (default 127.0.0.1)
- `DATA_DIR` (default `/app/var/nginxpulse_data`)
- `PGDATA` (default `/app/var/pgdata`)

If you want to use an external PG, set `DB_DSN` and the built-in PG will be bypassed.
In this case the built-in PG will not start, `POSTGRES_*` is ignored, and you can drop the `/app/var/pgdata` mount.

## Docker Compose
A `docker-compose.yml` is provided in the repo. Update:
- `WEBSITES` and log volume
- `nginxpulse_data` volume; mount `pgdata` only when using built-in PG
- `/etc/localtime` mount for timezone

One-click start (minimal config, first launch opens Setup Wizard):
```bash
docker compose -f docker-compose-simple.yml up -d
```

## Single binary (non-Docker)
You must install PostgreSQL yourself.

Suggested steps:
1. Install PostgreSQL and create DB/user.
2. Set `database.dsn` in `configs/nginxpulse_config.json`.
3. Build & run (e.g. `scripts/build_single.sh`).

Example DSN:
```json
"database": {
  "driver": "postgres",
  "dsn": "postgres://nginxpulse:nginxpulse@127.0.0.1:5432/nginxpulse?sslmode=disable",
  "maxOpenConns": 10,
  "maxIdleConns": 5,
  "connMaxLifetime": "30m"
}
```

## Local development
Use `scripts/dev_local.sh`:
- It starts a local docker postgres container by default.
- Data is stored in docker volume `nginxpulse_pgdata`.
- To reset: `docker volume rm nginxpulse_pgdata`.

## Ports
- 8088: Web UI
- 8089: API

## Timezone
The project uses system timezone for parsing.
- Docker: mount `/etc/localtime:/etc/localtime:ro`
- Bare metal: set system timezone and restart
