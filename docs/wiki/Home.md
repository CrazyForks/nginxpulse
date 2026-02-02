# NginxPulse Wiki

README 只保留“最快上手 + 关键告警”，细节统一放在 Wiki。

## 语言
- 中文（当前页）
- English: [Home-EN](Home-EN)

## 从这里开始
1. [快速开始](Quick-Start)
2. [部署方式](Deployment)
3. [SQLite -> PostgreSQL 迁移](Migration-SQLite-to-Postgres)
4. [配置说明](Configuration)
5. [日志解析机制](Log-Parsing)
6. [IP 归属地解析](IP-Geo)
7. [数据库结构](Database-Schema)
8. [常见问题](FAQ)

## 快速提醒
- 版本 > 1.5.3 必须部署 PostgreSQL（SQLite 已弃用）。
- 本项目使用系统时区解析日志，请确保运行环境时区正确。
- 站点 ID 由 `websites[].name` 生成，改名会被视为新站点。
- 多日志挂载、远端日志 `sources`、Push Agent 见《日志解析机制》。

## 常用路径
- 配置文件: `configs/nginxpulse_config.json`
- 数据目录: `var/nginxpulse_data`
- 扫描状态: `var/nginxpulse_data/nginx_scan_state.json`
- 应用日志: `var/nginxpulse_data/nginxpulse.log`
