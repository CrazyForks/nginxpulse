# 版本号与发布流程

本文档说明 NginxPulse 的版本号使用方式与发布流程（单体构建、GitHub Release、Docker Hub 推送）。

## 1) 给提交记录打 tag

采用语义化版本，例如 `v0.4.8`：

```bash
git tag v0.4.8
git push --tags
```

说明：
- 二进制版本号来自 Git tag（无 tag 时显示 `dev`）。
- 版本号会在 `/api/status` 和 `/api/version` 返回。

## 2) 单体构建（本地）

执行脚本会内置前端资源并注入版本信息：

```bash
./scripts/build_single.sh
```

构建产物：
- `bin/nginxpulse`（内置前端 + 后端）

可选：手动指定版本号
```bash
VERSION=v0.4.8 ./scripts/build_single.sh
```

## 3) GitHub Release（自动 Action）

1. 推送 tag 后，在 GitHub 上创建 Release 并发布（Release 类型：`published`）。
2. Actions 会自动构建多平台单体包并上传到 Release Assets：
   - `nginxpulse-<tag>-<os>-<arch>.tar.gz` / `.zip`
   - `checksums-<tag>-<os>-<arch>.txt`
   - `nginxpulse_config.json`（默认配置）

若需手动触发，也可在 Actions 页面使用 `workflow_dispatch`。

## 4) Docker Hub 推送（使用 publish_docker.sh）

脚本会自动读取当前 Git tag 作为版本号，并同时推送 `latest`：

```bash
# 登录 Docker Hub
docker login

# 推送镜像
scripts/publish_docker.sh -r yourname/nginxpulse
```

说明：
- 如果当前 commit 有 tag（如 `v0.4.8`），会使用该 tag。
- 如果没有 tag，会自动回退为 `git describe` 或时间戳。
- 默认会推送 `vX.Y.Z` 与 `latest` 两个 tag。
