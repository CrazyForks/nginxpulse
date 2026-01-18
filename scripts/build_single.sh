#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEBAPP_DIR="$ROOT_DIR/webapp"
WEBUI_DIST_DIR="$ROOT_DIR/internal/webui/dist"
BIN_DIR="$ROOT_DIR/bin"
CONFIG_SRC="$ROOT_DIR/configs/nginxpulse_config.json"
GZ_LOG_SRC="$ROOT_DIR/var/log/gz-log-read-test"
VERSION="${VERSION:-$(git -C "$ROOT_DIR" describe --tags --abbrev=0 2>/dev/null || echo "dev")}"
BUILD_TIME="${BUILD_TIME:-$(date "+%Y-%m-%d %H:%M:%S")}"
GIT_COMMIT="${GIT_COMMIT:-$(git -C "$ROOT_DIR" rev-parse --short=7 HEAD 2>/dev/null || echo "unknown")}"
LDFLAGS="-s -w -X 'github.com/likaia/nginxpulse/internal/version.Version=${VERSION}' -X 'github.com/likaia/nginxpulse/internal/version.BuildTime=${BUILD_TIME}' -X 'github.com/likaia/nginxpulse/internal/version.GitCommit=${GIT_COMMIT}'"

if [[ ! -d "$WEBAPP_DIR" ]]; then
  echo "webapp directory not found." >&2
  exit 1
fi

if [[ ! -f "$WEBAPP_DIR/package.json" ]]; then
  echo "webapp/package.json not found." >&2
  exit 1
fi

echo "Building frontend..."
(cd "$WEBAPP_DIR" && npm install && npm run build)

echo "Preparing embedded assets..."
rm -rf "$WEBUI_DIST_DIR"
mkdir -p "$WEBUI_DIST_DIR"
cp -R "$WEBAPP_DIR/dist/." "$WEBUI_DIST_DIR/"

echo "Building single binary (version: ${VERSION})..."
(cd "$ROOT_DIR" && go build -tags embed -ldflags="${LDFLAGS}" -o bin/nginxpulse ./cmd/nginxpulse/main.go)

echo "Copying default config and gz samples..."
if [[ ! -f "$CONFIG_SRC" ]]; then
  echo "Missing config file: $CONFIG_SRC" >&2
  exit 1
fi
mkdir -p "$BIN_DIR/configs"
cp "$CONFIG_SRC" "$BIN_DIR/configs/nginxpulse_config.json"
tmp_config="$(mktemp)"
awk '
  BEGIN { in_server=0; updated=0 }
  {
    if ($0 ~ /"server"[[:space:]]*:/) { in_server=1 }
    if (in_server && $0 ~ /"Port"[[:space:]]*:/) {
      sub(/"Port"[[:space:]]*:[[:space:]]*"[^"]*"/, "\"Port\": \":8088\"")
      updated=1
    }
    if (in_server && $0 ~ /}/) { in_server=0 }
    print
  }
  END {
    if (!updated) {
      exit 1
    }
  }
' "$BIN_DIR/configs/nginxpulse_config.json" > "$tmp_config"
if [[ $? -ne 0 ]]; then
  rm -f "$tmp_config"
  echo "Failed to update server port in bin config." >&2
  exit 1
fi
mv "$tmp_config" "$BIN_DIR/configs/nginxpulse_config.json"

if [[ ! -d "$GZ_LOG_SRC" ]]; then
  echo "Gzip sample folder not found: $GZ_LOG_SRC" >&2
  exit 1
fi
mkdir -p "$BIN_DIR/var/log"
rm -rf "$BIN_DIR/var/log/gz-log-read-test"
cp -R "$GZ_LOG_SRC" "$BIN_DIR/var/log/"

echo "Done: bin/nginxpulse"
