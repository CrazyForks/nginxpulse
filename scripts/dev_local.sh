#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_CONFIG="$ROOT_DIR/configs/nginxpulse_config.dev.json"
VERSION="${VERSION:-$(git -C "$ROOT_DIR" describe --tags --abbrev=0 2>/dev/null || echo "dev")}"
BUILD_TIME="${BUILD_TIME:-$(date "+%Y-%m-%d %H:%M:%S")}"
GIT_COMMIT="${GIT_COMMIT:-$(git -C "$ROOT_DIR" rev-parse --short=7 HEAD 2>/dev/null || echo "unknown")}"
LDFLAGS="-s -w -X 'github.com/likaia/nginxpulse/internal/version.Version=${VERSION}' -X 'github.com/likaia/nginxpulse/internal/version.BuildTime=${BUILD_TIME}' -X 'github.com/likaia/nginxpulse/internal/version.GitCommit=${GIT_COMMIT}'"

backend_pid=""
frontend_pid=""

ensure_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "$cmd not found in PATH. Please install it and retry." >&2
    exit 1
  fi
}

ensure_go_deps() {
  if [[ ! -f "$ROOT_DIR/go.sum" ]]; then
    echo "go.sum missing, running go mod tidy..."
    (cd "$ROOT_DIR" && GOFLAGS="-mod=mod" go mod tidy)
  fi
}

ensure_config() {
  local config_path="$DEV_CONFIG"
  if [[ ! -f "$config_path" ]]; then
    local base_config="$ROOT_DIR/configs/nginxpulse_config.json"
    if [[ ! -f "$base_config" ]]; then
      echo "configs/nginxpulse_config.json not found. Please create it first." >&2
      exit 1
    fi
    cp "$base_config" "$config_path"
    echo "Created configs/nginxpulse_config.dev.json from nginxpulse_config.json"
    echo "Edit configs/nginxpulse_config.dev.json and re-run." >&2
    exit 1
  fi
}

ensure_frontend_deps() {
  local install_needed=0
  if [[ ! -d "$ROOT_DIR/webapp/node_modules" ]]; then
    install_needed=1
  elif [[ "$ROOT_DIR/webapp/package.json" -nt "$ROOT_DIR/webapp/node_modules" ]]; then
    install_needed=1
  elif [[ -f "$ROOT_DIR/webapp/package-lock.json" && "$ROOT_DIR/webapp/package-lock.json" -nt "$ROOT_DIR/webapp/node_modules" ]]; then
    install_needed=1
  fi

  if [[ "$install_needed" -eq 1 ]]; then
    echo "Installing frontend dependencies..."
    if [[ -f "$ROOT_DIR/webapp/package-lock.json" ]]; then
      (cd "$ROOT_DIR/webapp" && npm ci) || (cd "$ROOT_DIR/webapp" && npm install)
    else
      (cd "$ROOT_DIR/webapp" && npm install)
    fi
  fi
}

start_backend() {
  echo "Starting backend on http://localhost:8089"
  (cd "$ROOT_DIR" && CONFIG_JSON="$(cat "$DEV_CONFIG")" SERVER_PORT=":8089" go run -ldflags="${LDFLAGS}" ./cmd/nginxpulse/main.go) &
  backend_pid=$!
}

start_frontend() {
  echo "Starting frontend on http://localhost:8088"
  (cd "$ROOT_DIR/webapp" && npm run dev) &
  frontend_pid=$!
}

cleanup() {
  if [[ -n "$frontend_pid" ]]; then
    kill "$frontend_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "$backend_pid" ]]; then
    kill "$backend_pid" >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT INT TERM

ensure_cmd go
ensure_cmd node
ensure_cmd npm
ensure_go_deps
ensure_config
ensure_frontend_deps

start_backend
start_frontend

wait
