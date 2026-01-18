#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage: scripts/publish_docker.sh -r <repo> [-v <version>] [-p <platforms>] [--no-push]

Options:
  -r, --repo        Docker Hub repo, e.g. username/nginxpulse
  -v, --version     Version tag (defaults to git describe or timestamp)
  -p, --platforms   Build platforms (default: linux/amd64)
  --no-push         Build only (no push)

Environment:
  DOCKERHUB_REPO    Same as --repo
  VERSION           Same as --version
  PLATFORMS         Same as --platforms
EOF
}

REPO="${DOCKERHUB_REPO:-}"
VERSION="${VERSION:-}"
PLATFORMS="${PLATFORMS:-linux/amd64}"
TAG_LATEST=true
PUSH=true

while [[ $# -gt 0 ]]; do
  case "$1" in
    -r|--repo)
      REPO="$2"
      shift 2
      ;;
    -v|--version)
      VERSION="$2"
      shift 2
      ;;
    -p|--platforms)
      PLATFORMS="$2"
      shift 2
      ;;
    --no-push)
      PUSH=false
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$REPO" ]]; then
  echo "Missing repo. Use -r or DOCKERHUB_REPO." >&2
  exit 1
fi

if [[ -z "$VERSION" ]]; then
  if git -C "$ROOT_DIR" describe --tags --exact-match >/dev/null 2>&1; then
    VERSION="$(git -C "$ROOT_DIR" describe --tags --exact-match)"
  else
    VERSION="$(git -C "$ROOT_DIR" describe --tags --abbrev=7 --always 2>/dev/null || date -u +%Y%m%d%H%M%S)"
  fi
fi

BUILD_TIME="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
GIT_COMMIT="$(git -C "$ROOT_DIR" rev-parse --short=7 HEAD 2>/dev/null || echo "unknown")"

TAG_LIST=("$REPO:$VERSION")
if $TAG_LATEST; then
  TAG_LIST+=("$REPO:latest")
fi
TAGS=()
for tag in "${TAG_LIST[@]}"; do
  TAGS+=(-t "$tag")
done

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker CLI not found." >&2
  exit 1
fi

BUILD_ARGS=(
  --build-arg "BUILD_TIME=$BUILD_TIME"
  --build-arg "GIT_COMMIT=$GIT_COMMIT"
  --build-arg "VERSION=$VERSION"
)

echo "Repo:     $REPO"
echo "Version:  $VERSION"
echo "Platforms:$PLATFORMS"
echo "Commit:   $GIT_COMMIT"
echo "Time:     $BUILD_TIME"

if $PUSH; then
  if docker buildx version >/dev/null 2>&1; then
    docker buildx build \
      --platform "$PLATFORMS" \
      --push \
      "${TAGS[@]}" \
      "${BUILD_ARGS[@]}" \
      -f "$ROOT_DIR/Dockerfile" \
      "$ROOT_DIR"
  else
    if [[ "$PLATFORMS" != "linux/amd64" ]]; then
      echo "Docker buildx is required for multi-arch builds." >&2
      exit 1
    fi
    docker build \
      "${TAGS[@]}" \
      "${BUILD_ARGS[@]}" \
      -f "$ROOT_DIR/Dockerfile" \
      "$ROOT_DIR"
    for tag in "${TAG_LIST[@]}"; do
      docker push "$tag"
    done
  fi
else
  docker build \
    "${TAGS[@]}" \
    "${BUILD_ARGS[@]}" \
    -f "$ROOT_DIR/Dockerfile" \
    "$ROOT_DIR"
fi
