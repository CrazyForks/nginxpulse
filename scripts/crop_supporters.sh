#!/usr/bin/env bash
set -euo pipefail

size=80
out_dir=""

usage() {
  cat <<'EOF'
Usage: scripts/crop_supporters.sh [-s size] [-o output_dir] <image1> [image2 ...]

Creates circular PNG avatars from input images using ffmpeg.
- Centers, crops to square, scales to size, then applies a circular alpha mask.

Options:
  -s size        Output size (pixels). Default: 80
  -o output_dir  Output directory. Default: same as input image
  -h             Show this help
EOF
}

while getopts ":s:o:h" opt; do
  case "$opt" in
    s) size="$OPTARG" ;;
    o) out_dir="$OPTARG" ;;
    h) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done
shift $((OPTIND-1))

if [ $# -lt 1 ]; then
  usage
  exit 1
fi

if ! command -v ffmpeg >/dev/null 2>&1; then
  echo "ffmpeg not found in PATH." >&2
  exit 1
fi

for src in "$@"; do
  if [ ! -f "$src" ]; then
    echo "skip (not a file): $src" >&2
    continue
  fi

  base="$(basename "$src")"
  name="${base%.*}"
  dir="${out_dir:-$(dirname "$src")}";
  mkdir -p "$dir"
  out="$dir/$name.png"

  ffmpeg -y -hide_banner -loglevel error -i "$src" \
    -vf "scale=${size}:${size}:force_original_aspect_ratio=increase,crop=${size}:${size},format=rgba,geq=r='r(X,Y)':g='g(X,Y)':b='b(X,Y)':a='if(lte((X-W/2)*(X-W/2)+(Y-H/2)*(Y-H/2),(W/2)*(W/2)),255,0)'" \
    -frames:v 1 "$out"

  echo "wrote $out"
done
