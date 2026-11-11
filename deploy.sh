#!/usr/bin/env bash
set -euo pipefail
SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" && pwd)
if [[ -f "$SOURCE_DIR/install.sh" ]]; then exec bash "$SOURCE_DIR/install.sh" "$@"; fi
file=$(mktemp /tmp/wdtt-panel-install.XXXXXX.sh)
curl -fsSL https://raw.githubusercontent.com/ttrroyy/wdtt-panel/main/install.sh -o "$file"
exec bash "$file" "$@"
