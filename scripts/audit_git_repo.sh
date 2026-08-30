#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(git -C "$script_dir/.." rev-parse --show-toplevel)"
timestamp="$(date '+%Y%m%d-%H%M')"
archive_path="$repo_root/$timestamp.zip"

if [[ -e "$archive_path" ]]; then
  printf 'Refusing to overwrite existing archive: %s\n' "$archive_path" >&2
  exit 1
fi

temporary_dir="$(mktemp -d "${TMPDIR:-/tmp}/zcode-mcp-audit.XXXXXX")"
temporary_archive="$temporary_dir/$timestamp.zip"

cleanup() {
  rm -f "$temporary_archive"
  rmdir "$temporary_dir" 2>/dev/null || true
}
trap cleanup EXIT

(
  cd "$repo_root"
  COPYFILE_DISABLE=1 zip -qry "$temporary_archive" . \
    -x 'target' 'target/*' \
       'tests/live-agent/workspace' 'tests/live-agent/workspace/*' \
       'tests/live-agent/git-based' 'tests/live-agent/git-based/*' \
       '.codegraph' '.codegraph/*' \
       'zcode-subagent-mcp-????????-????.zip'
)

zip -T "$temporary_archive" >/dev/null
mv "$temporary_archive" "$archive_path"

printf '%s\n' "$archive_path"
