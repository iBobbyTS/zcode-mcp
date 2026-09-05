#!/bin/sh
set -eu

package_file=$(find .agent-work/evidence/npm-tarball -maxdepth 1 -name 'zcode-as-subagent-*.tgz' -type f | head -1)
test -n "$package_file"

tar -tzf "$package_file" > .agent-work/evidence/npm-tarball/contents.txt
grep -qx 'package/npm/native/darwin-arm64/zcode-agentd' .agent-work/evidence/npm-tarball/contents.txt
if grep -Eq '(^|/)(\.agent-work|workspace|target|node_modules|\.npm|.*\.sqlite3|.*\.log|.*credentials|.*runtime)' .agent-work/evidence/npm-tarball/contents.txt; then
  echo 'forbidden release material found' >&2
  exit 1
fi

file npm/native/darwin-arm64/zcode-agentd | grep -q 'Mach-O 64-bit executable arm64'
test "$(stat -f '%Lp' npm/native/darwin-arm64/zcode-agentd)" = 755
shasum -a 256 npm/native/darwin-arm64/zcode-agentd "$package_file" > .agent-work/evidence/npm-tarball/sha256sums.txt
printf '%s\n' 'native tarball static checks passed'
