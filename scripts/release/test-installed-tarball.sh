#!/bin/sh
set -eu

package_file=$(find .agent-work/evidence/npm-tarball -maxdepth 1 -name 'zcode-as-subagent-*.tgz' -type f | head -1)
test -n "$package_file"
prefix=$(mktemp -d)
test_home=$(mktemp -d)
trap 'rm -rf "$prefix" "$test_home"' EXIT INT TERM

HOME="$test_home" npm install --global --prefix "$prefix" "$package_file" > .agent-work/evidence/npm-tarball/install.log
HOME="$test_home" "$prefix/bin/zcode-as-subagent" status > .agent-work/evidence/npm-tarball/status.json
HOME="$test_home" "$prefix/bin/zcode-as-subagent" init --dry-run > .agent-work/evidence/npm-tarball/dry-run.json
HOME="$test_home" "$prefix/bin/zcode-as-subagent" init > .agent-work/evidence/npm-tarball/init.json

daemon="$prefix/lib/node_modules/zcode-as-subagent/npm/native/darwin-arm64/zcode-agentd"
plist="$test_home/Library/LaunchAgents/com.zcode-as-subagent.daemon.plist"
test -x "$daemon"
test -f "$plist"
grep -Fq "$daemon" "$plist"
grep -Fq '/Applications/ZCode.app/Contents/Resources/glm/zcode.cjs' "$plist"
printf '%s\n' 'installed tarball checks passed'
