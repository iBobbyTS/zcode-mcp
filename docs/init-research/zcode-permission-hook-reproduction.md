# ZCode Edit Mode Bash Hook 复现记录

## 结论

ZCode app-server 的 edit mode 会自动执行文件编辑，但 Bash 仍要求 permission。没有公开的 Bash 命令数量上限，也没有公开完整的危险命令自动拒绝清单。

Hook 的 matcher 匹配工具名，不匹配 Bash 命令文本。命令文本在 hook stdin JSON 的 tool_input.command 中。应使用 matcher=Bash 锁定工具，再由外部脚本解析命令。

官方文档：

- https://zcode.z.ai/en/docs/safety-confirm
- https://zcode.z.ai/en/docs/agents
- https://zcode.z.ai/en/docs/hooks

## 环境

```text
runtime=/Applications/ZCode.app/Contents/Resources/glm/zcode.cjs
runtime_sha256=3597160465b67da248fa3fb919920ca30d4e093003a4d70cde2a2e33903cbabc
workspace=/Users/ibobby/SCSC/Development/scsc-mms
mode=edit
```

测试前后目标仓库均保留原有用户改动：

```text
 M src/lib/client-form-source.test.ts
 M src/lib/components/ClientForm.svelte
 M src/lib/components/PersonBasicInfoSection.svelte
```

## 用户级配置

```text
/Users/ibobby/.zcode/cli/config.json
/Users/ibobby/.zcode/hooks/check-bash-status.mjs
```

配置关键字段：hooks.enabled=true，hooks.events.PreToolUse 中有 matcher=Bash 的 process hook，脚本为上述绝对路径，timeoutMs=5000。

脚本只允许两种完整命令：

```text
git status --short
git -C /任意绝对路径 status --short
```

绝对路径表达式拒绝 shell 拼接或重定向字符：`; & | < > $ \` ( )`。不要使用 includes("git status") 这类子串判断。

核心判断等价于：

```js
tool === 'Bash' && (/^git status --short$/ 或 /^git -C \/[安全路径字符]+ status --short$/)
```

## Matcher 规则

- 缺省、空字符串、*：匹配所有工具。
- 只含字母、数字、下划线和 |：工具名精确匹配，例如 Write|Edit。
- 含其他字符：按 JavaScript 正则处理。
- Bash 匹配所有 Bash，不能在 matcher 中直接匹配命令文本。

PreToolUse 可 allow、deny 或替换完整 input；PermissionRequest 只在本来需要确认时触发。多个 hook 聚合时 deny 大于 ask，ask 大于 allow。

## 复现

启动：

```bash
node /Applications/ZCode.app/Contents/Resources/glm/zcode.cjs app-server --stdio --surface desktop
```

创建 session 后调用 session/setMode(mode=edit)，再要求模型只读检查 `/Users/ibobby/SCSC/Development/scsc-mms`，执行两条 git status 命令，不写文件、不测试、不构建、不改变 Docker。

无 Hook 基线记录：

```text
/private/tmp/zcode-status-before.y9wfRG/result.json
permission requests=1; Bash git -C ... status --short; decision=deny; turn=success
```

添加 Hook 并创建新 session 后记录：

```text
/private/tmp/zcode-status-after.M33lJM/result.json
permission requests=0; completed Bash calls=2; both status commands completed; turn=success
```

## 校验和回滚

```bash
node --check /Users/ibobby/.zcode/hooks/check-bash-status.mjs
cp /Users/ibobby/.zcode/cli/config.json.before-status-hook-20260828 /Users/ibobby/.zcode/cli/config.json
```

回滚前确认没有其他用户配置改动。修改 Hook 后必须启动新 session；运行中的 session 不保证热加载。

用户级 Hook 会影响所有工作区。当前版本不执行 `<workspace>/.zcode/config.json` 中的 project-level hooks。Always Allow in this project 是 ZCode 内部 permission rule，与 Hook matcher 不是同一语法；不要直接修改 `~/.zcode/cli/db/db.sqlite` 作为配置接口。
