# ZCode Agent-as-MCP 执行报告

## 0. 执行状态

这是一份交给本地实施 Agent 的完整工程工单。

当前已完成：

- 项目与协议调研。
- 架构选择。
- 生命周期和 MCP API 设计。
- 与 `sectioned-feature-development` 的集成设计。
- 风险和验收条件定义。

当前未宣称完成：

- 未在用户本机 clone 仓库。
- 未检测用户本机 ZCode runtime 路径。
- 未编写或编译 MCP。
- 未对当前安装的 ZCode 版本执行 integration smoke test。

本地 Agent 必须如实记录执行结果，不得把 fake app-server 测试通过表述为真实 ZCode runtime 已通过。

---

## 1. 实施目标

创建一个独立项目：

```text
zcode-review-mcp
```

它应当允许 Codex：

1. 启动一个在官方 ZCode runtime 内运行的 GLM reviewer。
2. 立即获得稳定的 `agent_id`，不等待 review 完成。
3. 查看 active/recent Agent。
4. 获取结构化进度和 event cursor。
5. 停止 Agent。
6. 向 Agent 排队消息。
7. 必要时停止当前 turn 后继续发送指令。
8. 回答 permission 或 user-input request。
9. 获取持续生成的 Markdown review report。
10. 获取最终报告、hash、runtime/session provenance。
11. 在 MCP server 重启后继续管理已有任务。
12. 供 `sectioned-feature-development` 的 Plan Review 和 Code Review 调用。

---

## 2. 硬性边界

实施期间不得违反以下约束：

- 不把 GLM provider 直接塞进 Codex。
- 不重新实现一个第三方 GLM coding agent。
- 实际审查必须由本地官方 ZCode Agent runtime 执行。
- 不打包、提交或分发 `zcode.cjs`。
- 不从社区 release 自动下载 ZCode runtime。
- 不反编译、patch 或重写官方 runtime。
- 只使用用户本机已经安装的官方 runtime。
- 不把 ZCode 底层 Read/Bash/Edit 等工具逐个暴露给 Codex。
- 外层 MCP 只暴露 Agent 生命周期操作。
- GLM reviewer 不得直接成为 admission authority。
- 不依赖一个长时间阻塞的 MCP tool call。
- 不把 MCP progress notification 作为唯一进度通道。
- 不宣称支持未经验证的同 turn live steering。
- 不让 Agent 在用户正式工作树中运行。
- 不把 hidden reasoning 记录到报告或事件日志。
- 不修改 `sectioned-feature-development`，直到 daemon、MCP、ledger 和 fake-runtime 测试全部通过。

---

## 3. 建立实施分支和目录

在目标 workspace 中：

```bash
git switch -c codex/zcode-review-mcp

mkdir -p references
mkdir -p docs
mkdir -p schemas
mkdir -p prompts
mkdir -p tests
```

将 `references/` 加入 `.gitignore`，只提交固定的 commit 清单和研究笔记，不把第三方仓库内容直接纳入产品仓库。

---

## 4. 下载参考项目

### 4.1 核心 ZCode 参考

```bash
git clone --depth=1 \
  https://github.com/jpalmae/zcode-acp.git \
  references/zcode-acp

git clone --depth=1 \
  https://github.com/kingsword09/zcode-cli.git \
  references/zcode-cli

git clone --depth=1 \
  https://github.com/gaozhi-ustc/zcode-tui.git \
  references/zcode-tui
```

### 4.2 Agent 调度参考

```bash
git clone --depth=1 \
  https://github.com/BennyKok/omg.dev.git \
  references/omg.dev

git clone --depth=1 \
  https://github.com/tintinweb/pi-subagents.git \
  references/pi-subagents

git clone --depth=1 \
  https://github.com/quazardous/sailing.git \
  references/sailing

git clone --depth=1 \
  https://github.com/yigitkonur/mcp-supersubagents.git \
  references/mcp-supersubagents
```

必要时额外下载：

```bash
git clone --depth=1 \
  https://github.com/shinpr/sub-agents-mcp.git \
  references/sub-agents-mcp
```

### 4.3 固定引用版本

```bash
{
  for repo in references/*; do
    if [ -d "$repo/.git" ]; then
      (
        cd "$repo"
        printf '%s\t%s\t%s\n' \
          "$(basename "$repo")" \
          "$(git remote get-url origin)" \
          "$(git rev-parse HEAD)"
      )
    fi
  done
} | sort > REFERENCES.lock
```

### 4.4 License preflight

```bash
find references \
  -maxdepth 3 \
  \( -iname 'LICENSE' -o -iname 'LICENSE.*' -o -iname 'COPYING*' \) \
  -print
```

生成：

```text
docs/reference-license-matrix.md
```

至少记录：

| Repo | Commit | License file | 允许借鉴设计 | 允许复制代码 | 实际复制文件 |
|---|---|---|---|---|---|

在 license 尚未确认前，只能重写协议和设计，不能复制代码。

社区实现使用的是私有 app-server 协议；`zcode-acp` 适合作为 typed driver 参考，两个 TUI 项目用于交叉核对协议和运行语义。

---

## 5. 推荐技术栈和代码结构

优先使用 **Rust workspace**，原因是：

- `zcode-acp` 已经提供 Rust 类型和并发 driver 参考。
- 子进程监管、NDJSON、IPC、SQLite 和 process-group 管理适合放在长期运行的 Rust daemon 中。
- 可以把协议层、调度层和 MCP facade 明确分离。
- 编译后的本地二进制易于由 Codex 配置为 stdio MCP。

建议结构：

```text
zcode-review-mcp/
├── Cargo.toml
├── crates/
│   ├── zcode-protocol/
│   │   ├── src/
│   │   └── tests/
│   ├── zcode-driver/
│   │   ├── src/
│   │   └── tests/
│   ├── review-core/
│   │   └── src/
│   ├── review-policy/
│   │   └── src/
│   ├── review-store/
│   │   └── src/
│   ├── review-ledger-mcp/
│   │   └── src/
│   ├── zcode-reviewd/
│   │   └── src/
│   ├── zcode-review-mcp/
│   │   └── src/
│   └── zcode-reviewctl/
│       └── src/
├── schemas/
│   ├── review-manifest.schema.json
│   ├── review-report.schema.json
│   └── review-event.schema.json
├── prompts/
│   ├── plan-review.md
│   └── code-review.md
├── tests/
│   ├── fake-app-server/
│   ├── fixtures/
│   └── integration/
├── docs/
│   ├── architecture.md
│   ├── protocol-compatibility.md
│   ├── security-model.md
│   ├── sectioned-integration.md
│   └── reference-license-matrix.md
└── REFERENCES.lock
```

不要把协议、daemon 和 MCP facade 写在同一个 crate 或单一事件循环中。

---

## 6. Phase 0：运行时、条款与兼容性预检

### 6.1 本地 runtime 获取方式

首版要求用户显式设置：

```bash
export ZCODE_RUNTIME_PATH="/absolute/path/to/local/official/zcode.cjs"
```

可以额外实现本地安装目录发现，但必须满足：

- 只搜索官方本地应用安装目录。
- 不联网下载。
- 不从参考仓库复制。
- 不自动替换。
- 找到多个候选时 fail closed。
- 输出路径、文件大小和 SHA-256。
- 不输出认证 token 或 provider secret。

### 6.2 Runtime identity

daemon 启动时记录：

```json
{
  "runtime_path": "...",
  "runtime_sha256": "...",
  "runtime_version": "...",
  "node_version": "...",
  "compatibility_status": "tested|untested|failed",
  "compatibility_tested_at": "..."
}
```

如果 runtime version 无法直接读取，至少使用：

- 文件 hash。
- 应用版本元数据。
- app-server smoke-test 结果。

### 6.3 兼容性 smoke test

对本地 runtime 测试：

1. 启动 `node <runtime> app-server`。
2. 确认 stdout 是预期 NDJSON。
3. 调用 workspace state。
4. 创建 session。
5. subscribe。
6. 发送一个不访问 repo 的短 prompt。
7. 接收文本和 terminal event。
8. 创建第二个 session 并执行 stop。
9. 测试 close。
10. 测试进程退出。
11. 如支持，测试 resume。
12. 记录所有 method response 和 event type，不记录密钥。

未知的非关键事件应保存为 redacted `raw.unknown`，不能静默丢弃；关键响应形态变化则标记：

```text
INCOMPATIBLE_RUNTIME
```

ZCode app-server 是未公开承诺兼容的接口，且 ZCode 条款包含反向工程和无默示许可条款，因此不要继承社区项目的 runtime 下载或提取机制。

### Phase 0 交付

```text
docs/protocol-compatibility.md
docs/reference-license-matrix.md
REFERENCES.lock
```

提交：

```text
research: pin references and document runtime compatibility boundary
```

---

## 7. Phase 1：类型化协议层与 fake app-server

### 7.1 `zcode-protocol`

定义：

- request/response envelope。
- app-server error。
- workspace state。
- session create/resume/list/subscribe/send/stop/close。
- session event envelope。
- turn lifecycle。
- text/tool/permission/input events。
- unknown event preservation。
- protocol error classification。

协议类型不能与 daemon 数据库实体混合。

### 7.2 `zcode-driver`

必须使用独立并发路径：

```text
child stdout reader
        │
        ▼
response/event demultiplexer
   ┌───────────────┐
   │               │
request waiter    event broadcaster
                       │
                 daemon event sink
```

不得：

```text
send prompt
await entire turn
then process permission
```

否则运行中出现 permission/input request 时会死锁。

`zcode-acp` 的关键价值正是 dispatcher、command loop 和 active-turn 状态分离。

### 7.3 Fake app-server

实现可脚本化 fake server，支持：

- 正常文本流。
- tool start/progress/end。
- permission request。
- user-input request。
- prompt already running。
- stop。
- crash。
- malformed NDJSON。
- unknown event。
- out-of-order event。
- delayed response。
- resume success/failure。

### Phase 1 验收

- 所有协议测试不需要真实 ZCode。
- 权限响应不会被 active prompt 阻塞。
- stdout/stderr 分离。
- malformed event 不导致未受控 panic。
- child exit 可被准确映射为 failure。
- 每个 event 获得 daemon-local monotonic sequence。

提交：

```text
feat(protocol): add typed ZCode app-server driver and fake runtime
```

---

## 8. Phase 2：持久 daemon

### 8.1 IPC

macOS/Linux 默认：

```text
Unix domain socket
```

Windows 后续可增加：

```text
named pipe 或 loopback TCP + random auth token
```

首版不要把 daemon 暴露到非 loopback 网络。

### 8.2 SQLite 数据表

至少包括：

#### `agents`

```text
agent_id
idempotency_key
parent_agent_id
review_kind
feature_id
section_id
round_kind
state
workspace_path
report_path
runtime_hash
zcode_session_id
pid
process_group_id
created_at
started_at
completed_at
last_heartbeat_at
last_event_seq
failure_code
failure_message
```

#### `events`

```text
agent_id
seq
timestamp
event_type
turn_id
payload_json
redaction_level
```

#### `messages`

```text
message_id
agent_id
mode
content
state
created_at
delivered_at
target_turn_id
```

#### `pending_requests`

```text
request_id
agent_id
request_type
payload_json
state
created_at
responded_at
```

#### `artifacts`

```text
artifact_id
agent_id
artifact_type
path
sha256
bytes
checkpoint_number
created_at
```

#### `compatibility_runs`

```text
runtime_hash
runtime_version
tested_at
status
details_json
```

启用 SQLite WAL 和事务。

### 8.3 进程监管

每个 review job：

- 单独 ZCode app-server 进程。
- 单独 process group。
- 单独 disposable worktree。
- 单独 ledger namespace。
- 单独 event sequence。
- 单独 session ID。
- 单独日志目录。

默认并发：

```text
global_max_agents = 2
per_workspace_max_agents = 1
```

支持配置，但不要默认无限并行。

### 8.4 重启恢复

daemon 重启时：

1. 读取所有非 terminal jobs。
2. 检查 PID/process group 是否仍存在。
3. 尝试重新连接或使用 session resume。
4. 无法恢复时标记 `ORPHANED` 或 `FAILED_RUNTIME_LOST`。
5. 保留 partial report 和 event log。
6. 不自动用新 session 重做并伪装为同一个 review。

### Phase 2 提交

```text
feat(daemon): add durable review registry and process supervision
```

---

## 9. Phase 3：Codex-facing MCP facade

### 9.1 工具接口

#### `zcode_review_spawn`

输入：

```json
{
  "manifest_path": "/absolute/path/review-manifest.json",
  "idempotency_key": "feature:section:round:glm",
  "priority": "normal"
}
```

要求：

- 快速返回。
- 重复 idempotency key 返回原有 job。
- 不等待 runtime 启动或 review 完成。
- manifest 校验失败时不创建 job。

#### `zcode_review_status`

输入：

```json
{
  "agent_id": "zr_..."
}
```

输出：

- state。
- phase。
- current tool summary。
- pending request。
- last event seq。
- last report checkpoint。
- elapsed time。
- capabilities。

#### `zcode_review_events`

输入：

```json
{
  "agent_id": "zr_...",
  "after_seq": 120,
  "limit": 100
}
```

输出：

- ordered events。
- next sequence。
- has_more。

默认不得返回 raw reasoning delta。

#### `zcode_review_wait`

输入：

```json
{
  "agent_id": "zr_...",
  "after_seq": 120,
  "timeout_ms": 15000
}
```

在以下任一情况返回：

- 新 event。
- state 变化。
- pending request。
- timeout。

不得无限阻塞。

#### `zcode_review_message`

输入：

```json
{
  "agent_id": "zr_...",
  "message_id": "msg_...",
  "mode": "queue",
  "content": "..."
}
```

`mode` 仅允许：

```text
queue
interrupt_and_continue
```

除非 runtime capability test 以后证明存在真正 live steer，否则不得增加或宣传 `live_steer`。

#### `zcode_review_respond`

输入绑定：

```json
{
  "agent_id": "zr_...",
  "request_id": "req_...",
  "decision": "allow|deny|answer",
  "content": "..."
}
```

adapter 的 hard-deny policy 优先于 Codex 提交的 allow。

#### 其余工具

- `zcode_review_stop`
- `zcode_review_result`
- `zcode_review_list`
- `zcode_review_close`

### 9.2 Progress 策略

不要把 MCP `notifications/progress` 作为正确性依赖。当前 Codex 对相关通知的消费仍有公开缺口。

正确路径：

```text
spawn
  ↓
status / wait / events
  ↓
result
```

### Phase 3 提交

```text
feat(mcp): expose durable ZCode reviewer lifecycle to Codex
```

---

## 10. Phase 4：Review manifest

创建：

```text
schemas/review-manifest.schema.json
```

示例：

```json
{
  "schema": "sectioned-zcode-review/v1",
  "review_kind": "code",
  "feature_id": "example-feature",
  "section_id": "section-03",
  "round_kind": "INITIAL_BOUNDED",
  "repository": "/absolute/path/to/repository",
  "base_ref": "abc1234",
  "head_ref": "def5678",
  "plan_path": ".agent-work/PLAN-FULL.md",
  "context_paths": [
    ".agent-work/FEATURE-CONTEXT.md",
    ".agent-work/sections/section-03.md"
  ],
  "scope_paths": [
    "src/",
    "tests/"
  ],
  "forbidden_input_globs": [
    ".agent-work/reviews/**/GPT-RAW.md",
    ".agent-work/reviews/**/GPT-ADMISSION.md",
    ".agent-work/reviews/**/GLM-RAW.md",
    ".agent-work/reviews/**/GLM-ADMISSION.md"
  ],
  "validation_commands": [
    "npm test -- --runInBand",
    "npm run lint"
  ],
  "report_target": ".agent-work/reviews/example/section-03/INITIAL_BOUNDED/GLM-RAW.md",
  "model": null,
  "fresh_session": true,
  "network_policy": "deny",
  "scratch_policy": "isolated",
  "idempotency_key": "example-feature:section-03:INITIAL_BOUNDED:glm"
}
```

### 校验要求

- 所有路径 canonicalize。
- repo、plan 和 context 必须存在。
- `base_ref`、`head_ref` 必须解析到固定 SHA。
- `report_target` 必须在允许的 review root 下。
- forbidden globs 必须在构造 reviewer context 前应用。
- `fresh_session` 对 counted full review 必须为 `true`。
- manifest 内容复制到 provenance 工件。
- daemon 创建 disposable worktree，不直接使用 manifest 指向的正式工作树进行执行。

提交：

```text
feat(manifest): add validated sectioned review job contract
```

---

## 11. Phase 5：内部 `review-ledger-mcp`

### 11.1 目的

GLM 不应只在最终消息中输出结论。

每个 job 启动一个受控 ledger endpoint，并通过 ZCode session 的 MCP 配置注入。ZCode 消费 MCP 是官方支持方向；app-server 适配代码也包含 session-level MCP server 配置。

### 11.2 工具定义

#### `review_checkpoint`

```json
{
  "stage": "scope|inspection|validation|synthesis",
  "summary": "Observable progress summary",
  "inspected": [
    {
      "path": "src/example.ts",
      "line_ranges": ["10-80"]
    }
  ],
  "commands": [
    {
      "command": "npm test",
      "result_summary": "..."
    }
  ],
  "open_questions": [],
  "remaining_scope": []
}
```

#### `review_finding_upsert`

```json
{
  "finding_id": "GLM-001",
  "severity": "P0|P1|P2|P3",
  "confidence": "high|medium|low",
  "title": "...",
  "locations": [
    {
      "path": "src/example.ts",
      "start_line": 42,
      "end_line": 51
    }
  ],
  "evidence": [
    "Observable evidence or command result"
  ],
  "impact": "...",
  "suggested_remediation": "...",
  "status": "open|withdrawn"
}
```

#### `review_validation_record`

```json
{
  "command": "npm test",
  "cwd": "...",
  "exit_code": 1,
  "duration_ms": 4200,
  "stdout_summary": "...",
  "stderr_summary": "...",
  "related_findings": ["GLM-001"]
}
```

#### `review_finalize`

```json
{
  "signal": "findings_present|no_findings_observed|incomplete_evidence|unable_to_review",
  "summary": "...",
  "coverage": {
    "covered": [],
    "not_covered": []
  },
  "uncertainties": [],
  "recommended_next_actions": []
}
```

### 11.3 Markdown renderer

每次 ledger 写入后重新渲染：

```text
GLM-RAW.md
```

并追加：

```text
report.checkpoint
```

event。

最终报告必须包括：

- manifest identity。
- ZCode session identity。
- runtime hash。
- model identity，如可获得。
- evidence checkpoints。
- findings。
- validation。
- coverage gaps。
- uncertainties。
- final signal。
- `FINALIZED: true`。

### 11.4 最低持续性要求

一个成功 review 至少出现：

1. initial report skeleton。
2. inspection checkpoint。
3. final report。

较复杂 review 应在不同 evidence batch 后产生更多 checkpoint。

不得通过任务结束后伪造旧时间戳来满足持续性要求。

### Phase 5 提交

```text
feat(reporting): add job-scoped review ledger and live report rendering
```

---

## 12. Phase 6：权限、worktree 和安全

### 12.1 Review worktree

每个 job：

```bash
git worktree add --detach <temporary-path> <head-sha>
```

任务结束：

```bash
git -C <temporary-path> diff --exit-code
git -C <temporary-path> diff --cached --exit-code
```

如果存在 tracked source 修改：

- 记录 `policy.source_modified`。
- 保存 diff 作为诊断工件。
- 报告 `COMPLETED_WITH_POLICY_VIOLATION` 或 `FAILED_POLICY`。
- 不把这些改动带回产品分支。
- 删除 worktree 前保存证据。

### 12.2 权限策略

允许：

- Read。
- Grep。
- Glob。
- `git diff/status/log/show`。
- manifest 允许的 validation commands。
- 访问 job-scoped ledger。
- 写 isolated scratch。

默认拒绝：

- 对正式 repo 的写入。
- 网络访问。
- 删除或移动 repo 文件。
- 修改 Git refs。
- commit、push、merge、rebase。
- 读取 forbidden review artifacts。
- 读取 credential 文件。
- 任意 shell 写入正式 workspace。

### 12.3 Plan mode

不要依赖 ZCode Plan mode实现该策略，因为 Plan mode的硬 write ban 会与持续报告要求冲突，且普通 permission/hook 不能覆盖所有硬限制。

使用普通 session，并由：

- disposable worktree
- ledger-only authoritative writing
- daemon policy
- terminal integrity check

共同形成安全边界。

### Phase 6 提交

```text
feat(policy): isolate reviewer worktrees and enforce artifact-only writes
```

---

## 13. Phase 7：Reviewer prompt

### 13.1 通用系统契约

```text
You are an independent external software reviewer running inside ZCode.

Your role is to discover issues and produce evidence. You are not an
acceptance authority and must never mark the plan or code as approved,
accepted, merged, or ready merely because you found no issue.

You must not edit product source files. The workspace is disposable, but
source modifications are policy violations. Use the review-ledger tools to
record observable progress throughout the review.

Record:
- files and line ranges inspected,
- commands executed and observable results,
- findings with concrete evidence,
- coverage gaps,
- unresolved uncertainty.

Do not output or store hidden chain-of-thought. Record only concise,
auditable observations and evidence.

Call review_checkpoint after each meaningful evidence batch.
Call review_finding_upsert as findings are discovered or revised.
Call review_validation_record for every validation command.
Call review_finalize exactly once before ending.

Do not read any prior reviewer RAW, ADMISSION, or review conclusion artifact.
The final signal must be one of:
- findings_present
- no_findings_observed
- incomplete_evidence
- unable_to_review
```

### 13.2 Plan Review 追加指令

检查：

- 需求和计划是否一致。
- section 边界和 DAG。
- 隐藏依赖。
- scope expansion。
- complexity budget。
- migration 和 rollback。
- failure recovery。
- testability。
- 并发和数据一致性。
- 与现有代码架构的冲突。
- 是否过度工程化。

### 13.3 Code Review 追加指令

检查：

- base/head diff。
- correctness 和 regression。
- error paths。
- data integrity。
- concurrency。
- security boundary。
- validation evidence。
- tests。
- plan compliance。
- 未声明的架构边界。
- 迁移和兼容性。

提交：

```text
feat(prompts): add independent GLM plan and code reviewer contracts
```

---

## 14. Phase 8：与 `sectioned-feature-development` 集成

在核心系统测试全部通过后，再新增薄适配层。

### 14.1 触发位置

#### Plan Review

```text
PLAN-FULL ready
  ├─ GPT Plan Reviewer
  └─ ZCode GLM Plan Reviewer
```

#### 完整 Code Review

```text
section implementation committed
  ├─ GPT Code Reviewer
  └─ ZCode GLM Code Reviewer
```

### 14.2 不改变的规则

- 主 Agent admission 仍是唯一 acceptance authority。
- 两次 clean admission 规则不由 GLM 自行判断。
- 5-round cap 不改变。
- failed branch backup 不改变。
- product commit 与 review metadata commit 分离。
- fresh reviewer independence 不改变。
- DELTA 不算 clean。
- `sol_max` decomposition 触发条件不改变。

### 14.3 新增工件

```text
<round>-GPT-RAW.md
<round>-GPT-ADMISSION.md
<round>-GLM-RAW.md
<round>-GLM-ADMISSION.md
<round>-GLM-PROVENANCE.json
```

### 14.4 禁止上下文污染

给 GLM 的 manifest 不得包含：

- 以前的 GPT RAW。
- 以前的 GLM RAW。
- admission 文件。
- reviewer session transcript。
- 主 Agent 对 finding 的处理意见。

### 14.5 Shadow rollout

先增加配置：

```yaml
external_review:
  provider: zcode_glm
  mode: shadow
  plan_review: true
  full_code_review: true
  delta_review: targeted
  infrastructure_failure: evidence_incomplete
```

记录至少：

- GLM 独有 finding 数。
- 与 GPT 重复 finding 数。
- admitted/rejected 比例。
- 无证据误报比例。
- runtime failure 率。
- report schema 合规率。
- 平均 review wall time。
- 平均 checkpoint 数。

完成校准后，才允许：

```yaml
mode: required
```

### Phase 8 提交

```text
feat(sectioned): add shadow ZCode GLM plan and code reviewer
```

---

## 15. 测试矩阵

### 15.1 协议和并发

- 多 request 并发。
- active prompt 期间 permission response。
- active prompt 期间 user-input response。
- response/event 交错。
- unknown event。
- malformed NDJSON。
- child stdout 中出现非协议日志。
- prompt already running。
- stop 和 terminal event race。
- daemon shutdown race。

### 15.2 Agent 生命周期

- spawn 快速返回。
- queue 超限。
- queued job 被停止。
- running job graceful stop。
- running job forced stop。
- completed job result。
- failed job partial result。
- close/reap。
- MCP facade 重启。
- daemon 重启。
- app-server crash。
- resume success。
- resume failure。
- process group 无孤儿。

### 15.3 消息

- running 时 `queue`。
- terminal 后 queue 自动 deliver。
- 重复 `message_id` 不重复发送。
- `interrupt_and_continue` 正确停止后发送。
- active turn 不支持 live steer 时 capability 为 false。
- 不把 `PROMPT_ALREADY_RUNNING` 吞掉。

### 15.4 报告

- report 在 Agent 完成前存在。
- 至少 initial、checkpoint、final 三个版本。
- finding upsert 不产生重复 ID。
- withdrawn finding 保留审计记录。
- final signal 枚举校验。
- `FINALIZED: true` 缺失时不进入正常 completed。
- Markdown 与 SQLite 内容一致。
- artifact hash 可重算。
- 大报告通过 path/hash/preview 返回，不淹没 MCP result。

### 15.5 安全

- `../` 路径穿越。
- symlink escape。
- absolute path escape。
- Bash 修改产品文件。
- Git ref 修改。
- credential file 读取。
- forbidden review artifact 读取。
- network command。
- report path 指向源码。
- scratch 污染 product commit。
- 日志泄露环境变量。
- stdout 污染 MCP framing。

### 15.6 Review independence

- 两个 full review 的 ZCode session ID 不同。
- 第二轮 manifest 不含第一轮 RAW/ADMISSION。
- resume 输出不能被标记为 independent clean review。
- GLM 自己写 `approved` 时报告 validator 拒绝或归一化为合法 signal。
- GLM 基础设施失败不产生 `no_findings_observed`。

### 15.7 真实 runtime 手工测试

只有本地存在官方 ZCode runtime 时执行：

- Plan Review fixture。
- Code Review fixture。
- validation command。
- permission denial。
- stop。
- queue。
- interrupt-and-continue。
- partial report recovery。
- current runtime hash compatibility registration。

---

## 16. Codex 配置

安装完成后：

```toml
[mcp_servers.zcode_review]
enabled = true
required = true
command = "/absolute/path/to/zcode-review-mcp"
args = [
  "--socket",
  "/absolute/path/to/zcode-reviewd.sock"
]
startup_timeout_sec = 10.0
tool_timeout_sec = 30.0
enabled_tools = [
  "zcode_review_spawn",
  "zcode_review_status",
  "zcode_review_events",
  "zcode_review_wait",
  "zcode_review_message",
  "zcode_review_respond",
  "zcode_review_stop",
  "zcode_review_result",
  "zcode_review_list",
  "zcode_review_close"
]
```

Codex 官方 MCP 配置支持 stdio command、args、env、startup timeout、tool timeout、required 和 enabled tools 等字段。

在 shadow 阶段可以先设置：

```toml
required = false
```

进入 required evidence 阶段后再改为：

```toml
required = true
```

`zcode_review_wait` 的最大等待时间必须显著小于 `tool_timeout_sec`。

---

## 17. 验收条件

只有同时满足以下条件，才可宣布 MVP 完成：

- [ ] `spawn` 不等待完整 review，快速返回唯一 `agent_id`。
- [ ] Codex 可以列出 active/recent Agent。
- [ ] Codex 可以读取增量事件。
- [ ] MCP facade 重启后仍能访问 daemon 中的任务。
- [ ] daemon 重启后能恢复或明确标记非终态任务。
- [ ] Agent 完成前报告已经存在。
- [ ] 报告至少经历 initial、checkpoint、final 三次状态。
- [ ] 最终报告有 schema、hash 和 provenance。
- [ ] stop 可终止整个 ZCode process group，不遗留子进程。
- [ ] queue 消息只在当前 turn 完成后发送。
- [ ] interrupt-and-continue 明确表现为停止再发送。
- [ ] capability 中 `live_steer` 默认是 `false`。
- [ ] 产品 tracked source 在 review 后保持不变。
- [ ] 禁止的 prior review artifacts 未进入 reviewer context。
- [ ] 每个 counted full review 使用新 ZCode session。
- [ ] GLM finding 必须经主 Codex admission。
- [ ] fake app-server 测试全部通过。
- [ ] 当前本地 ZCode runtime smoke test 的结果被单独记录。
- [ ] 未把官方 runtime、认证信息或用户 token 提交进 Git。
- [ ] 第三方代码复制均有明确 license 依据和 notice。
- [ ] `sectioned-feature-development` 集成默认处于 shadow mode。

---

## 18. 提交顺序

必须保持提交边界：

```text
1. research: pin references and document runtime compatibility boundary
2. feat(protocol): add typed ZCode app-server driver and fake runtime
3. feat(daemon): add durable review registry and process supervision
4. feat(mcp): expose durable ZCode reviewer lifecycle to Codex
5. feat(manifest): add validated sectioned review job contract
6. feat(reporting): add job-scoped review ledger and live report rendering
7. feat(policy): isolate reviewer worktrees and enforce artifact-only writes
8. feat(prompts): add independent GLM plan and code reviewer contracts
9. feat(sectioned): add shadow ZCode GLM plan and code reviewer
10. docs: add setup, compatibility, operations, and recovery guide
```

不得把产品功能、协议实现、review ledger 和 skill 集成混在同一个提交中。

---

## 19. 本地 Agent 的最终执行指令

```text
Implement the ZCode Agent-as-MCP system described in this execution report.

Start by cloning and pinning the specified reference repositories. Inspect
their current LICENSE files and exact commits before copying any code.

Use the locally installed official ZCode runtime only. Do not download,
vendor, extract, patch, decompile, or redistribute zcode.cjs. Require an
explicit ZCODE_RUNTIME_PATH for the initial implementation.

Use zcode-acp as the primary protocol and concurrency reference, zcode-cli
as the reference for native steering/background-task semantics, and
zcode-tui as a compact app-server protocol cross-check. Do not directly
turn either TUI project into the final MCP server.

Implement a persistent zcode-reviewd daemon, a thin stdio
zcode-review-mcp facade, and a job-scoped review-ledger MCP injected into
each ZCode session. The outer MCP must expose agent lifecycle operations,
not ZCode's individual tools.

Build and test the fake app-server before integrating a real ZCode
runtime. Do not modify sectioned-feature-development until protocol,
daemon, MCP, reporting, lifecycle, and policy tests pass.

Treat same-turn live steering as unsupported unless an explicit
compatibility test proves a documented app-server operation. Implement
queue and interrupt-and-continue as separate, observable semantics.

Run reviewers in disposable worktrees. Preserve product commits and
review ledger commits separately. Ensure that every counted full review
uses a fresh ZCode session and receives no previous reviewer RAW,
ADMISSION, conclusions, or transcript.

The ZCode reviewer must continuously record evidence through the
review-ledger tools. The daemon must render an in-progress Markdown report
before completion and a finalized report with hash and provenance.

At completion, produce:
- EXECUTION-REPORT.md
- TEST-REPORT.md
- COMPATIBILITY-REPORT.md
- SECURITY-REPORT.md
- REFERENCES.lock
- exact commit list
- unresolved limitations

Do not claim real-runtime compatibility if only fake-runtime tests ran.
Do not fabricate missing evidence or silently downgrade infrastructure
failures into a clean review.
```