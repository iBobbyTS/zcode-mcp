# ZCode Agent-as-MCP 调研报告

**调研日期：** 2026-08-22  
**目标环境：** Codex + `sectioned-feature-development`  
**目标模型：** 在官方 ZCode Agent runtime 内运行的 GLM  
**核心用途：** Plan Review、Code Review、持续审查记录、最终报告生成

---

## 1. 结论

### 1.1 决策结论

| 决策 | 结论 |
|---|---|
| 是否值得实现 | **值得，建议实施本地实验版** |
| 是否直接 fork `zcode-cli` 做 MCP | **不建议** |
| 是否直接 fork `zcode-tui` 做 MCP | **不建议** |
| 最适合作为协议代码基线的项目 | **`jpalmae/zcode-acp`** |
| 两个 TUI 项目的价值 | 作为运行时语义、协议事件和 UX 参考 |
| 是否能实现 spawn/status/stop/result/list | **能** |
| 是否能可靠实现同一 turn 内 live steering | **目前不能确认** |
| Steering 的首版实现 | 消息排队，或停止当前 turn 后继续 |
| 是否让 GLM 直接编辑产品代码 | **不应当** |
| 是否允许 GLM 产生文件工件 | **应当，且必须持续落盘** |
| 报告写入的推荐方式 | 给 ZCode 注入 job-scoped `review-ledger` MCP，由 daemon 实时渲染 Markdown |
| 与现有 review gate 的关系 | GLM 是补充独立 reviewer，不是 acceptance/admission authority |
| 商业或团队正式部署 | 在获得 ZCode 接口授权或完成法律评估前，只做条件性采用 |

ZCode 官方定位本身就是面向长时、多步骤软件工程任务优化的 Agent harness，并提供工具权限、模式、MCP 和运行控制能力；但官方文档目前描述的是 **ZCode 消费 MCP 工具**，没有公开描述“把 ZCode 自身作为 MCP Agent 服务暴露”的接口。社区项目使用的 `app-server` 因而应视为私有、未承诺兼容的接口。

### 1.2 推荐形态

```text
Codex / sectioned-feature-development
                │
                │ stdio MCP
                ▼
        zcode-review-mcp
         轻量控制面适配器
                │
                │ Unix socket / local IPC
                ▼
          zcode-reviewd
   ┌────────────┼─────────────────────┐
   │            │                     │
SQLite      Report renderer      Process supervisor
event store      │                     │
   │             ▼                     ▼
   │       *-GLM-RAW.md       Official ZCode app-server
   │                                  │
   │                         Official ZCode Agent + GLM
   │                                  │
   └────────────── review-ledger MCP ◄┘
                         │
             checkpoint / finding / validation / finalize
```

这个架构刻意区分：

- **审查主体：** 官方 ZCode Agent runtime。
- **模型：** ZCode 配置中的 GLM。
- **外部 MCP：** 只给 Codex 提供 Agent 生命周期管理。
- **内部 MCP：** 只给 ZCode 提供受控的审查记录通道。
- **报告：** 由 daemon 持续渲染，不依赖 Agent 最终回答。
- **产品工作区：** 使用一次性 worktree 或快照，防止审查任务污染正式分支。

---

## 2. 三个 ZCode 社区项目的适用性

虽然用户最初提到的是两个 TUI 扩展，但调研后发现，真正最适合作为实现基线的是第三个项目 `zcode-acp`。

### 2.1 `kingsword09/zcode-cli`

#### 它证明了什么

该项目的主路径是：

```text
Node launcher
    ↓
官方 zcode.cjs runtime
    ↓
本地 @zcode/tui adapter
    ↓
terminal UI
```

其 README 和代码明确区分了 launcher/TUI 与官方 runtime；Agent、session、tool、plugin、MCP、认证和 provider 逻辑仍由 ZCode runtime 执行。它还暴露了非常有价值的原生调度语义：

- Enter 可在安全的 model-step 边界进行同一 turn steering。
- Tab 可把消息按 FIFO 排到下一 turn。
- 后台 Agent 任务可查看、发送消息、停止、恢复和持久化。
- 存在 `/tasks message`、`/tasks stop`、`/tasks resume` 等管理操作。

#### 值得参考的部分

1. ZCode runtime 的本地定位与启动。
2. 版本和哈希固定。
3. 环境变量、认证和 provider 配置传递。
4. 信号处理和子进程退出。
5. 同一 turn steer 与 next-turn queue 在产品内部的语义区别。
6. 后台任务中心的状态和操作设计。
7. launcher 对 `--print`、`--prompt`、`--target` 等参数的处理。

#### 不适合直接作为 MCP 基线的原因

- 正常 TUI 路径依赖注入式内部 adapter，不是公开 app-server 客户端。
- 仓库中的 app-server helper 更接近“一次启动、一次请求、等待结束、退出”的调用方式，而不是持久 Agent 调度器。
- 它包含自动下载、提取或同步官方 runtime 的逻辑；这不应复制到正式实现。
- 它证明了 **内部 TUI 通路支持真正 steering**，但不能由此推断公开 app-server 也暴露相同操作。

#### 评价

> **高价值语义参考，低价值直接代码基线。**

---

### 2.2 `gaozhi-ustc/zcode-tui`

#### 它证明了什么

该项目通过：

```text
node zcode.cjs app-server
```

与 ZCode runtime 交互，并实现或调用了以下会话操作：

- `workspace/readState`
- `session/create`
- `session/subscribe`
- `session/send`
- `session/stop`
- `session/list`
- `session/resume`
- `session/setModel`
- `session/setMode`
- `session/compact`

它还处理了模型文本、reasoning、tool lifecycle、turn lifecycle、权限和用户输入等事件。

#### 值得参考的部分

1. 简明的 app-server 启动路径。
2. 方法名和事件形态交叉验证。
3. `subscribe`、`resume`、`stop` 的基本时序。
4. permission/user-input 事件的存在。
5. 重连和会话恢复的最小实现。

#### 不适合直接作为生产基线的原因

- 协议建模较松散，类型约束不足。
- 对未知事件和非 JSON 输出的处理偏宽松。
- 没有持久化 daemon、全局 active-agent registry 和可靠重启恢复。
- 没有独立的报告工件协议。
- 同样存在自行获取或分发 runtime 的路径。
- 没有证明 active prompt 状态下的 `session/send` 是 live steering。

#### 评价

> **适合作为小型协议说明书和兼容性对照，不适合作为调度核心。**

---

### 2.3 `jpalmae/zcode-acp`

#### 为什么它更重要

`zcode-acp` 已经把 ZCode app-server 包装成 ACP adapter，并对协议进行了较完整的类型化建模。其代码覆盖：

- 每个 ACP session 启动一个 `node zcode.cjs app-server`。
- NDJSON 请求和事件协议。
- `session/create`、`resume`、`list`、`subscribe`、`send`、`stop`、`close`。
- model/tool/permission 事件流。
- active-turn 状态。
- request dispatcher 与 event loop 分离，避免在等待 prompt 结束时阻塞权限响应。
- fake app-server 和协议测试。

这正是新 MCP 最难、也最容易写错的底层部分：**并发请求、事件顺序、权限请求和长 turn 生命周期不能共用一个阻塞循环。**

#### 仍然缺少的内容

`zcode-acp` 是 ACP adapter，不是 Agent 调度平台。它没有完整提供：

- 持久 daemon。
- 跨 MCP 重连的 active-agent registry。
- SQLite 事件和报告存储。
- 快速返回的异步 spawn。
- job queue、并发限制和 idempotency。
- active-agent list/status/events/wait/reap。
- 报告 checkpoint 和 artifact contract。
- 受控的产品目录与报告目录隔离。
- 对当前 ZCode 版本的持续兼容矩阵。

项目自身也列出了若干兼容性和实现限制，例如部分 progress tail、session list、setMode、用户输入和 provider header 的处理尚不完整；其验证版本也落后于当前 ZCode 版本，因此必须重新运行兼容性测试。

#### 评价

> **首选协议和 driver 基线，但必须在其外增加 daemon、MCP control plane、报告台账和安全策略。**

---

## 3. Steering 能力的边界

### 3.1 已经可以确认的能力

通过 app-server 社区适配器，可以较有把握地实现：

| 能力 | 可行性 |
|---|---:|
| 创建独立 session | 高 |
| 发送初始 prompt | 高 |
| 订阅 turn/tool/text 事件 | 高 |
| 停止当前任务 | 高 |
| 恢复已有 session | 中高，需要按 runtime 版本验证 |
| 获取最终回答 | 高 |
| 权限请求响应 | 高 |
| 用户问题响应 | 中高 |
| 多 Agent active registry | 由自建 daemon 实现 |
| 持久化 event log | 由自建 daemon 实现 |
| 报告持续落盘 | 由自建 ledger 实现 |

### 3.2 尚不能声称具备的能力

当前公开的 app-server 方法映射没有出现明确的 `turn/steer` 等价方法。已知 `session/send` 在已有 prompt 运行时可能返回 `PROMPT_ALREADY_RUNNING`，而 `zcode-cli` 的同 turn steering 来自内部 TUI adapter 路径。

因此首版 API 必须诚实暴露能力：

```json
{
  "live_steer": false,
  "queued_message": true,
  "interrupt_and_continue": true,
  "stop": true,
  "resume": true
}
```

### 3.3 首版消息语义

#### `queue`

当 Agent 正在运行时：

1. daemon 持久化消息。
2. 当前 turn 不受影响。
3. 收到 `turn.completed` 后自动把消息发送为下一 turn。
4. 返回 `queued`。

#### `interrupt_and_continue`

1. 调用 `session/stop`。
2. 等待当前 turn 进入终态。
3. 在同一个 session 中发送新的消息。
4. 新消息包含停止原因和新增指令。
5. 返回 `interrupted_then_delivered`。

#### 禁止的行为

- 不得把普通 next-turn message 宣称为 live steering。
- 不得在未知 method 名上进行暴力枚举。
- 不得依赖内部 TUI adapter，除非后续获得官方接口支持。
- 不得在 active prompt 上反复调用 `session/send` 并忽略错误。

---

## 4. 现有 Agent-as-MCP 项目的设计模式

### 4.1 `omg.dev`：持久服务 + 轻量 MCP

`omg.dev` 使用本地持久服务管理 session，MCP 只是外部入口；后台会话可以跨连接继续存活，并可从统一界面查看 session、消息和委派关系。

**应该借鉴：**

- daemon 是状态所有者。
- MCP server 本身不拥有 Agent 生命周期。
- Codex MCP 重启后，任务继续存在。
- session tree 和 parent/child lineage 显式记录。
- MCP 只负责命令转发和结果序列化。

### 4.2 `pi-subagents`：异步 spawn 和 steer UX

该项目采用：

- 后台启动后立即返回 ID。
- 通过 ID 获取结果。
- 可停止。
- 可向运行中的 subagent 发送 steer。
- 有持久化、并发限制和队列。
- 活动任务有可见状态。

**应该借鉴：**

- `spawn` 必须快速返回。
- 操作对象始终是稳定的 `agent_id`。
- steering、queue、stop 必须是不同语义。
- 并发超限后进入 `QUEUED`，而不是让 MCP 调用一直阻塞。

### 4.3 `sailing`：清晰的 Agent 生命周期工具集

其 MCP conductor 使用了类似：

- `agent_spawn`
- `agent_status`
- `agent_log`
- `agent_kill`
- `agent_reap`
- `agent_list`

并加入 worktree 校验。

**应该借鉴：**

- stop 与 reap 分离。
- terminal Agent 不应立即丢失日志和工件。
- `reap` 是显式资源清理操作。
- spawn 前进行 repo/worktree preflight。

### 4.4 `mcp-supersubagents`：任务句柄和双层输出

该项目使用后台 task ID、状态资源、message/cancel/answer 操作，并将短结果与大工件分离。

**应该借鉴：**

- MCP 返回小型摘要和 artifact locator。
- 大型 review report 不直接塞入每次 tool result。
- `WAITING_INPUT` 必须是正式状态。
- 输入回答必须绑定具体 request ID。

**不应采用：**

- 它使用的 GLM 路径并不等同于官方 ZCode Agent runtime。
- 其 message 操作也不等于 app-server 的同一 turn steering。

### 4.5 `agent-teams-mcp`：客户端唤醒不是通用能力

该项目通过 Claude 专用 Stop hook 把 worker 回答重新注入主 Agent，以解决 MCP resource 更新不会自动让主 Agent继续行动的问题。

这不能直接移植为 Codex 设计。Codex 侧应由调用者：

1. `spawn`
2. 继续其他工作
3. 定期 `wait/status`
4. 在需要结果时 `result`

而不是假设 MCP 能主动向 Codex 发起新 turn。

---

## 5. 为什么不直接依赖 MCP Tasks 或 progress notification

MCP 已定义异步 Tasks 扩展：工具可以返回 durable task handle，客户端随后轮询状态、处理 `input_required` 并在重连后继续访问。

但截至本次调研，Codex 对 MCP progress notification 的接线仍存在公开缺口：服务端可能发出 progress，而 Codex 没有把它完整呈现到 Agent 层。

因此首版应采用普通 MCP tools 加显式 job ID：

```text
spawn → agent_id
status(agent_id)
events(agent_id, after_seq)
wait(agent_id, after_seq, timeout_ms)
result(agent_id)
```

`wait` 是受控 long-poll，最长约 15–20 秒，必须短于 Codex 的 MCP tool timeout。

等 Codex 对 MCP Tasks 的支持足够稳定后，可以在不改变 daemon 内核的情况下增加 Tasks adapter。

---

## 6. 推荐的三层架构

### 6.1 `zcode-reviewd`

持久后台服务，是真正的 control plane。

职责：

- 维护 Agent registry。
- 创建一次性 review worktree。
- 启动和监管 ZCode app-server 子进程。
- 管理 process group。
- 持久化 events、messages、pending requests 和 artifacts。
- 执行并发限制和 job queue。
- 检测进程崩溃和 daemon 重启后的孤儿任务。
- 管理消息 queue 和 interrupt-and-continue。
- 生成最终 provenance。
- 实时渲染审查报告。
- 对产品目录变更做终态校验。

### 6.2 `zcode-review-mcp`

Codex 启动的 stdio MCP server。

职责仅限：

- 参数校验。
- 调用 daemon。
- 把 daemon 响应转换为 MCP tool result。
- 保证 stdout 只输出 MCP 协议，不混入 ZCode 日志。
- 不直接持有 ZCode 子进程。
- 不直接存储任务状态。

### 6.3 `review-ledger-mcp`

这是每个 ZCode review job 内部可见的 job-scoped MCP。

它不是暴露给 Codex 的 Agent 工具，而是提供给 ZCode 的受控记录接口：

| 内部工具 | 用途 |
|---|---|
| `review_checkpoint` | 记录已检查范围、可观察证据、命令结果和尚未覆盖内容 |
| `review_finding_upsert` | 创建或更新结构化 finding |
| `review_validation_record` | 写入测试、静态检查或复现命令结果 |
| `review_finalize` | 写入覆盖情况、不确定性和最终 review signal |

ZCode 官方支持消费 MCP；社区 app-server 类型定义也表明 session 创建参数可以携带 MCP server 配置。因此，用 job-scoped ledger 作为受控记录通道，比允许模型任意写整个 repo 更合适。

---

## 7. Codex-facing MCP 工具设计

### 7.1 必需工具

| 工具 | 核心语义 |
|---|---|
| `zcode_review_spawn` | 校验 manifest，创建 job，快速返回 `agent_id` |
| `zcode_review_status` | 获取状态、当前阶段、最后事件序号、报告 checkpoint |
| `zcode_review_events` | 从 `after_seq` 起分页读取结构化事件 |
| `zcode_review_wait` | 等待状态或事件变化，受限 long-poll |
| `zcode_review_message` | 排队消息，或 interrupt-and-continue |
| `zcode_review_respond` | 回答指定 permission/input request |
| `zcode_review_stop` | 幂等停止任务 |
| `zcode_review_result` | 获取报告、摘要、hash 和 provenance |
| `zcode_review_list` | 列出 active/recent Agent |
| `zcode_review_close` | 回收运行资源，保留或按策略清理工件 |

### 7.2 `spawn` 返回值

```json
{
  "agent_id": "zr_01J...",
  "state": "QUEUED",
  "report_path": ".agent-work/reviews/.../GLM-RAW.md",
  "capabilities": {
    "live_steer": false,
    "queued_message": true,
    "interrupt_and_continue": true,
    "resume": true,
    "stop": true
  },
  "last_event_seq": 0
}
```

### 7.3 标准状态机

```text
QUEUED
  ↓
STARTING
  ↓
RUNNING
  ├── WAITING_PERMISSION
  ├── WAITING_INPUT
  ├── STOPPING
  └── RUNNING
        ↓
COMPLETED
FAILED
CANCELLED
INCOMPATIBLE_RUNTIME
ORPHANED
        ↓
REAPED
```

`COMPLETED` 只能表示：

- ZCode turn 已正常结束。
- ledger 已调用 `review_finalize`。
- 报告 schema 验证通过。
- 工件已持久化。
- 产品 tracked source 校验通过或已明确标记 policy violation。

否则应进入 `FAILED_REPORT_VALIDATION` 或 `COMPLETED_WITH_POLICY_VIOLATION`，不能把不完整报告冒充成功。

---

## 8. 持续报告，而不是“最后返回一个回答”

### 8.1 工件优先

daemon 在 ZCode 启动前就创建：

```text
.agent-work/reviews/
  <feature>/
    <section>/
      <round>/
        GLM-RAW.md
        GLM-EVENTS.jsonl
        GLM-MANIFEST.json
        GLM-PROVENANCE.json
```

初始 `GLM-RAW.md` 状态为：

```yaml
status: in_progress
finalized: false
```

每次 ledger tool 调用后：

1. 数据写入 SQLite。
2. 生成新的报告快照。
3. 计算 SHA-256。
4. 追加 `report.checkpoint` 事件。
5. 更新 `bytes`、`mtime`、`checkpoint_count` 和完整性状态。

### 8.2 报告内容

```markdown
---
schema: sectioned-zcode-review/v1
reviewer: zcode-glm
review_kind: code
status: completed
feature_id: ...
section_id: ...
round_kind: ...
base_ref: ...
head_ref: ...
runtime_hash: ...
session_id: ...
finalized: true
---

# Scope

# Evidence and audit trail

## Checkpoint 1
- Inspected:
- Commands:
- Observable results:
- Remaining coverage:

# Findings

## GLM-001 — Title
- Severity:
- Confidence:
- Location:
- Evidence:
- Impact:
- Suggested remediation:

# Validation

# Coverage and gaps

# Uncertainty

# Final review signal

FINALIZED: true
```

“边审查边记录”应记录可审计事实：

- 看过哪些文件或 diff。
- 执行了哪些命令。
- 得到了什么结果。
- 哪些假设被验证或否定。
- 哪些范围尚未覆盖。

不应要求或存储模型的隐藏推理链。

### 8.3 最终 signal

GLM 不应写：

```text
APPROVED
ACCEPTED
MERGE
```

它只应输出：

```text
findings_present
no_findings_observed
incomplete_evidence
unable_to_review
```

是否采纳 finding、是否算 clean round，仍由 Codex 主 Agent 的 admission 流程决定。

---

## 9. 权限与工作区策略

### 9.1 不使用 ZCode Plan mode

ZCode 的 Plan mode 对写工具存在硬限制，hook 或 permission response 不能简单绕过这些硬限制。官方 hook 文档也说明 deny、ask、allow 具有固定优先级，且 Plan-mode write ban 属于不可由普通 permission 决策覆盖的边界。

因此应使用普通审查 session，并通过外层隔离控制权限。

### 9.2 推荐的写入模型

#### 产品源码

- 放入 disposable worktree。
- 可以读取、搜索、运行测试。
- 不允许对正式工作树产生影响。
- 任务结束后比较 tracked diff。
- 如模型误编辑代码，报告 policy violation，并销毁 worktree。

#### 报告

- 通过 `review-ledger-mcp` 持续写入。
- daemon 是 Markdown 文件的唯一权威 writer。
- 不依赖模型是否正确处理绝对路径。
- 不存在 symlink escape 或路径穿越。

#### Scratch

可选地允许：

```text
.review-scratch/<agent_id>/
```

但 scratch 不进入产品 commit，也不作为最终报告的唯一证据来源。

### 9.3 Bash 风险

仅限制 `Write/Edit` 工具并不足够，因为 Bash 仍可改文件。因此：

- 审查必须在 disposable worktree 中运行。
- 网络默认关闭或受控。
- 终态必须执行 tracked-source integrity check。
- 不能只依赖 prompt 中的“不要修改代码”。

---

## 10. 与 `sectioned-feature-development` 的集成

### 10.1 角色定位

GLM reviewer 是：

- 外部模型维度。
- 独立 evidence producer。
- 不负责 admission。
- 不负责接受自己的 finding。
- 不取代现有 GPT reviewer。
- 不读取上一轮 reviewer 的结论。

### 10.2 Plan Review

输入：

- `PLAN-FULL` 或对应 PLAN 文件。
- Feature Context / Assurance Envelope。
- section 边界。
- DAG 和依赖。
- complexity budget。
- migration、rollback、validation 设计。
- 当前 repo 中必要的实现约束。

重点：

- scope inflation。
- section 切分不合理。
- 隐藏依赖。
- 数据迁移和兼容性遗漏。
- 验收条件不可测试。
- 失败恢复缺失。
- 计划与现有架构冲突。
- 明显过度工程化。

### 10.3 Code Review

输入：

- 固定的 base SHA 和 head SHA。
- 当前 section plan。
- diff。
- validation commands。
- 允许检查的 context。
- 禁止读取的上一轮 review 工件。

重点：

- correctness。
- regression。
- concurrency。
- data integrity。
- error handling。
- security boundary。
- test coverage。
- scope compliance。
- migration/backward compatibility。
- 是否出现没有在 plan 中声明的新架构边界。

### 10.4 独立性规则

每个可计入 clean gate 的 GLM review 必须：

- 新建 ZCode session。
- 新建 `agent_id`。
- 不 resume 上一 reviewer session。
- 不提供上一轮 RAW。
- 不提供上一轮 ADMISSION。
- 不提供其他 reviewer 的 finding。
- 不提供主 Agent 对旧 finding 的处理结论。

对于修复咨询，可以恢复旧 session，但该输出只能作为 repair guidance，**不能计为新的独立 clean review**。

### 10.5 Admission

建议每个 reviewer 分开保留：

```text
...-GPT-RAW.md
...-GPT-ADMISSION.md
...-GLM-RAW.md
...-GLM-ADMISSION.md
```

主 Agent必须对每个 GLM finding逐项：

- `admit`
- `reject_with_evidence`
- `defer_out_of_scope`
- `duplicate_of`
- `not_reproducible`

不得因为 GLM 写了 `no_findings_observed` 就自动接受该轮。

### 10.6 上线策略

#### 阶段 A：Shadow

- GLM 在 Plan Review 和完整 Code Review 中运行。
- 所有 finding 必须被阅读和 admission。
- 暂不改变原有 clean-round 计数。
- 记录误报率、独有发现率、失败率和报告合规率。

#### 阶段 B：Required evidence

- 完整 Plan Review 和完整 Code Review 必须产生 GLM 工件。
- GLM 有 admitted finding 时，该轮不能算 clean。
- GLM 基础设施失败不能解释为 clean。
- 可通过显式 human waiver 或既定 fallback 继续，而不是无限重试。

#### DELTA round

- 默认不强制运行 GLM。
- 只在修复跨架构边界、数据迁移、并发或安全问题时运行 targeted GLM review。
- DELTA 仍不计为独立 clean review。

---

## 11. 法律、支持性与维护风险

ZCode 服务条款包含禁止反向工程软件算法、源代码或运行机制，以及不授予默示知识产权许可的条款。

因此：

1. 不把 `zcode.cjs` 放入自建仓库。
2. 不从社区 release 自动下载或重新分发 runtime。
3. 不复制 runtime 解包和提取链路。
4. 不修改、反编译或 patch runtime。
5. 仅定位用户本地安装的官方 ZCode runtime。
6. 记录 runtime path、version 和 SHA-256。
7. 未通过兼容性测试的 runtime hash 默认 fail closed。
8. 为每次 ZCode 更新维护 compatibility matrix。
9. 团队或商业使用前应取得厂商书面许可或进行法律评估。

这不是对条款法律效果的最终判断，但技术可行性不能被当成官方支持或合同授权。

---

## 12. 最终建议

### 建议采用

- 官方本地 ZCode runtime。
- `zcode-acp` 的 typed protocol/driver 思路。
- persistent daemon + thin MCP。
- 每 job 一个隔离的 app-server child。
- SQLite append-only event store。
- job-scoped `review-ledger-mcp`。
- disposable review worktree。
- 显式 queue 和 interrupt-and-continue。
- fresh session independent review。
- GPT admission 保持最终控制权。

### 明确不采用

- 把整个 ZCode runtime 打包进 MCP。
- 直接以 `zcode-cli` 或 `zcode-tui` 作为生产服务器。
- 把 ZCode 的每个底层工具暴露给 Codex。
- 用单个同步 MCP tool 等待整个 review 完成。
- 把 `session/send` 冒充为已验证的 live steering。
- 依靠 progress notification 作为唯一进度通道。
- 让 GLM 自己接受自己的审查结果。
- 把报告只保存在 Agent 最终回答中。
- 给审查 Agent 正式产品工作树的无约束写权限。

**总体判定：技术上可行，架构上合理；建议先以本地 shadow reviewer 形式实现，再根据兼容性和独有发现率决定是否进入 required gate。**