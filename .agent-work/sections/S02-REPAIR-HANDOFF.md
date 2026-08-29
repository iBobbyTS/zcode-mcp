# S02 Repair Handoff

## Scope

本轮只修改 `live-tests/conformance.py` 与 `live-tests/run_matrix.py`，没有改动 product code、S01 fixtures/reset、installer/supervisor 或 runtime bytes。

## 修复内容

- `run_matrix.py --official` 现在启动配置的 `zcode-review-mcp`，强制设置 `ZCODE_REVIEWD_SOCKET` 与 `ZCODE_PUBLIC_API_MODE=subagent_v2`，通过真实 JSON-RPC stdio 执行 `tools/list` 及 A/B/C 公共工具矩阵。
- catalog 从 `tools/list` 的 14 个公开工具读取；工具调用适配 rmcp `structuredContent`。
- 事件按 V2 `event_type` 五值投影，artifact 按 `bytes_base64/offset_bytes/eof/size_bytes` 校验。
- stdio 读写使用 select+单调时钟帧预算，close 有限等待、terminate/kill 兜底，并保存 redacted JSON transcript。
- LaunchLedger 使用跨进程锁、fsync 临时文件、原子替换；正式启动路径缺少 ledger 会直接失败，保留 nominal 5 + retry 3 上限。
- redaction 覆盖自由文本 secret/bearer/token（含空格、冒号、等号和引号形式）与完整绝对路径；pack finalizer/verify 执行根文件、目录、内容、symlink、cache/secret/path 与原子发布检查。
- FakeRuntime 增加 readiness/no-progress/restart-loss/progress、continuation、artifact 与 close/idempotency 负路径。

## Repair wave 4 closure

- Scope remained S02-only: `live-tests/**` plus this handoff; product crates and S01 fixtures/reset were not edited, and no official endpoint was called.
- R1/R7: fatal public-contract errors freeze immediately. Only classified infrastructure transport failures retry the same individual launch call once; ambiguous reservations stay consumed, immediate `existing` submissions release the unused reservation, and lifecycle errors never rerun a whole case.
- R2/R3: Case C uses only public provenance fields, optional counters, deduplicated dynamic event snapshots, attempt-2 validation, public-field threshold/non-refresh evidence, preserved rmcp error text/stable classes, and an actual MCP facade process restart with stable daemon `service_generation`. Active daemon restart remains deterministic fake-only.
- R5: all nine reports render from normalized evidence with computed case/overall enums. Pack finalize/verify reject placeholders, empty evidence roots/files, invalid UTF-8, malformed JSON/JSONL, unsafe names, symlinks, secrets, paths, and caches.
- R6: MCP identity binds to the launched command/hash; service/daemon state binds to public status; Hook identity binds to public spawn provenance. Active daemon binary, active runtime digest, and effective config digest are not publicly bindable and are recorded as explicit gaps rather than guessed.
- Direct main-runner tests cover successful actual-facade restart/rendering and fatal freeze before the next case.

## 验证

- `python3 -m py_compile live-tests/*.py`
- `python3 -m unittest discover -s live-tests -v`（6/6）
- `git diff --check`
- 仅对本地 facade 做了 `tools/list` 协议冒烟；本轮未调用 official runtime。

Wave 4 final validation: 20/20 stdlib tests passed; py_compile, diff-check, and CodeGraph sync passed; official calls remained 0.

## Repair wave 5 closure (R2b/R6b/R7b)

- Event sequence validation is attempt-local. Continuation attempts may restart
  at sequence `1`; duplicate page rereads remain in the observation stream and
  only the latest snapshot is used for the unique public projection.
- Public Hook binding gaps from both initial spawn and continuation are copied
  into case `evidence.gaps`, so computed conclusions and `KNOWN-GAPS.md` report
  `PASS_WITH_GAPS` truthfully instead of implying verified Hook activation.
- An ambiguous infrastructure retry reuses its reservation token but consumes
  a second total launch slot (`count` includes the retry; `retries` remains the
  retry subset). Proven idempotent `existing` replay still reserves no slot.
- Scope remained S02 live tests and handoff documentation only; no product,
  S01, or official-runtime calls were made.

Wave 5 validation: 24/24 stdlib tests passed; py_compile, diff-check, and
CodeGraph sync passed; official calls remained 0.
