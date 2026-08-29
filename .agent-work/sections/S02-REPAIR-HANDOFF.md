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

## 验证

- `python3 -m py_compile live-tests/*.py`
- `python3 -m unittest discover -s live-tests -v`（6/6）
- `git diff --check`
- 仅对本地 facade 做了 `tools/list` 协议冒烟；本轮未调用 official runtime。
