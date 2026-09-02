# zcode-subagent-mcp

本项目的目标是把zcode通过mcp协议暴露，让其他agent把它当成subagent调度。现在基本通信已完成，但是交接稳定性上始终不理想，验证阶段没有完成，所以也没有做工程化，现在有12000行的lib.rs。

准备转战 [codex-rosetta](https://github.com/iBobbyTS/codex-rosetta)，直接把GLM放进Codex。