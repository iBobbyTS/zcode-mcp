# Changelog

## 1.0.0

- Replaced whole-command regex matching with a limited shell tokenizer.
- Added command-specific argv policy for fourteen read-only command families.
- Added canonical path and symlink confinement.
- Added secret-like path denial.
- Added canonical command rewriting.
- Hardened Git invocation against optional writes, global/system configuration, pagers, external diff, and text conversion.
- Added modular plugin form and generated single-file replacement.
- Added adversarial, mutation, hook-protocol, path, and execution tests.
- Added optional metadata-only PostToolUse audit hook.
