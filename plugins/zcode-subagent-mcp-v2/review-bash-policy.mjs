export {
  evaluateCommand,
  evaluateHookInput,
  createHookOutput,
  policyMetadata,
  POLICY_VERSION,
  POLICY_SHA256,
} from './review-bash-hook/lib/readonly-bash-policy.mjs';

import { evaluateCommand } from './review-bash-hook/lib/readonly-bash-policy.mjs';

export function evaluate(input, options = {}) {
  const tool = input?.tool_name ?? input?.toolName;
  const toolInput = input?.tool_input ?? input?.input ?? {};
  const result = evaluateCommand({
    command: toolInput.command,
    cwd: input?.cwd ?? options.cwd,
    root: input?.worktree ?? options.worktree ?? options.root,
    unknownDecision: options.unknownDecision ?? 'deny',
    trustedBinDirs: options.trustedBinDirs,
  });
  return {
    allowed: tool === 'Bash' && result.decision === 'allow',
    reason: result.reason,
    policy_version: result.policyVersion,
    policy_sha256: result.policySha256,
    argv: result.argv,
    canonicalCommand: result.canonicalCommand,
    code: result.code,
  };
}
