#!/usr/bin/env node
import { createHookOutput, evaluateHookInput } from '../lib/bash-policy.mjs';

let raw = '';
process.stdin.setEncoding('utf8');
for await (const chunk of process.stdin) raw += chunk;

try {
  const input = JSON.parse(raw);
  const evaluated = evaluateHookInput(input);
  process.stdout.write(`${JSON.stringify(createHookOutput(evaluated))}\n`);
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stdout.write(`${JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: `zcode-agent-bash/v1.0.0 hook_internal_error: ${message.slice(0, 300)}`,
    },
  })}\n`);
  process.exitCode = 0;
}
