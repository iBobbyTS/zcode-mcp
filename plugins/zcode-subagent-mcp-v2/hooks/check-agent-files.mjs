#!/usr/bin/env node
import { createAgentFileHookOutput, evaluateAgentFileInput } from '../lib/agent-file-policy.mjs';

let raw = '';
process.stdin.setEncoding('utf8');
for await (const chunk of process.stdin) raw += chunk;
try {
  const input = JSON.parse(raw);
  process.stdout.write(`${JSON.stringify(createAgentFileHookOutput(evaluateAgentFileInput(input)))}\n`);
} catch {
  // Never echo input, paths, or parser details: hook failures are denied and redacted.
  process.stdout.write(`${JSON.stringify(createAgentFileHookOutput({
    decision: 'deny',
    reason: 'zcode-agent-file-policy/v1.0.0: hook_internal_error',
  }))}\n`);
}

