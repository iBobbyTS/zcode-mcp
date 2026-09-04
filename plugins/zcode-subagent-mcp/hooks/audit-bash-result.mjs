#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { evaluateCommand, policyMetadata } from '../lib/bash-policy.mjs';

let raw = '';
process.stdin.setEncoding('utf8');
for await (const chunk of process.stdin) raw += chunk;

function boundedText(value, maxBytes = 1_048_576) {
  if (typeof value !== 'string') return '';
  const bytes = Buffer.from(value, 'utf8');
  return bytes.length <= maxBytes ? value : bytes.subarray(0, maxBytes).toString('utf8');
}

try {
  const input = JSON.parse(raw);
  const tool = input?.tool_name ?? input?.toolName ?? '';
  if (tool !== 'Bash') process.exit(0);

  const toolInput = input?.tool_input ?? input?.input ?? {};
  const command = String(toolInput?.command ?? '');
  const cwd = String(input?.cwd ?? '');
  const evaluation = evaluateCommand({
    command,
    cwd,
    root: process.env.ZCODE_AGENT_BASH_ROOT || undefined,
    unknownDecision: process.env.ZCODE_AGENT_BASH_UNKNOWN_DECISION || 'deny',
  });
  const response = input?.tool_response ?? input?.toolResponse ?? {};
  const stdout = boundedText(response?.stdout ?? response?.output ?? '');
  const stderr = boundedText(response?.stderr ?? input?.error ?? '');
  const metadata = policyMetadata();
  const record = {
    schema: 'zcode-agent-bash-audit/v1',
    at: new Date().toISOString(),
    session_id: input?.session_id ?? input?.sessionId ?? null,
    tool_use_id: input?.tool_use_id ?? input?.toolUseId ?? null,
    hook_event_name: input?.hook_event_name ?? input?.hookEventName ?? null,
    cwd_sha256: crypto.createHash('sha256').update(cwd).digest('hex'),
    command_sha256: crypto.createHash('sha256').update(command).digest('hex'),
    canonical_argv: evaluation.decision === 'allow' ? evaluation.argv : null,
    policy_decision: evaluation.decision,
    policy_code: evaluation.code,
    policy_version: metadata.version,
    policy_sha256: metadata.sha256,
    status_code: Number.isInteger(response?.status_code) ? response.status_code : (Number.isInteger(response?.exitCode) ? response.exitCode : null),
    duration_ms: Number.isFinite(input?.duration_ms) ? Math.max(0, Math.floor(input.duration_ms))
      : (Number.isFinite(response?.duration_ms) ? Math.max(0, Math.floor(response.duration_ms)) : null),
    stdout_sha256: crypto.createHash('sha256').update(stdout).digest('hex'),
    stderr_sha256: crypto.createHash('sha256').update(stderr).digest('hex'),
    stdout_bytes_observed: Buffer.byteLength(stdout),
    stderr_bytes_observed: Buffer.byteLength(stderr),
    failed: Boolean(input?.error) || input?.hook_event_name === 'PostToolUseFailure' || input?.hookEventName === 'PostToolUseFailure',
  };

  const dataRoot = process.env.ZCODE_PLUGIN_DATA;
  if (!dataRoot) process.exit(0);
  fs.mkdirSync(dataRoot, { recursive: true, mode: 0o700 });
  const logPath = path.join(dataRoot, 'readonly-bash-audit.jsonl');
  fs.appendFileSync(logPath, `${JSON.stringify(record)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'a' });
} catch (error) {
  process.stderr.write(`[zcode-agent-bash-audit] ${error instanceof Error ? error.message : String(error)}\n`);
}
