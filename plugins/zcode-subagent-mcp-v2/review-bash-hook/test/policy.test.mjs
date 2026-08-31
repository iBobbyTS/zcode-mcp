import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { evaluateCommand, policyMetadata } from '../lib/readonly-bash-policy.mjs';

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zcode-bash-policy-'));
  fs.mkdirSync(path.join(root, 'src'));
  fs.mkdirSync(path.join(root, 'docs'));
  fs.writeFileSync(path.join(root, 'README.md'), 'needle\n');
  fs.writeFileSync(path.join(root, 'src', 'a.js'), 'const needle = 1;\n');
  fs.writeFileSync(path.join(root, 'docs', 'note.txt'), 'note\n');
  fs.writeFileSync(path.join(root, '.env'), 'SECRET=x\n');
  return root;
}

const ALLOW = [
  'pwd',
  'pwd -P',
  'ls -la',
  'ls --color=never src',
  `stat -f '%N %z' README.md`,
  'wc -l README.md',
  'head -n 20 README.md',
  'tail -n 20 README.md',
  'cat -n README.md',
  `grep -n 'needle' README.md`,
  `rg -n 'needle|other' src`,
  'rg --files src',
  `sed -n '1,20p' README.md`,
  `find . -maxdepth 2 -type f -name '*.js'`,
  'shasum -a 256 README.md',
  'cksum README.md',
  'git status --short',
  'git log --oneline -n 10',
  'git diff --stat HEAD~1 HEAD',
  'git diff --cached --name-status',
  'git show --stat HEAD',
  'git rev-parse --verify HEAD',
  'git cat-file -t HEAD',
  'git ls-files -- src',
  'git branch --show-current',
  `git branch --list 'feature/*'`,
];

const DENY = [
  'find . -delete',
  `find . -exec rm -rf '{}' +`,
  'find . -print',
  'find . -print0',
  'find -L . -type f',
  'git branch -D victim',
  'git branch victim',
  'git diff --output=/tmp/leak.patch',
  'git diff --no-index README.md /etc/passwd',
  'git show --show-signature HEAD',
  'git cat-file --filters HEAD:README.md',
  'git -C /tmp status --short',
  'git config --list',
  'git checkout main',
  'openssl rand -out /tmp/key.bin 32',
  'git log & touch /tmp/pwn',
  'ls -la && touch /tmp/pwn',
  'cat ~/.ssh/id_rsa',
  'cat /etc/passwd',
  'cat .env',
  'cat .git/config',
  'cat .agent-work/PLAN.md',
  'tail -f README.md',
  'grep needle',
  'rg --pre cat needle src',
  'rg --hidden needle .',
  'grep -r needle .',
  'shasum -c CHECKSUMS.sha256',
  'cat -',
];

test('allows the closed read-only command corpus and canonicalizes execution', () => {
  const root = fixture();
  for (const command of ALLOW) {
    const result = evaluateCommand({ command, cwd: root });
    assert.equal(result.decision, 'allow', `${command}: ${result.code} ${result.reason}`);
    assert.ok(result.canonicalCommand.length > 0);
    if (command.startsWith('git ')) {
      assert.match(result.canonicalCommand, /^GIT_OPTIONAL_LOCKS=0 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=\/dev\/null GIT_ATTR_NOSYSTEM=1 \/.*\/git -c core\.fsmonitor=false -c core\.untrackedCache=false --no-pager/u);
    }
  }
});

test('denies destructive, executable, unconfined, secret, and ambiguous corpus', () => {
  const root = fixture();
  for (const command of DENY) {
    const result = evaluateCommand({ command, cwd: root });
    assert.equal(result.decision, 'deny', `${command}: unexpectedly ${result.code}`);
  }
});

test('denies an existing symlink that escapes the review root', () => {
  const root = fixture();
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'zcode-bash-outside-'));
  fs.writeFileSync(path.join(outside, 'secret.txt'), 'secret');
  fs.symlinkSync(outside, path.join(root, 'escape'));
  const result = evaluateCommand({ command: 'cat escape/secret.txt', cwd: root });
  assert.equal(result.decision, 'deny');
  assert.equal(result.code, 'symlink_escape');
});

test('rechecks canonical symlink targets for secret and prior-review paths', () => {
  const root = fixture();
  fs.mkdirSync(path.join(root, '.git'), { recursive: true });
  fs.writeFileSync(path.join(root, '.git', 'config'), '[core]\n');
  fs.mkdirSync(path.join(root, '.agent-work', 'reviews'), { recursive: true });
  fs.writeFileSync(path.join(root, '.agent-work', 'reviews', 'old.md'), 'old\n');
  fs.writeFileSync(path.join(root, 'private.pem'), 'key\n');
  fs.writeFileSync(path.join(root, 'id_ed25519'), 'key\n');
  for (const [alias, target] of [
    ['safe-env', '.env'],
    ['safe-git', '.git/config'],
    ['safe-review', '.agent-work/reviews/old.md'],
    ['safe-pem', 'private.pem'],
    ['safe-ed', 'id_ed25519'],
  ]) {
    fs.symlinkSync(target, path.join(root, alias));
    const result = evaluateCommand({ command: `cat ${alias}`, cwd: root });
    assert.equal(result.decision, 'deny', alias);
  }
  fs.writeFileSync(path.join(root, 'ordinary.txt'), 'safe\n');
  fs.symlinkSync('ordinary.txt', path.join(root, 'safe-alias'));
  assert.equal(evaluateCommand({ command: 'cat safe-alias', cwd: root }).decision, 'allow');
});

test('denies cwd outside an explicit root', () => {
  const root = fixture();
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'zcode-bash-other-'));
  const result = evaluateCommand({ command: 'pwd', cwd: outside, root });
  assert.equal(result.decision, 'deny');
  assert.equal(result.code, 'cwd_outside_root');
});

test('can ask rather than deny for unsupported but not intrinsically dangerous commands', () => {
  const root = fixture();
  const result = evaluateCommand({ command: 'file README.md', cwd: root, unknownDecision: 'ask' });
  assert.equal(result.decision, 'ask');
  assert.equal(result.code, 'program_not_allowlisted');
});

test('policy metadata is stable and nonempty', () => {
  const metadata = policyMetadata();
  assert.match(metadata.version, /^zcode-readonly-bash\//u);
  assert.match(metadata.sha256, /^[a-f0-9]{64}$/u);
  assert.deepEqual(metadata.descriptor.denialRecoveryClasses, [
    'split_once',
    'simplify_once',
    'use_read',
    'use_named_check',
    'do_not_retry_equivalent',
  ]);
});

test('denial recovery permits one split or simplification without disabling unrelated Bash', () => {
  const root = fixture();
  const compound = evaluateCommand({ command: 'git status && pwd', cwd: root });
  assert.equal(compound.decision, 'deny');
  assert.equal(compound.retryClass, 'split_once');
  assert.equal(evaluateCommand({ command: 'git status --short', cwd: root }).decision, 'allow');

  const gitC = evaluateCommand({ command: `git -C '${root}' status --short`, cwd: root });
  assert.equal(gitC.decision, 'deny');
  assert.equal(gitC.retryClass, 'simplify_once');
  assert.equal(evaluateCommand({ command: 'git status --short', cwd: root }).decision, 'allow');
  assert.equal(evaluateCommand({ command: 'pwd', cwd: root }).decision, 'allow');
});

test('semantic denial fingerprints normalize quoted hard denials and separate Git categories', () => {
  const root = fixture();
  const andSequence = evaluateCommand({ command: 'git status && pwd', cwd: root });
  const semicolonSequence = evaluateCommand({ command: 'git status; pwd', cwd: root });
  assert.equal(andSequence.semanticFingerprint, semicolonSequence.semanticFingerprint);

  const plain = evaluateCommand({ command: 'cat .env', cwd: root });
  const quoted = evaluateCommand({ command: "cat './.env'", cwd: root });
  assert.equal(plain.retryClass, 'do_not_retry_equivalent');
  assert.equal(quoted.semanticFingerprint, plain.semanticFingerprint);

  const cwdOverride = evaluateCommand({ command: `git -C '${root}' status --short`, cwd: root });
  const outputWrite = evaluateCommand({ command: 'git diff --output=leak.patch', cwd: root });
  assert.notEqual(cwdOverride.semanticFingerprint, outputWrite.semanticFingerprint);
});

test('denies Git object paths that escape or target sensitive files', () => {
  const root = fixture();
  for (const command of [
    'git show HEAD:../../secret',
    'git show HEAD:.env',
    'git cat-file -p HEAD:.git/config',
  ]) {
    assert.equal(evaluateCommand({ command, cwd: root }).decision, 'deny', command);
  }
});

test('denies special files for content-reading commands', () => {
  const root = fixture();
  const fifo = path.join(root, 'pipe');
  const mkfifo = process.platform === 'win32' ? null : spawnSync('mkfifo', [fifo]);
  if (mkfifo && mkfifo.status === 0) {
    const result = evaluateCommand({ command: 'cat pipe', cwd: root });
    assert.equal(result.decision, 'deny');
    assert.equal(result.code, 'path_type_denied');
  }
});

test('does not resolve executables from caller PATH', () => {
  const root = fixture();
  const result = evaluateCommand({ command: 'cat README.md', cwd: root, trustedBinDirs: ['/definitely/not/a/bin'] });
  assert.equal(result.decision, 'deny');
  assert.equal(result.code, 'trusted_executable_not_found');
});
