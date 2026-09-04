import assert from 'node:assert/strict';
import test from 'node:test';
import { tokenizeSimpleCommand } from '../lib/bash-policy.mjs';

function decision(command) {
  return tokenizeSimpleCommand(command);
}

test('tokenizes simple quoted argv without executing shell syntax', () => {
  const result = decision(`rg -n 'foo|bar' "src/a b.js"`);
  assert.equal(result.decision, 'parsed');
  assert.deepEqual(result.tokens.map((token) => token.value), ['rg', '-n', 'foo|bar', 'src/a b.js']);
});

test('rejects shell composition and expansion outside quotes', () => {
  for (const command of [
    'git status; touch pwn',
    'git status & touch pwn',
    'git status && touch pwn',
    'git status | cat',
    'git status > out',
    'cat < input',
    'echo $(id)',
    'echo `id`',
    'echo $HOME',
    'ls *.js',
    'echo {a,b}',
    'git status # comment',
    'git status\nwhoami',
  ]) {
    assert.equal(decision(command).decision, 'deny', command);
  }
});

test('allows metacharacters only as quoted literal data', () => {
  for (const command of [
    `rg ';' src`,
    `rg 'a|b' src`,
    `rg '\$(literal)' src`,
    `grep -n '[0-9]*' README.md`,
  ]) {
    assert.equal(decision(command).decision, 'parsed', command);
  }
});

test('rejects double-quoted expansion and caller env assignments', () => {
  assert.equal(decision('rg "$HOME" src').decision, 'deny');
  assert.equal(decision('TOKEN=x git status').decision, 'deny');
});
