# Policy Contract

## Security objective

Automatically allow only commands that the hook can conservatively prove are:

1. one simple POSIX-shell command;
2. in a closed program allowlist;
3. using a command-specific read-only option grammar;
4. restricted to the agent root;
5. not reading secret-like paths;
6. not invoking another executable, external diff helper, shell expansion, background task, pipe, or redirection.

An unsupported command is not assumed safe. The default decision is `deny`; deployments that prefer an interactive fallback may set `ZCODE_AGENT_BASH_UNKNOWN_DECISION=ask`.

## Decision pipeline

```text
JSON input validation
→ reject control characters and multiline input
→ tokenize limited shell words
→ reject unquoted shell syntax/expansion
→ resolve root and cwd
→ select exact program validator
→ validate options and positional roles
→ canonicalize and confine paths
→ reject secret-like paths and symlink escape
→ render canonical replacement command
→ allow
```

The canonical replacement prevents parser/execution drift. For example, an accepted Git status command is rewritten approximately as:

```bash
GIT_OPTIONAL_LOCKS=0 \
GIT_CONFIG_NOSYSTEM=1 \
GIT_CONFIG_GLOBAL=/dev/null \
GIT_ATTR_NOSYSTEM=1 \
git -c core.fsmonitor=false -c core.untrackedCache=false \
  --no-pager status --short
```

Diff-producing Git commands also receive `--no-ext-diff --no-textconv`.

## Shell grammar

Outside quotes, the following are always denied:

```text
;  &  |  <  >  (  )  {  }  $  `  *  ?  [  ]  #  !  newline
```

Consequences:

- no pipelines;
- no `&&`/`||`;
- no redirection;
- no command or parameter substitution;
- no background processes;
- no caller-supplied environment assignments;
- no unquoted glob expansion;
- no shell control flow.

Quoted metacharacters are literal data, so `rg 'foo|bar' src` is allowed when the remaining grammar is valid.

## Path policy

The root is `ZCODE_AGENT_BASH_ROOT` when set, otherwise the hook `cwd`.

Every path is:

- rejected if absolute, tilde-prefixed, URL-like, NUL-containing, or a Git magic pathspec;
- resolved relative to `cwd`;
- checked lexically against the root;
- checked through the deepest existing ancestor to prevent symlink escape;
- normalized in the rewritten command.

Direct reads of these categories are denied:

- `.git/**`;
- `.agent-work/**`;
- `.ssh`, `.gnupg`, `.aws`, `.azure`, `.kube`, `.docker`, GCloud and Keychain locations;
- `.env` and non-example `.env.*` files;
- common credential files and private-key/certificate extensions.

`.env.example`, `.env.sample`, `.env.template`, and `.env.dist` are not rejected solely by name.

## Command matrix

### `pwd`

Allows no option or one of `-L`, `-P`.

### `ls`

Allows non-recursive display options such as `-la`, `-A`, `-d`, `-h`, `-n`, `-1`, `-G`, plus a small long-option set. `-R` is denied.

### `stat`

Allows common BSD/GNU read formats and confined paths. Unknown options are not auto-allowed.

### `wc`

Allows byte/character/line/word/max-line counts on explicit files. Reading stdin is denied.

### `head` / `tail`

Allows bounded line or byte counts and explicit files. `tail -f`, `-F`, `--follow`, and `--retry` are denied.

### `cat`

Allows formatting options and explicit confined files. Reading stdin is denied.

### `grep`

Allows a closed set of search/format/context options, optional pattern files confined to the root, and at least one explicit file/directory path. `grep` may not read stdin, and recursive `-r`/`-R` is deliberately denied; use `rg` for repository-wide recursive search because its default hidden/ignore behavior is safer.

### `rg`

Allows common search, glob, type, context, file-list, and output-format options. `--pre`, `--pre-glob`, and `--follow` are denied. `rg` may default to the current agent root when no path is supplied.

### `sed`

Only this form is allowed:

```bash
sed -n 'N p' file        # written without the space: Np
sed -n 'N,Mp' file
```

The numeric upper bound is 100000. Editing, arbitrary expressions, and stdin are denied.

### `find`

Allows confined starting roots and a closed predicate grammar:

```text
-maxdepth -mindepth -type -name -iname -path -ipath
-size -mtime -mmin -newer -empty -readable -print -print0 -quit
```

These are hard-denied:

```text
-delete -exec -execdir -ok -okdir -fprint -fprint0 -fprintf -fls
-L -H
```

### `shasum` / `cksum`

Allows hashing explicit confined files. Check-file mode is denied because checksum files can refer to paths outside the agent root.

### Git

Allowed subcommands:

```text
status
log
diff
show
rev-parse
cat-file
ls-files
branch
```

Global caller-supplied Git options are denied, including `-C`, `-c`, `--git-dir`, and `--work-tree`.

Notable hard denials:

- `git diff --output`;
- `--ext-diff` and `--textconv` from the caller;
- `--no-index`;
- `--show-signature`;
- branch create/delete/rename forms;
- arbitrary Git subcommands;
- object paths that escape the repository or target sensitive files.

`git branch` is limited to list/query forms. A positional branch name without `--list` is rejected.

## Tests and builds

Commands such as these are deliberately outside the allowlist:

```text
cargo test
pytest
bun test
npm test
docker-compose
make
repository scripts
```

They execute repository code, write caches/build outputs, or start processes. Use daemon-owned named checks with exact program/args/cwd/environment, timeout, output cap, and process-group cleanup.

## Residual risks

- This hook does not provide kernel-level filesystem or network isolation.
- Executables are resolved only from a fixed trusted-directory list (or `ZCODE_AGENT_BASH_TRUSTED_BIN_DIRS`) and rewritten to an absolute real path; caller `PATH` is never searched. The configured trusted directories still belong to the local-user trust boundary and must not be writable by an untrusted principal.
- Git still reads repository-local metadata. The rewrite disables system/global config, fsmonitor, untracked-cache writes, pagers, external diff, and text conversion, but this is not equivalent to a hostile-repository sandbox.
- The policy is intentionally biased toward false denials. Add support by extending a command-specific validator and its adversarial corpus, not by adding a broad prefix/regex rule.
