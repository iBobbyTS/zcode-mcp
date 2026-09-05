use crate::{PreparationError, PreparationResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    thread,
};

const MAX_DIAGNOSTIC_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedWorktree {
    pub repository: PathBuf,
    pub path: PathBuf,
    pub scratch_worktrees_root: PathBuf,
    pub diagnostic_root: PathBuf,
    pub head_sha: String,
    pub source_refs_before: String,
    pub source_refs_before_sha256: String,
    pub source_refs_before_truncated: bool,
    pub source_status_before: String,
    pub source_status_before_sha256: String,
    pub source_status_before_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityDiagnostics {
    pub repository: PathBuf,
    pub worktree: PathBuf,
    pub expected_head: String,
    pub observed_head: Option<String>,
    pub source_refs_before: String,
    pub source_refs_before_sha256: String,
    pub source_refs_after: String,
    pub source_refs_after_sha256: String,
    pub source_status_before: String,
    pub source_status_before_sha256: String,
    pub source_status_after: String,
    pub source_status_after_sha256: String,
    pub worktree_status: String,
    pub tracked_diff: String,
    pub staged_diff: String,
    pub diagnostic_truncated: bool,
    pub refs_unchanged: bool,
    pub source_status_unchanged: bool,
    pub detached_head_unchanged: bool,
    pub worktree_clean: bool,
}

impl IntegrityDiagnostics {
    pub fn source_integrity_preserved(&self) -> bool {
        self.refs_unchanged && self.source_status_unchanged
    }

    pub fn has_policy_violation(&self) -> bool {
        !self.source_integrity_preserved() || !self.detached_head_unchanged || !self.worktree_clean
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupRecord {
    pub repository: PathBuf,
    pub task_root: PathBuf,
    pub worktree: PathBuf,
    pub expected_head: String,
    pub diagnostics: IntegrityDiagnostics,
    pub scratch_worktrees_root: PathBuf,
    pub diagnostic_root: PathBuf,
    pub cleaned: bool,
}

#[derive(Debug, Clone)]
pub struct WorktreeManager {
    repository: PathBuf,
    scratch_root: PathBuf,
}

impl WorktreeManager {
    pub fn new(repository: PathBuf, scratch_root: PathBuf) -> PreparationResult<Self> {
        let repository = fs::canonicalize(repository)?;
        let scratch_root = fs::canonicalize(&scratch_root)?;
        if scratch_root == repository || !scratch_root.starts_with(&repository) {
            // Scratch may be external, but it must not alias the source tree itself.
            if scratch_root == repository {
                return Err(PreparationError::InvalidPath {
                    path: scratch_root,
                    reason: "scratch root cannot be the repository root".into(),
                });
            }
        }
        Ok(Self {
            repository,
            scratch_root,
        })
    }

    pub fn create(
        &self,
        head_sha: &str,
        worktree_key: &str,
    ) -> PreparationResult<PreparedWorktree> {
        if worktree_key.is_empty() || !worktree_key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(PreparationError::InvalidManifest(
                "worktree key must be hexadecimal".into(),
            ));
        }
        let worktrees_root = create_and_canonicalize(&self.scratch_root.join("worktrees"))?;
        let diagnostic_root = create_and_canonicalize(&self.scratch_root.join("diagnostics"))?;
        let path = worktrees_root.join(worktree_key);
        let refs_before = refs_snapshot(&self.repository)?;
        let status_before = status_snapshot(&self.repository)?;

        if path.exists() {
            verify_existing_worktree(&self.repository, &path, &worktrees_root, head_sha)?;
        } else {
            let output = git(
                &self.repository,
                &["worktree", "add", "--detach", path_to_str(&path)?, head_sha],
            )?;
            ensure_success(output, "git worktree add")?;
        }
        let path = fs::canonicalize(&path)?;
        if !path.starts_with(&worktrees_root) {
            return Err(PreparationError::PathEscape {
                path,
                root: worktrees_root,
            });
        }
        verify_existing_worktree(&self.repository, &path, &worktrees_root, head_sha)?;
        let refs_after = refs_snapshot(&self.repository)?;
        if refs_after.sha256 != refs_before.sha256 {
            return Err(PreparationError::Worktree(
                "detached worktree creation changed source refs".into(),
            ));
        }
        let status_after = status_snapshot(&self.repository)?;
        if status_after.sha256 != status_before.sha256 {
            return Err(PreparationError::Worktree(
                "detached worktree creation changed source tracked/staged status".into(),
            ));
        }
        Ok(PreparedWorktree {
            repository: self.repository.clone(),
            path,
            scratch_worktrees_root: worktrees_root,
            diagnostic_root,
            head_sha: head_sha.into(),
            source_refs_before: refs_before.text,
            source_refs_before_sha256: refs_before.sha256,
            source_refs_before_truncated: refs_before.truncated,
            source_status_before: status_before.text,
            source_status_before_sha256: status_before.sha256,
            source_status_before_truncated: status_before.truncated,
        })
    }

    /// Bind a prepared task directly to the canonical repository. This path
    /// intentionally performs no `git worktree add`; cleanup is a no-op for
    /// the source workspace and only scratch metadata is owned by the task.
    pub fn bind_direct(&self) -> PreparationResult<PreparedWorktree> {
        let worktrees_root = create_and_canonicalize(&self.scratch_root.join("worktrees"))?;
        let diagnostic_root = create_and_canonicalize(&self.scratch_root.join("diagnostics"))?;
        let path = self.repository.clone();
        Ok(PreparedWorktree {
            repository: self.repository.clone(),
            path,
            scratch_worktrees_root: worktrees_root,
            diagnostic_root,
            head_sha: String::new(),
            source_refs_before: String::new(),
            source_refs_before_sha256: String::new(),
            source_refs_before_truncated: false,
            source_status_before: String::new(),
            source_status_before_sha256: String::new(),
            source_status_before_truncated: false,
        })
    }

    pub fn capture_integrity(
        &self,
        worktree: &PreparedWorktree,
    ) -> PreparationResult<IntegrityDiagnostics> {
        self.verify_worktree_owner(worktree)?;
        let source_refs_after = refs_snapshot(&worktree.repository)?;
        let source_status_after = status_snapshot(&worktree.repository)?;
        let observed_head = git_text(&worktree.path, &["rev-parse", "HEAD"]).ok();
        let worktree_status = bounded_git_snapshot(
            &worktree.path,
            &["status", "--porcelain=v1", "--untracked-files=all"],
            MAX_DIAGNOSTIC_BYTES,
        )?;
        let (tracked_diff, tracked_truncated) = bounded_git_text(
            &worktree.path,
            &["diff", "--binary", "--no-ext-diff", "--no-textconv"],
            MAX_DIAGNOSTIC_BYTES,
        )?;
        let (staged_diff, staged_truncated) = bounded_git_text(
            &worktree.path,
            &[
                "diff",
                "--cached",
                "--binary",
                "--no-ext-diff",
                "--no-textconv",
            ],
            MAX_DIAGNOSTIC_BYTES,
        )?;
        Ok(IntegrityDiagnostics {
            repository: worktree.repository.clone(),
            worktree: worktree.path.clone(),
            expected_head: worktree.head_sha.clone(),
            observed_head: observed_head.clone(),
            source_refs_before: worktree.source_refs_before.clone(),
            source_refs_before_sha256: worktree.source_refs_before_sha256.clone(),
            source_refs_after: source_refs_after.text.clone(),
            source_refs_after_sha256: source_refs_after.sha256.clone(),
            source_status_before: worktree.source_status_before.clone(),
            source_status_before_sha256: worktree.source_status_before_sha256.clone(),
            source_status_after: source_status_after.text.clone(),
            source_status_after_sha256: source_status_after.sha256.clone(),
            worktree_clean: worktree_status.text.is_empty()
                && tracked_diff.is_empty()
                && staged_diff.is_empty(),
            worktree_status: worktree_status.text,
            tracked_diff,
            staged_diff,
            diagnostic_truncated: worktree.source_refs_before_truncated
                || worktree.source_status_before_truncated
                || source_refs_after.truncated
                || source_status_after.truncated
                || worktree_status.truncated
                || tracked_truncated
                || staged_truncated,
            refs_unchanged: source_refs_after.sha256 == worktree.source_refs_before_sha256,
            source_status_unchanged: source_status_after.sha256
                == worktree.source_status_before_sha256,
            detached_head_unchanged: observed_head.as_deref() == Some(worktree.head_sha.as_str())
                && is_detached(&worktree.path)?,
        })
    }

    pub fn persist_integrity(
        &self,
        worktree: &PreparedWorktree,
        diagnostics: IntegrityDiagnostics,
    ) -> PreparationResult<PathBuf> {
        self.verify_worktree_owner(worktree)?;
        if diagnostics.repository != worktree.repository
            || diagnostics.worktree != worktree.path
            || diagnostics.expected_head != worktree.head_sha
        {
            return Err(PreparationError::Worktree(
                "integrity diagnostics do not match prepared worktree".into(),
            ));
        }
        let record = CleanupRecord {
            repository: self.repository.clone(),
            task_root: self.scratch_root.clone(),
            worktree: worktree.path.clone(),
            expected_head: worktree.head_sha.clone(),
            diagnostics,
            scratch_worktrees_root: worktree.scratch_worktrees_root.clone(),
            diagnostic_root: worktree.diagnostic_root.clone(),
            cleaned: false,
        };
        let worktree_name = worktree.path.file_name().ok_or_else(|| {
            PreparationError::Worktree("prepared worktree has no final path component".into())
        })?;
        let filename = format!("{}.json", worktree_name.to_string_lossy());
        let path = worktree.diagnostic_root.join(filename);
        atomic_write_json(&path, &record)?;
        Ok(path)
    }

    pub fn cleanup_from_record(&self, record_path: &Path) -> PreparationResult<CleanupRecord> {
        let (worktrees_root, diagnostic_root) = self.expected_roots()?;
        let record_path = fs::canonicalize(record_path)?;
        if record_path.parent() != Some(diagnostic_root.as_path()) {
            return Err(PreparationError::PathEscape {
                path: record_path,
                root: diagnostic_root,
            });
        }
        let mut record: CleanupRecord = serde_json::from_slice(&fs::read(&record_path)?)?;
        if fs::canonicalize(&record.repository)? != self.repository
            || record.repository != self.repository
            || fs::canonicalize(&record.task_root)? != self.scratch_root
            || record.task_root != self.scratch_root
            || fs::canonicalize(&record.scratch_worktrees_root)? != worktrees_root
            || record.scratch_worktrees_root != worktrees_root
            || fs::canonicalize(&record.diagnostic_root)? != diagnostic_root
            || record.diagnostic_root != diagnostic_root
        {
            return Err(PreparationError::Worktree(
                "cleanup record is not bound to this manager".into(),
            ));
        }
        if record.worktree != record.diagnostics.worktree
            || record.expected_head != record.diagnostics.expected_head
            || record.repository != record.diagnostics.repository
        {
            return Err(PreparationError::Worktree(
                "cleanup record identity fields disagree".into(),
            ));
        }
        let worktree_name = record.worktree.file_name().ok_or_else(|| {
            PreparationError::Worktree("cleanup target has no final path component".into())
        })?;
        if record.worktree.parent() != Some(worktrees_root.as_path())
            || record.worktree == worktrees_root
            || record_path
                != diagnostic_root.join(format!("{}.json", worktree_name.to_string_lossy()))
        {
            return Err(PreparationError::Worktree(
                "cleanup record target does not match its manager-owned record path".into(),
            ));
        }
        let registered = registered_worktree(&self.repository, &record.worktree)?;
        if record.cleaned {
            if record.worktree.exists() || registered.is_some() {
                return Err(PreparationError::Worktree(
                    "cleanup record is complete but its worktree remains present or registered"
                        .into(),
                ));
            }
            return Ok(record);
        }
        if record.worktree.exists() {
            let worktree = fs::canonicalize(&record.worktree)?;
            if worktree != record.worktree {
                return Err(PreparationError::Worktree(
                    "cleanup target canonical identity changed".into(),
                ));
            }
            let observed = git_text(&worktree, &["rev-parse", "HEAD"])?;
            let registered = registered.ok_or_else(|| {
                PreparationError::Worktree(
                    "cleanup target is not a registered worktree of this repository".into(),
                )
            })?;
            if observed != record.expected_head
                || registered.head != record.expected_head
                || !registered.detached
                || !is_detached(&worktree)?
            {
                return Err(PreparationError::Worktree(
                    "cleanup target identity no longer matches diagnostics".into(),
                ));
            }
            let output = git(
                &self.repository,
                &["worktree", "remove", "--force", path_to_str(&worktree)?],
            )?;
            ensure_success(output, "git worktree remove")?;
        } else if registered.is_some() {
            return Err(PreparationError::Worktree(
                "cleanup target is missing but remains registered".into(),
            ));
        }
        if record.worktree.exists()
            || registered_worktree(&self.repository, &record.worktree)?.is_some()
        {
            return Err(PreparationError::Worktree(
                "verified worktree still exists or remains registered after cleanup".into(),
            ));
        }
        record.cleaned = true;
        atomic_write_json(&record_path, &record)?;
        Ok(record)
    }

    /// Verify that a prepared worktree has converged to both filesystem and
    /// Git-registration absence before its private task root is removed.
    pub fn verify_worktree_absent(&self, worktree: &PreparedWorktree) -> PreparationResult<()> {
        let (worktrees_root, diagnostic_root) = self.expected_roots()?;
        let path = fs::canonicalize(&worktree.path).unwrap_or_else(|_| worktree.path.clone());
        if worktree.repository != self.repository
            || worktree.scratch_worktrees_root != worktrees_root
            || worktree.diagnostic_root != diagnostic_root
            || path.parent() != Some(worktrees_root.as_path())
        {
            return Err(PreparationError::Worktree(
                "absent-worktree proof is not bound to this manager".into(),
            ));
        }
        if worktree.path.exists()
            || registered_worktree(&self.repository, &worktree.path)?.is_some()
        {
            return Err(PreparationError::Worktree(
                "worktree filesystem or Git registration remains".into(),
            ));
        }
        Ok(())
    }

    pub fn verify_path_absent(&self, path: &Path) -> PreparationResult<()> {
        let (worktrees_root, _) = self.expected_roots()?;
        let path = path.to_path_buf();
        if path.parent() != Some(worktrees_root.as_path()) {
            return Err(PreparationError::PathEscape {
                path,
                root: worktrees_root,
            });
        }
        if path.exists() || registered_worktree(&self.repository, &path)?.is_some() {
            return Err(PreparationError::Worktree(
                "worktree filesystem or Git registration remains".into(),
            ));
        }
        Ok(())
    }

    pub fn verify_registration_absent(&self, path: &Path) -> PreparationResult<()> {
        if registered_worktree(&self.repository, path)?.is_some() {
            return Err(PreparationError::Worktree(
                "Git registration remains after filesystem cleanup".into(),
            ));
        }
        Ok(())
    }

    pub fn cleanup_registered_under_task_root(&self, task_root: &Path) -> PreparationResult<()> {
        let task_root = fs::canonicalize(task_root)?;
        if task_root != self.scratch_root {
            return Err(PreparationError::Worktree(
                "malformed-record cleanup is not bound to this manager task root".into(),
            ));
        }
        let (worktrees_root, _) = self.expected_roots()?;
        let registrations = registered_worktrees_under(&self.repository, &worktrees_root)?;
        for registration in &registrations {
            if registration.path.parent() != Some(worktrees_root.as_path())
                || registration.path == worktrees_root
                || !registration.detached
            {
                return Err(PreparationError::Worktree(
                    "registered malformed-record cleanup target is not a trusted detached child"
                        .into(),
                ));
            }
        }
        for registration in registrations {
            let output = git(
                &self.repository,
                &[
                    "worktree",
                    "remove",
                    "--force",
                    path_to_str(&registration.path)?,
                ],
            )?;
            ensure_success(output, "git worktree remove malformed record")?;
        }
        if !registered_worktrees_under(&self.repository, &worktrees_root)?.is_empty() {
            return Err(PreparationError::Worktree(
                "Git registration remains after malformed-record cleanup".into(),
            ));
        }
        Ok(())
    }

    fn expected_roots(&self) -> PreparationResult<(PathBuf, PathBuf)> {
        Ok((
            fs::canonicalize(self.scratch_root.join("worktrees"))?,
            fs::canonicalize(self.scratch_root.join("diagnostics"))?,
        ))
    }

    fn verify_worktree_owner(&self, worktree: &PreparedWorktree) -> PreparationResult<()> {
        let (root, diagnostic_root) = self.expected_roots()?;
        let path = fs::canonicalize(&worktree.path)?;
        if worktree.repository != self.repository
            || fs::canonicalize(&worktree.repository)? != self.repository
            || worktree.scratch_worktrees_root != root
            || worktree.diagnostic_root != diagnostic_root
            || path != worktree.path
            || (path != self.repository && path.parent() != Some(root.as_path()))
        {
            return Err(PreparationError::Worktree(
                "prepared worktree is not bound to this manager".into(),
            ));
        }
        if path == self.repository {
            return Ok(());
        }
        let registered = registered_worktree(&self.repository, &path)?.ok_or_else(|| {
            PreparationError::Worktree(
                "prepared worktree is not registered with this repository".into(),
            )
        })?;
        if registered.head != worktree.head_sha || !registered.detached {
            return Err(PreparationError::Worktree(
                "prepared worktree registration does not match its expected head".into(),
            ));
        }
        Ok(())
    }
}

fn verify_existing_worktree(
    repository: &Path,
    path: &Path,
    root: &Path,
    expected: &str,
) -> PreparationResult<()> {
    let path = fs::canonicalize(path)?;
    if path == root || !path.starts_with(root) {
        return Err(PreparationError::PathEscape {
            path,
            root: root.to_path_buf(),
        });
    }
    let registered = registered_worktree(repository, &path)?;
    if git_text(&path, &["rev-parse", "HEAD"])? != expected
        || !is_detached(&path)?
        || !registered.is_some_and(|entry| entry.head == expected && entry.detached)
    {
        return Err(PreparationError::Worktree(
            "existing worktree is not detached at the requested head".into(),
        ));
    }
    Ok(())
}

fn is_detached(path: &Path) -> PreparationResult<bool> {
    let output = git(path, &["symbolic-ref", "-q", "HEAD"])?;
    Ok(!output.status.success())
}

#[derive(Debug)]
struct RegisteredWorktree {
    path: PathBuf,
    head: String,
    detached: bool,
}

fn registered_worktree(
    repository: &Path,
    target: &Path,
) -> PreparationResult<Option<RegisteredWorktree>> {
    let output = git(repository, &["worktree", "list", "--porcelain", "-z"])?;
    let output = ensure_success(output, "Git worktree registration query")?;
    if output.stdout.truncated {
        return Err(PreparationError::Worktree(
            "Git worktree registration list exceeds the bounded capture limit".into(),
        ));
    }
    let mut current_path: Option<PathBuf> = None;
    let mut current_head: Option<String> = None;
    let mut detached = false;
    for field in output.stdout.retained.split(|byte| *byte == 0) {
        if field.is_empty() {
            if current_path.as_deref() == Some(target) {
                return Ok(Some(RegisteredWorktree {
                    path: target.to_path_buf(),
                    head: current_head.unwrap_or_default(),
                    detached,
                }));
            }
            current_path = None;
            current_head = None;
            detached = false;
            continue;
        }
        let field = String::from_utf8_lossy(field);
        if let Some(value) = field.strip_prefix("worktree ") {
            current_path = Some(PathBuf::from(value));
        } else if let Some(value) = field.strip_prefix("HEAD ") {
            current_head = Some(value.into());
        } else if field == "detached" {
            detached = true;
        }
    }
    Ok(None)
}

fn registered_worktrees_under(
    repository: &Path,
    root: &Path,
) -> PreparationResult<Vec<RegisteredWorktree>> {
    let output = git(repository, &["worktree", "list", "--porcelain", "-z"])?;
    let output = ensure_success(output, "Git worktree registration query")?;
    if output.stdout.truncated {
        return Err(PreparationError::Worktree(
            "Git worktree registration list exceeds the bounded capture limit".into(),
        ));
    }
    let mut result = Vec::new();
    let mut current_path: Option<PathBuf> = None;
    let mut current_head: Option<String> = None;
    let mut detached = false;
    for field in output.stdout.retained.split(|byte| *byte == 0) {
        if field.is_empty() {
            if let Some(path) = current_path.take() {
                if path.starts_with(root) {
                    result.push(RegisteredWorktree {
                        path,
                        head: current_head.take().unwrap_or_default(),
                        detached,
                    });
                }
            }
            current_head = None;
            detached = false;
            continue;
        }
        let field = String::from_utf8_lossy(field);
        if let Some(value) = field.strip_prefix("worktree ") {
            current_path = Some(PathBuf::from(value));
        } else if let Some(value) = field.strip_prefix("HEAD ") {
            current_head = Some(value.into());
        } else if field == "detached" {
            detached = true;
        }
    }
    Ok(result)
}

#[derive(Debug)]
struct TextSnapshot {
    text: String,
    sha256: String,
    truncated: bool,
}

fn refs_snapshot(repository: &Path) -> PreparationResult<TextSnapshot> {
    bounded_git_snapshot(
        repository,
        &["for-each-ref", "--format=%(refname) %(objectname)"],
        MAX_DIAGNOSTIC_BYTES,
    )
}

fn status_snapshot(repository: &Path) -> PreparationResult<TextSnapshot> {
    bounded_git_snapshot(
        repository,
        &["status", "--porcelain=v1", "--untracked-files=no"],
        MAX_DIAGNOSTIC_BYTES,
    )
}

fn bounded_git_text(
    path: &Path,
    arguments: &[&str],
    max_bytes: usize,
) -> PreparationResult<(String, bool)> {
    let snapshot = bounded_git_snapshot(path, arguments, max_bytes)?;
    Ok((snapshot.text, snapshot.truncated))
}

fn bounded_git_snapshot(
    path: &Path,
    arguments: &[&str],
    max_bytes: usize,
) -> PreparationResult<TextSnapshot> {
    let output = git_with_limits(path, arguments, max_bytes, MAX_DIAGNOSTIC_BYTES)?;
    let output = ensure_success(output, "Git diagnostic")?;
    Ok(TextSnapshot {
        text: String::from_utf8_lossy(&output.stdout.retained).into_owned(),
        sha256: output.stdout.sha256,
        truncated: output.stdout.truncated,
    })
}

fn git_text(path: &Path, arguments: &[&str]) -> PreparationResult<String> {
    let output = git(path, arguments)?;
    let output = ensure_success(output, "Git query")?;
    if output.stdout.truncated {
        return Err(PreparationError::Git(
            "Git query output exceeds the bounded capture limit".into(),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout.retained)
        .trim()
        .to_owned())
}

#[derive(Debug)]
struct StreamCapture {
    retained: Vec<u8>,
    sha256: String,
    truncated: bool,
}

#[derive(Debug)]
struct GitOutput {
    status: ExitStatus,
    stdout: StreamCapture,
    stderr: StreamCapture,
}

fn git(path: &Path, arguments: &[&str]) -> PreparationResult<GitOutput> {
    git_with_limits(path, arguments, MAX_DIAGNOSTIC_BYTES, MAX_DIAGNOSTIC_BYTES)
}

fn git_with_limits(
    path: &Path,
    arguments: &[&str],
    max_stdout: usize,
    max_stderr: usize,
) -> PreparationResult<GitOutput> {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(path)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.pager=cat",
        ])
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_PAGER", "cat")
        .env_remove("GIT_EXTERNAL_DIFF")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| PreparationError::Git("Git stdout pipe was not available".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| PreparationError::Git("Git stderr pipe was not available".into()))?;
    let stdout_reader = thread::spawn(move || read_stream(stdout, max_stdout));
    let stderr_reader = thread::spawn(move || read_stream(stderr, max_stderr));
    let status = child.wait()?;
    let stdout = join_stream(stdout_reader, "stdout")?;
    let stderr = join_stream(stderr_reader, "stderr")?;
    Ok(GitOutput {
        status,
        stdout,
        stderr,
    })
}

fn read_stream(mut reader: impl Read, max_bytes: usize) -> std::io::Result<StreamCapture> {
    let mut retained = Vec::with_capacity(max_bytes.min(8192));
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    let mut truncated = false;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            return Ok(StreamCapture {
                retained,
                sha256: format!("{:x}", hasher.finalize()),
                truncated,
            });
        }
        hasher.update(&buffer[..count]);
        let remaining = max_bytes.saturating_sub(retained.len());
        retained.extend_from_slice(&buffer[..count.min(remaining)]);
        truncated |= count > remaining;
    }
}

fn join_stream(
    reader: thread::JoinHandle<std::io::Result<StreamCapture>>,
    stream: &str,
) -> PreparationResult<StreamCapture> {
    reader
        .join()
        .map_err(|_| PreparationError::Git(format!("Git {stream} reader panicked")))?
        .map_err(PreparationError::Io)
}

fn ensure_success(output: GitOutput, operation: &str) -> PreparationResult<GitOutput> {
    if output.status.success() {
        return Ok(output);
    }
    Err(PreparationError::Git(format!(
        "{operation}: {}",
        String::from_utf8_lossy(&output.stderr.retained).trim()
    )))
}

fn create_and_canonicalize(path: &Path) -> PreparationResult<PathBuf> {
    fs::create_dir_all(path)?;
    Ok(fs::canonicalize(path)?)
}

fn atomic_write_json(path: &Path, value: &impl Serialize) -> PreparationResult<()> {
    let parent = path.parent().ok_or_else(|| PreparationError::InvalidPath {
        path: path.to_path_buf(),
        reason: "path has no parent".into(),
    })?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".{}.tmp", std::process::id()));
    fs::write(&temporary, serde_json::to_vec_pretty(value)?)?;
    fs::rename(temporary, path)?;
    Ok(())
}

fn path_to_str(path: &Path) -> PreparationResult<&str> {
    path.to_str().ok_or_else(|| PreparationError::InvalidPath {
        path: path.to_path_buf(),
        reason: "path is not UTF-8".into(),
    })
}
