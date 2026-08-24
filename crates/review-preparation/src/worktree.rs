use crate::{PreparationError, PreparationResult};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
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
    pub source_status_before: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityDiagnostics {
    pub repository: PathBuf,
    pub worktree: PathBuf,
    pub expected_head: String,
    pub observed_head: Option<String>,
    pub source_refs_before: String,
    pub source_refs_after: String,
    pub source_status_before: String,
    pub source_status_after: String,
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
        let scratch_root = create_and_canonicalize(&scratch_root)?;
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
            verify_existing_worktree(&path, &worktrees_root, head_sha)?;
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
        verify_existing_worktree(&path, &worktrees_root, head_sha)?;
        let refs_after = refs_snapshot(&self.repository)?;
        if refs_after != refs_before {
            return Err(PreparationError::Worktree(
                "detached worktree creation changed source refs".into(),
            ));
        }
        let status_after = status_snapshot(&self.repository)?;
        if status_after != status_before {
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
            source_refs_before: refs_before,
            source_status_before: status_before,
        })
    }

    pub fn capture_integrity(
        &self,
        worktree: &PreparedWorktree,
    ) -> PreparationResult<IntegrityDiagnostics> {
        verify_worktree_owner(worktree)?;
        let source_refs_after = refs_snapshot(&worktree.repository)?;
        let source_status_after = status_snapshot(&worktree.repository)?;
        let observed_head = git_text(&worktree.path, &["rev-parse", "HEAD"]).ok();
        let worktree_status = git_text(
            &worktree.path,
            &["status", "--porcelain=v1", "--untracked-files=all"],
        )?;
        let (tracked_diff, tracked_truncated) = bounded_git_text(
            &worktree.path,
            &["diff", "--binary", "--no-ext-diff"],
            MAX_DIAGNOSTIC_BYTES,
        )?;
        let (staged_diff, staged_truncated) = bounded_git_text(
            &worktree.path,
            &["diff", "--cached", "--binary", "--no-ext-diff"],
            MAX_DIAGNOSTIC_BYTES,
        )?;
        Ok(IntegrityDiagnostics {
            repository: worktree.repository.clone(),
            worktree: worktree.path.clone(),
            expected_head: worktree.head_sha.clone(),
            observed_head: observed_head.clone(),
            source_refs_before: worktree.source_refs_before.clone(),
            source_refs_after: source_refs_after.clone(),
            source_status_before: worktree.source_status_before.clone(),
            source_status_after: source_status_after.clone(),
            worktree_clean: worktree_status.is_empty()
                && tracked_diff.is_empty()
                && staged_diff.is_empty(),
            worktree_status,
            tracked_diff,
            staged_diff,
            diagnostic_truncated: tracked_truncated || staged_truncated,
            refs_unchanged: source_refs_after == worktree.source_refs_before,
            source_status_unchanged: source_status_after == worktree.source_status_before,
            detached_head_unchanged: observed_head.as_deref() == Some(worktree.head_sha.as_str())
                && is_detached(&worktree.path)?,
        })
    }

    pub fn persist_integrity(
        &self,
        worktree: &PreparedWorktree,
        diagnostics: IntegrityDiagnostics,
    ) -> PreparationResult<PathBuf> {
        verify_worktree_owner(worktree)?;
        if diagnostics.repository != worktree.repository
            || diagnostics.worktree != worktree.path
            || diagnostics.expected_head != worktree.head_sha
        {
            return Err(PreparationError::Worktree(
                "integrity diagnostics do not match prepared worktree".into(),
            ));
        }
        let record = CleanupRecord {
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
        let diagnostic_root = fs::canonicalize(self.scratch_root.join("diagnostics"))?;
        let record_path = fs::canonicalize(record_path)?;
        if !record_path.starts_with(&diagnostic_root) {
            return Err(PreparationError::PathEscape {
                path: record_path,
                root: diagnostic_root,
            });
        }
        let mut record: CleanupRecord = serde_json::from_slice(&fs::read(&record_path)?)?;
        if fs::canonicalize(&record.diagnostic_root)? != diagnostic_root {
            return Err(PreparationError::Worktree(
                "cleanup record names a different diagnostic root".into(),
            ));
        }
        let worktrees_root = fs::canonicalize(&record.scratch_worktrees_root)?;
        if record.cleaned {
            if record.diagnostics.worktree.exists() {
                return Err(PreparationError::Worktree(
                    "cleanup record is complete but worktree still exists".into(),
                ));
            }
            return Ok(record);
        }
        if record.diagnostics.worktree.exists() {
            let worktree = fs::canonicalize(&record.diagnostics.worktree)?;
            if !worktree.starts_with(&worktrees_root) || worktree == worktrees_root {
                return Err(PreparationError::PathEscape {
                    path: worktree,
                    root: worktrees_root,
                });
            }
            let observed = git_text(&worktree, &["rev-parse", "HEAD"])?;
            if observed != record.diagnostics.expected_head || !is_detached(&worktree)? {
                return Err(PreparationError::Worktree(
                    "cleanup target identity no longer matches diagnostics".into(),
                ));
            }
            let output = git(
                &record.diagnostics.repository,
                &["worktree", "remove", "--force", path_to_str(&worktree)?],
            )?;
            ensure_success(output, "git worktree remove")?;
        }
        if record.diagnostics.worktree.exists() {
            return Err(PreparationError::Worktree(
                "verified worktree still exists after cleanup".into(),
            ));
        }
        record.cleaned = true;
        atomic_write_json(&record_path, &record)?;
        Ok(record)
    }
}

fn verify_worktree_owner(worktree: &PreparedWorktree) -> PreparationResult<()> {
    let path = fs::canonicalize(&worktree.path)?;
    let root = fs::canonicalize(&worktree.scratch_worktrees_root)?;
    if path == root || !path.starts_with(&root) {
        return Err(PreparationError::PathEscape { path, root });
    }
    if fs::canonicalize(&worktree.repository)? != worktree.repository {
        return Err(PreparationError::Worktree(
            "repository identity changed".into(),
        ));
    }
    Ok(())
}

fn verify_existing_worktree(path: &Path, root: &Path, expected: &str) -> PreparationResult<()> {
    let path = fs::canonicalize(path)?;
    if path == root || !path.starts_with(root) {
        return Err(PreparationError::PathEscape {
            path,
            root: root.to_path_buf(),
        });
    }
    if git_text(&path, &["rev-parse", "HEAD"])? != expected || !is_detached(&path)? {
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

fn refs_snapshot(repository: &Path) -> PreparationResult<String> {
    git_text(
        repository,
        &["for-each-ref", "--format=%(refname) %(objectname)"],
    )
}

fn status_snapshot(repository: &Path) -> PreparationResult<String> {
    git_text(
        repository,
        &["status", "--porcelain=v1", "--untracked-files=no"],
    )
}

fn bounded_git_text(
    path: &Path,
    arguments: &[&str],
    max_bytes: usize,
) -> PreparationResult<(String, bool)> {
    let output = git(path, arguments)?;
    let output = ensure_success(output, "Git diagnostic")?;
    let truncated = output.stdout.len() > max_bytes;
    let bytes = &output.stdout[..output.stdout.len().min(max_bytes)];
    Ok((String::from_utf8_lossy(bytes).into_owned(), truncated))
}

fn git_text(path: &Path, arguments: &[&str]) -> PreparationResult<String> {
    let output = git(path, arguments)?;
    let output = ensure_success(output, "Git query")?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn git(path: &Path, arguments: &[&str]) -> PreparationResult<Output> {
    Ok(Command::new("git")
        .arg("-C")
        .arg(path)
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .output()?)
}

fn ensure_success(output: Output, operation: &str) -> PreparationResult<Output> {
    if output.status.success() {
        return Ok(output);
    }
    Err(PreparationError::Git(format!(
        "{operation}: {}",
        String::from_utf8_lossy(&output.stderr).trim()
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
