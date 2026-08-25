use review_preparation::{
    AttachmentInput, CompletionOutcome, ExternalDecision, GeneralArtifactKind,
    GeneralCompletionSubmission, GeneralFinalizer, GeneralProfile, GeneralTaskManifest,
    GeneralTaskPreparer, PermissionRequest, PreparationError, GENERAL_TASK_SCHEMA,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::TempDir;

struct Fixture {
    _temp: TempDir,
    repository: PathBuf,
    attachments: PathBuf,
    head: String,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let repository = temp.path().join("repository");
        let attachments = temp.path().join("attachments");
        fs::create_dir_all(repository.join("src")).unwrap();
        fs::create_dir_all(&attachments).unwrap();
        fs::write(
            repository.join("src/lib.rs"),
            "pub fn value() -> u8 { 1 }\n",
        )
        .unwrap();
        fs::write(repository.join("README.md"), "fixture\n").unwrap();
        fs::write(attachments.join("notes.txt"), "owner context\n").unwrap();
        git(&repository, &["init"]);
        git(&repository, &["config", "user.name", "General Test"]);
        git(
            &repository,
            &["config", "user.email", "general@example.invalid"],
        );
        git(&repository, &["add", "src/lib.rs", "README.md"]);
        git(&repository, &["commit", "-m", "fixture"]);
        let head = git(&repository, &["rev-parse", "HEAD"]);
        Self {
            _temp: temp,
            repository: fs::canonicalize(repository).unwrap(),
            attachments: fs::canonicalize(attachments).unwrap(),
            head,
        }
    }
    fn manifest(&self, profile: GeneralProfile) -> GeneralTaskManifest {
        GeneralTaskManifest {
            schema: GENERAL_TASK_SCHEMA.into(),
            task_id: "task-1".into(),
            repository: self.repository.clone(),
            base_ref: self.head.clone(),
            profile,
            prompt: "Inspect and produce the bounded result.".into(),
            repo_context: vec!["README.md".into()],
            attachments: vec![AttachmentInput {
                logical_name: "notes".into(),
                source_path: self.attachments.join("notes.txt"),
                allowed_root: self.attachments.clone(),
            }],
            write_manifest: if profile == GeneralProfile::ImplementationWorktree {
                vec!["src".into()]
            } else {
                vec![]
            },
            scratch_root: ".agent-work/scratch/general".into(),
            artifact_root: ".agent-work/artifacts/task-1".into(),
            budget: None,
            validation_commands: BTreeMap::new(),
            retain_partial: false,
            idempotency_key: format!("task-1-{profile:?}"),
        }
    }
    fn preparer(&self) -> GeneralTaskPreparer {
        GeneralTaskPreparer::new(vec![self.attachments.clone()]).unwrap()
    }
}

#[test]
fn preparation_snapshots_immutable_context_and_uses_profile_defaults() {
    let f = Fixture::new();
    let prepared = f
        .preparer()
        .prepare(&f.manifest(GeneralProfile::AnalysisReadonly))
        .unwrap();
    assert_eq!(
        prepared.effective_budget,
        GeneralProfile::AnalysisReadonly.default_budget()
    );
    assert!(prepared
        .worktree
        .path
        .starts_with(&prepared.worktree.scratch_worktrees_root));
    assert_ne!(prepared.worktree.path, f.repository);
    let public = prepared.attachments[0].public_projection();
    assert_eq!(public.logical_name, "notes");
    assert_eq!(public.size_bytes, 14);
    assert_eq!(
        public.sha256,
        format!("{:x}", Sha256::digest(b"owner context\n"))
    );
    fs::write(f.attachments.join("notes.txt"), "mutated").unwrap();
    assert_eq!(
        fs::read(&prepared.attachments[0].prepared_path).unwrap(),
        b"owner context\n"
    );
    prepared.validate_digest().unwrap();
}

#[test]
fn owner_roots_symlinks_secret_types_and_budget_fail_closed() {
    let f = Fixture::new();
    let other = f._temp.path().join("other");
    fs::create_dir_all(&other).unwrap();
    fs::write(other.join("x.txt"), "x").unwrap();
    let mut m = f.manifest(GeneralProfile::AnalysisReadonly);
    m.attachments[0] = AttachmentInput {
        logical_name: "x".into(),
        source_path: other.join("x.txt"),
        allowed_root: other.clone(),
    };
    assert!(matches!(
        f.preparer().prepare(&m),
        Err(PreparationError::Policy(_))
    ));
    symlink(
        f.attachments.join("notes.txt"),
        f.attachments.join("linked.txt"),
    )
    .unwrap();
    m = f.manifest(GeneralProfile::AnalysisReadonly);
    m.attachments[0].source_path = f.attachments.join("linked.txt");
    assert!(matches!(
        f.preparer().prepare(&m),
        Err(PreparationError::PathEscape { .. }) | Err(PreparationError::SymlinkInput(_))
    ));
    fs::write(f.attachments.join("identity.pem"), "secret").unwrap();
    m = f.manifest(GeneralProfile::AnalysisReadonly);
    m.attachments[0].source_path = f.attachments.join("identity.pem");
    assert!(matches!(
        f.preparer().prepare(&m),
        Err(PreparationError::CredentialInput(_))
    ));
    fs::write(f.attachments.join(".env"), "TOKEN=value").unwrap();
    m = f.manifest(GeneralProfile::AnalysisReadonly);
    m.attachments[0].source_path = f.attachments.join(".env");
    assert!(matches!(
        f.preparer().prepare(&m),
        Err(PreparationError::CredentialInput(_))
    ));
    m = f.manifest(GeneralProfile::AnalysisReadonly);
    let mut budget = GeneralProfile::AnalysisReadonly.default_budget();
    budget.max_turns = 0;
    m.budget = Some(budget);
    assert!(matches!(
        f.preparer().prepare(&m),
        Err(PreparationError::InvalidManifest(_))
    ));
    m = f.manifest(GeneralProfile::AnalysisReadonly);
    let mut budget = GeneralProfile::AnalysisReadonly.default_budget();
    budget.wall_time_ms = 86_400_001;
    m.budget = Some(budget);
    assert!(matches!(
        f.preparer().prepare(&m),
        Err(PreparationError::InvalidManifest(_))
    ));
}

#[test]
fn failed_preparation_reaps_worktree_and_profile_set_is_closed() {
    let f = Fixture::new();
    let before = git(&f.repository, &["worktree", "list", "--porcelain"]);
    let mut manifest = f.manifest(GeneralProfile::TestRunner);
    manifest.validation_commands.insert(
        "bad".into(),
        review_preparation::ValidationCommand {
            program: "/definitely/missing".into(),
            args: vec![],
            cwd: ".".into(),
            timeout_ms: 100,
            max_output_bytes: 100,
        },
    );
    assert!(f.preparer().prepare(&manifest).is_err());
    assert_eq!(
        git(&f.repository, &["worktree", "list", "--porcelain"]),
        before
    );
    assert!(serde_json::from_str::<GeneralProfile>("\"review_readonly\"").is_err());
    assert_eq!(
        serde_json::to_string(&GeneralProfile::TestRunner).unwrap(),
        "\"test_runner\""
    );
}

#[test]
fn profile_policy_allows_only_frozen_implementation_paths() {
    let f = Fixture::new();
    let readonly = f
        .preparer()
        .prepare(&f.manifest(GeneralProfile::AnalysisReadonly))
        .unwrap();
    let readonly_policy = readonly.launcher().unwrap();
    assert!(
        !readonly_policy
            .decide(
                &PermissionRequest::Write(readonly.worktree.path.join("src/lib.rs")),
                ExternalDecision::Allow
            )
            .allowed
    );
    let implementation = f
        .preparer()
        .prepare(&f.manifest(GeneralProfile::ImplementationWorktree))
        .unwrap();
    let policy = implementation.launcher().unwrap();
    assert!(
        policy
            .decide(
                &PermissionRequest::Edit(implementation.worktree.path.join("src/lib.rs")),
                ExternalDecision::Allow
            )
            .allowed
    );
    assert!(
        !policy
            .decide(
                &PermissionRequest::Write(implementation.worktree.path.join("README.md")),
                ExternalDecision::Allow
            )
            .allowed
    );
    assert!(
        !policy
            .decide(
                &PermissionRequest::Edit(implementation.worktree.path.join(".git")),
                ExternalDecision::Allow
            )
            .allowed
    );
    assert!(
        !policy
            .decide(
                &PermissionRequest::Write(implementation.worktree.path.join(".gitmodules")),
                ExternalDecision::Allow
            )
            .allowed
    );
    assert!(
        !policy
            .decide(
                &PermissionRequest::InternalReviewLedger,
                ExternalDecision::Allow
            )
            .allowed
    );
}

#[test]
fn daemon_finalizer_commits_detached_patch_without_moving_source_refs() {
    let f = Fixture::new();
    let source_head = git(&f.repository, &["rev-parse", "HEAD"]);
    let source_status = git(
        &f.repository,
        &["status", "--porcelain=v1", "--untracked-files=no"],
    );
    let prepared = f
        .preparer()
        .prepare(&f.manifest(GeneralProfile::ImplementationWorktree))
        .unwrap();
    fs::write(
        prepared.worktree.path.join("src/lib.rs"),
        "pub fn value() -> u8 { 2 }\n",
    )
    .unwrap();
    let completion = GeneralFinalizer::finalize_submission(
        &prepared,
        &GeneralCompletionSubmission {
            requested_outcome: CompletionOutcome::Succeeded,
            summary: "implemented".into(),
            checks: vec!["unit".into()],
            residual_gaps: vec![],
        },
    );
    assert_eq!(completion.outcome, CompletionOutcome::Succeeded);
    assert!(completion.cleaned);
    let artifact = completion.artifact.unwrap();
    assert!(!artifact.partial);
    assert_eq!(artifact.kind, GeneralArtifactKind::ChangesPatch);
    assert!(!prepared.worktree.path.exists());
    let patch = fs::read(prepared.artifact_root.join("changes.patch")).unwrap();
    assert!(String::from_utf8_lossy(&patch).contains("value() -> u8 { 2 }"));
    assert_eq!(artifact.sha256, format!("{:x}", Sha256::digest(&patch)));
    assert_ne!(artifact.head_commit.as_deref(), Some(f.head.as_str()));
    assert_eq!(git(&f.repository, &["rev-parse", "HEAD"]), source_head);
    assert!(completion.cleaned);
    assert_eq!(
        git(
            &f.repository,
            &["status", "--porcelain=v1", "--untracked-files=no"]
        ),
        source_status
    );
}

#[test]
fn readonly_change_and_result_limit_become_result_invalid() {
    let f = Fixture::new();
    let prepared = f
        .preparer()
        .prepare(&f.manifest(GeneralProfile::AnalysisReadonly))
        .unwrap();
    fs::write(prepared.worktree.path.join("README.md"), "changed\n").unwrap();
    let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::Succeeded);
    assert_eq!(completion.outcome, CompletionOutcome::ResultInvalid);
    assert_eq!(
        completion.reason_code.as_deref(),
        Some("READONLY_PROFILE_MODIFIED_TRACKED_STATE")
    );
    assert!(completion.cleaned);
    let f = Fixture::new();
    let mut m = f.manifest(GeneralProfile::AnalysisReadonly);
    let mut budget = GeneralProfile::AnalysisReadonly.default_budget();
    budget.max_result_bytes = 1;
    m.budget = Some(budget);
    let prepared = f.preparer().prepare(&m).unwrap();
    let completion = GeneralFinalizer::finalize_submission(
        &prepared,
        &GeneralCompletionSubmission {
            requested_outcome: CompletionOutcome::Succeeded,
            summary: "too long".into(),
            checks: vec![],
            residual_gaps: vec![],
        },
    );
    assert_eq!(completion.reason_code.as_deref(), Some("RESULT_TOO_LARGE"));
    assert!(completion.cleaned);
}

#[test]
fn blocked_without_changes_cleans_and_has_no_partial_artifact() {
    let f = Fixture::new();
    let prepared = f
        .preparer()
        .prepare(&f.manifest(GeneralProfile::ImplementationWorktree))
        .unwrap();
    let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::Blocked);
    assert_eq!(completion.outcome, CompletionOutcome::Blocked);
    assert!(completion.cleaned);
    assert!(completion.artifact.is_none());
    assert!(!prepared.worktree.path.exists());
}

#[test]
fn null_budget_and_idempotency_conflicts_are_rejected() {
    let f = Fixture::new();
    let value = serde_json::to_value(f.manifest(GeneralProfile::AnalysisReadonly)).unwrap();
    let mut null_budget = value.clone();
    null_budget["budget"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<GeneralTaskManifest>(null_budget).is_err());
    let mut omitted = value;
    omitted.as_object_mut().unwrap().remove("budget");
    assert!(serde_json::from_value::<GeneralTaskManifest>(omitted).is_ok());

    let preparer = f.preparer();
    let manifest = f.manifest(GeneralProfile::AnalysisReadonly);
    let first = preparer.prepare(&manifest).unwrap();
    assert_eq!(
        preparer.prepare(&manifest).unwrap().prepared_sha256,
        first.prepared_sha256
    );
    let mut changed = manifest;
    changed.prompt = "different prompt".into();
    assert!(matches!(
        preparer.prepare(&changed),
        Err(PreparationError::IdempotencyConflict(_))
    ));
    assert_eq!(
        fs::read_to_string(first.prompt_path).unwrap(),
        "Inspect and produce the bounded result."
    );
}

#[test]
fn partial_patch_retention_follows_submission_opt_in() {
    let f = Fixture::new();
    let prepared = f
        .preparer()
        .prepare(&f.manifest(GeneralProfile::ImplementationWorktree))
        .unwrap();
    fs::write(
        prepared.worktree.path.join("src/lib.rs"),
        "pub fn value() -> u8 { 3 }\n",
    )
    .unwrap();
    let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::Failed);
    assert_eq!(completion.outcome, CompletionOutcome::Failed);
    assert!(completion.artifact.is_none());
    assert!(completion.cleaned);

    let f = Fixture::new();
    let mut manifest = f.manifest(GeneralProfile::ImplementationWorktree);
    manifest.retain_partial = true;
    let prepared = f.preparer().prepare(&manifest).unwrap();
    fs::write(
        prepared.worktree.path.join("src/lib.rs"),
        "pub fn value() -> u8 { 4 }\n",
    )
    .unwrap();
    let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::TimedOut);
    let artifact = completion.artifact.unwrap();
    assert!(artifact.partial);
    assert_eq!(artifact.kind, GeneralArtifactKind::ChangesPatch);
    assert!(completion.cleaned);
}

#[test]
fn artifact_limit_failure_is_result_invalid_and_reaped() {
    let f = Fixture::new();
    let mut manifest = f.manifest(GeneralProfile::ImplementationWorktree);
    let mut budget = GeneralProfile::ImplementationWorktree.default_budget();
    budget.max_artifact_bytes = 1;
    manifest.budget = Some(budget);
    let prepared = f.preparer().prepare(&manifest).unwrap();
    fs::write(
        prepared.worktree.path.join("src/lib.rs"),
        "pub fn value() -> u8 { 9 }\n",
    )
    .unwrap();
    let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::Succeeded);
    assert_eq!(completion.outcome, CompletionOutcome::ResultInvalid);
    assert_eq!(
        completion.reason_code.as_deref(),
        Some("ARTIFACT_LIMIT_EXCEEDED")
    );
    assert!(completion.cleaned);
    assert!(!prepared.worktree.path.exists());
}

fn git(path: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(path)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {:?}: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().into()
}
