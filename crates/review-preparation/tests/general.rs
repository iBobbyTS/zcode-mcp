use review_preparation::{
    AttachmentInput, CompletionOutcome, ExternalDecision, GeneralArtifactIntent,
    GeneralArtifactKind, GeneralCompletion, GeneralCompletionSubmission, GeneralFinalizer,
    GeneralNamedCommand, GeneralProfile, GeneralTaskManifest, GeneralTaskPreparer,
    PermissionRequest, PolicyCapabilities, PolicyLauncher, PreparationError, ValidationCommand,
    GENERAL_TASK_SCHEMA,
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
    assert!(
        fs::read_dir(f.repository.join(".agent-work/scratch/general"))
            .unwrap()
            .next()
            .is_none()
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
                &PermissionRequest::Write(implementation.artifact_root.join("leak.txt")),
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
fn internal_general_completion_permission_is_exact_and_general_profile_scoped() {
    const TOOL: &str = "mcp__general-completion__zcode_general_complete";
    let f = Fixture::new();
    for (profile, tracked_write_allowed) in [
        (GeneralProfile::AnalysisReadonly, false),
        (GeneralProfile::TestRunner, false),
        (GeneralProfile::ImplementationWorktree, true),
    ] {
        let prepared = f.preparer().prepare(&f.manifest(profile)).unwrap();
        let launcher = prepared.launcher().unwrap();
        let request = serde_json::json!({"toolName":TOOL,"input":{}});

        let allowed = launcher.decide_zcode_permission(&request, ExternalDecision::Allow);
        assert!(allowed.allowed, "{profile:?}: {allowed:?}");
        assert_eq!(allowed.reason, "allowed_by_bounded_policy");
        assert!(
            launcher
                .decide(
                    &PermissionRequest::InternalGeneralCompletion,
                    ExternalDecision::Allow,
                )
                .allowed
        );
        let denied = launcher.decide_zcode_permission(&request, ExternalDecision::Deny);
        assert!(!denied.allowed);
        assert_eq!(denied.reason, "external_policy_denied");

        for near_miss in [
            "MCP__GENERAL-COMPLETION__ZCODE_GENERAL_COMPLETE",
            "mcp__general-completion__ZCode_general_complete",
            "mcp__general-completion__zcode_general_complete_extra",
            "prefix_mcp__general-completion__zcode_general_complete",
        ] {
            let decision = launcher.decide_zcode_permission(
                &serde_json::json!({"toolName":near_miss,"input":{}}),
                ExternalDecision::Allow,
            );
            assert!(!decision.allowed, "{profile:?}: {near_miss}");
            assert_eq!(decision.reason, "permission_request_unrecognized");
        }

        let review_ledger = launcher.decide_zcode_permission(
            &serde_json::json!({
                "toolName":"mcp__review-ledger__review_finalize",
                "input":{}
            }),
            ExternalDecision::Allow,
        );
        assert!(!review_ledger.allowed);
        assert_eq!(
            review_ledger.reason,
            "review_ledger_unavailable_for_general_task"
        );
        for unchanged_unknown in ["Bash", "mcp__other__zcode_general_complete"] {
            let decision = launcher.decide_zcode_permission(
                &serde_json::json!({"toolName":unchanged_unknown,"input":{}}),
                ExternalDecision::Allow,
            );
            assert!(!decision.allowed);
            assert_eq!(decision.reason, "permission_request_unrecognized");
        }
        let write = launcher.decide_zcode_permission(
            &serde_json::json!({
                "toolName":"write",
                "input":{"path":prepared.worktree.path.join("src/lib.rs")}
            }),
            ExternalDecision::Allow,
        );
        assert_eq!(write.allowed, tracked_write_allowed, "{profile:?}");
        let git = launcher.decide_zcode_permission(
            &serde_json::json!({"toolName":"git_ref_mutation","input":{}}),
            ExternalDecision::Allow,
        );
        assert!(!git.allowed);
        assert_eq!(git.reason, "git_ref_mutation_denied");
        let network = launcher.decide_zcode_permission(
            &serde_json::json!({
                "toolName":"network",
                "input":{"target":"https://example.invalid"}
            }),
            ExternalDecision::Allow,
        );
        assert!(!network.allowed);
        assert_eq!(network.reason, "network_not_enforced_and_request_denied");
        let execute = launcher.decide_zcode_permission(
            &serde_json::json!({
                "toolName":"execute",
                "input":{"program":"/bin/sh","args":[],"cwd":prepared.worktree.path}
            }),
            ExternalDecision::Allow,
        );
        assert!(!execute.allowed);
        assert_eq!(execute.reason, "command_not_allowlisted");
    }
}

#[test]
fn internal_named_check_permission_is_exact_selected_and_profile_scoped() {
    const TOOL: &str = "mcp__general-completion__zcode_general_run_check";
    let f = Fixture::new();
    for (profile, readonly_safe, expected) in [
        (GeneralProfile::AnalysisReadonly, true, true),
        (GeneralProfile::AnalysisReadonly, false, false),
        (GeneralProfile::TestRunner, false, true),
        (GeneralProfile::ImplementationWorktree, false, true),
    ] {
        let manifest = f.manifest(profile);
        let named = BTreeMap::from([(
            "unit".into(),
            GeneralNamedCommand {
                command: ValidationCommand {
                    program: PathBuf::from("/usr/bin/true"),
                    args: Vec::new(),
                    cwd: ".".into(),
                    timeout_ms: 1_000,
                    max_output_bytes: 1_024,
                },
                readonly_safe,
            },
        )]);
        let prepared = f
            .preparer()
            .prepare_named_submission(&manifest, &named)
            .unwrap();
        let launcher = prepared.launcher().unwrap();
        let request = serde_json::json!({
            "toolName":TOOL,
            "input":{"command_id":"unit"}
        });
        assert_eq!(
            launcher
                .decide_zcode_permission(&request, ExternalDecision::Allow)
                .allowed,
            expected,
            "{profile:?} readonly_safe={readonly_safe}"
        );
        assert!(
            !launcher
                .decide_zcode_permission(&request, ExternalDecision::Deny)
                .allowed
        );
        for denied in [
            serde_json::json!({"toolName":TOOL,"input":{"command_id":"unknown"}}),
            serde_json::json!({"toolName":TOOL,"input":{"command_id":"unit","args":[]}}),
            serde_json::json!({"toolName":"mcp__general-completion__zcode_general_run_check_extra","input":{"command_id":"unit"}}),
            serde_json::json!({"toolName":"mcp__general-completion__Zcode_general_run_check","input":{"command_id":"unit"}}),
        ] {
            assert!(
                !launcher
                    .decide_zcode_permission(&denied, ExternalDecision::Allow)
                    .allowed
            );
        }
        if expected {
            let output = launcher.run("unit").unwrap();
            assert_eq!(output.status_code, Some(0));
            assert!(!output.timed_out);
            assert!(!output.cancelled);
        }
        let review = PolicyLauncher::new(
            prepared.worktree.path.clone(),
            prepared.scratch_root.clone(),
            prepared.artifact_root.join("result.json"),
            vec![prepared.prompt_path.clone()],
            prepared.validation_commands.clone(),
            false,
            PolicyCapabilities::default(),
        )
        .unwrap();
        assert!(
            !review
                .decide_zcode_permission(&request, ExternalDecision::Allow)
                .allowed
        );
        let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::Blocked);
        assert!(completion.cleaned);
    }
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
            artifact_intents: vec![],
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
    assert_eq!(artifact.base_sha, f.head);
    assert_eq!(artifact.changed_paths, ["src/lib.rs"]);
    assert!(artifact
        .diff_stat
        .as_deref()
        .is_some_and(|stat| stat.contains("src/lib.rs")));
    let expected_patch = Command::new("git")
        .current_dir(&f.repository)
        .args([
            "diff",
            "--binary",
            "--no-ext-diff",
            "--no-textconv",
            &artifact.base_sha,
            artifact.head_commit.as_deref().unwrap(),
        ])
        .output()
        .unwrap()
        .stdout;
    assert_eq!(patch, expected_patch);
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
fn implementation_context_covered_by_write_manifest_can_finalize() {
    let f = Fixture::new();
    let mut manifest = f.manifest(GeneralProfile::ImplementationWorktree);
    manifest.repo_context = vec!["src/lib.rs".into()];
    manifest.write_manifest = vec!["src".into()];
    let prepared = f.preparer().prepare(&manifest).unwrap();
    fs::write(
        prepared.worktree.path.join("src/lib.rs"),
        "pub fn value() -> u8 { 22 }\n",
    )
    .unwrap();

    let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::Succeeded);

    assert_eq!(completion.outcome, CompletionOutcome::Succeeded);
    assert!(completion.cleaned);
    let artifact = completion.artifact.unwrap();
    assert_eq!(artifact.changed_paths, ["src/lib.rs"]);
    let head = artifact.head_commit.as_deref().unwrap();
    assert_eq!(git(&f.repository, &["cat-file", "-t", head]), "commit");
    assert_eq!(
        git(&f.repository, &["rev-list", "--parents", "-n", "1", head]),
        format!("{head} {}", artifact.base_sha)
    );
    let patch = fs::read(prepared.artifact_root.join("changes.patch")).unwrap();
    assert!(String::from_utf8_lossy(&patch).contains("value() -> u8 { 22 }"));
}

#[test]
fn implementation_context_outside_write_manifest_remains_immutable() {
    let f = Fixture::new();
    let prepared = f
        .preparer()
        .prepare(&f.manifest(GeneralProfile::ImplementationWorktree))
        .unwrap();
    fs::write(
        prepared.worktree.path.join("README.md"),
        "changed non-writable context\n",
    )
    .unwrap();

    let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::Succeeded);

    assert_eq!(completion.outcome, CompletionOutcome::ResultInvalid);
    assert_eq!(
        completion.reason_code.as_deref(),
        Some("PREPARED_CONTENT_INVALID")
    );
    assert!(completion.cleaned);
}

#[test]
fn readonly_change_and_result_limit_become_result_invalid() {
    let f = Fixture::new();
    let prepared = f
        .preparer()
        .prepare(&f.manifest(GeneralProfile::AnalysisReadonly))
        .unwrap();
    fs::write(
        prepared.worktree.path.join("src/lib.rs"),
        "pub fn value() -> u8 { 8 }\n",
    )
    .unwrap();
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
            artifact_intents: vec![],
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
    assert!(first.prompt_path.exists());
    let compatible = preparer
        .prepare(&f.manifest(GeneralProfile::AnalysisReadonly))
        .unwrap();
    assert_eq!(compatible.prepared_sha256, first.prepared_sha256);
    assert!(compatible.worktree.path.exists());
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

#[test]
fn context_uses_detached_base_and_prepared_bytes_are_reverified() {
    let mut f = Fixture::new();
    fs::write(f.repository.join("README.md"), vec![b'x'; 4096]).unwrap();
    git(&f.repository, &["add", "README.md"]);
    git(&f.repository, &["commit", "-m", "large base context"]);
    f.head = git(&f.repository, &["rev-parse", "HEAD"]);
    fs::write(f.repository.join("README.md"), "small source drift\n").unwrap();
    let mut manifest = f.manifest(GeneralProfile::AnalysisReadonly);
    let mut budget = GeneralProfile::AnalysisReadonly.default_budget();
    budget.max_context_bytes = 512;
    manifest.budget = Some(budget);
    assert!(matches!(
        f.preparer().prepare(&manifest),
        Err(PreparationError::InvalidManifest(_))
    ));

    let f = Fixture::new();
    fs::write(f.repository.join("README.md"), vec![b'y'; 4096]).unwrap();
    let prepared = f
        .preparer()
        .prepare(&f.manifest(GeneralProfile::AnalysisReadonly))
        .unwrap();
    assert_eq!(prepared.context[0].size_bytes, b"fixture\n".len() as u64);
    fs::write(&prepared.prompt_path, "mutated prepared prompt").unwrap();
    assert!(prepared.launcher().is_err());
    let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::Succeeded);
    assert_eq!(
        completion.reason_code.as_deref(),
        Some("PREPARED_CONTENT_INVALID")
    );
    assert!(completion.cleaned);
    assert!(!prepared.prompt_path.exists());

    let f = Fixture::new();
    let prepared = f
        .preparer()
        .prepare(&f.manifest(GeneralProfile::AnalysisReadonly))
        .unwrap();
    fs::write(&prepared.attachments[0].prepared_path, "replacement").unwrap();
    assert!(prepared.launcher().is_err());
    assert_eq!(
        GeneralFinalizer::finalize(&prepared, CompletionOutcome::Succeeded)
            .reason_code
            .as_deref(),
        Some("PREPARED_CONTENT_INVALID")
    );

    let f = Fixture::new();
    let prepared = f
        .preparer()
        .prepare(&f.manifest(GeneralProfile::AnalysisReadonly))
        .unwrap();
    fs::write(
        prepared.worktree.path.join("README.md"),
        "changed context\n",
    )
    .unwrap();
    assert!(prepared.launcher().is_err());
    assert_eq!(
        GeneralFinalizer::finalize(&prepared, CompletionOutcome::Succeeded)
            .reason_code
            .as_deref(),
        Some("PREPARED_CONTENT_INVALID")
    );

    let mut f = Fixture::new();
    fs::remove_file(f.repository.join("README.md")).unwrap();
    symlink("src/lib.rs", f.repository.join("README.md")).unwrap();
    git(&f.repository, &["add", "README.md"]);
    git(&f.repository, &["commit", "-m", "symlink context"]);
    f.head = git(&f.repository, &["rev-parse", "HEAD"]);
    fs::remove_file(f.repository.join("README.md")).unwrap();
    fs::write(f.repository.join("README.md"), "regular source drift\n").unwrap();
    assert!(matches!(
        f.preparer()
            .prepare(&f.manifest(GeneralProfile::AnalysisReadonly)),
        Err(PreparationError::SymlinkInput(_))
    ));
}

#[test]
fn precreated_history_and_attached_head_are_rejected() {
    let f = Fixture::new();
    let prepared = f
        .preparer()
        .prepare(&f.manifest(GeneralProfile::ImplementationWorktree))
        .unwrap();
    fs::write(
        prepared.worktree.path.join("src/lib.rs"),
        "pub fn value() -> u8 { 5 }\n",
    )
    .unwrap();
    git(&prepared.worktree.path, &["add", "src/lib.rs"]);
    git(
        &prepared.worktree.path,
        &[
            "-c",
            "user.name=attacker",
            "-c",
            "user.email=attacker@example.invalid",
            "commit",
            "-m",
            "pre-created history",
        ],
    );
    let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::Succeeded);
    assert_eq!(
        completion.reason_code.as_deref(),
        Some("PREFINALIZATION_HEAD_INVALID")
    );
    assert!(completion.cleaned);

    let f = Fixture::new();
    git(&f.repository, &["branch", "spare", &f.head]);
    let prepared = f
        .preparer()
        .prepare(&f.manifest(GeneralProfile::ImplementationWorktree))
        .unwrap();
    git(&prepared.worktree.path, &["checkout", "spare"]);
    let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::Succeeded);
    assert_eq!(
        completion.reason_code.as_deref(),
        Some("PREFINALIZATION_HEAD_INVALID")
    );
    assert!(completion.cleaned);
}

#[test]
fn daemon_git_blocks_hooks_external_diff_and_gitlinks() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    let canary = f._temp.path().join("hook-canary");
    let hooks = f._temp.path().join("hooks");
    fs::create_dir_all(&hooks).unwrap();
    let hook = hooks.join("pre-commit");
    fs::write(
        &hook,
        format!("#!/bin/sh\nprintf hook > '{}'\n", canary.display()),
    )
    .unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
    git(
        &f.repository,
        &["config", "core.hooksPath", hooks.to_str().unwrap()],
    );
    git(&f.repository, &["config", "commit.gpgSign", "true"]);
    let fsmonitor_canary = f._temp.path().join("fsmonitor-canary");
    let fsmonitor = f._temp.path().join("fsmonitor");
    fs::write(
        &fsmonitor,
        format!(
            "#!/bin/sh\nprintf fsmonitor > '{}'\n",
            fsmonitor_canary.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&fsmonitor, fs::Permissions::from_mode(0o755)).unwrap();
    git(
        &f.repository,
        &["config", "core.fsmonitor", fsmonitor.to_str().unwrap()],
    );
    let _ = fs::remove_file(&fsmonitor_canary);
    assert!(!fsmonitor_canary.exists());
    let prepared = f
        .preparer()
        .prepare(&f.manifest(GeneralProfile::ImplementationWorktree))
        .unwrap();
    fs::write(
        prepared.worktree.path.join("src/lib.rs"),
        "pub fn value() -> u8 { 6 }\n",
    )
    .unwrap();
    let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::Succeeded);
    assert_eq!(completion.outcome, CompletionOutcome::ResultInvalid);
    assert_eq!(completion.reason_code.as_deref(), Some("UNSAFE_GIT_CONFIG"));
    assert!(!canary.exists());
    assert!(!fsmonitor_canary.exists());

    let f = Fixture::new();
    let diff_canary = f._temp.path().join("diff-canary");
    let script = f._temp.path().join("external-diff");
    fs::write(
        &script,
        format!("#!/bin/sh\nprintf diff > '{}'\n", diff_canary.display()),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    git(
        &f.repository,
        &["config", "diff.evil.command", script.to_str().unwrap()],
    );
    let prepared = f
        .preparer()
        .prepare(&f.manifest(GeneralProfile::ImplementationWorktree))
        .unwrap();
    fs::write(
        prepared.worktree.path.join("src/lib.rs"),
        "pub fn value() -> u8 { 7 }\n",
    )
    .unwrap();
    let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::Succeeded);
    assert_eq!(completion.reason_code.as_deref(), Some("UNSAFE_GIT_CONFIG"));
    assert!(!diff_canary.exists());

    let f = Fixture::new();
    let mut manifest = f.manifest(GeneralProfile::ImplementationWorktree);
    manifest.write_manifest = vec!["vendor".into()];
    let prepared = f.preparer().prepare(&manifest).unwrap();
    let nested = prepared.worktree.path.join("vendor/sub");
    fs::create_dir_all(&nested).unwrap();
    fs::write(nested.join("data.txt"), "nested").unwrap();
    git(&nested, &["init"]);
    git(&nested, &["add", "data.txt"]);
    git(
        &nested,
        &[
            "-c",
            "user.name=nested",
            "-c",
            "user.email=nested@example.invalid",
            "commit",
            "-m",
            "nested",
        ],
    );
    let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::Succeeded);
    assert_eq!(
        completion.reason_code.as_deref(),
        Some("GITLINK_CHANGE_DENIED")
    );
    assert!(completion.cleaned);
}

#[test]
fn ordinary_filename_containing_gitlink_mode_digits_is_allowed() {
    let f = Fixture::new();
    let prepared = f
        .preparer()
        .prepare(&f.manifest(GeneralProfile::ImplementationWorktree))
        .unwrap();
    fs::write(
        prepared.worktree.path.join("src/160000_notes.txt"),
        "ordinary blob\n",
    )
    .unwrap();

    let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::Succeeded);

    assert_eq!(completion.outcome, CompletionOutcome::Succeeded);
    assert!(completion.cleaned);
    assert_eq!(
        completion.artifact.unwrap().changed_paths,
        ["src/160000_notes.txt"]
    );
}

#[test]
fn result_metadata_and_declared_artifact_inventory_are_preserved() {
    let f = Fixture::new();
    let prepared = f
        .preparer()
        .prepare(&f.manifest(GeneralProfile::AnalysisReadonly))
        .unwrap();
    let output_root = prepared.scratch_root.join("agent-artifacts");
    fs::create_dir_all(&output_root).unwrap();
    let report = b"# Analysis\n\nBounded result.\n";
    fs::write(output_root.join("report.md"), report).unwrap();
    let report_hash = format!("{:x}", Sha256::digest(report));
    let completion = GeneralFinalizer::finalize_submission(
        &prepared,
        &GeneralCompletionSubmission {
            requested_outcome: CompletionOutcome::Succeeded,
            summary: "bounded summary".into(),
            checks: vec!["cargo check".into()],
            residual_gaps: vec!["owner decision".into()],
            artifact_intents: vec![GeneralArtifactIntent {
                kind: GeneralArtifactKind::ReportMarkdown,
                sha256: Some(report_hash.clone()),
                size_bytes: Some(report.len() as u64),
            }],
        },
    );
    assert_eq!(completion.outcome, CompletionOutcome::Succeeded);
    assert_eq!(completion.summary, "bounded summary");
    assert_eq!(completion.checks, ["cargo check"]);
    assert_eq!(completion.residual_gaps, ["owner decision"]);
    assert_eq!(completion.artifacts.len(), 1);
    assert_eq!(completion.artifacts[0].sha256, report_hash);
    assert_eq!(
        fs::read(prepared.artifact_root.join("report.md")).unwrap(),
        report
    );
    assert!(prepared
        .artifact_root
        .join("artifacts.manifest.json")
        .is_file());
    assert!(!prepared.prompt_path.exists());
    let job_root = prepared.worktree.scratch_worktrees_root.parent().unwrap();
    assert!(!job_root.exists());

    let replay = f
        .preparer()
        .prepare(&f.manifest(GeneralProfile::AnalysisReadonly))
        .unwrap();
    assert!(replay.worktree.path.exists());
    let replay_completion = GeneralFinalizer::finalize(&replay, CompletionOutcome::Blocked);
    assert_eq!(
        replay_completion.reason_code.as_deref(),
        Some("ARTIFACT_ROOT_NOT_EMPTY")
    );
    assert!(replay_completion.cleaned);

    let f = Fixture::new();
    let prepared = f
        .preparer()
        .prepare(&f.manifest(GeneralProfile::TestRunner))
        .unwrap();
    let output_root = prepared.scratch_root.join("agent-artifacts");
    fs::create_dir_all(&output_root).unwrap();
    fs::write(output_root.join("undeclared.txt"), "unexpected").unwrap();
    let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::Succeeded);
    assert_eq!(
        completion.reason_code.as_deref(),
        Some("UNDECLARED_ARTIFACT")
    );
    assert!(completion.cleaned);
}

#[test]
fn cleanup_failure_is_truthful_and_keeps_final_artifact_metadata() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    let prepared = f
        .preparer()
        .prepare(&f.manifest(GeneralProfile::ImplementationWorktree))
        .unwrap();
    fs::write(
        prepared.worktree.path.join("src/lib.rs"),
        "pub fn value() -> u8 { 10 }\n",
    )
    .unwrap();
    let job_root = prepared.worktree.scratch_worktrees_root.parent().unwrap();
    let owner_root = job_root.parent().unwrap();
    let original = fs::metadata(owner_root).unwrap().permissions();
    fs::set_permissions(owner_root, fs::Permissions::from_mode(0o500)).unwrap();
    let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::Succeeded);
    fs::set_permissions(owner_root, original).unwrap();
    assert_eq!(completion.outcome, CompletionOutcome::ResultInvalid);
    assert_eq!(
        completion.reason_code.as_deref(),
        Some("TASK_ROOT_CLEANUP_FAILED")
    );
    assert!(!completion.cleaned);
    assert!(completion.artifact.is_some());
    assert_eq!(completion.artifacts.len(), 1);
    assert!(prepared.artifact_root.join("changes.patch").is_file());

    let cleanup = GeneralFinalizer::retry_cleanup(&prepared, &completion);
    assert!(cleanup.cleaned);
    assert!(cleanup.artifact.is_some());
    assert!(prepared.artifact_root.join("changes.patch").is_file());
}

#[test]
fn missing_worktree_with_stale_git_registration_is_not_cleaned() {
    let f = Fixture::new();
    let prepared = f
        .preparer()
        .prepare(&f.manifest(GeneralProfile::AnalysisReadonly))
        .unwrap();
    fs::remove_dir_all(&prepared.worktree.path).unwrap();
    let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::Succeeded);
    assert_eq!(completion.outcome, CompletionOutcome::ResultInvalid);
    assert!(!completion.cleaned);
    assert_eq!(
        completion.reason_code.as_deref(),
        Some("PREPARED_CONTENT_INVALID")
    );
    assert!(git(&f.repository, &["worktree", "list", "--porcelain"]).contains("worktree"));
}

#[test]
fn preparation_failure_retries_cleanup_and_leaves_truthful_residue() {
    let f = Fixture::new();
    let mut manifest = f.manifest(GeneralProfile::TestRunner);
    manifest.validation_commands.insert(
        "missing".into(),
        review_preparation::ValidationCommand {
            program: "/definitely/missing".into(),
            args: vec![],
            cwd: ".".into(),
            timeout_ms: 100,
            max_output_bytes: 100,
        },
    );
    assert!(f.preparer().prepare(&manifest).is_err());
    let scratch = f.repository.join(".agent-work/scratch/general");
    assert!(fs::read_dir(&scratch).unwrap().next().is_none());

    let mut manifest = f.manifest(GeneralProfile::TestRunner);
    manifest.scratch_root = ".agent-work/scratch/general/symlink-root".into();
    let linked = f
        .repository
        .join(".agent-work/scratch/general/symlink-root");
    fs::create_dir_all(linked.parent().unwrap()).unwrap();
    symlink(f.repository.join("outside"), &linked).unwrap();
    assert!(f.preparer().prepare(&manifest).is_err());
    assert!(linked.is_symlink());
}

#[test]
fn stale_prepared_record_never_returns_dangling_task_and_retries_deterministically() {
    let f = Fixture::new();
    let manifest = f.manifest(GeneralProfile::AnalysisReadonly);
    let prepared = f.preparer().prepare(&manifest).unwrap();
    let record = prepared
        .worktree
        .scratch_worktrees_root
        .parent()
        .unwrap()
        .join("prepared-general.json");
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&record).unwrap()).unwrap();
    value["prompt_sha256"] = serde_json::Value::String("0".repeat(64));
    fs::write(&record, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    let error = f.preparer().prepare(&manifest).unwrap_err();
    assert!(matches!(
        error,
        PreparationError::InvalidManifest(_) | PreparationError::Worktree(_)
    ));
    assert!(!record.exists());
    assert!(!prepared.worktree.path.exists());
    let retry = f.preparer().prepare(&manifest).unwrap();
    retry.validate_digest().unwrap();
    assert!(retry.worktree.path.exists());

    fs::remove_dir_all(&retry.worktree.path).unwrap();
    assert!(f.preparer().prepare(&manifest).is_err());
    assert!(!retry.worktree.path.exists());
}

#[test]
fn malformed_prepared_record_cleans_registered_worktree_before_private_root() {
    let f = Fixture::new();
    let manifest = f.manifest(GeneralProfile::AnalysisReadonly);
    let prepared = f.preparer().prepare(&manifest).unwrap();
    let job_root = prepared
        .worktree
        .scratch_worktrees_root
        .parent()
        .unwrap()
        .to_path_buf();
    let record = job_root.join("prepared-general.json");
    assert!(git(&f.repository, &["worktree", "list", "--porcelain"])
        .contains(prepared.worktree.path.to_str().unwrap()));
    fs::write(&record, b"{malformed").unwrap();
    assert!(f.preparer().prepare(&manifest).is_err());
    assert!(!job_root.exists());
    assert!(!git(&f.repository, &["worktree", "list", "--porcelain"])
        .contains(prepared.worktree.path.to_str().unwrap()));

    let retry = f.preparer().prepare(&manifest).unwrap();
    retry.validate_digest().unwrap();
    assert!(retry.worktree.path.exists());
}

#[test]
fn tampered_record_path_cleans_real_registration_without_touching_external_path() {
    let f = Fixture::new();
    let manifest = f.manifest(GeneralProfile::AnalysisReadonly);
    let prepared = f.preparer().prepare(&manifest).unwrap();
    let job_root = prepared
        .worktree
        .scratch_worktrees_root
        .parent()
        .unwrap()
        .to_path_buf();
    let record = job_root.join("prepared-general.json");
    let external = f._temp.path().join("must-survive");
    fs::create_dir_all(&external).unwrap();
    fs::write(external.join("sentinel"), "preserve").unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&record).unwrap()).unwrap();
    value["worktree"]["path"] = serde_json::Value::String(external.to_string_lossy().into_owned());
    value["worktree"]["scratch_worktrees_root"] =
        serde_json::Value::String(external.to_string_lossy().into_owned());
    fs::write(&record, serde_json::to_vec_pretty(&value).unwrap()).unwrap();

    assert!(f.preparer().prepare(&manifest).is_err());
    assert_eq!(
        fs::read_to_string(external.join("sentinel")).unwrap(),
        "preserve"
    );
    assert!(!job_root.exists());
    assert!(!git(&f.repository, &["worktree", "list", "--porcelain"])
        .contains(prepared.worktree.path.to_str().unwrap()));

    let retry = f.preparer().prepare(&manifest).unwrap();
    assert!(retry.worktree.path.exists());
}

#[test]
fn retry_cleanup_with_corrupt_a_pointing_to_b_is_fail_closed_and_non_destructive() {
    let a = Fixture::new();
    let b = Fixture::new();
    let prepared_a = a
        .preparer()
        .prepare(&a.manifest(GeneralProfile::AnalysisReadonly))
        .unwrap();
    let prepared_b = b
        .preparer()
        .prepare(&b.manifest(GeneralProfile::AnalysisReadonly))
        .unwrap();
    let mut corrupt = prepared_a.clone();
    corrupt.worktree = prepared_b.worktree.clone();
    corrupt.scratch_root = prepared_b.scratch_root.clone();
    corrupt.artifact_root = prepared_b.artifact_root.clone();
    let persisted = GeneralCompletion {
        outcome: CompletionOutcome::ResultInvalid,
        reason_code: Some("TASK_ROOT_CLEANUP_FAILED".into()),
        summary: "preserve".into(),
        checks: vec!["check".into()],
        residual_gaps: vec![],
        artifacts: vec![],
        artifact: None,
        cleaned: false,
    };
    let retried = GeneralFinalizer::retry_cleanup(&corrupt, &persisted);
    assert!(!retried.cleaned);
    assert!(prepared_b.worktree.path.exists());
    assert!(prepared_b.prompt_path.exists());
    assert!(git(&b.repository, &["worktree", "list", "--porcelain"])
        .contains(prepared_b.worktree.path.to_str().unwrap()));
    assert_eq!(retried.summary, "preserve");
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
