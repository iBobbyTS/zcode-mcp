use zcode_agent_preparation::{
    general_control_header, general_launch_prompt, AccessMode, AttachmentInput, CompletionOutcome,
    ExternalDecision, GeneralCompletion, GeneralFinalizer, GeneralNamedCommand,
    GeneralTaskManifest, GeneralTaskPreparer, PermissionRequest, PolicyCapabilities,
    PolicyLauncher, PreparationError, PreparedGeneralTask, ValidationCommand, GENERAL_TASK_SCHEMA,
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

#[test]
fn readonly_policy_protects_generic_agent_metadata_without_filename_heuristics() {
    let f = Fixture::new();
    let scratch = f.repository.join("policy-scratch");
    let reports = f.repository.join("policy-reports");
    fs::create_dir_all(&scratch).unwrap();
    fs::create_dir_all(&reports).unwrap();
    for name in [
        "gpt-raw-notes.txt",
        "gpt-admission-notes.txt",
        "glm-raw-notes.txt",
        "glm-admission-notes.txt",
    ] {
        fs::write(f.repository.join(name), "ordinary input\n").unwrap();
    }
    let metadata = f.repository.join(".agent-work/runtime/metadata.json");
    fs::create_dir_all(metadata.parent().unwrap()).unwrap();
    fs::write(&metadata, "{}\n").unwrap();
    symlink(
        ".agent-work/runtime/metadata.json",
        f.repository.join("metadata-alias"),
    )
    .unwrap();

    let policy = PolicyLauncher::new(
        f.repository.clone(),
        scratch,
        reports.join("result.json"),
        Vec::new(),
        BTreeMap::new(),
        false,
        PolicyCapabilities::default(),
    )
    .unwrap();
    let bash = |command: &str| {
        policy.decide_zcode_permission(
            &serde_json::json!({
                "toolName":"Bash",
                "input":{"command":command,"cwd":f.repository}
            }),
            ExternalDecision::Allow,
        )
    };

    for name in [
        "gpt-raw-notes.txt",
        "gpt-admission-notes.txt",
        "glm-raw-notes.txt",
        "glm-admission-notes.txt",
    ] {
        assert!(bash(&format!("cat {name}")).allowed, "{name}");
        assert!(bash(&format!("git diff -- {name}")).allowed, "git {name}");
    }

    for path in [".agent-work/runtime/metadata.json", "metadata-alias"] {
        assert!(!bash(&format!("cat {path}")).allowed, "{path}");
    }
    let metadata_request = serde_json::json!({
        "toolName":"Read",
        "input":{"file_path":metadata}
    });
    let (metadata_read, metadata_denial) =
        policy.decide_zcode_permission_validated(&metadata_request, ExternalDecision::Allow);
    assert!(!metadata_read.allowed);
    assert_eq!(metadata_read.reason, "agent_metadata_read_denied");
    let feedback = metadata_denial.unwrap().feedback(false);
    assert!(feedback.contains("code=agent_metadata_read_denied"));
    assert!(feedback.contains("retry=do_not_retry_equivalent"));
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
    fn manifest(&self, access_mode: AccessMode) -> GeneralTaskManifest {
        GeneralTaskManifest {
            schema: GENERAL_TASK_SCHEMA.into(),
            agent_id: "task-1".into(),
            repository: self.repository.clone(),
            base_ref: self.head.clone(),
            access_mode,
            prompt: "Inspect and produce the bounded result.".into(),
            repo_context: vec!["README.md".into()],
            attachments: vec![AttachmentInput {
                logical_name: "notes".into(),
                source_path: self.attachments.join("notes.txt"),
                allowed_root: self.attachments.clone(),
            }],
            write_manifest: if access_mode == AccessMode::WorkspaceWrite {
                vec!["src".into()]
            } else {
                vec![]
            },
            scratch_root: ".agent-work/scratch/general".into(),
            artifact_root: ".agent-work/artifacts/task-1".into(),
            budget: None,
            validation_commands: BTreeMap::new(),
            retain_partial: false,
            idempotency_key: format!("task-1-{access_mode:?}"),
        }
    }
    fn preparer(&self) -> GeneralTaskPreparer {
        GeneralTaskPreparer::new(vec![self.attachments.clone()]).unwrap()
    }
}

#[test]
fn preparation_snapshots_immutable_context_and_uses_access_mode_defaults() {
    let f = Fixture::new();
    let prepared = f
        .preparer()
        .prepare(&f.manifest(AccessMode::ReadOnly))
        .unwrap();
    assert_eq!(
        prepared.effective_budget,
        AccessMode::ReadOnly.default_budget()
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
fn daemon_control_header_is_deterministic_identity_bound_and_prompt_separate() {
    let f = Fixture::new();
    let mut manifest = f.manifest(AccessMode::ReadOnly);
    manifest.prompt = "Analyze the bounded input without an operational reminder.".into();
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
            readonly_safe: false,
        },
    )]);
    let prepared = f
        .preparer()
        .prepare_named_submission(&manifest, &named)
        .unwrap();
    let header = general_control_header(&prepared).unwrap();
    assert_eq!(header, general_control_header(&prepared).unwrap());
    assert!(header.starts_with("--- BEGIN DAEMON GENERAL CONTROL"));
    assert!(header.contains("\"access_mode\": \"read_only\""));
    assert!(header.contains("\"command_id\": \"unit\""));
    assert!(header.contains("daemon finalizes a matching turn.completed boundary"));
    assert!(header.contains("daemon owns outcome classification"));
    assert!(!header.contains("general-completion"));
    assert!(!header.contains("checkpoint"));
    assert!(!header.contains("finding"));
    assert!(header.contains("hidden reasoning, credentials, absolute host paths"));
    assert!(header.contains(&prepared.prompt_sha256));
    assert!(!header.contains("changes_patch"));
    assert!(!header.contains(&manifest.prompt));
    assert!(!header.contains(f.repository.to_string_lossy().as_ref()));
    assert!(!header.contains("/usr/bin/true"));
    assert_eq!(
        fs::read_to_string(&prepared.prompt_path).unwrap(),
        manifest.prompt
    );

    let replay = f
        .preparer()
        .prepare_named_submission(&manifest, &named)
        .unwrap();
    assert_eq!(general_control_header(&replay).unwrap(), header);

    let mut different = f.manifest(AccessMode::ReadOnly);
    different.agent_id = "different-control".into();
    different.idempotency_key = "different-control".into();
    different.prompt = manifest.prompt.clone();
    let mut changed_named = named.clone();
    changed_named.get_mut("unit").unwrap().command.args = vec!["changed".into()];
    let changed = f
        .preparer()
        .prepare_named_submission(&different, &changed_named)
        .unwrap();
    assert_ne!(general_control_header(&changed).unwrap(), header);
    assert_ne!(changed.manifest_sha256, prepared.manifest_sha256);

    let mut implementation = f.manifest(AccessMode::WorkspaceWrite);
    implementation.agent_id = "implementation-control".into();
    implementation.idempotency_key = "implementation-control".into();
    implementation.prompt = manifest.prompt.clone();
    let implementation = f.preparer().prepare_submission(&implementation).unwrap();
    let implementation_header = general_control_header(&implementation).unwrap();
    assert!(implementation_header.contains("\"access_mode\": \"workspace_write\""));
    assert!(implementation_header.contains("\"write_manifest\": [\n    \"src\""));
    assert!(!implementation_header.contains("changes_patch"));
    assert_ne!(implementation.manifest_sha256, prepared.manifest_sha256);

    assert!(GeneralFinalizer::finalize(&prepared, CompletionOutcome::Failed).cleaned);
    assert!(GeneralFinalizer::finalize(&changed, CompletionOutcome::Failed).cleaned);
    assert!(GeneralFinalizer::finalize(&implementation, CompletionOutcome::Failed).cleaned);
}

#[test]
fn named_command_identity_uses_pinned_base_canonical_cwd() {
    let f = Fixture::new();
    fs::create_dir_all(f.repository.join("pinned")).unwrap();
    fs::create_dir_all(f.repository.join("current")).unwrap();
    fs::write(f.repository.join("pinned/.keep"), "pinned\n").unwrap();
    fs::write(f.repository.join("current/.keep"), "current\n").unwrap();
    symlink("pinned", f.repository.join("command-cwd")).unwrap();
    git(&f.repository, &["add", "pinned", "current", "command-cwd"]);
    git(&f.repository, &["commit", "-m", "add command cwd symlink"]);
    let pinned_base = git(&f.repository, &["rev-parse", "HEAD"]);

    fs::remove_file(f.repository.join("command-cwd")).unwrap();
    symlink("current", f.repository.join("command-cwd")).unwrap();

    let mut manifest = f.manifest(AccessMode::ReadOnly);
    manifest.base_ref = pinned_base;
    manifest.idempotency_key = "pinned-command-cwd".into();
    let named = BTreeMap::from([(
        "unit".into(),
        GeneralNamedCommand {
            command: ValidationCommand {
                program: PathBuf::from("/usr/bin/true"),
                args: Vec::new(),
                cwd: "command-cwd".into(),
                timeout_ms: 1_000,
                max_output_bytes: 1_024,
            },
            readonly_safe: false,
        },
    )]);

    let prepared = f
        .preparer()
        .prepare_named_submission(&manifest, &named)
        .unwrap();
    assert_eq!(
        prepared.validation_commands["unit"].cwd,
        fs::canonicalize(prepared.worktree.path.join("pinned")).unwrap()
    );
    assert_ne!(
        prepared.validation_commands["unit"].cwd,
        fs::canonicalize(f.repository.join("command-cwd")).unwrap()
    );
    let header = general_control_header(&prepared).unwrap();
    let replay = f
        .preparer()
        .prepare_named_submission(&manifest, &named)
        .unwrap();
    assert_eq!(replay.manifest_sha256, prepared.manifest_sha256);
    assert_eq!(general_control_header(&replay).unwrap(), header);
    assert!(GeneralFinalizer::finalize(&prepared, CompletionOutcome::Failed).cleaned);
}

#[test]
fn composed_prompt_budget_checks_zero_inputs_at_exact_boundary_and_reaps_rejection() {
    let f = Fixture::new();
    let mut manifest = f.manifest(AccessMode::ReadOnly);
    manifest.repo_context.clear();
    manifest.attachments.clear();
    manifest.idempotency_key = "composed-prompt-budget".into();

    let generous = f.preparer().prepare_submission(&manifest).unwrap();
    let exact_bytes = general_launch_prompt(&generous, &manifest.prompt)
        .unwrap()
        .len() as u64;
    assert!(GeneralFinalizer::finalize(&generous, CompletionOutcome::Failed).cleaned);

    let mut exact_budget = AccessMode::ReadOnly.default_budget();
    exact_budget.max_context_bytes = exact_bytes;
    manifest.budget = Some(exact_budget.clone());
    let exact = f.preparer().prepare_submission(&manifest).unwrap();
    assert_eq!(
        general_launch_prompt(&exact, &manifest.prompt)
            .unwrap()
            .len() as u64,
        exact_bytes
    );
    assert!(GeneralFinalizer::finalize(&exact, CompletionOutcome::Failed).cleaned);

    exact_budget.max_context_bytes = exact_bytes - 1;
    manifest.budget = Some(exact_budget);
    let registrations_before = git(&f.repository, &["worktree", "list", "--porcelain"]);
    assert!(matches!(
        f.preparer().prepare_submission(&manifest),
        Err(PreparationError::InvalidManifest(message))
            if message == "context byte limit exceeded"
    ));
    assert_eq!(
        git(&f.repository, &["worktree", "list", "--porcelain"]),
        registrations_before
    );
    assert!(
        fs::read_dir(f.repository.join(".agent-work/scratch/general"))
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
fn inline_command_digest_remains_valid_and_readonly_true_is_identity_bound() {
    let f = Fixture::new();
    let mut legacy_manifest = f.manifest(AccessMode::ReadOnly);
    legacy_manifest.validation_commands.insert(
        "unit".into(),
        ValidationCommand {
            program: PathBuf::from("/usr/bin/true"),
            args: Vec::new(),
            cwd: ".".into(),
            timeout_ms: 1_000,
            max_output_bytes: 1_024,
        },
    );
    let legacy = f.preparer().prepare_submission(&legacy_manifest).unwrap();
    let canonical = serde_json::to_string(&legacy).unwrap();
    let encoded: serde_json::Value = serde_json::from_str(&canonical).unwrap();
    assert!(encoded["validation_commands"]["unit"]
        .get("readonly_safe")
        .is_none());
    let restored: PreparedGeneralTask = serde_json::from_str(&canonical).unwrap();
    restored.validate_digest().unwrap();
    assert!(GeneralFinalizer::finalize(&restored, CompletionOutcome::Failed).cleaned);

    let mut named_manifest = f.manifest(AccessMode::ReadOnly);
    named_manifest.agent_id = "task-readonly-safe".into();
    named_manifest.idempotency_key = "task-readonly-safe".into();
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
            readonly_safe: true,
        },
    )]);
    let prepared = f
        .preparer()
        .prepare_named_submission(&named_manifest, &named)
        .unwrap();
    assert_eq!(
        serde_json::to_value(&prepared).unwrap()["validation_commands"]["unit"]["readonly_safe"],
        true
    );
    let mut tampered = prepared.clone();
    tampered
        .validation_commands
        .get_mut("unit")
        .unwrap()
        .readonly_safe = false;
    assert!(tampered.validate_digest().is_err());
    assert!(GeneralFinalizer::finalize(&prepared, CompletionOutcome::Failed).cleaned);
}

#[test]
fn empty_named_selection_reuses_direct_identity_and_nonempty_changes_conflict() {
    let f = Fixture::new();
    let legacy_manifest = f.manifest(AccessMode::ReadOnly);
    let legacy = f.preparer().prepare_submission(&legacy_manifest).unwrap();
    let replayed = f
        .preparer()
        .prepare_named_submission(&legacy_manifest, &BTreeMap::new())
        .unwrap();
    assert_eq!(replayed, legacy);

    let selected = BTreeMap::from([(
        "unit".into(),
        GeneralNamedCommand {
            command: ValidationCommand {
                program: PathBuf::from("/usr/bin/true"),
                args: Vec::new(),
                cwd: ".".into(),
                timeout_ms: 1_000,
                max_output_bytes: 1_024,
            },
            readonly_safe: true,
        },
    )]);
    assert!(matches!(
        f.preparer()
            .prepare_named_submission(&legacy_manifest, &selected),
        Err(PreparationError::IdempotencyConflict(_))
    ));
    assert!(GeneralFinalizer::finalize(&legacy, CompletionOutcome::Failed).cleaned);

    let mut selected_manifest = f.manifest(AccessMode::ReadOnly);
    selected_manifest.agent_id = "task-selected-identity".into();
    selected_manifest.idempotency_key = "task-selected-identity".into();
    let mut selected = selected;
    selected.get_mut("unit").unwrap().readonly_safe = false;
    let prepared = f
        .preparer()
        .prepare_named_submission(&selected_manifest, &selected)
        .unwrap();
    assert_eq!(
        f.preparer()
            .prepare_named_submission(&selected_manifest, &selected)
            .unwrap(),
        prepared
    );

    let mut readonly_changed = selected.clone();
    readonly_changed.get_mut("unit").unwrap().readonly_safe = true;
    assert!(matches!(
        f.preparer()
            .prepare_named_submission(&selected_manifest, &readonly_changed),
        Err(PreparationError::IdempotencyConflict(_))
    ));

    let mut definition_changed = selected.clone();
    definition_changed.get_mut("unit").unwrap().command.args = vec!["changed".into()];
    assert!(matches!(
        f.preparer()
            .prepare_named_submission(&selected_manifest, &definition_changed),
        Err(PreparationError::IdempotencyConflict(_))
    ));
    assert!(GeneralFinalizer::finalize(&prepared, CompletionOutcome::Failed).cleaned);
}

#[test]
fn owner_roots_symlinks_secret_types_and_budget_fail_closed() {
    let f = Fixture::new();
    let other = f._temp.path().join("other");
    fs::create_dir_all(&other).unwrap();
    fs::write(other.join("x.txt"), "x").unwrap();
    let mut m = f.manifest(AccessMode::ReadOnly);
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
    m = f.manifest(AccessMode::ReadOnly);
    m.attachments[0].source_path = f.attachments.join("linked.txt");
    assert!(matches!(
        f.preparer().prepare(&m),
        Err(PreparationError::PathEscape { .. }) | Err(PreparationError::SymlinkInput(_))
    ));
    fs::write(f.attachments.join("identity.pem"), "secret").unwrap();
    m = f.manifest(AccessMode::ReadOnly);
    m.attachments[0].source_path = f.attachments.join("identity.pem");
    assert!(matches!(
        f.preparer().prepare(&m),
        Err(PreparationError::CredentialInput(_))
    ));
    fs::write(f.attachments.join(".env"), "TOKEN=value").unwrap();
    m = f.manifest(AccessMode::ReadOnly);
    m.attachments[0].source_path = f.attachments.join(".env");
    assert!(matches!(
        f.preparer().prepare(&m),
        Err(PreparationError::CredentialInput(_))
    ));
    m = f.manifest(AccessMode::ReadOnly);
    let mut budget = AccessMode::ReadOnly.default_budget();
    budget.max_turns = 0;
    m.budget = Some(budget);
    assert!(matches!(
        f.preparer().prepare(&m),
        Err(PreparationError::InvalidManifest(_))
    ));
    m = f.manifest(AccessMode::ReadOnly);
    let mut budget = AccessMode::ReadOnly.default_budget();
    budget.absolute_wall_time_ms = 86_400_001;
    m.budget = Some(budget);
    assert!(matches!(
        f.preparer().prepare(&m),
        Err(PreparationError::InvalidManifest(_))
    ));
}

#[test]
fn failed_preparation_reaps_worktree_and_access_mode_set_is_closed() {
    let f = Fixture::new();
    let before = git(&f.repository, &["worktree", "list", "--porcelain"]);
    let mut manifest = f.manifest(AccessMode::ReadOnly);
    manifest.validation_commands.insert(
        "bad".into(),
        zcode_agent_preparation::ValidationCommand {
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
    assert!(serde_json::from_str::<AccessMode>("\"review_readonly\"").is_err());
    assert_eq!(
        serde_json::to_string(&AccessMode::ReadOnly).unwrap(),
        "\"read_only\""
    );
}

#[test]
fn access_policy_allows_only_frozen_workspace_write_paths() {
    let f = Fixture::new();
    let readonly = f
        .preparer()
        .prepare(&f.manifest(AccessMode::ReadOnly))
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
        .prepare(&f.manifest(AccessMode::WorkspaceWrite))
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
}

#[test]
fn official_file_path_permissions_reuse_the_bounded_file_policy() {
    let f = Fixture::new();
    let implementation = f
        .preparer()
        .prepare(&f.manifest(AccessMode::WorkspaceWrite))
        .unwrap();
    let policy = implementation.launcher().unwrap();
    let worktree = &implementation.worktree.path;
    let src = worktree.join("src/lib.rs");
    let new_src = worktree.join("src/new.rs");
    let read = |tool: &str, input: serde_json::Value| {
        policy.decide_zcode_permission(
            &serde_json::json!({"toolName":tool,"input":input}),
            ExternalDecision::Allow,
        )
    };

    for tool in ["Read", "Edit", "Delete"] {
        assert!(
            read(tool, serde_json::json!({"file_path":src.to_string_lossy()})).allowed,
            "official {tool} file_path should use the existing bounded policy"
        );
    }
    assert!(
        read(
            "Write",
            serde_json::json!({"file_path":new_src.to_string_lossy()})
        )
        .allowed
    );
    assert!(
        read(
            "Write",
            serde_json::json!({"path":new_src.to_string_lossy()})
        )
        .allowed,
        "the existing path contract remains supported"
    );

    let conflict = read(
        "Write",
        serde_json::json!({
            "file_path":new_src.to_string_lossy(),
            "path":worktree.join("README.md").to_string_lossy(),
        }),
    );
    assert!(!conflict.allowed);
    assert_eq!(conflict.reason, "permission_request_unrecognized");
    let missing = read("Write", serde_json::json!({}));
    assert!(!missing.allowed);
    assert_eq!(missing.reason, "permission_request_unrecognized");

    let outside = read(
        "Write",
        serde_json::json!({"file_path":f.repository.join("src/lib.rs").to_string_lossy()}),
    );
    assert!(!outside.allowed);
    assert_eq!(outside.reason, "write_outside_artifact_roots_denied");
    let unlisted = read(
        "Write",
        serde_json::json!({"file_path":worktree.join("README.md").to_string_lossy()}),
    );
    assert!(!unlisted.allowed);
    assert_eq!(unlisted.reason, "tracked_path_not_allowlisted");

    fs::write(worktree.join("src/.env"), "SECRET=x\n").unwrap();
    let secret = read(
        "Read",
        serde_json::json!({"file_path":worktree.join("src/.env").to_string_lossy()}),
    );
    assert!(!secret.allowed);
    assert_eq!(secret.reason, "credential_read_denied");

    let outside_file = f.repository.join("outside.rs");
    fs::write(&outside_file, "outside\n").unwrap();
    symlink(&outside_file, worktree.join("src/link.rs")).unwrap();
    let symlink_escape = read(
        "Edit",
        serde_json::json!({"file_path":worktree.join("src/link.rs").to_string_lossy()}),
    );
    assert!(!symlink_escape.allowed);
    assert_eq!(symlink_escape.reason, "write_outside_artifact_roots_denied");
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
        .prepare(&f.manifest(AccessMode::WorkspaceWrite))
        .unwrap();
    fs::write(
        prepared.worktree.path.join("src/lib.rs"),
        "pub fn value() -> u8 { 2 }\n",
    )
    .unwrap();
    let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::Completed);
    assert_eq!(completion.outcome, CompletionOutcome::Completed);
    assert!(completion.cleaned);
    let artifact = completion.changes_patch.unwrap();
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
    let mut manifest = f.manifest(AccessMode::WorkspaceWrite);
    manifest.repo_context = vec!["src/lib.rs".into()];
    manifest.write_manifest = vec!["src".into()];
    let prepared = f.preparer().prepare(&manifest).unwrap();
    fs::write(
        prepared.worktree.path.join("src/lib.rs"),
        "pub fn value() -> u8 { 22 }\n",
    )
    .unwrap();
    assert!(prepared.launcher().is_err());
    assert!(prepared.final_tree_launcher().is_ok());

    let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::Completed);

    assert_eq!(completion.outcome, CompletionOutcome::Completed);
    assert!(completion.cleaned);
    let artifact = completion.changes_patch.unwrap();
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
        .prepare(&f.manifest(AccessMode::WorkspaceWrite))
        .unwrap();
    fs::write(
        prepared.worktree.path.join("README.md"),
        "changed non-writable context\n",
    )
    .unwrap();

    let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::Completed);

    assert_eq!(completion.outcome, CompletionOutcome::ResultInvalid);
    assert_eq!(
        completion.reason_code.as_deref(),
        Some("PREPARED_CONTENT_INVALID")
    );
    assert!(completion.cleaned);
}

#[test]
fn readonly_change_becomes_result_invalid() {
    let f = Fixture::new();
    let prepared = f
        .preparer()
        .prepare(&f.manifest(AccessMode::ReadOnly))
        .unwrap();
    fs::write(
        prepared.worktree.path.join("src/lib.rs"),
        "pub fn value() -> u8 { 8 }\n",
    )
    .unwrap();
    let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::Completed);
    assert_eq!(completion.outcome, CompletionOutcome::ResultInvalid);
    assert_eq!(
        completion.reason_code.as_deref(),
        Some("READ_ONLY_MODIFIED_TRACKED_STATE")
    );
    assert!(completion.cleaned);
}

#[test]
fn failed_without_changes_cleans_and_has_no_partial_artifact() {
    let f = Fixture::new();
    let prepared = f
        .preparer()
        .prepare(&f.manifest(AccessMode::WorkspaceWrite))
        .unwrap();
    let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::Failed);
    assert_eq!(completion.outcome, CompletionOutcome::Failed);
    assert!(completion.cleaned);
    assert!(completion.changes_patch.is_none());
    assert!(!prepared.worktree.path.exists());
}

#[test]
fn null_budget_and_idempotency_conflicts_are_rejected() {
    let f = Fixture::new();
    let value = serde_json::to_value(f.manifest(AccessMode::ReadOnly)).unwrap();
    let mut null_budget = value.clone();
    null_budget["budget"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<GeneralTaskManifest>(null_budget).is_err());
    let mut omitted = value;
    omitted.as_object_mut().unwrap().remove("budget");
    assert!(serde_json::from_value::<GeneralTaskManifest>(omitted).is_ok());

    let preparer = f.preparer();
    let manifest = f.manifest(AccessMode::ReadOnly);
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
    let compatible = preparer.prepare(&f.manifest(AccessMode::ReadOnly)).unwrap();
    assert_eq!(compatible.prepared_sha256, first.prepared_sha256);
    assert!(compatible.worktree.path.exists());
}

#[test]
fn partial_patch_retention_follows_submission_opt_in() {
    let f = Fixture::new();
    let prepared = f
        .preparer()
        .prepare(&f.manifest(AccessMode::WorkspaceWrite))
        .unwrap();
    fs::write(
        prepared.worktree.path.join("src/lib.rs"),
        "pub fn value() -> u8 { 3 }\n",
    )
    .unwrap();
    let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::Failed);
    assert_eq!(completion.outcome, CompletionOutcome::Failed);
    assert!(completion.changes_patch.is_none());
    assert!(completion.cleaned);

    let f = Fixture::new();
    let mut manifest = f.manifest(AccessMode::WorkspaceWrite);
    manifest.retain_partial = true;
    let prepared = f.preparer().prepare(&manifest).unwrap();
    fs::write(
        prepared.worktree.path.join("src/lib.rs"),
        "pub fn value() -> u8 { 4 }\n",
    )
    .unwrap();
    let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::TimedOut);
    let artifact = completion.changes_patch.unwrap();
    assert_eq!(artifact.changed_paths, ["src/lib.rs"]);
    assert!(completion.cleaned);
}

#[test]
fn artifact_limit_failure_is_result_invalid_and_reaped() {
    let f = Fixture::new();
    let mut manifest = f.manifest(AccessMode::WorkspaceWrite);
    let mut budget = AccessMode::WorkspaceWrite.default_budget();
    budget.max_artifact_bytes = 1;
    manifest.budget = Some(budget);
    let prepared = f.preparer().prepare(&manifest).unwrap();
    fs::write(
        prepared.worktree.path.join("src/lib.rs"),
        "pub fn value() -> u8 { 9 }\n",
    )
    .unwrap();
    let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::Completed);
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
    let mut manifest = f.manifest(AccessMode::ReadOnly);
    let mut budget = AccessMode::ReadOnly.default_budget();
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
        .prepare(&f.manifest(AccessMode::ReadOnly))
        .unwrap();
    assert_eq!(prepared.context[0].size_bytes, b"fixture\n".len() as u64);
    fs::write(&prepared.prompt_path, "mutated prepared prompt").unwrap();
    assert!(prepared.launcher().is_err());
    assert!(prepared.final_tree_launcher().is_err());
    let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::Completed);
    assert_eq!(
        completion.reason_code.as_deref(),
        Some("PREPARED_CONTENT_INVALID")
    );
    assert!(completion.cleaned);
    assert!(!prepared.prompt_path.exists());

    let f = Fixture::new();
    let prepared = f
        .preparer()
        .prepare(&f.manifest(AccessMode::ReadOnly))
        .unwrap();
    fs::write(&prepared.attachments[0].prepared_path, "replacement").unwrap();
    assert!(prepared.launcher().is_err());
    assert!(prepared.final_tree_launcher().is_err());
    assert_eq!(
        GeneralFinalizer::finalize(&prepared, CompletionOutcome::Completed)
            .reason_code
            .as_deref(),
        Some("PREPARED_CONTENT_INVALID")
    );

    let f = Fixture::new();
    let prepared = f
        .preparer()
        .prepare(&f.manifest(AccessMode::ReadOnly))
        .unwrap();
    fs::write(
        prepared.worktree.path.join("README.md"),
        "changed context\n",
    )
    .unwrap();
    assert!(prepared.launcher().is_err());
    assert!(prepared.final_tree_launcher().is_err());
    assert_eq!(
        GeneralFinalizer::finalize(&prepared, CompletionOutcome::Completed)
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
        f.preparer().prepare(&f.manifest(AccessMode::ReadOnly)),
        Err(PreparationError::SymlinkInput(_))
    ));
}

#[test]
fn precreated_history_and_attached_head_are_rejected() {
    let f = Fixture::new();
    let prepared = f
        .preparer()
        .prepare(&f.manifest(AccessMode::WorkspaceWrite))
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
    let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::Completed);
    assert_eq!(
        completion.reason_code.as_deref(),
        Some("PREFINALIZATION_HEAD_INVALID")
    );
    assert!(completion.cleaned);

    let f = Fixture::new();
    git(&f.repository, &["branch", "spare", &f.head]);
    let prepared = f
        .preparer()
        .prepare(&f.manifest(AccessMode::WorkspaceWrite))
        .unwrap();
    git(&prepared.worktree.path, &["checkout", "spare"]);
    let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::Completed);
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
        .prepare(&f.manifest(AccessMode::WorkspaceWrite))
        .unwrap();
    fs::write(
        prepared.worktree.path.join("src/lib.rs"),
        "pub fn value() -> u8 { 6 }\n",
    )
    .unwrap();
    let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::Completed);
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
        .prepare(&f.manifest(AccessMode::WorkspaceWrite))
        .unwrap();
    fs::write(
        prepared.worktree.path.join("src/lib.rs"),
        "pub fn value() -> u8 { 7 }\n",
    )
    .unwrap();
    let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::Completed);
    assert_eq!(completion.reason_code.as_deref(), Some("UNSAFE_GIT_CONFIG"));
    assert!(!diff_canary.exists());

    let f = Fixture::new();
    let mut manifest = f.manifest(AccessMode::WorkspaceWrite);
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
    let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::Completed);
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
        .prepare(&f.manifest(AccessMode::WorkspaceWrite))
        .unwrap();
    fs::write(
        prepared.worktree.path.join("src/160000_notes.txt"),
        "ordinary blob\n",
    )
    .unwrap();

    let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::Completed);

    assert_eq!(completion.outcome, CompletionOutcome::Completed);
    assert!(completion.cleaned);
    assert_eq!(
        completion.changes_patch.unwrap().changed_paths,
        ["src/160000_notes.txt"]
    );
}

#[test]
fn model_authored_scratch_files_never_become_public_artifacts() {
    let f = Fixture::new();
    let prepared = f
        .preparer()
        .prepare(&f.manifest(AccessMode::ReadOnly))
        .unwrap();
    let output_root = prepared.scratch_root.join("agent-artifacts");
    fs::create_dir_all(&output_root).unwrap();
    fs::write(output_root.join("report.md"), "model supplied\n").unwrap();
    fs::write(output_root.join("check-report.json"), "{}\n").unwrap();

    let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::Completed);

    assert_eq!(completion.outcome, CompletionOutcome::Completed);
    assert!(completion.changes_patch.is_none());
    assert!(completion.changes_patch.is_none());
    assert!(!prepared.artifact_root.join("report.md").exists());
    assert!(!prepared.artifact_root.join("check-report.json").exists());
    assert!(!prepared.prompt_path.exists());
    let task_root = prepared.worktree.scratch_worktrees_root.parent().unwrap();
    assert!(!task_root.exists());
}

#[test]
fn preexisting_artifact_root_content_is_rejected_without_adoption() {
    let f = Fixture::new();
    let prepared = f
        .preparer()
        .prepare(&f.manifest(AccessMode::ReadOnly))
        .unwrap();
    fs::write(prepared.artifact_root.join("foreign.txt"), "untrusted\n").unwrap();

    let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::Completed);

    assert_eq!(
        completion.reason_code.as_deref(),
        Some("ARTIFACT_ROOT_NOT_EMPTY")
    );
    assert!(completion.cleaned);
    assert_eq!(
        fs::read_to_string(prepared.artifact_root.join("foreign.txt")).unwrap(),
        "untrusted\n"
    );
}

#[test]
fn cleanup_failure_is_truthful_and_keeps_final_artifact_metadata() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    let prepared = f
        .preparer()
        .prepare(&f.manifest(AccessMode::WorkspaceWrite))
        .unwrap();
    fs::write(
        prepared.worktree.path.join("src/lib.rs"),
        "pub fn value() -> u8 { 10 }\n",
    )
    .unwrap();
    let task_root = prepared.worktree.scratch_worktrees_root.parent().unwrap();
    let owner_root = task_root.parent().unwrap();
    let original = fs::metadata(owner_root).unwrap().permissions();
    fs::set_permissions(owner_root, fs::Permissions::from_mode(0o500)).unwrap();
    let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::Completed);
    fs::set_permissions(owner_root, original).unwrap();
    assert_eq!(completion.outcome, CompletionOutcome::ResultInvalid);
    assert_eq!(
        completion.reason_code.as_deref(),
        Some("TASK_ROOT_CLEANUP_FAILED")
    );
    assert!(!completion.cleaned);
    assert!(completion.changes_patch.is_some());
    assert!(completion.changes_patch.is_some());
    assert!(prepared.artifact_root.join("changes.patch").is_file());

    let cleanup = GeneralFinalizer::retry_cleanup(&prepared, &completion);
    assert!(cleanup.cleaned);
    assert!(cleanup.changes_patch.is_some());
    assert!(prepared.artifact_root.join("changes.patch").is_file());
}

#[test]
fn missing_worktree_with_stale_git_registration_is_not_cleaned() {
    let f = Fixture::new();
    let prepared = f
        .preparer()
        .prepare(&f.manifest(AccessMode::ReadOnly))
        .unwrap();
    fs::remove_dir_all(&prepared.worktree.path).unwrap();
    let completion = GeneralFinalizer::finalize(&prepared, CompletionOutcome::Completed);
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
    let mut manifest = f.manifest(AccessMode::ReadOnly);
    manifest.validation_commands.insert(
        "missing".into(),
        zcode_agent_preparation::ValidationCommand {
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

    let mut manifest = f.manifest(AccessMode::ReadOnly);
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
    let manifest = f.manifest(AccessMode::ReadOnly);
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
    let manifest = f.manifest(AccessMode::ReadOnly);
    let prepared = f.preparer().prepare(&manifest).unwrap();
    let task_root = prepared
        .worktree
        .scratch_worktrees_root
        .parent()
        .unwrap()
        .to_path_buf();
    let record = task_root.join("prepared-general.json");
    assert!(git(&f.repository, &["worktree", "list", "--porcelain"])
        .contains(prepared.worktree.path.to_str().unwrap()));
    fs::write(&record, b"{malformed").unwrap();
    assert!(f.preparer().prepare(&manifest).is_err());
    assert!(!task_root.exists());
    assert!(!git(&f.repository, &["worktree", "list", "--porcelain"])
        .contains(prepared.worktree.path.to_str().unwrap()));

    let retry = f.preparer().prepare(&manifest).unwrap();
    retry.validate_digest().unwrap();
    assert!(retry.worktree.path.exists());
}

#[test]
fn tampered_record_path_cleans_real_registration_without_touching_external_path() {
    let f = Fixture::new();
    let manifest = f.manifest(AccessMode::ReadOnly);
    let prepared = f.preparer().prepare(&manifest).unwrap();
    let task_root = prepared
        .worktree
        .scratch_worktrees_root
        .parent()
        .unwrap()
        .to_path_buf();
    let record = task_root.join("prepared-general.json");
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
    assert!(!task_root.exists());
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
        .prepare(&a.manifest(AccessMode::ReadOnly))
        .unwrap();
    let prepared_b = b
        .preparer()
        .prepare(&b.manifest(AccessMode::ReadOnly))
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
        changes_patch: None,
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
