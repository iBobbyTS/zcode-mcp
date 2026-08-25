use review_preparation::{
    CleanupRecord, ExternalDecision, NetworkPolicy, PermissionRequest, PreparationError,
    ReviewKind, ReviewManifest, ReviewPreparer, RoundKind, SandboxEnforcement, ScratchPolicy,
    ValidationCommand, WorktreeManager,
};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::TempDir;

struct RepositoryFixture {
    _directory: TempDir,
    repository: PathBuf,
    head: String,
}

impl RepositoryFixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let repository = directory.path().join("repository");
        fs::create_dir_all(repository.join("src")).unwrap();
        fs::write(
            repository.join("src/lib.rs"),
            "pub fn value() -> u8 { 1 }\n",
        )
        .unwrap();
        git(&repository, &["init"]).unwrap();
        git(&repository, &["config", "user.name", "S04 Test"]).unwrap();
        git(
            &repository,
            &["config", "user.email", "s04@example.invalid"],
        )
        .unwrap();
        git(&repository, &["add", "src/lib.rs"]).unwrap();
        git(&repository, &["commit", "-m", "fixture"]).unwrap();
        let head = git(&repository, &["rev-parse", "HEAD"]).unwrap();
        fs::create_dir_all(repository.join(".agent-work/context")).unwrap();
        fs::write(repository.join(".agent-work/PLAN.md"), "# Current plan\n").unwrap();
        fs::write(
            repository.join(".agent-work/context/S04.md"),
            "# Current context\n",
        )
        .unwrap();
        Self {
            _directory: directory,
            repository: fs::canonicalize(repository).unwrap(),
            head,
        }
    }

    fn manifest(&self) -> ReviewManifest {
        ReviewManifest {
            schema: "sectioned-zcode-review/v1".into(),
            review_kind: ReviewKind::Code,
            feature_id: "feature".into(),
            section_id: "S04".into(),
            round_kind: RoundKind::InitialBounded,
            repository: self.repository.clone(),
            base_ref: self.head.clone(),
            head_ref: self.head.clone(),
            plan_path: ".agent-work/PLAN.md".into(),
            context_paths: vec![".agent-work/context/S04.md".into()],
            scope_paths: vec!["src".into()],
            forbidden_input_globs: vec![".agent-work/reviews/*".into()],
            validation_commands: BTreeMap::from([(
                "print".into(),
                ValidationCommand {
                    program: executable("printf"),
                    args: vec!["prepared".into()],
                    cwd: ".".into(),
                    timeout_ms: 1_000,
                    max_output_bytes: 1_024,
                },
            )]),
            report_target: ".agent-work/reviews/feature/S04/report.md".into(),
            scratch_root: ".agent-work/scratch/jobs".into(),
            model: None,
            fresh_session: true,
            network_policy: NetworkPolicy::Deny,
            scratch_policy: ScratchPolicy::Isolated,
            idempotency_key: "feature:S04:initial".into(),
        }
    }
}

#[test]
fn schema_and_valid_manifest_prepare_canonical_immutable_launch() {
    let fixture = RepositoryFixture::new();
    let manifest = fixture.manifest();
    let encoded = serde_json::to_vec(&manifest).unwrap();
    let parsed = ReviewManifest::from_json(&encoded).unwrap();
    let schema: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../schemas/review-manifest.schema.json"
    ))
    .unwrap();
    assert_eq!(schema["properties"]["fresh_session"]["const"], true);

    let prepared = ReviewPreparer.prepare(&parsed).unwrap();
    prepared.validate_digest().unwrap();
    assert_eq!(prepared.repository, fixture.repository);
    assert_eq!(prepared.base_sha, fixture.head);
    assert_eq!(prepared.head_sha, fixture.head);
    assert!(prepared
        .worktree
        .path
        .starts_with(&prepared.worktree.scratch_worktrees_root));
    assert!(!prepared.worktree.path.starts_with(&prepared.scratch_root));
    assert!(prepared
        .plan
        .prepared_path
        .starts_with(prepared.worktree.scratch_worktrees_root.parent().unwrap()));
    assert_eq!(prepared.scope[0].repository_relative, Path::new("src"));
    assert!(prepared
        .report_target
        .starts_with(fixture.repository.join(".agent-work/reviews")));
    assert!(!prepared.capabilities.network_isolation_enforced);
    assert_eq!(
        prepared.capabilities.os_sandbox,
        SandboxEnforcement::Unsupported
    );
    assert!(prepared
        .capabilities
        .network_control
        .contains("unsupported"));
    assert!(prepared.manifest_provenance_path.is_file());
    let mut changed_command_key = prepared.clone();
    let command = changed_command_key
        .validation_commands
        .remove("print")
        .unwrap();
    changed_command_key
        .validation_commands
        .insert("renamed".into(), command);
    assert!(changed_command_key.validate_digest().is_err());

    let original_context_hash = prepared.context[0].sha256.clone();
    fs::write(
        fixture.repository.join(".agent-work/context/S04.md"),
        "# changed after preparation\n",
    )
    .unwrap();
    let repeated = ReviewPreparer.prepare(&parsed).unwrap();
    assert_eq!(repeated.prepared_sha256, prepared.prepared_sha256);
    assert_eq!(repeated.context[0].sha256, original_context_hash);

    let mut conflict = parsed;
    conflict.scope_paths = vec!["src/lib.rs".into()];
    assert!(matches!(
        ReviewPreparer.prepare(&conflict),
        Err(PreparationError::IdempotencyConflict(_))
    ));
}

#[test]
fn schema_and_rust_field_rules_have_table_parity() {
    let fixture = RepositoryFixture::new();
    let schema: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../schemas/review-manifest.schema.json"
    ))
    .unwrap();
    jsonschema::draft202012::meta::validate(&schema).unwrap();
    let validator = jsonschema::draft202012::options().build(&schema).unwrap();

    let valid = serde_json::to_value(fixture.manifest()).unwrap();
    let mut cases = Vec::new();
    cases.push(("valid", valid.clone(), true));

    let mut value = valid.clone();
    value["feature_id"] = "a".repeat(256).into();
    cases.push(("identifier at bound", value, true));
    let mut value = valid.clone();
    value["feature_id"] = "a".repeat(257).into();
    cases.push(("identifier over bound", value, false));
    let mut value = valid.clone();
    value["section_id"] = "bad/id".into();
    cases.push(("identifier alphabet", value, false));
    let mut value = valid.clone();
    let command = value["validation_commands"]["print"].take();
    value["validation_commands"] = serde_json::json!({"bad/id": command});
    cases.push(("command identifier alphabet", value, false));
    let mut value = valid.clone();
    value["idempotency_key"] = "a".repeat(512).into();
    cases.push(("idempotency at bound", value, true));
    let mut value = valid.clone();
    value["idempotency_key"] = "has space".into();
    cases.push(("idempotency alphabet", value, false));
    let mut value = valid.clone();
    value["idempotency_key"] = "a".repeat(513).into();
    cases.push(("idempotency over bound", value, false));
    let mut value = valid.clone();
    value["model"] = serde_json::Value::Null;
    cases.push(("null optional model", value, true));
    let mut value = valid.clone();
    value.as_object_mut().unwrap().remove("model");
    cases.push(("absent optional model", value, true));
    let mut value = valid.clone();
    value["model"] = "  ".into();
    cases.push(("blank optional model", value, false));
    let mut value = valid.clone();
    value["context_paths"] =
        serde_json::json!([".agent-work/context/S04.md", ".agent-work/context/S04.md"]);
    cases.push(("duplicate context", value, false));
    let mut value = valid.clone();
    value["scope_paths"] = serde_json::json!(["src", "src"]);
    cases.push(("duplicate scope", value, false));
    let mut value = valid.clone();
    value["forbidden_input_globs"] = serde_json::json!(["*.raw", "*.raw"]);
    cases.push(("duplicate forbidden glob", value, false));
    let mut value = valid.clone();
    let mut first = value["validation_commands"]["print"].clone();
    first["id"] = "print".into();
    let mut second = first.clone();
    second["args"] = serde_json::json!(["different"]);
    value["validation_commands"] = serde_json::json!([first, second]);
    cases.push((
        "same command id with different args in legacy array",
        value,
        false,
    ));
    let mut value = valid.clone();
    value["validation_commands"]["print"]["timeout_ms"] = 3_600_001u64.into();
    cases.push(("timeout over bound", value, false));
    let mut value = valid.clone();
    value["validation_commands"]["print"]["timeout_ms"] = 0u64.into();
    cases.push(("timeout under bound", value, false));
    let mut value = valid.clone();
    value["validation_commands"]["print"]["max_output_bytes"] = (16 * 1024 * 1024 + 1).into();
    cases.push(("output over bound", value, false));
    let mut value = valid.clone();
    value["validation_commands"]["print"]["max_output_bytes"] = 0u64.into();
    cases.push(("output under bound", value, false));
    let mut value = valid.clone();
    value["unexpected"] = true.into();
    cases.push(("unknown manifest field", value, false));
    let mut value = valid;
    value["validation_commands"]["print"]["unexpected"] = true.into();
    cases.push(("unknown command field", value, false));

    for (name, manifest, expected) in cases {
        let schema_valid = validator.is_valid(&manifest);
        let rust_valid = ReviewManifest::from_json(&serde_json::to_vec(&manifest).unwrap()).is_ok();
        assert_eq!(schema_valid, expected, "JSON Schema parity case: {name}");
        assert_eq!(rust_valid, expected, "Rust parity case: {name}");
    }
}

#[test]
fn traversal_symlink_report_escape_missing_ref_and_mutable_ref_fail_closed() {
    let fixture = RepositoryFixture::new();

    let mut traversal = fixture.manifest();
    traversal.plan_path = "../PLAN.md".into();
    assert!(matches!(
        ReviewPreparer.prepare(&traversal),
        Err(PreparationError::InvalidPath { .. })
    ));

    let linked = fixture.repository.join(".agent-work/linked-plan.md");
    symlink(fixture.repository.join(".agent-work/PLAN.md"), &linked).unwrap();
    let mut symlinked = fixture.manifest();
    symlinked.plan_path = ".agent-work/linked-plan.md".into();
    assert!(matches!(
        ReviewPreparer.prepare(&symlinked),
        Err(PreparationError::SymlinkInput(_))
    ));

    let mut escaped_report = fixture.manifest();
    escaped_report.report_target = ".agent-work/not-reviews/report.md".into();
    assert!(matches!(
        ReviewPreparer.prepare(&escaped_report),
        Err(PreparationError::PathEscape { .. })
    ));

    fs::create_dir_all(fixture.repository.join("outside-report")).unwrap();
    symlink(
        fixture.repository.join("outside-report"),
        fixture.repository.join(".agent-work/reviews-link"),
    )
    .unwrap();
    let mut linked_report = fixture.manifest();
    linked_report.report_target = ".agent-work/reviews-link/report.md".into();
    assert!(matches!(
        ReviewPreparer.prepare(&linked_report),
        Err(PreparationError::SymlinkInput(_)) | Err(PreparationError::PathEscape { .. })
    ));

    let mut mutable = fixture.manifest();
    mutable.head_ref = "HEAD".into();
    assert!(matches!(
        ReviewPreparer.prepare(&mutable),
        Err(PreparationError::MutableReference(_))
    ));

    let mut missing = fixture.manifest();
    missing.head_ref = "0000000000000000000000000000000000000000".into();
    assert!(ReviewPreparer.prepare(&missing).is_err());

    let mut stale = fixture.manifest();
    stale.fresh_session = false;
    assert!(matches!(
        ReviewPreparer.prepare(&stale),
        Err(PreparationError::InvalidManifest(_))
    ));
}

#[test]
fn prior_review_credentials_and_uncommitted_scope_are_rejected() {
    let fixture = RepositoryFixture::new();
    fs::create_dir_all(fixture.repository.join(".agent-work/reviews/old")).unwrap();
    fs::write(
        fixture
            .repository
            .join(".agent-work/reviews/old/GPT-RAW.md"),
        "stale",
    )
    .unwrap();
    let mut prior = fixture.manifest();
    prior.context_paths = vec![".agent-work/reviews/old/GPT-RAW.md".into()];
    assert!(matches!(
        ReviewPreparer.prepare(&prior),
        Err(PreparationError::ForbiddenInput(_))
    ));

    fs::create_dir_all(fixture.repository.join(".ssh")).unwrap();
    fs::write(fixture.repository.join(".ssh/id_ed25519"), "not-a-key").unwrap();
    let mut credential = fixture.manifest();
    credential.context_paths = vec![".ssh/id_ed25519".into()];
    assert!(matches!(
        ReviewPreparer.prepare(&credential),
        Err(PreparationError::CredentialInput(_))
    ));

    fs::write(fixture.repository.join("mutable.rs"), "uncommitted").unwrap();
    let mut mutable_scope = fixture.manifest();
    mutable_scope.scope_paths = vec!["mutable.rs".into()];
    assert!(matches!(
        ReviewPreparer.prepare(&mutable_scope),
        Err(PreparationError::MissingInput(_))
    ));
}

#[test]
fn scope_uses_fixed_head_and_rejects_tracked_staged_or_unstaged_source_changes() {
    let historical = RepositoryFixture::new();
    fs::write(historical.repository.join("historical.rs"), "historical\n").unwrap();
    git(&historical.repository, &["add", "historical.rs"]).unwrap();
    git(&historical.repository, &["commit", "-m", "add historical"]).unwrap();
    let historical_head = git(&historical.repository, &["rev-parse", "HEAD"]).unwrap();
    git(&historical.repository, &["rm", "historical.rs"]).unwrap();
    git(
        &historical.repository,
        &["commit", "-m", "remove historical"],
    )
    .unwrap();
    assert!(!historical.repository.join("historical.rs").exists());
    let mut manifest = historical.manifest();
    manifest.base_ref = historical_head.clone();
    manifest.head_ref = historical_head;
    manifest.scope_paths = vec!["historical.rs".into()];
    manifest.idempotency_key = "historical-head".into();
    let prepared = ReviewPreparer.prepare(&manifest).unwrap();
    assert!(prepared.scope[0].worktree_path.is_file());

    let unstaged = RepositoryFixture::new();
    fs::write(
        unstaged.repository.join("src/lib.rs"),
        "pub fn value() -> u8 { 2 }\n",
    )
    .unwrap();
    let mut manifest = unstaged.manifest();
    manifest.scope_paths = vec!["src/lib.rs".into()];
    assert!(matches!(
        ReviewPreparer.prepare(&manifest),
        Err(PreparationError::Worktree(message)) if message.contains("unstaged")
    ));

    let staged = RepositoryFixture::new();
    fs::write(
        staged.repository.join("src/lib.rs"),
        "pub fn value() -> u8 { 3 }\n",
    )
    .unwrap();
    git(&staged.repository, &["add", "src/lib.rs"]).unwrap();
    let mut manifest = staged.manifest();
    manifest.scope_paths = vec!["src/lib.rs".into()];
    assert!(matches!(
        ReviewPreparer.prepare(&manifest),
        Err(PreparationError::Worktree(message)) if message.contains("staged")
    ));
}

#[test]
fn rejected_external_scratch_and_report_paths_have_no_external_side_effect() {
    let fixture = RepositoryFixture::new();
    let external_scratch = fixture._directory.path().join("external-scratch/new");
    let mut manifest = fixture.manifest();
    manifest.scratch_root = external_scratch.clone();
    assert!(matches!(
        ReviewPreparer.prepare(&manifest),
        Err(PreparationError::PathEscape { .. })
    ));
    assert!(!external_scratch.exists());

    let external_report = fixture
        ._directory
        .path()
        .join("external-report/new/report.md");
    let mut manifest = fixture.manifest();
    manifest.idempotency_key = "external-report".into();
    manifest.report_target = external_report.clone();
    assert!(matches!(
        ReviewPreparer.prepare(&manifest),
        Err(PreparationError::PathEscape { .. })
    ));
    assert!(!external_report.parent().unwrap().exists());
}

#[test]
fn launcher_sanitizes_environment_bounds_output_and_times_out() {
    let fixture = RepositoryFixture::new();
    let mut manifest = fixture.manifest();
    manifest.validation_commands = BTreeMap::from([
        (
            "environment".into(),
            ValidationCommand {
                program: executable("env"),
                args: Vec::new(),
                cwd: ".".into(),
                timeout_ms: 1_000,
                max_output_bytes: 4_096,
            },
        ),
        (
            "bounded".into(),
            ValidationCommand {
                program: executable("yes"),
                args: Vec::new(),
                cwd: ".".into(),
                timeout_ms: 25,
                max_output_bytes: 32,
            },
        ),
    ]);
    let prepared = ReviewPreparer.prepare(&manifest).unwrap();
    let launcher = prepared.launcher().unwrap();
    let environment = launcher.run("environment").unwrap();
    assert_eq!(environment.status_code, Some(0));
    assert!(environment.stdout.contains("LANG=C"));
    assert!(environment.stdout.contains("HOME="));
    assert!(!environment.stdout.contains("CARGO_MANIFEST_DIR"));
    let bounded = launcher.run("bounded").unwrap();
    assert!(bounded.timed_out);
    assert!(bounded.stdout_truncated);
    assert_eq!(bounded.stdout.len(), 32);
    assert!(launcher.run("not-allowed").is_err());
}

#[test]
fn hard_deny_precedes_external_allow_and_network_capability_is_truthful() {
    let fixture = RepositoryFixture::new();
    let prepared = ReviewPreparer.prepare(&fixture.manifest()).unwrap();
    let launcher = prepared.launcher().unwrap();
    let decision = launcher.decide(
        &PermissionRequest::Network("https://example.invalid".into()),
        ExternalDecision::Allow,
    );
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "network_not_enforced_and_request_denied");
    let source_write = launcher.decide(
        &PermissionRequest::Write(prepared.worktree.path.join("src/lib.rs")),
        ExternalDecision::Allow,
    );
    assert!(!source_write.allowed);
    let ref_write = launcher.decide(&PermissionRequest::GitRefMutation, ExternalDecision::Allow);
    assert!(!ref_write.allowed);
    assert!(!launcher.capabilities().network_isolation_enforced);

    let zcode_read = serde_json::json!({
        "toolName": "read",
        "input": {"path": "src/lib.rs"}
    });
    assert!(
        launcher
            .decide_zcode_permission(&zcode_read, ExternalDecision::Allow)
            .allowed
    );
    let zcode_write = serde_json::json!({
        "toolName": "write",
        "input": {"path": "src/lib.rs"}
    });
    assert!(
        !launcher
            .decide_zcode_permission(&zcode_write, ExternalDecision::Allow)
            .allowed
    );
    let unknown = serde_json::json!({"toolName": "browser", "input": {}});
    assert!(
        !launcher
            .decide_zcode_permission(&unknown, ExternalDecision::Allow)
            .allowed
    );
    for tool in [
        "mcp__review-ledger__review_checkpoint",
        "mcp__review-ledger__review_finding_upsert",
        "mcp__review-ledger__review_validation_record",
        "mcp__review-ledger__review_finalize",
    ] {
        let request = serde_json::json!({"toolName":tool,"input":{}});
        assert!(
            launcher
                .decide_zcode_permission(&request, ExternalDecision::Allow)
                .allowed
        );
        assert!(
            !launcher
                .decide_zcode_permission(&request, ExternalDecision::Deny)
                .allowed
        );
    }
    let arbitrary_mcp = serde_json::json!({
        "toolName":"mcp__review-ledger__unapproved_tool","input":{}
    });
    let arbitrary = launcher.decide_zcode_permission(&arbitrary_mcp, ExternalDecision::Allow);
    assert!(!arbitrary.allowed);
    assert_eq!(arbitrary.reason, "permission_request_unrecognized");
    for variant in [
        "MCP__REVIEW-LEDGER__REVIEW_FINALIZE",
        "mcp__review-ledger__Review_Finalize",
    ] {
        let decision = launcher.decide_zcode_permission(
            &serde_json::json!({"toolName":variant,"input":{}}),
            ExternalDecision::Allow,
        );
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "permission_request_unrecognized");
    }

    let mut network_allowed = fixture.manifest();
    network_allowed.idempotency_key = "feature:S04:network-allow".into();
    network_allowed.network_policy = NetworkPolicy::Allow;
    let allowed = ReviewPreparer.prepare(&network_allowed).unwrap();
    let allowed_launcher = allowed.launcher().unwrap();
    assert!(
        allowed_launcher
            .decide(
                &PermissionRequest::Network("https://example.invalid".into()),
                ExternalDecision::Allow,
            )
            .allowed
    );
    assert!(!allowed_launcher.capabilities().network_isolation_enforced);
    assert!(allowed_launcher
        .capabilities()
        .network_control
        .contains("no network isolation"));
}

#[test]
fn write_permissions_resolve_symlinks_and_validate_move_endpoints() {
    let fixture = RepositoryFixture::new();
    let prepared = ReviewPreparer.prepare(&fixture.manifest()).unwrap();
    let launcher = prepared.launcher().unwrap();
    let scratch = &prepared.scratch_root;

    let external_root = fixture._directory.path().join("external-artifacts");
    fs::create_dir_all(&external_root).unwrap();
    let external_file = external_root.join("outside.txt");
    fs::write(&external_file, "outside").unwrap();
    assert!(
        launcher
            .decide(
                &PermissionRequest::Write(prepared.report_target.clone()),
                ExternalDecision::Allow,
            )
            .allowed
    );
    symlink(&external_file, &prepared.report_target).unwrap();
    assert!(
        !launcher
            .decide(
                &PermissionRequest::Write(prepared.report_target.clone()),
                ExternalDecision::Allow,
            )
            .allowed
    );
    assert!(
        launcher
            .decide(
                &PermissionRequest::Delete(prepared.report_target.clone()),
                ExternalDecision::Allow,
            )
            .allowed
    );
    let external_link = scratch.join("external-link");
    symlink(&external_file, &external_link).unwrap();
    for external in [ExternalDecision::Allow, ExternalDecision::Deny] {
        let decision = launcher.decide(&PermissionRequest::Write(external_link.clone()), external);
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "write_outside_artifact_roots_denied");
    }
    let external_directory_link = scratch.join("external-directory-link");
    symlink(&external_root, &external_directory_link).unwrap();
    assert!(
        !launcher
            .decide(
                &PermissionRequest::Write(external_directory_link.join("new.txt")),
                ExternalDecision::Allow,
            )
            .allowed
    );

    let broken_link = scratch.join("broken-link");
    symlink(external_root.join("missing"), &broken_link).unwrap();
    let broken = launcher.decide(
        &PermissionRequest::Write(broken_link.clone()),
        ExternalDecision::Allow,
    );
    assert!(!broken.allowed);
    assert_eq!(broken.reason, "write_path_unverifiable");
    assert!(
        launcher
            .decide(
                &PermissionRequest::Delete(broken_link),
                ExternalDecision::Allow,
            )
            .allowed
    );

    let loop_a = scratch.join("loop-a");
    let loop_b = scratch.join("loop-b");
    symlink("loop-b", &loop_a).unwrap();
    symlink("loop-a", &loop_b).unwrap();
    assert!(
        !launcher
            .decide(
                &PermissionRequest::Write(loop_a.clone()),
                ExternalDecision::Allow,
            )
            .allowed
    );
    assert!(
        launcher
            .decide(&PermissionRequest::Delete(loop_a), ExternalDecision::Allow)
            .allowed
    );

    let safe_target = scratch.join("safe-target.txt");
    fs::write(&safe_target, "safe").unwrap();
    let safe_link = scratch.join("safe-link");
    symlink("safe-target.txt", &safe_link).unwrap();
    assert!(
        launcher
            .decide(
                &PermissionRequest::Edit(safe_link.clone()),
                ExternalDecision::Allow,
            )
            .allowed
    );
    assert!(
        launcher
            .decide(
                &PermissionRequest::Delete(safe_link),
                ExternalDecision::Allow,
            )
            .allowed
    );
    let safe_edit = serde_json::json!({
        "toolName": "edit",
        "input": {"path": safe_target.clone()}
    });
    assert!(
        launcher
            .decide_zcode_permission(&safe_edit, ExternalDecision::Allow)
            .allowed
    );
    let escaped_edit = serde_json::json!({
        "toolName": "edit",
        "input": {"path": external_link.clone()}
    });
    assert!(
        !launcher
            .decide_zcode_permission(&escaped_edit, ExternalDecision::Allow)
            .allowed
    );
    let external_link_delete = serde_json::json!({
        "toolName": "delete",
        "input": {"path": external_link.clone()}
    });
    assert!(
        launcher
            .decide_zcode_permission(&external_link_delete, ExternalDecision::Allow)
            .allowed
    );

    let scratch_link_to_worktree = scratch.join("link-to-worktree");
    symlink(
        prepared.worktree.path.join("src/lib.rs"),
        &scratch_link_to_worktree,
    )
    .unwrap();
    assert!(
        !launcher
            .decide(
                &PermissionRequest::Write(scratch_link_to_worktree.clone()),
                ExternalDecision::Allow,
            )
            .allowed
    );
    assert!(
        !launcher
            .decide(
                &PermissionRequest::Edit(scratch_link_to_worktree.clone()),
                ExternalDecision::Allow,
            )
            .allowed
    );
    assert!(
        launcher
            .decide(
                &PermissionRequest::Delete(scratch_link_to_worktree.clone()),
                ExternalDecision::Allow,
            )
            .allowed
    );

    let worktree_link_to_scratch = prepared.worktree.path.join("link-to-scratch");
    symlink(&safe_target, &worktree_link_to_scratch).unwrap();
    assert!(
        !launcher
            .decide(
                &PermissionRequest::Write(worktree_link_to_scratch.clone()),
                ExternalDecision::Allow,
            )
            .allowed
    );
    assert!(
        !launcher
            .decide(
                &PermissionRequest::Delete(worktree_link_to_scratch.clone()),
                ExternalDecision::Allow,
            )
            .allowed
    );
    assert!(
        !launcher
            .decide(
                &PermissionRequest::Move {
                    source: worktree_link_to_scratch.clone(),
                    destination: scratch.join("from-worktree-link"),
                },
                ExternalDecision::Allow,
            )
            .allowed
    );
    assert!(
        !launcher
            .decide(
                &PermissionRequest::Move {
                    source: safe_target.clone(),
                    destination: worktree_link_to_scratch,
                },
                ExternalDecision::Allow,
            )
            .allowed
    );
    assert!(
        !launcher
            .decide(
                &PermissionRequest::Move {
                    source: prepared.worktree.path.join("src/lib.rs"),
                    destination: scratch.join("from-worktree-entry"),
                },
                ExternalDecision::Allow,
            )
            .allowed
    );
    assert!(
        !launcher
            .decide(
                &PermissionRequest::Move {
                    source: safe_target.clone(),
                    destination: prepared.worktree.path.join("src/lib.rs"),
                },
                ExternalDecision::Allow,
            )
            .allowed
    );

    let safe_directory = scratch.join("safe-directory");
    fs::create_dir(&safe_directory).unwrap();
    let safe_directory_link = scratch.join("safe-directory-link");
    symlink("safe-directory", &safe_directory_link).unwrap();
    assert!(
        launcher
            .decide(
                &PermissionRequest::Write(safe_directory_link.join("new.txt")),
                ExternalDecision::Allow,
            )
            .allowed
    );
    let nonexistent_leaf = scratch.join("new/deep/output.txt");
    assert!(
        launcher
            .decide(
                &PermissionRequest::Write(nonexistent_leaf.clone()),
                ExternalDecision::Allow,
            )
            .allowed
    );
    assert!(
        !launcher
            .decide(
                &PermissionRequest::Edit(nonexistent_leaf),
                ExternalDecision::Allow,
            )
            .allowed
    );
    assert!(
        !launcher
            .decide(
                &PermissionRequest::Delete(scratch.join("missing-delete")),
                ExternalDecision::Allow,
            )
            .allowed
    );

    let move_destination = scratch.join("moved.txt");
    assert!(
        launcher
            .decide(
                &PermissionRequest::Move {
                    source: safe_target.clone(),
                    destination: move_destination.clone(),
                },
                ExternalDecision::Allow,
            )
            .allowed
    );
    assert!(
        launcher
            .decide(
                &PermissionRequest::Move {
                    source: safe_target.clone(),
                    destination: external_link.clone(),
                },
                ExternalDecision::Allow,
            )
            .allowed
    );
    assert!(
        launcher
            .decide(
                &PermissionRequest::Move {
                    source: external_link.clone(),
                    destination: scratch.join("moved-external-link"),
                },
                ExternalDecision::Allow,
            )
            .allowed
    );
    assert!(
        launcher
            .decide(
                &PermissionRequest::Move {
                    source: scratch_link_to_worktree.clone(),
                    destination: scratch.join("moved-worktree-link"),
                },
                ExternalDecision::Allow,
            )
            .allowed
    );
    assert!(
        launcher
            .decide(
                &PermissionRequest::Move {
                    source: safe_target.clone(),
                    destination: scratch_link_to_worktree,
                },
                ExternalDecision::Allow,
            )
            .allowed
    );
    assert!(
        !launcher
            .decide(
                &PermissionRequest::Move {
                    source: scratch.join("missing-source"),
                    destination: move_destination.clone(),
                },
                ExternalDecision::Allow,
            )
            .allowed
    );

    let zcode_move = serde_json::json!({
        "toolName": "move",
        "input": {
            "source": safe_target,
            "destination": move_destination,
        }
    });
    assert!(
        launcher
            .decide_zcode_permission(&zcode_move, ExternalDecision::Allow)
            .allowed
    );
    let incomplete_move = serde_json::json!({
        "toolName": "move",
        "input": {"source": prepared.scratch_root.join("safe-target.txt")}
    });
    assert!(
        !launcher
            .decide_zcode_permission(&incomplete_move, ExternalDecision::Allow)
            .allowed
    );

    let zcode_external_write = serde_json::json!({
        "toolName": "write",
        "input": {"path": external_link}
    });
    assert_eq!(
        launcher
            .decide_zcode_permission(&zcode_external_write, ExternalDecision::Deny)
            .reason,
        "write_outside_artifact_roots_denied"
    );
}

#[test]
fn integrity_diagnostics_preserve_source_and_enable_recoverable_cleanup() {
    let fixture = RepositoryFixture::new();
    let prepared = ReviewPreparer.prepare(&fixture.manifest()).unwrap();
    let source_before = fs::read_to_string(fixture.repository.join("src/lib.rs")).unwrap();
    fs::write(
        prepared.worktree.path.join("src/lib.rs"),
        "pub fn value() -> u8 { 2 }\n",
    )
    .unwrap();
    let manager = WorktreeManager::new(
        prepared.repository.clone(),
        prepared
            .worktree
            .scratch_worktrees_root
            .parent()
            .unwrap()
            .to_path_buf(),
    )
    .unwrap();
    let diagnostics = manager.capture_integrity(&prepared.worktree).unwrap();
    assert!(diagnostics.source_integrity_preserved());
    assert!(diagnostics.has_policy_violation());
    assert!(diagnostics.tracked_diff.contains("value() -> u8"));
    let record = manager
        .persist_integrity(&prepared.worktree, diagnostics)
        .unwrap();
    assert!(record.is_file());
    let cleaned = manager.cleanup_from_record(&record).unwrap();
    assert!(cleaned.cleaned);
    assert!(!prepared.worktree.path.exists());
    assert_eq!(
        fs::read_to_string(fixture.repository.join("src/lib.rs")).unwrap(),
        source_before
    );
    assert!(manager.cleanup_from_record(&record).unwrap().cleaned);
}

#[test]
fn cleanup_record_is_bound_to_its_repository_job_roots_target_and_head() {
    let first = RepositoryFixture::new();
    let first_prepared = ReviewPreparer.prepare(&first.manifest()).unwrap();
    let first_manager = manager_for(&first_prepared);
    let first_diagnostics = first_manager
        .capture_integrity(&first_prepared.worktree)
        .unwrap();
    let first_record = first_manager
        .persist_integrity(&first_prepared.worktree, first_diagnostics)
        .unwrap();

    let second = RepositoryFixture::new();
    let second_prepared = ReviewPreparer.prepare(&second.manifest()).unwrap();
    let second_manager = manager_for(&second_prepared);
    let second_diagnostics = second_manager
        .capture_integrity(&second_prepared.worktree)
        .unwrap();
    assert!(first_manager
        .persist_integrity(&second_prepared.worktree, second_diagnostics.clone())
        .is_err());
    let second_record = second_manager
        .persist_integrity(&second_prepared.worktree, second_diagnostics)
        .unwrap();
    let mismatched: CleanupRecord =
        serde_json::from_slice(&fs::read(second_record).unwrap()).unwrap();
    fs::write(
        &first_record,
        serde_json::to_vec_pretty(&mismatched).unwrap(),
    )
    .unwrap();

    assert!(matches!(
        first_manager.cleanup_from_record(&first_record),
        Err(PreparationError::Worktree(_))
    ));
    assert!(second_prepared.worktree.path.exists());
    assert!(
        git(&second.repository, &["worktree", "list", "--porcelain"])
            .unwrap()
            .contains(second_prepared.worktree.path.to_str().unwrap())
    );
}

#[test]
fn large_integrity_diff_is_streamed_and_retained_at_the_fixed_cap() {
    const DIAGNOSTIC_CAP: usize = 4 * 1024 * 1024;
    let fixture = RepositoryFixture::new();
    let mut initial = vec![b'a'; DIAGNOSTIC_CAP + 1024 * 1024];
    initial.push(b'\n');
    fs::write(fixture.repository.join("large.txt"), &initial).unwrap();
    git(&fixture.repository, &["add", "large.txt"]).unwrap();
    git(&fixture.repository, &["commit", "-m", "add large fixture"]).unwrap();
    let head = git(&fixture.repository, &["rev-parse", "HEAD"]).unwrap();
    let mut manifest = fixture.manifest();
    manifest.base_ref = head.clone();
    manifest.head_ref = head;
    manifest.scope_paths = vec!["large.txt".into()];
    manifest.idempotency_key = "large-diagnostic".into();
    let prepared = ReviewPreparer.prepare(&manifest).unwrap();

    let mut changed = vec![b'b'; DIAGNOSTIC_CAP + 1024 * 1024];
    changed.push(b'\n');
    fs::write(prepared.worktree.path.join("large.txt"), changed).unwrap();
    let diagnostics = manager_for(&prepared)
        .capture_integrity(&prepared.worktree)
        .unwrap();
    assert!(diagnostics.diagnostic_truncated);
    assert_eq!(diagnostics.tracked_diff.len(), DIAGNOSTIC_CAP);
    assert!(diagnostics.has_policy_violation());
}

#[test]
fn forbidden_command_classes_fail_during_preparation() {
    let fixture = RepositoryFixture::new();
    let mut network = fixture.manifest();
    network
        .validation_commands
        .get_mut("print")
        .unwrap()
        .program = executable("curl");
    network.validation_commands.get_mut("print").unwrap().args =
        vec!["https://example.invalid".into()];
    assert!(matches!(
        ReviewPreparer.prepare(&network),
        Err(PreparationError::Policy(_))
    ));
    assert!(
        !git(&fixture.repository, &["worktree", "list", "--porcelain"])
            .unwrap()
            .contains("/worktrees/")
    );

    let mut git_mutation = fixture.manifest();
    git_mutation
        .validation_commands
        .get_mut("print")
        .unwrap()
        .program = executable("git");
    git_mutation
        .validation_commands
        .get_mut("print")
        .unwrap()
        .args = vec!["commit".into()];
    assert!(matches!(
        ReviewPreparer.prepare(&git_mutation),
        Err(PreparationError::Policy(_))
    ));
    assert!(
        !git(&fixture.repository, &["worktree", "list", "--porcelain"])
            .unwrap()
            .contains("/worktrees/")
    );

    let external_output = fixture._directory.path().join("git-output.txt");
    let mut git_output = fixture.manifest();
    git_output.idempotency_key = "git-output".into();
    git_output
        .validation_commands
        .get_mut("print")
        .unwrap()
        .program = executable("git");
    git_output
        .validation_commands
        .get_mut("print")
        .unwrap()
        .args = vec![
        "diff".into(),
        "--no-ext-diff".into(),
        "--no-textconv".into(),
        format!("--output={}", external_output.display()),
    ];
    assert!(matches!(
        ReviewPreparer.prepare(&git_output),
        Err(PreparationError::Policy(_))
    ));
    assert!(!external_output.exists());

    let mut safe_git = fixture.manifest();
    safe_git.idempotency_key = "safe-git-status".into();
    safe_git
        .validation_commands
        .get_mut("print")
        .unwrap()
        .program = executable("git");
    safe_git.validation_commands.get_mut("print").unwrap().args = vec![
        "status".into(),
        "--porcelain=v1".into(),
        "--untracked-files=no".into(),
        "--".into(),
        "src".into(),
    ];
    let prepared = ReviewPreparer.prepare(&safe_git).unwrap();
    assert_eq!(
        prepared
            .launcher()
            .unwrap()
            .run("print")
            .unwrap()
            .status_code,
        Some(0)
    );
}

fn manager_for(prepared: &review_preparation::PreparedLaunchSpec) -> WorktreeManager {
    WorktreeManager::new(
        prepared.repository.clone(),
        prepared
            .worktree
            .scratch_worktrees_root
            .parent()
            .unwrap()
            .to_path_buf(),
    )
    .unwrap()
}

fn executable(name: &str) -> PathBuf {
    [
        PathBuf::from("/usr/bin").join(name),
        PathBuf::from("/bin").join(name),
    ]
    .into_iter()
    .find(|path| path.is_file())
    .unwrap_or_else(|| panic!("required test executable {name} is unavailable"))
}

fn git(repository: &Path, arguments: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().into())
}
