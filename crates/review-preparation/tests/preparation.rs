use review_preparation::{
    ExternalDecision, NetworkPolicy, PermissionRequest, PreparationError, ReviewKind,
    ReviewManifest, ReviewPreparer, RoundKind, SandboxEnforcement, ScratchPolicy,
    ValidationCommand, WorktreeManager,
};
use std::{
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
            validation_commands: vec![ValidationCommand {
                id: "print".into(),
                program: executable("printf"),
                args: vec!["prepared".into()],
                cwd: ".".into(),
                timeout_ms: 1_000,
                max_output_bytes: 1_024,
            }],
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
fn launcher_sanitizes_environment_bounds_output_and_times_out() {
    let fixture = RepositoryFixture::new();
    let mut manifest = fixture.manifest();
    manifest.validation_commands = vec![
        ValidationCommand {
            id: "environment".into(),
            program: executable("env"),
            args: Vec::new(),
            cwd: ".".into(),
            timeout_ms: 1_000,
            max_output_bytes: 4_096,
        },
        ValidationCommand {
            id: "bounded".into(),
            program: executable("yes"),
            args: Vec::new(),
            cwd: ".".into(),
            timeout_ms: 25,
            max_output_bytes: 32,
        },
    ];
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
fn forbidden_command_classes_fail_during_preparation() {
    let fixture = RepositoryFixture::new();
    let mut network = fixture.manifest();
    network.validation_commands[0].program = executable("curl");
    network.validation_commands[0].args = vec!["https://example.invalid".into()];
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
    git_mutation.validation_commands[0].program = executable("git");
    git_mutation.validation_commands[0].args = vec!["commit".into()];
    assert!(matches!(
        ReviewPreparer.prepare(&git_mutation),
        Err(PreparationError::Policy(_))
    ));
    assert!(
        !git(&fixture.repository, &["worktree", "list", "--porcelain"])
            .unwrap()
            .contains("/worktrees/")
    );
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
