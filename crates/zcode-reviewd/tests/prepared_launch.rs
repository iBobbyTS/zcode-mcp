use review_preparation::{
    NetworkPolicy, ReviewKind, ReviewManifest, ReviewPreparer, RoundKind, ScratchPolicy,
};
use review_store::Store;
use std::{
    fs, io,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tempfile::TempDir;
use zcode_reviewd::{
    CommandRuntimeFactory, LifecycleRecord, LifecycleSink, ManagedRuntime, RuntimeFactory,
    Scheduler, SchedulerConfig,
};

struct UnusedFactory;

struct NullSink;

impl LifecycleSink for NullSink {
    fn emit(&self, _record: LifecycleRecord) {}
}

impl RuntimeFactory for UnusedFactory {
    fn spawn(
        &self,
        _job: &review_store::Job,
        _sink: Arc<dyn LifecycleSink>,
    ) -> io::Result<Arc<dyn ManagedRuntime>> {
        Err(io::Error::other(
            "runtime must not start during preparation",
        ))
    }
}

#[test]
fn prepared_launch_is_the_only_workspace_consumed_by_scheduler_adapter() {
    let directory = tempfile::tempdir().unwrap();
    let repository = create_repository(&directory);
    let head = git(&repository, &["rev-parse", "HEAD"]);
    let manifest = ReviewManifest {
        schema: "sectioned-zcode-review/v1".into(),
        review_kind: ReviewKind::Code,
        feature_id: "feature".into(),
        section_id: "S04".into(),
        round_kind: RoundKind::InitialBounded,
        repository: repository.clone(),
        base_ref: head.clone(),
        head_ref: head,
        plan_path: ".agent-work/PLAN.md".into(),
        context_paths: Vec::new(),
        scope_paths: vec!["src".into()],
        forbidden_input_globs: Vec::new(),
        validation_commands: Default::default(),
        report_target: ".agent-work/reviews/feature/S04/report.md".into(),
        scratch_root: ".agent-work/scratch/jobs".into(),
        model: None,
        fresh_session: true,
        network_policy: NetworkPolicy::Deny,
        scratch_policy: ScratchPolicy::Isolated,
        idempotency_key: "feature:S04:initial".into(),
    };
    let prepared = ReviewPreparer.prepare(&manifest).unwrap();
    let store = Arc::new(Store::open(directory.path().join("review.sqlite3")).unwrap());
    let scheduler = Scheduler::new(
        "prepared-test",
        Arc::clone(&store),
        Arc::new(UnusedFactory),
        SchedulerConfig::default(),
    )
    .unwrap();
    let job = scheduler
        .enqueue_prepared("prepared-job", "review the accepted section", &prepared)
        .unwrap();
    assert_eq!(job.workspace_path, prepared.worktree.path.to_string_lossy());
    assert_eq!(
        job.prepared_launch_sha256,
        Some(prepared.prepared_sha256.clone())
    );
    assert_eq!(
        job.prepared_launch_json.as_deref(),
        Some(prepared.canonical_json().unwrap().as_str())
    );
    assert_eq!(store.active_count().unwrap(), 0);

    let same = scheduler
        .enqueue_prepared("different-agent", "different ignored prompt", &prepared)
        .unwrap();
    assert_eq!(same.agent_id, "prepared-job");

    let mut changed = manifest;
    changed.scope_paths = vec!["src/lib.rs".into()];
    assert!(ReviewPreparer.prepare(&changed).is_err());

    fs::write(
        prepared.repository.join("src/lib.rs"),
        "pub fn unexpected_user_change() {}\n",
    )
    .unwrap();
    assert!(scheduler
        .enqueue_prepared("after-source-change", "review", &prepared)
        .is_err());
}

#[test]
fn production_factory_rejects_unprepared_job_before_command_construction() {
    let called = Arc::new(AtomicBool::new(false));
    let callback_called = Arc::clone(&called);
    let factory = CommandRuntimeFactory::new_prepared(
        move |_job: &review_store::Job| -> io::Result<Command> {
            callback_called.store(true, Ordering::Release);
            Ok(Command::new("/usr/bin/false"))
        },
    );
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path().join("raw.sqlite3")).unwrap();
    let raw = store
        .enqueue_job(&review_store::NewJob::new("raw", "/unprepared"))
        .unwrap();
    assert!(factory.spawn(&raw, Arc::new(NullSink)).is_err());
    assert!(!called.load(Ordering::Acquire));
}

fn create_repository(directory: &TempDir) -> PathBuf {
    let repository = directory.path().join("repository");
    fs::create_dir_all(repository.join("src")).unwrap();
    fs::write(repository.join("src/lib.rs"), "pub fn fixture() {}\n").unwrap();
    git(&repository, &["init"]);
    git(&repository, &["config", "user.name", "S04 Test"]);
    git(
        &repository,
        &["config", "user.email", "s04@example.invalid"],
    );
    git(&repository, &["add", "src/lib.rs"]);
    git(&repository, &["commit", "-m", "fixture"]);
    fs::create_dir_all(repository.join(".agent-work")).unwrap();
    fs::write(repository.join(".agent-work/PLAN.md"), "# plan\n").unwrap();
    fs::canonicalize(repository).unwrap()
}

fn git(repository: &Path, arguments: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().into()
}
