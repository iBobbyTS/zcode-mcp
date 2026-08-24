use crate::{prompts::build_review_prompt, ReviewFailure, Scheduler, SchedulerError};
use review_ledger::{ArtifactIntegrity, LedgerManager};
use review_preparation::{PreparedLaunchSpec, ReviewManifest, ReviewPreparer, WorktreeManager};
use review_store::{Job, StoreError};
use std::{
    fmt,
    path::PathBuf,
    sync::{Arc, Mutex},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnedReview {
    pub job: Job,
    pub prompt_sha256: String,
    pub resumed_existing: bool,
}

#[derive(Debug)]
pub enum OrchestrationError {
    Preparation(String),
    Prompt(String),
    Scheduler(SchedulerError),
    Store(StoreError),
    Unavailable(&'static str),
}

impl fmt::Display for OrchestrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Preparation(message) => write!(formatter, "review preparation failed: {message}"),
            Self::Prompt(message) => write!(formatter, "review prompt failed: {message}"),
            Self::Scheduler(error) => write!(formatter, "review scheduling failed: {error}"),
            Self::Store(error) => write!(formatter, "review state failed: {error}"),
            Self::Unavailable(message) => {
                write!(formatter, "review orchestration unavailable: {message}")
            }
        }
    }
}

impl std::error::Error for OrchestrationError {}

#[derive(Clone)]
pub struct ReviewJobOrchestrator {
    scheduler: Scheduler,
    spawn_lock: Arc<Mutex<()>>,
}

impl ReviewJobOrchestrator {
    pub fn new(scheduler: Scheduler) -> Result<Self, OrchestrationError> {
        if scheduler.ledger().is_none() || !scheduler.review_completion_enabled() {
            return Err(OrchestrationError::Unavailable(
                "scheduler has no job-scoped ledger completion gate",
            ));
        }
        Ok(Self {
            scheduler,
            spawn_lock: Arc::new(Mutex::new(())),
        })
    }

    pub fn spawn_review(
        &self,
        manifest: &ReviewManifest,
    ) -> Result<SpawnedReview, OrchestrationError> {
        let prepared = ReviewPreparer
            .prepare(manifest)
            .map_err(|error| OrchestrationError::Preparation(error.to_string()))?;
        let prompt = build_review_prompt(&prepared)
            .map_err(|error| OrchestrationError::Prompt(error.to_string()))?;
        let agent_id = format!("review-{}", prepared.prepared_sha256);
        let _guard = self
            .spawn_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self
            .scheduler
            .store()
            .get_job(&agent_id)
            .map_err(OrchestrationError::Store)?
            .is_some()
        {
            let _ = self.scheduler.start_ready();
            let job = self
                .scheduler
                .store()
                .get_job(&agent_id)
                .map_err(OrchestrationError::Store)?
                .ok_or_else(|| OrchestrationError::Unavailable("scheduled job disappeared"))?;
            return Ok(SpawnedReview {
                job,
                prompt_sha256: prompt.sha256,
                resumed_existing: true,
            });
        }
        let stored = self
            .scheduler
            .enqueue_prepared(agent_id, prompt.text, &prepared)
            .map_err(OrchestrationError::Scheduler)?;

        // Starting is intentionally automatic. Runtime/session failures are durable
        // job outcomes, so callers still receive the stable job identifier.
        let _ = self.scheduler.start_ready();
        let job = self
            .scheduler
            .store()
            .get_job(&stored.agent_id)
            .map_err(OrchestrationError::Store)?
            .ok_or_else(|| OrchestrationError::Unavailable("scheduled job disappeared"))?;
        Ok(SpawnedReview {
            job,
            prompt_sha256: prompt.sha256,
            resumed_existing: false,
        })
    }
}

pub(crate) struct ReviewCompletionGate {
    ledger: Arc<LedgerManager>,
    cleanup_lock: Mutex<()>,
}

impl ReviewCompletionGate {
    pub(crate) fn new(ledger: Arc<LedgerManager>) -> Self {
        Self {
            ledger,
            cleanup_lock: Mutex::new(()),
        }
    }

    pub(crate) fn complete(&self, job: &Job) -> Result<(), ReviewFailure> {
        let _guard = self.cleanup_lock.lock().unwrap();
        let prepared = self.prepared(job)?;
        let manager = self.manager(&prepared)?;
        let diagnostics = manager
            .capture_integrity(&prepared.worktree)
            .map_err(|_| ReviewFailure::SourceIntegrity)?;
        let source_valid = !diagnostics.has_policy_violation();
        let record = manager
            .persist_integrity(&prepared.worktree, diagnostics)
            .map_err(|_| ReviewFailure::CleanupFailed)?;

        let report_result = self.validate_report(job);
        let cleanup_result = manager
            .cleanup_from_record(&record)
            .map_err(|_| ReviewFailure::CleanupFailed);
        if !source_valid {
            return Err(ReviewFailure::SourceIntegrity);
        }
        report_result?;
        cleanup_result?;
        Ok(())
    }

    pub(crate) fn cleanup_nonclean(&self, job: &Job) -> Result<(), ReviewFailure> {
        let _guard = self.cleanup_lock.lock().unwrap();
        let prepared = self.prepared(job)?;
        let manager = self.manager(&prepared)?;
        let worktree_name = prepared
            .worktree
            .path
            .file_name()
            .ok_or(ReviewFailure::PreparedLaunchInvalid)?;
        let record = prepared
            .worktree
            .diagnostic_root
            .join(format!("{}.json", worktree_name.to_string_lossy()));
        if record.is_file() {
            manager
                .cleanup_from_record(&record)
                .map_err(|_| ReviewFailure::CleanupFailed)?;
            return Ok(());
        }
        if !prepared.worktree.path.exists() {
            return Ok(());
        }
        let diagnostics = manager
            .capture_integrity(&prepared.worktree)
            .map_err(|_| ReviewFailure::SourceIntegrity)?;
        let record = manager
            .persist_integrity(&prepared.worktree, diagnostics)
            .map_err(|_| ReviewFailure::CleanupFailed)?;
        manager
            .cleanup_from_record(&record)
            .map_err(|_| ReviewFailure::CleanupFailed)?;
        Ok(())
    }

    fn validate_report(&self, job: &Job) -> Result<(), ReviewFailure> {
        let snapshot = self
            .ledger
            .store()
            .review_snapshot(&job.agent_id)
            .map_err(|_| ReviewFailure::ReportInvalid)?
            .ok_or(ReviewFailure::ReportMissing)?;
        if !snapshot.report.finalized || snapshot.finalization.is_none() {
            return Err(ReviewFailure::MissingFinalization);
        }
        if snapshot.checkpoints.is_empty() || snapshot.validations.is_empty() {
            return Err(ReviewFailure::EvidenceIncomplete);
        }
        if snapshot.provenance.zcode_session_id.as_deref() != job.zcode_session_id.as_deref()
            || snapshot.provenance.zcode_session_id.is_none()
        {
            return Err(ReviewFailure::ProvenanceMismatch);
        }
        let artifact = self
            .ledger
            .verify_artifact(&job.agent_id, 256)
            .map_err(|_| ReviewFailure::ReportInvalid)?;
        if artifact.integrity != ArtifactIntegrity::Valid
            || !artifact.finalized
            || artifact.expected_sha256 != artifact.actual_sha256
            || artifact.expected_bytes != artifact.actual_bytes
            || artifact
                .preview
                .as_deref()
                .is_none_or(|preview| !preview.starts_with("# ZCode Review Report"))
        {
            return Err(ReviewFailure::ReportInvalid);
        }
        Ok(())
    }

    fn prepared(&self, job: &Job) -> Result<PreparedLaunchSpec, ReviewFailure> {
        let json = job
            .prepared_launch_json
            .as_deref()
            .ok_or(ReviewFailure::PreparedLaunchInvalid)?;
        let prepared: PreparedLaunchSpec =
            serde_json::from_str(json).map_err(|_| ReviewFailure::PreparedLaunchInvalid)?;
        prepared
            .validate_digest()
            .map_err(|_| ReviewFailure::PreparedLaunchInvalid)?;
        if job.prepared_launch_sha256.as_deref() != Some(prepared.prepared_sha256.as_str()) {
            return Err(ReviewFailure::PreparedLaunchInvalid);
        }
        Ok(prepared)
    }

    fn manager(&self, prepared: &PreparedLaunchSpec) -> Result<WorktreeManager, ReviewFailure> {
        let job_root = prepared
            .worktree
            .scratch_worktrees_root
            .parent()
            .map(PathBuf::from)
            .ok_or(ReviewFailure::PreparedLaunchInvalid)?;
        WorktreeManager::new(prepared.repository.clone(), job_root)
            .map_err(|_| ReviewFailure::PreparedLaunchInvalid)
    }
}
