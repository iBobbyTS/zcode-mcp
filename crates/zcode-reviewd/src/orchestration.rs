use crate::{
    prompts::{build_review_continuation_prompt, build_review_prompt, ReviewPrompt},
    ReviewFailure, Scheduler, SchedulerError,
};
use review_ledger::{ArtifactIntegrity, LedgerManager};
use review_preparation::{
    BudgetLimits, CompletionOutcome, GeneralCompletion, GeneralCompletionSubmission,
    GeneralFinalizer, PreparedGeneralTask, PreparedLaunchSpec, ReviewKind, ReviewManifest,
    ReviewPreparer, RoundKind, WorktreeManager,
};
use review_store::{
    resolve_effective_budget, BudgetRequest, EffectiveBudget, Job, NewJob, NewTask, StoreError,
    TaskKind, TaskOutcome, TaskPhase, TaskQueryScope, TaskRecord, TaskResult,
};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StructuredReviewKind {
    PlanReview,
    InitialBounded,
    RepairDelta,
    FinalBounded,
}

impl StructuredReviewKind {
    fn manifest_contract(self) -> (ReviewKind, RoundKind) {
        match self {
            Self::PlanReview => (ReviewKind::Plan, RoundKind::PlanReview),
            Self::InitialBounded => (ReviewKind::Code, RoundKind::InitialBounded),
            Self::RepairDelta => (ReviewKind::Code, RoundKind::RepairDelta),
            Self::FinalBounded => (ReviewKind::Code, RoundKind::FinalBounded),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredReviewSubmission {
    pub review_kind: StructuredReviewKind,
    pub manifest: ReviewManifest,
    pub ownership_token: String,
    pub read_only: bool,
    #[serde(default, deserialize_with = "deserialize_optional_budget")]
    pub budget: Option<BudgetLimits>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredReviewContinuation {
    pub agent_id: String,
    pub review_id: String,
    pub review_kind: StructuredReviewKind,
    pub manifest: ReviewManifest,
    pub frozen_finding_ids: Vec<String>,
    pub read_only: bool,
    #[serde(default, deserialize_with = "deserialize_optional_budget")]
    pub budget: Option<BudgetLimits>,
}

fn deserialize_optional_budget<'de, D>(deserializer: D) -> Result<Option<BudgetLimits>, D::Error>
where
    D: Deserializer<'de>,
{
    BudgetLimits::deserialize(deserializer).map(Some)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewSubmissionDisposition {
    Created,
    Existing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredReviewProvenance {
    pub review_kind: StructuredReviewKind,
    pub manifest_sha256: String,
    pub prepared_sha256: String,
    pub prompt_sha256: String,
    pub base_sha: String,
    pub head_sha: String,
    pub requested_model: Option<String>,
    pub fresh_session_observed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredReviewProjection {
    pub agent_id: String,
    pub review_id: String,
    pub submission_disposition: ReviewSubmissionDisposition,
    pub phase: String,
    pub attempt_sequence: u64,
    pub effective_budget: EffectiveBudget,
    pub counts_as_independent: bool,
    pub provenance: StructuredReviewProvenance,
}

/// Daemon-owned typed boundary for general-task completion. Runtime ingress is
/// added in S03; callers cannot supply a worktree or Git command here.
pub struct GeneralCompletionGate;

impl GeneralCompletionGate {
    pub fn complete(
        prepared: &PreparedGeneralTask,
        submission: &GeneralCompletionSubmission,
    ) -> GeneralCompletion {
        GeneralFinalizer::finalize_submission(prepared, submission)
    }

    pub fn terminalize(
        prepared: &PreparedGeneralTask,
        outcome: CompletionOutcome,
    ) -> GeneralCompletion {
        GeneralFinalizer::finalize(prepared, outcome)
    }
}

#[derive(Debug)]
pub enum OrchestrationError {
    Contract(&'static str),
    Conflict(&'static str),
    Preparation(String),
    Prompt(String),
    Scheduler(SchedulerError),
    Store(StoreError),
    Unavailable(&'static str),
}

impl fmt::Display for OrchestrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(message) => write!(formatter, "review contract rejected: {message}"),
            Self::Conflict(message) => write!(formatter, "review submission conflicts: {message}"),
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

    pub fn submit_structured_review(
        &self,
        input: &StructuredReviewSubmission,
    ) -> Result<StructuredReviewProjection, OrchestrationError> {
        self.submit_structured_mode(input, false)
    }

    pub fn spawn_structured_review(
        &self,
        input: &StructuredReviewSubmission,
    ) -> Result<StructuredReviewProjection, OrchestrationError> {
        self.submit_structured_mode(input, true)
    }

    pub fn submit_structured_continuation(
        &self,
        input: &StructuredReviewContinuation,
    ) -> Result<StructuredReviewProjection, OrchestrationError> {
        self.submit_continuation_mode(input, false)
    }

    pub fn spawn_structured_continuation(
        &self,
        input: &StructuredReviewContinuation,
    ) -> Result<StructuredReviewProjection, OrchestrationError> {
        self.submit_continuation_mode(input, true)
    }

    fn submit_structured_mode(
        &self,
        input: &StructuredReviewSubmission,
        start: bool,
    ) -> Result<StructuredReviewProjection, OrchestrationError> {
        validate_structured_contract(
            input.review_kind,
            &input.manifest,
            input.read_only,
            Some(&input.ownership_token),
        )?;
        self.require_structured_review_owner()?;
        let _guard = self
            .spawn_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let public_agent_id = derived_id("review-agent", &input.manifest.idempotency_key);
        let review_id = derived_id("review", &input.manifest.idempotency_key);
        let execution_agent_id = derived_id("review-attempt", &input.manifest.idempotency_key);
        let budget = store_budget(input.budget.as_ref());
        if let Some(existing) = self.replay_projection(
            &execution_agent_id,
            &public_agent_id,
            &review_id,
            TaskKind::Review,
            None,
            &input.ownership_token,
            input.review_kind,
            &input.manifest,
            &[],
            &budget,
            start,
        )? {
            return Ok(existing);
        }
        let prepared = ReviewPreparer
            .prepare(&input.manifest)
            .map_err(|error| OrchestrationError::Preparation(error.to_string()))?;
        let prompt = match build_review_prompt(&prepared) {
            Ok(prompt) => prompt,
            Err(error) => {
                cleanup_prepared(&prepared)?;
                return Err(OrchestrationError::Prompt(error.to_string()));
            }
        };
        self.enqueue_structured_attempt(
            StructuredAttempt {
                execution_agent_id,
                public_agent_id,
                review_id,
                task_kind: TaskKind::Review,
                parent_execution_id: None,
                ownership_token: input.ownership_token.clone(),
                budget,
                review_kind: input.review_kind,
            },
            &prepared,
            prompt,
            start,
        )
    }

    fn submit_continuation_mode(
        &self,
        input: &StructuredReviewContinuation,
        start: bool,
    ) -> Result<StructuredReviewProjection, OrchestrationError> {
        validate_structured_contract(input.review_kind, &input.manifest, input.read_only, None)?;
        validate_frozen_finding_ids(&input.frozen_finding_ids)?;
        self.require_structured_review_owner()?;
        let _guard = self
            .spawn_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let execution_agent_id = derived_id("review-attempt", &input.manifest.idempotency_key);
        let budget = store_budget(input.budget.as_ref());
        let store = self.scheduler.store();
        if let Some(existing_task) = store
            .task_by_execution_agent_id(&execution_agent_id)
            .map_err(OrchestrationError::Store)?
        {
            let existing = self.replay_projection(
                &execution_agent_id,
                &input.agent_id,
                &input.review_id,
                TaskKind::ReviewContinuation,
                existing_task.continuation_of.as_deref(),
                &existing_task.ownership_token,
                input.review_kind,
                &input.manifest,
                &input.frozen_finding_ids,
                &budget,
                start,
            )?;
            return existing.ok_or(OrchestrationError::Conflict(
                "idempotent continuation metadata has no job",
            ));
        }
        if store
            .get_job(&execution_agent_id)
            .map_err(OrchestrationError::Store)?
            .is_some()
        {
            return Err(OrchestrationError::Conflict(
                "idempotent continuation identity is incomplete",
            ));
        }
        let context = self.continuation_context(input)?;
        if let Some(existing) = self.replay_projection(
            &execution_agent_id,
            &input.agent_id,
            &input.review_id,
            TaskKind::ReviewContinuation,
            Some(&context.parent.execution_agent_id),
            &context.parent.ownership_token,
            input.review_kind,
            &input.manifest,
            &input.frozen_finding_ids,
            &budget,
            start,
        )? {
            return Ok(existing);
        }
        let prepared = ReviewPreparer
            .prepare(&input.manifest)
            .map_err(|error| OrchestrationError::Preparation(error.to_string()))?;
        if let Err(error) = validate_continuation_prepared(&context, &prepared) {
            cleanup_prepared(&prepared)?;
            return Err(error);
        }
        let prompt = match build_review_continuation_prompt(&prepared, &input.frozen_finding_ids) {
            Ok(prompt) => prompt,
            Err(error) => {
                cleanup_prepared(&prepared)?;
                return Err(OrchestrationError::Prompt(error.to_string()));
            }
        };
        self.enqueue_structured_attempt(
            StructuredAttempt {
                execution_agent_id,
                public_agent_id: input.agent_id.clone(),
                review_id: input.review_id.clone(),
                task_kind: TaskKind::ReviewContinuation,
                parent_execution_id: Some(context.parent.execution_agent_id),
                ownership_token: context.parent.ownership_token,
                budget,
                review_kind: input.review_kind,
            },
            &prepared,
            prompt,
            start,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn replay_projection(
        &self,
        execution_agent_id: &str,
        public_agent_id: &str,
        review_id: &str,
        task_kind: TaskKind,
        parent_execution_id: Option<&str>,
        ownership_token: &str,
        review_kind: StructuredReviewKind,
        manifest: &ReviewManifest,
        frozen_finding_ids: &[String],
        budget: &BudgetRequest,
        start: bool,
    ) -> Result<Option<StructuredReviewProjection>, OrchestrationError> {
        let store = self.scheduler.store();
        let Some(job) = store
            .get_job(execution_agent_id)
            .map_err(OrchestrationError::Store)?
        else {
            return Ok(None);
        };
        let task = store
            .task_by_execution_agent_id(execution_agent_id)
            .map_err(OrchestrationError::Store)?
            .ok_or(OrchestrationError::Conflict(
                "idempotency identity is not a structured review attempt",
            ))?;
        let prepared = prepared_from_job(&job)?;
        let expected_manifest_sha = manifest_sha256(manifest)?;
        let expected_budget =
            resolve_effective_budget(budget).map_err(OrchestrationError::Store)?;
        let prompt = if task_kind == TaskKind::ReviewContinuation {
            build_review_continuation_prompt(&prepared, frozen_finding_ids)
        } else {
            build_review_prompt(&prepared)
        }
        .map_err(|error| OrchestrationError::Prompt(error.to_string()))?;
        let valid = job.idempotency_key.as_deref() == Some(manifest.idempotency_key.as_str())
            && job.initial_prompt == prompt.text
            && prepared.manifest_sha256 == expected_manifest_sha
            && prepared.review_kind == manifest.review_kind
            && prepared.round_kind == manifest.round_kind
            && task.public_agent_id == public_agent_id
            && task.review_id.as_deref() == Some(review_id)
            && task.task_kind == task_kind
            && task.continuation_of.as_deref() == parent_execution_id
            && task.ownership_token == ownership_token
            && task.feature_id == manifest.feature_id
            && task.effective_budget == expected_budget;
        if !valid {
            return Err(OrchestrationError::Conflict(
                "idempotency key names a different structured review",
            ));
        }
        if start {
            let _ = self.scheduler.start_ready();
        }
        let job = store
            .get_job(execution_agent_id)
            .map_err(OrchestrationError::Store)?
            .ok_or(OrchestrationError::Unavailable(
                "idempotent review attempt disappeared",
            ))?;
        let task = store
            .task_by_execution_agent_id(execution_agent_id)
            .map_err(OrchestrationError::Store)?
            .ok_or(OrchestrationError::Unavailable(
                "idempotent review metadata disappeared",
            ))?;
        Ok(Some(structured_projection(
            job,
            task,
            &prepared,
            &prompt,
            review_kind,
            ReviewSubmissionDisposition::Existing,
        )))
    }

    fn continuation_context(
        &self,
        input: &StructuredReviewContinuation,
    ) -> Result<ContinuationContext, OrchestrationError> {
        validate_identifier(&input.agent_id, "agent_id")?;
        validate_identifier(&input.review_id, "review_id")?;
        let store = self.scheduler.store();
        let parent = store
            .get_task_scoped(
                &input.agent_id,
                TaskQueryScope {
                    repository: None,
                    feature_id: Some(&input.manifest.feature_id),
                    ownership_token: None,
                },
            )
            .map_err(OrchestrationError::Store)?
            .ok_or(OrchestrationError::Conflict(
                "continuation parent was not found in the requested feature",
            ))?;
        if parent.public_agent_id != input.agent_id
            || parent.review_id.as_deref() != Some(input.review_id.as_str())
            || !matches!(
                parent.task_kind,
                TaskKind::Review | TaskKind::ReviewContinuation
            )
        {
            return Err(OrchestrationError::Conflict(
                "continuation identity is incompatible",
            ));
        }
        let parent_job = store
            .get_job(&parent.execution_agent_id)
            .map_err(OrchestrationError::Store)?
            .ok_or(OrchestrationError::Conflict(
                "continuation parent job is missing",
            ))?;
        if parent.phase != TaskPhase::Terminal || parent_job.closed_at.is_some() {
            return Err(OrchestrationError::Conflict(
                "continuation parent is active or closed",
            ));
        }
        let snapshot = store
            .review_snapshot(&parent.execution_agent_id)
            .map_err(OrchestrationError::Store)?;
        let terminal_result = store
            .task_result(&parent.execution_agent_id)
            .map_err(OrchestrationError::Store)?
            .ok_or(OrchestrationError::Conflict(
                "continuation parent has no immutable terminal result",
            ))?;
        if terminal_result.result.outcome == TaskOutcome::ResultInvalid {
            return Err(OrchestrationError::Conflict(
                "result-invalid reviews cannot continue",
            ));
        }
        let eligible_signal = snapshot.as_ref().is_some_and(|snapshot| {
            snapshot.report.finalized
                && snapshot.finalization.is_some()
                && snapshot.report.final_signal.as_ref().is_some_and(|signal| {
                    matches!(
                        signal.as_str(),
                        "findings_present"
                            | "no_findings_observed"
                            | "incomplete_evidence"
                            | "unable_to_review"
                    )
                })
        });
        let eligible_runtime = matches!(
            terminal_result.result.outcome,
            TaskOutcome::Failed
                | TaskOutcome::Cancelled
                | TaskOutcome::TimedOut
                | TaskOutcome::BudgetExhausted
                | TaskOutcome::RuntimeLost
        );
        if !eligible_signal && !eligible_runtime {
            return Err(OrchestrationError::Conflict(
                "continuation parent has no eligible terminal evidence",
            ));
        }
        if !input.frozen_finding_ids.is_empty() {
            let snapshot = snapshot.as_ref().ok_or(OrchestrationError::Conflict(
                "frozen findings have no parent ledger",
            ))?;
            let available = snapshot
                .findings
                .iter()
                .map(|finding| finding.stable_id.as_str())
                .collect::<HashSet<_>>();
            if input
                .frozen_finding_ids
                .iter()
                .any(|finding| !available.contains(finding.as_str()))
            {
                return Err(OrchestrationError::Conflict(
                    "frozen finding does not exist in the parent ledger",
                ));
            }
        }

        let mut cursor = Some(parent.execution_agent_id.clone());
        let mut seen = HashSet::new();
        let mut allowed_bases = HashSet::new();
        let mut report_targets = HashSet::new();
        let mut inherited_scope = None;
        let mut inherited_review_kind = None;
        let mut inherited_section = None;
        while let Some(execution_id) = cursor {
            if !seen.insert(execution_id.clone()) || seen.len() > 1_024 {
                return Err(OrchestrationError::Conflict(
                    "continuation lineage is cyclic or unbounded",
                ));
            }
            let attempt = store
                .task_by_execution_agent_id(&execution_id)
                .map_err(OrchestrationError::Store)?
                .ok_or(OrchestrationError::Conflict(
                    "continuation lineage attempt is missing",
                ))?;
            if attempt.public_agent_id != input.agent_id
                || attempt.review_id.as_deref() != Some(input.review_id.as_str())
            {
                return Err(OrchestrationError::Conflict(
                    "continuation lineage changes stable identity",
                ));
            }
            let job = store
                .get_job(&execution_id)
                .map_err(OrchestrationError::Store)?
                .ok_or(OrchestrationError::Conflict(
                    "continuation lineage job is missing",
                ))?;
            let prepared = prepared_from_job(&job)?;
            allowed_bases.insert(prepared.base_sha.clone());
            allowed_bases.insert(prepared.head_sha.clone());
            report_targets.insert(prepared.report_target.clone());
            let current_scope = prepared
                .scope
                .iter()
                .map(|scope| scope.repository_relative.clone())
                .collect::<Vec<_>>();
            if inherited_scope
                .as_ref()
                .is_some_and(|scope| scope != &current_scope)
                || inherited_review_kind
                    .is_some_and(|review_kind| review_kind != prepared.review_kind)
                || inherited_section
                    .as_ref()
                    .is_some_and(|section| section != &prepared.section_id)
            {
                return Err(OrchestrationError::Conflict(
                    "continuation lineage changes its review contract",
                ));
            }
            inherited_scope.get_or_insert(current_scope);
            inherited_review_kind.get_or_insert(prepared.review_kind);
            inherited_section.get_or_insert(prepared.section_id.clone());
            cursor = attempt.continuation_of;
        }
        Ok(ContinuationContext {
            parent,
            allowed_bases,
            report_targets,
            scope: inherited_scope.unwrap_or_default(),
            review_kind: inherited_review_kind.ok_or(OrchestrationError::Conflict(
                "continuation lineage has no review contract",
            ))?,
            section_id: inherited_section.ok_or(OrchestrationError::Conflict(
                "continuation lineage has no section identity",
            ))?,
        })
    }

    fn enqueue_structured_attempt(
        &self,
        attempt: StructuredAttempt,
        prepared: &PreparedLaunchSpec,
        prompt: ReviewPrompt,
        start: bool,
    ) -> Result<StructuredReviewProjection, OrchestrationError> {
        let mut job = NewJob::new(
            attempt.execution_agent_id.clone(),
            prepared.worktree.path.to_string_lossy(),
        );
        job.idempotency_key = Some(prepared.idempotency_key.clone());
        job.parent_agent_id = attempt.parent_execution_id.clone();
        job.review_kind = Some(prepared.review_kind.as_str().into());
        job.feature_id = Some(prepared.feature_id.clone());
        job.section_id = Some(prepared.section_id.clone());
        job.round_kind = Some(prepared.round_kind.as_str().into());
        job.report_path = Some(prepared.report_target.to_string_lossy().into_owned());
        let runtime_hash = self.scheduler.review_runtime_hash();
        job.runtime_hash = runtime_hash.clone();
        job.initial_prompt = prompt.text.clone();
        job.prepared_launch_json = Some(
            prepared
                .canonical_json()
                .map_err(|error| OrchestrationError::Preparation(error.to_string()))?,
        );
        job.prepared_launch_sha256 = Some(prepared.prepared_sha256.clone());
        let store = self.scheduler.store();
        let task = NewTask {
            job,
            public_agent_id: attempt.public_agent_id,
            task_kind: attempt.task_kind,
            review_id: Some(attempt.review_id),
            continuation_of: attempt.parent_execution_id,
            repository: prepared.repository.to_string_lossy().into_owned(),
            feature_id: prepared.feature_id.clone(),
            ownership_token: attempt.ownership_token,
            budget: attempt.budget,
            retain_partial: false,
        };
        let (job, task_record) = match store.enqueue_task(&task) {
            Ok(stored) => stored,
            Err(error) => {
                if store
                    .get_job(&attempt.execution_agent_id)
                    .map_err(OrchestrationError::Store)?
                    .is_none()
                {
                    let _ = cleanup_prepared(prepared);
                }
                return Err(OrchestrationError::Store(error));
            }
        };
        let ledger = self
            .scheduler
            .ledger()
            .ok_or(OrchestrationError::Unavailable(
                "scheduler lost its review ledger",
            ))?;
        if let Err(error) = ledger.initialize(&job.agent_id, prepared, runtime_hash.as_deref()) {
            let cleanup = cleanup_prepared(prepared);
            let result = TaskResult {
                outcome: TaskOutcome::Failed,
                summary: "review ledger initialization failed".into(),
                partial: true,
                base_commit: None,
                head_commit: None,
                changed_files: Vec::new(),
                diff_stat: None,
                checks: Vec::new(),
                residual_gaps: vec!["REVIEW_LEDGER_INIT_FAILED".into()],
                artifacts: Vec::new(),
            };
            store
                .set_task_phase(&job.agent_id, TaskPhase::Preparing)
                .map_err(OrchestrationError::Store)?;
            store
                .store_task_result(&job.agent_id, &result)
                .map_err(OrchestrationError::Store)?;
            if cleanup.is_err() {
                return Err(OrchestrationError::Unavailable(
                    "review ledger and cleanup initialization failed",
                ));
            }
            return Err(OrchestrationError::Preparation(error.to_string()));
        }
        if start {
            let _ = self.scheduler.start_ready();
        }
        let job = store
            .get_job(&job.agent_id)
            .map_err(OrchestrationError::Store)?
            .ok_or(OrchestrationError::Unavailable(
                "scheduled structured review disappeared",
            ))?;
        let task_record = store
            .task_by_execution_agent_id(&job.agent_id)
            .map_err(OrchestrationError::Store)?
            .unwrap_or(task_record);
        Ok(structured_projection(
            job,
            task_record,
            prepared,
            &prompt,
            attempt.review_kind,
            ReviewSubmissionDisposition::Created,
        ))
    }

    fn require_structured_review_owner(&self) -> Result<(), OrchestrationError> {
        if self.scheduler.ledger().is_none() || !self.scheduler.review_completion_enabled() {
            return Err(OrchestrationError::Unavailable(
                "structured review ledger is unavailable",
            ));
        }
        Ok(())
    }

    pub fn spawn_review(
        &self,
        manifest: &ReviewManifest,
    ) -> Result<SpawnedReview, OrchestrationError> {
        self.submit_review_mode(manifest, true)
    }

    pub fn submit_review(
        &self,
        manifest: &ReviewManifest,
    ) -> Result<SpawnedReview, OrchestrationError> {
        self.submit_review_mode(manifest, false)
    }

    fn submit_review_mode(
        &self,
        manifest: &ReviewManifest,
        start: bool,
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
            if start {
                let _ = self.scheduler.start_ready();
            }
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

        if start {
            let _ = self.scheduler.start_ready();
        }

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

struct StructuredAttempt {
    execution_agent_id: String,
    public_agent_id: String,
    review_id: String,
    task_kind: TaskKind,
    parent_execution_id: Option<String>,
    ownership_token: String,
    budget: BudgetRequest,
    review_kind: StructuredReviewKind,
}

struct ContinuationContext {
    parent: TaskRecord,
    allowed_bases: HashSet<String>,
    report_targets: HashSet<PathBuf>,
    scope: Vec<PathBuf>,
    review_kind: ReviewKind,
    section_id: String,
}

fn validate_structured_contract(
    review_kind: StructuredReviewKind,
    manifest: &ReviewManifest,
    read_only: bool,
    ownership_token: Option<&str>,
) -> Result<(), OrchestrationError> {
    if (manifest.review_kind, manifest.round_kind) != review_kind.manifest_contract() {
        return Err(OrchestrationError::Contract(
            "review kind and manifest round are incompatible",
        ));
    }
    if !read_only || !manifest.fresh_session {
        return Err(OrchestrationError::Contract(
            "structured reviews require read_only=true and a fresh session",
        ));
    }
    validate_identifier(&manifest.feature_id, "feature_id")?;
    validate_identifier(&manifest.section_id, "section_id")?;
    validate_identifier(&manifest.idempotency_key, "idempotency_key")?;
    if let Some(token) = ownership_token {
        validate_identifier(token, "ownership_token")?;
    }
    Ok(())
}

fn validate_frozen_finding_ids(ids: &[String]) -> Result<(), OrchestrationError> {
    if ids.len() > 128 {
        return Err(OrchestrationError::Contract(
            "too many frozen finding identifiers",
        ));
    }
    let mut unique = HashSet::with_capacity(ids.len());
    for id in ids {
        validate_identifier(id, "frozen_finding_id")?;
        if !unique.insert(id) {
            return Err(OrchestrationError::Contract(
                "frozen finding identifiers must be unique",
            ));
        }
    }
    Ok(())
}

fn validate_identifier(value: &str, _field: &'static str) -> Result<(), OrchestrationError> {
    if value.trim().is_empty() || value.len() > 512 || value.contains('\0') {
        return Err(OrchestrationError::Contract(
            "structured review identifier is invalid",
        ));
    }
    Ok(())
}

fn store_budget(budget: Option<&BudgetLimits>) -> BudgetRequest {
    budget.map_or(BudgetRequest::Omitted, |budget| {
        BudgetRequest::Limits(EffectiveBudget {
            wall_time_ms: budget.wall_time_ms,
            max_turns: budget.max_turns,
            max_tool_calls: budget.max_tool_calls,
            max_context_bytes: budget.max_context_bytes,
            max_result_bytes: budget.max_result_bytes,
            max_artifact_bytes: budget.max_artifact_bytes,
        })
    })
}

fn derived_id(domain: &str, idempotency_key: &str) -> String {
    let digest =
        Sha256::digest(format!("structured-review/v1|{domain}|{idempotency_key}").as_bytes());
    format!("{domain}-{digest:x}")
}

fn manifest_sha256(manifest: &ReviewManifest) -> Result<String, OrchestrationError> {
    serde_json::to_vec_pretty(manifest)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| OrchestrationError::Preparation(error.to_string()))
}

fn prepared_from_job(job: &Job) -> Result<PreparedLaunchSpec, OrchestrationError> {
    let json = job
        .prepared_launch_json
        .as_deref()
        .ok_or(OrchestrationError::Conflict(
            "structured review preparation is missing",
        ))?;
    let prepared: PreparedLaunchSpec = serde_json::from_str(json)
        .map_err(|_| OrchestrationError::Conflict("structured review preparation is invalid"))?;
    prepared
        .validate_digest()
        .map_err(|_| OrchestrationError::Conflict("structured review preparation is invalid"))?;
    if job.prepared_launch_sha256.as_deref() != Some(prepared.prepared_sha256.as_str()) {
        return Err(OrchestrationError::Conflict(
            "structured review preparation digest is inconsistent",
        ));
    }
    Ok(prepared)
}

fn validate_continuation_prepared(
    context: &ContinuationContext,
    prepared: &PreparedLaunchSpec,
) -> Result<(), OrchestrationError> {
    let scope = prepared
        .scope
        .iter()
        .map(|scope| scope.repository_relative.clone())
        .collect::<Vec<_>>();
    if prepared.repository.to_string_lossy() != context.parent.repository
        || prepared.feature_id != context.parent.feature_id
        || prepared.section_id != context.section_id
        || prepared.review_kind != context.review_kind
        || scope != context.scope
    {
        return Err(OrchestrationError::Conflict(
            "continuation repository, kind, section, or scope is incompatible",
        ));
    }
    if !context.allowed_bases.contains(&prepared.base_sha) {
        return Err(OrchestrationError::Conflict(
            "continuation base is outside the prior review lineage",
        ));
    }
    if context.report_targets.contains(&prepared.report_target) {
        return Err(OrchestrationError::Conflict(
            "continuation must use a new report target",
        ));
    }
    Ok(())
}

fn cleanup_prepared(prepared: &PreparedLaunchSpec) -> Result<(), OrchestrationError> {
    let job_root = prepared
        .worktree
        .scratch_worktrees_root
        .parent()
        .map(PathBuf::from)
        .ok_or(OrchestrationError::Unavailable(
            "prepared review has no cleanup owner",
        ))?;
    let manager = WorktreeManager::new(prepared.repository.clone(), job_root)
        .map_err(|_| OrchestrationError::Unavailable("prepared review cleanup is unavailable"))?;
    if !prepared.worktree.path.exists() {
        return Ok(());
    }
    let diagnostics = manager
        .capture_integrity(&prepared.worktree)
        .map_err(|_| OrchestrationError::Unavailable("prepared review cleanup failed"))?;
    let record = manager
        .persist_integrity(&prepared.worktree, diagnostics)
        .map_err(|_| OrchestrationError::Unavailable("prepared review cleanup failed"))?;
    manager
        .cleanup_from_record(&record)
        .map(|_| ())
        .map_err(|_| OrchestrationError::Unavailable("prepared review cleanup failed"))
}

fn structured_projection(
    job: Job,
    task: TaskRecord,
    prepared: &PreparedLaunchSpec,
    prompt: &ReviewPrompt,
    review_kind: StructuredReviewKind,
    disposition: ReviewSubmissionDisposition,
) -> StructuredReviewProjection {
    let fresh_session_observed = job
        .zcode_session_id
        .as_deref()
        .is_some_and(|session| !session.trim().is_empty());
    StructuredReviewProjection {
        agent_id: task.public_agent_id,
        review_id: task.review_id.unwrap_or_default(),
        submission_disposition: disposition,
        phase: match task.phase {
            TaskPhase::Queued => "QUEUED",
            TaskPhase::Preparing => "PREPARING",
            TaskPhase::Running => "RUNNING",
            TaskPhase::WaitingInput => "WAITING_INPUT",
            TaskPhase::Cancelling => "CANCELLING",
            TaskPhase::Terminal => "TERMINAL",
        }
        .into(),
        attempt_sequence: task.attempt_sequence,
        effective_budget: task.effective_budget,
        counts_as_independent: disposition == ReviewSubmissionDisposition::Created
            && task.independent_evidence
            && fresh_session_observed,
        provenance: StructuredReviewProvenance {
            review_kind,
            manifest_sha256: prepared.manifest_sha256.clone(),
            prepared_sha256: prepared.prepared_sha256.clone(),
            prompt_sha256: prompt.sha256.clone(),
            base_sha: prepared.base_sha.clone(),
            head_sha: prepared.head_sha.clone(),
            requested_model: prepared.model.clone(),
            fresh_session_observed,
        },
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

#[cfg(test)]
mod structured_tests {
    use super::*;
    use review_preparation::{NetworkPolicy, ScratchPolicy};
    use std::{collections::BTreeMap, path::PathBuf};

    fn manifest(review_kind: ReviewKind, round_kind: RoundKind) -> ReviewManifest {
        ReviewManifest {
            schema: "sectioned-zcode-review/v1".into(),
            review_kind,
            feature_id: "feature".into(),
            section_id: "S04".into(),
            round_kind,
            repository: PathBuf::from("/repository"),
            base_ref: "a".repeat(40),
            head_ref: "b".repeat(40),
            plan_path: PathBuf::from(".agent-work/PLAN.md"),
            context_paths: Vec::new(),
            scope_paths: vec![PathBuf::from("src")],
            forbidden_input_globs: Vec::new(),
            validation_commands: BTreeMap::new(),
            report_target: PathBuf::from(".agent-work/reviews/report.md"),
            scratch_root: PathBuf::from(".agent-work/scratch/jobs"),
            model: None,
            fresh_session: true,
            network_policy: NetworkPolicy::Deny,
            scratch_policy: ScratchPolicy::Isolated,
            idempotency_key: "feature:S04:typed".into(),
        }
    }

    #[test]
    fn structured_kind_mapping_is_closed_and_exact() {
        for (kind, review, round) in [
            (
                StructuredReviewKind::PlanReview,
                ReviewKind::Plan,
                RoundKind::PlanReview,
            ),
            (
                StructuredReviewKind::InitialBounded,
                ReviewKind::Code,
                RoundKind::InitialBounded,
            ),
            (
                StructuredReviewKind::RepairDelta,
                ReviewKind::Code,
                RoundKind::RepairDelta,
            ),
            (
                StructuredReviewKind::FinalBounded,
                ReviewKind::Code,
                RoundKind::FinalBounded,
            ),
        ] {
            assert!(validate_structured_contract(
                kind,
                &manifest(review, round),
                true,
                Some("owner")
            )
            .is_ok());
        }
        assert!(validate_structured_contract(
            StructuredReviewKind::PlanReview,
            &manifest(ReviewKind::Code, RoundKind::PlanReview),
            true,
            Some("owner")
        )
        .is_err());
        assert!(validate_structured_contract(
            StructuredReviewKind::InitialBounded,
            &manifest(ReviewKind::Code, RoundKind::InitialBounded),
            false,
            Some("owner")
        )
        .is_err());
    }

    #[test]
    fn structured_budget_null_and_unknown_fields_fail_closed() {
        let input = StructuredReviewSubmission {
            review_kind: StructuredReviewKind::InitialBounded,
            manifest: manifest(ReviewKind::Code, RoundKind::InitialBounded),
            ownership_token: "owner".into(),
            read_only: true,
            budget: None,
        };
        let mut value = serde_json::to_value(input).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("budget".into(), serde_json::Value::Null);
        assert!(serde_json::from_value::<StructuredReviewSubmission>(value).is_err());
        let mut value = serde_json::to_value(StructuredReviewSubmission {
            review_kind: StructuredReviewKind::InitialBounded,
            manifest: manifest(ReviewKind::Code, RoundKind::InitialBounded),
            ownership_token: "owner".into(),
            read_only: true,
            budget: None,
        })
        .unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("raw_prompt".into(), serde_json::json!("forbidden"));
        assert!(serde_json::from_value::<StructuredReviewSubmission>(value).is_err());
    }
}
