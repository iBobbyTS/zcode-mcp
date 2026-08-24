use review_preparation::PreparedLaunchSpec;
use review_store::{
    ReviewInitialization, ReviewMutationDisposition, ReviewMutationResult, ReviewReportState,
    ReviewSnapshot, Store, StoreError,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

const MAX_PAYLOAD_BYTES: usize = 64 * 1024;
const MAX_REPORT_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_TOOL_TEXT_BYTES: usize = 16 * 1024;
pub const MAX_TOOL_ITEMS: usize = 128;
pub const MAX_TOOL_ID_BYTES: usize = 128;

pub const REVIEW_CHECKPOINT: &str = "review_checkpoint";
pub const REVIEW_FINDING_UPSERT: &str = "review_finding_upsert";
pub const REVIEW_VALIDATION_RECORD: &str = "review_validation_record";
pub const REVIEW_FINALIZE: &str = "review_finalize";

#[derive(Debug)]
pub enum LedgerError {
    Store(StoreError),
    InvalidInput(String),
    Conflict(String),
    Missing(String),
    Path(String),
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl fmt::Display for LedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "{error}"),
            Self::InvalidInput(message) => write!(formatter, "invalid ledger input: {message}"),
            Self::Conflict(message) => write!(formatter, "ledger conflict: {message}"),
            Self::Missing(message) => write!(formatter, "missing ledger state: {message}"),
            Self::Path(message) => write!(formatter, "invalid report path: {message}"),
            Self::Io(error) => write!(formatter, "report I/O failed: {error}"),
            Self::Json(error) => write!(formatter, "ledger JSON failed: {error}"),
        }
    }
}

impl std::error::Error for LedgerError {}

impl From<StoreError> for LedgerError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::Conflict(message) => Self::Conflict(message),
            other => Self::Store(other),
        }
    }
}

impl From<std::io::Error> for LedgerError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for LedgerError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

pub type LedgerResult<T> = Result<T, LedgerError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointStage {
    Scope,
    Inspection,
    Validation,
    Synthesis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InspectedPath {
    pub path: String,
    #[serde(default)]
    pub line_ranges: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandSummary {
    pub command: String,
    pub result_summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointInput {
    pub checkpoint_id: String,
    pub stage: CheckpointStage,
    pub summary: String,
    #[serde(default)]
    pub inspected: Vec<InspectedPath>,
    #[serde(default)]
    pub commands: Vec<CommandSummary>,
    #[serde(default)]
    pub open_questions: Vec<String>,
    #[serde(default)]
    pub remaining_scope: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FindingSeverity {
    P0,
    P1,
    P2,
    P3,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Open,
    Withdrawn,
}

impl FindingStatus {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Withdrawn => "withdrawn",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingLocation {
    pub path: String,
    pub start_line: u64,
    pub end_line: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingInput {
    pub finding_id: String,
    pub severity: FindingSeverity,
    pub confidence: Confidence,
    pub title: String,
    #[serde(default)]
    pub locations: Vec<FindingLocation>,
    #[serde(default)]
    pub evidence: Vec<String>,
    pub impact: String,
    pub suggested_remediation: String,
    pub status: FindingStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationInput {
    pub validation_id: String,
    pub command: String,
    pub cwd: String,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub stdout_summary: String,
    pub stderr_summary: String,
    #[serde(default)]
    pub related_findings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalSignal {
    FindingsPresent,
    NoFindingsObserved,
    IncompleteEvidence,
    UnableToReview,
}

impl FinalSignal {
    fn as_str(&self) -> &'static str {
        match self {
            Self::FindingsPresent => "findings_present",
            Self::NoFindingsObserved => "no_findings_observed",
            Self::IncompleteEvidence => "incomplete_evidence",
            Self::UnableToReview => "unable_to_review",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Coverage {
    #[serde(default)]
    pub covered: Vec<String>,
    #[serde(default)]
    pub not_covered: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizeInput {
    pub signal: FinalSignal,
    pub summary: String,
    pub coverage: Coverage,
    #[serde(default)]
    pub uncertainties: Vec<String>,
    #[serde(default)]
    pub recommended_next_actions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolDisposition {
    Applied,
    Duplicate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolResult {
    pub tool: String,
    pub disposition: ToolDisposition,
    pub report_revision: u64,
    pub finalized: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactIntegrity {
    Valid,
    Missing,
    Replaced,
    Binary,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedArtifact {
    pub integrity: ArtifactIntegrity,
    pub locator: String,
    pub expected_sha256: Option<String>,
    pub expected_bytes: Option<u64>,
    pub actual_sha256: Option<String>,
    pub actual_bytes: Option<u64>,
    pub checkpoint_number: u64,
    pub finalized: bool,
    pub preview: Option<String>,
}

pub struct LedgerManager {
    store: Arc<Store>,
    mutation_lock: Mutex<()>,
}

impl LedgerManager {
    pub fn new(store: Arc<Store>) -> Self {
        Self {
            store,
            mutation_lock: Mutex::new(()),
        }
    }

    pub fn store(&self) -> Arc<Store> {
        Arc::clone(&self.store)
    }

    pub fn initialize(
        &self,
        agent_id: &str,
        prepared: &PreparedLaunchSpec,
        runtime_sha256: Option<&str>,
    ) -> LedgerResult<ReviewReportState> {
        let _guard = self.mutation_lock.lock().unwrap();
        prepared
            .validate_digest()
            .map_err(|error| LedgerError::InvalidInput(error.to_string()))?;
        validate_id(agent_id, "agent_id")?;
        let (expected_path, report_root) = validate_prepared_target(&prepared.report_target)?;
        self.store.initialize_review(&ReviewInitialization {
            agent_id: agent_id.to_owned(),
            expected_path: expected_path.to_string_lossy().into_owned(),
            report_root: report_root.to_string_lossy().into_owned(),
            manifest_sha256: prepared.manifest_sha256.clone(),
            prepared_sha256: prepared.prepared_sha256.clone(),
            base_sha: prepared.base_sha.clone(),
            head_sha: prepared.head_sha.clone(),
            runtime_sha256: runtime_sha256.map(str::to_owned),
            requested_model: prepared.model.clone(),
        })?;
        self.ensure_published(agent_id, false)
    }

    pub fn record_runtime(
        &self,
        agent_id: &str,
        runtime_sha256: Option<&str>,
        zcode_session_id: &str,
        observed_model: Option<&str>,
    ) -> LedgerResult<ReviewReportState> {
        let _guard = self.mutation_lock.lock().unwrap();
        validate_id(agent_id, "agent_id")?;
        validate_text(zcode_session_id, "zcode_session_id")?;
        if let Some(model) = observed_model {
            validate_text(model, "observed_model")?;
        }
        let result = self.store.record_review_runtime(
            agent_id,
            runtime_sha256,
            zcode_session_id,
            observed_model,
        )?;
        self.publish_mutation(agent_id, result)
    }

    pub fn call_tool(
        &self,
        agent_id: &str,
        tool: &str,
        arguments: Value,
    ) -> LedgerResult<ToolResult> {
        let _guard = self.mutation_lock.lock().unwrap();
        validate_id(agent_id, "agent_id")?;
        validate_tool_arguments(tool, &arguments)?;
        let result = match tool {
            REVIEW_CHECKPOINT => {
                let input: CheckpointInput = serde_json::from_value(arguments)?;
                let (json, hash) = canonical_payload(&input)?;
                self.store
                    .apply_review_checkpoint(agent_id, &input.checkpoint_id, &json, &hash)?
            }
            REVIEW_FINDING_UPSERT => {
                let mut input: FindingInput = serde_json::from_value(arguments)?;
                normalize_finding(&mut input);
                let (json, hash) = canonical_payload(&input)?;
                self.store.upsert_review_finding(
                    agent_id,
                    &input.finding_id,
                    input.status.as_str(),
                    &json,
                    &hash,
                )?
            }
            REVIEW_VALIDATION_RECORD => {
                let input: ValidationInput = serde_json::from_value(arguments)?;
                let (json, hash) = canonical_payload(&input)?;
                self.store
                    .apply_review_validation(agent_id, &input.validation_id, &json, &hash)?
            }
            REVIEW_FINALIZE => {
                let input: FinalizeInput = serde_json::from_value(arguments)?;
                let snapshot = self
                    .store
                    .review_snapshot(agent_id)?
                    .ok_or_else(|| LedgerError::Missing(format!("unknown review {agent_id}")))?;
                let open_findings = snapshot
                    .findings
                    .iter()
                    .filter(|finding| finding.status.as_deref() == Some("open"))
                    .count();
                if matches!(input.signal, FinalSignal::FindingsPresent) && open_findings == 0 {
                    return Err(LedgerError::InvalidInput(
                        "findings_present requires an open finding".into(),
                    ));
                }
                if matches!(input.signal, FinalSignal::NoFindingsObserved) && open_findings != 0 {
                    return Err(LedgerError::InvalidInput(
                        "no_findings_observed conflicts with an open finding".into(),
                    ));
                }
                let (json, hash) = canonical_payload(&input)?;
                self.store
                    .finalize_review(agent_id, input.signal.as_str(), &json, &hash)?
            }
            _ => {
                return Err(LedgerError::InvalidInput(
                    "unknown internal ledger tool".into(),
                ))
            }
        };
        let report = self.publish_mutation(agent_id, result.clone())?;
        Ok(ToolResult {
            tool: tool.to_owned(),
            disposition: disposition(result),
            report_revision: report.current_revision,
            finalized: report.finalized,
        })
    }

    pub fn recover(&self, agent_id: &str) -> LedgerResult<ReviewReportState> {
        let _guard = self.mutation_lock.lock().unwrap();
        self.recover_unlocked(agent_id)
    }

    pub fn recover_all(&self) -> LedgerResult<Vec<String>> {
        let _guard = self.mutation_lock.lock().unwrap();
        let mut recovered = Vec::new();
        for agent_id in self.store.review_report_agent_ids()? {
            let before = self
                .store
                .review_report_state(&agent_id)?
                .ok_or_else(|| LedgerError::Missing(format!("unknown review {agent_id}")))?;
            let verified = verify_state(&before, 0)?;
            if before.published_revision != Some(before.current_revision)
                || verified.integrity != ArtifactIntegrity::Valid
            {
                self.recover_unlocked(&agent_id)?;
                recovered.push(agent_id);
            }
        }
        Ok(recovered)
    }

    pub fn verify_artifact(
        &self,
        agent_id: &str,
        preview_bytes: usize,
    ) -> LedgerResult<VerifiedArtifact> {
        validate_id(agent_id, "agent_id")?;
        let state = self
            .store
            .review_report_state(agent_id)?
            .ok_or_else(|| LedgerError::Missing(format!("unknown review {agent_id}")))?;
        verify_state(&state, preview_bytes.min(8 * 1024))
    }

    fn render_and_publish(
        &self,
        agent_id: &str,
        emit_event: bool,
    ) -> LedgerResult<ReviewReportState> {
        let snapshot = self
            .store
            .review_snapshot(agent_id)?
            .ok_or_else(|| LedgerError::Missing(format!("unknown review {agent_id}")))?;
        let bytes = render_snapshot(&snapshot)?;
        if bytes.len() as u64 > MAX_REPORT_BYTES {
            return Err(LedgerError::InvalidInput(
                "rendered report exceeds cap".into(),
            ));
        }
        let expected = PathBuf::from(&snapshot.report.expected_path);
        let root = PathBuf::from(&snapshot.report.report_root);
        validate_stored_target(&expected, &root)?;
        atomic_write(&expected, &root, snapshot.report.current_revision, &bytes)?;
        let hash = sha256(&bytes);
        let event = serde_json::to_string(&serde_json::json!({
            "schema": "sectioned-zcode-review-event/v1",
            "type": "report.checkpoint",
            "agent_id": agent_id,
            "revision": snapshot.report.current_revision,
            "finalized": snapshot.report.finalized,
        }))?;
        Ok(self.store.publish_review_report(
            agent_id,
            snapshot.report.current_revision,
            &hash,
            bytes.len() as u64,
            emit_event.then_some(event.as_str()),
        )?)
    }

    fn publish_mutation(
        &self,
        agent_id: &str,
        result: ReviewMutationResult,
    ) -> LedgerResult<ReviewReportState> {
        match result.disposition {
            ReviewMutationDisposition::Applied => self.render_and_publish(agent_id, true),
            ReviewMutationDisposition::Duplicate => self.ensure_published(agent_id, true),
        }
    }

    fn ensure_published(
        &self,
        agent_id: &str,
        emit_event: bool,
    ) -> LedgerResult<ReviewReportState> {
        let state = self
            .store
            .review_report_state(agent_id)?
            .ok_or_else(|| LedgerError::Missing(format!("unknown review {agent_id}")))?;
        let verified = verify_state(&state, 0)?;
        if state.published_revision == Some(state.current_revision)
            && verified.integrity == ArtifactIntegrity::Valid
        {
            Ok(state)
        } else {
            self.render_and_publish(agent_id, emit_event)
        }
    }

    fn recover_unlocked(&self, agent_id: &str) -> LedgerResult<ReviewReportState> {
        let state = self
            .store
            .review_report_state(agent_id)?
            .ok_or_else(|| LedgerError::Missing(format!("unknown review {agent_id}")))?;
        let verified = verify_state(&state, 0)?;
        if state.published_revision == Some(state.current_revision)
            && verified.integrity == ArtifactIntegrity::Valid
        {
            return Ok(state);
        }
        self.render_and_publish(agent_id, state.current_revision > 0)
    }
}

pub fn validate_tool_arguments(tool: &str, arguments: &Value) -> LedgerResult<()> {
    validate_payload(arguments)?;
    match tool {
        REVIEW_CHECKPOINT => {
            let input: CheckpointInput = serde_json::from_value(arguments.clone())?;
            validate_checkpoint(&input)
        }
        REVIEW_FINDING_UPSERT => {
            let input: FindingInput = serde_json::from_value(arguments.clone())?;
            validate_finding(&input)
        }
        REVIEW_VALIDATION_RECORD => {
            let input: ValidationInput = serde_json::from_value(arguments.clone())?;
            validate_validation(&input)
        }
        REVIEW_FINALIZE => {
            let input: FinalizeInput = serde_json::from_value(arguments.clone())?;
            validate_finalize(&input)
        }
        _ => Err(LedgerError::InvalidInput(
            "unknown internal ledger tool".into(),
        )),
    }
}

fn disposition(result: ReviewMutationResult) -> ToolDisposition {
    match result.disposition {
        ReviewMutationDisposition::Applied => ToolDisposition::Applied,
        ReviewMutationDisposition::Duplicate => ToolDisposition::Duplicate,
    }
}

fn validate_checkpoint(input: &CheckpointInput) -> LedgerResult<()> {
    validate_id(&input.checkpoint_id, "checkpoint_id")?;
    validate_text(&input.summary, "summary")?;
    validate_len(&input.inspected, "inspected")?;
    validate_len(&input.commands, "commands")?;
    validate_strings(&input.open_questions, "open_questions")?;
    validate_strings(&input.remaining_scope, "remaining_scope")?;
    for inspected in &input.inspected {
        validate_text(&inspected.path, "inspected.path")?;
        validate_strings(&inspected.line_ranges, "line_ranges")?;
    }
    for command in &input.commands {
        validate_text(&command.command, "command")?;
        validate_text(&command.result_summary, "result_summary")?;
    }
    Ok(())
}

fn validate_finding(input: &FindingInput) -> LedgerResult<()> {
    validate_id(&input.finding_id, "finding_id")?;
    validate_text(&input.title, "title")?;
    validate_len(&input.locations, "locations")?;
    validate_strings(&input.evidence, "evidence")?;
    validate_text(&input.impact, "impact")?;
    validate_text(&input.suggested_remediation, "suggested_remediation")?;
    for location in &input.locations {
        validate_text(&location.path, "location.path")?;
        if location.start_line == 0 || location.end_line == 0 {
            return Err(LedgerError::InvalidInput(
                "finding line range is invalid".into(),
            ));
        }
    }
    Ok(())
}

fn normalize_finding(input: &mut FindingInput) {
    for location in &mut input.locations {
        if location.end_line < location.start_line {
            std::mem::swap(&mut location.start_line, &mut location.end_line);
        }
    }
}

fn validate_validation(input: &ValidationInput) -> LedgerResult<()> {
    validate_id(&input.validation_id, "validation_id")?;
    validate_text(&input.command, "command")?;
    validate_text(&input.cwd, "cwd")?;
    validate_text_allow_empty(&input.stdout_summary, "stdout_summary")?;
    validate_text_allow_empty(&input.stderr_summary, "stderr_summary")?;
    validate_strings(&input.related_findings, "related_findings")?;
    for finding_id in &input.related_findings {
        validate_id(finding_id, "related finding")?;
    }
    Ok(())
}

fn validate_finalize(input: &FinalizeInput) -> LedgerResult<()> {
    validate_text(&input.summary, "summary")?;
    validate_strings(&input.coverage.covered, "coverage.covered")?;
    validate_strings(&input.coverage.not_covered, "coverage.not_covered")?;
    validate_strings(&input.uncertainties, "uncertainties")?;
    validate_strings(&input.recommended_next_actions, "recommended_next_actions")?;
    Ok(())
}

fn validate_payload(value: &Value) -> LedgerResult<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(LedgerError::InvalidInput(
            "tool arguments exceed cap".into(),
        ));
    }
    reject_sensitive(value)
}

fn reject_sensitive(value: &Value) -> LedgerResult<()> {
    match value {
        Value::String(value) => {
            let lowered = value.to_ascii_lowercase();
            let forbidden = [
                "chain of thought",
                "hidden reasoning",
                "<thinking>",
                "authorization: bearer",
                "api_key=",
                "api-key=",
                "secret=",
                "token=",
            ];
            if forbidden.iter().any(|needle| lowered.contains(needle)) {
                return Err(LedgerError::InvalidInput(
                    "hidden reasoning or secret-bearing content is forbidden".into(),
                ));
            }
        }
        Value::Array(values) => {
            for value in values {
                reject_sensitive(value)?;
            }
        }
        Value::Object(values) => {
            for (key, value) in values {
                if matches!(
                    key.as_str(),
                    "raw_args" | "raw_arguments" | "hidden_reasoning" | "chain_of_thought"
                ) {
                    return Err(LedgerError::InvalidInput(
                        "raw arguments or hidden reasoning fields are forbidden".into(),
                    ));
                }
                reject_sensitive(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_id(value: &str, field: &str) -> LedgerResult<()> {
    if value.is_empty()
        || value.len() > MAX_TOOL_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(LedgerError::InvalidInput(format!("{field} is invalid")));
    }
    Ok(())
}

fn validate_text(value: &str, field: &str) -> LedgerResult<()> {
    if value.is_empty() {
        return Err(LedgerError::InvalidInput(format!("{field} is empty")));
    }
    validate_text_allow_empty(value, field)
}

fn validate_text_allow_empty(value: &str, field: &str) -> LedgerResult<()> {
    if value.len() > MAX_TOOL_TEXT_BYTES || value.contains('\0') {
        return Err(LedgerError::InvalidInput(format!("{field} is invalid")));
    }
    Ok(())
}

fn validate_strings(values: &[String], field: &str) -> LedgerResult<()> {
    validate_len(values, field)?;
    for value in values {
        validate_text(value, field)?;
    }
    Ok(())
}

fn validate_len<T>(values: &[T], field: &str) -> LedgerResult<()> {
    if values.len() > MAX_TOOL_ITEMS {
        return Err(LedgerError::InvalidInput(format!("{field} exceeds cap")));
    }
    Ok(())
}

fn canonical_payload<T: Serialize>(input: &T) -> LedgerResult<(String, String)> {
    let json = serde_json::to_string(input)?;
    let hash = sha256(json.as_bytes());
    Ok((json, hash))
}

fn validate_prepared_target(target: &Path) -> LedgerResult<(PathBuf, PathBuf)> {
    if !target.is_absolute() {
        return Err(LedgerError::Path(
            "prepared report target is not absolute".into(),
        ));
    }
    let parent = target
        .parent()
        .ok_or_else(|| LedgerError::Path("report target has no parent".into()))?;
    let root = fs::canonicalize(parent)?;
    let file_name = target
        .file_name()
        .ok_or_else(|| LedgerError::Path("report target has no file name".into()))?;
    let expected = root.join(file_name);
    validate_stored_target(&expected, &root)?;
    Ok((expected, root))
}

fn validate_stored_target(expected: &Path, root: &Path) -> LedgerResult<()> {
    if !expected.is_absolute() || !root.is_absolute() || expected.parent() != Some(root) {
        return Err(LedgerError::Path(
            "expected report is not a direct child of its prepared root".into(),
        ));
    }
    let canonical_root = fs::canonicalize(root)?;
    if canonical_root != root {
        return Err(LedgerError::Path("report root identity changed".into()));
    }
    let root_metadata = fs::symlink_metadata(root)?;
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Err(LedgerError::Path(
            "report root is not a real directory".into(),
        ));
    }
    match fs::symlink_metadata(expected) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(LedgerError::Path("report target is a symlink".into()))
        }
        Ok(metadata) if !metadata.is_file() => Err(LedgerError::Path(
            "report target is not a regular file".into(),
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn atomic_write(expected: &Path, root: &Path, revision: u64, bytes: &[u8]) -> LedgerResult<()> {
    validate_stored_target(expected, root)?;
    let file_name = expected
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| LedgerError::Path("report filename is invalid".into()))?;
    let mut temporary = None;
    for attempt in 0..16u8 {
        let candidate = root.join(format!(
            ".{file_name}.{}.{}.{}.tmp",
            std::process::id(),
            revision,
            attempt
        ));
        let opened = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate);
        match opened {
            Ok(file) => {
                temporary = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    let (temporary_path, mut file) = temporary
        .ok_or_else(|| LedgerError::Path("could not allocate atomic report file".into()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    let written = (|| -> std::io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        validate_stored_target(expected, root)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        fs::rename(&temporary_path, expected)?;
        File::open(root)?.sync_all()?;
        Ok(())
    })();
    if written.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    written?;
    Ok(())
}

fn render_snapshot(snapshot: &ReviewSnapshot) -> LedgerResult<Vec<u8>> {
    let mut report = String::new();
    report.push_str("# ZCode Review Report\n\n");
    report.push_str(&format!(
        "FINALIZED: {}\nREPORT_REVISION: {}\n\n",
        snapshot.report.finalized, snapshot.report.current_revision
    ));
    report.push_str("## Provenance\n\n");
    let provenance = &snapshot.provenance;
    for (label, value) in [
        (
            "Manifest SHA-256",
            Some(provenance.manifest_sha256.as_str()),
        ),
        (
            "Prepared SHA-256",
            Some(provenance.prepared_sha256.as_str()),
        ),
        ("Base SHA", Some(provenance.base_sha.as_str())),
        ("Head SHA", Some(provenance.head_sha.as_str())),
        ("Runtime SHA-256", provenance.runtime_sha256.as_deref()),
        ("ZCode Session", provenance.zcode_session_id.as_deref()),
        ("Requested Model", provenance.requested_model.as_deref()),
        ("Observed Model", provenance.observed_model.as_deref()),
    ] {
        render_value(&mut report, label, value.unwrap_or("not_observed"));
    }
    report.push_str("\n## Checkpoints\n\n");
    if snapshot.checkpoints.is_empty() {
        report.push_str("No checkpoints recorded.\n");
    }
    for entry in &snapshot.checkpoints {
        let input: CheckpointInput = serde_json::from_str(&entry.payload_json)?;
        report.push_str(&format!(
            "### {} (revision {})\n\n- Stage: `{:?}`\n",
            markdown_text(&input.checkpoint_id),
            entry.revision,
            input.stage
        ));
        render_value(&mut report, "Summary", &input.summary);
        render_inspected(&mut report, &input.inspected);
        render_commands(&mut report, &input.commands);
        render_string_list(&mut report, "Open questions", &input.open_questions);
        render_string_list(&mut report, "Remaining scope", &input.remaining_scope);
    }
    report.push_str("\n## Findings\n\n");
    if snapshot.findings.is_empty() {
        report.push_str("No findings recorded.\n");
    }
    for entry in &snapshot.findings {
        let input: FindingInput = serde_json::from_str(&entry.payload_json)?;
        report.push_str(&format!(
            "### {}: {}\n\n- Status: `{}`\n- Severity: `{:?}`\n- Confidence: `{:?}`\n",
            markdown_text(&input.finding_id),
            markdown_text(&input.title),
            input.status.as_str(),
            input.severity,
            input.confidence
        ));
        render_locations(&mut report, &input.locations);
        render_string_list(&mut report, "Evidence", &input.evidence);
        render_value(&mut report, "Impact", &input.impact);
        render_value(
            &mut report,
            "Suggested remediation",
            &input.suggested_remediation,
        );
    }
    report.push_str("\n## Validation\n\n");
    if snapshot.validations.is_empty() {
        report.push_str("No validation recorded.\n");
    }
    for entry in &snapshot.validations {
        let input: ValidationInput = serde_json::from_str(&entry.payload_json)?;
        report.push_str(&format!(
            "### {}\n\n- Exit code: `{}`\n- Duration ms: `{}`\n",
            markdown_text(&input.validation_id),
            input.exit_code,
            input.duration_ms
        ));
        render_value(&mut report, "Command", &input.command);
        render_value(&mut report, "CWD", &input.cwd);
        render_value(&mut report, "Stdout summary", &input.stdout_summary);
        render_value(&mut report, "Stderr summary", &input.stderr_summary);
        render_string_list(&mut report, "Related findings", &input.related_findings);
    }
    report.push_str("\n## Finalization\n\n");
    if let Some(entry) = &snapshot.finalization {
        let input: FinalizeInput = serde_json::from_str(&entry.payload_json)?;
        report.push_str(&format!("- Signal: `{}`\n", input.signal.as_str()));
        render_value(&mut report, "Summary", &input.summary);
        render_string_list(&mut report, "Covered", &input.coverage.covered);
        render_string_list(&mut report, "Not covered", &input.coverage.not_covered);
        render_string_list(&mut report, "Uncertainties", &input.uncertainties);
        render_string_list(
            &mut report,
            "Recommended next actions",
            &input.recommended_next_actions,
        );
    } else {
        report.push_str("Review is in progress.\n");
    }
    let content_hash = sha256(report.as_bytes());
    let content_bytes = report.len();
    report.push_str(&format!(
        "\n## Artifact Content Digest\n\n- Content SHA-256: `{content_hash}`\n- Content bytes: `{content_bytes}`\n"
    ));
    Ok(report.into_bytes())
}

fn render_value(report: &mut String, label: &str, value: &str) {
    report.push_str(&format!("- {label}: {}\n", markdown_text(value)));
}

fn render_string_list(report: &mut String, label: &str, values: &[String]) {
    report.push_str(&format!("- {label}:"));
    if values.is_empty() {
        report.push_str(" none\n");
    } else {
        report.push('\n');
        for value in values {
            report.push_str(&format!("  - {}\n", markdown_text(value)));
        }
    }
}

fn render_inspected(report: &mut String, inspected: &[InspectedPath]) {
    report.push_str("- Inspected:");
    if inspected.is_empty() {
        report.push_str(" none\n");
        return;
    }
    report.push('\n');
    for item in inspected {
        report.push_str(&format!("  - Path: {}\n", markdown_text(&item.path)));
        render_nested_list(report, "Line ranges", &item.line_ranges, 4);
    }
}

fn render_commands(report: &mut String, commands: &[CommandSummary]) {
    report.push_str("- Commands:");
    if commands.is_empty() {
        report.push_str(" none\n");
        return;
    }
    report.push('\n');
    for command in commands {
        report.push_str(&format!(
            "  - Command: {}\n    Result: {}\n",
            markdown_text(&command.command),
            markdown_text(&command.result_summary)
        ));
    }
}

fn render_locations(report: &mut String, locations: &[FindingLocation]) {
    report.push_str("- Locations:");
    if locations.is_empty() {
        report.push_str(" none\n");
        return;
    }
    report.push('\n');
    for location in locations {
        report.push_str(&format!(
            "  - {}:{}-{}\n",
            markdown_text(&location.path),
            location.start_line,
            location.end_line
        ));
    }
}

fn render_nested_list(report: &mut String, label: &str, values: &[String], indent: usize) {
    let padding = " ".repeat(indent);
    report.push_str(&format!("{padding}{label}:"));
    if values.is_empty() {
        report.push_str(" none\n");
        return;
    }
    report.push('\n');
    for value in values {
        report.push_str(&format!("{padding}  - {}\n", markdown_text(value)));
    }
}

fn markdown_text(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\n' => encoded.push_str("\\n"),
            '\r' => encoded.push_str("\\r"),
            '\t' => encoded.push_str("\\t"),
            character if character.is_control() => {
                encoded.push_str(&format!("\\u{{{:04x}}}", character as u32));
            }
            '\\' | '`' | '*' | '_' | '{' | '}' | '[' | ']' | '<' | '>' | '(' | ')' | '#' | '+'
            | '-' | '.' | '!' | '|' | '~' | '&' => {
                encoded.push('\\');
                encoded.push(character);
            }
            _ => encoded.push(character),
        }
    }
    encoded
}

fn verify_state(state: &ReviewReportState, preview_bytes: usize) -> LedgerResult<VerifiedArtifact> {
    let expected = PathBuf::from(&state.expected_path);
    let root = PathBuf::from(&state.report_root);
    let base = VerifiedArtifact {
        integrity: ArtifactIntegrity::Invalid,
        locator: state.expected_path.clone(),
        expected_sha256: state.sha256.clone(),
        expected_bytes: state.bytes,
        actual_sha256: None,
        actual_bytes: None,
        checkpoint_number: state.current_revision,
        finalized: state.finalized,
        preview: None,
    };
    if validate_stored_target(&expected, &root).is_err() {
        let integrity = match fs::symlink_metadata(&expected) {
            Ok(metadata) if metadata.file_type().is_symlink() => ArtifactIntegrity::Replaced,
            _ => ArtifactIntegrity::Invalid,
        };
        return Ok(VerifiedArtifact { integrity, ..base });
    }
    let metadata = match fs::symlink_metadata(&expected) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(VerifiedArtifact {
                integrity: ArtifactIntegrity::Missing,
                ..base
            })
        }
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file() || metadata.len() > MAX_REPORT_BYTES {
        return Ok(VerifiedArtifact {
            integrity: ArtifactIntegrity::Invalid,
            ..base
        });
    }
    let file = File::open(&expected)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_REPORT_BYTES + 1).read_to_end(&mut bytes)?;
    let actual_hash = sha256(&bytes);
    let actual_bytes = bytes.len() as u64;
    let utf8 = match std::str::from_utf8(&bytes) {
        Ok(value) if !bytes.contains(&0) => value,
        _ => {
            return Ok(VerifiedArtifact {
                integrity: ArtifactIntegrity::Binary,
                actual_sha256: Some(actual_hash),
                actual_bytes: Some(actual_bytes),
                ..base
            })
        }
    };
    let header_valid = utf8.starts_with("# ZCode Review Report\n")
        && utf8.contains(&format!("REPORT_REVISION: {}", state.current_revision))
        && utf8.contains(&format!("FINALIZED: {}", state.finalized));
    let hashes_match = state.published_revision == Some(state.current_revision)
        && state.sha256.as_deref() == Some(actual_hash.as_str())
        && state.bytes == Some(actual_bytes);
    let integrity = if !header_valid {
        ArtifactIntegrity::Invalid
    } else if !hashes_match {
        ArtifactIntegrity::Replaced
    } else {
        ArtifactIntegrity::Valid
    };
    let preview = if preview_bytes == 0 {
        None
    } else {
        let mut end = preview_bytes.min(utf8.len());
        while end > 0 && !utf8.is_char_boundary(end) {
            end -= 1;
        }
        Some(utf8[..end].to_owned())
    };
    Ok(VerifiedArtifact {
        integrity,
        actual_sha256: Some(actual_hash),
        actual_bytes: Some(actual_bytes),
        preview,
        ..base
    })
}

fn sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}
