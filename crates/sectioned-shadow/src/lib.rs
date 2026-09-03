use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fmt, fs,
    future::Future,
    path::{Path, PathBuf},
    time::Instant,
};

pub const SHADOW_SCHEMA: &str = "sectioned-zcode-shadow/v2";

#[derive(Debug)]
pub enum ShadowError {
    Configuration(String),
    Transport(String),
    Protocol(String),
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl fmt::Display for ShadowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(message) => {
                write!(formatter, "shadow configuration invalid: {message}")
            }
            Self::Transport(message) => write!(formatter, "shadow MCP transport failed: {message}"),
            Self::Protocol(message) => write!(formatter, "shadow MCP response invalid: {message}"),
            Self::Io(error) => write!(formatter, "shadow artifact IO failed: {error}"),
            Self::Json(error) => write!(formatter, "shadow JSON failed: {error}"),
        }
    }
}

impl std::error::Error for ShadowError {}
impl From<std::io::Error> for ShadowError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<serde_json::Error> for ShadowError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShadowConfig {
    pub schema: String,
    pub repository: PathBuf,
    pub base_ref: String,
    pub prompt: String,
    pub feature_id: String,
    pub ownership_token: String,
    pub idempotency_key: String,
    #[serde(default)]
    pub repo_context: Vec<PathBuf>,
    pub artifact_directory: PathBuf,
    pub artifact_stem: String,
    #[schemars(range(min = 1, max = 5000))]
    pub poll_timeout_ms: u64,
    #[schemars(range(min = 1, max = 1000))]
    pub max_polls: u16,
}

impl ShadowConfig {
    pub fn validate(&self) -> Result<(), ShadowError> {
        if self.schema != SHADOW_SCHEMA {
            return Err(ShadowError::Configuration("unsupported schema".into()));
        }
        if !self.repository.is_absolute() || !self.artifact_directory.is_absolute() {
            return Err(ShadowError::Configuration(
                "repository and artifact_directory must be absolute".into(),
            ));
        }
        if self.prompt.trim().is_empty()
            || self.feature_id.trim().is_empty()
            || self.ownership_token.trim().is_empty()
            || self.idempotency_key.trim().is_empty()
        {
            return Err(ShadowError::Configuration(
                "prompt and task identity must be nonempty".into(),
            ));
        }
        if self.artifact_stem.is_empty()
            || self.artifact_stem.len() > 160
            || !self
                .artifact_stem
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(ShadowError::Configuration(
                "artifact_stem must be a bounded portable identifier".into(),
            ));
        }
        if !(1..=5000).contains(&self.poll_timeout_ms) || !(1..=1000).contains(&self.max_polls) {
            return Err(ShadowError::Configuration("poll bounds are invalid".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClassification {
    IndependentEvidence,
    EvidenceIncomplete,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ShadowProvenance {
    pub schema: String,
    pub agent_id: String,
    pub submission_disposition: String,
    pub classification: EvidenceClassification,
    pub result_sha256: Option<String>,
    pub final_text_sha256: Option<String>,
    pub wall_time_ms: u64,
    pub resources_reaped: bool,
}

#[derive(Debug, Clone)]
pub struct ShadowRun {
    pub provenance: ShadowProvenance,
}

pub trait PublicMcpClient {
    fn call(
        &self,
        tool: &'static str,
        arguments: Value,
    ) -> impl Future<Output = Result<Value, ShadowError>> + Send;
}

pub struct RmcpFacadeClient {
    service: rmcp::service::RunningService<rmcp::RoleClient, ()>,
}
impl RmcpFacadeClient {
    pub async fn spawn(facade_program: &Path, daemon_socket: &Path) -> Result<Self, ShadowError> {
        let mut command = tokio::process::Command::new(facade_program);
        command.env("ZCODE_REVIEWD_SOCKET", daemon_socket);
        let transport = rmcp::transport::TokioChildProcess::new(command)
            .map_err(|error| ShadowError::Transport(error.to_string()))?;
        let service = rmcp::ServiceExt::serve((), transport)
            .await
            .map_err(|error| ShadowError::Transport(error.to_string()))?;
        Ok(Self { service })
    }
    pub async fn shutdown(self) -> Result<(), ShadowError> {
        self.service
            .cancel()
            .await
            .map(|_| ())
            .map_err(|error| ShadowError::Transport(error.to_string()))
    }
}
impl PublicMcpClient for RmcpFacadeClient {
    async fn call(&self, tool: &'static str, arguments: Value) -> Result<Value, ShadowError> {
        let arguments = arguments
            .as_object()
            .cloned()
            .ok_or_else(|| ShadowError::Protocol("tool arguments must be an object".into()))?;
        let result = self
            .service
            .peer()
            .call_tool(rmcp::model::CallToolRequestParams::new(tool).with_arguments(arguments))
            .await
            .map_err(|error| ShadowError::Transport(error.to_string()))?;
        if result.is_error == Some(true) {
            return Err(ShadowError::Protocol(format!("{tool} returned an error")));
        }
        result
            .structured_content
            .ok_or_else(|| ShadowError::Protocol(format!("{tool} omitted structuredContent")))
    }
}

pub async fn run_shadow_v2<C: PublicMcpClient>(
    client: &C,
    config: &ShadowConfig,
) -> Result<ShadowRun, ShadowError> {
    config.validate()?;
    let started = Instant::now();
    let spawn = client
        .call(
            "zcode_agent_spawn",
            json!({
                "repository": config.repository,
                "base_ref": config.base_ref,
                "prompt": config.prompt,
                "access_mode": "read_only",
                "feature_id": config.feature_id,
                "ownership_token": config.ownership_token,
                "idempotency_key": config.idempotency_key,
                "repo_context": config.repo_context,
                "allowed_command_ids": [],
                "required_command_ids": []
            }),
        )
        .await?;
    let agent_id = spawn
        .get("agent_id")
        .and_then(Value::as_str)
        .ok_or_else(|| ShadowError::Protocol("spawn omitted agent_id".into()))?
        .to_owned();
    let disposition = spawn
        .get("submission_disposition")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_owned();
    let lifecycle = async {
        let mut revision = 0;
        let mut terminal = false;
        for _ in 0..config.max_polls {
            let poll = client
                .call(
                    "zcode_agent_poll",
                    json!({"agent_id": agent_id, "after_revision": revision, "timeout_ms": config.poll_timeout_ms}),
                )
                .await?;
            revision = poll
                .get("next_revision")
                .and_then(Value::as_u64)
                .unwrap_or(revision);
            if poll.pointer("/task/phase").and_then(Value::as_str) == Some("TERMINAL") {
                terminal = true;
                break;
            }
        }
        if !terminal {
            return Err(ShadowError::Protocol("agent did not reach terminal state".into()));
        }
        let result = client
            .call("zcode_agent_result", json!({"agent_id": agent_id}))
            .await?;
        let outcome = result
            .pointer("/result/outcome")
            .and_then(Value::as_str)
            .unwrap_or("UNKNOWN")
            .to_owned();
        let final_text = result
            .pointer("/result/final_text")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let result_sha256 = result
            .pointer("/result/result_sha256")
            .and_then(Value::as_str)
            .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .map(str::to_owned);
        Ok((outcome, final_text, result_sha256))
    }
    .await;
    let close = client
        .call("zcode_agent_close", json!({"agent_id": agent_id}))
        .await;
    let (outcome, final_text, result_sha256) = lifecycle?;
    let close = close?;
    let reaped = close
        .pointer("/task/resources_reaped")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let successful = disposition == "created"
        && outcome == "SUCCEEDED"
        && !final_text.trim().is_empty()
        && result_sha256.is_some()
        && reaped;
    fs::create_dir_all(&config.artifact_directory)?;
    if successful {
        fs::write(
            config
                .artifact_directory
                .join(format!("{}-ZCODE-RAW.md", config.artifact_stem)),
            &final_text,
        )?;
    }
    let provenance = ShadowProvenance {
        schema: SHADOW_SCHEMA.into(),
        agent_id,
        submission_disposition: disposition,
        classification: if successful {
            EvidenceClassification::IndependentEvidence
        } else {
            EvidenceClassification::EvidenceIncomplete
        },
        result_sha256,
        final_text_sha256: successful
            .then(|| format!("{:x}", Sha256::digest(final_text.as_bytes()))),
        wall_time_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
        resources_reaped: reaped,
    };
    fs::write(
        config
            .artifact_directory
            .join(format!("{}-ZCODE-PROVENANCE.json", config.artifact_stem)),
        serde_json::to_vec_pretty(&provenance)?,
    )?;
    Ok(ShadowRun { provenance })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };

    enum Step {
        Ok(Value),
        Err,
    }

    #[derive(Clone)]
    struct MockClient {
        steps: Arc<Mutex<VecDeque<(&'static str, Step)>>>,
        calls: Arc<Mutex<Vec<&'static str>>>,
    }

    impl MockClient {
        fn new(steps: Vec<(&'static str, Step)>) -> Self {
            Self {
                steps: Arc::new(Mutex::new(steps.into())),
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl PublicMcpClient for MockClient {
        async fn call(&self, tool: &'static str, _arguments: Value) -> Result<Value, ShadowError> {
            self.calls.lock().unwrap().push(tool);
            let (expected, step) = self.steps.lock().unwrap().pop_front().unwrap();
            assert_eq!(tool, expected);
            match step {
                Step::Ok(value) => Ok(value),
                Step::Err => Err(ShadowError::Transport("scripted".into())),
            }
        }
    }

    fn config(root: &Path) -> ShadowConfig {
        ShadowConfig {
            schema: SHADOW_SCHEMA.into(),
            repository: root.to_path_buf(),
            base_ref: "a".repeat(40),
            prompt: "review".into(),
            feature_id: "feature".into(),
            ownership_token: "owner".into(),
            idempotency_key: "key".into(),
            repo_context: Vec::new(),
            artifact_directory: root.join("artifacts"),
            artifact_stem: "S01".into(),
            poll_timeout_ms: 1,
            max_polls: 1,
        }
    }

    fn close() -> Step {
        Step::Ok(json!({"task":{"resources_reaped":true}}))
    }

    #[tokio::test]
    async fn created_success_with_text_hash_and_reap_is_independent() {
        let directory = tempfile::tempdir().unwrap();
        let client = MockClient::new(vec![
            (
                "zcode_agent_spawn",
                Step::Ok(json!({"agent_id":"agent","submission_disposition":"created"})),
            ),
            (
                "zcode_agent_poll",
                Step::Ok(json!({"next_revision":2,"task":{"phase":"TERMINAL"}})),
            ),
            (
                "zcode_agent_result",
                Step::Ok(
                    json!({"result":{"outcome":"SUCCEEDED","final_text":"clean","result_sha256":"a".repeat(64)}}),
                ),
            ),
            ("zcode_agent_close", close()),
        ]);
        let run = run_shadow_v2(&client, &config(directory.path()))
            .await
            .unwrap();
        assert_eq!(
            run.provenance.classification,
            EvidenceClassification::IndependentEvidence
        );
        assert!(directory
            .path()
            .join("artifacts/S01-ZCODE-RAW.md")
            .is_file());
        assert_eq!(
            client.calls.lock().unwrap().as_slice(),
            [
                "zcode_agent_spawn",
                "zcode_agent_poll",
                "zcode_agent_result",
                "zcode_agent_close"
            ]
        );
    }

    #[tokio::test]
    async fn existing_or_non_success_result_is_not_independent() {
        let directory = tempfile::tempdir().unwrap();
        let client = MockClient::new(vec![
            (
                "zcode_agent_spawn",
                Step::Ok(json!({"agent_id":"agent","submission_disposition":"existing"})),
            ),
            (
                "zcode_agent_poll",
                Step::Ok(json!({"next_revision":1,"task":{"phase":"TERMINAL"}})),
            ),
            (
                "zcode_agent_result",
                Step::Ok(
                    json!({"result":{"outcome":"FAILED","final_text":"failure","result_sha256":"b".repeat(64)}}),
                ),
            ),
            ("zcode_agent_close", close()),
        ]);
        let run = run_shadow_v2(&client, &config(directory.path()))
            .await
            .unwrap();
        assert_eq!(
            run.provenance.classification,
            EvidenceClassification::EvidenceIncomplete
        );
        assert!(!directory.path().join("artifacts/S01-ZCODE-RAW.md").exists());
    }

    #[tokio::test]
    async fn poll_error_still_closes_spawned_agent() {
        let directory = tempfile::tempdir().unwrap();
        let client = MockClient::new(vec![
            (
                "zcode_agent_spawn",
                Step::Ok(json!({"agent_id":"agent","submission_disposition":"created"})),
            ),
            ("zcode_agent_poll", Step::Err),
            ("zcode_agent_close", close()),
        ]);
        assert!(run_shadow_v2(&client, &config(directory.path()))
            .await
            .is_err());
        assert_eq!(
            client.calls.lock().unwrap().as_slice(),
            ["zcode_agent_spawn", "zcode_agent_poll", "zcode_agent_close"]
        );
    }
}
