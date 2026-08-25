use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

pub const WORKSPACE_READ_STATE: &str = "workspace/readState";
pub const SESSION_CREATE: &str = "session/create";
pub const SESSION_SUBSCRIBE: &str = "session/subscribe";
pub const SESSION_SEND: &str = "session/send";
pub const SESSION_STOP: &str = "session/stop";
pub const SESSION_CLOSE: &str = "session/close";
pub const SESSION_EVENT: &str = "session/event";
pub const SESSION_REQUEST_RUNTIME_PREFERENCES: &str = "session/requestRuntimePreferences";
pub const INTERACTION_REQUEST_PERMISSION: &str = "interaction/requestPermission";
pub const INTERACTION_REQUEST_USER_INPUT: &str = "interaction/requestUserInput";

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WireId {
    Integer(i64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestEnvelope {
    pub id: WireId,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEnvelope {
    pub id: WireId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventEnvelope {
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireMessage {
    Request(RequestEnvelope),
    Response(ResponseEnvelope),
    Event(EventEnvelope),
    UnknownEvent { method: String, raw: Value },
}

impl RequestEnvelope {
    pub fn new(id: WireId, method: impl Into<String>, params: Value) -> Self {
        Self {
            id,
            method: method.into(),
            params,
        }
    }
}

impl ResponseEnvelope {
    pub fn success(id: WireId, result: Value) -> Self {
        Self {
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn failure(id: WireId, error: Value) -> Self {
        Self {
            id,
            result: None,
            error: Some(error),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectionError {
    Missing(&'static str),
    Invalid(&'static str),
    UnobservedAlternate(&'static str),
    ModelConflict,
}

impl fmt::Display for ProjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(path) => write!(formatter, "missing authoritative field {path}"),
            Self::Invalid(path) => write!(formatter, "invalid pinned field {path}"),
            Self::UnobservedAlternate(path) => {
                write!(formatter, "unobserved alternate field {path} is present")
            }
            Self::ModelConflict => write!(formatter, "requested and observed model conflict"),
        }
    }
}

impl std::error::Error for ProjectionError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCreateProjection {
    pub session_id: String,
    pub requested_model: Option<String>,
}

impl SessionCreateProjection {
    pub fn from_result(result: &Value) -> Result<Self, ProjectionError> {
        let root = result
            .as_object()
            .ok_or(ProjectionError::Invalid("result"))?;
        reject_alternate(root, "sessionId", "result.sessionId")?;
        reject_alternate(root, "session_id", "result.session_id")?;
        reject_alternate(root, "modelId", "result.modelId")?;
        reject_alternate(root, "model", "result.model")?;

        let session = root
            .get("session")
            .ok_or(ProjectionError::Missing("result.session.sessionId"))?
            .as_object()
            .ok_or(ProjectionError::Invalid("result.session"))?;
        reject_alternate(session, "id", "result.session.id")?;
        reject_alternate(session, "session_id", "result.session.session_id")?;
        reject_alternate(session, "modelId", "result.session.modelId")?;
        reject_alternate(session, "settings", "result.session.settings")?;

        let session_id =
            required_bounded_string(session.get("sessionId"), "result.session.sessionId", 512)?
                .to_owned();
        // result.projection.sessionId is an independent identifier in pinned
        // 3.8.1. It is intentionally not inspected or used as provenance.

        let requested_model = settings_current_model(root)?;
        let consistency_model = session_consistency_model(session)?;
        match (&requested_model, &consistency_model) {
            (Some(requested), Some(observed))
                if normalized_zai_model(requested) != normalized_zai_model(observed) =>
            {
                return Err(ProjectionError::ModelConflict);
            }
            (None, Some(_)) => {
                return Err(ProjectionError::Missing(
                    "result.settings.model.current.modelId",
                ));
            }
            _ => {}
        }

        Ok(Self {
            session_id,
            requested_model,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceDiagnosticProjection {
    pub current_model: Option<String>,
    pub available_models: Vec<String>,
}

impl WorkspaceDiagnosticProjection {
    pub fn from_result(result: &Value) -> Result<Self, ProjectionError> {
        let root = result
            .as_object()
            .ok_or(ProjectionError::Invalid("result"))?;
        let current_model = settings_current_model(root)?;
        let mut available_models = Vec::new();
        if let Some(catalog) = optional_object(root, "modelCatalog", "result.modelCatalog")? {
            if let Some(available) = catalog.get("available") {
                let available = available
                    .as_array()
                    .ok_or(ProjectionError::Invalid("result.modelCatalog.available"))?;
                for item in available {
                    let item = item
                        .as_object()
                        .ok_or(ProjectionError::Invalid("result.modelCatalog.available[]"))?;
                    available_models.push(
                        required_bounded_string(
                            item.get("modelId"),
                            "result.modelCatalog.available[].modelId",
                            128,
                        )?
                        .to_owned(),
                    );
                }
            }
        }
        available_models.sort();
        available_models.dedup();
        Ok(Self {
            current_model,
            available_models,
        })
    }
}

pub fn normalized_zai_model(value: &str) -> Option<String> {
    if value.is_empty() || value.len() > 128 || value.contains('\0') {
        return None;
    }
    let model = match value.split_once('/') {
        Some(("zai", model)) => model,
        Some(_) => return None,
        None => value,
    };
    if model.is_empty() || model.contains('/') {
        return None;
    }
    Some(model.to_ascii_lowercase())
}

fn reject_alternate(
    object: &serde_json::Map<String, Value>,
    key: &str,
    path: &'static str,
) -> Result<(), ProjectionError> {
    if object.contains_key(key) {
        Err(ProjectionError::UnobservedAlternate(path))
    } else {
        Ok(())
    }
}

fn optional_object<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
    path: &'static str,
) -> Result<Option<&'a serde_json::Map<String, Value>>, ProjectionError> {
    object
        .get(key)
        .map(|value| value.as_object().ok_or(ProjectionError::Invalid(path)))
        .transpose()
}

fn settings_current_model(
    root: &serde_json::Map<String, Value>,
) -> Result<Option<String>, ProjectionError> {
    let Some(settings) = optional_object(root, "settings", "result.settings")? else {
        return Ok(None);
    };
    let Some(model) = optional_object(settings, "model", "result.settings.model")? else {
        return Ok(None);
    };
    reject_alternate(model, "value", "result.settings.model.value")?;
    let Some(current) = optional_object(model, "current", "result.settings.model.current")? else {
        return Ok(None);
    };
    reject_alternate(current, "id", "result.settings.model.current.id")?;
    let Some(value) = current.get("modelId") else {
        return Ok(None);
    };
    let value = required_bounded_string(Some(value), "result.settings.model.current.modelId", 128)?;
    if normalized_zai_model(value).is_none() {
        return Err(ProjectionError::Invalid(
            "result.settings.model.current.modelId",
        ));
    }
    Ok(Some(value.to_owned()))
}

fn session_consistency_model(
    session: &serde_json::Map<String, Value>,
) -> Result<Option<String>, ProjectionError> {
    let Some(model) = optional_object(session, "model", "result.session.model")? else {
        return Ok(None);
    };
    let Some(value) = model.get("modelId") else {
        return Ok(None);
    };
    let value = required_bounded_string(Some(value), "result.session.model.modelId", 128)?;
    if normalized_zai_model(value).is_none() {
        return Err(ProjectionError::Invalid("result.session.model.modelId"));
    }
    Ok(Some(value.to_owned()))
}

fn required_bounded_string<'a>(
    value: Option<&'a Value>,
    path: &'static str,
    max_len: usize,
) -> Result<&'a str, ProjectionError> {
    let value = value.ok_or(ProjectionError::Missing(path))?;
    let value = value.as_str().ok_or(ProjectionError::Invalid(path))?;
    if value.is_empty() || value.len() > max_len || value.contains('\0') {
        return Err(ProjectionError::Invalid(path));
    }
    Ok(value)
}

pub fn turn_id_from_result(result: &Value) -> Option<&str> {
    result.get("turnId").and_then(Value::as_str)
}

pub fn event_type(event: &EventEnvelope) -> Option<&str> {
    (event.method == SESSION_EVENT)
        .then(|| event.params.get("type").and_then(Value::as_str))
        .flatten()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceRef<'a> {
    pub workspace_key: &'a str,
    pub workspace_path: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceParams<'a> {
    pub workspace: WorkspaceRef<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSessionParams<'a> {
    pub workspace: WorkspaceRef<'a>,
    #[serde(skip_serializing_if = "is_empty_mcp_servers")]
    pub mcp_servers: &'a [StdioMcpServer],
}

fn is_empty_mcp_servers(servers: &&[StdioMcpServer]) -> bool {
    servers.is_empty()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StdioMcpServer {
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
    pub env: Vec<McpEnvironmentVariable>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpEnvironmentVariable {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscribeParams<'a> {
    pub session_id: &'a str,
    pub delivery_kind: &'static str,
    pub include_snapshot: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SendParams<'a> {
    pub session_id: &'a str,
    pub content: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionParams<'a> {
    pub session_id: &'a str,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimePreferences {
    pub native_search_enhancements_enabled: bool,
    pub memory_enabled: bool,
    pub ask_user_question_auto_resolution_enabled: bool,
}

pub fn offered_permission_response(params: &Value, decision: &str) -> Option<Value> {
    let expected_kind = match decision {
        "allow" => "allow_once",
        "deny" => "deny",
        _ => return None,
    };
    let matches = params
        .get("options")?
        .as_array()?
        .iter()
        .filter(|option| option.get("kind").and_then(Value::as_str) == Some(expected_kind))
        .collect::<Vec<_>>();
    let [option] = matches.as_slice() else {
        return None;
    };
    let response = option.get("response")?.as_object()?;
    (response.get("decision").and_then(Value::as_str) == Some(decision))
        .then(|| Value::Object(response.clone()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    InvalidJson(String),
    NotObject,
    MissingKind,
    InvalidEnvelope(String),
    ContradictoryResponse,
}

pub fn parse_line(line: &str) -> Result<WireMessage, ParseError> {
    let value: Value =
        serde_json::from_str(line).map_err(|e| ParseError::InvalidJson(e.to_string()))?;
    let obj = value.as_object().ok_or(ParseError::NotObject)?;
    if obj.contains_key("jsonrpc") {
        return Err(ParseError::InvalidEnvelope(
            "jsonrpc is not part of the strict ZCode envelope".into(),
        ));
    }
    if obj.contains_key("id") && (obj.contains_key("result") || obj.contains_key("error")) {
        if obj.contains_key("result") && obj.contains_key("error") {
            return Err(ParseError::ContradictoryResponse);
        }
        if obj
            .get("result")
            .or_else(|| obj.get("error"))
            .is_none_or(Value::is_null)
        {
            return Err(ParseError::InvalidEnvelope(
                "response requires exactly one non-null result or error".into(),
            ));
        }
        return serde_json::from_value(value)
            .map(WireMessage::Response)
            .map_err(|e| ParseError::InvalidEnvelope(e.to_string()));
    }
    if let Some(method) = obj.get("method").and_then(Value::as_str) {
        if obj.contains_key("id") {
            return serde_json::from_value(value)
                .map(WireMessage::Request)
                .map_err(|e| ParseError::InvalidEnvelope(e.to_string()));
        }
        let known = method == SESSION_EVENT
            && obj
                .get("params")
                .and_then(|params| params.get("type"))
                .and_then(Value::as_str)
                .is_some_and(|kind| {
                    matches!(kind, "turn.started" | "turn.completed" | "turn.failed")
                });
        return if known {
            serde_json::from_value(value)
                .map(WireMessage::Event)
                .map_err(|e| ParseError::InvalidEnvelope(e.to_string()))
        } else {
            Ok(WireMessage::UnknownEvent {
                method: method.into(),
                raw: value,
            })
        };
    }
    Err(ParseError::MissingKind)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleOrder {
    NotLifecycle,
    InOrder,
    OutOfOrder { expected: &'static str },
}

/// Classify lifecycle events without reordering or dropping the wire stream.
pub fn classify_lifecycle(method: &str, turn_active: bool) -> LifecycleOrder {
    match (method, turn_active) {
        ("turn.started", false) => LifecycleOrder::InOrder,
        ("turn.started", true) => LifecycleOrder::OutOfOrder {
            expected: "turn.completed or turn.failed",
        },
        ("turn.completed" | "turn.failed", true) => LifecycleOrder::InOrder,
        ("turn.completed" | "turn.failed", false) => LifecycleOrder::OutOfOrder {
            expected: "turn.started",
        },
        _ => LifecycleOrder::NotLifecycle,
    }
}

pub fn encode<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    serde_json::to_string(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_trip() {
        let req = RequestEnvelope {
            id: WireId::Integer(1),
            method: SESSION_CREATE.into(),
            params: serde_json::json!({"x":1}),
        };
        let parsed = parse_line(&encode(&req).unwrap()).unwrap();
        assert_eq!(parsed, WireMessage::Request(req));
        assert!(!encode(&RequestEnvelope::new(
            WireId::Integer(2),
            SESSION_SEND,
            serde_json::json!({"sessionId":"s1","content":"review"}),
        ))
        .unwrap()
        .contains("jsonrpc"));
    }
    #[test]
    fn unknown_preserved() {
        let msg = parse_line(r#"{"method":"new/event","params":{"a":2}}"#).unwrap();
        assert!(matches!(msg, WireMessage::UnknownEvent { .. }));
    }

    #[test]
    fn observed_permission_resolution_remains_bounded_without_typed_semantics() {
        let msg = parse_line(
            r#"{"method":"session/event","params":{"sessionId":"s1","type":"permission.resolved","payload":{"future":"shape"}}}"#,
        )
        .unwrap();
        assert!(matches!(msg, WireMessage::UnknownEvent { .. }));
    }
    #[test]
    fn malformed_classified() {
        assert!(matches!(parse_line("{"), Err(ParseError::InvalidJson(_))));
    }

    #[test]
    fn contradictory_response_is_rejected() {
        assert_eq!(
            parse_line(r#"{"id":1,"result":{},"error":{}}"#),
            Err(ParseError::ContradictoryResponse)
        );
    }

    #[test]
    fn wire_ids_are_limited_to_integer_or_string() {
        for id in ["true", "null", "{}", "[]", "1.5"] {
            let request = format!(r#"{{"id":{id},"method":"session/stop","params":{{}}}}"#);
            assert!(matches!(
                parse_line(&request),
                Err(ParseError::InvalidEnvelope(_))
            ));
            let response = format!(r#"{{"id":{id},"result":{{}}}}"#);
            assert!(matches!(
                parse_line(&response),
                Err(ParseError::InvalidEnvelope(_))
            ));
        }
        assert!(matches!(
            parse_line(r#"{"id":"server-1","method":"interaction/requestPermission","params":{}}"#),
            Ok(WireMessage::Request(RequestEnvelope {
                id: WireId::String(ref id),
                ..
            })) if id == "server-1"
        ));
    }

    #[test]
    fn response_requires_exactly_one_non_null_outcome() {
        for frame in [
            r#"{"id":1}"#,
            r#"{"id":1,"result":null}"#,
            r#"{"id":1,"error":null}"#,
            r#"{"id":1,"result":null,"error":null}"#,
            r#"{"id":1,"result":{},"error":null}"#,
            r#"{"id":1,"result":null,"error":{}}"#,
            r#"{"id":1,"result":{},"error":{}}"#,
        ] {
            assert!(
                parse_line(frame).is_err(),
                "accepted malformed response: {frame}"
            );
        }
        assert!(matches!(
            parse_line(r#"{"id":1,"result":{}}"#),
            Ok(WireMessage::Response(ResponseEnvelope {
                id: WireId::Integer(1),
                result: Some(_),
                error: None,
            }))
        ));
    }

    #[test]
    fn legacy_jsonrpc_envelope_is_rejected() {
        assert!(matches!(
            parse_line(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#),
            Err(ParseError::InvalidEnvelope(_))
        ));
    }

    #[test]
    fn lifecycle_order_is_explicit() {
        assert_eq!(
            classify_lifecycle("turn.completed", false),
            LifecycleOrder::OutOfOrder {
                expected: "turn.started"
            }
        );
    }

    #[test]
    fn session_projection_requires_the_authoritative_nested_id() {
        let nested = serde_json::json!({"session": {"sessionId": "s1"}, "turnId": "t1"});
        assert_eq!(
            SessionCreateProjection::from_result(&nested).unwrap(),
            SessionCreateProjection {
                session_id: "s1".into(),
                requested_model: None,
            }
        );
        assert_eq!(turn_id_from_result(&nested), Some("t1"));

        for invalid in [
            serde_json::json!({}),
            serde_json::json!({"session": null}),
            serde_json::json!({"session": {}}),
            serde_json::json!({"session": {"sessionId": null}}),
            serde_json::json!({"session": {"sessionId": ""}}),
            serde_json::json!({"session": {"sessionId": 7}}),
        ] {
            assert!(SessionCreateProjection::from_result(&invalid).is_err());
        }
    }

    #[test]
    fn projection_identifier_is_always_ignored_for_session_provenance() {
        for projection in [
            None,
            Some(serde_json::json!({"sessionId": "different-projection"})),
            Some(serde_json::json!({"sessionId": null})),
            Some(serde_json::json!({"sessionId": 42})),
        ] {
            let mut result = serde_json::json!({"session": {"sessionId": "authoritative"}});
            if let Some(projection) = projection {
                result["projection"] = projection;
            }
            assert_eq!(
                SessionCreateProjection::from_result(&result)
                    .unwrap()
                    .session_id,
                "authoritative"
            );
        }
    }

    #[test]
    fn unobserved_session_fallbacks_fail_closed_even_when_they_coexist() {
        for invalid in [
            serde_json::json!({"sessionId": "fallback", "session": {}}),
            serde_json::json!({
                "sessionId": "authoritative",
                "session": {"sessionId": "authoritative"}
            }),
        ] {
            assert!(SessionCreateProjection::from_result(&invalid).is_err());
        }
    }

    #[test]
    fn model_projection_uses_settings_current_with_optional_session_consistency() {
        let base = serde_json::json!({
            "session": {"sessionId": "session"},
            "settings": {"model": {"current": {"modelId": "GLM-5.3"}}}
        });
        assert_eq!(
            SessionCreateProjection::from_result(&base)
                .unwrap()
                .requested_model
                .as_deref(),
            Some("GLM-5.3")
        );

        let equal = serde_json::json!({
            "session": {
                "sessionId": "session",
                "model": {"modelId": "zai/glm-5.3"}
            },
            "settings": {"model": {"current": {"modelId": "GLM-5.3"}}}
        });
        assert!(SessionCreateProjection::from_result(&equal).is_ok());

        for consistency in [
            serde_json::Value::Null,
            serde_json::json!(""),
            serde_json::json!(7),
            serde_json::json!("glm-5.1"),
        ] {
            let mut invalid = base.clone();
            invalid["session"]["model"] = serde_json::json!({"modelId": consistency});
            assert!(SessionCreateProjection::from_result(&invalid).is_err());
        }
    }

    #[test]
    fn model_projection_preserves_absence_and_rejects_fallbacks_or_alternates() {
        let absent = serde_json::json!({"session": {"sessionId": "session"}});
        assert_eq!(
            SessionCreateProjection::from_result(&absent)
                .unwrap()
                .requested_model,
            None
        );

        let consistency_only = serde_json::json!({
            "session": {
                "sessionId": "session",
                "model": {"modelId": "glm-5.3"}
            }
        });
        assert!(SessionCreateProjection::from_result(&consistency_only).is_err());

        for invalid in [
            serde_json::json!({
                "session": {"sessionId": "session"},
                "settings": {"model": {"current": {"modelId": null}}}
            }),
            serde_json::json!({
                "session": {"sessionId": "session"},
                "settings": {"model": {"current": {"modelId": ""}}}
            }),
            serde_json::json!({
                "session": {"sessionId": "session"},
                "settings": {"model": {"current": {"modelId": 7}}}
            }),
            serde_json::json!({
                "modelId": "glm-5.3",
                "session": {"sessionId": "session"},
                "settings": {"model": {"current": {"modelId": "glm-5.3"}}}
            }),
            serde_json::json!({
                "session": {"sessionId": "session", "modelId": "glm-5.3"},
                "settings": {"model": {"current": {"modelId": "glm-5.3"}}}
            }),
            serde_json::json!({
                "session": {
                    "sessionId": "session",
                    "settings": {"model": {"current": {"modelId": "glm-5.3"}}}
                },
                "settings": {"model": {"current": {"modelId": "glm-5.3"}}}
            }),
        ] {
            assert!(SessionCreateProjection::from_result(&invalid).is_err());
        }
    }

    #[test]
    fn workspace_diagnostic_projection_uses_only_observed_catalog_paths() {
        let projection = WorkspaceDiagnosticProjection::from_result(&serde_json::json!({
            "settings": {"model": {"current": {"modelId": "glm-current"}}},
            "modelCatalog": {"available": [
                {"modelId": "glm-other"},
                {"modelId": "glm-current"},
                {"modelId": "glm-current"}
            ]}
        }))
        .unwrap();
        assert_eq!(projection.current_model.as_deref(), Some("glm-current"));
        assert_eq!(
            projection.available_models,
            vec!["glm-current", "glm-other"]
        );

        assert!(
            WorkspaceDiagnosticProjection::from_result(&serde_json::json!({
                "settings": {"model": {"current": {"modelId": 7}}}
            }))
            .is_err()
        );
    }

    #[test]
    fn session_event_exposes_lifecycle_discriminator() {
        let event = parse_line(
            r#"{"method":"session/event","params":{"sessionId":"s1","type":"turn.started"}}"#,
        )
        .unwrap();
        let WireMessage::Event(event) = event else {
            panic!("session/event must remain on the event stream");
        };
        assert_eq!(event_type(&event), Some("turn.started"));
    }

    #[test]
    fn session_create_serializes_the_observed_acp_mcp_array_shape() {
        let servers = vec![StdioMcpServer {
            name: "review-ledger".into(),
            command: "/usr/bin/reviewd".into(),
            args: vec!["--ledger-mcp".into(), "--agent-id".into(), "job".into()],
            env: Vec::new(),
        }];
        let value = serde_json::to_value(CreateSessionParams {
            workspace: WorkspaceRef {
                workspace_key: "/work",
                workspace_path: "/work",
            },
            mcp_servers: &servers,
        })
        .unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "workspace":{"workspaceKey":"/work","workspacePath":"/work"},
                "mcpServers":[{
                    "name":"review-ledger","command":"/usr/bin/reviewd",
                    "args":["--ledger-mcp","--agent-id","job"],"env":[]
                }]
            })
        );
    }

    #[test]
    fn official_workspace_preferences_and_permission_shapes_are_exact() {
        assert_eq!(
            serde_json::to_value(WorkspaceParams {
                workspace: WorkspaceRef {
                    workspace_key: "/work",
                    workspace_path: "/work",
                },
            })
            .unwrap(),
            serde_json::json!({"workspace":{"workspaceKey":"/work","workspacePath":"/work"}})
        );
        assert_eq!(
            serde_json::to_value(RuntimePreferences::default()).unwrap(),
            serde_json::json!({
                "nativeSearchEnhancementsEnabled":false,
                "memoryEnabled":false,
                "askUserQuestionAutoResolutionEnabled":false
            })
        );
        let params = serde_json::json!({"options":[
            {"kind":"allow_once","response":{"decision":"allow","reason":"once"}},
            {"kind":"deny","response":{"decision":"deny","reason":"bounded"}}
        ]});
        assert_eq!(
            offered_permission_response(&params, "deny"),
            Some(serde_json::json!({"decision":"deny","reason":"bounded"}))
        );
        assert!(offered_permission_response(&params, "other").is_none());
        let mismatched = serde_json::json!({"options":[
            {"kind":"deny","response":{"decision":"allow"}}
        ]});
        assert!(offered_permission_response(&mismatched, "deny").is_none());
        let duplicate = serde_json::json!({"options":[
            {"kind":"deny","response":{"decision":"deny"}},
            {"kind":"deny","response":{"decision":"deny"}}
        ]});
        assert!(offered_permission_response(&duplicate, "deny").is_none());
    }
}
