use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const WORKSPACE_READ_STATE: &str = "workspace/readState";
pub const SESSION_CREATE: &str = "session/create";
pub const SESSION_SUBSCRIBE: &str = "session/subscribe";
pub const SESSION_SEND: &str = "session/send";
pub const SESSION_STOP: &str = "session/stop";
pub const SESSION_CLOSE: &str = "session/close";
pub const SESSION_EVENT: &str = "session/event";
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

pub fn session_id_from_result(result: &Value) -> Option<&str> {
    result.get("sessionId").and_then(Value::as_str).or_else(|| {
        result
            .get("session")
            .and_then(|session| session.get("sessionId"))
            .and_then(Value::as_str)
    })
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
pub struct CreateSessionParams<'a> {
    pub workspace: WorkspaceRef<'a>,
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
                    matches!(
                        kind,
                        "turn.started" | "turn.completed" | "turn.failed" | "permission.responded"
                    )
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
    fn session_and_turn_ids_accept_observed_result_shapes() {
        let nested = serde_json::json!({"session": {"sessionId": "s1"}, "turnId": "t1"});
        assert_eq!(session_id_from_result(&nested), Some("s1"));
        assert_eq!(turn_id_from_result(&nested), Some("t1"));
        assert_eq!(
            session_id_from_result(&serde_json::json!({"sessionId": "s2"})),
            Some("s2")
        );
        assert_eq!(
            session_id_from_result(&serde_json::json!({"session": {"id": "legacy"}})),
            None
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
}
