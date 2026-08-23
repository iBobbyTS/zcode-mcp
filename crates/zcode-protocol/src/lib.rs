use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const JSON_RPC_VERSION: &str = "2.0";
pub const WORKSPACE_READ_STATE: &str = "workspace/readState";
pub const SESSION_CREATE: &str = "session/create";
pub const SESSION_SUBSCRIBE: &str = "session/subscribe";
pub const SESSION_SEND: &str = "session/send";
pub const SESSION_STOP: &str = "session/stop";
pub const SESSION_CLOSE: &str = "session/close";

fn default_jsonrpc() -> String {
    JSON_RPC_VERSION.into()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestEnvelope {
    #[serde(default = "default_jsonrpc")]
    pub jsonrpc: String,
    pub id: Value,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseEnvelope {
    #[serde(default = "default_jsonrpc")]
    pub jsonrpc: String,
    pub id: Value,
    #[serde(default)]
    pub result: Option<Value>,
    #[serde(default)]
    pub error: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventEnvelope {
    #[serde(default = "default_jsonrpc")]
    pub jsonrpc: String,
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
    pub fn new(id: Value, method: impl Into<String>, params: Value) -> Self {
        Self {
            jsonrpc: JSON_RPC_VERSION.into(),
            id,
            method: method.into(),
            params,
        }
    }
}

impl ResponseEnvelope {
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: JSON_RPC_VERSION.into(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn failure(id: Value, error: Value) -> Self {
        Self {
            jsonrpc: JSON_RPC_VERSION.into(),
            id,
            result: None,
            error: Some(error),
        }
    }
}

pub fn session_id_from_result(result: &Value) -> Option<&str> {
    result
        .get("session_id")
        .or_else(|| result.get("sessionId"))
        .and_then(Value::as_str)
        .or_else(|| {
            result
                .get("session")
                .and_then(|session| session.get("id"))
                .and_then(Value::as_str)
        })
}

pub fn turn_id_from_result(result: &Value) -> Option<&str> {
    result
        .get("turn_id")
        .or_else(|| result.get("turnId"))
        .and_then(Value::as_str)
        .or_else(|| {
            result
                .get("turn")
                .and_then(|turn| turn.get("id"))
                .and_then(Value::as_str)
        })
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
    if obj.contains_key("id") && (obj.contains_key("result") || obj.contains_key("error")) {
        if obj.contains_key("result") && obj.contains_key("error") {
            return Err(ParseError::ContradictoryResponse);
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
        let known = matches!(
            method,
            "turn/started"
                | "turn/completed"
                | "session/updated"
                | "permission/request"
                | "input/request"
                | "turn/failed"
        );
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
        ("turn/started", false) => LifecycleOrder::InOrder,
        ("turn/started", true) => LifecycleOrder::OutOfOrder {
            expected: "turn/completed or turn/failed",
        },
        ("turn/completed" | "turn/failed", true) => LifecycleOrder::InOrder,
        ("turn/completed" | "turn/failed", false) => LifecycleOrder::OutOfOrder {
            expected: "turn/started",
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
            jsonrpc: JSON_RPC_VERSION.into(),
            id: Value::from(1),
            method: "initialize".into(),
            params: serde_json::json!({"x":1}),
        };
        let parsed = parse_line(&encode(&req).unwrap()).unwrap();
        assert_eq!(parsed, WireMessage::Request(req));
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
    fn lifecycle_order_is_explicit() {
        assert_eq!(
            classify_lifecycle("turn/completed", false),
            LifecycleOrder::OutOfOrder {
                expected: "turn/started"
            }
        );
    }

    #[test]
    fn session_and_turn_ids_accept_observed_result_shapes() {
        let nested = serde_json::json!({"session": {"id": "s1"}, "turn": {"id": "t1"}});
        assert_eq!(session_id_from_result(&nested), Some("s1"));
        assert_eq!(turn_id_from_result(&nested), Some("t1"));
        assert_eq!(
            session_id_from_result(&serde_json::json!({"sessionId": "s2"})),
            Some("s2")
        );
    }
}
