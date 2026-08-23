use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestEnvelope {
    pub id: Value,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseEnvelope {
    pub id: Value,
    #[serde(default)]
    pub result: Option<Value>,
    #[serde(default)]
    pub error: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    InvalidJson(String),
    NotObject,
    MissingKind,
    InvalidEnvelope(String),
}

pub fn parse_line(line: &str) -> Result<WireMessage, ParseError> {
    let value: Value =
        serde_json::from_str(line).map_err(|e| ParseError::InvalidJson(e.to_string()))?;
    let obj = value.as_object().ok_or(ParseError::NotObject)?;
    if obj.contains_key("id") && (obj.contains_key("result") || obj.contains_key("error")) {
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

pub fn encode<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    serde_json::to_string(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_trip() {
        let req = RequestEnvelope {
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
}
