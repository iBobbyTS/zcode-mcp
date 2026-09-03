use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use zcode_reviewd::rpc::{PendingRequestStateView, PendingRequestView, RpcError, RpcErrorCode};

pub mod v2;
pub use v2::{serve_stdio_v2, SubagentMcp, V2_PUBLIC_TOOLS};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PublicPendingKind {
    Permission,
    UnsupportedInput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PublicPendingState {
    Pending,
    Sending,
    Responded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PublicPolicyPreview {
    ExternallyDecidable,
    HardDeny,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PublicOperation {
    Read,
    Write,
    Command,
    Network,
    GitRefMutation,
    UserInput,
    Unknown,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct PublicPendingRequest {
    pub request_id: String,
    pub kind: PublicPendingKind,
    pub state: PublicPendingState,
    pub respondable: bool,
    pub tool_name: Option<String>,
    pub operation: PublicOperation,
    pub summary: String,
    pub policy_preview: PublicPolicyPreview,
}

impl From<PendingRequestView> for PublicPendingRequest {
    fn from(value: PendingRequestView) -> Self {
        Self {
            request_id: value.request_id,
            kind: if value.kind == "permission" {
                PublicPendingKind::Permission
            } else {
                PublicPendingKind::UnsupportedInput
            },
            state: match value.state {
                PendingRequestStateView::Pending => PublicPendingState::Pending,
                PendingRequestStateView::Sending => PublicPendingState::Sending,
                PendingRequestStateView::Responded => PublicPendingState::Responded,
            },
            respondable: value.respondable,
            tool_name: value.tool_name,
            operation: match value.operation.as_str() {
                "read" => PublicOperation::Read,
                "write" => PublicOperation::Write,
                "command" => PublicOperation::Command,
                "network" => PublicOperation::Network,
                "git_ref_mutation" => PublicOperation::GitRefMutation,
                "user_input" => PublicOperation::UserInput,
                _ => PublicOperation::Unknown,
            },
            summary: value.summary,
            policy_preview: match value.policy_preview.as_str() {
                "externally_decidable" => PublicPolicyPreview::ExternallyDecidable,
                "hard_deny" => PublicPolicyPreview::HardDeny,
                _ => PublicPolicyPreview::Unknown,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PublicDecision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PublicResponseDisposition {
    Responded,
    AlreadyResponded,
    InFlight,
}

pub(crate) fn public_error(error: RpcError) -> String {
    let (code, message) = match error.code {
        RpcErrorCode::Malformed | RpcErrorCode::Validation => {
            ("validation", "request validation failed")
        }
        RpcErrorCode::Oversized => ("oversized", "bounded response or request was too large"),
        RpcErrorCode::UnsupportedVersion => {
            ("protocol_version_mismatch", "incompatible subagent daemon")
        }
        RpcErrorCode::UnknownMethod => ("protocol_error", "daemon method is unavailable"),
        RpcErrorCode::NotFound => ("not_found", "agent task was not found"),
        RpcErrorCode::Conflict => ("conflict", "agent operation conflicts with durable state"),
        RpcErrorCode::Timeout => ("timeout", "daemon operation timed out"),
        RpcErrorCode::RuntimeLost => ("runtime_lost", "agent runtime was lost"),
        RpcErrorCode::ResultInvalid => ("result_invalid", "stored task result failed verification"),
        RpcErrorCode::Persistence | RpcErrorCode::Unavailable | RpcErrorCode::Internal => (
            "daemon_unavailable",
            "subagent daemon could not complete the operation",
        ),
    };
    format!("{code}: {message}")
}

pub(crate) fn public_transport_error(error: std::io::Error) -> String {
    String::from(match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
            "timeout: daemon call exceeded its bound"
        }
        std::io::ErrorKind::InvalidData => {
            "protocol_error: daemon returned an invalid or oversized frame"
        }
        _ => "daemon_unavailable: subagent daemon is unavailable",
    })
}

pub(crate) fn protocol_error() -> String {
    "protocol_error: unexpected daemon response".into()
}
