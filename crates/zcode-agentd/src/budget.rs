#[cfg(test)]
use zcode_agent_preparation::BudgetLimits;
use zcode_agent_store::EffectiveBudget;
use std::{
    collections::HashSet,
    sync::Mutex,
    time::{Duration, Instant},
};
use zcode_driver::Inbound;
use zcode_protocol::{event_type, WireMessage};

const MAX_RUNTIME_ID_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BudgetViolation {
    WallTime,
    TurnLimit,
    ToolCallLimit,
    AmbiguousTurnIdentity,
    AmbiguousToolIdentity,
}

impl BudgetViolation {
    pub(crate) fn reason_code(self) -> &'static str {
        match self {
            Self::WallTime => "WALL_TIME_DEADLINE_EXCEEDED",
            Self::TurnLimit => "TURN_BUDGET_EXHAUSTED",
            Self::ToolCallLimit => "TOOL_CALL_BUDGET_EXHAUSTED",
            Self::AmbiguousTurnIdentity => "TURN_IDENTITY_AMBIGUOUS",
            Self::AmbiguousToolIdentity => "TOOL_CALL_IDENTITY_AMBIGUOUS",
        }
    }
}

#[derive(Debug)]
struct BudgetState {
    turns: HashSet<String>,
    tool_calls: HashSet<String>,
    violation: Option<BudgetViolation>,
}

#[derive(Debug)]
pub(crate) struct RuntimeBudget {
    deadline: Instant,
    max_turns: u64,
    max_tool_calls: u64,
    state: Mutex<BudgetState>,
}

impl RuntimeBudget {
    #[cfg(test)]
    pub(crate) fn new(limits: &BudgetLimits) -> Self {
        Self::with_limits(
            limits.absolute_wall_time_ms,
            limits.max_turns,
            limits.max_tool_calls,
        )
    }

    pub(crate) fn from_effective(limits: &EffectiveBudget) -> Self {
        Self::with_limits(
            limits.absolute_wall_time_ms,
            limits.max_turns,
            limits.max_tool_calls,
        )
    }

    fn with_limits(wall_time_ms: u64, max_turns: u64, max_tool_calls: u64) -> Self {
        Self {
            deadline: Instant::now()
                .checked_add(Duration::from_millis(wall_time_ms))
                .unwrap_or_else(Instant::now),
            max_turns,
            max_tool_calls,
            state: Mutex::new(BudgetState {
                turns: HashSet::new(),
                tool_calls: HashSet::new(),
                violation: None,
            }),
        }
    }

    pub(crate) fn observe(&self, inbound: &Inbound) {
        let Inbound::Message(WireMessage::Event(event)) = inbound else {
            return;
        };
        let Some(kind) = event_type(event) else {
            return;
        };
        let mut state = self.state.lock().unwrap();
        if state.violation.is_some() {
            return;
        }
        match kind {
            "turn.started" => {
                let Some(identity) = unique_event_identity(event, "turnId") else {
                    state.violation = Some(BudgetViolation::AmbiguousTurnIdentity);
                    return;
                };
                state.turns.insert(identity);
                if state.turns.len() as u64 > self.max_turns {
                    state.violation = Some(BudgetViolation::TurnLimit);
                }
            }
            "tool.updated" => {
                let identity = unique_event_identity(event, "toolCallId");
                let Some(identity) = identity else {
                    state.violation = Some(BudgetViolation::AmbiguousToolIdentity);
                    return;
                };
                state.tool_calls.insert(identity);
                if state.tool_calls.len() as u64 > self.max_tool_calls {
                    state.violation = Some(BudgetViolation::ToolCallLimit);
                }
            }
            _ => {}
        }
    }

    pub(crate) fn violation(&self) -> Option<BudgetViolation> {
        let mut state = self.state.lock().unwrap();
        if state.violation.is_none() && Instant::now() >= self.deadline {
            state.violation = Some(BudgetViolation::WallTime);
        }
        state.violation
    }

    pub(crate) fn remaining(&self) -> Option<Duration> {
        self.deadline.checked_duration_since(Instant::now())
    }

    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }

    #[cfg(test)]
    fn counts(&self) -> (u64, usize) {
        let state = self.state.lock().unwrap();
        (state.turns.len() as u64, state.tool_calls.len())
    }
}

fn unique_event_identity(event: &zcode_protocol::EventEnvelope, key: &str) -> Option<String> {
    let nested = event
        .params
        .get("payload")
        .and_then(|payload| payload.get(key));
    let top_level = event.params.get(key);
    match (
        nested.map(valid_runtime_identity),
        top_level.map(valid_runtime_identity),
    ) {
        (Some(Some(nested)), Some(Some(top_level))) if nested == top_level => {
            Some(nested.to_owned())
        }
        (Some(Some(identity)), None) | (None, Some(Some(identity))) => Some(identity.to_owned()),
        _ => None,
    }
}

fn valid_runtime_identity(value: &serde_json::Value) -> Option<&str> {
    value.as_str().filter(|identity| {
        !identity.is_empty() && identity.len() <= MAX_RUNTIME_ID_BYTES && !identity.contains('\0')
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcode_protocol::{EventEnvelope, WireMessage};

    fn limits() -> BudgetLimits {
        BudgetLimits {
            absolute_wall_time_ms: 10_000,
            runtime_activity_idle_timeout_ms: 1_000,
            model_stream_idle_timeout_ms: 1_000,
            tool_call_timeout_ms: 1_000,
            input_wait_timeout_ms: 1_000,
            max_turns: 2,
            max_tool_calls: 1,
            max_context_bytes: 1,
            max_result_bytes: 1,
            max_artifact_bytes: 1,
        }
    }

    fn event(kind: &str, payload: serde_json::Value) -> Inbound {
        Inbound::Message(WireMessage::Event(EventEnvelope {
            method: "session/event".into(),
            params: serde_json::json!({"type":kind,"payload":payload}),
        }))
    }

    #[test]
    fn duplicate_tool_updates_count_once_and_ambiguous_identity_fails_closed() {
        let budget = RuntimeBudget::new(&limits());
        budget.observe(&event(
            "tool.updated",
            serde_json::json!({"toolCallId":"tool-1"}),
        ));
        budget.observe(&event(
            "tool.updated",
            serde_json::json!({"toolCallId":"tool-1"}),
        ));
        assert_eq!(budget.counts(), (0, 1));
        assert_eq!(budget.violation(), None);
        budget.observe(&event(
            "tool.updated",
            serde_json::json!({"toolCallId":"tool-2"}),
        ));
        assert_eq!(budget.violation(), Some(BudgetViolation::ToolCallLimit));

        let ambiguous = RuntimeBudget::new(&limits());
        ambiguous.observe(&event(
            "tool.updated",
            serde_json::json!({"toolName":"Bash"}),
        ));
        assert_eq!(
            ambiguous.violation(),
            Some(BudgetViolation::AmbiguousToolIdentity)
        );
    }

    #[test]
    fn duplicate_turn_identity_counts_once_and_ambiguous_identity_fails_closed() {
        let budget = RuntimeBudget::new(&limits());
        budget.observe(&event(
            "turn.started",
            serde_json::json!({"turnId":"turn-1"}),
        ));
        budget.observe(&event(
            "turn.started",
            serde_json::json!({"turnId":"turn-1"}),
        ));
        assert_eq!(budget.counts(), (1, 0));
        assert_eq!(budget.violation(), None);
        budget.observe(&event(
            "turn.started",
            serde_json::json!({"turnId":"turn-2"}),
        ));
        assert_eq!(budget.counts(), (2, 0));
        assert_eq!(budget.violation(), None);

        let missing = RuntimeBudget::new(&limits());
        missing.observe(&event("turn.started", serde_json::json!({})));
        assert_eq!(
            missing.violation(),
            Some(BudgetViolation::AmbiguousTurnIdentity)
        );

        let conflicting = RuntimeBudget::new(&limits());
        let Inbound::Message(WireMessage::Event(mut event)) =
            event("turn.started", serde_json::json!({"turnId":"turn-1"}))
        else {
            unreachable!()
        };
        event.params["turnId"] = serde_json::json!("other-turn");
        conflicting.observe(&Inbound::Message(WireMessage::Event(event)));
        assert_eq!(
            conflicting.violation(),
            Some(BudgetViolation::AmbiguousTurnIdentity)
        );
    }
}
