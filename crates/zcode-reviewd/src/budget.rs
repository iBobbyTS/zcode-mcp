use review_preparation::BudgetLimits;
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
    AmbiguousToolIdentity,
}

impl BudgetViolation {
    pub(crate) fn reason_code(self) -> &'static str {
        match self {
            Self::WallTime => "WALL_TIME_BUDGET_EXHAUSTED",
            Self::TurnLimit => "TURN_BUDGET_EXHAUSTED",
            Self::ToolCallLimit => "TOOL_CALL_BUDGET_EXHAUSTED",
            Self::AmbiguousToolIdentity => "TOOL_CALL_IDENTITY_AMBIGUOUS",
        }
    }
}

#[derive(Debug)]
struct BudgetState {
    turns: u64,
    tool_calls: HashSet<String>,
    violation: Option<BudgetViolation>,
}

#[derive(Debug)]
pub(crate) struct AttemptBudget {
    deadline: Instant,
    max_turns: u64,
    max_tool_calls: u64,
    state: Mutex<BudgetState>,
}

impl AttemptBudget {
    pub(crate) fn new(limits: &BudgetLimits) -> Self {
        Self {
            deadline: Instant::now()
                .checked_add(Duration::from_millis(limits.wall_time_ms))
                .unwrap_or_else(Instant::now),
            max_turns: limits.max_turns,
            max_tool_calls: limits.max_tool_calls,
            state: Mutex::new(BudgetState {
                turns: 0,
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
                state.turns = state.turns.saturating_add(1);
                if state.turns > self.max_turns {
                    state.violation = Some(BudgetViolation::TurnLimit);
                }
            }
            "tool.updated" => {
                let identity = event
                    .params
                    .get("payload")
                    .and_then(|payload| payload.get("toolCallId"))
                    .and_then(serde_json::Value::as_str)
                    .filter(|identity| {
                        !identity.is_empty()
                            && identity.len() <= MAX_RUNTIME_ID_BYTES
                            && !identity.contains('\0')
                    });
                let Some(identity) = identity else {
                    state.violation = Some(BudgetViolation::AmbiguousToolIdentity);
                    return;
                };
                state.tool_calls.insert(identity.to_owned());
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

    #[cfg(test)]
    fn counts(&self) -> (u64, usize) {
        let state = self.state.lock().unwrap();
        (state.turns, state.tool_calls.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcode_protocol::{EventEnvelope, WireMessage};

    fn limits() -> BudgetLimits {
        BudgetLimits {
            wall_time_ms: 10_000,
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
        let budget = AttemptBudget::new(&limits());
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

        let ambiguous = AttemptBudget::new(&limits());
        ambiguous.observe(&event(
            "tool.updated",
            serde_json::json!({"toolName":"Bash"}),
        ));
        assert_eq!(
            ambiguous.violation(),
            Some(BudgetViolation::AmbiguousToolIdentity)
        );
    }
}
