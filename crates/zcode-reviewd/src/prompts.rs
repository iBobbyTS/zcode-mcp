use review_preparation::{PreparedLaunchSpec, ReviewKind, RoundKind};
use sha2::{Digest, Sha256};
use std::fmt;

pub const PROMPT_SCHEMA: &str = "zcode-review-prompt/v1";
const PLAN_REVIEW_TEMPLATE: &str = include_str!("../../../prompts/plan-review.md");
const CODE_REVIEW_TEMPLATE: &str = include_str!("../../../prompts/code-review.md");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewPromptKind {
    Plan,
    Code,
}

impl ReviewPromptKind {
    fn from_review_kind(kind: ReviewKind) -> Self {
        match kind {
            ReviewKind::Plan => Self::Plan,
            ReviewKind::Code => Self::Code,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::Code => "code",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewPrompt {
    pub kind: ReviewPromptKind,
    pub round_kind: RoundKind,
    pub text: String,
    pub sha256: String,
}

const TASK_PROGRESS_INSTRUCTION: &str = "TASK_SCOPED_SEMANTIC_PROGRESS: This is a daemon-bound task review. After the initial scope checkpoint and whenever the semantic stage advances, call the private mcp__review-ledger__review_progress tool with only the bounded stage, summary, and optional counters. The daemon supplies attempt and run identity; do not invent or include private identity fields.";
const TASK_PERMISSION_INSTRUCTION: &str = "TASK_SCOPED_PERMISSION_HANDLING: After the first Bash permission_denied, permanently stop all Bash calls for this review; do not retry the rejected command with another spelling, path, shell, or equivalent. Continue with Read and the existing mcp__review-ledger tools. For each denied Bash, record only a bounded safe descriptor in uncertainties: tool name, policy reason code, and command category/program name or a one-way hash; never record raw command text, raw arguments, secrets, bearer tokens, credentials, or absolute host paths. Put unreviewed paths in coverage.not_covered or recommended_next_actions. Regardless of findings or evidence completeness, invoke review_finalize one time with one legal signal: findings_present, no_findings_observed, incomplete_evidence, or unable_to_review; use a truthful incomplete signal and never fabricate findings or success.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptError {
    InvalidContract(&'static str),
    Json(String),
}

impl fmt::Display for PromptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidContract(message) => write!(formatter, "invalid review prompt: {message}"),
            Self::Json(message) => write!(formatter, "review prompt encoding failed: {message}"),
        }
    }
}

impl std::error::Error for PromptError {}

pub fn build_review_prompt(prepared: &PreparedLaunchSpec) -> Result<ReviewPrompt, PromptError> {
    prepared
        .validate_digest()
        .map_err(|_| PromptError::InvalidContract("prepared launch digest is invalid"))?;
    if !prepared.fresh_session {
        return Err(PromptError::InvalidContract(
            "counted review does not use a fresh session",
        ));
    }
    let kind = ReviewPromptKind::from_review_kind(prepared.review_kind);
    let template = match kind {
        ReviewPromptKind::Plan => PLAN_REVIEW_TEMPLATE,
        ReviewPromptKind::Code => CODE_REVIEW_TEMPLATE,
    };
    let scope = prepared
        .scope
        .iter()
        .map(|path| path.repository_relative.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let context = prepared
        .context
        .iter()
        .map(|artifact| artifact.prepared_path.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let scope =
        serde_json::to_string(&scope).map_err(|error| PromptError::Json(error.to_string()))?;
    let context =
        serde_json::to_string(&context).map_err(|error| PromptError::Json(error.to_string()))?;
    let plan = serde_json::to_string(&prepared.plan.prepared_path.to_string_lossy())
        .map_err(|error| PromptError::Json(error.to_string()))?;

    let header = format!(
        "PROMPT_SCHEMA: {PROMPT_SCHEMA}\n\
REVIEW_KIND: {}\n\
ROUND_KIND: {}\n\
FRESH_SESSION_REQUIRED: true\n\
PRIOR_REVIEW_CONTEXT: forbidden\n\
LIVE_STEER: false\n\
LEGAL_FINAL_SIGNALS: findings_present,no_findings_observed,incomplete_evidence,unable_to_review\n\
BASE_SHA: {}\n\
HEAD_SHA: {}\n\
PLAN_INPUT: {plan}\n\
CONTEXT_INPUTS: {context}\n\
SCOPE_PATHS: {scope}",
        kind.as_str(),
        prepared.round_kind.as_str(),
        prepared.base_sha,
        prepared.head_sha,
    );
    let text = format!("{header}\n\n{template}");
    validate_review_prompt(kind, prepared.round_kind, &text)?;
    let sha256 = format!("{:x}", Sha256::digest(text.as_bytes()));
    Ok(ReviewPrompt {
        kind,
        round_kind: prepared.round_kind,
        text,
        sha256,
    })
}

pub fn build_review_continuation_prompt(
    prepared: &PreparedLaunchSpec,
    frozen_finding_ids: &[String],
) -> Result<ReviewPrompt, PromptError> {
    let base = build_review_prompt(prepared)?;
    let frozen = serde_json::to_string(frozen_finding_ids)
        .map_err(|error| PromptError::Json(error.to_string()))?;
    let text = base.text.replacen(
        "PRIOR_REVIEW_CONTEXT: forbidden\nLIVE_STEER: false",
        &format!(
            "PRIOR_REVIEW_CONTEXT: frozen_finding_ids_only\n\
COUNTS_AS_INDEPENDENT: false\n\
FROZEN_FINDING_IDS: {frozen}\n\
LIVE_STEER: false"
        ),
        1,
    );
    validate_review_continuation_prompt(base.kind, base.round_kind, &text, frozen_finding_ids)?;
    let sha256 = format!("{:x}", Sha256::digest(text.as_bytes()));
    Ok(ReviewPrompt {
        kind: base.kind,
        round_kind: base.round_kind,
        text,
        sha256,
    })
}

pub fn build_task_review_prompt(
    prepared: &PreparedLaunchSpec,
) -> Result<ReviewPrompt, PromptError> {
    add_task_progress_instruction(build_review_prompt(prepared)?, None)
}

pub fn build_task_review_continuation_prompt(
    prepared: &PreparedLaunchSpec,
    frozen_finding_ids: &[String],
) -> Result<ReviewPrompt, PromptError> {
    add_task_progress_instruction(
        build_review_continuation_prompt(prepared, frozen_finding_ids)?,
        Some(frozen_finding_ids),
    )
}

fn add_task_progress_instruction(
    mut prompt: ReviewPrompt,
    frozen_finding_ids: Option<&[String]>,
) -> Result<ReviewPrompt, PromptError> {
    prompt.text.push_str("\n\n");
    prompt.text.push_str(TASK_PROGRESS_INSTRUCTION);
    prompt.text.push_str("\n");
    prompt.text.push_str(TASK_PERMISSION_INSTRUCTION);
    if let Some(frozen_finding_ids) = frozen_finding_ids {
        validate_review_continuation_prompt(
            prompt.kind,
            prompt.round_kind,
            &prompt.text,
            frozen_finding_ids,
        )?;
    } else {
        validate_review_prompt(prompt.kind, prompt.round_kind, &prompt.text)?;
    }
    let sha256 = format!("{:x}", Sha256::digest(prompt.text.as_bytes()));
    prompt.sha256 = sha256;
    Ok(prompt)
}

pub fn validate_review_continuation_prompt(
    kind: ReviewPromptKind,
    round_kind: RoundKind,
    text: &str,
    frozen_finding_ids: &[String],
) -> Result<(), PromptError> {
    validate_prompt_kind(kind, round_kind)?;
    let (header, instructions) = text.split_once("\n\n").ok_or(PromptError::InvalidContract(
        "prompt header and instructions are not separated",
    ))?;
    let frozen = serde_json::to_string(frozen_finding_ids)
        .map_err(|error| PromptError::Json(error.to_string()))?;
    let lines = header.lines().collect::<Vec<_>>();
    let fixed = [
        format!("PROMPT_SCHEMA: {PROMPT_SCHEMA}"),
        format!("REVIEW_KIND: {}", kind.as_str()),
        format!("ROUND_KIND: {}", round_kind.as_str()),
        "FRESH_SESSION_REQUIRED: true".into(),
        "PRIOR_REVIEW_CONTEXT: frozen_finding_ids_only".into(),
        "COUNTS_AS_INDEPENDENT: false".into(),
        format!("FROZEN_FINDING_IDS: {frozen}"),
        "LIVE_STEER: false".into(),
        "LEGAL_FINAL_SIGNALS: findings_present,no_findings_observed,incomplete_evidence,unable_to_review".into(),
    ];
    if lines.len() != 14
        || fixed
            .iter()
            .enumerate()
            .any(|(index, line)| lines[index] != line)
    {
        return Err(PromptError::InvalidContract(
            "fixed continuation prompt fields are invalid",
        ));
    }
    validate_dynamic_header_and_instructions(&lines, fixed.len(), instructions)
}

pub fn validate_review_prompt(
    kind: ReviewPromptKind,
    round_kind: RoundKind,
    text: &str,
) -> Result<(), PromptError> {
    validate_prompt_kind(kind, round_kind)?;
    let (header, instructions) = text.split_once("\n\n").ok_or(PromptError::InvalidContract(
        "prompt header and instructions are not separated",
    ))?;
    let lines = header.lines().collect::<Vec<_>>();
    let fixed = [
        format!("PROMPT_SCHEMA: {PROMPT_SCHEMA}"),
        format!("REVIEW_KIND: {}", kind.as_str()),
        format!("ROUND_KIND: {}", round_kind.as_str()),
        "FRESH_SESSION_REQUIRED: true".into(),
        "PRIOR_REVIEW_CONTEXT: forbidden".into(),
        "LIVE_STEER: false".into(),
        "LEGAL_FINAL_SIGNALS: findings_present,no_findings_observed,incomplete_evidence,unable_to_review".into(),
    ];
    if lines.len() != 12
        || fixed
            .iter()
            .enumerate()
            .any(|(index, line)| lines[index] != line)
    {
        return Err(PromptError::InvalidContract(
            "fixed prompt header fields are invalid",
        ));
    }
    validate_dynamic_header_and_instructions(&lines, fixed.len(), instructions)
}

fn validate_prompt_kind(kind: ReviewPromptKind, round_kind: RoundKind) -> Result<(), PromptError> {
    let compatible = matches!(
        (kind, round_kind),
        (ReviewPromptKind::Plan, RoundKind::PlanReview)
            | (
                ReviewPromptKind::Code,
                RoundKind::InitialBounded | RoundKind::RepairDelta | RoundKind::FinalBounded
            )
    );
    if !compatible {
        return Err(PromptError::InvalidContract(
            "review and round prompt kinds are incompatible",
        ));
    }
    Ok(())
}

fn validate_dynamic_header_and_instructions(
    lines: &[&str],
    fixed_fields: usize,
    instructions: &str,
) -> Result<(), PromptError> {
    for (index, field) in [
        "BASE_SHA:",
        "HEAD_SHA:",
        "PLAN_INPUT:",
        "CONTEXT_INPUTS:",
        "SCOPE_PATHS:",
    ]
    .iter()
    .enumerate()
    {
        if lines[index + fixed_fields]
            .strip_prefix(&format!("{field} "))
            .is_none_or(str::is_empty)
        {
            return Err(PromptError::InvalidContract(
                "prompt metadata field is missing or empty",
            ));
        }
    }
    let required_instructions = [
        "review_checkpoint",
        "review_finding_upsert",
        "review_validation_record",
        "review_finalize exactly once",
        "observable repository",
        "covered scope, gaps, uncertainty",
        "one legal final signal",
    ];
    if required_instructions
        .iter()
        .any(|needle| !instructions.contains(needle))
    {
        return Err(PromptError::InvalidContract(
            "required observable review instruction is missing",
        ));
    }
    if instructions.matches("review_finalize exactly once").count() != 1 {
        return Err(PromptError::InvalidContract(
            "prompt markers or final signal instruction are ambiguous",
        ));
    }
    let lowered = instructions.to_ascii_lowercase();
    let forbidden = [
        "chain of thought",
        "hidden reasoning",
        "approval",
        "you approve",
        "admission",
        "admission authority",
        "merge readiness",
        "merge-ready",
    ];
    if forbidden.iter().any(|needle| lowered.contains(needle)) {
        return Err(PromptError::InvalidContract(
            "prompt requests hidden or caller-owned judgment",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validator_rejects_hidden_and_caller_owned_language() {
        let base = format!(
            "PROMPT_SCHEMA: {PROMPT_SCHEMA}\nREVIEW_KIND: code\nROUND_KIND: INITIAL_BOUNDED\nFRESH_SESSION_REQUIRED: true\n\
PRIOR_REVIEW_CONTEXT: forbidden\nLIVE_STEER: false\nLEGAL_FINAL_SIGNALS: findings_present,no_findings_observed,incomplete_evidence,unable_to_review\nBASE_SHA: a\nHEAD_SHA: b\nPLAN_INPUT: p\nCONTEXT_INPUTS: []\nSCOPE_PATHS: []\n\nreview_checkpoint review_finding_upsert \
review_validation_record review_finalize exactly once observable repository covered scope, gaps, \
uncertainty one legal final signal"
        );
        assert!(
            validate_review_prompt(ReviewPromptKind::Code, RoundKind::InitialBounded, &base)
                .is_ok()
        );
        assert!(
            validate_review_prompt(ReviewPromptKind::Code, RoundKind::PlanReview, &base).is_err()
        );
        for forbidden in [
            "hidden reasoning",
            "you approve this change",
            "admission authority belongs to you",
            "merge readiness",
        ] {
            assert!(validate_review_prompt(
                ReviewPromptKind::Code,
                RoundKind::InitialBounded,
                &format!("{base} {forbidden}")
            )
            .is_err());
        }

        let legal_metadata = base
            .replace("PLAN_INPUT: p", "PLAN_INPUT: \"context/admission.json\"")
            .replace(
                "CONTEXT_INPUTS: []",
                "CONTEXT_INPUTS: [\"context/admission.json\"]",
            )
            .replace("SCOPE_PATHS: []", "SCOPE_PATHS: [\"src/approval.rs\"]");
        assert!(validate_review_prompt(
            ReviewPromptKind::Code,
            RoundKind::InitialBounded,
            &legal_metadata
        )
        .is_ok());
    }

    #[test]
    fn task_prompt_adds_daemon_bound_progress_without_changing_legacy_prompt() {
        let legacy = format!(
            "PROMPT_SCHEMA: {PROMPT_SCHEMA}\nREVIEW_KIND: code\nROUND_KIND: INITIAL_BOUNDED\nFRESH_SESSION_REQUIRED: true\n\
PRIOR_REVIEW_CONTEXT: forbidden\nLIVE_STEER: false\nLEGAL_FINAL_SIGNALS: findings_present,no_findings_observed,incomplete_evidence,unable_to_review\nBASE_SHA: a\nHEAD_SHA: b\nPLAN_INPUT: p\nCONTEXT_INPUTS: []\nSCOPE_PATHS: []\n\nreview_checkpoint review_finding_upsert review_validation_record review_finalize exactly once observable repository covered scope, gaps, uncertainty one legal final signal"
        );
        let prompt = ReviewPrompt {
            kind: ReviewPromptKind::Code,
            round_kind: RoundKind::InitialBounded,
            text: legacy.clone(),
            sha256: String::new(),
        };
        let task = add_task_progress_instruction(prompt, None).unwrap();
        assert!(task.text.contains("TASK_SCOPED_SEMANTIC_PROGRESS"));
        assert!(task.text.contains("mcp__review-ledger__review_progress"));
        assert!(task
            .text
            .contains("After the first Bash permission_denied, permanently stop all Bash calls"));
        assert!(task.text.contains(
            "do not retry the rejected command with another spelling, path, shell, or equivalent"
        ));
        assert!(task
            .text
            .contains("Continue with Read and the existing mcp__review-ledger tools"));
        assert!(task
            .text
            .contains("bounded safe descriptor in uncertainties"));
        assert!(task.text.contains("tool name, policy reason code"));
        assert!(task
            .text
            .contains("command category/program name or a one-way hash"));
        assert!(task.text.contains("never record raw command text, raw arguments, secrets, bearer tokens, credentials, or absolute host paths"));
        assert!(task
            .text
            .contains("coverage.not_covered or recommended_next_actions"));
        assert!(task.text.contains("review_finalize exactly once"));
        for signal in [
            "findings_present",
            "no_findings_observed",
            "incomplete_evidence",
            "unable_to_review",
        ] {
            assert!(task.text.contains(signal), "missing legal signal {signal}");
        }
        let safe_descriptor =
            "tool=mcp__review-ledger__review_progress reason=permission_denied category=filesystem program=find hash=sha256:abc";
        for forbidden in [
            "--secret=",
            "Bearer ",
            "token=",
            "/Users/",
            "raw command text",
            "raw arguments",
        ] {
            assert!(
                !safe_descriptor.contains(forbidden),
                "unsafe descriptor: {forbidden}"
            );
        }
        assert!(task.text.contains("never record raw command text, raw arguments, secrets, bearer tokens, credentials, or absolute host paths"));
        assert!(!legacy.contains("TASK_SCOPED_PERMISSION_HANDLING"));
        assert_ne!(task.text, legacy);
        assert!(validate_review_prompt(task.kind, task.round_kind, &task.text).is_ok());
    }

    #[test]
    fn task_continuation_prompt_uses_the_continuation_validator() {
        let frozen = vec!["S02-F6".to_owned()];
        let text = format!(
            "PROMPT_SCHEMA: {PROMPT_SCHEMA}\nREVIEW_KIND: code\nROUND_KIND: REPAIR_DELTA\nFRESH_SESSION_REQUIRED: true\n\
PRIOR_REVIEW_CONTEXT: frozen_finding_ids_only\nCOUNTS_AS_INDEPENDENT: false\nFROZEN_FINDING_IDS: [\"S02-F6\"]\nLIVE_STEER: false\nLEGAL_FINAL_SIGNALS: findings_present,no_findings_observed,incomplete_evidence,unable_to_review\nBASE_SHA: a\nHEAD_SHA: b\nPLAN_INPUT: p\nCONTEXT_INPUTS: []\nSCOPE_PATHS: []\n\nreview_checkpoint review_finding_upsert review_validation_record review_finalize exactly once observable repository covered scope, gaps, uncertainty one legal final signal"
        );
        let prompt = ReviewPrompt {
            kind: ReviewPromptKind::Code,
            round_kind: RoundKind::RepairDelta,
            text,
            sha256: String::new(),
        };
        let task = add_task_progress_instruction(prompt, Some(&frozen)).unwrap();
        assert!(task.text.contains("mcp__review-ledger__review_progress"));
        assert!(task
            .text
            .contains("After the first Bash permission_denied, permanently stop all Bash calls"));
        assert!(task
            .text
            .contains("bounded safe descriptor in uncertainties"));
        assert!(task
            .text
            .contains("coverage.not_covered or recommended_next_actions"));
        assert!(task.text.contains("review_finalize exactly once"));
        assert!(validate_review_continuation_prompt(
            task.kind,
            task.round_kind,
            &task.text,
            &frozen
        )
        .is_ok());
    }
}
