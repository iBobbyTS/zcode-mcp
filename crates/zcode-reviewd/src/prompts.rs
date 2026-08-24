use review_preparation::{PreparedLaunchSpec, ReviewKind};
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
    pub text: String,
    pub sha256: String,
}

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
        prepared.base_sha,
        prepared.head_sha,
    );
    let text = format!("{header}\n\n{template}");
    validate_review_prompt(kind, &text)?;
    let sha256 = format!("{:x}", Sha256::digest(text.as_bytes()));
    Ok(ReviewPrompt { kind, text, sha256 })
}

pub fn validate_review_prompt(kind: ReviewPromptKind, text: &str) -> Result<(), PromptError> {
    let (header, instructions) = text.split_once("\n\n").ok_or(PromptError::InvalidContract(
        "prompt header and instructions are not separated",
    ))?;
    let lines = header.lines().collect::<Vec<_>>();
    let fixed = [
        format!("PROMPT_SCHEMA: {PROMPT_SCHEMA}"),
        format!("REVIEW_KIND: {}", kind.as_str()),
        "FRESH_SESSION_REQUIRED: true".into(),
        "PRIOR_REVIEW_CONTEXT: forbidden".into(),
        "LIVE_STEER: false".into(),
        "LEGAL_FINAL_SIGNALS: findings_present,no_findings_observed,incomplete_evidence,unable_to_review".into(),
    ];
    if lines.len() != 11
        || fixed
            .iter()
            .enumerate()
            .any(|(index, line)| lines[index] != line)
    {
        return Err(PromptError::InvalidContract(
            "fixed prompt header fields are invalid",
        ));
    }
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
        if lines[index + fixed.len()]
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
            "PROMPT_SCHEMA: {PROMPT_SCHEMA}\nREVIEW_KIND: code\nFRESH_SESSION_REQUIRED: true\n\
PRIOR_REVIEW_CONTEXT: forbidden\nLIVE_STEER: false\nLEGAL_FINAL_SIGNALS: findings_present,no_findings_observed,incomplete_evidence,unable_to_review\nBASE_SHA: a\nHEAD_SHA: b\nPLAN_INPUT: p\nCONTEXT_INPUTS: []\nSCOPE_PATHS: []\n\nreview_checkpoint review_finding_upsert \
review_validation_record review_finalize exactly once observable repository covered scope, gaps, \
uncertainty one legal final signal"
        );
        assert!(validate_review_prompt(ReviewPromptKind::Code, &base).is_ok());
        for forbidden in [
            "hidden reasoning",
            "you approve this change",
            "admission authority belongs to you",
            "merge readiness",
        ] {
            assert!(
                validate_review_prompt(ReviewPromptKind::Code, &format!("{base} {forbidden}"))
                    .is_err()
            );
        }

        let legal_metadata = base
            .replace("PLAN_INPUT: p", "PLAN_INPUT: \"context/admission.json\"")
            .replace(
                "CONTEXT_INPUTS: []",
                "CONTEXT_INPUTS: [\"context/admission.json\"]",
            )
            .replace("SCOPE_PATHS: []", "SCOPE_PATHS: [\"src/approval.rs\"]");
        assert!(validate_review_prompt(ReviewPromptKind::Code, &legal_metadata).is_ok());
    }
}
