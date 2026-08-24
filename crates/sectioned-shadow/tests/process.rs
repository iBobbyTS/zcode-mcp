use review_preparation::{NetworkPolicy, ReviewKind, ReviewManifest, RoundKind, ScratchPolicy};
use sectioned_shadow::{
    EvidenceClassification, ShadowConfig, ShadowMode, ShadowProvenance, SHADOW_SCHEMA,
};
use std::{collections::BTreeMap, path::Path, process::Command};

fn run(root: &Path, kind: ReviewKind, round: RoundKind, stem: &str) -> ShadowProvenance {
    let plan = root.join("PLAN.md");
    std::fs::write(&plan, "# process smoke plan\n").unwrap();
    let manifest = ReviewManifest {
        schema: "sectioned-zcode-review/v1".into(),
        review_kind: kind,
        feature_id: "shadow-process".into(),
        section_id: "S08".into(),
        round_kind: round,
        repository: root.into(),
        base_ref: "1111111111111111111111111111111111111111".into(),
        head_ref: "2222222222222222222222222222222222222222".into(),
        plan_path: plan,
        context_paths: vec![],
        scope_paths: vec![root.join("src")],
        forbidden_input_globs: vec![],
        validation_commands: BTreeMap::new(),
        report_target: root.join(".agent-work/reviews/report.md"),
        scratch_root: root.join(".agent-work/scratch/jobs"),
        model: Some("glm-shadow".into()),
        fresh_session: true,
        network_policy: NetworkPolicy::Deny,
        scratch_policy: ScratchPolicy::Isolated,
        idempotency_key: stem.into(),
    };
    let manifest_path = root.join(format!("{stem}-manifest.json"));
    std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let config = ShadowConfig {
        schema: SHADOW_SCHEMA.into(),
        manifest_path,
        artifact_directory: root.join("artifacts"),
        artifact_stem: stem.into(),
        mode: ShadowMode::Full,
        wait_timeout_ms: 50,
        max_waits: 3,
    };
    let config_path = root.join(format!("{stem}-config.json"));
    std::fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sectioned-shadow"))
        .arg(config_path)
        .env(
            "ZCODE_REVIEW_MCP_PATH",
            env!("CARGO_BIN_EXE_zcode-shadow-fake-mcp-fixture"),
        )
        .env("ZCODE_REVIEWD_SOCKET", root.join("unused.sock"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).lines().count(), 1);
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn plan_and_full_code_shadow_processes_use_official_mcp_framing() {
    for (kind, round, stem) in [
        (ReviewKind::Plan, RoundKind::PlanReview, "plan-process"),
        (ReviewKind::Code, RoundKind::FinalBounded, "code-process"),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let provenance = run(directory.path(), kind, round, stem);
        assert_eq!(
            provenance.classification,
            EvidenceClassification::IndependentEvidence
        );
        assert_eq!(provenance.review_kind, kind.as_str());
        assert_eq!(provenance.checkpoint_count, 1);
        assert!(directory
            .path()
            .join(format!("artifacts/{stem}-GLM-RAW.md"))
            .is_file());
        assert!(directory
            .path()
            .join(format!("artifacts/{stem}-GLM-PROVENANCE.json"))
            .is_file());
    }
}
