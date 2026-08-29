import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).parents[1]
CASES = ("case-01-user-fuzzy-search", "case-02-shared-group-members", "case-03-agent-control-lifecycle")

def test_reset_verify_is_deterministic():
    for name in CASES:
        case = ROOT / name
        outputs = []
        for _ in range(3):
            subprocess.run([str(case / "scripts/reset.sh")], check=True)
            result = subprocess.run([str(case / "scripts/verify.sh")], check=True, capture_output=True, text=True)
            outputs.append(json.loads(result.stdout))
        assert outputs[0] == outputs[1] == outputs[2]

def test_case_c_declares_continuation_hook_and_thresholds():
    manifest = json.loads((ROOT / CASES[2] / "fixture-manifest.json").read_text())
    assert manifest["shape"]["continuation"]["required"] is True
    assert manifest["shape"]["thresholds"]["max_retry_count"] == 2
    assert (ROOT / CASES[2] / manifest["shape"]["continuation"]["hook"]).is_file()
