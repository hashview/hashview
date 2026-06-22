import importlib.util
import json
from pathlib import Path

GEN = Path(__file__).resolve().parents[1] / "e2e" / "crack" / "gen_slices.py"


def _load():
    spec = importlib.util.spec_from_file_location("gen_slices", GEN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_generate_builds_two_tasks_and_slices(tmp_path):
    gen = _load()
    rockyou = tmp_path / "rockyou.txt"
    rockyou.write_text("\n".join(f"word{i}" for i in range(500)) + "\n")
    out = tmp_path / "out"
    manifest = gen.generate(str(rockyou), str(out), targets_per_task=3, slice_size=100, seed=42)

    assert len(manifest["tasks"]) == 2
    a, b = manifest["tasks"]
    assert a["use_rule"] is False and b["use_rule"] is True
    assert manifest["rule_body"].strip() == "$1"
    assert len(a["target_plaintexts"]) == 3
    assert all(pt.endswith("1") for pt in b["target_plaintexts"])

    # Slice files exist, are bounded, and contain the needed base words.
    sa = Path(a["slice_host_path"]).read_text().splitlines()
    sb = Path(b["slice_host_path"]).read_text().splitlines()
    assert len(sa) <= 100 and len(sb) <= 100
    for pt in a["target_plaintexts"]:
        assert pt in sa
    for pt in b["target_plaintexts"]:
        assert pt[:-1] in sb        # base word (without the appended "1")


def test_manifest_is_json_serializable(tmp_path):
    gen = _load()
    rockyou = tmp_path / "rockyou.txt"
    rockyou.write_text("\n".join(f"w{i}" for i in range(200)) + "\n")
    out = tmp_path / "out"
    gen.generate(str(rockyou), str(out), targets_per_task=2, slice_size=50, seed=1)
    data = json.loads((out / "manifest.json").read_text())
    assert data["job_name"] == "e2e-crack-job"
    assert data["customer_id"] == 9001
