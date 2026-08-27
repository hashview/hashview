"""Host-side: derive random rockyou targets and bounded wordlist slices, plus a
manifest the in-container seeder and the pytest verifier both read.

Reads rockyou from $ROCKYOU_PATH (or the path given to generate()). The two
agents/tasks: Task A is a plain dictionary attack; Task B is dictionary + a
'$1' rule, so its targets are <base>+"1" and the crack only succeeds if the
rule was synced and applied.
"""
import json
import os
import random
import sys

JOB_NAME = "e2e-crack-job"
CUSTOMER_ID = 9001
RULE_BODY = "$1\n"
RULE_SUFFIX = "1"
CONTAINER_SLICE_DIR = "/tmp/crack"        # where slices are cp'd inside the app container


def _read_lines(path):
    with open(path, encoding="utf-8", errors="surrogateescape") as f:
        return [line.rstrip("\n") for line in f if line.strip()]


def _build_slice(pool, must_include, slice_size, rng):
    chosen = set(must_include)
    if len(pool) > slice_size:
        chosen.update(rng.sample(pool, slice_size - len(must_include)))
    else:
        chosen.update(pool)
    out = list(chosen)
    rng.shuffle(out)
    return out[:slice_size]


def generate(rockyou_path, out_dir, targets_per_task=3, slice_size=50000, seed=None):
    rng = random.Random(seed)
    os.makedirs(out_dir, exist_ok=True)
    pool = _read_lines(rockyou_path)
    if len(pool) < targets_per_task * 2:
        raise RuntimeError(f"rockyou at {rockyou_path} too small ({len(pool)} lines)")

    picks = rng.sample(pool, targets_per_task * 2)
    a_words = picks[:targets_per_task]
    b_base = picks[targets_per_task:]

    a_slice = _build_slice(pool, a_words, slice_size, rng)
    b_slice = _build_slice(pool, b_base, slice_size, rng)

    a_path = os.path.join(out_dir, "sliceA.txt")
    b_path = os.path.join(out_dir, "sliceB.txt")
    with open(a_path, "w", encoding="utf-8", errors="surrogateescape") as f:
        f.write("\n".join(a_slice) + "\n")
    with open(b_path, "w", encoding="utf-8", errors="surrogateescape") as f:
        f.write("\n".join(b_slice) + "\n")

    manifest = {
        "job_name": JOB_NAME,
        "customer_id": CUSTOMER_ID,
        "rule_body": RULE_BODY,
        "agents": [
            {"name": "e2e-agent-1", "uuid": "11111111-1111-1111-1111-111111111111"},
            {"name": "e2e-agent-2", "uuid": "22222222-2222-2222-2222-222222222222"},
        ],
        "tasks": [
            {
                "name": "e2e-crack-task-dict",
                "use_rule": False,
                "slice_host_path": a_path,
                "slice_container_path": os.path.join(CONTAINER_SLICE_DIR, "sliceA.txt"),
                "target_plaintexts": list(a_words),
            },
            {
                "name": "e2e-crack-task-rules",
                "use_rule": True,
                "slice_host_path": b_path,
                "slice_container_path": os.path.join(CONTAINER_SLICE_DIR, "sliceB.txt"),
                "target_plaintexts": [w + RULE_SUFFIX for w in b_base],
            },
        ],
    }
    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    return manifest


def main():
    rockyou = os.getenv("ROCKYOU_PATH")
    out_dir = os.getenv("CRACK_ARTIFACT_DIR", "tests/e2e/crack/.artifacts")
    if not rockyou or not os.path.exists(rockyou):
        print("gen_slices: ROCKYOU_PATH not set or file missing", file=sys.stderr)
        return 2
    generate(rockyou, out_dir)
    print(os.path.join(out_dir, "manifest.json"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
