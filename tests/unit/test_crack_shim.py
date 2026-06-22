import gzip
import importlib.util
import subprocess
import sys
from pathlib import Path

SHIM_DIR = Path(__file__).resolve().parents[1] / "e2e" / "crack" / "shim"


def _load():
    spec = importlib.util.spec_from_file_location("hcshim", SHIM_DIR / "hcshim.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_ntlm_hex_matches_known_vector():
    hcshim = _load()
    # NTLM("password") = 8846f7eaee8fb117ad06bdd830b7586c
    assert hcshim.ntlm_hex("password") == "8846f7eaee8fb117ad06bdd830b7586c"


def test_apply_rule_append_and_passthrough():
    hcshim = _load()
    assert hcshim.apply_rule("cat", "$1") == "cat1"
    assert hcshim.apply_rule("cat", ":") == "cat"
    assert hcshim.apply_rule("cat", "^x") == "xcat"
    assert hcshim.apply_rule("cat", "u") == "CAT"


def test_parse_args_dict_with_rule():
    hcshim = _load()
    argv = ("-O -w 3 --session ab12 -m 1000 --potfile-path p.pot --status "
            "--status-timer=15 --outfile-format 1,3 --outfile out.txt "
            "-r control/rules/r.txt control/hashes/h.txt control/wordlists/w.gz "
            "--status-json").split()
    mode, outfile, fmt, rules, positionals = hcshim.parse_args(argv)
    assert mode == 1000
    assert outfile == "out.txt"
    assert rules == ["control/rules/r.txt"]
    assert positionals == ["control/hashes/h.txt", "control/wordlists/w.gz"]


def test_crack_recovers_plain_and_ruled(tmp_path):
    hcshim = _load()
    # Targets: NTLM("cat") plain, and NTLM("dog1") via $1 rule on base "dog".
    target_cat = hcshim.ntlm_hex("cat").upper()       # echoed verbatim regardless of case
    target_dog1 = hcshim.ntlm_hex("dog1")
    hashfile = tmp_path / "h.txt"
    hashfile.write_text(target_cat + "\n" + target_dog1 + "\n")
    wl = tmp_path / "w.gz"
    with gzip.open(wl, "wt") as f:
        f.write("cat\ndog\nbird\n")
    rules = tmp_path / "r.txt"
    rules.write_text("$1\n")

    # No rule -> only "cat" cracks (plain wordlist words).
    found = hcshim.crack(1000, [target_cat, target_dog1], str(wl), [])
    assert found == {target_cat: "cat"}

    # With $1 rule -> only "dog1" cracks (ruled candidates).
    found2 = hcshim.crack(1000, [target_cat, target_dog1], str(wl), [str(rules)])
    assert found2 == {target_dog1: "dog1"}


def test_executable_writes_outfile_and_no_stderr(tmp_path):
    hcshim = _load()
    target = hcshim.ntlm_hex("cat")
    hashfile = tmp_path / "h.txt"
    hashfile.write_text(target + "\n")
    wl = tmp_path / "w.gz"
    with gzip.open(wl, "wt") as f:
        f.write("cat\n")
    out = tmp_path / "cracked.txt"
    proc = subprocess.run(
        [sys.executable, str(SHIM_DIR / "hashcat"),
         "-m", "1000", "--outfile-format", "1,3", "--outfile", str(out),
         str(hashfile), str(wl), "--status-json"],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0
    assert proc.stderr == ""                      # CRITICAL: agent treats stderr as fatal
    # outfile-format 1,3 -> hash:hex_plain ; hex("cat") == 636174
    assert out.read_text().strip() == f"{target}:636174"
