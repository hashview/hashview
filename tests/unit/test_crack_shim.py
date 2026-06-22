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


# ---------------------------------------------------------------------------
# crack() only supports NTLM (mode 1000) in v1
# ---------------------------------------------------------------------------

def test_crack_returns_empty_for_unsupported_mode(tmp_path):
    hcshim = _load()
    # Even when the wordlist trivially contains the plaintext, a non-1000 mode
    # must recover nothing (the shim is NTLM-only for now).
    target = hcshim.ntlm_hex("cat")
    wl = tmp_path / "w.gz"
    with gzip.open(wl, "wt") as f:
        f.write("cat\n")
    assert hcshim.crack(0, [target], str(wl), []) == {}


# ---------------------------------------------------------------------------
# main(): the ONLY path allowed to use stderr is the misuse path; it must also
# return a non-zero exit code. (A regression that printed to stderr on the happy
# path would trip the agent's stderr-is-fatal contract.)
# ---------------------------------------------------------------------------

def test_main_errors_when_positionals_missing(tmp_path, capsys):
    hcshim = _load()
    # Only flags, no hashfile/wordlist positionals.
    rc = hcshim.main(["-m", "1000", "--outfile", str(tmp_path / "o.txt")])
    assert rc == 1
    assert "expected hashfile and wordlist" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# parse_args: the other attack-mode shapes the server's build_hashcat_command
# can emit, plus the '=' form and a missing --outfile.
# ---------------------------------------------------------------------------

def test_parse_args_mask_mode_a3():
    hcshim = _load()
    argv = ("-O -w 3 --session ab12 -m 1000 --status --status-timer=15 "
            "--outfile-format 1,3 --outfile out.txt -a 3 control/hashes/h.txt ?a?a?a").split()
    mode, outfile, fmt, rules, positionals = hcshim.parse_args(argv)
    assert mode == 1000
    assert outfile == "out.txt"
    assert rules == []
    # -a 3 is a value flag (consumed); the hashfile and the mask remain positional.
    assert positionals == ["control/hashes/h.txt", "?a?a?a"]


def test_parse_args_combinator_mode_a1():
    hcshim = _load()
    argv = ("-m 1000 --outfile out.txt -a 1 control/hashes/h.txt "
            "control/wordlists/a.gz control/wordlists/b.gz").split()
    mode, outfile, fmt, rules, positionals = hcshim.parse_args(argv)
    assert mode == 1000
    assert positionals == ["control/hashes/h.txt",
                           "control/wordlists/a.gz", "control/wordlists/b.gz"]


def test_parse_args_equals_form_and_missing_outfile():
    hcshim = _load()
    # '--status-timer=15' is ignored via the '=' branch; no --outfile -> None.
    mode, outfile, fmt, rules, positionals = hcshim.parse_args(
        ["-m", "1000", "--status-timer=15", "h.txt", "w.gz", "--status-json"])
    assert mode == 1000
    assert outfile is None
    assert positionals == ["h.txt", "w.gz"]


# ---------------------------------------------------------------------------
# apply_rule: multi-op lines, case ops, and silent skip of unknown ops.
# ---------------------------------------------------------------------------

def test_apply_rule_multi_op_and_case_ops():
    hcshim = _load()
    assert hcshim.apply_rule("cat", "$1 $2") == "cat12"      # ops applied left-to-right
    assert hcshim.apply_rule("cat", "^a ^b") == "bacat"      # prepends stack up
    assert hcshim.apply_rule("CaT", "l") == "cat"
    assert hcshim.apply_rule("cat", "c") == "Cat"


def test_apply_rule_skips_unknown_ops():
    hcshim = _load()
    # An unsupported op (e.g. a substitution) is skipped, not fatal; the rest apply.
    assert hcshim.apply_rule("cat", "sa@ $1") == "cat1"


# ---------------------------------------------------------------------------
# _iter_words: plaintext (non-.gz) wordlist path; _load_rule_lines: skip
# blank/comment lines.
# ---------------------------------------------------------------------------

def test_iter_words_reads_plaintext_wordlist(tmp_path):
    hcshim = _load()
    wl = tmp_path / "w.txt"            # no .gz -> opened as plain text
    wl.write_text("alpha\nbeta\ngamma\n")
    assert list(hcshim._iter_words(str(wl))) == ["alpha", "beta", "gamma"]


def test_load_rule_lines_skips_blank_and_comments(tmp_path):
    hcshim = _load()
    rules = tmp_path / "r.txt"
    rules.write_text("# a comment\n\n$1\n   \n^x\n")
    assert hcshim._load_rule_lines(str(rules)) == ["$1", "^x"]


# ---------------------------------------------------------------------------
# hexplain round-trips a multi-byte/Unicode plaintext (NTLM is UTF-16; the
# outfile-format 1,3 hex encoding must survive non-ASCII).
# ---------------------------------------------------------------------------

def test_crack_and_outfile_roundtrip_unicode(tmp_path):
    hcshim = _load()
    plaintext = "pässwörd"          # "pässwörd"
    target = hcshim.ntlm_hex(plaintext)
    wl = tmp_path / "w.gz"
    with gzip.open(wl, "wt", encoding="utf-8") as f:
        f.write(plaintext + "\n")
    out = tmp_path / "cracked.txt"

    found = hcshim.crack(1000, [target], str(wl), [])
    assert found == {target: plaintext}

    hcshim._write_outfile(str(out), found)
    line = out.read_text(encoding="utf-8").strip()
    written_hash, hexplain = line.split(":")
    assert written_hash == target
    # hex_plain is the UTF-8 bytes of the plaintext -> decodes back exactly
    # (this is what the server's hexplain_to_text() reverses on upload).
    assert bytes.fromhex(hexplain).decode("utf-8") == plaintext
