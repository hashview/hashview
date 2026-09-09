"""Live hashcat Kerberos AES-mode case/SPN contract (Task 2 fix, D1-D3).

hashview.utils.utils.normalize_kerberos_hash preserves user/realm case and
strips the SPN field for 19600/19700 so that stored ciphertext stays
byte-identical to what hashcat echoes for it -- recovery matches on
md5(ciphertext) (hashview/api/routes.py), so any drift between our
normalization and hashcat's own echo format silently breaks recovery for
every hash it touches. This module runs the real binary and asserts that
contract directly, rather than trusting the Task 2 unit tests' fixed
expectations to still describe hashcat's actual behaviour.

Needs a real binary; set HASHCAT_BIN to run. Skipped by default.
"""
import os
import re
import subprocess

import pytest

from hashview.utils.utils import normalize_kerberos_hash

HASHCAT_BIN = os.environ.get("HASHCAT_BIN")

pytestmark = [
    pytest.mark.hashcat_interop,
    pytest.mark.skipif(not HASHCAT_BIN, reason="set HASHCAT_BIN to run live hashcat tests"),
]

# Password "hashcat" for every vector below; hashcat's own --example-hashes
# output for each mode (verified against 7.1.2, values recorded in the plan).
EXAMPLE_19600 = (
    "$krb5tgs$17$srv_http$synacktiv.local$849e31b3db1c1f203fa20b85"
    "$948690f5875125348286ad3346d27b43eaabc71896b620c16de7ddcdbd561628c650c508856a"
    "3f574261948b6db4b48332d30536e978046a423ad4368f9a69b4dc4642dab4e0d475d8299be71"
    "8fd6f98ac85a771b457b2453e78c9411dfce572b19660fe7a5a8246d9b2a91ea2f14d1986ea0a"
    "77ecf9b8330bc8fd9ab540bcf46b74c5aa7005cfccd89ec05f66aeab30c6b2bf8595cf6c9a1b6"
    "8ad885258850c4b1dd9265f270fb2af52fd76c16246df51ea67efc58a65c345686c84e43642fe"
    "be908a"
)
EXAMPLE_19700 = (
    "$krb5tgs$18$srv_http$synacktiv.local$16ce51f6eba20c8ee534ff8a"
    "$57d07b23643a516834795f0c010da8f549b7e65063e5a367ca9240f9b800adad1734df7e7d5d"
    "d8307e785de4f40aacf901df41aa6ce695f8619ec579c1fa57ee93661cf402aeef4e3a42e7e34"
    "77645d52c09dc72feade03512dffe0df517344f673c63532b790c242cc1d50f4b4b34976cb6e"
    "08ab325b3aefb2684262a5ee9faacb14d059754f50553be5bfa5c4c51e833ff2b6ac02c6e5d4"
    "c4eb193e27d7dde301bd1ddf480e5e282b8c27ef37b136c8f140b56de105b73adeb1de16232f"
    "a1ab5c9f6"
)
EXAMPLE_19800 = (
    "$krb5pa$17$hashcat$HASHCATDOMAIN.COM"
    "$a17776abe5383236c58582f515843e029ecbff43706d177651b7b6cdb2713b17597ddb35b1c9"
    "c470c281589fd1d51cca125414d19e40e333"
)
EXAMPLE_19900 = (
    "$krb5pa$18$hashcat$HASHCATDOMAIN.COM"
    "$96c289009b05181bfd32062962740b1b1ce5f74eb12e0266cde74e81094661addab08c0c1a17"
    "8882c91a0ed89ae4e0e68d2820b9cce69770"
)
EXAMPLE_28800 = "$krb5db$17$test$TEST.LOCAL$1c41586d6c060071e08186ee214e725e"
EXAMPLE_28900 = (
    "$krb5db$18$test$TEST.LOCAL"
    "$266b5a53a6d663c3f69174f3309acada8e467c097c7973699f86286a6cf1a6c7"
)

PASSWORD = "hashcat"
# hashcat's outfile echoes cracked plaintext hex-encoded after the ':'.
PASSWORD_HEX = PASSWORD.encode().hex()

# The signature of a genuine hash-parse rejection, as opposed to hashcat never
# getting as far as parsing (missing OpenCL device, missing library, a
# rejected flag) -- both look identical on returncode and outfile-absence
# alone. Tolerant of the exact wording since only 7.1.2 is testable locally
# and this must also hold for 6.2.6/7.0.0/7.1.0/7.1.1.
_PARSE_ERROR_RE = re.compile(r"Hash parsing error|Separator unmatched")


def _insert_spn(line, spn="HTTP/DC01"):
    """Turn a no-SPN 19600/19700 line into its SPN-bearing form."""
    parts = line.split("$")
    # ['', 'krb5tgs', ver, user, realm, checksum, edata]
    return "$".join(parts[:5] + [f"*{spn}*"] + parts[5:])


def _uppercase_user(line):
    parts = line.split("$")
    parts[3] = parts[3].upper()
    return "$".join(parts)


def _upper_hex_fields(line):
    """Uppercase the trailing checksum+edata hex fields of a 19600/19700 line."""
    parts = line.split("$")
    parts[-2] = parts[-2].upper()
    parts[-1] = parts[-1].upper()
    return "$".join(parts)


def _run_crack(tmp_path, mode, line, tag):
    """Run a real crack attempt; return (returncode, recovered_hex_or_None).

    Checks the exit status before trusting an empty/missing outfile -- a bad
    flag or missing device produces no outfile too, which must not be
    confused with "this hash did not crack".
    """
    hashfile = tmp_path / f"hash-{tag}.txt"
    hashfile.write_text(line + "\n", encoding="utf-8")
    wordlist = tmp_path / f"wl-{tag}.txt"
    wordlist.write_text(PASSWORD + "\n", encoding="utf-8")
    potfile = tmp_path / f"crack-{tag}.pot"
    outfile = tmp_path / f"out-{tag}.txt"

    proc = subprocess.run(
        [HASHCAT_BIN, "-m", str(mode), "-a", "0",
         "--potfile-path", str(potfile),
         "--outfile-format", "1,3", "--outfile", str(outfile),
         "--quiet", str(hashfile), str(wordlist)],
        check=False, capture_output=True, timeout=300, text=True,
    )
    # 0 = cracked, 1 = exhausted without cracking. Anything else is a broken
    # run, not a legitimate "this hash never cracks" result.
    assert proc.returncode in (0, 1), (
        f"hashcat exited {proc.returncode} for mode {mode} tag {tag}; "
        f"stderr: {proc.stderr.strip()!r}"
    )
    if not outfile.exists():
        return proc.returncode, None
    text = outfile.read_text(encoding="utf-8").strip()
    if not text:
        return proc.returncode, None
    return proc.returncode, text.rsplit(":", 1)[-1]


def _run_left_oracle(tmp_path, mode, line, tag):
    """Return hashcat's own normalized echo of `line`, independent of cracking.

    `--left` with an always-empty --potfile-path lists every hash hashcat
    parsed successfully, in the exact form hashcat would echo it on a crack.
    Unlike a real crack attempt, this works even for vectors engineered to
    never crack (e.g. a case-mangled salt), which M8 needs for full coverage.
    `--potfile-disable` is rejected in combination with `--left`, so an empty
    potfile path is used instead, fresh per call so no run can pollute another.
    """
    hashfile = tmp_path / f"left-hash-{tag}.txt"
    hashfile.write_text(line + "\n", encoding="utf-8")
    potfile = tmp_path / f"left-{tag}.pot"
    potfile.write_text("", encoding="utf-8")
    outfile = tmp_path / f"left-out-{tag}.txt"

    proc = subprocess.run(
        [HASHCAT_BIN, "-m", str(mode),
         "--potfile-path", str(potfile),
         "--self-test-disable", "--left",
         "-o", str(outfile), "--quiet", str(hashfile)],
        check=False, capture_output=True, timeout=300, text=True,
    )
    assert proc.returncode == 0, (
        f"hashcat --left exited {proc.returncode} for mode {mode} tag {tag}; "
        f"stderr: {proc.stderr.strip()!r}"
    )
    assert outfile.exists(), (
        f"--left produced no outfile for mode {mode} tag {tag}; "
        f"hashcat could not parse the input line at all"
    )
    return outfile.read_text(encoding="utf-8").strip()


@pytest.mark.parametrize("mode,example", [(19600, EXAMPLE_19600), (19700, EXAMPLE_19700)])
def test_m1_no_spn_form_recovers_password(tmp_path, mode, example):
    rc, plaintext_hex = _run_crack(tmp_path, mode, example, f"m1-{mode}")
    assert (rc, plaintext_hex) == (0, PASSWORD_HEX)


@pytest.mark.parametrize("mode,example", [(19600, EXAMPLE_19600), (19700, EXAMPLE_19700)])
def test_m2_spn_form_recovers_password(tmp_path, mode, example):
    spn_line = _insert_spn(example)
    rc, plaintext_hex = _run_crack(tmp_path, mode, spn_line, f"m2-{mode}")
    assert (rc, plaintext_hex) == (0, PASSWORD_HEX)


@pytest.mark.parametrize("mode,example", [(19600, EXAMPLE_19600), (19700, EXAMPLE_19700)])
def test_m3_spn_is_stripped_from_echo(tmp_path, mode, example):
    spn_line = _insert_spn(example)
    no_spn_echo = _run_left_oracle(tmp_path, mode, example, f"m3-nospn-{mode}")
    spn_echo = _run_left_oracle(tmp_path, mode, spn_line, f"m3-spn-{mode}")
    assert spn_echo == no_spn_echo == example


@pytest.mark.parametrize("mode,example", [(19600, EXAMPLE_19600), (19700, EXAMPLE_19700)])
def test_m4_uppercase_hex_is_echoed_lowercased(tmp_path, mode, example):
    upper = _upper_hex_fields(example)
    assert upper != example  # sanity: the mutation actually changed the line
    echo = _run_left_oracle(tmp_path, mode, upper, f"m4-{mode}")
    assert echo == example


@pytest.mark.parametrize("mode,example", [(19600, EXAMPLE_19600), (19700, EXAMPLE_19700)])
def test_m5_user_and_realm_case_echoed_verbatim(tmp_path, mode, example):
    mixed = _uppercase_user(example)
    assert mixed != example
    echo = _run_left_oracle(tmp_path, mode, mixed, f"m5-{mode}")
    assert echo == mixed


@pytest.mark.parametrize("mode,example", [(19600, EXAMPLE_19600), (19700, EXAMPLE_19700)])
def test_m6_all_star_form_is_rejected(tmp_path, mode, example):
    # module_19600.c's own source comment claims $krb5tgs$<ver>$*user*realm*spn*$...
    # is accepted (verified stale at v6.2.6, v7.0.0, v7.1.2: it fails with
    # "Separator unmatched"). This is why our validator rejects the form too --
    # accepting it would import hashes hashcat itself cannot parse.
    #
    # This is a parse failure, not "exhausted without cracking", so hashcat
    # exits neither 0 nor 1 (observed: 255) and never produces an outfile --
    # unlike _run_crack's other callers, that non-(0,1) exit IS the assertion.
    parts = example.split("$")
    all_star = "$".join(
        parts[:3] + [f"*{parts[3]}*{parts[4]}*HTTP/DC01*"] + parts[5:]
    )
    tag = f"m6-{mode}"
    hashfile = tmp_path / f"hash-{tag}.txt"
    hashfile.write_text(all_star + "\n", encoding="utf-8")
    wordlist = tmp_path / f"wl-{tag}.txt"
    wordlist.write_text(PASSWORD + "\n", encoding="utf-8")
    potfile = tmp_path / f"crack-{tag}.pot"
    outfile = tmp_path / f"out-{tag}.txt"

    proc = subprocess.run(
        [HASHCAT_BIN, "-m", str(mode), "-a", "0",
         "--potfile-path", str(potfile),
         "--outfile-format", "1,3", "--outfile", str(outfile),
         "--quiet", str(hashfile), str(wordlist)],
        check=False, capture_output=True, timeout=300, text=True,
    )
    assert proc.returncode not in (0, 1), (
        f"all-star form for mode {mode} was accepted (exit {proc.returncode}); "
        f"if hashcat now parses it, the validator's rejection is out of date"
    )
    assert not outfile.exists()
    # A non-(0,1) exit with no outfile is ALSO what happens if hashcat never
    # ran at all (missing OpenCL device/library, a rejected flag) -- that
    # would make this test pass without ever exercising the parser, which is
    # exactly the "gate proves nothing" failure this module exists to avoid.
    # The discriminating message ("Hash parsing error: ...") is written to
    # STDOUT, not stderr, even under --quiet -- observed on 7.1.2. Checking
    # stderr alone would match "No hashes loaded.", a weaker message that can
    # plausibly appear for other, non-parse load failures too. So both
    # streams are combined and checked here; do not narrow this back to
    # stderr only.
    combined_output = proc.stdout + proc.stderr
    assert _PARSE_ERROR_RE.search(combined_output), (
        f"all-star form for mode {mode} exited {proc.returncode} with no "
        f"outfile, but neither 'Hash parsing error' nor 'Separator unmatched' "
        f"appeared in stdout/stderr -- hashcat may never have run at all.\n"
        f"stdout: {proc.stdout.strip()!r}\nstderr: {proc.stderr.strip()!r}"
    )


@pytest.mark.parametrize("mode,example", [(19600, EXAMPLE_19600), (19700, EXAMPLE_19700)])
def test_m7_uppercase_username_does_not_recover(tmp_path, mode, example):
    mixed = _uppercase_user(example)
    rc, plaintext_hex = _run_crack(tmp_path, mode, mixed, f"m7-{mode}")
    assert rc == 1
    assert plaintext_hex is None


@pytest.mark.parametrize("mode,example", [(19600, EXAMPLE_19600), (19700, EXAMPLE_19700)])
def test_m8_normalize_matches_live_echo_no_spn(tmp_path, mode, example):
    echo = _run_left_oracle(tmp_path, mode, example, f"m8-nospn-{mode}")
    assert normalize_kerberos_hash(example, str(mode)) == echo


@pytest.mark.parametrize("mode,example", [(19600, EXAMPLE_19600), (19700, EXAMPLE_19700)])
def test_m8_normalize_matches_live_echo_spn(tmp_path, mode, example):
    spn_line = _insert_spn(example)
    echo = _run_left_oracle(tmp_path, mode, spn_line, f"m8-spn-{mode}")
    assert normalize_kerberos_hash(spn_line, str(mode)) == echo


@pytest.mark.parametrize("mode,example", [(19600, EXAMPLE_19600), (19700, EXAMPLE_19700)])
def test_m8_normalize_matches_live_echo_mixed_case_username(tmp_path, mode, example):
    mixed = _uppercase_user(example)
    echo = _run_left_oracle(tmp_path, mode, mixed, f"m8-mixed-{mode}")
    assert normalize_kerberos_hash(mixed, str(mode)) == echo


@pytest.mark.parametrize("mode,example", [(19600, EXAMPLE_19600), (19700, EXAMPLE_19700)])
def test_m8_normalize_matches_live_echo_uppercase_hex(tmp_path, mode, example):
    upper = _upper_hex_fields(example)
    echo = _run_left_oracle(tmp_path, mode, upper, f"m8-upperhex-{mode}")
    assert normalize_kerberos_hash(upper, str(mode)) == echo


# 19800/19900/28800/28900 also went through the Task 2 case fix (D2), but
# have no SPN concept -- only M4/M5/M8 (via the --left oracle) apply.
_OTHER_AES_MODES = [
    (19800, EXAMPLE_19800),
    (19900, EXAMPLE_19900),
    (28800, EXAMPLE_28800),
    (28900, EXAMPLE_28900),
]


@pytest.mark.parametrize("mode,example", _OTHER_AES_MODES)
def test_m8_other_aes_modes_normalize_matches_live_echo(tmp_path, mode, example):
    parts = example.split("$")
    parts[3] = parts[3].upper()
    parts[4] = parts[4].lower()
    parts[-1] = parts[-1].upper()
    variant = "$".join(parts)
    assert variant != example  # sanity: the mutation actually changed the line
    echo = _run_left_oracle(tmp_path, mode, variant, f"m8-other-{mode}")
    assert normalize_kerberos_hash(variant, str(mode)) == echo
