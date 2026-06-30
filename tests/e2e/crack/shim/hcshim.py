"""Test double for hashcat used by the multi-agent crack e2e test.

Performs REAL recovery (it computes NTLM and matches the target hashfile); it
just isn't the optimized hashcat engine. Parses the server-built hashcat
command, reads the gzip wordlist, applies any -r rules, and writes genuine
hash:hex_plain matches to --outfile (outfile-format 1,3).

CRITICAL: never write to stderr on the happy path — the agent's run_command
treats any stderr output as a fatal error and kills the agent.
"""
import binascii
import gzip
import json
import os
import struct
import sys
import time


# --- pure-Python MD4 (NTLM); OpenSSL 3 frequently lacks md4 ----------------
def _lrot(x, n):
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def md4(data):
    A, B, C, D = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    msg = bytearray(data)
    bit_len = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", bit_len)
    for off in range(0, len(msg), 64):
        X = list(struct.unpack("<16I", msg[off:off + 64]))
        a, b, c, d = A, B, C, D
        for i in range(0, 16, 4):
            a = _lrot(a + ((b & c) | (~b & d)) + X[i], 3)
            d = _lrot(d + ((a & b) | (~a & c)) + X[i + 1], 7)
            c = _lrot(c + ((d & a) | (~d & b)) + X[i + 2], 11)
            b = _lrot(b + ((c & d) | (~c & a)) + X[i + 3], 19)
        for i in (0, 1, 2, 3):
            a = _lrot(a + ((b & c) | (b & d) | (c & d)) + X[i] + 0x5A827999, 3)
            d = _lrot(d + ((a & b) | (a & c) | (b & c)) + X[i + 4] + 0x5A827999, 5)
            c = _lrot(c + ((d & a) | (d & b) | (a & b)) + X[i + 8] + 0x5A827999, 9)
            b = _lrot(b + ((c & d) | (c & a) | (d & a)) + X[i + 12] + 0x5A827999, 13)
        for i in (0, 2, 1, 3):
            a = _lrot(a + (b ^ c ^ d) + X[i] + 0x6ED9EBA1, 3)
            d = _lrot(d + (a ^ b ^ c) + X[i + 8] + 0x6ED9EBA1, 9)
            c = _lrot(c + (d ^ a ^ b) + X[i + 4] + 0x6ED9EBA1, 11)
            b = _lrot(b + (c ^ d ^ a) + X[i + 12] + 0x6ED9EBA1, 15)
        A = (A + a) & 0xFFFFFFFF
        B = (B + b) & 0xFFFFFFFF
        C = (C + c) & 0xFFFFFFFF
        D = (D + d) & 0xFFFFFFFF
    return struct.pack("<4I", A, B, C, D)


def ntlm_hex(plaintext):
    return binascii.hexlify(md4(plaintext.encode("utf-16le", "surrogatepass"))).decode("ascii")


# --- minimal hashcat rule engine -------------------------------------------
def apply_rule(word, rule_line):
    """Apply one space-separated rule line. Unknown ops are silently skipped
    (never stderr). Supported: ':' '$X' '^X' 'l' 'u' 'c'."""
    for op in rule_line.split():
        if op == ":":
            continue
        if op[0] == "$":
            word = word + op[1:]
        elif op[0] == "^":
            word = op[1:] + word
        elif op == "l":
            word = word.lower()
        elif op == "u":
            word = word.upper()
        elif op == "c":
            word = (word[:1].upper() + word[1:].lower()) if word else word
        # else: skip
    return word


def _load_rule_lines(path):
    lines = []
    with open(path, "r", encoding="utf-8", errors="surrogateescape") as f:
        for raw in f:
            line = raw.rstrip("\n")
            stripped = line.strip()
            # Skip blank, whitespace-only, and comment lines. A whitespace-only
            # line would otherwise split to zero ops and act as a silent
            # passthrough rule (testing the un-ruled word).
            if not stripped or stripped.startswith("#"):
                continue
            lines.append(line)
    return lines


def _candidates(word, rule_lines):
    return [word] if not rule_lines else [apply_rule(word, r) for r in rule_lines]


def _iter_words(path):
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="surrogateescape") as f:
        for line in f:
            yield line.rstrip("\n")


def _load_targets(path):
    with open(path, "r", encoding="utf-8", errors="surrogateescape") as f:
        return [line.rstrip("\n") for line in f if line.strip()]


def crack(mode, targets, wordlist_path, rule_files):
    """Return {original_target_line: plaintext} for recovered hashes."""
    if mode != 1000:
        return {}                       # v1 supports NTLM only
    want = {}
    for t in targets:
        want.setdefault(t.strip().lower(), t.strip())
    rule_lines = []
    for rf in rule_files:
        rule_lines += _load_rule_lines(rf)
    found = {}
    for word in _iter_words(wordlist_path):
        for cand in _candidates(word, rule_lines):
            h = ntlm_hex(cand).lower()
            if h in want and want[h] not in found:
                found[want[h]] = cand
        if len(found) == len(want):
            break
    return found


def _write_outfile(path, found):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for target_line, plain in found.items():
            hexplain = binascii.hexlify(plain.encode("utf-8", "surrogateescape")).decode("ascii")
            f.write(target_line + ":" + hexplain + "\n")


def _emit_status(total, recovered):
    # One --status-json line so the agent's hashcatParser has parseable input.
    status = {
        "status": 5,
        "recovered_hashes": [recovered, total],
        "estimated_stop": int(time.time()) + 1,
        "devices": [{"speed": 1000000}],
    }
    print(json.dumps(status), flush=True)


VALUE_FLAGS = {"-m", "-w", "--session", "--potfile-path", "--outfile",
               "--outfile-format", "-a", "-r", "-j", "-k"}
FLAG_ONLY = {"-O", "--status", "--status-json", "--loopback", "--force"}


def parse_args(argv):
    mode, outfile, outfile_format, rules, positionals = 0, None, "1,3", [], []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a.startswith("--") and "=" in a:
            k, v = a.split("=", 1)
            if k == "--outfile-format":
                outfile_format = v
            i += 1
            continue
        if a in VALUE_FLAGS:
            v = argv[i + 1] if i + 1 < len(argv) else ""
            if a == "-m":
                mode = int(v)
            elif a == "--outfile":
                outfile = v
            elif a == "--outfile-format":
                outfile_format = v
            elif a == "-r":
                rules.append(v)
            i += 2
            continue
        if a in FLAG_ONLY or a.startswith("-"):
            i += 1
            continue
        positionals.append(a)
        i += 1
    return mode, outfile, outfile_format, rules, positionals


def main(argv):
    mode, outfile, _fmt, rules, positionals = parse_args(argv)
    if len(positionals) < 2:
        sys.stderr.write("hcshim: expected hashfile and wordlist positionals\n")
        return 1
    hashfile, wordlist = positionals[0], positionals[1]
    targets = _load_targets(hashfile)
    _emit_status(len(targets), 0)
    found = crack(mode, targets, wordlist, rules)
    if outfile:
        _write_outfile(outfile, found)
    _emit_status(len(targets), len(found))
    return 0
