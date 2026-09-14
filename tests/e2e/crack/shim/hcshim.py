"""Test double for hashcat used by the multi-agent crack e2e test.

Performs REAL recovery (it computes NTLM and matches the target hashfile); it
just isn't the optimized hashcat engine. Parses the server-built hashcat
command, reads the gzip wordlist, applies any -r rules, and writes genuine
hash:hex_plain matches to --outfile (outfile-format 1,3).

CRITICAL: never write to stderr on the happy path — the agent's run_hashcat
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
    with open(path, encoding="utf-8", errors="surrogateescape") as f:
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
    with open(path, encoding="utf-8", errors="surrogateescape") as f:
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


# --skip/--limit are consumed and IGNORED: the shim always cracks the whole
# candidate set, which is what a chunk-coverage test wants. They have to be here
# all the same -- without them the flag fell through to the startswith("-")
# catch-all but its numeric VALUE landed in positionals, so a chunked command
# was parsed as hashfile="0" (already wrong for every wordlist chunk today).
# -1..-4 are hashcat's custom charsets. Like --skip/--limit they are consumed
# and ignored (the shim does not expand masks), but they MUST be consumed: their
# value is a bare token that otherwise lands in positionals and shifts the
# hashfile/wordlist/mask order.
# The long forms of the custom charsets take a value exactly as -1..-4 do, and
# the unit tests exercise them (tests/unit/test_mask_argv.py). The device
# selectors are here for the same reason: an agent configured with
# HC_EXTRA_ARGS='-d 3,4' prepends one, and its bare value would shift the
# positionals in precisely the way --skip once did.
VALUE_FLAGS = {"-m", "-w", "--session", "--potfile-path", "--outfile",
               "--outfile-format", "-a", "-r", "-j", "-k", "--skip", "--limit",
               "-1", "-2", "-3", "-4",
               "--custom-charset1", "--custom-charset2",
               "--custom-charset3", "--custom-charset4",
               "-d", "--backend-devices", "--opencl-device-types"}
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
        if a == "--":
            # End of options: every remaining token is a positional, even one
            # that starts with '-' (a mask such as '-?d?d'). Model hashcat here
            # or the shim cannot exercise the sentinel at all.
            positionals.extend(argv[i + 1:])
            break
        if a in FLAG_ONLY or a.startswith("-"):
            i += 1
            continue
        positionals.append(a)
        i += 1
    return mode, outfile, outfile_format, rules, positionals


def _mask_keyspace(mask):
    """Candidate count of a built-in-charset mask, or None.

    Deliberately a plain product of the charset sizes: the shim is not hashcat
    and does not model its base/device loop split. It reports the FULL mask
    keyspace, so --skip/--limit here address candidates one-for-one, which is what
    makes a chunk-coverage test over the shim meaningful.
    """
    sizes = {"l": 26, "u": 26, "d": 10, "s": 33, "h": 16, "H": 16, "a": 95, "b": 256}
    total, i = 1, 0
    while i < len(mask):
        if mask[i] == "?":
            if i + 1 >= len(mask):
                return None
            nxt = mask[i + 1]
            if nxt == "?":
                pass                      # a literal '?'
            elif nxt in sizes:
                total *= sizes[nxt]
            else:
                return None               # custom charset: not modelled
            i += 2
        else:
            i += 1
    return total


def _keyspace(argv):
    """Answer `--keyspace` with a bare integer on STDOUT, exit 0.

    It has to be handled BEFORE the crack path. --keyspace passes no hashfile, so
    it would fall through with too few positionals and write to STDERR -- and
    run_hashcat treats any stderr as fatal and kills the agent, so an un-taught
    shim does not merely fail the probe, it takes the container down.
    """
    _mode, _outfile, _fmt, _rules, positionals = parse_args(argv)
    attack = 0
    for i, a in enumerate(argv):
        if a == "-a" and i + 1 < len(argv):
            attack = int(argv[i + 1])
    # -a 3 is the mask alone; -a 6 is wordlist then mask; -a 7 is mask then
    # wordlist. No hashfile in any of them.
    if attack == 3:
        total = _mask_keyspace(positionals[0]) if positionals else None
    elif attack == 6:
        total = _linecount(positionals[0]) if positionals else None
    elif attack == 7:
        total = _mask_keyspace(positionals[0]) if positionals else None
    else:
        total = _linecount(positionals[0]) if positionals else None
    if total is None:
        sys.stderr.write("hcshim: cannot compute a keyspace for that attack\n")
        return 1
    print(total, flush=True)
    return 0


def _linecount(path):
    try:
        with open(path, "rb") as handle:
            return sum(1 for line in handle if line.strip())
    except OSError:
        return None


def main(argv):
    if "--version" in argv:
        # The agent probes this to report its hashcat major to the server.
        print("hcshim v6.2.6", flush=True)
        return 0
    if "--keyspace" in argv:
        return _keyspace(argv)
    if "-b" in argv or "--benchmark" in argv:
        # Benchmark mode: the real agent runs ``hashcat -b -m <mode>`` and feeds
        # the output to agent/bench.parse_benchmark_speed, which looks for a
        # per-device line ``Speed.#<n>...: <num> <unit>H/s``. Emit one so the
        # agent records a speed and proceeds to actual cracking instead of
        # re-benchmarking forever (no hashfile/wordlist positionals are passed
        # in this mode).
        print(
            "Speed.#1.........:  1000.0 MH/s (0.50ms) @ Accel:1 Loops:1 Thr:1 Vec:1",
            flush=True,
        )
        return 0
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
