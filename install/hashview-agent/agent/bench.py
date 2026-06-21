"""hashcat benchmark output parsing.

Kept dependency-free (no psutil / no argv side effects) so it is unit-testable
on its own, like the server-side chunk planner. The agent's run_benchmark()
shells out to ``hashcat -b -m <mode>`` and feeds the captured output here.
"""
import re
import shlex


def parse_hc_extra_args(extra):
    """Parse HC_EXTRA_ARGS (free-form hashcat flags, e.g. '-d 3,4') into a list
    of argv tokens for list-form subprocess calls (benchmarking). Empty -> [].
    Falls back to whitespace splitting on unbalanced quotes."""
    try:
        return shlex.split(extra or '')
    except ValueError:
        return (extra or '').split()

# Per-device benchmark line, e.g. "Speed.#1.........:  1234.5 MH/s (12.34ms) ...".
# Match #<digit> only so the aggregate "Speed.#*" line is not double counted.
_BENCH_SPEED_RE = re.compile(r'Speed\.#\d+\.*:\s*([0-9.]+)\s*([kMGTP]?)H/s', re.IGNORECASE)
_BENCH_UNIT = {'': 1, 'k': 10**3, 'M': 10**6, 'G': 10**9, 'T': 10**12, 'P': 10**15}


def parse_benchmark_speed(output):
    """Sum a hashcat benchmark's per-device speeds into raw hashes/sec.

    Returns an int (H/s), or None if no Speed line was found. 0 is a valid result
    (the device can't run that mode) and is returned so the server stops asking.
    """
    total = 0.0
    found = False
    for match in _BENCH_SPEED_RE.finditer(output):
        total += float(match.group(1)) * _BENCH_UNIT.get(match.group(2), 1)
        found = True
    return int(total) if found else None


def _short_gpu_name(name):
    """Trim vendor noise from a hashcat device name -> 'RTX 4090', 'A100', etc."""
    name = (name or '').strip()
    for prefix in ('NVIDIA GeForce ', 'NVIDIA ', 'AMD Radeon ', 'AMD ', 'Radeon '):
        if name.startswith(prefix):
            return name[len(prefix):].strip()
    return name


def parse_device_info(json_data):
    """From a hashcat --status-json object, return (gpu_count, gpu_model, temps_csv).

    Picks GPU-type devices (falling back to all devices if hashcat doesn't tag a
    type), shortens the model name, and joins the per-card temperatures as a CSV
    string (e.g. '71,70,72'). Used to report card model/count/temps each check-in.
    """
    devices = (json_data or {}).get('devices') or []
    gpus = [d for d in devices if str(d.get('device_type', '')).upper() == 'GPU'] or devices
    count = len(gpus)
    model = _short_gpu_name(gpus[0].get('device_name', '')) if gpus else ''
    temps = ','.join(str(d['temp']) for d in gpus if d.get('temp') is not None)
    return count, model, temps
