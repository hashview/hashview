"""hashcat --status-json output parsing.

Kept dependency-free (json / logging / datetime plus agent.bench) so it is
unit-testable on its own, like agent/bench.py. The agent's status poll tees
hashcat's stdout to a file and feeds the path here.

Extracted verbatim from hashview-agent.py so the parser can be exercised
against real output captured from multiple hashcat releases
(tests/fixtures/hashcat, .github/workflows/hashcat-matrix.yml).
"""
import json
import logging
from datetime import datetime

LOG = logging.getLogger('hashview-agent')


def time_difference(future_timestamp):
    """Humanise the gap between now and a future epoch timestamp, to the two
    largest non-zero units (e.g. '2 days, 3 hours')."""
    delta = datetime.fromtimestamp(future_timestamp) - datetime.now()

    if delta.total_seconds() < 0:
        return "The specified time is in the past."

    years = delta.days // 365
    months = (delta.days % 365) // 30
    days = (delta.days % 365) % 30
    hours, remainder = divmod(delta.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    components = [
        (years, "year"),
        (months, "month"),
        (days, "day"),
        (hours, "hour"),
        (minutes, "minute"),
        (seconds, "second")
    ]

    components = [(value, name) for value, name in components if value > 0]

    if len(components) == 0:
        return "The specified time is very close to now."
    elif len(components) == 1:
        return f"{components[0][0]} {components[0][1]}{'s' if components[0][0] > 1 else ''}"

    largest_two = components[:2]
    return ', '.join(f"{value} {name}{'s' if value > 1 else ''}" for value, name in largest_two)


def convert_speed(speed):
    """Render a raw hashes/sec integer as a human unit string."""
    if speed > 1000000000:
        return str(round((speed / 1000000000), 1)) + " GH/s"
    elif speed > 1000000:
        return str(round((speed / 1000000), 1)) + " MH/s"
    elif speed > 1000:
        return str(round((speed / 1000), 1)) + " KH/s"
    else:
        return str(speed) + " H/s"


def hashcat_status(filepath):
    """Parse a tee'd hashcat stdout file into the agent's status dict.

    Returns {} when the file holds no parseable --status-json line.
    """
    from agent.bench import parse_device_info
    status = {}
    # hashcat's stdout can contain arbitrary non-UTF-8 bytes (recovered plaintext
    # / candidate bytes). We only need the ASCII --status-json lines, so decode
    # tolerantly (errors='replace') instead of crashing on a stray byte.
    with open(filepath, encoding='utf-8', errors='replace') as hashcat_output:
        for line in hashcat_output:
            # Iterate the whole file; the last valid status line wins. We read this
            # while hashcat is still writing it (via tee), so a line can be partial
            # or malformed -- skip those rather than aborting the status poll.
            if not line.startswith('{'):
                continue
            try:
                json_data = json.loads(line)
                status['Time_Estimated'] = "(" + time_difference(json_data['estimated_stop']) + ")"
                status['Recovered'] = (str(json_data['recovered_hashes'][0]) + "/"
                                       + str(json_data['recovered_hashes'][1]))
                status['Speed #'] = convert_speed(sum(d['speed'] for d in json_data['devices']))
                gpu_count, gpu_model, temps = parse_device_info(json_data)
                status['GPU_Count'] = gpu_count
                status['GPU_Model'] = gpu_model
                status['Temps'] = temps
            except (ValueError, KeyError, IndexError, TypeError) as err:
                LOG.debug('Skipping unparseable hashcat status line: %s', err)
    return status
