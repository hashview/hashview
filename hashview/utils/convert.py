"""Server-side conversion of raw source files into hashcat-ready text files."""
import os
import subprocess  # nosec B404 - used only with fixed argv lists, never shell=True


class ConversionError(Exception):
    """Raised when an external conversion tool fails or produces no output."""


def convert_pcap(src_path: str) -> str:
    """Convert a pcap/pcapng WPA capture to hashcat 22000 format.

    Runs hcxpcapngtool from the hcxtools package. Raises ConversionError
    if the tool is missing, exits non-zero, or produces no hashes.
    Returns the path to the converted text file on success.
    """
    out_path = src_path + '.hc22000'
    try:
        # Fixed argv list, no shell=True; tool name resolved from PATH by design.
        result = subprocess.run(  # nosec B603 B607
            ['hcxpcapngtool', '-o', out_path, src_path],
            capture_output=True,
            timeout=300,
        )
    except FileNotFoundError as err:
        raise ConversionError(
            'hcxpcapngtool is not installed on this server. '
            'Install hcxtools (apt install hcxtools) to enable WPA capture conversion.'
        ) from err
    except subprocess.TimeoutExpired as err:
        # Clean up any partial output before raising
        if os.path.exists(out_path):
            os.remove(out_path)
        raise ConversionError('hcxpcapngtool timed out after 5 minutes.') from err
    if result.returncode != 0:
        msg = result.stderr.decode('utf-8', errors='replace').strip()
        raise ConversionError(msg or 'hcxpcapngtool exited with an error and produced no output.')
    if not os.path.exists(out_path) or os.path.getsize(out_path) == 0:
        raise ConversionError(
            'No valid WPA handshakes or PMKIDs found in the capture file.'
        )
    return out_path
