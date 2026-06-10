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


def convert_ntds(ntds_path: str, system_path: str) -> str:
    """Convert an NTDS.dit + SYSTEM hive pair to pwdump format using impacket-secretsdump.

    Runs impacket-secretsdump in LOCAL mode (no network required). Output is
    written to a .pwdump file for processing by import_hashfilehashes().
    Raises ConversionError if the tool is missing, exits non-zero, or
    produces no output. Returns the path to the pwdump file on success.
    """
    out_path = ntds_path + '.pwdump'
    try:
        # Fixed argv list, no shell=True; tool name resolved from PATH by design.
        result = subprocess.run(  # nosec B603 B607
            ['impacket-secretsdump',
             '-ntds', ntds_path,
             '-system', system_path,
             'LOCAL'],
            capture_output=True,
            timeout=600,
        )
    except FileNotFoundError as err:
        raise ConversionError(
            'impacket-secretsdump is not installed on this server. '
            'Install impacket (pip install impacket) to enable NTDS.dit conversion.'
        ) from err
    except subprocess.TimeoutExpired as err:
        raise ConversionError('impacket-secretsdump timed out after 10 minutes.') from err
    if result.returncode != 0:
        msg = result.stderr.decode('utf-8', errors='replace').strip()
        raise ConversionError(msg or 'impacket-secretsdump exited with an error and produced no output.')
    if not result.stdout.strip():
        raise ConversionError(
            'No hashes extracted from the NTDS.dit file. '
            'Verify the SYSTEM hive corresponds to this NTDS.dit.'
        )
    with open(out_path, 'wb') as f:
        f.write(result.stdout)
    return out_path
