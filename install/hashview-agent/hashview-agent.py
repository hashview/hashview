import sys

# Hashview supports Python 3.11 and newer (matches the server's setup.py floor).
# Checked before any third-party import so an unsupported runtime fails cleanly.
if sys.version_info < (3, 11):  # noqa: UP036 - runtime guard for older interpreters
    sys.stderr.write('Hashview agent requires Python 3.11 or newer.\n')
    sys.exit(1)

import argparse
import builtins
import gzip
import hashlib
import json
import logging
import os
import secrets
import signal
import socket
import subprocess
import time
import uuid
import zlib
from threading import Thread

import psutil

parser = argparse.ArgumentParser()
parser.add_argument("--debug", action="store_true", help="increase output verbosity")
args = parser.parse_args()

# Standardised console output for everything the agent logs during operation.
# --debug raises the level to DEBUG to surface the verbose per-file / per-status
# detail; without it the console stays at INFO (milestones + problems only).
logging.basicConfig(
    level=logging.DEBUG if args.debug else logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
LOG = logging.getLogger('hashview-agent')

# Build Config

# ----------------------------------------------
# Manifest management (JSON based)
# ----------------------------------------------
class Manifest:
    """
    Simple JSON‑based manifest manager.
    Keeps the manifest data in memory and writes to disk only when
    `save()` is called.
    """
    def __init__(self, path):
        self.path = path
        self.data = {}
        self._load()

    def _load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path) as f:
                    self.data = json.load(f)
            except Exception:
                # Corrupt or empty file – start fresh
                self.data = {}
        else:
            self.data = {}

    def save(self):
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w") as f:
            json.dump(self.data, f, indent=2, sort_keys=True)

# Global manifest instances
rules_manifest = Manifest("control/rules_manifest.json")
wordlists_manifest = Manifest("control/wordlists_manifest.json")
if not os.path.exists('agent/config.conf'):

    # Time to ask some questions
    print('\nInitial setup detected. Hashview Agent will now prompt you to setup the config fild ./agent/config/config.conf.\n')
    server = input('Enter IP address or FQDN of the hashview server: ')
    while len(server) == 0:
        print('Error: Value must be an IP address or FQDN. Can not be blank: ')
        server = input("Enter IP address or FQDN of the hashview server: ")
    port = input('Enter the port of the hashview server: ')
    while len(port) == 0:
        print('Error: You must provide a port. By default Hashview Server runs on 8443: ')
        port = input("Enter the port of the hashview server: ")
    use_tls = input('Does the Hashview server use SSL/TLS? [y/N]:')
    # Accept y / yes / true (any case) as yes; anything else is no. Stored as the
    # string 'True'/'False'. (Previously only an exact 'y'/'Y' counted, so 'yes'
    # silently became no -> the agent then spoke plain HTTP to a TLS port.)
    use_tls = str(use_tls).strip().lower() in ('y', 'yes', 'true', 't', '1')

    hostname = socket.gethostname()
    name = input('Enter the name of this Hashview Agent [Hit Enter for: ' + hostname + ']: ')
    if len(name) == 0:
        name = hostname
    
    # Generate UUID
    agent_uuid = uuid.uuid4()

    hashcat_path = input('Enter the path to a local install of hashcat: ')
    while not os.path.exists(hashcat_path):
        print("Error: File not found.")
        hashcat_path = input('Enter the path to a local install of hashcat: ')

    hc_extra_args = input('Optional: extra hashcat arguments for this agent, '
                          'e.g. -d 3,4 (leave blank for none): ').strip()

    # Write config file
    config = open("agent/config.conf", "w")
    config.write("[HASHVIEW]\n")
    config.write("server = " + str(server) + "\n")
    config.write("port = " + str(port) + "\n")
    config.write("use_ssl = " + str(use_tls) + "\n\n")

    config.write("[AGENT]\n")
    config.write("name = " + str(name) + "\n")
    config.write("uuid = " + str(agent_uuid) + "\n")
    config.write("HC_BIN_PATH = " + str(hashcat_path) + "\n")
    config.write("HC_EXTRA_ARGS = " + str(hc_extra_args) + "\n")

    config.close()

from agent.api import api  # noqa: E402 - config.conf must exist before agent.api loads it
from agent.status import convert_speed, time_difference  # noqa: E402,F401 - re-exported for callers
from agent.status import hashcat_status as hashcatParser  # noqa: E402


def send_heartbeat(agent_status, hc_status):
    return api.heartbeat(agent_status, hc_status)

def getHashcatPid():
    if sys.platform == 'win32':
        LOG.error("Hashview-Agent does not currently run on Windows. PRs welcome :)")
        sys.exit()
    else:
        for proc in psutil.process_iter():
            try:
                pinfo = proc.as_dict(attrs=['pid', 'name', 'cmdline'])
                # In the future we should change this to session id
                if 'hashcat' in pinfo['name'].lower():
                    for cli_args in pinfo['cmdline']:
                        if 'hc_cracked_' in cli_args:
                            return pinfo['pid']
            except Exception:
                return False
    return False

def _safe_control_filename(path_value):
    """Reduce a server-supplied path to a plain filename for our control dirs.

    The manifest `path` values come from the server's database (`Rules.path` /
    `Wordlists.path`), so they are untrusted input on this host: they must only ever
    become a file NAME inside control/, never a path that escapes it and never a
    shell word. Returns None when the value does not reduce to a usable filename,
    so the caller can skip the entry instead of writing somewhere unexpected.
    """
    raw = str(path_value or '').replace('\\', '/')
    name = os.path.basename(raw)
    if name in ('', '.', '..') or '\x00' in name:
        return None
    return name


def _install_rule_file(rule_id, entry_id, filename, remote_checksum):
    """Download, verify and install one rule file into control/rules.

    Shell-free by construction (issue #297): the gzip payload is decompressed
    in-process with `gzip` and the verified file is put in place with `os.replace`,
    instead of the old `run_command(f'gunzip {tmp_gz}')` / `run_command(f'mv
    {tmp_file} {dest}')` pair, which interpolated a server-supplied filename into a
    shell command line. Returns the manifest entry, or None if skipped.
    """
    compressed = api.get_rules_file(entry_id)
    if not compressed:
        LOG.warning('No data received for rule %s; will retry next sync.', rule_id)
        return None

    try:
        content = gzip.decompress(compressed)
    except (OSError, EOFError, zlib.error) as err:
        # Not gzip, or truncated. Previously `gunzip` failed and run_command turned
        # its stderr into a SIGINT of the whole agent; now we just skip the rule.
        LOG.warning('Rule %s did not decompress as gzip; skipping: %s', rule_id, err)
        return None

    local_checksum = hashlib.sha256(content).hexdigest()
    LOG.debug('Rule checksum local=%s remote=%s', local_checksum, remote_checksum)
    if local_checksum != remote_checksum:
        LOG.warning('Checksum verification failed for rule %s; discarding download.', rule_id)
        return None

    os.makedirs('control/rules', exist_ok=True)
    os.makedirs('control/tmp', exist_ok=True)
    tmp_file = os.path.join('control/tmp', secrets.token_hex(8))
    with open(tmp_file, 'wb') as f:
        f.write(content)
    os.replace(tmp_file, os.path.join('control/rules', filename))
    return {'checksum': local_checksum, 'filename': filename}


def sync_rules():
    """
    Synchronise local rule files with the server using JSON manifests.
    """
    LOG.info('Syncing rules with server.')
    # Guard the manifest fetch: on a network/server error api.rules_list() yields
    # no parseable list. Bail out WITHOUT pruning so a transient failure can never
    # wipe the local rules.
    try:
        server_entries = api.rules_list()
    except (TypeError, ValueError, KeyError) as err:
        LOG.warning('Could not fetch the rules manifest; skipping rules sync and cleanup: %s', err)
        return
    new_manifest = {}

    for entry in server_entries:
        rule_id = str(entry['id'])
        remote_checksum = entry['checksum']
        # Untrusted: the server's Rules.path only ever becomes a bare filename here.
        filename = _safe_control_filename(entry['path'])
        if not filename:
            LOG.warning('Rule %s has an unusable path %r; skipping it.', rule_id, entry.get('path'))
            continue

        local_entry = rules_manifest.data.get(rule_id)
        if local_entry and local_entry.get('checksum') == remote_checksum:
            # Up to date; keep as-is.
            new_manifest[rule_id] = local_entry
            continue

        if local_entry:
            LOG.debug('Rule %s changed on the server; re-downloading.', rule_id)
            old_name = local_entry.get('filename')
            old_path = os.path.join('control/rules', old_name) if old_name else None
            if old_path and os.path.exists(old_path):
                os.remove(old_path)
        else:
            LOG.info('Downloading new rule %s.', rule_id)

        installed = _install_rule_file(rule_id, entry['id'], filename, remote_checksum)
        if installed:
            new_manifest[rule_id] = installed

    if new_manifest != rules_manifest.data:
        rules_manifest.data = new_manifest
        rules_manifest.save()
        LOG.info('Rules manifest updated.')
    else:
        LOG.debug('Rules manifest unchanged.')

    # Sync complete: drop any local rule files no longer in the manifest. Skip on
    # an empty manifest so a momentary empty server response can't wipe the cache.
    if new_manifest:
        _prune_orphan_files('control/rules',
                            {e['filename'] for e in new_manifest.values() if e.get('filename')})

def _gz_name(basename):
    """Mirror of the server's utils.ensure_gz: ensure a trailing '.gz'.

    Wordlists are stored compressed on the server; the file the server serves
    is gzip. We keep it compressed locally (hashcat reads gzip directly), so a
    static '<hex>' path becomes '<hex>.gz' and a dynamic '<hex>.txt' path
    becomes '<hex>.txt.gz' — matching the path build_hashcat_command emits.
    """
    return basename if basename.endswith('.gz') else basename + '.gz'


def _sha256_file(path):
    sha256 = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(4096), b''):
            sha256.update(block)
    return sha256.hexdigest()


def _prune_orphan_files(directory, keep_filenames):
    """Delete files in `directory` that the just-completed sync did NOT record in
    its manifest (`keep_filenames`). This removes wordlists/rules that were
    deleted server-side (or left over from a previous version) so the agent's
    folders mirror the server manifest.

    Safety: only ever called after a SUCCESSFUL manifest fetch (see the guards in
    sync_rules/sync_wordlists), so a network/server error can't trigger a wipe.
    Dotfiles (e.g. .gitkeep / .gitignore) and subdirectories are always left
    alone, and each removal is isolated so one failure can't abort the pass.
    """
    if not os.path.isdir(directory):
        return
    removed = 0
    for name in os.listdir(directory):
        if name.startswith('.') or name in keep_filenames:
            continue
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            continue
        try:
            os.remove(path)
            removed += 1
            LOG.debug('Removed stale file not in manifest: %s', path)
        except OSError as err:
            LOG.warning('Could not remove stale file %s: %s', path, err)
    if removed:
        LOG.info('Pruned %d stale file(s) from %s.', removed, directory)


def sync_wordlists():
    """
    Synchronise local wordlist files with the server using JSON manifests.

    Wordlists are stored compressed (gzip) on the server and kept compressed
    here — hashcat reads gzip wordlists directly, so we DO NOT decompress them.

      - static  wordlists: the downloaded .gz is verified against the server
        checksum (which is the sha256 of the compressed file) and dropped on
        mismatch.
      - dynamic wordlists: NOT handled here. The server regenerates them from
        the DB on every download (into a per-request temp file), so they are
        fetched on demand per task by maybe_update_dynamic_wordlist (after the
        job is 'Running'). This loop, and the persistent manifest, track only
        static lists.
    """
    LOG.info('Syncing wordlists with server.')

    # Transition guard: older agents stored decompressed wordlists under their
    # plain (non-.gz) filename. If any manifest entry is from that era, reset
    # the manifest so everything is re-downloaded once as .gz. The orphaned
    # plaintext files are harmless (build_hashcat_command now references .gz).
    if any(not e.get('filename', '').endswith('.gz') for e in wordlists_manifest.data.values()):
        LOG.info('Detected a pre-gzip wordlist manifest; resetting for a one-time re-download.')
        wordlists_manifest.data = {}

    os.makedirs('control/wordlists', exist_ok=True)
    os.makedirs('control/tmp', exist_ok=True)

    # Guard the manifest fetch: on a network/server error api.getWordlists()
    # yields no parseable list. Bail out WITHOUT pruning so a transient failure
    # can never wipe the local wordlists.
    try:
        server_entries = api.getWordlists()
    except (TypeError, ValueError, KeyError) as err:
        LOG.warning('Could not fetch the wordlists manifest; skipping wordlist sync and cleanup: %s', err)
        return
    new_manifest = {}

    for entry in server_entries:
        wl_id = str(entry['id'])
        remote_checksum = entry['checksum']
        wl_type = entry.get('type')
        # Dynamic wordlists are fetched on demand per task by
        # maybe_update_dynamic_wordlist (the server regenerates them per
        # request), so this sync loop and the persistent manifest track only
        # static lists. Their transient files are pruned as orphans below and
        # re-fetched at task start, which is fine.
        if wl_type == 'dynamic':
            continue
        # Untrusted: the server's Wordlists.path only ever becomes a bare filename.
        base_filename = _safe_control_filename(entry['path'])
        if not base_filename:
            LOG.warning('Wordlist %s has an unusable path %r; skipping it.', wl_id, entry.get('path'))
            continue
        dest_filename = _gz_name(base_filename)

        local_entry = wordlists_manifest.data.get(wl_id)
        if local_entry and local_entry.get('checksum') == remote_checksum:
            # Up to date; keep as-is.
            new_manifest[wl_id] = local_entry
            continue

        LOG.info('Downloading wordlist %s.', wl_id)
        compressed = api.get_wordlists_file(entry['id'])
        if not compressed:
            LOG.warning('No data received for wordlist %s; keeping any existing copy.', wl_id)
            # Keep this entry so the still-valid local file isn't pruned as an orphan.
            if local_entry:
                new_manifest[wl_id] = local_entry
            continue

        tmp_gz = os.path.join('control/tmp', secrets.token_hex(8) + '.gz')
        with open(tmp_gz, 'wb') as f:
            f.write(compressed)

        # Static wordlists are served verbatim (stable bytes) so we can verify
        # the compressed file against the server checksum. Dynamic ones are
        # compressed on the fly server-side, so skip verification.
        if wl_type == 'static':
            local_checksum = _sha256_file(tmp_gz)
            if local_checksum != remote_checksum:
                LOG.warning('Checksum verification failed for wordlist %s (local=%s remote=%s); discarding.',
                            wl_id, local_checksum, remote_checksum)
                os.remove(tmp_gz)
                # Keep this entry so the still-valid local file isn't pruned as an orphan.
                if local_entry:
                    new_manifest[wl_id] = local_entry
                continue

        # Remove any previous file for this entry, then move the new .gz in.
        if local_entry and local_entry.get('filename'):
            old_path = os.path.join('control/wordlists', local_entry['filename'])
            if os.path.exists(old_path):
                os.remove(old_path)

        dest = os.path.join('control/wordlists', dest_filename)
        os.replace(tmp_gz, dest)
        new_manifest[wl_id] = {'checksum': remote_checksum, 'filename': dest_filename}

    if new_manifest != wordlists_manifest.data:
        wordlists_manifest.data = new_manifest
        wordlists_manifest.save()
        LOG.info('Wordlists manifest updated.')
    else:
        LOG.debug('Wordlists manifest unchanged.')

    # Sync complete: drop any local wordlist files no longer in the manifest. Skip
    # when the manifest is empty (e.g. a momentary empty server response) so we
    # never wipe the whole cache; a genuinely-empty server is cleaned up on the
    # next sync that returns at least one entry.
    if new_manifest:
        _prune_orphan_files('control/wordlists',
                            {e['filename'] for e in new_manifest.values() if e.get('filename')})

def jobTasks(job_task_id):
    return api.jobTasks(job_task_id)

def jobs(job_id):
    return api.jobs(job_id)

def tasks(task_id):
    return api.tasks(task_id)

def getWordlists():
    return api.getWordlists()

def download_hashfile(job_id, jobtask_id, hashfile_id):
    # Note we are not compressing our hashfile
    hashfile_content = api.get_hashfile(hashfile_id)
    if not hashfile_content:
        # A non-200 / missing hashfile yields None; writing that straight to disk
        # would raise. Report False so the caller skips launching hashcat against a
        # missing target rather than crashing the cycle.
        LOG.warning('No hashfile received for hashfile %s (job %s); skipping this task run.',
                    hashfile_id, job_id)
        return False
    with open('control/hashes/hashfile_' + str(job_id) + '_' + str(jobtask_id) + '.txt', 'wb') as hashfile:
        hashfile.write(hashfile_content)
    return True

def build_hashcat_argv(command):
    """Decode the server's stored command (a JSON argv list) into a real argv.

    Expands the @HASHCATBINPATH@ placeholder token into the operator-configured
    hashcat binary plus any host-specific HC_EXTRA_ARGS (e.g. '-d 3,4', split into
    its own tokens). Returns list[str] to run with shell=False — free-form task
    fields (mask, j/k rules) stay literal argv elements, never shell-parsed
    (issue #297).
    """
    from agent.bench import parse_hc_extra_args
    from agent.config import Config
    extra = parse_hc_extra_args(getattr(Config, 'HC_EXTRA_ARGS', ''))
    argv = []
    for token in json.loads(command):
        if token == '@HASHCATBINPATH@':  # nosec B105 - placeholder token, not a password
            argv.append(Config.HC_BIN_PATH)
            argv.extend(extra)
        else:
            argv.append(str(token))
    return argv

def run_hashcat(argv, output_file):
    """Run hashcat directly, no shell, so task fields can't inject shell commands
    (issue #297). hashcat's --status-json stream is redirected to output_file,
    which monitor_hashcat tails (replaces the old '<cmd> | tee <file>' pipe)."""
    try:
        with open(output_file, 'wb') as out:
            # nosec B603 - shell=False; argv[0] is the operator-set HC_BIN_PATH and
            # every other element is a server-built token passed literally to hashcat.
            proc = subprocess.Popen(argv, shell=False, stdout=out,  # nosec B603
                                    stderr=subprocess.PIPE)
            _output, error = proc.communicate()
        if error:
            LOG.error('Command stderr: %s', error.decode('utf-8', 'replace').strip())
            if 'hashfile is empty or corrupt' not in str(error):
                if 'Terminated' in str(error):
                    sys.exit()
                else:
                    api.sendError(str(error))
                    os.kill(os.getpid(), signal.SIGINT)
    except OSError as e:
        LOG.error('Command failed to execute: %s', e)
        api.sendError(str(e))
        os.kill(os.getpid(), signal.SIGINT)

BENCHMARK_TIMEOUT = 1200  # seconds, per hash mode


def run_benchmark(hash_modes):
    """Run `hashcat -b -m <mode>` for each requested mode and report H/s back.

    Triggered by a heartbeat reply of msg='BENCHMARK'. The server uses these
    per-(agent, hash type) speeds to size task chunks for the slowest agent.
    """
    from agent.bench import parse_benchmark_speed, parse_hc_extra_args
    from agent.config import Config
    # Apply host-specific args (e.g. '-d 3,4') to the benchmark too, so the
    # measured rate reflects the same devices that will run the crack.
    hc_args = parse_hc_extra_args(getattr(Config, 'HC_EXTRA_ARGS', ''))
    results = {}
    for mode in hash_modes or []:
        LOG.info('Benchmarking hash mode %s...', mode)
        try:
            # nosec B603 - fixed argv (no shell); binary is the operator-set
            # Config.HC_BIN_PATH and args are local config / numeric hash modes.
            proc = subprocess.run(  # nosec B603
                [Config.HC_BIN_PATH, *hc_args, '-b', '-m', str(mode)],
                capture_output=True,
                timeout=BENCHMARK_TIMEOUT)
        except Exception:
            LOG.exception('Benchmark failed for hash mode %s; skipping.', mode)
            continue
        output = ((proc.stdout or b'').decode('utf-8', 'replace')
                  + (proc.stderr or b'').decode('utf-8', 'replace'))
        speed = parse_benchmark_speed(output)
        if speed is None:
            LOG.warning('Could not parse a benchmark speed for hash mode %s.', mode)
            continue
        results[str(mode)] = speed
        LOG.info('Hash mode %s benchmark: %s H/s', mode, speed)
    if results:
        report_benchmark(results)


def report_benchmark(results):
    return api.report_benchmark(results)
    #os.system(cmd)


def killHashcat(pid):
    if sys.platform == 'win32':
        LOG.warning('Killing hashcat is not supported on Windows.')
    else:
        os.kill(int(pid), signal.SIGTERM)
        #p = psutil.Process(pid)
        #p.terminate()

#def uploadCrackFile(file_path, hash_type, task_id):
#    return api.uploadCrackFile(file_path, hash_type, task_id)
def uploadCrackFile(file_path, job_task_id):
    return api.uploadCrackFile(file_path, job_task_id)

def getHashType(hashfile_id):
    return api.getHashType(hashfile_id)

def updateJobTask(job_task_id, task_status):
    return api.updateJobTask(job_task_id, task_status)    

def data_retention_cleanup():
    """Remove temp / output / hash files older than the server's retention period."""
    try:
        server_settings = api.server_settings()
    except (KeyError, ValueError, TypeError):
        LOG.info('Data-retention cleanup skipped: server returned an unauthorized or '
                 'unexpected response (agent may not be approved yet).')
        return

    if not server_settings or 'retention_period' not in server_settings[0]:
        LOG.info('Data-retention cleanup skipped: no retention_period in server settings.')
        return

    retention_days = server_settings[0]['retention_period']
    if retention_days == 0:        # 0 means "keep forever"
        return

    cutoff = time.time() - retention_days * 86400
    for directory in ('control/tmp', 'control/outfiles', 'control/hashes'):
        for name in os.listdir(directory):
            if name == '.gitignore':
                continue
            path = os.path.join(directory, name)
            if os.stat(path).st_mtime < cutoff:
                os.remove(path)
                LOG.debug('Data-retention removed: %s', path)


# ---------------------------------------------------------------------------
# Main agent loop
# ---------------------------------------------------------------------------

HEARTBEAT_INTERVAL = 10        # seconds between idle/working heartbeats
STATUS_POLL_INTERVAL = 15      # seconds between hashcat status polls; matches the
                               # server-built crack command's --status-timer


def maybe_update_dynamic_wordlist(task):
    """If this task's wordlist is dynamic, fetch a fresh copy of it by id.

    The server regenerates a dynamic wordlist from the DB on every
    GET /v1/wordlists/<id> (into its own per-request temp file) and serves that,
    so there is no separate "update" call: we just download the task's list here.
    This runs after the JobTask is 'Running' (see run_assigned_task), so the
    server resolves the correct job for crawl-based lists. sync_wordlists() only
    handles static lists, so the manifest is scanned purely to learn this
    wordlist's type/path; the fetch itself is by id."""
    try:
        server_wordlists = getWordlists()
    except (TypeError, ValueError, KeyError) as err:
        LOG.warning('Could not fetch wordlists for the dynamic-update check; skipping it: %s', err)
        return
    for wordlist in server_wordlists:
        if wordlist['id'] == task['wl_id'] and wordlist['type'] == 'dynamic':
            LOG.debug('Task uses a dynamic wordlist; requesting it by id.')
            base_filename = _safe_control_filename(wordlist['path'])
            if not base_filename:
                LOG.warning('Dynamic wordlist %s has an unusable path %r; skipping it.',
                            wordlist['id'], wordlist.get('path'))
                return
            dest_filename = _gz_name(base_filename)
            compressed = api.get_wordlists_file(wordlist['id'])
            if not compressed:
                LOG.warning('No data received for dynamic wordlist %s; keeping any existing copy.',
                            wordlist['id'])
                return
            # Dynamic downloads are regenerated + gzipped on the fly server-side,
            # so their bytes are non-deterministic and are not checksum-verified
            # (mirrors the static-only sync path). Write to a temp file, then
            # atomically move it into place, overwriting any prior copy.
            os.makedirs('control/wordlists', exist_ok=True)
            os.makedirs('control/tmp', exist_ok=True)
            tmp_gz = os.path.join('control/tmp', secrets.token_hex(8) + '.gz')
            with open(tmp_gz, 'wb') as f:
                f.write(compressed)
            os.replace(tmp_gz, os.path.join('control/wordlists', dest_filename))
            LOG.info('Dynamic wordlist %s downloaded.', wordlist['id'])
            return


def upload_cracks(job, job_task):
    """Upload the hashcat crack file for this job task, if any cracks exist yet."""
    # Chunked tasks name temp files by JobTask id (to avoid collisions between
    # chunks of one task); whole tasks keep the legacy job+task id naming.
    file_key = job_task['id'] if job_task.get('chunk_total') else job_task['task_id']
    crack_file = 'control/outfiles/hc_cracked_' + str(job['id']) + '_' + str(file_key) + '.txt'
    if not os.path.exists(crack_file):
        LOG.debug('No results yet for job task %s; nothing to upload.', job_task['id'])
        return
    hash_type = getHashType(job['hashfile_id'])
    if not hash_type or hash_type.get('msg') != 'OK':
        LOG.warning('Could not confirm the hash type for job task %s; deferring crack upload.',
                    job_task['id'])
        return
    result = uploadCrackFile(crack_file, str(job_task['id']))
    if result and result.get('msg') == 'OK':
        LOG.info('Uploaded recovered hashes to the server.')


def monitor_hashcat(thread, job, job_task):
    """While hashcat runs: heartbeat status to the server, honour cancels, and
    stream recovered hashes up as they appear."""
    output_file = 'control/outfiles/hcoutput_' + str(job['id']) + '_' + str(job_task['id']) + '.txt'
    while thread.is_alive():
        time.sleep(STATUS_POLL_INTERVAL)
        hc_status = hashcatParser(output_file)
        if hc_status:
            LOG.info('hashcat running — recovered %s, %s, eta %s',
                     hc_status.get('Recovered', '?'),
                     hc_status.get('Speed #', '?'),
                     hc_status.get('Time_Estimated', '?'))
        # A transient server outage (e.g. a restart) raised here must NOT kill the
        # monitor loop -- that would orphan the still-running hashcat (no status,
        # no final upload, task never Completed). Log and retry on the next poll;
        # the HTTP layer already retries through brief outages, this catches the
        # rest. We keep looping as long as hashcat is alive.
        try:
            if send_heartbeat('Working', hc_status)['msg'] == 'Canceled':
                LOG.info('Server canceled this task; stopping hashcat.')
                pid = getHashcatPid()
                if pid:
                    killHashcat(pid)
            upload_cracks(job, job_task)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            LOG.exception('Status report/upload failed this poll; retrying next cycle.')


def run_assigned_task(job_task_id):
    """Run a single task the server has assigned to this agent."""
    LOG.info('Assigned job task %s.', job_task_id)

    # Make sure our local rules + wordlists match the server before running.
    sync_rules()
    sync_wordlists()

    # Any of these fetches can return None (server mid-restart, missing row,
    # unexpected body). Bail with a clear message instead of crashing on a None
    # subscript; the server keeps the task assigned and its runtime reaper (or a
    # later reassignment) recovers it. We deliberately do NOT reset the status
    # here -- a persistent failure (e.g. a genuinely missing hashfile) would then
    # re-dispatch in a hot loop.
    job_task = jobTasks(job_task_id)
    if not job_task:
        LOG.warning('Could not fetch job task %s; skipping this run.', job_task_id)
        return
    task = tasks(job_task['task_id'])
    job = jobs(job_task['job_id'])
    if not task or not job:
        LOG.warning('Could not fetch the task/job for job task %s; skipping this run.', job_task_id)
        return

    # Defensive: the server occasionally misses flipping this to Running.
    updateJobTask(job_task['id'], 'Running')
    maybe_update_dynamic_wordlist(task)

    # Name the hashfile to match the server-built command's target file: chunks
    # are keyed by JobTask id (so chunks of one task never collide); whole tasks
    # keep the legacy job+task id naming so existing agents stay compatible.
    file_key = job_task['id'] if job_task.get('chunk_total') else job_task['task_id']
    if not download_hashfile(job['id'], file_key, job['hashfile_id']):
        return

    output_file = ('control/outfiles/hcoutput_'
                   + str(job['id']) + '_' + str(job_task['id']) + '.txt')
    argv = build_hashcat_argv(job_task['command'])
    argv.append('--status-json')      # hashcat writes status JSON to stdout -> output_file
    LOG.debug('hashcat argv: %s', argv)

    LOG.info('Running hashcat for job task %s...', job_task['id'])
    thread = Thread(target=run_hashcat, args=(argv, output_file))
    thread.start()
    monitor_hashcat(thread, job, job_task)
    LOG.info('hashcat completed for job task %s; uploading final results.', job_task['id'])

    upload_cracks(job, job_task)

    completed = updateJobTask(job_task['id'], 'Completed')
    if completed and completed.get('msg') == 'OK':
        LOG.info('Job task %s set to Completed.', job_task['id'])


def handle_heartbeat():
    """One heartbeat cycle: report this agent's status and act on the reply."""
    if getHashcatPid():
        # A hashcat run is already in flight (e.g. it outlived an agent restart).
        # We're not monitoring that process here, so we have no hc_status to report
        # -- send an empty one (the server skips the telemetry parse for a blank
        # value) rather than a placeholder it would fail to JSON-decode.
        response = send_heartbeat('Working', '')
        if response and response.get('msg') == 'Canceled':
            LOG.info('Server canceled the running task.')
        return

    response = send_heartbeat('Idle', '')
    if not response:
        # No usable reply this beat (server mid-restart / non-200); retry next cycle.
        return
    if response.get('msg') == 'Go Away':
        LOG.warning('This agent is not authorized on the server. Ask a Hashview admin to approve it.')
    elif response.get('msg') == 'BENCHMARK':
        run_benchmark(response.get('hash_modes', []))
    elif response.get('msg') == 'START':
        run_assigned_task(response.get('job_task_id'))


def main():
    from agent import config  # noqa: F401 - imported for its config side effects
    builtins.state = 'debug' if args.debug else 'normal'
    LOG.info('Hashview agent started (polling every %ss).', HEARTBEAT_INTERVAL)

    while True:
        try:
            data_retention_cleanup()
            handle_heartbeat()
        except (KeyboardInterrupt, SystemExit):
            raise                        # let hashcat's SIGINT / explicit exits stop the agent
        except Exception:
            # A single bad cycle (network blip, malformed response, transient I/O)
            # must never take the agent down -- log it and try again next cycle.
            LOG.exception('Unhandled error during agent cycle; continuing.')
        time.sleep(HEARTBEAT_INTERVAL)


if __name__ == '__main__':
    main()
