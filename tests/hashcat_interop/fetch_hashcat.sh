#!/usr/bin/env bash
# Download, verify, and unpack one hashcat release.
#
#   fetch_hashcat.sh <version> <sha256> <destdir>
#
# Prints the unpacked directory on stdout. A checksum mismatch is a hard
# failure: a corrupted download must never be mistaken for an interop break.
set -euo pipefail

version="${1:?usage: fetch_hashcat.sh <version> <sha256> <destdir>}"
sha256="${2:?missing expected sha256}"
destdir="${3:?missing destination directory}"

archive="${destdir}/hashcat-${version}.7z"
url="https://github.com/hashcat/hashcat/releases/download/v${version}/hashcat-${version}.7z"

mkdir -p "${destdir}"
# Same budget, and the same reason, as tests/hashcat_matrix/fetch.sh: --retry 3
# --retry-delay 5 gives up after ~15s, which is shorter than a routine GitHub
# release-CDN hiccup -- four consecutive 504s on one artifact failed a matrix job
# before any test ran. Dropping --retry-delay restores curl's exponential backoff
# (1s, 2s, 4s ...), --retry-max-time bounds the whole retry window so a dead
# mirror still fails rather than hanging the job, and --retry-all-errors covers
# what a CDN edge returns mid-outage. The sha256 check below is unaffected: a
# retried download is verified exactly like a first-attempt one.
curl -fsSL --retry 6 --retry-max-time 300 --retry-all-errors \
     --connect-timeout 20 -o "${archive}" "${url}"
echo "${sha256}  ${archive}" | sha256sum -c - >&2
7z x -y -o"${destdir}" "${archive}" >/dev/null

unpacked="${destdir}/hashcat-${version}"
test -x "${unpacked}/hashcat.bin" || {
  echo "fetch_hashcat.sh: ${unpacked}/hashcat.bin missing or not executable" >&2
  exit 1
}
echo "${unpacked}"
