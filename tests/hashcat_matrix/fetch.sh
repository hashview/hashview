#!/usr/bin/env bash
# Download, verify, and unpack one hashcat release.
#
#   fetch.sh <version> <sha256> <destdir>
#
# Prints the unpacked directory on stdout. A checksum mismatch is a hard
# failure: a corrupted download must never be mistaken for an interop break.
set -euo pipefail

version="${1:?usage: fetch.sh <version> <sha256> <destdir>}"
sha256="${2:?missing expected sha256}"
destdir="${3:?missing destination directory}"

archive="${destdir}/hashcat-${version}.7z"
url="https://github.com/hashcat/hashcat/releases/download/v${version}/hashcat-${version}.7z"

mkdir -p "${destdir}"
# --retry 3 --retry-delay 5 gave up after ~15s, which is shorter than a routine
# GitHub release-CDN hiccup: one leg of the matrix took four consecutive 504s on
# this artifact while the other four versions downloaded fine, failing the job
# before a single test ran. Dropping --retry-delay restores curl's exponential
# backoff (1s, 2s, 4s ... ), and --retry-max-time caps the whole retry window so
# a genuinely dead mirror still fails in bounded time rather than hanging the
# job. --retry-all-errors covers the non-transient-looking failures a CDN edge
# can return mid-outage; the sha256 check below is what keeps a bad download
# from ever being mistaken for a good one, retried or not.
curl -fsSL --retry 6 --retry-max-time 300 --retry-all-errors \
     --connect-timeout 20 -o "${archive}" "${url}"
echo "${sha256}  ${archive}" | sha256sum -c - >&2
7z x -y -o"${destdir}" "${archive}" >/dev/null

unpacked="${destdir}/hashcat-${version}"
test -x "${unpacked}/hashcat.bin" || {
  echo "fetch.sh: ${unpacked}/hashcat.bin missing or not executable" >&2
  exit 1
}
echo "${unpacked}"
