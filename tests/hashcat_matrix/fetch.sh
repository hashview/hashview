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
curl -fsSL --retry 3 --retry-delay 5 -o "${archive}" "${url}"
echo "${sha256}  ${archive}" | sha256sum -c - >&2
7z x -y -o"${destdir}" "${archive}" >/dev/null

unpacked="${destdir}/hashcat-${version}"
test -x "${unpacked}/hashcat.bin" || {
  echo "fetch.sh: ${unpacked}/hashcat.bin missing or not executable" >&2
  exit 1
}
echo "${unpacked}"
