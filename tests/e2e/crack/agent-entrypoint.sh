#!/usr/bin/env sh
# Non-interactive agent bootstrap for the e2e crack test: write agent/config.conf
# from env vars (bypassing hashview-agent.py's interactive first-run setup), then
# run the real agent. CWD is /agent (WORKDIR), where VERSION.TXT + agent/ live.
set -e

mkdir -p agent control/tmp control/hashes control/outfiles control/wordlists control/rules

cat > agent/config.conf <<EOF
[HASHVIEW]
server = ${HASHVIEW_SERVER}
port = ${HASHVIEW_PORT}
use_ssl = ${USE_SSL:-False}

[AGENT]
name = ${NAME}
uuid = ${UUID}
HC_BIN_PATH = ${HC_BIN_PATH}
EOF

exec python hashview-agent.py
