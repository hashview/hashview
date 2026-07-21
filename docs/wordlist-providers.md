# Wordlist Providers

A **wordlist provider** is an external HTTP service that generates a wordlist on
demand. An administrator registers a provider under **Settings → Wordlist
providers** (base URL + credentials); doing so creates a `(DYNAMIC)` wordlist that
appears in the job-creation wizard alongside `(DYNAMIC) Website Keywords`.

The interaction is modeled on the built-in website-keywords crawler: when a job
uses a provider-backed wordlist, the operator supplies a free-form **input** during
job creation. At crack time Hashview submits that input to the provider, receives a
generated wordlist, and materializes it to disk. **Agents never contact the
provider** — they download the materialized file from Hashview exactly like any
other dynamic wordlist.

Hashview dictates the API. To integrate, implement the two endpoints below.

## Endpoints

Both are relative to the provider's configured **base URL** (e.g. a base URL of
`https://api.example.com/hv` means the health endpoint is
`https://api.example.com/hv/health`).

### `GET {base_url}/health`

Powers the **Test connection** button in Settings. The configured auth header is
attached, so this also validates credentials.

- **Success:** HTTP `200` with a JSON body `{"status": "ok"}`. Optional `name` and
  `description` fields are surfaced in the UI.
- **Failure:** any non-`200`, a timeout, or a TLS error is reported as "test
  failed" with the reason.

Timeout: connect 5s / read 15s.

### `POST {base_url}/generate`

Generates the wordlist for a given input.

- **Request body:** `application/json` — `{"input": "<operator-supplied text>"}`.
  The input is arbitrary text (a target domain, company name, keyword set, …); the
  provider decides how to interpret it.
- **Success response:** HTTP `200` with the wordlist as the body — newline-delimited
  UTF-8 text (`text/plain`), one candidate per line. The response **should be
  streamed / chunked**; Hashview streams it straight to disk.
- **Failure:** any non-`200` is treated as a failure. Hashview logs a warning and
  **leaves the existing wordlist file unchanged** (it never errors the crack).

Timeout: connect 5s / read 300s (generation may be slow). Hashview caps a single
materialized wordlist at 2 GiB and discards anything larger.

## Authentication

Configured per provider:

| `auth_type` | Header / mechanism Hashview sends |
|-------------|-----------------------------------|
| `bearer`    | `Authorization: Bearer <secret>`  |
| `basic`     | HTTP Basic — `Authorization: Basic base64(username:secret)` |

Hashview also sends `User-Agent: Hashview/<version>`, and `Content-Type:
application/json` on the generate call.

## Reference implementation (Flask)

A minimal provider that echoes a themed list for the given input:

```python
from flask import Flask, request, Response, jsonify

app = Flask(__name__)
TOKEN = "change-me"

def _authorized():
    return request.headers.get("Authorization") == f"Bearer {TOKEN}"

@app.get("/health")
def health():
    if not _authorized():
        return jsonify(status="unauthorized"), 401
    return jsonify(status="ok", name="Example Provider")

@app.post("/generate")
def generate():
    if not _authorized():
        return jsonify(status="unauthorized"), 401
    seed = (request.get_json(silent=True) or {}).get("input", "")

    def stream():
        for suffix in ("", "123", "!", "2024", "2025"):
            yield f"{seed}{suffix}\n"

    return Response(stream(), mimetype="text/plain")
```

## Security notes

- **Credentials are stored plaintext at rest** in the `wordlist_providers` table.
  This is an intentional, conscious choice that matches Hashview's existing
  convention for the Azure client secret and Slack bot token: the value is a
  write-only form field (never rendered back to the page) and is excluded from API
  serialization (`api.routes._ENCODER_DENYLIST`). It is not encrypted with a KMS or
  app key — treat DB access as equivalent to credential access.
- **Server-side requests.** Only administrators can register providers. Hashview
  validates that a base URL is `http`/`https` (blocking `file://`, `gopher://`,
  etc.), but it does **not** block internal/link-local targets — an administrator
  may legitimately run a provider on internal infrastructure. This is an accepted
  SSRF residual risk given the admin-only trust boundary.
- Set **Verify TLS** off only for a provider presenting a self-signed certificate
  on a trusted network.

## Limitations

- A job carries a **single** `provider_input`. If one job uses two different
  provider-backed wordlists, they share the same input. Give each provider-backed
  wordlist its own job if it needs a distinct input.
- Provider-backed wordlists are treated as dynamic: they are stored uncompressed,
  refreshed per job, and are **never chunked** across agents.
