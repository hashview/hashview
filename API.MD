# Hashview API

The full, authoritative reference for the Hashview `/v1` API is now an
**OpenAPI 3.0.3** specification rather than this prose document, so it can be
browsed interactively, used with tooling (Swagger/Postman/codegen), and kept
in lock-step with the code.

- **Interactive docs (Swagger UI):** log in to the Hashview web UI and open
  **API Docs** in the sidebar, or go to **`/api/docs`**. From there you can
  read every endpoint and use *Try it out* (click *Authorize try-it-out* to
  send your API key).
- **Raw spec:** [`hashview/api_docs/openapi.yaml`](hashview/api_docs/openapi.yaml),
  also served at `/api/docs/openapi.yaml`.

The spec is kept honest by `tests/unit/test_openapi_spec.py`, which fails the
build if any `/v1` route drifts from the document, and is structurally
validated in CI and via pre-commit (`openapi-spec-validator`).

## Authentication

All `/v1` endpoints authenticate with a single cookie named `uuid`:

1. **User** — `uuid` set to your user API key (generate one under account
   settings / *Generate API Key*).
2. **Agent** — `uuid` set to a registered agent's UUID.

```bash
Cookie: uuid=<your-api-key-or-agent-uuid>
```

Each endpoint accepts a user credential, an agent credential, or either — the
`security` requirement shown per operation in the spec tells you which. On an
auth failure the server issues an HTTP 302 to `/v1/not_authorized`.

## A note on responses

Most endpoints answer **HTTP 200** and report the real outcome in the response
body's `status` field (200/400/403/426/500); a few newer endpoints also use
genuine HTTP status codes (e.g. 404 on `DELETE /v1/jobs/{job_id}`). The list
and detail endpoints now return ORM rows as **native JSON**, so a client no
longer has to parse the response body a second time. The exact response shape
of every endpoint is documented in the OpenAPI spec.
