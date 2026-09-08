## Summary

<!-- What does this PR do, and why? Link the issue it addresses. -->

Closes #

## Checklist

- [ ] This PR targets `v0.8.3-dev` (the current dev branch), **not** `main`
- [ ] Commit subjects follow `type(scope): subject` (see [CONTRIBUTING.md](../CONTRIBUTING.md#commit-messages))
- [ ] `scripts/preflight.sh` passes locally
- [ ] Pushed through the pre-push hook (not `--no-verify`)
- [ ] New/changed behavior has test coverage
- [ ] If a route changed: `hashview/api_docs/openapi.yaml` is updated
- [ ] If a migration was added: it's MySQL/MariaDB-safe, and `DEV_HEAD` in
      `tests/run_migration_e2e.sh` is bumped
- [ ] If user-visible: `CHANGELOG.md` has an entry under `## Current Release`
- [ ] N/A items above are just left unchecked, not deleted

## Testing

<!-- How did you verify this? Commands run, suites exercised. -->
