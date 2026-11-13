---
name: Bug report
about: Report incorrect behavior of the vault server
title: "[Bug] "
labels: bug
assignees: ''
---

> **Security problem?** Do not open a public issue. Report it privately, as described in the
> [security policy](https://github.com/pocket-nutrition/vault/security/policy).

## Describe the bug

A clear and concise description of what is wrong.

## Request and response

The endpoint you called, the HTTP status you got and the JSON error body (for example
`409` with `{"detail": {"error": "revision_conflict", "current_revision": 3}}`).

**Remove API keys, admin tokens, auth hashes, keyrings and ciphertexts before pasting.** Never post a secret.

```http
PUT /v1/records/<id>
```

```json
```

## Expected behavior

What you expected instead, and why (link the relevant section of `docs/PROTOCOL.md` if there is one).

## Environment

- Version: the image tag (for example `2026.11.1`) or `git rev-parse HEAD`
- How you ran it: `uvicorn` locally / Docker image / behind a reverse proxy (which one)
- Python version, if you ran it from source: `python --version`
- Database: PostgreSQL (which version) or SQLite
- `VAULT_*` settings you changed (names and values, never the secrets)

## Additional context

Logs and stack traces. Check them for usernames, IP addresses and tokens before pasting.
