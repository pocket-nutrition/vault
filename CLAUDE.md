# CLAUDE.md

E2EE sync store (FastAPI + SQLAlchemy). Protocol and threat model: `docs/PROTOCOL.md`.

**Port:** 8000 | **Stack:** Python 3.12, FastAPI, SQLAlchemy, Alembic, Argon2, PostgreSQL (SQLite for dev and tests)

## Rules

- **The server must never decrypt, parse, or log record contents, and must never receive a key.**
  Do not add server-side search, validation of plaintext, or a "recovery" path. If a feature needs
  the server to read user data, it does not belong here.
- API keys are authentication only. Never derive an encryption key from one.
- A protocol change updates `docs/PROTOCOL.md` and regenerates `docs/test-vectors.json` with `scripts/gen_vectors.py`.
- A change to `app/models.py` needs an Alembic migration (a test enforces it); a change in behavior needs a test.
- Standalone repo, own database. Not part of the nutrition data pipeline (the `knowledge`, `data`, `ingest`, `ml` and `api` repositories).
- Config is env-driven (`VAULT_*`: see `app/config.py`, and `.env.example` for every setting). The server does not load a `.env` file itself.
- Run a single instance: the rate limiter is in memory and migrations run at startup.
- Code, comments, commit messages and docs are in English.

## Commands

```bash
./setup.sh                      # first-time setup: .venv (python3.12), requirements-dev.txt, .env from .env.example
VAULT_ADMIN_TOKEN=dev .venv/bin/uvicorn app.main:build --factory --reload   # http://localhost:8000, SQLite in ./vault.db
curl -X POST localhost:8000/admin/accounts -H 'Authorization: Bearer dev'   # owner API key, shown once
.venv/bin/pytest                # Python 3.12 (the pinned pydantic-core does not build on 3.14)
docker build -t vault .         # port 8000, non-root user; needs VAULT_DATABASE_URL (PostgreSQL) at run time
```

Tests run on in-memory SQLite, from the repository root, with no `VAULT_*` variable exported (they override the
defaults the tests build on, and `VAULT_REGISTRATION=closed` alone fails dozens of tests); a `.env` file is not read.
SQLite does not exercise row locks or timezone-aware datetimes, so for such changes also run the server against
PostgreSQL (README, "Running the container image"). No linter or coverage gate is configured.

Test vectors, for protocol changes only. The generator needs PyNaCl (the tests do not), and the sealed box is random,
so `sealed_b64` changes on every run:

```bash
.venv/bin/pip install pynacl
.venv/bin/python scripts/gen_vectors.py > docs/test-vectors.json
```

## Architecture

```
app/
  main.py        # create_app() / build(): settings, migrations at startup, middleware, /healthz, apple-app-site-association
  config.py      # Settings: every VAULT_* variable and its default
  db.py          # engine, run_migrations() (Alembic at startup; advisory lock on PostgreSQL)
  models.py      # SQLAlchemy models: Account, ApiKey, Grant, Drop, Record
  schemas.py     # Pydantic request/response models and input limits
  security.py    # API key auth (SHA-256 of pnv_ keys), Principal roles: owner / reader / dropper
  accounts.py    # server-info, prelogin, register, login, logout, delete, passphrase change/reset, two-factor
  routes.py      # admin, me, keyring, records, sync, drops, grants, keys
  totp.py        # TOTP (RFC 6238) and recovery codes
  ratelimit.py   # in-memory rate limiter, unknown-login guard, client_ip() (X-Forwarded-For)
  bodylimit.py   # request body size cap (ASGI middleware)
  migrations/    # Alembic env + versions/0001..0004, hand-written and forward-only
docs/            # PROTOCOL.md (the contract clients implement), test-vectors.json (known crypto answers)
scripts/         # gen_vectors.py
tests/           # pytest suite; fixtures `client` and `owner` in conftest.py
```

Clients (the apps, external readers, drop holders) send `Authorization: Bearer <API key>`. `get_principal` turns the key
into a role, and routes demand one with `require_owner` / `require_dropper`. Records are opaque base64 ciphertext with a
per-account `seq` that doubles as the sync cursor. Login uses an auth hash the client derives from the passphrase: the
server stores only an Argon2id digest of it, plus the keyring blob, which it never parses.

## Migrations

Hand-written (there is no `alembic.ini`): next number in `app/migrations/versions/`, chained with `down_revision`,
`op.batch_alter_table` for column changes so SQLite works too, and `downgrade()` raising `NotImplementedError`.
`tests/test_migrations.py` fails when models and migrations drift apart.

## Container

`Dockerfile`: `python:3.12-slim`, uid 10001, `uvicorn app.main:build --factory` on port 8000, published as
`ghcr.io/pocket-nutrition/vault`. The image only needs `requirements.txt` and `app/`, so `.dockerignore` keeps `tests/`
and local files out of the build context. In a container set `VAULT_DATABASE_URL`: the SQLite default is not writable
by the non-root user, and `localhost` in the URL means the container itself. Behind a reverse proxy the proxy must
overwrite `X-Forwarded-For` and `VAULT_TRUSTED_PROXY_HOPS` must match (README).

## CI and contributing

`.github/workflows/ci.yml`: tests on Python 3.12, an image build check on pull requests, the `ci-success` aggregate
check, and on `main` a CalVer release (`vYYYY.M.N`) that pushes the image to GHCR. See [CONTRIBUTING.md](CONTRIBUTING.md).
Vulnerabilities are reported privately, never in a public issue: [SECURITY.md](SECURITY.md).
