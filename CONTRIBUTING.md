# Contributing to Pocket Nutrition Vault

Thanks for your interest in improving the vault. It is a small, single-purpose FastAPI service, so the
contribution process is intentionally lightweight. Its one design rule is that the server stores what it
cannot read: see "Ground rules" below before you propose a feature.

## Development setup

```bash
git clone https://github.com/pocket-nutrition/vault.git
cd vault
./setup.sh                       # creates .venv, installs requirements-dev.txt, copies .env.example → .env
source .venv/bin/activate        # Windows: .venv\Scripts\activate
```

Or set up manually:

```bash
python3.12 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements-dev.txt

cp .env.example .env             # optional — only Docker reads it; the defaults work for local development
```

Python 3.12 is required: the pinned pydantic-core does not build on 3.14.

Run the server:

```bash
VAULT_ADMIN_TOKEN=dev uvicorn app.main:build --factory --reload
```

It listens on <http://localhost:8000>. Without `VAULT_DATABASE_URL` it keeps its data in a SQLite file,
`vault.db`, in the current directory (git-ignored); the schema is created and migrated at startup. The server
does not read `.env` itself: export `VAULT_*` variables to change a setting (every one is listed in
[.env.example](.env.example)). Create an owner account, whose API key is shown once, with:

```bash
curl -X POST localhost:8000/admin/accounts -H 'Authorization: Bearer dev'
```

## Running tests

```bash
pytest
```

The suite runs on in-memory SQLite and needs no other service. Run it from the repository root, in a shell
without exported `VAULT_*` variables: they override the defaults the tests build on (`VAULT_REGISTRATION=closed`
alone fails dozens of tests). A `.env` file is not read.

The suite covers SQLite only. SQLite has no row locks and returns naive datetimes, so for a change to queries,
locking or datetimes, also run the server against PostgreSQL (see the [README](README.md)).

There is no linter or code coverage gate configured in this repository — keep changes consistent with the
surrounding style (type hints on function signatures, English identifiers and comments, lines of about 120
characters or less).

## Ground rules

The vault is end-to-end encrypted by design. Pull requests that break these rules will not be merged:

- **The server never decrypts, parses or logs record contents, and never receives a key.** No server-side
  search, no validation of plaintext, no "recovery" path. If a feature needs the server to read user data, it
  does not belong in this repository.
- **API keys are authentication only.** Never derive an encryption key from one.

The protocol and its threat model are in [docs/PROTOCOL.md](docs/PROTOCOL.md); read it before touching
authentication, keys, records, grants or drops.

## Test-first expectations

For any change to the server's behavior:

1. Add or update a test in `tests/` that captures the behavior you're adding or fixing.
2. Confirm the test fails without your change and passes with it.
3. Run the full suite (`pytest`) before opening a pull request — it must pass.

Pull requests that change behavior without an accompanying test will be asked to add one.

## Database changes

The schema is migrated at startup with Alembic (`app/migrations/`). Every change to `app/models.py` needs a new
migration in `app/migrations/versions/`:

- Write it by hand (there is no `alembic.ini`), number it after the latest one and chain it with
  `down_revision`, as the existing files do.
- For column changes use `op.batch_alter_table`, so the migration also runs on SQLite, which the tests use.
- Migrations are forward-only: `downgrade()` raises `NotImplementedError`, like the existing ones.

`tests/test_migrations.py::test_migrations_match_the_models` fails when the models and the migrations drift apart.

## Protocol changes

`docs/PROTOCOL.md` is the contract that every client and external reader implements, and
`docs/test-vectors.json` holds the known answers they must reproduce byte for byte. **Any change to the
protocol updates `docs/PROTOCOL.md` and regenerates `docs/test-vectors.json` with `scripts/gen_vectors.py`:**

```bash
pip install pynacl                                    # only the generator needs it, the tests do not
python scripts/gen_vectors.py > docs/test-vectors.json
git diff docs/test-vectors.json                       # review what changed
```

The sealed box in the vectors is random by design, so `sealed_b64` changes on every run (the script's docstring
says it is "fixed once and committed"). Say in your pull request which vectors changed and why: the apps and
readers that implement the protocol have to follow.

## Branch and PR workflow

1. Fork the repository and create a feature branch off `main`.
2. Make focused commits with clear messages (e.g. `fix: reject a keyring over the size limit`).
3. Ensure `pytest` passes locally.
4. Open a pull request against `main` and fill in the template: what changed, why, and how you checked it.
   For behavioral changes, say which test covers it.
5. Be responsive to review feedback — small, focused PRs are easier to review and merge.

## Reporting issues

Please open a GitHub issue with the bug report or feature request template. For a bug, include the endpoint,
the HTTP status and the JSON error body you got, and how you ran the server (version, database, reverse
proxy). Remove API keys, admin tokens, auth hashes, keyrings and ciphertexts first: never post a secret.

**Do not report a security problem in a public issue.** Use "Report a vulnerability" on the repository's
Security tab, as described in [SECURITY.md](SECURITY.md).

## CI and releases

- Every pull request runs `.github/workflows/ci.yml`: the tests on Python 3.12 and a check that the Docker
  image builds. The `ci-success` check must be green before a pull request can be merged, the branch must be
  up to date with `main`, and pull requests are squash-merged so history stays linear.
- If you contribute from a fork, the workflow waits for a maintainer to approve it. It runs with a
  read-only token and no secrets.
- Every commit merged to `main` is released automatically with a CalVer version, `vYYYY.M.N`: the year, the
  month, then a counter that restarts at 1 each month (for example `v2026.11.1`). You never pick a version
  number or edit a changelog; release notes are generated from the merged pull requests.
- A release publishes the container image `ghcr.io/pocket-nutrition/vault`.

## Using Claude Code

The repository includes a [CLAUDE.md](CLAUDE.md) with the architecture, the commands and the rules above, so
`claude` started in the repository root has the context it needs. The same expectations apply to changes it
writes: tests for behavior, a migration for the schema, and an updated protocol document and test vectors for
the protocol.
