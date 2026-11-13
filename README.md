# Pocket Nutrition Vault

End-to-end encrypted sync server for the Pocket Nutrition meal journal: it stores what your phone encrypts, never the keys.

The vault is a small FastAPI service backed by PostgreSQL. The apps encrypt the journal on the phone and sync the
ciphertext through the vault, Bitwarden-style: devices and explicitly granted external readers hold the keys, the
server holds ciphertext only. It is standalone and self-hostable (the apps take a server URL and an API key). It is
**not** part of the nutrition data pipeline and shares no database with the other services.

- Public endpoint, and the apps' default server: <https://vault.pocketnutrition.org> (an API, there is no web page)
- Protocol and threat model: [docs/PROTOCOL.md](docs/PROTOCOL.md)
- Crypto test vectors for client authors: [docs/test-vectors.json](docs/test-vectors.json), generated from fixed
  test inputs by [scripts/gen_vectors.py](scripts/gen_vectors.py) (needs PyNaCl)
- Docs: [running the vault](https://website.pocketnutrition.org/docs/self-hosting/run-the-platform#vault) and the
  [architecture overview](https://website.pocketnutrition.org/docs/architecture/overview)

## What it does, and what it never sees

The vault stores each user's journal as opaque records and syncs them between that user's devices. It also keeps:

- the **keyring** the apps build (the user key, wrapped by the passphrase and by the recovery key), an Argon2id
  digest of the auth hash the device derives from the passphrase, and one API key per device;
- **grants**, which give an external reader access to one scope of records, and **drops**: short-lived, write-only
  slots where a service such as the recognition worker deposits a result sealed for the phone. A drop token can only
  deposit: it cannot sync, read or list anything, not even what it just wrote, and it expires.

It never sees:

- **Keys.** Not the passphrase, the recovery key, the user key or a scope key. API keys only authenticate: no
  encryption key is ever derived from one.
- **Plaintext.** Everything the apps store is encrypted on the device before it is sent. By design the server does not
  decrypt, parse or log record contents, and it has no server-side search, plaintext validation or recovery path.

It does see metadata: record count and sizes, `type`, `scope_id`, `key_id`, revisions, timestamps, and which API key
reads what ([details](docs/PROTOCOL.md#what-the-server-can-see)). There is no email reset: losing both the passphrase
and the recovery key loses the data.

## Prerequisites

- Python 3.12 (matches the `python:3.12-slim` base image in the [Dockerfile](Dockerfile); the pinned pydantic-core does
  not build on 3.14)
- `pip`
- Docker and PostgreSQL to run the container image

## Quick start

For local development. Without `VAULT_DATABASE_URL` the server keeps its data in a SQLite file (`./vault.db`,
git-ignored), and creates and migrates the schema at startup.

```bash
./setup.sh                      # creates .venv, installs requirements-dev.txt, copies .env.example to .env
VAULT_ADMIN_TOKEN=dev .venv/bin/uvicorn app.main:build --factory --reload
```

In a second terminal:

```bash
curl localhost:8000/healthz                                                 # {"status":"ok"}
curl -X POST localhost:8000/admin/accounts -H 'Authorization: Bearer dev'   # returns the owner API key once
curl localhost:8000/v1/me -H 'Authorization: Bearer <that API key>'         # validates the URL and key, as the apps do
.venv/bin/pytest                                                            # runs the tests
```

Or set up by hand: `python3.12 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt`. Interactive API
docs are served at <http://localhost:8000/docs>. The server does not read `.env` itself (see
[Configuration](#configuration)).

## Running the container image

Container image: `ghcr.io/pocket-nutrition/vault` (built from the [Dockerfile](Dockerfile); listens on port 8000 and
runs as a non-root user). Run **one instance** (the rate limiter is in memory and migrations run at startup) with a
PostgreSQL database, behind a TLS-terminating reverse proxy, and configure it with the `VAULT_*` variables from
[.env.example](.env.example). The server does not load a `.env` file itself: export the variables, or pass the file to
Docker with `--env-file`.

```bash
# PostgreSQL on a Docker network, so the vault can reach it by name
DB_PASSWORD=$(openssl rand -hex 16)
docker network create vault-net
docker run -d --name vault-db --network vault-net -v vault-db-data:/var/lib/postgresql/data \
  -e POSTGRES_USER=vault -e POSTGRES_PASSWORD="$DB_PASSWORD" -e POSTGRES_DB=vault postgres:16

# Configuration: copy the template, then set these three values (openssl rand -hex 32 makes a good secret)
cp .env.example .env
#   VAULT_DATABASE_URL=postgresql://vault:<the DB_PASSWORD above>@vault-db:5432/vault
#   VAULT_ADMIN_TOKEN=<secret>
#   VAULT_PRELOGIN_SECRET=<another secret>

# The vault, published on the loopback address for your reverse proxy
docker run -d --name vault --network vault-net -p 127.0.0.1:8000:8000 --env-file .env ghcr.io/pocket-nutrition/vault
curl localhost:8000/healthz   # {"status":"ok"}
```

Two traps when you adapt this:

- **Set `VAULT_DATABASE_URL`.** The built-in SQLite default is a file in the working directory, `/app`, which the
  non-root container user cannot write: the container exits at startup with `unable to open database file`.
- **`localhost` in the database URL means the container itself**, not your machine, so the `localhost` in
  `.env.example` has to change. Use the name of the database container on a shared Docker network, as above, or a host
  the container can reach (on Docker Desktop, `host.docker.internal`; on Linux, add
  `--add-host=host.docker.internal:host-gateway` to the `docker run`).

Registration is open by default, so anyone who can reach the server can create an account. Once your own accounts
exist, set `VAULT_REGISTRATION=closed` and restart: new accounts then come only from `POST /admin/accounts`. The vault
cannot read the journals it stores, but losing its database loses them, so back up the PostgreSQL database.

### Behind a reverse proxy

The per-IP rate limits (registration, login and passphrase requests, two-factor settings) use the client address from
the `X-Forwarded-For` header, so the proxy and the vault have to agree on how that header is built:

- **The proxy facing the clients must overwrite `X-Forwarded-For` with the address the client connected from**, not
  append to a header the client sent. A proxy that appends to the header, or passes it through, lets a client choose
  its own "address" and dodge the limits; one that sets nothing makes every client share the proxy's address. For nginx
  facing clients directly, use `proxy_set_header X-Forwarded-For $remote_addr;`, not `$proxy_add_x_forwarded_for`.
- **Set `VAULT_TRUSTED_PROXY_HOPS` to match** (see `.env.example`). The client is the entry just before the last N
  entries of the header (the first entry when there are N or fewer), and `0` ignores the header and uses the address
  the connection comes from. One proxy that overwrites the header works with the default, `1`.

A wrong value breaks the limits silently, so verify it. On a throwaway instance started with
`VAULT_LOGIN_PER_10MIN_PER_IP=2`, three requests through the proxy with made-up addresses must be limited together:

```bash
for i in 1 2 3; do
  curl -s -o /dev/null -w '%{http_code}\n' -X POST https://vault.example.org/v1/accounts/prelogin \
    -H 'Content-Type: application/json' -H "X-Forwarded-For: 203.0.113.$i" -d '{"username":"somebody"}'
done   # 200, 200, 429 when the header is handled correctly
```

No deployment manifests are included in this repository. The vault is also an optional service of the full platform:
see [running the vault](https://website.pocketnutrition.org/docs/self-hosting/run-the-platform#vault) for the Docker
Compose route.

## Configuration

Every setting is an environment variable with the `VAULT_` prefix, and every one is listed, with its default and a
one-line explanation, in [.env.example](.env.example) (the code is [app/config.py](app/config.py)). The ones to look at
first:

| Variable | Default | What it does |
|---|---|---|
| `VAULT_DATABASE_URL` | `sqlite:///./vault.db` | Database URL: PostgreSQL for real use, SQLite for a trial run |
| `VAULT_ADMIN_TOKEN` | empty | Secret for `POST /admin/accounts`; the endpoint is disabled while it is empty |
| `VAULT_PRELOGIN_SECRET` | the admin token, else random per process | Keys the fake KDF salts served for unknown usernames; set it so they survive restarts |
| `VAULT_REGISTRATION` | `open` | `open`: anyone can register (rate-limited, quota-bound); `closed`: accounts come only from the admin endpoint |
| `VAULT_TRUSTED_PROXY_HOPS` | `1` | How the client address is read from `X-Forwarded-For` (see above) |
| `VAULT_SERVER_NAME` | `Pocket Nutrition Vault` | Name the apps show, and the issuer in authenticator apps |

The same file also covers quotas and size limits, abuse limits, the iOS app association and CORS origins. The schema is
migrated at startup (`app/migrations`); every change to `app/models.py` needs a migration (a test enforces it).

## API

Send the API key as `Authorization: Bearer <key>`.

| Endpoint | Who | Purpose |
|---|---|---|
| `GET /healthz` | public | Liveness check, `{"status":"ok"}` |
| `GET /.well-known/apple-app-site-association` | public | iOS app association; `404` unless `VAULT_APPLE_APP_IDS` is set |
| `GET /v1/server-info` | public | Name, registration mode, quota, KDF defaults |
| `POST /v1/accounts/prelogin` | public | KDF settings for a username |
| `POST /v1/accounts` | public (if open) | Register: username, KDF, auth hash, keyring; returns a device key |
| `POST /v1/login` | public | Log in on a device (plus a TOTP or recovery code if 2FA is on); returns a device key and the keyring |
| `POST /v1/logout`, `DELETE /v1/account` | owner | Unlink this device, erase the account |
| `POST /v1/account/passphrase` | owner | Change the passphrase (new auth hash, KDF, keyring); unlinks other devices |
| `POST /v1/account/passphrase/reset` | owner | Set a new passphrase from a linked device that no longer knows the old one (2FA code if on); unlinks other devices |
| `GET /v1/account/two-factor` | owner | Two-factor status and recovery codes left |
| `POST /v1/account/two-factor/setup`, `/enable`, `/disable` | owner | Turn TOTP two-factor login on or off |
| `POST /admin/accounts` | admin token | Create a password-less account (API key only) |
| `GET /v1/me` | any key | Validate the URL and key from the app settings |
| `GET/PUT /v1/keyring` | owner | Wrapped user key blob (compare-and-swap) |
| `PUT/DELETE /v1/records/{id}` | owner | Write or tombstone one encrypted record |
| `GET /v1/sync?since=` | owner, reader | Pull changes (readers see only their scope) |
| `POST/GET/DELETE /v1/grants` | owner | Manage external readers |
| `POST /v1/drops` | owner | Mint a short-lived write-only drop token |
| `DELETE /v1/drops/{id}` | owner | Cancel a drop token before it expires |
| `PUT /v1/drop` | drop token | Deposit one sealed payload (cannot read anything) |
| `GET /v1/grants/me` | reader | Fetch the wrapped scope key |
| `POST/GET/DELETE /v1/keys` | owner | One API key per device |

The protocol behind these endpoints (key hierarchy, record encryption, grants, drops, sync) is specified in
[docs/PROTOCOL.md](docs/PROTOCOL.md), and the known answers every client must reproduce are in
[docs/test-vectors.json](docs/test-vectors.json). To regenerate them after a protocol change, install PyNaCl and run
`python scripts/gen_vectors.py > docs/test-vectors.json` (see [CONTRIBUTING.md](CONTRIBUTING.md)).

## Related repositories

All under <https://github.com/pocket-nutrition>:

- [ios](https://github.com/pocket-nutrition/ios) and [android](https://github.com/pocket-nutrition/android):
  the apps, which implement the client side of the protocol.
- [recognition](https://github.com/pocket-nutrition/recognition): the meal recognition service, which can
  deposit its results through write-only drops.
- [api](https://github.com/pocket-nutrition/api): the nutrition API, separate from the vault.

## Testing

```bash
.venv/bin/pytest
```

The suite runs on in-memory SQLite and needs no other service. Run it from the repository root, in a shell without
exported `VAULT_*` variables: they override the defaults the tests build on.

## Using with Claude Code

This project includes a [CLAUDE.md](CLAUDE.md) that gives Claude Code the architecture, the commands and the rules of the
codebase (including the one that the server never decrypts, parses or logs record contents).

```bash
claude    # Start Claude Code — reads CLAUDE.md automatically
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, testing expectations and the pull request workflow. Any
change to the protocol updates `docs/PROTOCOL.md` and regenerates `docs/test-vectors.json` with
`scripts/gen_vectors.py`.

## Security

Please do not report a vulnerability in a public issue. Use GitHub's private vulnerability reporting: the **Report a
vulnerability** button on the Security tab of this repository. See [SECURITY.md](SECURITY.md) for what is in scope.

## License

GNU Affero General Public License v3.0: see [LICENSE](LICENSE). If you run a modified version of the server for other
people, section 13 of the license requires you to offer them the source of your version.
