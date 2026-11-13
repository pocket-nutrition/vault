# Security policy

The vault stores users' end-to-end encrypted journals. The server cannot read what it stores, but a flaw in
it can still expose accounts, lock people out or weaken the encryption around it. Please report security
problems **privately**: not in a public issue, discussion or pull request.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting:

1. Open the **Security** tab of <https://github.com/pocket-nutrition/vault>.
2. Click **Report a vulnerability** (direct link:
   <https://github.com/pocket-nutrition/vault/security/advisories/new>).
3. Describe the problem: the release or commit you tested, what you did, what happened, what you expected
   and the impact as you see it. A proof of concept against a local instance (see the [README](README.md))
   helps most.

Only the maintainers can see the report. We will acknowledge it, keep you informed while we work on a fix,
and credit you in the published advisory if you want to be named. Please give us a reasonable time to ship a
fix before you disclose the problem publicly.

Test against an instance you run yourself, with throwaway accounts. Do not access or keep data that is not
yours, and do not put real credentials or users' data in a report.

## What is in scope

- **The server** (`app/`) and the container image built from the [Dockerfile](Dockerfile): authentication and
  authorization (owner keys, reader keys and drop tokens; one account reaching another's data), the login
  lockout, rate limits, quotas and size limits, the handling of malformed input, the database migrations,
  and anything that makes the server log, store or return a secret it should not hold.
- **The protocol** ([docs/PROTOCOL.md](docs/PROTOCOL.md)): a design flaw that lets the server, a drop-token
  holder or an external reader learn a key or a plaintext it should not, forge, swap or replay records,
  downgrade the key derivation, or otherwise break a guarantee the document states. The threat model, with its
  known limits, is in that document: read it first, and tell us if you think a limit is worse than described.
- **The crypto test vectors** ([docs/test-vectors.json](docs/test-vectors.json)) and the script that generates
  them ([scripts/gen_vectors.py](scripts/gen_vectors.py)): a wrong or misleading vector would lead clients to
  implement the protocol incorrectly.

## Out of scope

- The other Pocket Nutrition repositories (the apps, the recognition service, the nutrition API): report
  problems there. A flaw in how an app implements this protocol belongs to that app; a flaw in the protocol
  itself belongs here.
- Vulnerabilities in third-party dependencies: report them upstream. If one is exploitable through the vault,
  tell us as well.

## Supported versions

Fixes land on `main` and ship in the next release (releases are CalVer, `vYYYY.M.N`, published from `main`).
Older releases are not patched: run the latest one.
