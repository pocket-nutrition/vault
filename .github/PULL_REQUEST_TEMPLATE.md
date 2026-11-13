## What and why

<!-- What does this change, and what problem does it solve? Link the issue if there is one. -->

## How it was checked

<!-- Tests added or run, or how you verified it by hand. Never paste API keys, tokens or real user data. -->

## Checklist

- [ ] The change is focused: one concern per pull request
- [ ] Tests cover the new behavior, or this PR explains why they don't
- [ ] Documentation is updated where behavior changed
- [ ] The server still never decrypts, parses or logs record contents, and never receives a key
- [ ] A change to `app/models.py` comes with a migration in `app/migrations/versions/`
- [ ] A change to the protocol updates `docs/PROTOCOL.md` and regenerates `docs/test-vectors.json` with `scripts/gen_vectors.py`
