---
name: Feature request
about: Suggest an idea or improvement for the vault
title: "[Feature] "
labels: enhancement
assignees: ''
---

## Is your feature request related to a problem?

A clear and concise description of what the problem is (e.g. "I'm always frustrated
when...").

## Describe the solution you'd like

A clear and concise description of what you want to happen. If it changes an endpoint or the
protocol (`docs/PROTOCOL.md`), include an example request and response.

## Describe alternatives you've considered

Any alternative solutions or features you've considered.

## Scope check

- [ ] This does not require the server to decrypt, parse or log record contents, or to receive a
      key (see the first rule in `CLAUDE.md`). Server-side search, validation of plaintext and an
      account "recovery" path all fall in this category.
- [ ] This does not derive an encryption key from an API key: API keys are authentication only.
- [ ] If it changes the protocol, I understand that `docs/PROTOCOL.md` and
      `docs/test-vectors.json` change with it, and that every client and reader has to follow.

## Additional context

Add any other context, references, or screenshots about the feature request here.
