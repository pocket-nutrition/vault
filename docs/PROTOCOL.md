# Vault protocol v1

The server stores **opaque ciphertext**. Everything below the "Server" line is enforced by clients;
the server cannot check it and must never be given a key. Clients and external readers implement
this document; it is meant to move to the [contracts](https://github.com/pocket-nutrition/contracts)
repository once a client consumes it.

## Key hierarchy

```
passphrase ──Argon2id + crypto_kdf──► wrap key ──wraps──► user key (random 256-bit, never leaves devices unwrapped)
recovery key (random 256-bit, printed once) ──wraps──► user key        (second copy of the same key)
user key ──encrypts──► private records                                  key_id = "user"
scope key (random 256-bit, one per shared scope + generation)
        ──encrypts──► records in that scope                             key_id = "scope:<scope_id>:<n>"
        ──HPKE-sealed to a reader's public key──► wrapped_scope_key     (stored in the grant)
```

- The **API key is authentication only.** It identifies the account to the server. It is not, and
  must never be derived into, an encryption key.
- Losing both the passphrase and the recovery key loses the data. The server cannot recover it.
- Random keys, not password-derived ones, so changing the passphrase re-wraps one key instead of
  re-encrypting every record.

## Accounts, login and linking a device

Accounts are **per server** (as in Bitwarden): the app lets the user pick the server URL first
(`https://vault.pocketnutrition.org` by default, or a self-hosted one), then register or log in there.
Identifier is a **username** (3 to 64 chars, lowercase `a-z 0-9 _ . -`). No email is stored.

**Key derivation** (libsodium, identical on every client):

```
master_key = Argon2id(NFKC(passphrase) as UTF-8, salt = kdf.salt, opslimit, memlimit)   32 bytes
auth_hash  = crypto_kdf_derive_from_key(master_key, subkey_id = 1, ctx = "pnvauth1")   32 bytes, sent to the server
wrap_key   = crypto_kdf_derive_from_key(master_key, subkey_id = 2, ctx = "pnvwrap1")   32 bytes, never leaves the device
```

**Normalise the passphrase with Unicode NFKC before UTF-8 encoding** (whitespace is kept), so an accent typed
as one character or as base letter + combining mark derives the same key on every keyboard and platform.
Clients enforce a minimum of 12 characters, counted after normalisation; the server cannot, because it never
sees the passphrase. Clients must also refuse KDF settings below the server floor listed below, so a hostile
server cannot downgrade the derivation at prelogin.

The two subkeys are independent: knowing `auth_hash` (the server does) reveals nothing about `wrap_key`.
The server accepts only `argon2id`, `opslimit` 3 to 10, `memlimit` 64 MiB to 1 GiB, salt of 16 bytes,
so a client cannot register a weak KDF. The floor equals the recommended setting (opslimit 3, memlimit
64 MiB), so a hostile server answering prelogin with "the floor" gains nothing. Clients enforce the same
floor, store the KDF at link time, and must refuse a later prelogin or keyring whose KDF differs from it.

**Register** (`POST /v1/accounts`): the client generates `kdf.salt`, the user key and the inbox keypair,
builds the keyring (user key wrapped by `wrap_key` and by the recovery key), and sends
`{username, kdf, auth_hash, keyring, device_label}`. The reply is a session: this device's API key
plus the keyring. The app must make the user save the **recovery key** before finishing.

**Login** (`POST /v1/accounts/prelogin` then `POST /v1/login`): prelogin returns the account's `kdf`
(a stable fake one for unknown usernames). The client derives the keys, sends `{username, auth_hash,
device_label}`, and gets a new **device API key** and the keyring, then unwraps the user key locally.
That key is what "links" the phone to the server. Unlinking is `POST /v1/logout`; any device can be
revoked from `GET/DELETE /v1/keys`.

**Abuse limits:** 5 wrong passwords lock the account for 15 minutes (`429` + `Retry-After`). Unknown
usernames lock the same way, so a `429` does not reveal that an account exists. A lock only blocks
*new* logins: devices already linked keep working, because they authenticate with their device key.
Registration and login are rate-limited per client IP, Argon2 work is capped server-wide (excess requests
get `503`), request bodies are capped at 1 MiB, and each account has a storage quota
(`GET /v1/server-info`) that also charges a fixed overhead per stored row, tombstones included, plus caps
on devices (20), active grants (20) and pending drops (100). Known trade-off: anyone who knows a
username can keep new logins to that account locked. Changing server means logging in to another one: data does not move by
itself, so moving it is an export and re-import done on the device, the only place it can be decrypted.

**Erasure:** `DELETE /v1/account` with `{auth_hash}` removes the account and everything stored for it.

## Changing the passphrase

`POST /v1/account/passphrase` (owner key) with
`{auth_hash, new_auth_hash, kdf, keyring, base_version}`. The client derives the *current* `auth_hash`
from the stored KDF, picks a **fresh** `kdf.salt`, derives the new `auth_hash` and `wrap_key`, re-wraps
the user key under the new `wrap_key` (the recovery copy and the inbox key are unchanged), and sends the
whole new keyring. The user key itself does not change, so no record is re-encrypted.

- `kdf` follows the registration rules, `keyring` the `PUT /v1/keyring` size limit.
- Wrong current `auth_hash`: `401 invalid_credentials`, counted toward the same lockout as login (and
  `429 account_locked` + `Retry-After` while it is locked).
- `base_version` differs from the stored keyring version: `409 keyring_conflict` with `current_version`
  (same as `PUT /v1/keyring`). Refetch the keyring, re-wrap, retry.
- Admin-created accounts without a passphrase: `409 no_passphrase`.
- On success the auth digest, KDF and keyring are replaced in one transaction, the keyring version is
  bumped, and **every other owner API key of the account is revoked**: those devices hold the old KDF
  and must log in again with the new passphrase. The calling device stays linked. Reader grants and
  drop tokens are left alone (they do not depend on the passphrase). Reply:
  `{"version": <new keyring version>, "revoked_devices": <n>}`.

## Resetting a forgotten passphrase from a linked device

`POST /v1/account/passphrase/reset` (owner key) with
`{new_auth_hash, kdf, keyring, base_version, totp_code?, recovery_code?}`. For a person who no longer
knows the passphrase but still has a linked device: that device holds the user key, so it generates a
**new passphrase and a new recovery key**, picks a fresh `kdf.salt`, wraps the unchanged user key under
both, and sends the whole new keyring (inbox key copied as is). No record is re-encrypted.

- This is not a server-side recovery: the server receives no key and still cannot decrypt anything. It
  only accepts a keyring from a device that already proves it is linked.
- Threat: a stolen owner key could use it to lock the other devices out, but it reveals nothing, and an
  owner key can already delete every record. Clients put it behind the device's own lock (Face ID,
  device credential).
- Two-factor on: `totp_code` or `recovery_code` is required, as at login (`401 two_factor_required`,
  `401 invalid_two_factor` counted toward the lockout, `429 account_locked` while locked).
- `base_version` stale: `409 keyring_conflict` with `current_version`. Size limits as for the passphrase
  change.
- Effects and reply as for the passphrase change: other owner keys revoked, keyring version bumped,
  `{"version", "revoked_devices"}`. The old recovery key stops working, because its wrapped copy is replaced.

## Two-factor login (TOTP)

Optional, per account. RFC 6238 TOTP: HMAC-SHA1, 6 digits, 30 s period, codes from the previous and the
next step accepted for clock drift. The TOTP secret is **authentication material, not an encryption key**:
the server stores it to check codes, and it decrypts nothing.

1. `POST /v1/account/two-factor/setup` (owner key) with `{auth_hash}` returns
   `{secret, otpauth_uri}`: a 20-byte secret as unpadded RFC 4648 Base32, and
   `otpauth://totp/<server name>:<username>?secret=…&issuer=<server name>&algorithm=SHA1&digits=6&period=30`
   (server name from `GET /v1/server-info`, URL-encoded). The secret is only *pending*; a new setup
   replaces it. Errors: `401 invalid_credentials` (counted toward the lockout), `409 two_factor_enabled`,
   `409 no_passphrase` for accounts without a passphrase.
2. `POST /v1/account/two-factor/enable` with `{code}` checks a code from the authenticator app against
   the pending secret and switches 2FA on. The reply is `{recovery_codes: [10 codes]}`, **shown once**.
   Errors: `409 no_pending_setup`, `400 invalid_code`.
3. `GET /v1/account/two-factor` returns `{enabled, recovery_codes_left}`.
4. `POST /v1/account/two-factor/disable` with `{auth_hash, code}`, where `code` is a current TOTP code or
   an unused recovery code, removes the secret and every recovery code (`204`). Errors:
   `409 two_factor_disabled`, `401 invalid_credentials` (counted), `400 invalid_code`.

Setup, enable and disable are rate-limited per client IP.

**Recovery codes:** `xxxx-xxxx-xxxx`, lowercase Base32 alphabet (`a-z 2-7`), 60 random bits each. The
server keeps only the SHA-256 of the normalised form (lowercase, dashes and spaces removed), so clients may
accept any case and spacing. Each code works once.

**Login with 2FA on:** `POST /v1/login` takes two optional fields, `totp_code` and `recovery_code`. They
are checked only after `auth_hash` verifies:

- neither given: `401 two_factor_required`. Not counted as a failure and no key is issued; the client
  asks for a code and repeats the request with it.
- a wrong code, or a TOTP code for a time step at or before the last accepted one (replay):
  `401 invalid_two_factor`, counted toward the account lockout.
- a valid recovery code is consumed; 2FA stays on.
- only on success are the failure counter reset and a device key issued.

**What it protects, and what it does not.** 2FA guards **linking a new device**: someone who learns the
passphrase still cannot get a device key without the second factor. It does **nothing against offline
guessing from a stolen database**: the encryption keys come from the passphrase alone, so an attacker
with the database can still try passphrases against the wrapped keyring without any code. And a device
that is **already linked keeps working** after 2FA is turned on, because it authenticates with its device
key; revoke it (`DELETE /v1/keys/{id}`, or change the passphrase) if it should not.

**What a stolen database allows:** the attacker holds each user's `kdf`, wrapped keyring and the
Argon2id digest of `auth_hash`, so they can try to guess passphrases offline, one account at a time,
paying the full Argon2id cost per guess. Strong passphrases and the KDF minimums are the defence;
there is no email reset, because the server cannot recover a key it never had. Two-factor login does not help
here: it gates new device links, not the keyring, and the TOTP secrets in the same database give an
attacker who already has it nothing to decrypt.

## Record encryption

- Cipher: **XChaCha20-Poly1305** (libsodium `crypto_aead_xchacha20poly1305_ietf`).
- `ciphertext = base64(nonce[24] || aead_ciphertext)`, nonce random per write.
- **AAD** (UTF-8, `|`-separated, bound so the server cannot swap or replay records):

  ```
  pnv1|<account_id>|<record_id>|<type>|<scope_id or "">|<revision>|<key_id>
  ```

- Plaintext is client-defined JSON. Clients ignore unknown fields.
- A client must reject a record whose AAD fields do not match what the server returned.

## Keyring blob

`PUT /v1/keyring` (and the `keyring` sent at registration) stores a client-built JSON string,
compare-and-swapped on `base_version`. Keys are sorted and the JSON is compact, so every device saves the
same bytes:

```json
{
  "v": 1,
  "kdf": {"alg": "argon2id", "salt": "<b64 16 bytes>", "opslimit": 3, "memlimit": 67108864},
  "passphrase_wrapped_user_key": "<b64 nonce||aead>",
  "recovery_wrapped_user_key": "<b64 nonce||aead>",
  "inbox_public_key": "<b64 X25519 public key>",
  "inbox_wrapped_secret_key": "<b64 nonce||aead>"
}
```

Each wrapped value is XChaCha20-Poly1305 with a random nonce and **AAD `pnv1|keyring|<purpose>`**, where
purpose is `passphrase`, `recovery` or `inbox`, so one wrapped key can never be passed off as another:

| Field | Wrapped by | AAD |
|---|---|---|
| `passphrase_wrapped_user_key` | `wrap_key` (from the passphrase) | `pnv1|keyring|passphrase` |
| `recovery_wrapped_user_key` | the recovery key itself | `pnv1|keyring|recovery` |
| `inbox_wrapped_secret_key` | the user key | `pnv1|keyring|inbox` |

**`inbox_public_key` is not trusted.** It sits in the blob in plaintext, so a malicious server could swap
it for its own key and read every drop. Clients MUST derive the public key from the unwrapped
`inbox_wrapped_secret_key` (X25519 scalar multiplication of the base point) and reject the keyring if the
field differs, never using the blob's value to seal or to hand to a service.

The server only checks size (16 KiB). A new device fetches it at login, derives `wrap_key`, unwraps the
user key, then the inbox secret key. Each device gets its own API key (`POST /v1/login`), so a lost
phone can be revoked alone.

**Recovery key:** 32 random bytes, shown as RFC 4648 Base32 in groups of four (`ABCD-EFGH-…`, 52
characters). Decoders ignore case, dashes and spaces, and reject nonzero padding bits.

## Fingerprint phrase

Client-side only; the server is not involved. Five words that name an account's keys, so a person can
check that two devices (or the web viewer) opened the same keyring:

```
input  = UTF-8("pnv1|fingerprint|<account_id>|") || inbox_public_key (raw 32 bytes, derived from the secret key)
digest = BLAKE2b-256(input)                         (libsodium crypto_generichash, no key)
word i = EFF long wordlist[ uint32_be(digest[4i .. 4i+4]) mod 7776 ],  i = 0..4,  joined by "-"
```

Different words on two devices mean one of them was given other keys. The phrase is not a secret.

## Granting an external reader access

1. The reader generates an X25519 keypair and gives the owner its **public key** (QR or paste).
2. On an unlocked client the owner creates a scope key (or reuses the current generation), then
   HPKE-seals it to the reader's public key.
3. `POST /v1/grants` with `{scope_id, label, recipient_public_key, wrapped_scope_key}`. The response
   contains the reader's API key, **shown once**.
4. The reader calls `GET /v1/grants/me`, unseals `wrapped_scope_key`, then `GET /v1/sync` and
   decrypts locally. It only ever receives records with its `scope_id`.

**Revocation** (`DELETE /v1/grants/{id}`) kills the API key at once. To also protect *future* data
the owner bumps the scope key generation and writes new records under `scope:<id>:<n+1>`. Data the
reader already fetched cannot be un-read, and re-encrypting old records is a client choice.

## Drops: depositing data without being able to read it

A drop lets a third party (for example the [recognition](https://github.com/pocket-nutrition/recognition)
service) put one result in the vault. It
holds no key that can decrypt anything, including what it just wrote.

1. The phone owns an **inbox keypair** (X25519). It is generated once; the private key is stored as
   a normal record under the user key, so every device can open drops. The public key is not secret.
2. Per request, the phone calls `POST /v1/drops` with its owner key:
   `{record_id, type, key_id: "inbox", ttl_s (60 s to 7 d), max_writes (1 to 10)}`. The response is a
   **drop token**, shown once. `record_id` must be new, and `type` and `key_id` are fixed by the owner.
3. The phone gives the service the vault URL, the drop token and the inbox public key.
4. The service seals its payload to the inbox public key (libsodium `crypto_box_seal`) and sends
   `PUT /v1/drop {ciphertext}` with the drop token. The server assigns the revision.
5. The owner can cancel a drop early with `DELETE /v1/drops/{id}`.
6. The drop token can do **only** that: it cannot sync, read, list, or write anything else. It stops
   working when `ttl_s` passes or `max_writes` is used up, and as soon as the owner writes the record.
7. On its next sync the phone sees `key_id = "inbox"`, opens the sealed box, and re-saves the data
   as a normal record under the user key (which also takes the record away from the drop).

Sealed boxes have no AAD and anyone with the public key can forge one. The payload must therefore
embed its own `record_id`, which the phone checks, and the server and drop holder are trusted for
the integrity of drops until the phone re-saves them. Confidentiality does not depend on them.

## Sync

- Every write gets a per-account increasing `seq`. `GET /v1/sync?since=<cursor>` returns records
  with `seq > cursor` in order, tombstones included. Store the returned `cursor`.
- Writes carry `revision` = current + 1. A mismatch is `409 revision_conflict` with
  `current_revision`; the client pulls, merges (client-side, the server cannot read content) and
  retries.
- Tombstones are purged 90 days after the deletion, when the account next deletes a record. A device
  that has been offline longer than that must resync from `since=0` and discard local records the server
  no longer lists.
- `scope_id` is fixed at creation (`409 scope_immutable`). To move data to another scope, delete the
  record and create a new one.

## What the server can see

Record count, sizes, `type`, `scope_id`, `key_id`, revisions, timestamps, and which API key reads
what. Keep `type` and `scope_id` coarse ("meal", "weight"), and never put user data in them.
Ciphertext length leaks plaintext length; clients may pad if that matters.

## Out of scope for v1

Rate limiting (do it at the reverse proxy), SRP or OPAQUE login (API keys are 256-bit random, so there is
no password to brute-force on the server), and multi-user sharing between accounts.
