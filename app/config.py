from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VAULT_")

    database_url: str = "sqlite:///./vault.db"
    # POST /admin/accounts is DISABLED while this is empty.
    admin_token: str = ""
    max_record_bytes: int = 256 * 1024
    max_keyring_bytes: int = 16 * 1024
    max_page_size: int = 500

    server_name: str = "Pocket Nutrition Vault"
    # "open": anyone can register (rate-limited, quota-bound). "closed": admin endpoint only.
    registration: str = "open"
    # Total stored ciphertext per account, in bytes (base64 characters, as stored).
    quota_bytes: int = 50 * 1024 * 1024

    # Keyed secret for the fake KDF settings served for unknown usernames.
    # Falls back to admin_token, then to a random per-process value.
    prelogin_secret: str = ""

    login_max_failures: int = 5
    login_lock_s: int = 900
    register_per_hour_per_ip: int = 10
    login_per_10min_per_ip: int = 30
    # Two-factor setup/enable/disable. Low: each is a deliberate settings action, never a loop.
    two_factor_per_10min_per_ip: int = 10
    # Proxies in front of the app that append to X-Forwarded-For: the client is the entry just before the last
    # N (the first entry when there are N or fewer). 0 ignores the header and uses the socket peer.
    trusted_proxy_hops: int = 1

    # Argon2 runs at most this many at a time, process-wide (about 19 MiB each). Excess requests wait a
    # few seconds, then get a 503, instead of letting a burst of logins exhaust the container's memory.
    argon_concurrency: int = 2
    argon_wait_s: float = 5
    # Cap on any request body, enforced while reading, before JSON parsing.
    max_body_bytes: int = 1024 * 1024

    # Bookkeeping per stored row counted against the quota, tombstones included, so create-then-delete
    # cycles cannot grow the table for free. Old tombstones are purged when records are deleted.
    row_overhead_bytes: int = 256
    tombstone_retention_days: int = 90
    max_devices: int = 20
    max_grants: int = 20
    max_pending_drops: int = 100

    # Comma-separated "TEAMID.bundle.id" values of the apps allowed to use this server's credentials
    # (served in /.well-known/apple-app-site-association so iOS and password managers can match the
    # app to this domain). The file is not served while empty.
    apple_app_ids: str = ""

    # Comma-separated browser origins allowed to call the API (the web viewer). Empty means none: the
    # phone apps are not browsers and need no CORS. Never "*": requests carry a bearer key.
    cors_origins: str = ""
