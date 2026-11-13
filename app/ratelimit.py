import hashlib
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request

_MAX_TRACKED_KEYS = 10_000
_EVICT_FRACTION = 10


class RateLimiter:
    """In-memory sliding window. Per replica: fine at replicas=1, move to Redis before scaling out."""

    def __init__(self) -> None:
        self._hits: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    def check(self, bucket: str, key: str, limit: int, window_s: int) -> None:
        now = time.monotonic()
        hits = self._hits[(bucket, key)]
        while hits and hits[0] <= now - window_s:
            hits.popleft()
        if len(hits) >= limit:
            retry_after = max(1, int(hits[0] + window_s - now))
            raise HTTPException(429, {"error": "rate_limited"}, {"Retry-After": str(retry_after)})
        hits.append(now)
        if len(self._hits) > _MAX_TRACKED_KEYS:
            _evict(self._hits, now - window_s, lambda hits: hits[-1] if hits else 0.0)


def _evict(table: dict, stale_before: float, last_seen) -> None:
    """Drop stale entries; if the table is still over its cap, drop the oldest tenth. Bounded memory."""
    for key in [k for k, v in table.items() if last_seen(v) <= stale_before]:
        del table[key]
    if len(table) > _MAX_TRACKED_KEYS:
        oldest = sorted(table, key=lambda k: last_seen(table[k]))[: _MAX_TRACKED_KEYS // _EVICT_FRACTION]
        for key in oldest:
            del table[key]


class UnknownLoginGuard:
    """Failed-login counting for usernames that do not exist, so they lock exactly like real accounts and
    the 429 does not reveal which usernames are registered. In memory, keyed by a hash of the name."""

    def __init__(self) -> None:
        # key -> [failures, locked_until (monotonic), last_seen (monotonic)]
        self._state: dict[str, list[float]] = {}

    @staticmethod
    def _key(username: str) -> str:
        return hashlib.sha256(username.encode()).hexdigest()

    def locked_for(self, username: str) -> int:
        """Seconds left on the lock, or 0."""
        entry = self._state.get(self._key(username))
        if entry is None:
            return 0
        return max(0, int(entry[1] - time.monotonic()) + 1) if entry[1] > time.monotonic() else 0

    def record_failure(self, username: str, max_failures: int, lock_s: int) -> None:
        now = time.monotonic()
        entry = self._state.setdefault(self._key(username), [0, 0.0, now])
        entry[0] += 1
        entry[2] = now
        if entry[0] >= max_failures:
            entry[0] = 0
            entry[1] = now + lock_s
        if len(self._state) > _MAX_TRACKED_KEYS:
            _evict(self._state, now - 3600, lambda e: e[2])


def client_ip(request: Request, trusted_hops: int) -> str:
    """The client address as seen by the outermost trusted proxy. Never trusts more hops than configured."""
    peer = request.client.host if request.client else "unknown"
    forwarded = [part.strip() for part in request.headers.get("x-forwarded-for", "").split(",") if part.strip()]
    if trusted_hops > 0 and len(forwarded) > trusted_hops:
        return forwarded[-(trusted_hops + 1)]
    if trusted_hops > 0 and forwarded:
        return forwarded[0]
    return peer
