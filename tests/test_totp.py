import base64

import pytest

from app import totp

RFC_KEY = b"12345678901234567890"


@pytest.mark.parametrize(
    "counter,expected",
    enumerate(["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]),
)
def test_hotp_matches_rfc4226_appendix_d(counter, expected):
    assert totp.hotp(RFC_KEY, counter) == expected


@pytest.mark.parametrize(
    "at,expected",
    [
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
        (20000000000, "65353130"),
    ],
)
def test_totp_matches_rfc6238_sha1_vectors(at, expected):
    assert totp.totp(RFC_KEY, at, digits=8) == expected
    # Six digits is the same value mod 10^6, i.e. the last six of the 8-digit vector.
    assert totp.totp(RFC_KEY, at) == expected[-6:]


def _secret() -> str:
    return base64.b32encode(RFC_KEY).decode().rstrip("=")


def test_matching_step_accepts_one_step_of_drift_either_way(monkeypatch):
    monkeypatch.setattr(totp, "_now", lambda: 1111111111)
    step = 1111111111 // 30
    for offset in (-1, 0, 1):
        code = totp.hotp(RFC_KEY, step + offset)
        assert totp.matching_step(_secret(), code, None) == step + offset
    assert totp.matching_step(_secret(), totp.hotp(RFC_KEY, step + 2), None) is None
    assert totp.matching_step(_secret(), totp.hotp(RFC_KEY, step - 2), None) is None


def test_matching_step_refuses_steps_at_or_before_the_last_accepted(monkeypatch):
    monkeypatch.setattr(totp, "_now", lambda: 1111111111)
    step = 1111111111 // 30
    assert totp.matching_step(_secret(), totp.hotp(RFC_KEY, step), step) is None
    assert totp.matching_step(_secret(), totp.hotp(RFC_KEY, step - 1), step) is None
    assert totp.matching_step(_secret(), totp.hotp(RFC_KEY, step + 1), step) == step + 1


@pytest.mark.parametrize("code", ["", "12345", "1234567", "abcdef", "12345a"])
def test_malformed_codes_never_match(code):
    assert totp.matching_step(_secret(), code, None) is None


def test_new_secret_is_20_bytes_of_unpadded_base32():
    secret = totp.new_secret()
    assert "=" not in secret and len(secret) == 32
    assert len(totp._decode_secret(secret)) == 20


def test_recovery_codes_have_the_documented_format_and_are_distinct():
    codes = totp.new_recovery_codes()
    assert len(codes) == 10 and len(set(codes)) == 10
    for code in codes:
        groups = code.split("-")
        assert [len(g) for g in groups] == [4, 4, 4]
        assert set("".join(groups)) <= set("abcdefghijklmnopqrstuvwxyz234567")


def test_recovery_codes_are_normalised_and_single_use():
    code = "abcd-efgh-2345"
    stored = totp.dump_hashes([totp.hash_recovery_code(code), totp.hash_recovery_code("zzzz-zzzz-zzzz")])
    remaining = totp.consume_recovery_code(stored, " ABCD efgh-2345 ")
    assert remaining is not None and len(totp.load_hashes(remaining)) == 1
    assert totp.consume_recovery_code(remaining, code) is None
