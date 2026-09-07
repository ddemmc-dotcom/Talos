"""TALOS — UTILITIES (all implemented).

15 password generator        (cryptographically secure, stdlib ``secrets``)
16 hash generator            (md5 / sha1 / sha2 / sha3 families)
17 MAC address generator     (random, locally administered unicast)
18 UUID generator            (uuid4)
19 string encoder / decoder  (base64, hex, url)
20 session / target manager  (set targets, clear results, show context)
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import string
import uuid
from typing import Optional
from urllib.parse import quote, unquote

from src.core.context import Session
from src.core.table import print_table

_ALPHABET = string.ascii_letters + string.digits + string.punctuation


def _ask(prompt: str, default: Optional[str] = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    try:
        return input(f"  {prompt}{suffix}: ").strip() or (default or "")
    except EOFError:
        return default or ""


def _clamp_int(raw: str, default: int, low: int, high: int) -> int:
    try:
        value = int(raw)
    except ValueError:
        value = default
    return max(low, min(value, high))


# ---------------------------------------------------------------------------
# [15] Password Generator
# ---------------------------------------------------------------------------
def _random_password(length: int) -> str:
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits, string.punctuation]
    chosen = [secrets.choice(pool) for pool in pools]
    while len(chosen) < length:
        chosen.append(secrets.choice(_ALPHABET))
    secrets.SystemRandom().shuffle(chosen)
    return "".join(chosen)


def password_generator(session: Session) -> None:
    """Generate a cryptographically secure password (default length 16)."""
    raw = _ask("Length", "16")
    length = _clamp_int(raw, default=16, low=8, high=128)
    if raw and (raw.strip() != str(length)):
        print(f"[INFO] Length adjusted to {length} (allowed range 8-128).")
    password = _random_password(length)
    entropy = length * 6.55  # ~6.55 bits of entropy per character
    print(f"  Generated password ({length} chars, approx. {entropy:.0f} bits):")
    print(f"  {password}")
    session.set_result("generated_password", password)


# ---------------------------------------------------------------------------
# [16] Hash Generator
# ---------------------------------------------------------------------------
_HASH_ALGORITHMS = ("md5", "sha1", "sha224", "sha256", "sha384", "sha512",
                    "sha3_224", "sha3_256", "sha3_384", "sha3_512",
                    "blake2s", "blake2b", "sha512_224", "sha512_256")


def hash_generator(session: Session) -> None:
    """Compute a digest of user text with the chosen algorithm."""
    text = _ask("Text to hash", "")
    if not text:
        print("[ERROR] Nothing to hash; aborting.")
        return
    algorithm = _ask(f"Algorithm ({', '.join(_HASH_ALGORITHMS)})", "sha256").lower()
    if algorithm not in _HASH_ALGORITHMS:
        print(f"[ERROR] Unknown algorithm '{algorithm}'. Pick one of: "
              f"{', '.join(_HASH_ALGORITHMS)}")
        return
    digest = hashlib.new(algorithm, text.encode("utf-8")).hexdigest()
    print_table(["field", "value"], [("algorithm", algorithm), ("digest", digest)])
    session.set_result("hash", {"algorithm": algorithm, "digest": digest, "input": text})


# ---------------------------------------------------------------------------
# [17] MAC Address Generator
# ---------------------------------------------------------------------------
def _random_mac() -> str:
    first = secrets.randbelow(256)
    first = (first & 0xFC) | 0x02  # locally administered, unicast
    octets = [first] + [secrets.randbelow(256) for _ in range(5)]
    return ":".join(f"{octet:02x}" for octet in octets)


def mac_generator(session: Session) -> None:
    """Generate one or more random locally-administered MAC addresses."""
    raw = _ask("How many", "1")
    count = _clamp_int(raw, default=1, low=1, high=20)
    macs = [_random_mac() for _ in range(count)]
    print_table(["#", "mac address"], [(i + 1, mac) for i, mac in enumerate(macs)])
    session.set_result("macs", macs)
    print(f"[INFO] {count} MAC address(es) generated. Stored as 'macs'.")


# ---------------------------------------------------------------------------
# [18] UUID Generator
# ---------------------------------------------------------------------------
def uuid_generator(session: Session) -> None:
    """Generate random (version 4) UUIDs."""
    raw = _ask("How many", "1")
    count = _clamp_int(raw, default=1, low=1, high=100)
    values = [str(uuid.uuid4()) for _ in range(count)]
    print_table(["#", "uuid"], [(i + 1, value) for i, value in enumerate(values)])
    session.set_result("uuids", values)
    print(f"[INFO] {count} UUID(s) generated. Stored as 'uuids'.")


# ---------------------------------------------------------------------------
# [19] String Encoder / Decoder
# ---------------------------------------------------------------------------
def _encode_value(codec: str, text: str) -> str:
    if codec == "base64":
        return base64.b64encode(text.encode("utf-8")).decode("ascii")
    if codec == "hex":
        return text.encode("utf-8").hex()
    if codec == "url":
        return quote(text, safe="")
    raise ValueError(f"unsupported codec: {codec}")


def _decode_value(codec: str, text: str) -> str:
    if codec == "base64":
        # Strip whitespace/newlines: pasted base64 is often wrapped.
        compact = "".join(text.split())
        return base64.b64decode(compact.encode("ascii"), validate=True).decode("utf-8")
    if codec == "hex":
        return bytes.fromhex(text).decode("utf-8")
    if codec == "url":
        return unquote(text)
    raise ValueError(f"unsupported codec: {codec}")


def string_codec(session: Session) -> None:
    """Encode or decode text using base64 / hex / URL encoding."""
    operation = _ask("Operation (encode/decode)", "encode").lower()
    if operation not in ("encode", "decode"):
        print(f"[ERROR] Operation must be 'encode' or 'decode', got '{operation}'.")
        return
    codec = _ask("Codec (base64/hex/url)", "base64").lower()
    if codec not in ("base64", "hex", "url"):
        print("[ERROR] Codec must be one of: base64, hex, url.")
        return
    value = _ask("Input", "")
    if not value:
        print("[ERROR] No input given; aborting.")
        return
    try:
        result = _encode_value(codec, value) if operation == "encode" else _decode_value(codec, value)
    except Exception as exc:
        print(f"[ERROR] Could not {operation} with {codec}: {type(exc).__name__}. "
              "Check that the input is valid.")
        return
    print_table(
        ["field", "value"],
        [("operation", operation), ("codec", codec), ("result", result)],
    )
    session.set_result("codec", {"operation": operation, "codec": codec, "result": result})


# ---------------------------------------------------------------------------
# [20] Session / Target Manager
# ---------------------------------------------------------------------------
def manage_session(session: Session) -> None:
    """Set targets, clear stored results, or inspect the current session."""
    while True:
        print_table(
            ["#", "action"],
            [
                (1, f"set target ip     (current: {session.target_ip or '-'})"),
                (2, f"set target domain (current: {session.target_domain or '-'})"),
                (3, "clear stored results"),
                (4, "show session summary"),
            ],
        )
        try:
            choice = input("  Option [1-4, E=done] : ").strip().lower()
        except EOFError:
            return
        if choice in ("e", "done", ""):
            break
        if choice == "1":
            value = _ask("Target ip", session.target_ip or "")
            session.target_ip = value or session.target_ip
        elif choice == "2":
            value = _ask("Target domain", session.target_domain or "")
            session.target_domain = value or session.target_domain
        elif choice == "3":
            session.clear_results()
            print("[INFO] Stored results cleared.")
        elif choice == "4":
            for line in session.summary():
                print(f"  {line}")
        else:
            print(f"[ERROR] Unknown option '{choice}'.")
