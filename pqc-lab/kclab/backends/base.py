"""Uniform interface every implementation-under-test (IUT) adapter exposes.

KEMs follow the FIPS 203 shape (KeyGen / Encaps / Decaps). Classical key
agreement is wrapped into the same shape the way DHKEM (RFC 9180) does it:
Encaps = fresh ephemeral key + DH with the recipient's static key, with the
ephemeral public key serving as the "ciphertext". RSA-OAEP is wrapped as key
transport of a random 32-byte secret. This keeps T1-T5 comparable row by row.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass
class KEM:
    name: str
    family: str                       # "pqc" | "classical"
    iut: str                          # backend id, e.g. "pqcrypto", "openssl"
    keygen: Callable[[], tuple[Any, Any]]
    encaps: Callable[[Any], tuple[bytes, bytes]]          # pk -> (ct, ss)
    decaps: Callable[[Any, bytes], bytes]                 # (sk, ct) -> ss
    encode_pk: Callable[[Any], bytes]
    encode_sk: Callable[[Any], bytes]
    encoding_note: str = ""
    nist_category: int | None = None
    kind: str = "kem"


@dataclass
class Signature:
    name: str
    family: str
    iut: str
    keygen: Callable[[], tuple[Any, Any]]
    sign: Callable[[Any, bytes], bytes]                   # (sk, msg) -> sig
    verify: Callable[[Any, bytes, bytes], bool]           # (pk, msg, sig) -> ok
    encode_pk: Callable[[Any], bytes]
    encode_sk: Callable[[Any], bytes]
    encoding_note: str = ""
    nist_category: int | None = None
    kind: str = "sig"


def _identity(b: bytes) -> bytes:
    return b
