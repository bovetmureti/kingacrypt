"""PQClean-derived implementations via the ``pqcrypto`` package.

Covers all three FIPS 203 and FIPS 204 parameter sets. Secret keys are the
expanded FIPS encodings (e.g. ML-KEM-768 dk = 2400 B), which is what an
operator stores in an HSM or key file.
"""
from __future__ import annotations

import importlib

from .base import KEM, Signature, _identity

_KEM = {"ML-KEM-512": ("ml_kem_512", 1), "ML-KEM-768": ("ml_kem_768", 3), "ML-KEM-1024": ("ml_kem_1024", 5)}
_SIG = {"ML-DSA-44": ("ml_dsa_44", 2), "ML-DSA-65": ("ml_dsa_65", 3), "ML-DSA-87": ("ml_dsa_87", 5)}


def version() -> str:
    from importlib.metadata import version as v
    return f"pqcrypto {v('pqcrypto')}"


def available() -> list[str]:
    importlib.import_module("pqcrypto")
    return list(_KEM) + list(_SIG)


def get(name: str):
    if name in _KEM:
        mod_name, cat = _KEM[name]
        m = importlib.import_module(f"pqcrypto.kem.{mod_name}")
        return KEM(
            name=name, family="pqc", iut="pqcrypto",
            keygen=m.keygen, encaps=m.encaps, decaps=m.decaps,
            encode_pk=_identity, encode_sk=_identity,
            encoding_note="FIPS 203 ek / expanded dk", nist_category=cat,
        )
    if name in _SIG:
        mod_name, cat = _SIG[name]
        m = importlib.import_module(f"pqcrypto.sign.{mod_name}")
        from pqcrypto import InvalidSignatureError  # type: ignore

        def verify(pk, msg, sig):
            try:
                m.verify(pk, msg, sig)
                return True
            except InvalidSignatureError:
                return False

        return Signature(
            name=name, family="pqc", iut="pqcrypto",
            keygen=m.keygen, sign=m.sign, verify=verify,
            encode_pk=_identity, encode_sk=_identity,
            encoding_note="FIPS 204 pk / expanded sk, pure mode, empty context", nist_category=cat,
        )
    raise KeyError(f"pqcrypto backend has no {name}")
