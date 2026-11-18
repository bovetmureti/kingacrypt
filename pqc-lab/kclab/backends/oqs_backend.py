"""liboqs via liboqs-python (``import oqs``): the protocol's suggested
"liboqs-family" IUT. Optional: needs a liboqs shared library on the host
(straightforward on Linux; see docs/REPRODUCE.md)."""
from __future__ import annotations

from .base import KEM, Signature, _identity

_CAT = {"ML-KEM-512": 1, "ML-KEM-768": 3, "ML-KEM-1024": 5, "ML-DSA-44": 2, "ML-DSA-65": 3, "ML-DSA-87": 5}


def version() -> str:
    import oqs
    return f"liboqs {oqs.oqs_version()} / liboqs-python {oqs.oqs_python_version()}"


def available() -> list[str]:
    try:
        import oqs
    except BaseException:  # liboqs-python may try to build liboqs and exit
        return []
    enabled = set(oqs.get_enabled_kem_mechanisms()) | set(oqs.get_enabled_sig_mechanisms())
    return [n for n in _CAT if n in enabled]


def get(name: str):
    import oqs
    if name.startswith("ML-KEM"):
        def keygen():
            k = oqs.KeyEncapsulation(name)
            pk = k.generate_keypair()
            return pk, k                                   # the object holds sk

        def encaps(pk):
            with oqs.KeyEncapsulation(name) as k:
                return k.encap_secret(pk)

        return KEM(name, "pqc", "oqs", keygen, encaps, lambda k, ct: k.decap_secret(ct),
                   _identity, lambda k: k.export_secret_key(),
                   "FIPS 203 ek / expanded dk", _CAT[name])
    if name.startswith("ML-DSA"):
        def keygen():
            s = oqs.Signature(name)
            pk = s.generate_keypair()
            return pk, s

        def verify(pk, msg, sig):
            with oqs.Signature(name) as v:
                return bool(v.verify(msg, sig, pk))

        return Signature(name, "pqc", "oqs", keygen, lambda s, m: s.sign(m), verify,
                         _identity, lambda s: s.export_secret_key(),
                         "FIPS 204 pk / expanded sk", _CAT[name])
    raise KeyError(f"oqs backend has no {name}")
