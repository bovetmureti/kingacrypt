"""OpenSSL (via pyca/cryptography): classical baselines and a PQC cross-check.

Secret-key encodings: ML-KEM / ML-DSA are reported as the 64/32-byte FIPS
seed (what OpenSSL serialises raw); classical keys use their raw scalar or
PKCS#1 DER form as noted per algorithm.
"""
from __future__ import annotations

import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, x25519

from .base import KEM, Signature

_RAW = (ser.Encoding.Raw, ser.PublicFormat.Raw)
_RAW_SK = (ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())


def version() -> str:
    import cryptography
    from cryptography.hazmat.backends.openssl import backend
    return f"pyca/cryptography {cryptography.__version__} / {backend.openssl_version_text()}"


# ----------------------------------------------------------------- PQC (cross-check)
def _mlkem(name, cls_name, cat):
    from cryptography.hazmat.primitives.asymmetric import mlkem
    cls = getattr(mlkem, cls_name)

    def keygen():
        sk = cls.generate()
        return sk.public_key(), sk

    def encaps(pk):
        ss, ct = pk.encapsulate()
        return ct, ss

    return KEM(name, "pqc", "openssl", keygen, encaps, lambda sk, ct: sk.decapsulate(ct),
               lambda pk: pk.public_bytes_raw(), lambda sk: sk.private_bytes_raw(),
               "FIPS 203 ek / 64-byte seed dk", cat)


def _mldsa(name, cls_name, cat):
    from cryptography.hazmat.primitives.asymmetric import mldsa
    cls = getattr(mldsa, cls_name)

    def keygen():
        sk = cls.generate()
        return sk.public_key(), sk

    def verify(pk, msg, sig):
        try:
            pk.verify(sig, msg)
            return True
        except InvalidSignature:
            return False

    return Signature(name, "pqc", "openssl", keygen, lambda sk, m: sk.sign(m), verify,
                     lambda pk: pk.public_bytes_raw(), lambda sk: sk.private_bytes_raw(),
                     "FIPS 204 pk / 32-byte seed sk", cat)


# ----------------------------------------------------------------- classical, KEM-shaped
def _x25519():
    def keygen():
        sk = x25519.X25519PrivateKey.generate()
        return sk.public_key(), sk

    def encaps(pk):
        eph = x25519.X25519PrivateKey.generate()
        return eph.public_key().public_bytes(*_RAW), eph.exchange(pk)

    def decaps(sk, ct):
        return sk.exchange(x25519.X25519PublicKey.from_public_bytes(ct))

    return KEM("X25519", "classical", "openssl", keygen, encaps, decaps,
               lambda pk: pk.public_bytes(*_RAW), lambda sk: sk.private_bytes(*_RAW_SK),
               "raw 32-byte keys; ct = ephemeral pk (DHKEM shape)", 1)


def _ecdh(name, curve, cat):
    pt = (ser.Encoding.X962, ser.PublicFormat.UncompressedPoint)
    nbytes = (curve().key_size + 7) // 8

    def keygen():
        sk = ec.generate_private_key(curve())
        return sk.public_key(), sk

    def encaps(pk):
        eph = ec.generate_private_key(curve())
        return eph.public_key().public_bytes(*pt), eph.exchange(ec.ECDH(), pk)

    def decaps(sk, ct):
        peer = ec.EllipticCurvePublicKey.from_encoded_point(curve(), ct)
        return sk.exchange(ec.ECDH(), peer)

    return KEM(name, "classical", "openssl", keygen, encaps, decaps,
               lambda pk: pk.public_bytes(*pt),
               lambda sk: sk.private_numbers().private_value.to_bytes(nbytes, "big"),
               "uncompressed SEC1 point; sk = raw scalar; ct = ephemeral pk", cat)


_OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH)
_PKCS1_PUB = (ser.Encoding.DER, ser.PublicFormat.PKCS1)
_PKCS1_SK = (ser.Encoding.DER, ser.PrivateFormat.TraditionalOpenSSL, ser.NoEncryption())


def _rsa_keygen(bits):
    def keygen():
        sk = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        return sk.public_key(), sk
    return keygen


def _rsa_oaep(name, bits):
    def encaps(pk):
        ss = os.urandom(32)
        return pk.encrypt(ss, _OAEP), ss

    return KEM(name, "classical", "openssl", _rsa_keygen(bits), encaps,
               lambda sk, ct: sk.decrypt(ct, _OAEP),
               lambda pk: pk.public_bytes(*_PKCS1_PUB), lambda sk: sk.private_bytes(*_PKCS1_SK),
               "PKCS#1 DER keys; key transport of 32-byte secret, OAEP-SHA256", None)


# ----------------------------------------------------------------- classical signatures
def _sig_verify(fn):
    def verify(pk, msg, sig):
        try:
            fn(pk, msg, sig)
            return True
        except InvalidSignature:
            return False
    return verify


def _ed25519():
    def keygen():
        sk = ed25519.Ed25519PrivateKey.generate()
        return sk.public_key(), sk
    return Signature("Ed25519", "classical", "openssl", keygen, lambda sk, m: sk.sign(m),
                     _sig_verify(lambda pk, m, s: pk.verify(s, m)),
                     lambda pk: pk.public_bytes(*_RAW), lambda sk: sk.private_bytes(*_RAW_SK),
                     "raw 32-byte keys", 1)


def _ecdsa(name, curve, h, cat):
    pt = (ser.Encoding.X962, ser.PublicFormat.UncompressedPoint)
    nbytes = (curve().key_size + 7) // 8

    def keygen():
        sk = ec.generate_private_key(curve())
        return sk.public_key(), sk
    return Signature(name, "classical", "openssl", keygen, lambda sk, m: sk.sign(m, ec.ECDSA(h())),
                     _sig_verify(lambda pk, m, s: pk.verify(s, m, ec.ECDSA(h()))),
                     lambda pk: pk.public_bytes(*pt),
                     lambda sk: sk.private_numbers().private_value.to_bytes(nbytes, "big"),
                     f"SEC1 point; DER signature; {h.name.upper()}", cat)


def _rsa_pss(name, bits):
    return Signature(name, "classical", "openssl", _rsa_keygen(bits),
                     lambda sk, m: sk.sign(m, _PSS, hashes.SHA256()),
                     _sig_verify(lambda pk, m, s: pk.verify(s, m, _PSS, hashes.SHA256())),
                     lambda pk: pk.public_bytes(*_PKCS1_PUB), lambda sk: sk.private_bytes(*_PKCS1_SK),
                     "PKCS#1 DER keys; PSS-SHA256", None)


_REGISTRY = {
    "ML-KEM-768": lambda: _mlkem("ML-KEM-768", "MLKEM768PrivateKey", 3),
    "ML-KEM-1024": lambda: _mlkem("ML-KEM-1024", "MLKEM1024PrivateKey", 5),
    "ML-DSA-44": lambda: _mldsa("ML-DSA-44", "MLDSA44PrivateKey", 2),
    "ML-DSA-65": lambda: _mldsa("ML-DSA-65", "MLDSA65PrivateKey", 3),
    "ML-DSA-87": lambda: _mldsa("ML-DSA-87", "MLDSA87PrivateKey", 5),
    "X25519": _x25519,
    "ECDH-P256": lambda: _ecdh("ECDH-P256", ec.SECP256R1, 1),
    "ECDH-P384": lambda: _ecdh("ECDH-P384", ec.SECP384R1, 3),
    "RSA-2048-OAEP": lambda: _rsa_oaep("RSA-2048-OAEP", 2048),
    "RSA-3072-OAEP": lambda: _rsa_oaep("RSA-3072-OAEP", 3072),
    "Ed25519": _ed25519,
    "ECDSA-P256": lambda: _ecdsa("ECDSA-P256", ec.SECP256R1, hashes.SHA256, 1),
    "ECDSA-P384": lambda: _ecdsa("ECDSA-P384", ec.SECP384R1, hashes.SHA384, 3),
    "RSA-2048-PSS": lambda: _rsa_pss("RSA-2048-PSS", 2048),
    "RSA-3072-PSS": lambda: _rsa_pss("RSA-3072-PSS", 3072),
}


def available() -> list[str]:
    out = []
    for n, f in _REGISTRY.items():
        try:
            f()
            out.append(n)
        except Exception:  # algorithm not compiled into this OpenSSL build
            pass
    return out


def get(name: str):
    if name not in _REGISTRY:
        raise KeyError(f"openssl backend has no {name}")
    return _REGISTRY[name]()
