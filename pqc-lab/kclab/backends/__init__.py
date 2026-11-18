"""Registry of implementation-under-test adapters."""
from __future__ import annotations

import importlib

BACKENDS = {
    "pqcrypto": "kclab.backends.pqcrypto_backend",
    "openssl": "kclab.backends.openssl_backend",
    "oqs": "kclab.backends.oqs_backend",
}


def module(backend: str):
    if backend not in BACKENDS:
        raise KeyError(f"unknown backend {backend!r}; choose from {sorted(BACKENDS)}")
    return importlib.import_module(BACKENDS[backend])


def get(backend: str, algorithm: str):
    return module(backend).get(algorithm)


def version(backend: str) -> str:
    try:
        return module(backend).version()
    except BaseException as e:  # missing optional dependency
        return f"unavailable ({type(e).__name__})"


def available(backend: str) -> list[str]:
    try:
        return module(backend).available()
    except BaseException:
        return []
