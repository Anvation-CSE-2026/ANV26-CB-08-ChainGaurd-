"""Prototype connector for fictional FastAPI applications."""

from .middleware import ChainGuardMiddleware, fingerprint_identifier

__all__ = ["ChainGuardMiddleware", "fingerprint_identifier"]
