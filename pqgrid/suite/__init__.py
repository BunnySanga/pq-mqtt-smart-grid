"""Cryptographic primitives only (Master §6, §7). No protocol logic lives here.

Algorithms are fixed by the design: X25519 + ML-KEM-768 (X-Wing), AES-256-GCM or ChaCha20-Poly1305 by
device class, HKDF/HMAC/SHA-256, SHA3-256, ML-DSA-65, SLH-DSA-SHA2-128s.
"""
