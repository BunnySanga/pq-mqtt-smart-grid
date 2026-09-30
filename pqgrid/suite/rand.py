"""The single randomness entry point (Master §7.13, requirement D-8).

On the prototype host this is the operating system CSPRNG. A device port replaces this one function with
its hardware TRNG seeding an SP 800-90A DRBG, seeded before the first handshake.
"""
import os


def random_bytes(n: int) -> bytes:
    return os.urandom(n)
