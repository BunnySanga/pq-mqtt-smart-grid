"""Two-phase replay guard (Master §9.6, invariant I-7).

`validate` runs before AEAD decryption, `accept` only after it succeeds, so a forged envelope can never
consume a valid sequence number.
"""
from ..errors import ReplayError


class ReplayGuard:
    def __init__(self):
        self.highest = 0

    def validate(self, seq: int) -> None:
        if seq <= self.highest:
            raise ReplayError(f"sequence {seq} not newer than {self.highest}")

    def accept(self, seq: int) -> None:
        self.validate(seq)
        self.highest = seq
