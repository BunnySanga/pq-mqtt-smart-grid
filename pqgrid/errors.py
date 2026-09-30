"""Exception types. Each failure class is distinct so callers can fail closed without string matching.

Messages are for local logs only; peers are told nothing more than "refused" (Master §27.7 G-1).
"""


class PqgridError(Exception):
    """Base class for every error raised by pqgrid."""


class WireError(PqgridError, ValueError):
    """Malformed encoding: wrong field count, oversized length, trailing bytes (Master §12, I-21)."""


class CryptoError(PqgridError):
    """A primitive rejected its input: bad length, failed tag, failed signature, missing backend."""


class PolicyError(PqgridError, ValueError):
    """A policy failed decoding or one of the validator rules (Master §12)."""


class HandshakeError(PqgridError):
    """The E2E handshake must abort (Master §9.4). Never downgrades; the caller starts over."""


class ReplayError(PqgridError):
    """A sequence number was not newer than the last accepted one (Master §9.6, I-7)."""


class EnvelopeError(PqgridError, ValueError):
    """An application envelope was refused: wrong tier, wrong owner, unknown session, bad tag."""


class PolicyMismatchError(HandshakeError):
    """A client hello under an older POLICY_INFO: refused (G-1), and the utility republishes its policy (E-4)."""


class TicketError(HandshakeError):
    """A resumption ticket failed one of the 9 checks (Master §14.5): the device must do a full handshake."""


class TicketReusedError(TicketError):
    """A valid ticket was presented a second time (check 9): a clone or a rebuilt RH (E-P5, S5). Alarm on it."""


class CapacityError(PqgridError):
    """The configured storage cannot hold the documented worst case: an impossible configuration, refused
    explicitly at start-up (or when a new policy would require more)."""


class CommandError(PqgridError):
    """The utility refuses to issue a CONTROL message (class not allowed, no live session, bounds, …)."""
