"""Plain files are replaced atomically (Master §16 "fsync / atomic rename"): write a temporary file in the same
directory, fsync it, rename it over the target, fsync the directory. Never open(path, "w") on the live file:
a crash then leaves either the old file or the new one, never a torn mix (the v2.1 S3 failure)."""
from __future__ import annotations

import os
import tempfile


def atomic_write(path: str, data: bytes, mode: int = 0o600) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-")
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fchmod(fd, mode)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(tmp, path)
    except BaseException:
        if fd >= 0:
            os.close(fd)
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    dfd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
