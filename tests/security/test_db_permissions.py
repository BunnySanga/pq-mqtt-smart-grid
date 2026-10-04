"""Codex audit P1-3 (2026-10-03, IMPLEMENTATION-ROADMAP §16): the utility database holds the utility's private keys
(utility_keys) and the STEKs, so every copy of it is owner-only. Before the fix the database was created 0600 but
UtilityDB.backup_to() created its copy with sqlite3's default mode (0644 under umask 022), and nothing checked the
mode of a database, or of a restored backup, when it was opened."""
import os
import stat

import pytest

from pqgrid.persistence.utility_db import UtilityDB


def mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


@pytest.fixture
def permissive_umask():
    old = os.umask(0o000)                                    # the worst case: nothing masked
    yield
    os.umask(old)


def test_a_backup_is_owner_only_whatever_the_umask(tmp_path, permissive_umask):
    db = UtilityDB(str(tmp_path / "u.db"))
    db.execute("INSERT INTO revoked_anchors VALUES (1)")
    db.backup_to(str(tmp_path / "backup.db"))
    assert mode(tmp_path / "u.db") == 0o600
    assert mode(tmp_path / "backup.db") == 0o600              # before the fix: 0666 here (0644 under umask 022)
    db.close()


def test_a_backup_into_an_existing_readable_file_narrows_it_first(tmp_path):
    target = tmp_path / "backup.db"
    target.write_bytes(b"")
    os.chmod(target, 0o644)
    db = UtilityDB(str(tmp_path / "u.db"))
    db.backup_to(str(target))
    assert mode(target) == 0o600
    db.close()


def test_a_database_readable_by_others_is_refused_when_opened(tmp_path):
    path = str(tmp_path / "u.db")
    UtilityDB(path).close()
    os.chmod(path, 0o644)
    with pytest.raises(PermissionError, match="owner-only"):
        UtilityDB(path)                                       # before the fix: opened without a word
    os.chmod(path, 0o600)
    UtilityDB(path).close()


def test_a_restored_backup_readable_by_others_is_refused(tmp_path):
    db = UtilityDB(str(tmp_path / "u.db"))
    db.backup_to(str(tmp_path / "restored.db"))
    db.close()
    os.chmod(tmp_path / "restored.db", 0o640)                 # e.g. copied back with group read
    with pytest.raises(PermissionError, match="owner-only"):
        UtilityDB(str(tmp_path / "restored.db"))


def test_a_readable_wal_file_beside_the_database_is_refused(tmp_path):
    path = str(tmp_path / "u.db")
    db = UtilityDB(path)
    db.execute("INSERT INTO revoked_anchors VALUES (1)")      # the WAL now holds a page of the database
    assert os.path.exists(path + "-wal")
    os.chmod(path + "-wal", 0o644)
    with pytest.raises(PermissionError, match="-wal"):
        UtilityDB(path)
    db.close()
