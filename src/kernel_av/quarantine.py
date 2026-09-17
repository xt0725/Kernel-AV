from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path

from .database import Database


class Quarantine:
    def __init__(self, database: Database, vault: Path):
        self.database = database
        self.vault = vault.resolve()
        self.vault.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            self.vault.chmod(0o700)
        except OSError:
            pass

    def contain(self, source: Path, expected_sha256: str | None = None) -> str:
        original = source.resolve(strict=True)
        if not original.is_file():
            raise ValueError("only regular files can be quarantined")
        item_id = uuid.uuid4().hex
        destination = self.vault / f"{item_id}.quarantine"
        temporary = self.vault / f".{item_id}.partial"
        digest = hashlib.sha256()
        size = 0
        try:
            with original.open("rb") as reader, temporary.open("xb") as writer:
                while chunk := reader.read(1024 * 1024):
                    digest.update(chunk)
                    size += len(chunk)
                    writer.write(chunk)
                writer.flush()
                os.fsync(writer.fileno())
            actual = digest.hexdigest()
            if expected_sha256 and actual != expected_sha256.lower():
                raise ValueError("file changed after scanning; quarantine aborted")
            temporary.chmod(0o000)
            temporary.replace(destination)
            with self.database.connect() as connection:
                connection.execute(
                    "INSERT INTO quarantine(id, original_path, vault_path, sha256, size, quarantined_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (item_id, str(original), str(destination), actual, size, datetime.now(UTC).isoformat()),
                )
            original.unlink()
            return item_id
        except Exception:
            temporary.unlink(missing_ok=True)
            destination.unlink(missing_ok=True)
            raise

    def restore(self, item_id: str, destination: Path | None = None) -> Path:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM quarantine WHERE id = ? AND restored_at IS NULL", (item_id,)
            ).fetchone()
            if row is None:
                raise KeyError("active quarantine item not found")
            vault_path = Path(row["vault_path"]).resolve(strict=True)
            if vault_path.parent != self.vault or not vault_path.is_file():
                raise ValueError("invalid quarantine record")
            target = (destination or Path(row["original_path"])).resolve(strict=False)
            if target.exists():
                raise FileExistsError(f"restore target already exists: {target}")
            target.parent.mkdir(parents=True, exist_ok=True)
            vault_path.chmod(0o600)
            shutil.copy2(vault_path, target)
            if _sha256(target) != row["sha256"]:
                target.unlink(missing_ok=True)
                raise OSError("restored file failed integrity verification")
            connection.execute(
                "UPDATE quarantine SET restored_at = ? WHERE id = ?",
                (datetime.now(UTC).isoformat(), item_id),
            )
            vault_path.unlink()
            return target


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()

