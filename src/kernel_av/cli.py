from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .database import Database
from .quarantine import Quarantine
from .scanner import Scanner
from .yara_engine import YaraEngine


def _defaults() -> tuple[Path, Path]:
    root = Path(os.environ.get("KERNEL_AV_HOME", Path.home() / ".kernel-av"))
    return root / "kernel-av.db", root / "quarantine"


def parser() -> argparse.ArgumentParser:
    default_db, default_vault = _defaults()
    command = argparse.ArgumentParser(prog="kernel-av", description="Kernel-AV defensive scanner")
    command.add_argument("--database", type=Path, default=default_db)
    sub = command.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan one file")
    scan.add_argument("path", type=Path)
    scan.add_argument("--rules", type=Path, default=Path("rules"))

    signature = sub.add_parser("add-signature", help="add a malicious SHA-256")
    signature.add_argument("sha256")
    signature.add_argument("family")
    signature.add_argument("--source", default="local")

    quarantine = sub.add_parser("quarantine", help="move a file into containment")
    quarantine.add_argument("path", type=Path)
    quarantine.add_argument("--sha256")
    quarantine.add_argument("--vault", type=Path, default=default_vault)

    restore = sub.add_parser("restore", help="restore one quarantined item")
    restore.add_argument("id")
    restore.add_argument("--to", type=Path)
    restore.add_argument("--vault", type=Path, default=default_vault)
    return command


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    database = Database(args.database)
    if args.command == "scan":
        engine = YaraEngine(args.rules)
        result = Scanner(database, engine).scan_file(args.path)
        payload = result.as_dict()
        if engine.error:
            payload["yara_warning"] = engine.error
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return {"clean": 0, "suspicious": 10, "malicious": 20, "error": 30}[result.verdict.value]
    if args.command == "add-signature":
        database.add_signature(args.sha256, args.family, args.source)
        return 0
    if args.command == "quarantine":
        item_id = Quarantine(database, args.vault).contain(args.path, args.sha256)
        print(item_id)
        return 0
    if args.command == "restore":
        restored = Quarantine(database, args.vault).restore(args.id, args.to)
        print(restored)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

