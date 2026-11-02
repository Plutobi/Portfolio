"""Command-line interface: `python -m guardian ...`"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .quarantine import DEFAULT_DIR, Quarantine
from .scanner import Scanner
from .signatures import SignatureDB

DEFAULT_SIGS = Path.home() / ".guardian" / "signatures.json"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="guardian", description="Guardian antivirus scanner")
    p.add_argument("--version", action="version", version=f"guardian {__version__}")
    p.add_argument("--signatures", type=Path, default=DEFAULT_SIGS, help="custom signature JSON file")
    p.add_argument("--quarantine-dir", type=Path, default=DEFAULT_DIR)
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan a file or directory")
    s.add_argument("path", type=Path)
    s.add_argument("--quarantine", action="store_true", help="move detected files into quarantine")
    s.add_argument("--no-heuristics", action="store_true")
    s.add_argument("--json", action="store_true", help="print the report as JSON")
    s.add_argument("--exclude", type=Path, action="append", default=[])

    q = sub.add_parser("quarantine", help="manage quarantined files")
    qs = q.add_subparsers(dest="qcommand", required=True)
    qs.add_parser("list")
    r = qs.add_parser("restore"); r.add_argument("id"); r.add_argument("--to", type=Path)
    d = qs.add_parser("delete"); d.add_argument("id")

    a = sub.add_parser("add-hash", help="add a SHA-256 to the local blocklist")
    a.add_argument("sha256"); a.add_argument("name")

    t = sub.add_parser("selftest", help="write an EICAR file to a temp dir and verify detection")
    return p


def cmd_scan(args) -> int:
    db = SignatureDB.load(args.signatures)
    vault_dir = args.quarantine_dir
    scanner = Scanner(db, use_heuristics=not args.no_heuristics, exclude=[vault_dir, *args.exclude])
    report = scanner.scan(args.path)
    quarantined: dict[Path, str] = {}
    if args.quarantine and report.detections:
        vault = Quarantine(vault_dir)
        for det in report.detections:
            quarantined[det.path] = vault.add(det.path, det.reasons, det.sha256)

    if args.json:
        print(json.dumps({
            "scanned": report.scanned, "skipped": report.skipped, "errors": report.errors,
            "detections": [{"path": str(d.path), "verdict": d.verdict, "severity": d.severity,
                            "reasons": d.reasons, "sha256": d.sha256,
                            "quarantine_id": quarantined.get(d.path)} for d in report.detections],
        }, indent=2))
    else:
        for d in report.detections:
            tag = d.verdict.upper()
            print(f"[{tag}] {d.path}")
            for reason in d.reasons:
                print(f"    - {reason}")
            if d.path in quarantined:
                print(f"    -> quarantined as {quarantined[d.path]}")
        print(f"\nScanned {report.scanned} files, skipped {report.skipped}, "
              f"{len(report.detections)} detection(s).")
        for err in report.errors:
            print(f"  warning: {err}", file=sys.stderr)
    return 0 if report.clean else 1


def cmd_quarantine(args) -> int:
    vault = Quarantine(args.quarantine_dir)
    if args.qcommand == "list":
        items = vault.list()
        for i in items:
            print(f"{i['id']}  {i['quarantined_at']}  {i['original_path']}  ({'; '.join(i['reasons'])})")
        if not items:
            print("Quarantine is empty.")
    elif args.qcommand == "restore":
        print(f"Restored to {vault.restore(args.id, args.to)}")
    elif args.qcommand == "delete":
        vault.delete(args.id)
        print(f"Deleted {args.id}")
    return 0


def cmd_add_hash(args) -> int:
    db = SignatureDB.load(args.signatures)
    db.add_hash(args.sha256, args.name)
    args.signatures.parent.mkdir(parents=True, exist_ok=True)
    db.save(args.signatures)
    print(f"Added {args.sha256.lower()} as {args.name}")
    return 0


def cmd_selftest(args) -> int:
    import tempfile
    from .signatures import EICAR
    with tempfile.TemporaryDirectory() as tmp:
        f = Path(tmp) / "eicar.com.txt"
        f.write_bytes(EICAR)
        report = Scanner(SignatureDB(), exclude=[args.quarantine_dir]).scan(f)
    ok = len(report.detections) == 1
    print("selftest passed: EICAR detected" if ok else "selftest FAILED: EICAR not detected")
    return 0 if ok else 2


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handler = {"scan": cmd_scan, "quarantine": cmd_quarantine,
               "add-hash": cmd_add_hash, "selftest": cmd_selftest}[args.command]
    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
