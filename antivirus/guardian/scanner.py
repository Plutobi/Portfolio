"""File and directory scanning engine."""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Iterator

from . import heuristics
from .signatures import SignatureDB

MAX_READ = 32 * 1024 * 1024  # bytes inspected for pattern matching per file
CHUNK = 1024 * 1024
OVERLAP = 512  # carry-over so patterns spanning chunk borders still match
HEURISTIC_THRESHOLD = 50


@dataclass
class Detection:
    path: Path
    verdict: str  # "malicious" | "suspicious"
    reasons: list[str]
    sha256: str
    severity: str = "high"


@dataclass
class ScanReport:
    scanned: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)
    detections: list[Detection] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.detections


class Scanner:
    def __init__(self, db: SignatureDB | None = None, use_heuristics: bool = True,
                 exclude: Iterable[Path] = ()) -> None:
        self.db = db or SignatureDB()
        self.use_heuristics = use_heuristics
        # The engine's own package holds signature text, so it is skipped by default.
        self.exclude = [Path(e).resolve() for e in exclude] + [Path(__file__).resolve().parent]

    def _excluded(self, path: Path) -> bool:
        resolved = path.resolve()
        return any(resolved == e or e in resolved.parents for e in self.exclude)

    def iter_files(self, root: Path) -> Iterator[Path]:
        root = Path(root)
        if root.is_file():
            yield root
            return
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames if not self._excluded(Path(dirpath) / d)]
            for name in filenames:
                p = Path(dirpath) / name
                if not p.is_symlink() and not self._excluded(p):
                    yield p

    def scan_file(self, path: Path) -> Detection | None:
        sha = hashlib.sha256()
        matched: dict[str, str] = {}
        head = b""
        sample = b""
        read = 0
        tail = b""
        with open(path, "rb") as fh:
            while read < MAX_READ:
                chunk = fh.read(CHUNK)
                if not chunk:
                    break
                if not head:
                    head = chunk[:16]
                    sample = chunk[:65536]
                sha.update(chunk)
                window = tail + chunk
                for sig in self.db.patterns:
                    if sig.name not in matched and sig.pattern.search(window):
                        matched[sig.name] = sig.severity
                tail = chunk[-OVERLAP:]
                read += len(chunk)
            # hash the remainder so hash signatures cover the whole file
            while True:
                chunk = fh.read(CHUNK)
                if not chunk:
                    break
                sha.update(chunk)
        digest = sha.hexdigest()

        reasons: list[str] = []
        severities: list[str] = []
        if digest in self.db.hashes:
            reasons.append(f"hash match: {self.db.hashes[digest]}")
            severities.append("high")
        for name, sev in matched.items():
            reasons.append(f"pattern match: {name}")
            severities.append(sev)
        if reasons:
            rank = {"low": 0, "medium": 1, "high": 2}
            return Detection(path, "malicious", reasons, digest, max(severities, key=rank.get))

        if self.use_heuristics:
            findings = heuristics.analyse(path, head, sample)
            if sum(score for _, score in findings) >= HEURISTIC_THRESHOLD:
                return Detection(path, "suspicious", [r for r, _ in findings], digest, "medium")
        return None

    def scan(self, root: Path, on_file: Callable[[Path], None] | None = None) -> ScanReport:
        report = ScanReport()
        for path in self.iter_files(root):
            if on_file:
                on_file(path)
            try:
                det = self.scan_file(path)
            except (OSError, PermissionError) as exc:
                report.skipped += 1
                report.errors.append(f"{path}: {exc}")
                continue
            report.scanned += 1
            if det:
                report.detections.append(det)
        return report
