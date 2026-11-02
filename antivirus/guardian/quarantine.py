"""Quarantine vault: isolates detected files and allows restore or purge."""
from __future__ import annotations

import json
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DIR = Path.home() / ".guardian" / "quarantine"


class Quarantine:
    def __init__(self, directory: Path | None = None) -> None:
        self.dir = Path(directory or DEFAULT_DIR)
        self.dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)

    def _meta(self, item_id: str) -> Path:
        return self.dir / f"{item_id}.json"

    def _blob(self, item_id: str) -> Path:
        return self.dir / f"{item_id}.quar"

    def add(self, path: Path, reasons: list[str], sha256: str) -> str:
        path = Path(path).resolve()
        item_id = uuid.uuid4().hex[:12]
        shutil.move(str(path), self._blob(item_id))
        os.chmod(self._blob(item_id), 0o600)  # strip execute bits
        self._meta(item_id).write_text(json.dumps({
            "id": item_id,
            "original_path": str(path),
            "reasons": reasons,
            "sha256": sha256,
            "quarantined_at": datetime.now(timezone.utc).isoformat(),
        }, indent=2), encoding="utf-8")
        return item_id

    def list(self) -> list[dict]:
        items = [json.loads(p.read_text(encoding="utf-8")) for p in self.dir.glob("*.json")]
        return sorted(items, key=lambda i: i["quarantined_at"])

    def restore(self, item_id: str, destination: Path | None = None) -> Path:
        meta = json.loads(self._meta(item_id).read_text(encoding="utf-8"))
        target = Path(destination or meta["original_path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            raise FileExistsError(f"{target} already exists")
        shutil.move(str(self._blob(item_id)), target)
        self._meta(item_id).unlink()
        return target

    def delete(self, item_id: str) -> None:
        self._blob(item_id).unlink(missing_ok=True)
        self._meta(item_id).unlink(missing_ok=True)
