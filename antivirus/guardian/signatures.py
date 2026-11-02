"""Signature database: SHA-256 hashes and byte-pattern signatures."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

# Standard EICAR antivirus test string (harmless, recognised by all scanners).
# Stored in two halves so this source file does not match the signature itself.
EICAR = (rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-"
         rb"STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


@dataclass(frozen=True)
class PatternSignature:
    name: str
    pattern: re.Pattern[bytes]
    severity: str = "high"


def _p(name: str, regex: bytes, severity: str = "high") -> PatternSignature:
    return PatternSignature(name, re.compile(regex, re.IGNORECASE | re.DOTALL), severity)


BUILTIN_PATTERNS: list[PatternSignature] = [
    _p("Test.EICAR", re.escape(EICAR), "high"),
    _p("Script.PowerShell.EncodedCommand", rb"powershell[^\n]{0,80}-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}", "high"),
    _p("Script.PowerShell.DownloadExec", rb"(iex|invoke-expression)[^\n]{0,120}(downloadstring|net\.webclient|invoke-webrequest)", "high"),
    _p("Script.Shell.PipeToShell", rb"(curl|wget)[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z)?sh\b", "medium"),
    _p("Script.Shell.ReverseShell", rb"(bash\s+-i\s+>&\s*/dev/tcp/|nc\s+(-e|-c)\s+/bin/(ba)?sh)", "high"),
    _p("Script.VBS.WScriptShell", rb"CreateObject\(\s*[\"']WScript\.Shell[\"']\s*\)[^\n]{0,200}\.Run", "medium"),
    _p("Script.JS.EvalObfuscation", rb"eval\(\s*(unescape|atob|String\.fromCharCode)\(", "medium"),
    _p("Script.Python.ExecDecode", rb"exec\(\s*(base64\.b64decode|zlib\.decompress|codecs\.decode)\(", "medium"),
    _p("Ransomware.Note.Keywords", rb"(your files (have been|are) encrypted).{0,300}(bitcoin|btc|monero|decrypt)", "high"),
]


class SignatureDB:
    def __init__(self, hashes: dict[str, str] | None = None,
                 patterns: list[PatternSignature] | None = None) -> None:
        self.hashes: dict[str, str] = {EICAR_SHA256: "Test.EICAR"}
        self.hashes.update(hashes or {})
        self.patterns = list(BUILTIN_PATTERNS) + list(patterns or [])

    @classmethod
    def load(cls, path: Path | None) -> "SignatureDB":
        """Load extra signatures from a JSON file.

        Format: {"hashes": {"<sha256>": "Name"}, "patterns": [{"name": "...", "regex": "...", "severity": "high"}]}
        """
        if path is None or not Path(path).exists():
            return cls()
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        hashes = {h.lower(): n for h, n in data.get("hashes", {}).items()}
        patterns = [
            _p(p["name"], p["regex"].encode(), p.get("severity", "high"))
            for p in data.get("patterns", [])
        ]
        return cls(hashes, patterns)

    def add_hash(self, sha256: str, name: str) -> None:
        self.hashes[sha256.lower()] = name

    def save(self, path: Path) -> None:
        builtin_names = {p.name for p in BUILTIN_PATTERNS}
        out = {
            "hashes": {h: n for h, n in self.hashes.items() if h != EICAR_SHA256},
            "patterns": [
                {"name": p.name, "regex": p.pattern.pattern.decode("latin-1"), "severity": p.severity}
                for p in self.patterns if p.name not in builtin_names
            ],
        }
        Path(path).write_text(json.dumps(out, indent=2), encoding="utf-8")
