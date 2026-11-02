"""Heuristic checks that flag suspicious files without a matching signature."""
from __future__ import annotations

import math
from collections import Counter
from pathlib import Path

EXEC_EXTENSIONS = {".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".msi", ".ps1",
                   ".vbs", ".js", ".jar", ".sh", ".elf", ".so", ".app"}
DOCUMENT_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
                       ".txt", ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".zip"}
# Packed or encrypted payloads usually sit above this Shannon entropy (bits per byte).
HIGH_ENTROPY = 7.4

MAGIC = {
    b"MZ": "Windows PE executable",
    b"\x7fELF": "ELF executable",
    b"\xcf\xfa\xed\xfe": "Mach-O executable",
    b"\xca\xfe\xba\xbe": "Mach-O/Java class",
}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def executable_kind(head: bytes) -> str | None:
    for magic, kind in MAGIC.items():
        if head.startswith(magic):
            return kind
    return None


def analyse(path: Path, head: bytes, sample: bytes) -> list[tuple[str, int]]:
    """Return a list of (reason, score) findings for one file."""
    findings: list[tuple[str, int]] = []
    suffixes = [s.lower() for s in path.suffixes]
    ext = suffixes[-1] if suffixes else ""

    if len(suffixes) >= 2 and suffixes[-1] in EXEC_EXTENSIONS and suffixes[-2] in DOCUMENT_EXTENSIONS:
        findings.append((f"double extension '{''.join(suffixes[-2:])}' disguises an executable", 50))

    kind = executable_kind(head)
    if kind and ext in DOCUMENT_EXTENSIONS:
        findings.append((f"{kind} content inside a '{ext}' file", 60))

    if kind and len(sample) >= 4096 and shannon_entropy(sample) >= HIGH_ENTROPY:
        findings.append((f"high-entropy {kind} (likely packed or encrypted)", 30))

    if ext in {".bat", ".cmd", ".ps1", ".vbs", ".js", ".sh"} and len(sample) >= 2048:
        text = sample.decode("latin-1")
        longest = max((len(line) for line in text.splitlines()), default=0)
        if longest > 4000:
            findings.append(("script with extremely long line (likely obfuscated)", 25))

    return findings
