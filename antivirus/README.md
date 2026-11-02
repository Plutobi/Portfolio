# Guardian

A dependency-free antivirus scanner written in Python 3.10+.

## Features

- SHA-256 hash blocklist and byte-pattern signatures (PowerShell droppers, reverse shells, pipe-to-shell installers, obfuscated JS/Python loaders, ransomware notes, EICAR)
- Heuristics: double extensions, executables disguised as documents, packed high-entropy binaries, obfuscated scripts
- Streaming scan engine with chunk-boundary matching
- Quarantine vault with list, restore, and delete
- JSON reports and exit codes for CI (`0` clean, `1` detections)

## Usage

```bash
python -m guardian selftest                       # verify detection using the EICAR test string
python -m guardian scan ~/Downloads               # scan a directory
python -m guardian scan ~/Downloads --quarantine  # isolate detections
python -m guardian scan file.bin --json           # machine-readable output
python -m guardian quarantine list
python -m guardian quarantine restore <id>
python -m guardian add-hash <sha256> Family.Name  # extend the blocklist
```

Run from the `antivirus/` directory. Custom signatures live in `~/.guardian/signatures.json`:

```json
{"hashes": {"<sha256>": "Name"},
 "patterns": [{"name": "My.Rule", "regex": "evil\\.example\\.com", "severity": "medium"}]}
```

## Tests

```bash
python -m unittest discover -s tests -v
```

## Limits

Guardian is a static scanner. It does not provide real-time protection, memory scanning, or behavioral analysis, and its signature set is small. Pair it with an OS-level security product for production defence.
