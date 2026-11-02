import json
import os
import sys
import unittest
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from guardian.cli import main
from guardian.heuristics import shannon_entropy
from guardian.quarantine import Quarantine
from guardian.scanner import Scanner
from guardian.signatures import EICAR, SignatureDB


class GuardianTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.scan_dir = self.root / "scan"
        self.scan_dir.mkdir()
        self.vault_dir = self.root / "vault"

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, name, data):
        p = self.scan_dir / name
        p.write_bytes(data)
        return p

    def test_clean_files_pass(self):
        self.write("notes.txt", b"hello world")
        report = Scanner().scan(self.scan_dir)
        self.assertTrue(report.clean)
        self.assertEqual(report.scanned, 1)

    def test_eicar_detected_by_pattern_and_hash(self):
        self.write("eicar.txt", EICAR)
        det = Scanner().scan(self.scan_dir).detections[0]
        self.assertEqual(det.verdict, "malicious")
        self.assertTrue(any("hash match" in r for r in det.reasons))
        self.assertTrue(any("pattern match" in r for r in det.reasons))

    def test_pattern_spanning_chunk_boundary(self):
        import guardian.scanner as sc
        old = sc.CHUNK
        sc.CHUNK = 64
        try:
            self.write("big.bin", b"A" * 50 + EICAR + b"B" * 200)
            self.assertEqual(len(Scanner().scan(self.scan_dir).detections), 1)
        finally:
            sc.CHUNK = old

    def test_powershell_encoded_command(self):
        self.write("a.ps1", b"powershell -enc " + b"QUJD" * 20)
        det = Scanner().scan(self.scan_dir).detections[0]
        self.assertIn("pattern match: Script.PowerShell.EncodedCommand", det.reasons)

    def test_double_extension_heuristic(self):
        self.write("invoice.pdf.exe", b"MZ" + b"\x00" * 100)
        det = Scanner().scan(self.scan_dir).detections[0]
        self.assertEqual(det.verdict, "suspicious")
        self.assertTrue(Scanner(use_heuristics=False).scan(self.scan_dir).clean)

    def test_executable_disguised_as_document(self):
        self.write("photo.jpg", b"\x7fELF" + b"\x00" * 100)
        self.assertEqual(len(Scanner().scan(self.scan_dir).detections), 1)

    def test_custom_hash_signature(self):
        import hashlib
        data = b"custom-malware-sample"
        self.write("x.bin", data)
        db = SignatureDB({hashlib.sha256(data).hexdigest(): "Custom.Sample"})
        self.assertIn("hash match: Custom.Sample", Scanner(db).scan(self.scan_dir).detections[0].reasons)

    def test_entropy(self):
        self.assertEqual(shannon_entropy(b""), 0.0)
        self.assertAlmostEqual(shannon_entropy(bytes(range(256)) * 4), 8.0)

    def test_quarantine_roundtrip(self):
        f = self.write("eicar.txt", EICAR)
        rc = main(["--quarantine-dir", str(self.vault_dir), "scan", str(self.scan_dir), "--quarantine"])
        self.assertEqual(rc, 1)
        self.assertFalse(f.exists())
        vault = Quarantine(self.vault_dir)
        (item,) = vault.list()
        self.assertEqual(vault.restore(item["id"]), f.resolve())
        self.assertTrue(f.exists())
        self.assertEqual(vault.list(), [])

    def test_quarantine_dir_excluded_from_scan(self):
        self.vault_dir.mkdir()
        (self.vault_dir / "old.quar").write_bytes(EICAR)
        report = Scanner(exclude=[self.vault_dir]).scan(self.root)
        self.assertTrue(report.clean)
        self.assertEqual(report.scanned, 0)
        self.assertFalse(Scanner().scan(self.root).clean)

    def test_exit_codes_and_selftest(self):
        self.write("ok.txt", b"fine")
        self.assertEqual(main(["--quarantine-dir", str(self.vault_dir), "scan", str(self.scan_dir)]), 0)
        self.assertEqual(main(["--quarantine-dir", str(self.vault_dir), "selftest"]), 0)

    def test_add_hash_persists(self):
        sigs = self.root / "sigs.json"
        main(["--signatures", str(sigs), "add-hash", "AB" * 32, "Bad.Thing"])
        data = json.loads(sigs.read_text())
        self.assertEqual(data["hashes"]["ab" * 32], "Bad.Thing")
        self.assertIn("ab" * 32, SignatureDB.load(sigs).hashes)


if __name__ == "__main__":
    unittest.main()
