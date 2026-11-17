import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OLD = "a" * 32
NEW = "b" * 32
SLUG = "-DEMO"


class ReleaseChecks(unittest.TestCase):
    def test_repair_preserves_input_and_unrelated_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / (OLD + SLUG)
            root.mkdir()
            (root / "task.toml").write_text(f'[task]\nname = "demo/{OLD}{SLUG}"\n')
            unrelated = root / "payload.bin"
            unrelated.write_bytes(bytes(range(256)))
            before = {str(p.relative_to(root)): (p.read_bytes(), p.stat().st_mode)
                      for p in root.rglob("*") if p.is_file()}
            out = str(Path(tmp) / "result.zip")
            subprocess.run([sys.executable, "-I", str(ROOT / "uuid_swap.py"),
                            "apply", str(root), "--from", OLD,
                            "--to", NEW, "--zip", out],
                           capture_output=True, text=True, check=True)
            after = {str(p.relative_to(root)): (p.read_bytes(), p.stat().st_mode)
                     for p in root.rglob("*") if p.is_file()}
            self.assertEqual(before, after)
            with zipfile.ZipFile(out) as archive:
                name = NEW + SLUG + "/payload.bin"
                self.assertEqual(archive.read(name), bytes(range(256)))

    def test_cli_entry_point_without_optional_dependencies(self):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT)
        result = subprocess.run(
            [sys.executable, "-c", "from uuid_swap import main; main()", "--help"],
            env=env, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("TaskPack Integrity", result.stdout)


if __name__ == "__main__":
    unittest.main()
