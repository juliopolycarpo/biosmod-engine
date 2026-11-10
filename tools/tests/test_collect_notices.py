"""License selection and packaging entry point coverage with a named Cargo fake."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "packaging/linux/collect-notices.py"
SPEC = importlib.util.spec_from_file_location("collect_notices", SCRIPT)
COLLECTOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COLLECTOR)


class CargoRuntimeTreeFake:
    """Supply a fixed Cargo runtime graph. Example: CargoRuntimeTreeFake(root)."""

    def __init__(self, root):
        self.bin = root / "bin"
        self.bin.mkdir()
        cargo = self.bin / "cargo"
        cargo.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "if sys.argv[1:] != ['tree', '--locked', '-p', 'biosmod-cli', '-p', "
            "'biosmod-gui', '--target', 'x86_64-unknown-linux-gnu', '-e', 'normal', "
            "'--prefix', 'none', '--format', '{p}']:\n"
            "    raise SystemExit('CargoRuntimeTreeFake: unexpected command ' + repr(sys.argv))\n"
            "print('fixture v1.0.0')\n"
        )
        cargo.chmod(0o755)


class CollectNoticesTests(unittest.TestCase):
    def test_license_candidates_preserve_notices_tree_and_declared_file(self):
        root = Path("/fixture")
        files = [root / name for name in [
            "LICENSE", "notice.txt", "src/lib.rs", "nested/LICENSES/sub/mit.txt",
            "LICENSES/Apache-2.0.txt", "src/license-header.rs",
        ]]
        actual = COLLECTOR.license_candidates(root, files, "custom/legal.txt")
        self.assertEqual(actual, sorted([
            path for path in files if path != root / "src/lib.rs"
        ] + [root / "custom/legal.txt"]))
        self.assertEqual(COLLECTOR.license_candidates(root, [], None), [])

    def test_source_copyrights_filter_and_deduplicate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "lib.RS"
            source.write_text("// Copyright 2026 Example\n" * 2 + "copyright " + "x" * 500)
            invalid = root / "invalid.txt"
            invalid.write_bytes(b"copyright \xff")
            ignored = root / "binary.bin"
            ignored.write_text("Copyright ignored")
            actual = COLLECTOR.source_copyrights([source, invalid, ignored, root / "missing.rs"])
            self.assertEqual(actual, {"// Copyright 2026 Example"})

    def test_main_reuses_metadata_and_copies_selected_notices(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cargo = CargoRuntimeTreeFake(root)
            source = root / "source"
            source.mkdir()
            (source / "LICENSE").write_text("Fixture license\n")
            (source / "lib.rs").write_text("// Copyright 2026 Example\n")
            metadata = root / "metadata.json"
            metadata.write_text(json.dumps({"packages": [{
                "name": "fixture", "version": "1.0.0", "source": "registry+fixture",
                "manifest_path": str(source / "Cargo.toml"), "license_file": None,
                "license": "MIT", "authors": ["Example"],
            }]}))
            destination = root / "notices"
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(destination), str(metadata)],
                env={**os.environ, "PATH": str(cargo.bin) + os.pathsep + os.environ["PATH"]},
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            package = destination / "crates/fixture-1.0.0"
            self.assertEqual((package / "LICENSE").read_text(), "Fixture license\n")
            self.assertEqual((package / "source-copyrights.txt").read_text(), "// Copyright 2026 Example\n")
            self.assertIn("fixture-1.0.0: MIT", (destination / "THIRD-PARTY.txt").read_text())

    def test_main_requires_destination(self):
        result = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("usage: collect-notices.py <destination-directory>", result.stderr)


if __name__ == "__main__":
    unittest.main()
