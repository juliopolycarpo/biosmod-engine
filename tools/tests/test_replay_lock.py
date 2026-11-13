"""Replay lock generation against a named PyPI JSON fake; no network."""

import importlib.util
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("replay_lock", ROOT / "tools/replay/lock.py")
LOCK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LOCK)


def pypi_document(filenames):
    """A PyPI JSON document whose files hash to the sha of their own name."""
    return {
        "urls": [
            {"filename": name, "digests": {"sha256": name.encode().hex().ljust(64, "0")[:64]}}
            for name in filenames
        ]
    }


class WheelSelectionTest(unittest.TestCase):
    def test_keeps_64_bit_desktop_wheels_and_drops_legacy_and_32_bit_files(self):
        kept = [
            "unicorn-2.1.4-cp37-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
            "unicorn-2.1.4-cp37-abi3-manylinux_2_17_aarch64.manylinux2014_aarch64.whl",
            "unicorn-2.1.4-cp37-abi3-macosx_11_0_arm64.whl",
            "unicorn-2.1.4-cp37-abi3-win_amd64.whl",
            "pefile-2024.8.26-py3-none-any.whl",
        ]
        dropped = [
            "unicorn-2.1.4-py2-none-win_amd64.whl",
            "unicorn-2.1.4-cp37-abi3-win32.whl",
            "unicorn-2.1.4-cp37-abi3-manylinux_2_17_i686.manylinux2014_i686.whl",
            "unicorn-2.1.4.tar.gz",
        ]
        for name in kept:
            self.assertTrue(LOCK.wanted(name), f"expected kept | received dropped: {name}")
        for name in dropped:
            self.assertFalse(LOCK.wanted(name), f"expected dropped | received kept: {name}")


class RenderTest(unittest.TestCase):
    def documents(self):
        return {
            "unicorn": pypi_document(
                ["unicorn-2.1.4-cp37-abi3-win_amd64.whl", "unicorn-2.1.4.tar.gz"]
            ),
            "capstone": pypi_document(["capstone-5.0.9-py3-none-win_amd64.whl"]),
            "pefile": pypi_document(["pefile-2024.8.26-py3-none-any.whl"]),
        }

    def test_pins_every_package_in_order_with_one_hash_per_wheel(self):
        text = LOCK.render(self.documents())
        self.assertEqual(
            re.findall(r"^(\w+==\S+) \\$", text, re.M),
            ["unicorn==2.1.4", "capstone==5.0.9", "pefile==2024.8.26"],
        )
        self.assertEqual(text.count("--hash=sha256:"), 3, text)

    def test_a_package_without_wheels_names_the_package(self):
        documents = self.documents()
        documents["pefile"] = pypi_document(["pefile-2024.8.26.tar.gz"])
        with self.assertRaises(SystemExit) as raised:
            LOCK.render(documents)
        self.assertIn("pefile==2024.8.26: expected at least one wheel", str(raised.exception))


class CommittedLockTest(unittest.TestCase):
    def test_pins_match_the_generator_and_every_hash_is_sha256(self):
        text = (ROOT / "tools/replay/requirements.lock").read_text()
        pins = re.findall(r"^(\w+)==(\S+) \\$", text, re.M)
        self.assertEqual(tuple(pins), LOCK.PINNED)
        hashes = re.findall(r"--hash=sha256:(\S+?)(?: \\)?$", text, re.M)
        self.assertTrue(hashes)
        for digest in hashes:
            self.assertRegex(digest, r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
