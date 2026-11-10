"""Regression tests for documentation coverage and link checks."""

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "check-doc-translations.py"
spec = importlib.util.spec_from_file_location("doc_check", SCRIPT)
doc_check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(doc_check)


class DocumentationCheckTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "docs/pt-BR").mkdir(parents=True)
        self.write("README.md", "# Readme\n[Page](docs/page.md#the-page)\n")
        self.write("CONTRIBUTING.md", "# Contributing\n")
        self.write("docs/page.md", "# The page\n")
        self.write("README.pt-BR.md", "# Leia\n[Página](docs/pt-BR/page.md#a-página)\n")
        self.write("CONTRIBUTING.pt-BR.md", "# Contribuir\n")
        self.write("docs/pt-BR/page.md", "# A página\n")
        pairs = []
        for source in sorted(doc_check.source_paths(self.root)):
            pairs.append({"source": str(source), "translation": str(doc_check.translation_path(source)),
                          "sha256": hashlib.sha256((self.root / source).read_bytes()).hexdigest()})
        self.write("docs/i18n-manifest.json", json.dumps({"version": 1, "pairs": pairs}))

    def write(self, path, contents):
        (self.root / path).write_text(contents, encoding="utf-8")

    def test_valid_and_stale_source(self):
        self.assertEqual(doc_check.check(self.root), [])
        self.write("docs/page.md", "# The page\nChanged\n")
        self.assertTrue(any("source changed" in error and "docs/page.md" in error for error in doc_check.check(self.root)))

    def test_missing_and_orphan_translations_and_new_source(self):
        (self.root / "docs/pt-BR/page.md").unlink()
        self.write("docs/pt-BR/orphan.md", "# Órfão\n")
        self.write("docs/new.md", "# New\n")
        errors = "\n".join(doc_check.check(self.root))
        self.assertIn("missing translation docs/pt-BR/page.md", errors)
        self.assertIn("orphan translation docs/pt-BR/orphan.md", errors)
        self.assertIn("missing source docs/new.md", errors)

    def test_missing_link_and_heading_and_fenced_examples(self):
        self.write("README.pt-BR.md", "# Leia\n[Perdido](missing.md) [Cabeçalho](docs/pt-BR/page.md#ausente)\n```md\n[Example](absent.md)\n```\n")
        errors = "\n".join(doc_check.check(self.root))
        self.assertIn("missing local target missing.md", errors)
        self.assertIn("missing heading docs/pt-BR/page.md#ausente", errors)
        self.assertNotIn("absent.md", errors)

    def test_duplicate_mapping_is_rejected(self):
        path = self.root / doc_check.MANIFEST
        manifest = json.loads(path.read_text())
        manifest["pairs"].append(manifest["pairs"][0])
        path.write_text(json.dumps(manifest))
        self.assertTrue(any("duplicate source" in error for error in doc_check.check(self.root)))


if __name__ == "__main__":
    unittest.main()
