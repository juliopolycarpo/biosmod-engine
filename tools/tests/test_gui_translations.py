"""Checks for the GUI gettext catalog validator."""
import importlib.util
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    'translations', Path(__file__).resolve().parents[1] / 'update-gui-translations.py')
translations = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(translations)


class FakeExtractor:
    """Emit a deterministic template without requiring a system extractor."""

    def version(self, _command, **_kwargs):
        return 'slint-tr-extractor 1.18.1\n'

    def extract(self, command, **_kwargs):
        Path(command[command.index('-o') + 1]).write_text(
            'msgid ""\nmsgstr ""\n"POT-Creation-Date: volatile\\n"\n\n'
            'msgctxt "Panel"\nmsgid "Hello {}"\nmsgstr ""\n')


class CatalogTests(unittest.TestCase):
    def test_multiline_and_context(self):
        block = '#. Translator note\nmsgctxt "Panel"\nmsgid ""\n"First "\n"second"\nmsgstr "Outro"'
        self.assertEqual(translations.fields(block)['msgid'], 'First second')
        self.assertEqual(translations.key(block), ('Panel', 'First second', ''))
        self.assertEqual(len(translations.entries(block)), 1)

    def test_placeholder_reordering_and_missing_arguments(self):
        self.assertEqual(translations.placeholders('{} and {}'),
                         translations.placeholders('{1} e {0}'))
        self.assertNotEqual(translations.placeholders('{} and {}'),
                            translations.placeholders('{}'))
        self.assertNotEqual(translations.placeholders('{n}'),
                            translations.placeholders('{other}'))

    def test_update_preserves_comments_and_check_rejects_fuzzy(self):
        fake = FakeExtractor()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'ui').mkdir()
            (root / 'ui' / 'app.slint').write_text('')
            template = root / 'messages.pot'
            catalog = root / 'messages.po'
            catalog.write_text('msgid ""\nmsgstr ""\n\n'
                               '#. Preserve this note\nmsgctxt "Panel"\n'
                               'msgid "Hello {}"\nmsgstr "Olá {}"\n')
            with mock.patch.object(translations, 'GUI', root), \
                 mock.patch.object(translations, 'TEMPLATE', template), \
                 mock.patch.object(translations, 'CATALOG', catalog), \
                 mock.patch.object(translations.shutil, 'which', return_value='/fake/extractor'), \
                 mock.patch.object(translations.subprocess, 'check_output', fake.version), \
                 mock.patch.object(translations.subprocess, 'run', fake.extract), \
                 mock.patch('sys.argv', ['update-gui-translations.py']), \
                 contextlib.redirect_stdout(io.StringIO()):
                translations.main()
                self.assertIn('#. Preserve this note', catalog.read_text())
                self.assertNotIn('POT-Creation-Date', template.read_text())
                catalog.write_text(catalog.read_text().replace('#. Preserve', '#, fuzzy\n#. Preserve'))
                with mock.patch('sys.argv', ['update-gui-translations.py', '--check']):
                    with self.assertRaisesRegex(SystemExit, 'fuzzy:.*Hello'):
                        translations.main()


if __name__ == '__main__':
    unittest.main()
