import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from addoncheck import compare
from addoncheck import report as english_report


class ReleaseCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.old = self.make('before.zip', 'OS.execute("PRIVATE_OLD", [])')
        self.new = self.make('after.zip', 'OS.execute("PRIVATE_NEW", [])')

    def make(self, name, source, extra=None):
        path = self.root / name
        with zipfile.ZipFile(path, 'w') as archive:
            for filename, value in {'plugin.cfg': '[plugin]\nscript="main.gd"', 'LICENSE': 'MIT',
                                    'main.gd': source, **(extra or {})}.items():
                archive.writestr('wrapper/' + filename, value)
        return path

    def cli(self, old=None, new=None, *args):
        return subprocess.run([sys.executable, '-m', 'addoncheck.compare', str(old or self.old),
                               str(new or self.new), '--strip-wrapper', *args], capture_output=True)

    def test_ci_exit_codes_and_english_default(self):
        p = self.cli(None, None, '--fail-on-change')
        self.assertEqual(p.returncode, 1, p.stderr)
        self.assertIn(b'Changed bytes: review', p.stdout)
        self.assertEqual(self.cli(self.old, self.old, '--fail-on-change').returncode, 0)
        native = self.make('native.zip', 'OS.execute("x", [])', {'native.dll': b'unknown'})
        self.assertEqual(self.cli(self.old, native, '--fail-on-change').returncode, 3)

    def test_english_report_redaction_unknown_and_source_opt_in(self):
        result = compare.compare_targets(self.old, self.new, True)
        hidden = english_report.render(result)
        self.assertIn('<html lang="en">', hidden)
        self.assertIn('Not a safety verdict.', hidden)
        self.assertIn('Source hidden by default', hidden)
        self.assertNotIn('PRIVATE_OLD', hidden)
        self.assertNotIn('PRIVATE_NEW', hidden)
        self.assertIn('PRIVATE_NEW', english_report.render(result, True))
        native = self.make('native.zip', '', {'native.dll': b'unknown'})
        unknown = english_report.render(compare.compare_targets(self.old, native, True))
        self.assertIn('Unknown / not comparable', unknown)
        self.assertIn('native_or_binary_file', unknown)

    def test_export_destinations_prevalidated_before_any_write(self):
        report = self.root / 'should-not-exist.html'
        previous = self.new.read_bytes()
        proc = self.cli(None, None, '--html', str(report), '--json', str(self.new))
        self.assertEqual(proc.returncode, 2)
        self.assertFalse(report.exists())
        self.assertEqual(self.new.read_bytes(), previous)

    def test_cli_does_not_import_tk_or_gui(self):
        p = subprocess.run([sys.executable, '-c',
            'import sys; from addoncheck import compare; assert "tkinter" not in sys.modules; '
            'assert "addoncheck.desktop" not in sys.modules; print("headless import OK")'],
            cwd=Path(compare.__file__).parent.parent, capture_output=True)
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_ascii_terminal_and_unicode_paths_do_not_crash(self):
        other = self.make('emoji-☃.zip', 'OS.execute("PRIVATE_NEW", [])', {'snow-☃.gd': '@tool'})
        import os
        env = dict(os.environ, PYTHONIOENCODING='ascii:strict')
        p = subprocess.run([sys.executable, '-m', 'addoncheck.compare', str(self.old), str(other), '--strip-wrapper'],
                           capture_output=True, env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn(b'\\u2603', p.stdout)
