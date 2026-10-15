import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
import unittest
from unittest.mock import patch
import warnings
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from addoncheck import scanner
from addoncheck import compare
from addoncheck import compare_window as compare_app


class CompareTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.old = self.make('old.zip', 'old-root', 'OS.execute("private_a", [])\n')
        self.new = self.make('new.zip', 'new-root', 'OS.execute("private_b", [])\n')

    def make(self, name, root, code, extras=None):
        path = self.base / name
        with zipfile.ZipFile(path, 'w') as archive:
            for relative, value in {'plugin.cfg': '[plugin]\nscript="main.gd"',
                                    'main.gd': code, 'LICENSE': 'MIT', **(extras or {})}.items():
                archive.writestr((root + '/' if root else '') + relative, value)
        return path

    def test_self_compare_bytes_fingerprints_and_wrapper_opt_in(self):
        result = compare.compare_targets(self.old, self.old)
        self.assertTrue(all(item.status == 'same' for item in result.files))
        self.assertEqual(result.old.input_sha256, hashlib.sha256(self.old.read_bytes()).hexdigest())
        equal = self.make('equal.zip', 'different-root', 'OS.execute("private_a", [])\n')
        without = compare.compare_targets(self.old, equal)
        self.assertNotIn('same', [item.status for item in without.files])
        with_wrapper = compare.compare_targets(self.old, equal, True)
        self.assertEqual(with_wrapper.old_root, 'old-root/')
        self.assertTrue(all(item.status == 'same' for item in with_wrapper.files))

    def test_changed_parameters_multiline_and_repeated_clues_preserved(self):
        result = compare.compare_targets(self.old, self.new, True)
        main = next(item for item in result.files if item.path == 'main.gd')
        self.assertEqual(main.status, 'changed')
        self.assertEqual((len(main.old_findings), len(main.new_findings)), (1, 1))
        old = self.make('repeat.zip', 'r', 'OS.execute("x", [])\n' * 3)
        shifted = self.make('shifted.zip', 's', '# comment\n' * 100 + 'OS.execute(\n"x", [])\n')
        result = compare.compare_targets(old, shifted, True)
        main = next(item for item in result.files if item.path == 'main.gd')
        self.assertEqual(main.status, 'changed')  # deliberately no semantic matching
        self.assertEqual((len(main.old_findings), len(main.new_findings)), (3, 1))
        self.assertEqual(main.new_findings[0].line, 101)

    def test_any_byte_change_without_api_clues_still_visible(self):
        old = self.make('clean.zip', 'r', '# first\n')
        new = self.make('clean2.zip', 's', '# second\n')
        result = compare.compare_targets(old, new, True)
        item = next(item for item in result.files if item.path == 'main.gd')
        self.assertEqual(item.status, 'changed')
        self.assertEqual(item.old_findings + item.new_findings, [])

    def test_partial_input_missing_file_is_unknown_not_disappearance(self):
        oversized = self.make('oversized.zip', 'r', 'x' * (scanner.DEFAULT_MAX_FILE_BYTES + 1))
        result = compare.compare_targets(self.old, oversized, True)
        item = next(item for item in result.files if item.path == 'main.gd')
        self.assertEqual(item.status, 'unknown')
        self.assertTrue(result.new.incomplete)
        self.assertTrue(any('未知' in warning for warning in result.warnings))

    def test_truncated_file_and_rules_mismatch_refuse_false_same(self):
        old = scanner.scan_target(self.old)
        new = scanner.scan_target(self.old)
        new.file_manifest[0]['complete'] = False
        result = compare.compare_reports(old, new)
        affected = next(item for item in result.files if item.path == new.file_manifest[0]['path'])
        self.assertEqual(affected.status, 'unknown')
        new.ruleset_version = 'different'
        with self.assertRaises(scanner.ScanInputError):
            compare.compare_reports(old, new)

    def test_multiroot_duplicate_and_case_collision_are_rejected(self):
        multi = self.make('multi.zip', 'r', '', {'../s/main.gd': ''})
        # Use real separate roots, not traversal, to exercise normalization.
        with zipfile.ZipFile(multi, 'a') as archive:
            archive.writestr('another/main.gd', '')
        with self.assertRaises(scanner.ScanInputError):
            compare.compare_targets(self.old, multi, True)
        for extra in ('main.gd', 'MAIN.gd'):
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', UserWarning)
                colliding = self.make('collision.zip', 'r', 'original')
                with zipfile.ZipFile(colliding, 'a') as archive:
                    archive.writestr('r/' + extra, 'replacement')
            with self.assertRaises(scanner.ScanInputError):
                compare.compare_targets(colliding, colliding, True)

    def test_exports_redact_source_escape_html_and_protect_both_inputs(self):
        result = compare.compare_targets(self.old, self.new, True)
        self.assertNotIn('private_a', json.dumps(compare.to_dict(result)))
        self.assertNotIn('private_b', compare.render_html(result))
        self.assertIn('private_b', compare.render_html(result, True))
        for path in (self.old, self.new):
            previous = path.read_bytes()
            with self.assertRaises(scanner.ScanInputError):
                compare.save(result, path, self.old, self.new)
            self.assertEqual(path.read_bytes(), previous)
        hostile = self.make('html.zip', 'r', 'OS.execute("<script>alert(1)</script>", [])')
        html = compare.render_html(compare.compare_targets(hostile, hostile, True), True)
        self.assertNotIn('<script>', html)
        self.assertIn('&lt;script&gt;', html)

    def test_cli_reports_and_exit_status_and_broken_zip(self):
        out = self.base / 'out.json'
        html = self.base / 'out.html'
        command = [sys.executable, '-m', 'addoncheck.compare', str(self.old), str(self.new),
                   '--strip-wrapper', '--json', str(out), '--html', str(html)]
        proc = subprocess.run(command, capture_output=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(out.read_text(encoding='utf-8'))['schema_version'], 'comparison-0.1')
        self.assertTrue(html.exists())
        unknown = self.make('native.zip', 'n', '', {'test.dll': b'not executable, only bytes'})
        proc = subprocess.run([sys.executable, '-m', 'addoncheck.compare', str(self.old), str(unknown), '--strip-wrapper'], capture_output=True)
        self.assertEqual(proc.returncode, 3)
        bad = self.base / 'bad.zip'
        bad.write_bytes(b'not a zip')
        proc = subprocess.run([sys.executable, '-m', 'addoncheck.compare', str(self.old), str(bad)], capture_output=True)
        self.assertEqual(proc.returncode, 2)

    def test_preview_caps_encoding_and_line_ending_changes_are_explicit(self):
        old = self.make('text-old.zip', 'r', 'a\n' * 1000)
        new = self.make('text-new.zip', 's', 'b\n' * 1000)
        item = next(f for f in compare.compare_targets(old, new, True).files if f.path == 'main.gd')
        self.assertIn('截断', item.diff_note)
        self.assertLessEqual(len(item.diff_preview.splitlines()), 150)
        self.assertLessEqual(len(item.diff_preview), 16_150)
        for value, expected in [(b'a\r\n' * 1000, '换行'), (b'\xff\x00', '二进制'),
                                (b'z' * 65_537, '64 KiB')]:
            candidate = self.make('preview.zip', 's', value)
            item = next(f for f in compare.compare_targets(old, candidate, True).files if f.path == 'main.gd')
            self.assertEqual(item.status, 'changed')
            self.assertIn(expected, item.diff_note)

    def test_preview_uses_scan_snapshot_not_later_disk_content(self):
        real_scan = scanner.scan_target

        def mutate_after_scan(path, **kwargs):
            report = real_scan(path, **kwargs)
            if path == self.old:
                self.old.write_bytes(b'now replaced, cannot be reopened as zip')
            return report

        original_hash = hashlib.sha256(self.old.read_bytes()).hexdigest()
        with patch.object(scanner, 'scan_target', side_effect=mutate_after_scan):
            result = compare.compare_targets(self.old, self.new, True)
        self.assertEqual(result.old.input_sha256, original_hash)
        item = next(f for f in result.files if f.path == 'main.gd')
        self.assertIn('private_a', item.diff_preview)
        self.assertIn('private_b', item.diff_preview)

    def test_output_into_either_input_directory_is_rejected(self):
        old, new = self.base / 'before', self.base / 'after'
        for path in (old, new):
            path.mkdir()
            (path / 'main.gd').write_text('@tool', encoding='utf-8')
            (path / 'LICENSE').write_text('MIT', encoding='utf-8')
        result = compare.compare_targets(old, new)
        for path in (old, new):
            with self.assertRaises(scanner.ScanInputError):
                compare.save(result, path / 'report.html', old, new)
            self.assertFalse((path / 'report.html').exists())


class CompareDesktopTests(CompareTests):
    # Reuse fixture only, not inherited test methods: see explicit load_tests below.
    def setUp(self):
        super().setUp()
        self.root = tk.Tk()
        self.root.withdraw()
        self.addCleanup(self.root.destroy)
        self.callback_errors = []
        self.root.report_callback_exception = lambda kind, value, tb: self.callback_errors.append(str(value))
        self.ui = compare_app.CompareApp(self.root)
        self.ui.old_var.set(str(self.old))
        self.ui.new_var.set(str(self.new))
        self.ui.strip_var.set(True)

    def tearDown(self):
        self.assertEqual(self.callback_errors, [])

    def wait(self):
        end = time.monotonic() + 8
        while time.monotonic() < end:
            self.root.update()
            if str(self.ui.start_button.cget('state')) == 'normal':
                return
            time.sleep(.01)
        self.fail('Compare UI timeout')

    def test_ui_scan_filter_details_exports_and_small_window(self):
        self.ui.start_button.invoke()
        self.wait()
        self.assertIsNotNone(self.ui.result)
        self.assertEqual(len(self.ui.table.get_children()), 1)
        self.assertIn('private_b', self.ui.detail.get('1.0', 'end'))
        self.ui.show_same_var.set(True)
        self.ui._filter()
        self.assertEqual(len(self.ui.table.get_children()), 3)
        self.ui.search_var.set('nonexistent')
        self.root.update()
        self.assertFalse(self.ui.table.get_children())
        self.ui.search_var.set('')
        out = self.base / 'ui.html'
        with patch.object(compare_app.filedialog, 'asksaveasfilename', return_value=str(out)):
            self.ui.html_button.invoke()
        self.assertNotIn('private_b', out.read_text(encoding='utf-8'))
        data = self.base / 'ui.json'
        with patch.object(compare_app.filedialog, 'asksaveasfilename', return_value=str(data)):
            self.ui.json_button.invoke()
        self.assertEqual(json.loads(data.read_text(encoding='utf-8'))['schema_version'], 'comparison-0.1')
        self.root.attributes('-alpha', 0)
        self.root.deiconify()
        self.root.geometry('820x680')
        self.root.update()
        self.assertGreaterEqual(self.ui.table.winfo_height(), 100)

    def test_ui_error_and_cancel_preserve_previous_comparison(self):
        self.ui.start_button.invoke()
        self.wait()
        previous = self.ui.result
        self.ui.new_var.set(str(self.base / 'missing.zip'))
        with patch.object(compare_app.messagebox, 'showerror') as dialog:
            self.ui.start_button.invoke()
            self.wait()
        self.assertTrue(dialog.called)
        self.assertIs(self.ui.result, previous)
        self.assertEqual(str(self.ui.html_button.cget('state')), 'normal')
        entered = threading.Event()

        def slow(*args, cancel_check, **kwargs):
            entered.set()
            while not cancel_check():
                time.sleep(.01)
            raise scanner.ScanCancelled()

        with patch.object(compare, 'compare_targets', side_effect=slow):
            self.ui.start_button.invoke()
            self.assertTrue(entered.wait(2))
            self.assertEqual(str(self.ui.html_button.cget('state')), 'disabled')
            self.ui.cancel_button.invoke()
            self.wait()
        self.assertIs(self.ui.result, previous)
        self.assertIn('取消', self.ui.status_var.get())


def load_tests(loader, tests, pattern):
    # Avoid counting inherited core methods as separate desktop tests.
    suite = loader.loadTestsFromTestCase(CompareTests)
    for name in CompareDesktopTests.__dict__:
        if name.startswith('test_ui_'):
            suite.addTest(CompareDesktopTests(name))
    return suite
