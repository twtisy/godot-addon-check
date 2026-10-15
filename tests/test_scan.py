import contextlib
import io
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import stat
import struct
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from addoncheck import scanner


class PreflightRegressionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.source = self.base / 'addon'
        self.source.mkdir()
        (self.source / 'LICENSE').write_text('MIT', encoding='utf-8')
        (self.source / 'plugin.cfg').write_text('[plugin]\nscript="main.gd"\n', encoding='utf-8')
        (self.source / 'main.gd').write_text('@tool\nOS.execute("example", [])\n', encoding='utf-8')

    def codes(self, report):
        return {f.code for f in report.findings}

    def test_directory_scan_finds_code_but_ignores_readme_and_comment_examples(self):
        (self.source / 'README.md').write_text('HTTPRequest OS.execute("demo", [])', encoding='utf-8')
        (self.source / 'comments.gd').write_text('# OS.execute("demo", [])\n', encoding='utf-8')
        report = scanner.scan_target(self.source)
        self.assertIn('process_api', self.codes(report))
        self.assertFalse(any(f.path in {'README.md', 'comments.gd'} for f in report.findings))
        self.assertFalse(report.incomplete)
        self.assertNotIn('plugin_entry_not_found', self.codes(report))

    def test_missing_relative_entry_is_not_satisfied_by_another_folder(self):
        (self.source / 'main.gd').rename(self.source / 'other.gd')
        nested = self.source / 'other'
        nested.mkdir()
        (nested / 'main.gd').write_text('@tool', encoding='utf-8')
        self.assertIn('plugin_entry_not_found', self.codes(scanner.scan_target(self.source)))

    def test_entry_path_case_mismatch_is_visible(self):
        (self.source / 'plugin.cfg').write_text('[plugin]\nscript="MAIN.gd"', encoding='utf-8')
        self.assertIn('plugin_entry_case_mismatch', self.codes(scanner.scan_target(self.source)))

    def test_unparseable_config_marks_incomplete(self):
        (self.source / 'plugin.cfg').write_bytes(b'\xff\xfe\x00invalid')
        report = scanner.scan_target(self.source)
        self.assertIn('plugin_config_unreadable', self.codes(report))
        self.assertTrue(report.incomplete)

    def test_zip_repository_wrapper_and_resource_entry(self):
        archive = self.base / 'repo.zip'
        with zipfile.ZipFile(archive, 'w') as z:
            z.writestr('repo/addons/example/plugin.cfg', '[plugin]\nscript="res://addons/example/main.gd"')
            z.writestr('repo/addons/example/main.gd', '@tool\nFileAccess.open("user://x", FileAccess.WRITE)')
            z.writestr('repo/LICENSE', 'MIT')
        original = archive.read_bytes()
        report = scanner.scan_target(archive)
        self.assertIn('file_write_api', self.codes(report))
        self.assertNotIn('plugin_entry_not_found', self.codes(report))
        self.assertEqual(archive.read_bytes(), original)
        self.assertFalse((self.base / 'repo').exists())

    def test_crc_failure_marks_incomplete_without_claiming_size_limit(self):
        archive = self.base / 'damaged.zip'
        with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_STORED) as z:
            z.writestr('main.gd', '@tool\n')
            info = z.getinfo('main.gd')
            offset = info.header_offset + 30 + len(info.filename.encode()) + len(info.extra)
        data = bytearray(archive.read_bytes())
        data[offset] ^= 1
        archive.write_bytes(data)
        report = scanner.scan_target(archive)
        self.assertIn('entry_read_error', self.codes(report))
        self.assertTrue(report.incomplete)
        self.assertFalse(report.limited)
        self.assertIn('存在未检查内容：是', scanner.render_text(report))
        self.assertIn('存在未检查内容：是', scanner.render_html(report))

    def test_nested_archive_and_unreadable_script_are_not_silently_complete(self):
        (self.source / 'nested.zip').write_bytes(b'not recursively opened')
        (self.source / 'encoded.gd').write_bytes('@tool'.encode('utf-16'))
        report = scanner.scan_target(self.source)
        self.assertTrue(report.incomplete)
        self.assertIn('nested_archive_not_inspected', self.codes(report))
        self.assertIn('source_encoding_unreadable', self.codes(report))

    def test_corrupt_entries_cannot_bypass_total_read_budget(self):
        archive = self.base / 'many-damaged.zip'
        offsets = []
        with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_STORED) as z:
            for name in ('one.gd', 'two.gd', 'three.gd'):
                z.writestr(name, '@tool\n')
                info = z.getinfo(name)
                offsets.append(info.header_offset + 30 + len(info.filename.encode()) + len(info.extra))
        data = bytearray(archive.read_bytes())
        for offset in offsets:
            data[offset] ^= 1
        archive.write_bytes(data)
        report = scanner.scan_target(archive, max_total_bytes=6)
        self.assertTrue(report.limited)
        self.assertIn('total_size_limit', self.codes(report))
        self.assertEqual(sum(f.code == 'entry_read_error' for f in report.findings), 1)

    def test_zip_traversal_is_flagged_without_creating_files(self):
        archive = self.base / 'paths.zip'
        with zipfile.ZipFile(archive, 'w') as z:
            z.writestr('../escaped.gd', '@tool')
        report = scanner.scan_target(archive)
        self.assertIn('unsafe_archive_path', self.codes(report))
        self.assertTrue(report.incomplete)
        self.assertFalse((self.base / 'escaped.gd').exists())

    def test_zip_symlink_content_is_not_scanned(self):
        archive = self.base / 'link.zip'
        with zipfile.ZipFile(archive, 'w') as z:
            info = zipfile.ZipInfo('linked.gd')
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(info, 'OS.execute("do-not-read", [])')
        report = scanner.scan_target(archive)
        self.assertIn('archive_symlink', self.codes(report))
        self.assertNotIn('process_api', self.codes(report))
        self.assertTrue(report.incomplete)

    @unittest.skipUnless(sys.platform == 'win32', 'Windows junction regression')
    def test_windows_junction_does_not_read_outside_input(self):
        import _winapi
        outside = self.base / 'outside'
        outside.mkdir()
        (outside / 'do-not-read.gd').write_text('OS.execute("outside", [])', encoding='utf-8')
        link = self.source / 'junction'
        _winapi.CreateJunction(str(outside), str(link))
        self.addCleanup(link.rmdir)
        report = scanner.scan_target(self.source)
        self.assertIn('directory_symlink', self.codes(report))
        self.assertFalse(any('do-not-read.gd' in f.path for f in report.findings))
        self.assertTrue(report.incomplete)
        with self.assertRaises(scanner.ScanInputError):
            scanner.scan_target(link)

    def test_total_budget_and_cancellation(self):
        report = scanner.scan_target(self.source, max_total_bytes=4)
        self.assertLessEqual(report.bytes_read, 4)
        self.assertTrue(report.limited)
        self.assertTrue(report.incomplete)
        with self.assertRaises(scanner.ScanCancelled):
            scanner.scan_target(self.source, cancel_check=lambda: True)

    def test_html_escapes_source_markup(self):
        (self.source / 'main.gd').write_text('OS.execute("<script>boom</script>", [])', encoding='utf-8')
        report = scanner.scan_target(self.source)
        markup = scanner.render_html(report, include_evidence=True)
        self.assertNotIn('<script>boom</script>', markup)
        self.assertIn('&lt;script&gt;boom&lt;/script&gt;', markup)

    def test_export_rejects_input_directory(self):
        target = self.source / 'main.gd'
        original = target.read_bytes()
        with self.assertRaises(scanner.ScanInputError):
            scanner.write_report(target, 'overwrite', self.source)
        self.assertEqual(target.read_bytes(), original)

    def test_failed_atomic_replace_preserves_previous_report_and_cleans_temporary(self):
        output = self.base / 'report.html'
        output.write_text('old report', encoding='utf-8')
        with patch.object(scanner.os, 'replace', side_effect=PermissionError('locked')):
            with self.assertRaises(PermissionError):
                scanner.write_report(output, 'new report', self.source)
        self.assertEqual(output.read_text(encoding='utf-8'), 'old report')
        self.assertFalse(list(self.base.glob('.addoncheck-*.tmp')))

    def test_cli_generates_both_reports_and_rejects_output_collision(self):
        html = self.base / 'report.html'
        data = self.base / 'report.json'
        result = subprocess.run([sys.executable, '-m', 'addoncheck.scanner', str(self.source),
                                 '--html', str(html), '--json', str(data)], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(data.read_text(encoding='utf-8'))['schema_version'], '0.3')
        self.assertIn('静态检查报告', scanner.render_text(scanner.scan_target(self.source)))
        self.assertIn('Godot Addon Check', html.read_text(encoding='utf-8'))
        original = html.read_bytes()
        with contextlib.redirect_stderr(io.StringIO()):
            code = scanner.main([str(self.source), '--html', str(html), '--json', str(html)])
        self.assertEqual(code, 2)
        self.assertEqual(html.read_bytes(), original)

    def test_lexical_adversarial_matrix(self):
        cases = [
            ('gd-call', '.gd', '@tool\nOS.execute("x", [])', {'editor_tool_script', 'process_api'}),
            ('gd-string', '.gd', 'var text = "OS.execute(ignored) HTTPRequest"', set()),
            ('gd-docstring', '.gd', '"""\n@tool\nOS.execute()\n"""', set()),
            ('gd-inline-comment', '.gd', 'var x = 1 # OS.execute("x", [])', set()),
            ('gd-node-name', '.gd', 'var node = $HTTPRequest', set()),
            ('gd-typed-node', '.gd', 'var node: HTTPRequest = $HTTPRequest', {'network_api'}),
            ('gd-multiline-write', '.gd', 'FileAccess.open(\n get_path(),\n FileAccess.WRITE\n)', {'file_write_api'}),
            ('gd-read-unrelated-write', '.gd', 'FileAccess.open("x", FileAccess.READ)\nvar WRITE = 1', set()),
            ('cs-block-comment', '.cs', '/* [Tool]\nProcess.Start("x"); */', set()),
            ('cs-verbatim', '.cs', 'var x = @"OS.execute(""x"")";', set()),
            ('cs-dotnet-process', '.cs', 'System.Diagnostics.Process.Start("x");', {'process_api'}),
            ('cs-godot-process', '.cs', 'Godot.OS.CreateProcess("x", args);', {'process_api'}),
            ('cs-write-read', '.cs', 'FileAccess.Open(\n "x",\n FileAccess.ModeFlags.WriteRead);', {'file_write_api'}),
            ('cs-directory', '.cs', 'DirAccess.MakeDirRecursiveAbsolute("x");', {'file_write_api'}),
        ]
        (self.source / 'main.gd').unlink()
        for name, suffix, text, expected in cases:
            with self.subTest(name=name):
                script = self.source / f'case{suffix}'
                script.write_text(text, encoding='utf-8')
                try:
                    report = scanner.scan_target(self.source)
                    actual = {f.code for f in report.findings if f.path == script.name}
                    self.assertEqual(actual, expected)
                    self.assertEqual(report.scripts_checked, 1)
                finally:
                    script.unlink()

    def test_no_supported_scripts_and_native_extension_are_explicit(self):
        (self.source / 'main.gd').unlink()
        (self.source / 'native.gdextension').write_text('[configuration]', encoding='utf-8')
        report = scanner.scan_target(self.source)
        self.assertEqual(report.scripts_checked, 0)
        self.assertTrue(report.incomplete)
        self.assertIn('no_supported_scripts', self.codes(report))
        self.assertIn('native_extension_manifest', self.codes(report))

    def test_file_and_report_caps_cannot_appear_complete(self):
        count_limited = scanner.scan_target(self.source, max_files=1)
        self.assertTrue(count_limited.incomplete)
        self.assertIn('file_count_limit', self.codes(count_limited))
        size_limited = scanner.scan_target(self.source, max_file_bytes=4)
        self.assertTrue(size_limited.incomplete)
        self.assertIn('file_size_limit', self.codes(size_limited))
        (self.source / 'main.gd').write_text('@tool\n' * (scanner.MAX_FINDINGS + 1) + 'OS.execute("late", [])', encoding='utf-8')
        report_limited = scanner.scan_target(self.source)
        self.assertEqual(len(report_limited.findings), scanner.MAX_FINDINGS)
        self.assertTrue(report_limited.incomplete)
        self.assertIn('finding_limit', self.codes(report_limited))

    def test_zip_directory_entry_cap_precedes_zipinfo_allocation(self):
        archive = self.base / 'many.zip'
        with zipfile.ZipFile(archive, 'w') as z:
            for i in range(scanner.MAX_ARCHIVE_ENTRIES + 1):
                z.writestr(f'{i}/', '')
        with patch.object(scanner.zipfile, 'ZipFile', side_effect=AssertionError('ZipInfo allocation should not occur')):
            with self.assertRaises(scanner.ScanInputError):
                scanner.scan_target(archive)

    def test_zip_directory_does_not_trust_underreported_entry_count(self):
        archive = self.base / 'wrong-count.zip'
        with zipfile.ZipFile(archive, 'w') as z:
            z.writestr('one.gd', '@tool')
            z.writestr('two.gd', '@tool')
        data = bytearray(archive.read_bytes())
        footer = data.rfind(b'PK\x05\x06')
        struct.pack_into('<2H', data, footer + 8, 1, 1)
        archive.write_bytes(data)
        with self.assertRaises(scanner.ScanInputError):
            scanner.scan_target(archive)

    def test_zip_fingerprint_matches_exact_input_bytes(self):
        archive = self.base / 'fingerprint.zip'
        with zipfile.ZipFile(archive, 'w') as z:
            z.writestr('main.gd', '@tool')
        report = scanner.scan_target(archive)
        self.assertEqual(report.input_sha256, hashlib.sha256(archive.read_bytes()).hexdigest())
        self.assertEqual(report.fingerprint_scope, '完整 ZIP 字节快照')

    def test_interpolation_is_unknown_not_a_silent_negative(self):
        (self.source / 'main.gd').unlink()
        for value in ['var x = $"{System.Diagnostics.Process.Start("example")}";',
                      'var x = $@"{run()}";', 'var x = @$"{run()}";']:
            with self.subTest(value=value):
                (self.source / 'case.cs').write_text(value, encoding='utf-8')
                report = scanner.scan_target(self.source)
                self.assertTrue(report.incomplete)
                self.assertIn('interpolated_string_uninspected', self.codes(report))

    def test_variable_file_mode_is_explicitly_unresolved(self):
        (self.source / 'main.gd').write_text('var mode = FileAccess.WRITE\nFileAccess.open(path, mode)', encoding='utf-8')
        report = scanner.scan_target(self.source)
        self.assertIn('unresolved_file_mode', self.codes(report))
        self.assertTrue(report.incomplete)

    def test_native_library_is_uninspected(self):
        (self.source / 'library.dll').write_bytes(b'not executable test content')
        report = scanner.scan_target(self.source)
        self.assertIn('native_or_binary_file', self.codes(report))
        self.assertTrue(report.incomplete)

    def test_config_script_value_is_not_exported_by_default(self):
        private_value = 'example-private-folder-123'
        (self.source / 'plugin.cfg').write_text(f'[plugin]\nscript="{private_value}/missing.gd"', encoding='utf-8')
        report = scanner.scan_target(self.source)
        self.assertNotIn(private_value, scanner.render_html(report))
        self.assertNotIn(private_value, json.dumps(scanner.report_to_dict(report)))

    def test_directory_fingerprint_is_repeatable_and_tracks_content(self):
        first = scanner.scan_target(self.source).input_sha256
        self.assertEqual(scanner.scan_target(self.source).input_sha256, first)
        (self.source / 'main.gd').write_text('@tool', encoding='utf-8')
        self.assertNotEqual(scanner.scan_target(self.source).input_sha256, first)

    def test_exports_hide_source_by_default_and_only_opt_in_includes_it(self):
        secret = 'example-private-value-123'
        (self.source / 'main.gd').write_text(f'OS.execute("{secret}", [])', encoding='utf-8')
        report = scanner.scan_target(self.source)
        self.assertNotIn(secret, scanner.render_html(report))
        self.assertNotIn(secret, scanner.render_text(report))
        self.assertNotIn(secret, json.dumps(scanner.report_to_dict(report)))
        self.assertIn(secret, scanner.render_html(report, include_evidence=True))
        self.assertIn(secret, json.dumps(scanner.report_to_dict(report, include_evidence=True)))


if __name__ == '__main__':
    unittest.main()
