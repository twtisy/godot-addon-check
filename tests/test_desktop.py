from pathlib import Path
import sys
import tempfile
import threading
import time
import tkinter as tk
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from addoncheck import desktop as app
from addoncheck import scanner


class DesktopFlowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.source = self.base / 'addon'
        self.source.mkdir()
        (self.source / 'plugin.cfg').write_text('[plugin]\nscript="main.gd"', encoding='utf-8')
        (self.source / 'main.gd').write_text('@tool\nOS.execute("example", [])', encoding='utf-8')
        (self.source / 'LICENSE').write_text('MIT', encoding='utf-8')
        self.root = tk.Tk()
        self.root.withdraw()
        self.callback_errors = []
        self.root.report_callback_exception = lambda kind, value, traceback: self.callback_errors.append((kind, str(value)))
        self.ui = app.PreflightApp(self.root)
        self.addCleanup(self.root.destroy)

    def tearDown(self):
        self.assertEqual(self.callback_errors, [], 'Unhandled Tk callback errors')

    def wait_for_scan(self):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            self.root.update()
            if str(self.ui.scan_button.cget('state')) == 'normal':
                return
            time.sleep(.01)
        self.fail('Desktop scan did not finish within 8 seconds')

    def scan(self, source=None):
        self.ui.path_entry.delete(0, 'end')
        self.ui.path_entry.insert(0, str(source or self.source))
        self.ui.scan_button.invoke()
        self.wait_for_scan()

    def test_scan_filter_detail_and_both_exports(self):
        self.scan()
        self.assertIsNotNone(self.ui.report)
        self.ui.search_var.set('OS.execute')
        self.root.update()
        self.assertEqual(len(self.ui.table.get_children()), 1)
        self.assertIn('example', self.ui.detail.get('1.0', 'end'))
        self.ui.search_var.set('no matching phrase')
        self.assertFalse(self.ui.table.get_children())
        self.assertIn('没有符合', self.ui.detail.get('1.0', 'end'))
        html, data = self.base / 'report.html', self.base / 'report.json'
        with patch.object(app.filedialog, 'asksaveasfilename', side_effect=[str(html), str(data)]):
            self.ui.html_button.invoke()
            self.ui.json_button.invoke()
        self.assertTrue(html.exists())
        self.assertTrue(data.exists())
        self.assertNotIn('OS.execute', html.read_text(encoding='utf-8'))
        self.ui.export_evidence_var.set(True)
        with patch.object(app.filedialog, 'asksaveasfilename', return_value=str(html)):
            self.ui.html_button.invoke()
        self.assertIn('OS.execute', html.read_text(encoding='utf-8'))

    def test_failed_rescan_preserves_previous_report_and_export(self):
        self.scan()
        previous = self.ui.report
        old_findings = list(previous.findings)
        broken = self.base / 'broken.zip'
        broken.write_text('bad zip', encoding='utf-8')
        with patch.object(app.messagebox, 'showerror') as dialog:
            self.scan(broken)
        self.assertTrue(dialog.called)
        self.assertIs(self.ui.report, previous)
        self.assertEqual(previous.findings, old_findings)
        self.assertEqual(self.ui.source_path, self.source.resolve())
        self.assertEqual(str(self.ui.html_button.cget('state')), 'normal')
        self.assertIn('保留', self.ui.status_var.get())

    def test_cancellation_preserves_previous_report(self):
        self.scan()
        previous = self.ui.report
        entered = threading.Event()

        def slow_scan(target, cancel_check):
            entered.set()
            deadline = time.monotonic() + 5
            while not cancel_check() and time.monotonic() < deadline:
                time.sleep(.01)
            if cancel_check():
                raise scanner.ScanCancelled()
            raise RuntimeError('Cancellation was not received')

        with patch.object(scanner, 'scan_target', side_effect=slow_scan):
            self.ui.scan_button.invoke()
            self.assertTrue(entered.wait(2))
            self.assertEqual(str(self.ui.html_button.cget('state')), 'disabled')
            self.ui.cancel_button.invoke()
            self.wait_for_scan()
        self.assertIs(self.ui.report, previous)
        self.assertIn('已取消', self.ui.status_var.get())
        self.assertEqual(str(self.ui.html_button.cget('state')), 'normal')

    def test_successful_rescan_does_not_mutate_previous_report(self):
        self.scan()
        previous = self.ui.report
        old_findings = list(previous.findings)
        self.scan()
        self.assertIsNot(self.ui.report, previous)
        self.assertEqual(previous.findings, old_findings)

    def test_export_inside_addon_is_blocked(self):
        self.scan()
        output = self.source / 'main.gd'
        original = output.read_bytes()
        with patch.object(app.filedialog, 'asksaveasfilename', return_value=str(output)):
            with patch.object(app.messagebox, 'showerror') as dialog:
                self.ui.html_button.invoke()
        self.assertTrue(dialog.called)
        self.assertEqual(output.read_bytes(), original)

    def test_grouping_preserves_all_evidence_and_can_be_disabled(self):
        (self.source / 'main.gd').write_text('OS.execute("first", [])\nOS.execute("second", [])', encoding='utf-8')
        self.scan()
        self.assertEqual(len(self.ui.table.get_children()), 1)
        self.assertIn('second', self.ui.detail.get('1.0', 'end'))
        self.assertEqual(len(self.ui.report.findings), 2)
        self.ui.group_var.set(False)
        self.ui._apply_filter()
        self.assertEqual(len(self.ui.table.get_children()), 2)

    def test_minimum_window_keeps_result_table_visible(self):
        self.scan()
        self.root.attributes('-alpha', 0.0)
        self.root.deiconify()
        self.root.geometry('820x680')
        self.root.update()
        self.assertGreaterEqual(self.ui.table.winfo_height(), 90,
                                f'Root: {self.root.winfo_geometry()}; table: {self.ui.table.winfo_geometry()}')


if __name__ == '__main__':
    unittest.main()
