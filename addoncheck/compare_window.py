#!/usr/bin/env python3
"""Local desktop workflow for comparing two add-on packages."""
from __future__ import annotations

from pathlib import Path
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from addoncheck import scanner
from addoncheck import compare


class CompareApp:
    def __init__(self, root):
        self.root = root
        root.title('Godot Addon Check · 升级前对比')
        root.geometry('1060x800')
        root.minsize(820, 680)
        self.old_var, self.new_var = tk.StringVar(), tk.StringVar()
        self.strip_var = tk.BooleanVar(value=False)
        self.source_var = tk.BooleanVar(value=False)
        self.show_same_var = tk.BooleanVar(value=False)
        self.search_var = tk.StringVar()
        self.status_var = tk.StringVar(value='选择同一个插件的旧版和新版；不执行、不解压、不联网。')
        self.summary_var = tk.StringVar(value='尚未对比')
        self.warning_var = tk.StringVar(value='只比较文件字节和静态线索，不证明安全，也不判断语义等价。')
        self.result = None
        self.paths = None
        self.worker = None
        self.cancel_event = threading.Event()
        self.messages = queue.Queue()
        self.closing = False
        self.items = {}
        self.controls = []
        page = ttk.Frame(root, padding=16)
        page.pack(fill='both', expand=True)
        ttk.Label(page, text='升级前，先看哪些文件变了', font=('Segoe UI', 19)).pack(anchor='w')
        ttk.Label(page, text='旧新版均在本机重新扫描；参数变化、注释或换行变化都会要求重新查看。').pack(anchor='w', pady=(3, 10))
        for name, variable in [('旧版', self.old_var), ('新版', self.new_var)]:
            row = ttk.Frame(page)
            row.pack(fill='x', pady=3)
            ttk.Label(row, text=name, width=6).pack(side='left')
            entry = ttk.Entry(row, textvariable=variable)
            entry.pack(side='left', fill='x', expand=True)
            button = ttk.Button(row, text='选择 ZIP…', command=lambda var=variable: self._pick(var))
            button.pack(side='left', padx=(8, 0))
            self.controls.extend([entry, button])
        options = ttk.Frame(page)
        options.pack(fill='x', pady=6)
        strip = ttk.Checkbutton(options, text='剥离唯一公共包装目录（例如 GitHub 源码包外层目录；需核对映射）', variable=self.strip_var)
        strip.pack(side='left')
        self.controls.append(strip)
        actions = ttk.Frame(page)
        actions.pack(fill='x')
        self.start_button = ttk.Button(actions, text='对比两个版本', command=self._start)
        self.start_button.pack(side='left')
        self.cancel_button = ttk.Button(actions, text='取消', command=self._cancel, state='disabled')
        self.cancel_button.pack(side='left', padx=8)
        self.html_button = ttk.Button(actions, text='导出 HTML…', command=lambda: self._save('html'), state='disabled')
        self.html_button.pack(side='right')
        self.json_button = ttk.Button(actions, text='导出 JSON…', command=lambda: self._save('json'), state='disabled')
        self.json_button.pack(side='right', padx=8)
        self.status_label = ttk.Label(page, textvariable=self.status_var, wraplength=980)
        self.status_label.pack(fill='x', pady=6)
        self.summary_label = ttk.Label(page, textvariable=self.summary_var, wraplength=980, font=('Segoe UI', 10, 'bold'))
        self.summary_label.pack(fill='x')
        self.warning_label = tk.Label(page, textvariable=self.warning_var, bg='#fff4dc', fg='#644100',
                                     anchor='w', justify='left', wraplength=980, padx=8, pady=6)
        self.warning_label.pack(fill='x', pady=6)
        root.bind('<Configure>', self._resize, add=True)
        filters = ttk.Frame(page)
        filters.pack(fill='x', pady=(0, 5))
        ttk.Checkbutton(filters, text='显示内容相同文件', variable=self.show_same_var, command=self._filter).pack(side='left')
        ttk.Label(filters, text='搜索路径').pack(side='left', padx=8)
        ttk.Entry(filters, textvariable=self.search_var).pack(side='left', fill='x', expand=True)
        self.search_var.trace_add('write', self._filter)
        box = ttk.Frame(page)
        box.pack(fill='both', expand=True)
        self.table = ttk.Treeview(box, columns=('status', 'path', 'clues'), show='headings', selectmode='browse')
        for key, label, width in [('status', '文件状态', 200), ('path', '对比路径', 480), ('clues', '旧 / 新线索数', 120)]:
            self.table.heading(key, text=label)
            self.table.column(key, width=width, minwidth=100)
        scroll = ttk.Scrollbar(box, orient='vertical', command=self.table.yview)
        self.table.configure(yscrollcommand=scroll.set)
        self.table.pack(side='left', fill='both', expand=True)
        scroll.pack(side='right', fill='y')
        self.table.bind('<<TreeviewSelect>>', self._detail)
        self.detail = tk.Text(page, height=7, wrap='word', state='disabled', font=('Segoe UI', 9))
        self.detail.pack(fill='x', pady=6)
        ttk.Checkbutton(page, text='导出包含源码（默认关闭；路径和哈希仍会导出）', variable=self.source_var).pack(anchor='w')
        root.protocol('WM_DELETE_WINDOW', self._close)

    def _resize(self, event):
        if event.widget is self.root:
            for label in (self.warning_label, self.status_label, self.summary_label):
                label.configure(wraplength=max(400, event.width - 60))

    def _pick(self, variable):
        path = filedialog.askopenfilename(parent=self.root, title='选择插件 ZIP', filetypes=[('ZIP', '*.zip')])
        if path:
            variable.set(path)

    def _busy(self, busy):
        for control in self.controls + [self.start_button]:
            control.configure(state='disabled' if busy else 'normal')
        self.cancel_button.configure(state='normal' if busy else 'disabled')
        for button in (self.html_button, self.json_button):
            button.configure(state='normal' if self.result is not None and not busy else 'disabled')

    def _start(self):
        if self.worker and self.worker.is_alive():
            return
        raw = [var.get().strip().strip('"') for var in (self.old_var, self.new_var)]
        if not all(raw):
            messagebox.showinfo('还差一个版本', '请分别选择旧版和新版 ZIP，或输入本地目录。', parent=self.root)
            return
        paths = tuple(Path(path).expanduser() for path in raw)
        strip = self.strip_var.get()
        self.cancel_event = threading.Event()
        self._busy(True)
        self.status_var.set('正在扫描两侧…' + (' 下方保留上次结果。' if self.result else ''))
        self.worker = threading.Thread(target=self._work, args=(paths, strip, self.cancel_event), daemon=True)
        self.worker.start()
        self.root.after(50, self._poll)

    def _work(self, paths, strip, cancel):
        try:
            result = compare.compare_targets(*paths, strip_wrapper=strip, cancel_check=cancel.is_set)
            scanner._check_cancelled(cancel.is_set)
            self.messages.put(('done', (result, paths)))
        except scanner.ScanCancelled:
            self.messages.put(('cancelled', None))
        except Exception as exc:
            self.messages.put(('error', str(exc)))

    def _poll(self):
        if self.closing:
            return
        try:
            kind, payload = self.messages.get_nowait()
        except queue.Empty:
            self.root.after(50, self._poll)
            return
        if self.cancel_event.is_set():
            kind = 'cancelled'
        if kind == 'done':
            self.result, self.paths = payload
            self.summary_var.set(compare.summary(self.result))
            roots = f'路径映射：旧 {self.result.old_root or "保留原路径"} → 新 {self.result.new_root or "保留原路径"}'
            self.warning_var.set(('存在未检查内容；单侧缺失为未知。' if self.result.old.incomplete or self.result.new.incomplete else '')
                                 + '文件字节相同不代表安全；未做语义分析。\n' + roots)
            self.status_var.set(f'当前结果：{self.paths[0].name} → {self.paths[1].name}')
            self._filter()
        elif kind == 'cancelled':
            self.status_var.set('本次已取消，上次结果保留。' if self.result else '已取消，未生成部分报告。')
        else:
            self.status_var.set('本次失败，上次结果保留。' if self.result else '本次对比失败。')
            messagebox.showerror('无法对比', payload, parent=self.root)
        self._busy(False)

    def _filter(self, *_args):
        if self.result is None:
            return
        self.table.delete(*self.table.get_children())
        self.items.clear()
        query = self.search_var.get().casefold().strip()
        for i, item in enumerate(sorted(self.result.files, key=lambda item: (item.status == 'same', item.path))):
            if (item.status == 'same' and not self.show_same_var.get()) or query not in item.path.casefold():
                continue
            iid = str(i)
            self.items[iid] = item
            self.table.insert('', 'end', iid=iid, values=(compare.STATUS[item.status], item.path,
                                                        f'{len(item.old_findings)} / {len(item.new_findings)}'))
        if self.items:
            self.table.selection_set(next(iter(self.items)))
            self._detail()
        else:
            self._write_detail('当前筛选没有文件；可勾选“显示内容相同文件”或清空搜索。没有变化不代表安全。')

    def _detail(self, *_args):
        selected = self.table.selection()
        if not selected or selected[0] not in self.items:
            return
        item = self.items[selected[0]]
        lines = [item.path, compare.STATUS[item.status], '文件对比不是语义判断；完整扫描的未检查原因见导出报告。',
                 item.diff_note, item.diff_preview]
        for side, entry, findings in [('旧版', item.old_file, item.old_findings), ('新版', item.new_file, item.new_findings)]:
            lines.append(f'\n{side}：' + (f"{entry['path']}\nSHA-256 {entry['sha256']}；完整读取 {entry['complete']}" if entry else '没有读取到'))
            lines.extend(f'L{f.line or "?"} [{f.code}] {f.evidence}\n{f.note}' for f in findings)
            if not findings:
                lines.append('没有已记录线索，不代表没有行为。')
        self._write_detail('\n'.join(lines))

    def _write_detail(self, text):
        self.detail.configure(state='normal')
        self.detail.delete('1.0', 'end')
        self.detail.insert('1.0', text)
        self.detail.configure(state='disabled')

    def _save(self, format):
        if self.result is None:
            return
        path = filedialog.asksaveasfilename(parent=self.root, initialfile=f'addon-upgrade.{format}',
                                          defaultextension=f'.{format}', filetypes=[(format.upper(), f'*.{format}')])
        if not path:
            return
        try:
            compare.save(self.result, Path(path), *self.paths, self.source_var.get(), format)
        except (scanner.ScanInputError, OSError, RuntimeError) as exc:
            messagebox.showerror('导出失败', str(exc), parent=self.root)
            return
        self.status_var.set(f'报告已保存：{path}；当前结果：{self.paths[0].name} → {self.paths[1].name}')

    def _cancel(self):
        self.cancel_event.set()
        self.cancel_button.configure(state='disabled')
        self.status_var.set('正在取消，下次读取检查点停止…')

    def _close(self):
        self.closing = True
        self.cancel_event.set()
        self.root.destroy()


def main():
    root = tk.Tk()
    CompareApp(root)
    root.mainloop()


if __name__ == '__main__':
    main()
