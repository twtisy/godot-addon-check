#!/usr/bin/env python3
"""Small local desktop interface for Godot Addon Check."""

from __future__ import annotations

import json
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from addoncheck import scanner


COLORS = {
    "ink": "#17251f",
    "muted": "#5f7168",
    "green": "#176b50",
    "green_dark": "#10513d",
    "green_pale": "#e8f4ee",
    "paper": "#f5f8f6",
    "white": "#ffffff",
    "line": "#dce7e0",
    "amber": "#845300",
    "amber_pale": "#fff4dc",
    "red": "#9b3434",
    "red_pale": "#fff0ef",
}


class PreflightApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Godot Addon Check")
        self.root.geometry("1000x800")
        self.root.minsize(820, 680)
        self.root.configure(bg=COLORS["paper"])

        self.input_var = tk.StringVar()
        self.status_var = tk.StringVar(value="选择插件 ZIP 或文件夹，先看静态线索再安装。")
        self.summary_var = tk.StringVar(value="尚未扫描")
        self.report_source_var = tk.StringVar(value="完成扫描后会显示结果来源。")
        self.interpretation_var = tk.StringVar(value="命中规则只代表需要查看上下文，不等于漏洞或恶意行为。")
        self.filter_var = tk.StringVar(value="全部")
        self.search_var = tk.StringVar()
        self.result_count_var = tk.StringVar(value="显示 0 条")
        self.group_var = tk.BooleanVar(value=True)
        self.export_evidence_var = tk.BooleanVar(value=False)
        self.report: scanner.ScanReport | None = None
        self.source_path: Path | None = None
        self.pending_source_path: Path | None = None
        self.findings: list[scanner.Finding] = []
        self.findings_by_item: dict[str, list[scanner.Finding]] = {}
        self.messages: queue.Queue[tuple[str, object]] = queue.Queue()
        self.cancel_event: threading.Event | None = None
        self.worker: threading.Thread | None = None

        self._configure_style()
        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._close)

    def _configure_style(self) -> None:
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TFrame", background=COLORS["paper"])
        style.configure("Card.TFrame", background=COLORS["white"])
        style.configure("TLabel", background=COLORS["paper"], foreground=COLORS["ink"], font=("Segoe UI", 10))
        style.configure("Card.TLabel", background=COLORS["white"], foreground=COLORS["ink"], font=("Segoe UI", 10))
        style.configure("Muted.TLabel", background=COLORS["paper"], foreground=COLORS["muted"], font=("Segoe UI", 9))
        style.configure("CardMuted.TLabel", background=COLORS["white"], foreground=COLORS["muted"], font=("Segoe UI", 9))
        style.configure("Card.TCheckbutton", background=COLORS["white"], foreground=COLORS["ink"])
        style.configure("Title.TLabel", background=COLORS["paper"], foreground=COLORS["ink"], font=("Segoe UI Semibold", 22))
        style.configure("Section.TLabel", background=COLORS["white"], foreground=COLORS["ink"], font=("Segoe UI Semibold", 11))
        style.configure("Primary.TButton", font=("Segoe UI Semibold", 10), padding=(16, 9))
        style.map("Primary.TButton", foreground=[("!disabled", COLORS["white"])], background=[("!disabled", COLORS["green"]), ("active", COLORS["green_dark"])])
        style.configure("TButton", font=("Segoe UI", 9), padding=(10, 7))
        style.configure("Treeview", font=("Segoe UI", 9), rowheight=29, background=COLORS["white"], fieldbackground=COLORS["white"], foreground=COLORS["ink"])
        style.configure("Treeview.Heading", font=("Segoe UI Semibold", 9), background="#eef3ef", foreground=COLORS["ink"], padding=(8, 7))
        style.map("Treeview", background=[("selected", "#d9eee3")], foreground=[("selected", COLORS["ink"])])
        style.configure("Horizontal.TProgressbar", troughcolor=COLORS["green_pale"], background=COLORS["green"])

    def _build_ui(self) -> None:
        page = ttk.Frame(self.root, padding=(22, 16, 22, 14))
        page.pack(fill="both", expand=True)

        top = ttk.Frame(page)
        top.pack(fill="x")
        ttk.Button(top, text="旧版 / 新版对比…", command=self._open_compare).pack(side="right")
        ttk.Label(top, text="GODOT · ADDON PREFLIGHT", style="Muted.TLabel").pack(anchor="w")
        ttk.Label(top, text="安装前，先查插件的关键线索", style="Title.TLabel").pack(anchor="w", pady=(5, 3))
        ttk.Label(top, text="本地检查插件目录或 ZIP，列出值得人工复核的代码与文件线索。", style="Muted.TLabel").pack(anchor="w")

        privacy = tk.Frame(page, bg=COLORS["green_pale"], highlightbackground="#cfe4d8", highlightthickness=1, padx=14, pady=10)
        privacy.pack(fill="x", pady=(12, 10))
        tk.Label(privacy, text="本地处理", bg=COLORS["green_pale"], fg=COLORS["green_dark"], font=("Segoe UI Semibold", 10)).pack(side="left", padx=(0, 12))
        tk.Label(privacy, text="不执行插件 · 不联网 · 不上传文件 · ZIP 不会被解压", bg=COLORS["green_pale"], fg=COLORS["ink"], font=("Segoe UI", 9)).pack(side="left")

        picker = ttk.Frame(page, style="Card.TFrame", padding=12)
        picker.pack(fill="x")
        ttk.Label(picker, text="选择要检查的内容", style="Section.TLabel").pack(anchor="w")
        ttk.Label(picker, text="支持 .zip 插件包或已解压的文件夹；默认最多扫描 2,000 个文件和 32 MiB 内容。", style="CardMuted.TLabel").pack(anchor="w", pady=(3, 10))
        path_row = ttk.Frame(picker, style="Card.TFrame")
        path_row.pack(fill="x")
        self.path_entry = ttk.Entry(path_row, textvariable=self.input_var)
        self.path_entry.pack(side="left", fill="x", expand=True, ipady=6)
        self.pick_zip_button = ttk.Button(path_row, text="选择 ZIP…", command=self._pick_zip)
        self.pick_zip_button.pack(side="left", padx=(8, 0))
        self.pick_folder_button = ttk.Button(path_row, text="选择文件夹…", command=self._pick_folder)
        self.pick_folder_button.pack(side="left", padx=(8, 0))

        actions = ttk.Frame(picker, style="Card.TFrame")
        actions.pack(fill="x", pady=(10, 0))
        self.scan_button = ttk.Button(actions, text="开始预检", style="Primary.TButton", command=self._start_scan)
        self.scan_button.pack(side="left")
        self.cancel_button = ttk.Button(actions, text="取消扫描", command=self._cancel_scan, state="disabled")
        self.cancel_button.pack(side="left", padx=(8, 0))
        self.progress = ttk.Progressbar(actions, mode="indeterminate", length=150)
        self.progress.pack(side="left", padx=(14, 10))
        ttk.Label(actions, textvariable=self.status_var, style="CardMuted.TLabel").pack(side="left", fill="x", expand=True)

        summary = ttk.Frame(page, style="Card.TFrame", padding=(12, 9))
        summary.pack(fill="x", pady=(10, 9))
        self.summary_label = tk.Label(summary, textvariable=self.summary_var, bg=COLORS["white"], fg=COLORS["ink"], font=("Segoe UI Semibold", 11), anchor="w", wraplength=960, justify="left")
        self.summary_label.pack(fill="x")
        self.source_label = ttk.Label(summary, textvariable=self.report_source_var, style="CardMuted.TLabel", wraplength=900)
        self.source_label.pack(anchor="w", pady=(4, 0))
        self.interpretation_label = ttk.Label(summary, textvariable=self.interpretation_var, style="CardMuted.TLabel", wraplength=900)
        self.interpretation_label.pack(anchor="w", pady=(4, 0))
        summary.bind("<Configure>", self._resize_summary)

        results = ttk.Frame(page, style="Card.TFrame", padding=12)
        results.pack(fill="both", expand=True)
        result_head = ttk.Frame(results, style="Card.TFrame")
        result_head.pack(fill="x", pady=(0, 8))
        ttk.Label(result_head, text="检查线索", style="Section.TLabel").pack(side="left")
        ttk.Checkbutton(result_head, text="合并重复线索", variable=self.group_var,
                        command=self._apply_filter, style="Card.TCheckbutton").pack(side="left", padx=(12, 0))
        self.html_button = ttk.Button(result_head, text="导出 HTML 报告…", command=self._save_html, state="disabled")
        self.html_button.pack(side="right")
        self.json_button = ttk.Button(result_head, text="导出 JSON…", command=self._save_json, state="disabled")
        self.json_button.pack(side="right", padx=(0, 8))

        filter_row = ttk.Frame(results, style="Card.TFrame")
        filter_row.pack(fill="x", pady=(0, 8))
        ttk.Label(filter_row, text="筛选", style="CardMuted.TLabel").pack(side="left", padx=(0, 6))
        filter_box = ttk.Combobox(filter_row, textvariable=self.filter_var, state="readonly", width=11, values=("全部", "需查看", "提示"))
        filter_box.pack(side="left")
        filter_box.bind("<<ComboboxSelected>>", self._apply_filter)
        ttk.Label(filter_row, text="关键词", style="CardMuted.TLabel").pack(side="left", padx=(14, 6))
        ttk.Label(filter_row, textvariable=self.result_count_var, style="CardMuted.TLabel").pack(side="right", padx=(8, 0))
        ttk.Button(filter_row, text="清空", command=lambda: self.search_var.set("")).pack(side="right", padx=(8, 0))
        search_entry = ttk.Entry(filter_row, textvariable=self.search_var, width=36)
        search_entry.pack(side="left", fill="x", expand=True)
        self.search_var.trace_add("write", self._apply_filter)

        table_wrap = ttk.Frame(results, style="Card.TFrame")
        table_wrap.pack(fill="both", expand=True)
        columns = ("severity", "title", "location")
        self.table = ttk.Treeview(table_wrap, columns=columns, show="headings", height=8, selectmode="browse")
        self.table.heading("severity", text="级别")
        self.table.heading("title", text="发现线索")
        self.table.heading("location", text="文件位置")
        self.table.column("severity", width=90, minwidth=75, stretch=False, anchor="center")
        self.table.column("title", width=300, minwidth=180, stretch=True)
        self.table.column("location", width=390, minwidth=180, stretch=True)
        self.table.tag_configure("review", foreground=COLORS["amber"])
        self.table.tag_configure("info", foreground=COLORS["muted"])
        yscroll = ttk.Scrollbar(table_wrap, orient="vertical", command=self.table.yview)
        xscroll = ttk.Scrollbar(table_wrap, orient="horizontal", command=self.table.xview)
        self.table.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        table_wrap.columnconfigure(0, weight=1)
        table_wrap.rowconfigure(0, weight=1)
        self.table.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        self.table.bind("<<TreeviewSelect>>", self._show_finding)

        detail = ttk.Frame(results, style="Card.TFrame")
        detail.pack(fill="x", pady=(10, 0))
        ttk.Label(detail, text="证据与下一步", style="Section.TLabel").pack(anchor="w", pady=(0, 5))
        detail_body = ttk.Frame(detail, style="Card.TFrame")
        detail_body.pack(fill="x")
        self.detail = tk.Text(detail_body, height=4, wrap="word", bg="#f8faf8", fg=COLORS["ink"], relief="flat", padx=10, pady=8, font=("Segoe UI", 9), state="disabled")
        detail_scroll = ttk.Scrollbar(detail_body, orient="vertical", command=self.detail.yview)
        self.detail.configure(yscrollcommand=detail_scroll.set)
        self.detail.pack(side="left", fill="x", expand=True)
        detail_scroll.pack(side="right", fill="y")

        footer = ttk.Frame(page)
        footer.pack(fill="x", pady=(7, 0))
        ttk.Checkbutton(footer, text="导出包含源码行", variable=self.export_evidence_var).pack(side="left")
        ttk.Label(footer, text="默认隐藏源码；分享前检查路径等信息。未命中不代表安全。", style="Muted.TLabel").pack(side="left", padx=(8, 0))

    def _open_compare(self) -> None:
        from addoncheck.compare_window import CompareApp
        CompareApp(tk.Toplevel(self.root))

    def _pick_zip(self) -> None:
        chosen = filedialog.askopenfilename(
            parent=self.root,
            title="选择 Godot 插件 ZIP",
            filetypes=(("ZIP 文件", "*.zip"), ("所有文件", "*.*")),
        )
        if chosen:
            self.input_var.set(chosen)

    def _resize_summary(self, event: tk.Event) -> None:
        width = max(180, event.width - 32)
        self.summary_label.configure(wraplength=width)
        self.source_label.configure(wraplength=width)
        self.interpretation_label.configure(wraplength=width)

    def _pick_folder(self) -> None:
        chosen = filedialog.askdirectory(parent=self.root, title="选择已解压的 Godot 插件文件夹")
        if chosen:
            self.input_var.set(chosen)

    def _start_scan(self) -> None:
        raw_path = self.input_var.get().strip().strip('"')
        if not raw_path:
            messagebox.showinfo("先选一个插件", "选择 ZIP 文件或已解压的插件文件夹后，再开始预检。", parent=self.root)
            return
        target = Path(raw_path).expanduser()
        try:
            path_exists = target.exists()
            resolved_target = target.resolve()
        except (OSError, RuntimeError) as exc:
            messagebox.showerror("无法读取路径", str(exc), parent=self.root)
            return
        if not path_exists:
            messagebox.showerror("找不到这个路径", "请检查路径，或重新选择 ZIP/文件夹。", parent=self.root)
            return
        if not target.is_dir() and target.suffix.casefold() != ".zip":
            messagebox.showinfo("格式暂不支持", "请选择 .zip 文件或文件夹。", parent=self.root)
            return

        self.pending_source_path = resolved_target
        self._set_busy(True)
        self.status_var.set(f"正在检查 {target.name}…" + (" 下方保留上次结果。" if self.report else ""))
        if self.report is None:
            self.summary_var.set("正在扫描，请稍候…")
        self.cancel_event = threading.Event()
        self.worker = threading.Thread(
            target=self._scan_worker,
            args=(target, self.cancel_event),
            name="godot-addon-preflight-scan",
            daemon=True,
        )
        self.worker.start()
        self.root.after(100, self._poll_worker)

    def _scan_worker(self, target: Path, cancel_event: threading.Event) -> None:
        try:
            report = scanner.scan_target(target, cancel_check=cancel_event.is_set)
            if cancel_event.is_set():
                raise scanner.ScanCancelled()
            self.messages.put(("done", report))
        except scanner.ScanCancelled:
            self.messages.put(("cancelled", None))
        except Exception as exc:
            self.messages.put(("error", str(exc)))

    def _poll_worker(self) -> None:
        try:
            kind, payload = self.messages.get_nowait()
        except queue.Empty:
            if self.worker and self.worker.is_alive():
                self.root.after(100, self._poll_worker)
                return
            self._set_busy(False)
            self.status_var.set("扫描已结束。")
            return

        self._set_busy(False)
        if kind == "done" and self.cancel_event is not None and self.cancel_event.is_set():
            kind = "cancelled"
        if kind == "done" and isinstance(payload, scanner.ScanReport):
            self._clear_result()
            self.report = payload
            self.source_path = self.pending_source_path
            self._render_report(payload)
            self.status_var.set("完成；有未检查的内容，请查看对应提示。" if payload.incomplete else "完成。本次结果只代表静态规则线索。")
        elif kind == "cancelled":
            self.status_var.set("已取消本次扫描。" + ("上次结果已保留，可继续查看和导出。" if self.report else ""))
            if self.report is None:
                self.summary_var.set("扫描已取消")
                self._write_detail("没有生成部分报告。选择插件后可以重新扫描。")
        else:
            self.status_var.set("本次扫描失败。" + ("上次结果已保留。" if self.report else "请重新选择插件后重试。"))
            if self.report is None:
                self.summary_var.set("扫描未完成")
                self._write_detail(f"扫描失败：{payload}\n请检查文件是否损坏、路径是否可读，再重试。")
            messagebox.showerror("预检失败", f"{payload}\n\n请检查文件是否损坏、路径是否可读，再重试。", parent=self.root)
        self.pending_source_path = None

    def _cancel_scan(self) -> None:
        if self.cancel_event is not None:
            self.cancel_event.set()
            self.cancel_button.configure(state="disabled")
            self.status_var.set("正在停止；会在下一个文件检查点退出。")

    def _set_busy(self, busy: bool) -> None:
        state = "disabled" if busy else "normal"
        self.scan_button.configure(state=state)
        self.pick_zip_button.configure(state=state)
        self.pick_folder_button.configure(state=state)
        self.path_entry.configure(state=state)
        self.cancel_button.configure(state="normal" if busy else "disabled")
        export_state = "normal" if not busy and self.report is not None else "disabled"
        self.html_button.configure(state=export_state)
        self.json_button.configure(state=export_state)
        if busy:
            self.progress.start(12)
        else:
            self.progress.stop()

    def _clear_result(self) -> None:
        self.report = None
        self.findings.clear()
        self.findings_by_item.clear()
        for item in self.table.get_children():
            self.table.delete(item)
        self._write_detail("扫描完成后，选择一条线索查看原始行和人工检查建议。")
        self.summary_var.set("正在准备扫描…")
        self.report_source_var.set("完成扫描后会显示结果来源。")
        self.interpretation_var.set("命中项需要结合上下文判断；没有命中不等于插件安全。")
        self.filter_var.set("全部")
        self.search_var.set("")
        self.result_count_var.set("显示 0 条")
        self.html_button.configure(state="disabled")
        self.json_button.configure(state="disabled")

    def _render_report(self, report: scanner.ScanReport) -> None:
        review_count = sum(1 for finding in report.findings if finding.severity == "review")
        info_count = sum(1 for finding in report.findings if finding.severity == "info")
        if review_count or info_count:
            summary = f"找到 {review_count} 条需人工查看的线索，另有 {info_count} 条信息提示"
        else:
            summary = "本次规则没有命中线索"
        summary += f" · 检查 {report.scripts_checked} 份脚本 · 读取 {report.files_scanned}/{report.files_seen} 个文件"
        if report.incomplete:
            summary += " · 存在未检查内容"
        self.summary_var.set(summary)
        self.report_source_var.set(f"当前结果来源：{self.source_path or report.target_name}")
        if report.incomplete:
            self.interpretation_var.set("部分内容未检查；查看读取失败、格式或上限提示，处理后可重新扫描。")
        else:
            self.interpretation_var.set("静态规则只提供复核线索；命中不等于漏洞，没有命中也不代表安全。")
        self.summary_label.configure(fg=COLORS["amber"] if review_count or report.incomplete else COLORS["muted"])

        self.findings = list(report.findings)
        self._apply_filter()
        self.html_button.configure(state="normal")
        self.json_button.configure(state="normal")

    def _apply_filter(self, *_args: object) -> None:
        if not hasattr(self, "table") or self.report is None:
            return
        for item in self.table.get_children():
            self.table.delete(item)
        self.findings_by_item.clear()

        query = self.search_var.get().strip().casefold()
        severity_filter = self.filter_var.get()
        matched = 0
        grouped: dict[tuple, list[scanner.Finding]] = {}
        for index, finding in enumerate(self.findings):
            if severity_filter == "需查看" and finding.severity != "review":
                continue
            if severity_filter == "提示" and finding.severity != "info":
                continue
            searchable = " ".join((finding.code, finding.title, finding.path, finding.evidence, finding.note)).casefold()
            if query and query not in searchable:
                continue
            key = (finding.code, finding.path) if self.group_var.get() else (index,)
            grouped.setdefault(key, []).append(finding)
            matched += 1
        for index, group in enumerate(grouped.values()):
            finding = group[0]
            item_id = f"f{index}"
            severity = "需查看" if finding.severity == "review" else "提示"
            location = finding.path or "（整个插件包）"
            if finding.line is not None:
                location += f":{finding.line}"
            title = finding.title + (f"（{len(group)} 处）" if len(group) > 1 else "")
            self.table.insert("", "end", iid=item_id, values=(severity, title, location), tags=(finding.severity,))
            self.findings_by_item[item_id] = group
        self.result_count_var.set(f"{len(grouped)} 组 / {matched} 条")

        if matched:
            first = self.table.get_children()[0]
            self.table.selection_set(first)
            self.table.focus(first)
            self._show_finding()
        elif self.findings:
            self._write_detail("没有符合当前筛选条件的线索；试试清空关键词或切换筛选项。")
        else:
            self._write_detail("本次规则没有命中。这不是安全认证；仍建议核对来源、作者、授权和版本兼容性。")
            if self.report.incomplete:
                self._append_detail("\n\n部分内容未检查，请查看扫描说明。")
            self._append_detail("\n\n" + "\n".join(f"• {note}" for note in self.report.limitations))

    def _show_finding(self, _event: tk.Event[tk.Misc] | None = None) -> None:
        selection = self.table.selection()
        if not selection:
            return
        group = self.findings_by_item.get(selection[0])
        if not group:
            return
        finding = group[0]
        location = finding.path or "整个插件包"
        if finding.line is not None:
            location += f":{finding.line}"
        severity = "需要人工查看" if finding.severity == "review" else "信息提示"
        parts = [f"{severity} · {finding.title}", f"位置：{location}"]
        if finding.evidence:
            parts.append(f"证据：{finding.evidence}")
        if finding.note:
            parts.append(f"建议：{finding.note}")
        if len(group) > 1:
            parts.append(f"同文件同类线索共 {len(group)} 处：")
            parts.extend(f"第 {item.line or '?'} 行：{item.evidence}" for item in group[1:20])
            if len(group) > 20:
                parts.append("仅显示前 20 处；完整线索可在取消合并后查看，或主动附带源码导出。")
        if self.report is not None:
            if self.report.incomplete:
                parts.append("本次存在未检查内容，不能据此判断整个插件。")
        self._write_detail("\n".join(parts))

    def _write_detail(self, text: str) -> None:
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", text)
        self.detail.configure(state="disabled")

    def _append_detail(self, text: str) -> None:
        self.detail.configure(state="normal")
        self.detail.insert("end", text)
        self.detail.configure(state="disabled")

    def _save_html(self) -> None:
        if self.report is None:
            return
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="保存 HTML 预检报告",
            initialfile=self._suggested_report_name("html"),
            defaultextension=".html",
            filetypes=(("HTML 报告", "*.html"),),
        )
        if not path:
            return
        if not self._export_path_is_safe(Path(path)):
            messagebox.showerror("不能保存到这里", "报告不能覆盖插件文件，也不能写进正在检查的插件文件夹。", parent=self.root)
            return
        try:
            scanner.write_report(Path(path), scanner.render_html(self.report, self.export_evidence_var.get()), self.source_path)
        except (scanner.ScanInputError, OSError, RuntimeError) as exc:
            messagebox.showerror("保存失败", str(exc), parent=self.root)
            return
        self.status_var.set(f"HTML 报告已保存：{path}")

    def _save_json(self) -> None:
        if self.report is None:
            return
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="保存 JSON 预检报告",
            initialfile=self._suggested_report_name("json"),
            defaultextension=".json",
            filetypes=(("JSON 报告", "*.json"),),
        )
        if not path:
            return
        if not self._export_path_is_safe(Path(path)):
            messagebox.showerror("不能保存到这里", "报告不能覆盖插件文件，也不能写进正在检查的插件文件夹。", parent=self.root)
            return
        try:
            scanner.write_report(Path(path),
                json.dumps(scanner.report_to_dict(self.report, self.export_evidence_var.get()), ensure_ascii=False, indent=2) + "\n",
                self.source_path,
            )
        except (scanner.ScanInputError, OSError, RuntimeError) as exc:
            messagebox.showerror("保存失败", str(exc), parent=self.root)
            return
        self.status_var.set(f"JSON 报告已保存：{path}")

    def _export_path_is_safe(self, output: Path) -> bool:
        if self.source_path is None:
            return False
        try:
            destination = output.resolve()
        except (OSError, RuntimeError):
            return False
        if destination == self.source_path:
            return False
        if self.source_path.is_dir() and self.source_path in destination.parents:
            return False
        return True

    def _suggested_report_name(self, extension: str) -> str:
        target_name = self.report.target_name if self.report is not None else "插件"
        stem = Path(target_name).stem or "插件"
        safe_stem = "".join(
            "_" if char in '<>:"/\\|?*' or ord(char) < 32 else char
            for char in stem
        ).strip(" .") or "插件"
        return f"{safe_stem}-预检报告.{extension}"

    def _close(self) -> None:
        if self.cancel_event is not None and self.worker is not None and self.worker.is_alive():
            self.cancel_event.set()
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    PreflightApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
