#!/usr/bin/env python3
"""Compare bytes read from two local add-on packages, with static clues on each side."""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict, dataclass
import difflib
import html
import json
from pathlib import Path

from addoncheck import scanner

STATUS = {
    'changed': '内容变化，需复核', 'same': '已读完整文件内容相同',
    'newly_read': '仅新版读到', 'previously_read': '仅旧版读到',
    'unknown': '不可比较 / 另一侧未知',
}
EN_STATUS = {'changed': 'Changed bytes: review', 'same': 'Same fully-read bytes',
             'newly_read': 'Read only in new', 'previously_read': 'Read only in old',
             'unknown': 'Unknown / not comparable'}


@dataclass
class FileChange:
    path: str
    status: str
    old_file: dict | None
    new_file: dict | None
    old_findings: list[scanner.Finding]
    new_findings: list[scanner.Finding]
    diff_preview: str = ''
    diff_note: str = '仅有文件指纹对照；未生成文本预览。'


@dataclass
class Comparison:
    old: scanner.ScanReport
    new: scanner.ScanReport
    old_root: str
    new_root: str
    files: list[FileChange]
    warnings: list[str]
    schema_version: str = 'comparison-0.1'


def _index(report: scanner.ScanReport, strip_wrapper: bool) -> tuple[dict, dict, str]:
    if not report.file_manifest:
        raise scanner.ScanInputError('没有已读取文件清单，无法进行文件对比。')
    paths = [item['path'] for item in report.file_manifest]
    root = ''
    if strip_wrapper:
        tops = {path.split('/')[0] for path in paths}
        if len(tops) != 1 or any('/' not in path for path in paths):
            raise scanner.ScanInputError('剥离失败：每侧必须有唯一公共包装目录，且不能有根级文件。')
        root = next(iter(tops)) + '/'
    files, clues, folded = {}, {}, set()
    for item in report.file_manifest:
        path = item['path'][len(root):]
        parts = path.split('/')
        if not path or any(part in ('', '.', '..') for part in parts) or '\\' in path:
            raise scanner.ScanInputError('文件路径不规范，不能可靠对比。')
        if path.casefold() in folded:
            raise scanner.ScanInputError(f'路径重复或大小写碰撞，不能合并：{path}')
        folded.add(path.casefold())
        files[path] = item
        clues[path] = []
    for finding in report.findings:
        if root and not finding.path.startswith(root):
            continue
        path = finding.path[len(root):]
        if path in clues:
            clues[path].append(finding)
    return files, clues, root


def compare_reports(old: scanner.ScanReport, new: scanner.ScanReport,
                    strip_wrapper: bool = False) -> Comparison:
    if (old.scanner_version, old.ruleset_version) != (new.scanner_version, new.ruleset_version):
        raise scanner.ScanInputError('扫描器或规则版本不同；请使用当前版本重新扫描两侧。')
    left, left_clues, old_root = _index(old, strip_wrapper)
    right, right_clues, new_root = _index(new, strip_wrapper)
    warnings = [
        '先确认旧新版属于同一个插件及正确版本；本工具不能核验来源或发布者身份。',
        '只比较已读取文件的字节，不判断语义等价或风险变化；内容相同不代表安全。',
        '仅一侧读到不等于真实新增/删除；不识别文件重命名。默认排除的目录不在对比范围。',
        '代码线索仅覆盖有限的 UTF-8 .gd/.cs API；资源、原生库、动态行为未作完整分析。',
    ]
    uncertain = old.incomplete or new.incomplete or old.limited or new.limited
    if uncertain:
        warnings.insert(0, '至少一侧存在未检查内容；单侧缺失全部标为未知，不能推断线索消失。')
    if strip_wrapper:
        warnings.append(f'用户选择剥离公共目录：旧 {old_root}；新 {new_root}。请确认此路径映射合理。')
    changes = []
    for path in sorted(left.keys() | right.keys()):
        before, after = left.get(path), right.get(path)
        if before and after:
            if not before['complete'] or not after['complete']:
                state = 'unknown'
            else:
                state = 'same' if before['sha256'] == after['sha256'] else 'changed'
        elif uncertain:
            state = 'unknown'
        else:
            state = 'newly_read' if after else 'previously_read'
        changes.append(FileChange(path, state, before, after,
                                  left_clues.get(path, []), right_clues.get(path, [])))
    return Comparison(old, new, old_root, new_root, changes, warnings)


def compare_targets(old_path: Path, new_path: Path, strip_wrapper: bool = False,
                    cancel_check=None) -> Comparison:
    snapshots = []
    old = scanner.scan_target(old_path, cancel_check=cancel_check, file_observer=snapshots.append)
    new = scanner.scan_target(new_path, cancel_check=cancel_check, file_observer=snapshots.append)
    scanner._check_cancelled(cancel_check)
    result = compare_reports(old, new, strip_wrapper)
    # Reuse scan-time bytes, never reopen an input to fabricate a consistent preview.
    left, right = ({file.path: file for file in files} for files in snapshots)
    preview_budget = 524_288
    preview_count = 0
    for item in result.files:
        scanner._check_cancelled(cancel_check)
        if item.status != 'changed':
            item.diff_note = '非两侧完整读取的内容变化文件，不生成差异预览。'
            continue
        before, after = left[item.old_file['path']], right[item.new_file['path']]
        size = len(before.data) + len(after.data)
        if preview_count >= 100 or size > preview_budget:
            item.diff_note = '达到本次预览预算（100 文件 / 总输入 512 KiB）；请在编辑器中查看。'
            continue
        if max(len(before.data), len(after.data)) > 65_536:
            item.diff_note = '超过每侧 64 KiB 文本预览上限；文件仍已对比，预览未生成。'
            continue
        try:
            if b'\x00' in before.data or b'\x00' in after.data:
                raise UnicodeError('binary')
            old_lines = before.data.decode('utf-8-sig').splitlines()
            new_lines = after.data.decode('utf-8-sig').splitlines()
        except UnicodeError:
            item.diff_note = '二进制或非 UTF-8 内容：只比较字节，不生成文本差异。'
            continue
        if max(len(old_lines), len(new_lines)) > 2000:
            item.diff_note = '超过每侧 2,000 行预览上限；请在编辑器中查看。'
            continue
        preview_budget -= size
        preview_count += 1
        lines, total, truncated = [], 0, False
        for line in difflib.unified_diff(old_lines, new_lines, fromfile='旧版/' + item.path,
                                         tofile='新版/' + item.path, lineterm=''):
            scanner._check_cancelled(cancel_check)
            if len(lines) >= 150 or total + len(line) > 16_000:
                truncated = True
                break
            lines.append(line)
            total += len(line)
        item.diff_preview = '\n'.join(lines)
        item.diff_note = ('差异预览已截断（150 行 / 16,000 字符），不是完整 diff。' if truncated else
                          'UTF-8 文本差异预览；不做语义判断。')
        if not lines:
            item.diff_note = '字节不同，但逐行文本相同（可能是换行符或 BOM）；仍需复核。'
    return result


def summary(result: Comparison) -> str:
    counts = Counter(item.status for item in result.files)
    return ' · '.join(f'{STATUS[key]} {counts[key]}'
                      for key in ('changed', 'newly_read', 'previously_read', 'unknown', 'same'))


def to_dict(result: Comparison, include_source: bool = False) -> dict:
    # Redact using the same policy as single-scan exports; never round-trip untrusted reports.
    data = {'schema_version': result.schema_version, 'old_root': result.old_root,
            'new_root': result.new_root, 'warnings': result.warnings,
            'old': scanner.report_to_dict(result.old, include_source),
            'new': scanner.report_to_dict(result.new, include_source), 'files': [],
            'source_evidence_included': include_source}
    for item in result.files:
        row = asdict(item)
        if not include_source:
            row['diff_preview'] = '（源码差异默认隐藏）' if item.diff_preview else ''
        for name in ('old_findings', 'new_findings'):
            if not include_source:
                for finding in row[name]:
                    if finding['line'] is not None or finding['code'].startswith('plugin_entry'):
                        finding['evidence'] = '（源码证据默认隐藏）'
        data['files'].append(row)
    return data


def render_html(result: Comparison, include_source: bool = False) -> str:
    esc = html.escape
    data = to_dict(result, include_source)

    def clues(findings):
        return ''.join(f"<li>{esc(f['code'])} · L{f['line'] or '?'}<pre>{esc(f['evidence'])}</pre></li>" for f in findings) or '无已记录线索'

    rows = []
    # Changes first. Same-byte files remain accessible without cluttering the initial report.
    for row in sorted(data['files'], key=lambda item: (item['status'] == 'same', item['path'])):
        def meta(side):
            entry = row[f'{side}_file']
            return (f"<small>原路径：{esc(entry['path'])}<br>SHA-256：{esc(entry['sha256'])}<br>"
                    f"读取 {entry['bytes_read']} 字节 · 完整读取 {entry['complete']}</small>") if entry else '未读到文件'
        rows.append(f"<tr><td>{esc(STATUS[row['status']])}<br><code>{esc(row['path'])}</code>"
                    f"<p>{esc(row['diff_note'])}</p><details><summary>文本差异预览</summary><pre>{esc(row['diff_preview'])}</pre></details></td>"
                    f"<td>{meta('old')}<ul>{clues(row['old_findings'])}</ul></td>"
                    f"<td>{meta('new')}<ul>{clues(row['new_findings'])}</ul></td></tr>")
    notice = ''.join(f'<li>{esc(item)}</li>' for item in result.warnings)
    scans = ''.join(f"<h3>{name}：{esc(report.target_name)}</h3><p>SHA-256：<code>{esc(report.input_sha256)}</code><br>"
                    f"{esc(report.fingerprint_scope)} · 已读 {report.files_scanned} 文件 / {report.scripts_checked} 脚本 · "
                    f"未检查内容：{report.incomplete} · 达到上限：{report.limited}</p>"
                    f"<details><summary>完整扫描说明与线索</summary><pre>{esc(scanner.render_text(report, include_source))}</pre></details>"
                    for name, report in [('旧版', result.old), ('新版', result.new)])
    return f'''<!doctype html><html lang="zh-Hans"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Godot 插件升级对比</title>
<style>body{{font:15px/1.6 system-ui;max-width:1200px;margin:30px auto;padding:0 20px;color:#20372c}}
table{{border-collapse:collapse;width:100%;min-width:760px}}td,th{{border:1px solid #d4dfd8;padding:12px;vertical-align:top;text-align:left}}
pre,code,small{{white-space:pre-wrap;overflow-wrap:anywhere}}.table{{overflow:auto}}.notice{{background:#fff4dc;padding:16px}}
small{{display:block}}td{{width:33%}}</style><h1>插件升级前：文件与线索对照</h1>
<p>扫描器 {esc(result.old.scanner_version)} · 规则 {esc(result.old.ruleset_version)} · 源码证据：{'已包含' if include_source else '隐藏'}</p>
<div class="notice"><ul>{notice}</ul></div><h2>{esc(summary(result))}</h2>{scans}
<div class="table"><table><thead><tr><th>文件与状态</th><th>旧版</th><th>新版</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div></html>'''


def validate_destination(output: Path, old_path: Path, new_path: Path) -> None:
    """Protect both inputs before generating or writing an export."""
    destination = output.resolve()
    for source in (old_path, new_path):
        resolved = source.resolve()
        if destination == resolved or (source.is_dir() and resolved in destination.parents):
            raise scanner.ScanInputError('对比报告不能覆盖任一输入或写入任一被扫描目录。')


def save(result: Comparison, output: Path, old_path: Path, new_path: Path,
         include_source: bool = False, format: str = 'html') -> None:
    validate_destination(output, old_path, new_path)
    content = (json.dumps(to_dict(result, include_source), ensure_ascii=False, indent=2) + '\n'
               if format == 'json' else render_html(result, include_source))
    scanner.write_report(output, content, old_path)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('old', type=Path)
    parser.add_argument('new', type=Path)
    parser.add_argument('--strip-wrapper', action='store_true', help='主动剥离每侧唯一公共包装目录；请核对映射')
    parser.add_argument('--include-source', action='store_true')
    parser.add_argument('--html', type=Path)
    parser.add_argument('--json', type=Path)
    parser.add_argument('--lang', choices=['en', 'zh'], default='en', help='Terminal and HTML language (default: en)')
    parser.add_argument('--fail-on-change', action='store_true', help='Exit 1 on file byte changes; unknown scope still exits 3')
    parser.add_argument('--version', action='version', version=scanner.SCANNER_VERSION)
    args = parser.parse_args(argv)
    import sys
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(errors='backslashreplace')
    try:
        if args.html and args.json and args.html.resolve() == args.json.resolve():
            raise scanner.ScanInputError('HTML 和 JSON 不能写入同一路径。')
        for path in (args.html, args.json):
            if path:
                validate_destination(path, args.old, args.new)
        result = compare_targets(args.old, args.new, args.strip_wrapper)
        for path, format in ((args.html, 'html'), (args.json, 'json')):
            if path:
                if format == 'html' and args.lang == 'en':
                    from addoncheck.report import render
                    # Check both inputs before using the shared atomic writer.
                    validate_destination(path, args.old, args.new)
                    scanner.write_report(path, render(result, args.include_source), args.old)
                else:
                    save(result, path, args.old, args.new, args.include_source, format)
        labels = EN_STATUS if args.lang == 'en' else STATUS
        if args.lang == 'en':
            print(' | '.join(f'{labels[k]}: {Counter(f.status for f in result.files)[k]}' for k in labels))
            print('Byte comparison and finite static clues only. Not a safety verdict. Verify package identity and path mapping.')
            print(f'Unknown scan scope: old={result.old.incomplete}, new={result.new.incomplete}')
        else:
            print(summary(result))
            for warning in result.warnings:
                print(warning)
        for item in result.files:
            if item.status != 'same':
                print(f'[{labels[item.status]}] {item.path} | clues {len(item.old_findings)} -> {len(item.new_findings)}')
                if args.include_source and item.diff_preview:
                    print(item.diff_note + '\n' + item.diff_preview)
        # Unknown coverage is visible to automation, not silently treated as full success.
        if result.old.incomplete or result.new.incomplete:
            return 3
        return 1 if args.fail_on_change and any(f.status != 'same' for f in result.files) else 0
    except (scanner.ScanInputError, OSError, RuntimeError) as exc:
        import sys
        print(f'Comparison failed: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
