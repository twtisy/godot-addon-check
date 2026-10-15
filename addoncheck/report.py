"""English HTML for the CLI release; no browser, network or plugin execution."""
from collections import Counter
import html

from addoncheck import scanner
from addoncheck import compare


def render(result, include_source=False):
    esc = html.escape
    data = compare.to_dict(result, include_source)

    def evidence(value):
        if value in ('（源码证据默认隐藏）', '（源码差异默认隐藏）'):
            return 'Source hidden by default. Use --include-source only when appropriate.'
        return value

    def clues(values):
        return ''.join(f"<li><code>{esc(f['code'])}</code> | {esc(f['path'])}:{f['line'] or '-'}"
                       f"<pre>{esc(evidence(f['evidence']))}</pre></li>" for f in values) or '<li>No recorded clues. This is not a safety result.</li>'

    def metadata(entry):
        if entry is None:
            return 'Not read on this side.'
        return (f"<code>{esc(entry['path'])}</code><br><small>SHA-256: {esc(entry['sha256'])}<br>"
                f"Bytes read: {entry['bytes_read']} | Fully read: {entry['complete']}</small>")

    def preview_note(row):
        if row['status'] != 'changed':
            return 'No text preview for this file state.'
        notes = {
            'UTF-8 文本差异预览；不做语义判断。': 'UTF-8 line preview; not semantic analysis.',
            '差异预览已截断（150 行 / 16,000 字符），不是完整 diff。': 'TRUNCATED: 150 lines / 16,000 characters. Not a full diff.',
            '达到本次预览预算（100 文件 / 总输入 512 KiB）；请在编辑器中查看。': 'OMITTED: comparison preview budget reached (100 files / 512 KiB input).',
            '超过每侧 64 KiB 文本预览上限；文件仍已对比，预览未生成。': 'OMITTED: input exceeds 64 KiB per side. File byte comparison remains available.',
            '超过每侧 2,000 行预览上限；请在编辑器中查看。': 'OMITTED: input exceeds 2,000 lines per side.',
            '二进制或非 UTF-8 内容：只比较字节，不生成文本差异。': 'OMITTED: binary or non-UTF-8 content. Only bytes were compared.',
            '字节不同，但逐行文本相同（可能是换行符或 BOM）；仍需复核。': 'Bytes differ but decoded lines match (possibly line endings or BOM). Still review.',
        }
        return notes.get(row['diff_note'], 'No preview available; review the original files.')

    counts = Counter(item.status for item in result.files)
    totals = ' | '.join(f'{compare.EN_STATUS[k]}: {counts[k]}' for k in compare.EN_STATUS)
    sections = []
    for label, report, root in [('Old', result.old, result.old_root), ('New', result.new, result.new_root)]:
        redacted = scanner.report_to_dict(report, include_source)
        sections.append(f"<section><h2>{label}: {esc(report.target_name)}</h2>"
            f"<p>ZIP/input SHA-256: <code>{esc(report.input_sha256)}</code><br>"
            f"Files read: {report.files_scanned} | Scripts checked: {report.scripts_checked}<br>"
            f"Known uninspected scope: <strong>{report.incomplete}</strong> | Budget reached: {report.limited}<br>"
            f"Removed wrapper: <code>{esc(root or '(none)')}</code></p>"
            f"<details><summary>All finite scan clues, including unread or unsupported content</summary><ul>{clues(redacted['findings'])}</ul></details></section>")
    rows = []
    for row in sorted(data['files'], key=lambda r: (r['status'] == 'same', r['path'])):
        rows.append(f"<tr><td><strong>{esc(compare.EN_STATUS[row['status']])}</strong><br><code>{esc(row['path'])}</code>"
                    f"<p>{esc(preview_note(row))}</p><details><summary>Text preview</summary><pre>{esc(evidence(row['diff_preview']))}</pre></details></td>"
                    f"<td>{metadata(row['old_file'])}<ul>{clues(row['old_findings'])}</ul></td>"
                    f"<td>{metadata(row['new_file'])}<ul>{clues(row['new_findings'])}</ul></td></tr>")
    unknown = result.old.incomplete or result.new.incomplete
    return f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Godot Addon Check — upgrade comparison</title><style>
body{{font:15px/1.6 system-ui;max-width:1200px;margin:32px auto;padding:0 20px;color:#20372c}}
section,.notice{{padding:16px;border:1px solid #d5e0d8;border-radius:8px;margin:16px 0}}.notice{{background:#fff4dc}}
table{{border-collapse:collapse;min-width:760px;width:100%}}th,td{{border:1px solid #d5e0d8;padding:12px;vertical-align:top;text-align:left;width:33%}}
pre,code,small{{white-space:pre-wrap;overflow-wrap:anywhere}}.table{{overflow-x:auto}}
</style><h1>Godot add-on upgrade preflight</h1><p>Scanner {esc(result.old.scanner_version)} | Rules {esc(result.old.ruleset_version)} | Source included: {include_source}</p>
<div class="notice"><strong>Not a safety verdict.</strong> Verify that both inputs are the same add-on and that path mapping is appropriate.
<ul><li>Known uninspected scope on either side: <strong>{unknown}</strong>. Missing files on an incomplete side are unknown, never called deleted.</li>
<li>Only fully read bytes are compared. Same bytes do not establish trust; changed bytes do not establish changed behavior.</li>
<li>Finite lexical rules cover selected UTF-8 GDScript/C# APIs. Native code, dynamic behavior and unsupported syntax are not fully analyzed.</li>
<li>Source ZIPs may omit installed binaries/submodules. Directories are not consistent full snapshots. No publisher authentication.</li>
<li>No rename detection. Default exclusions and read budgets apply. Diff previews are bounded and may be omitted.</li>
<li>Exports retain filenames, paths and hashes; source is hidden by default, not anonymized.</li></ul></div>
<h2>{esc(totals)}</h2>{''.join(sections)}<div class="table"><table><thead><tr><th>File and state</th><th>Old</th><th>New</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div></html>'''
