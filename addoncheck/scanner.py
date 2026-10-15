#!/usr/bin/env python3
"""Read-only, local preflight report for a Godot add-on directory or ZIP.

The scanner deliberately does not extract archives, import a project, execute
scripts, activate editor plugins, make network requests, or claim that an add-on
is safe. Findings are review cues backed by file paths and source lines.
"""

from __future__ import annotations

import argparse
from bisect import bisect_right
import configparser
import datetime as dt
import html
import hashlib
import io
import json
import os
import posixpath
import re
import stat
import struct
import sys
import tempfile
import zipfile
import zlib
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Callable, Iterable


DEFAULT_MAX_FILES = 2_000
SCANNER_VERSION = "0.4.1a1"
RULESET_VERSION = "godot-text-r4"
DEFAULT_MAX_FILE_BYTES = 1_048_576
DEFAULT_MAX_TOTAL_BYTES = 33_554_432
MAX_ARCHIVE_BYTES = 67_108_864
MAX_ARCHIVE_ENTRIES = 20_000
MAX_FINDINGS = 500
SKIP_DIRS = {".git", ".godot", ".import", "node_modules", ".venv", "__pycache__"}
LICENSE_NAMES = {"license", "license.md", "license.txt", "copying", "copying.md", "notice"}
BINARY_SUFFIXES = {".dll", ".so", ".dylib", ".framework", ".exe", ".pck", ".wasm"}
ARCHIVE_SUFFIXES = {".zip", ".7z", ".rar", ".tar", ".gz", ".tgz"}


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    title: str
    path: str
    line: int | None
    evidence: str
    note: str


@dataclass(frozen=True)
class SourceFile:
    path: str
    data: bytes
    truncated: bool = False


@dataclass
class ScanReport:
    schema_version: str
    generated_at_utc: str
    target_name: str
    input_kind: str
    files_seen: int
    files_scanned: int
    bytes_read: int
    limited: bool
    license_files: list[str]
    findings: list[Finding]
    limitations: list[str]
    incomplete: bool = False
    scanner_version: str = SCANNER_VERSION
    ruleset_version: str = RULESET_VERSION
    input_sha256: str = ""
    fingerprint_scope: str = ""
    scripts_checked: int = 0
    # Additive schema field. Hashes cover exactly the bytes used by this scan.
    file_manifest: list[dict] = field(default_factory=list)


class ScanInputError(Exception):
    """An input could not be scanned without changing or executing it."""


class ScanCancelled(Exception):
    """A user requested cancellation between bounded scan steps."""


CancelCheck = Callable[[], bool]


def _check_cancelled(cancel_check: CancelCheck | None) -> None:
    if cancel_check is not None and cancel_check():
        raise ScanCancelled("扫描已由用户取消。")


RULES: tuple[tuple[str, str, str, re.Pattern[str]], ...] = (
    (
        "editor_tool_script", "info", "编辑器工具脚本（常见机制）",
        re.compile(r"(?:@tool\b|\[\s*Tool\s*\])", re.IGNORECASE),
    ),
    (
        "network_api", "review", "引用了可联网的 Godot API",
        re.compile(r"\b(?:HTTPRequest|HTTPClient|WebSocketPeer|TCPServer|UDPServer|PacketPeerUDP|StreamPeerTCP|ENetMultiplayerPeer)\b", re.IGNORECASE),
    ),
    (
        "process_api", "review", "引用了外部进程或 shell API",
        re.compile(r"\bOS\s*\.\s*(?:execute(?:_?with_?pipe)?|create_?process|create_?instance|open_?with_?program|shell_?open|kill)\s*\(|\b(?:System\s*\.\s*Diagnostics\s*\.\s*)?Process\s*\.\s*Start\s*\(", re.IGNORECASE),
    ),
    (
        "file_write_api", "review", "引用了文件写入或修改 API",
        re.compile(
            r"\bDirAccess\s*\.\s*(?:make_?dir(?:_?recursive)?(?:_?absolute)?|remove(?:_?absolute)?|rename(?:_?absolute)?|copy(?:_?absolute)?)\s*\(",
            re.IGNORECASE,
        ),
    ),
)
FILE_OPEN_PATTERN = re.compile(r"\bFileAccess\s*\.\s*open(?:_?encrypted(?:_?with_?pass)?|_?compressed)?\s*\(", re.IGNORECASE)
WRITE_MODE_PATTERN = re.compile(r"\b(?:WRITE|READ_?WRITE|WRITE_?READ)\b", re.IGNORECASE)

RULE_NOTES = {
    "editor_tool_script": "@tool 或 [Tool] 脚本可能在编辑器中运行，也可能改动场景；先在副本或版本控制下查看入口和副作用。",
    "network_api": "核对连接目标、发送的数据，以及联网是否属于插件的必要功能。",
    "process_api": "核对启动的程序、参数和输入来源；确认是否符合插件用途。",
    "file_write_api": "核对写入目标、覆盖行为和删除/移动路径。",
    "unresolved_file_mode": "模式参数使用变量、计算或超出解析范围；本工具无法判断此次打开是否可写。",
    "interpolated_string_uninspected": "未分析 C# 插值表达式内的代码；其中可能有真实调用，需要人工复核。",
}


def _finding(
    code: str,
    severity: str,
    title: str,
    path: str = "",
    line: int | None = None,
    evidence: str = "",
    note: str = "",
) -> Finding:
    return Finding(code, severity, title, path, line, evidence[:300], note)


def _normal_archive_path(name: str) -> tuple[str, bool]:
    """Return a display path and whether the archive path is suspicious."""
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    suspicious = (
        path.is_absolute()
        or ".." in path.parts
        or bool(re.match(r"^[A-Za-z]:", normalized))
        or normalized.startswith("//")
    )
    return normalized.lstrip("/"), suspicious


def _read_bounded(stream: BinaryIO, budget: int, cancel_check: CancelCheck | None = None) -> tuple[bytes, int]:
    """Read no more than the caller's byte budget."""
    budget = max(0, budget)
    chunks: list[bytes] = []
    consumed = 0
    while consumed < budget:
        _check_cancelled(cancel_check)
        request = min(65_536, budget - consumed)
        chunk = stream.read(request)
        if not chunk:
            break
        consumed += len(chunk)
        chunks.append(chunk)
    return b"".join(chunks), consumed


def _skip_name(path: str) -> bool:
    parts = PurePosixPath(path).parts
    return any(part in SKIP_DIRS or part == "__MACOSX" for part in parts)


def _is_link_like(path: Path) -> bool:
    metadata = path.lstat()
    # Path.is_junction() is unavailable on Python 3.10/3.11. Windows exposes
    # junctions and other redirected paths through the reparse-point attribute.
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _collect_zip(
    target: Path, max_files: int, max_file_bytes: int, max_total_bytes: int,
    cancel_check: CancelCheck | None = None,
    snapshot: bytes | None = None,
) -> tuple[list[SourceFile], list[Finding], int, int, bool]:
    files: list[SourceFile] = []
    findings: list[Finding] = []
    bytes_read = 0
    read_budget_spent = 0
    files_seen = 0
    limited = False

    try:
        archive_size = target.stat().st_size
    except OSError as exc:
        raise ScanInputError(f"无法读取 ZIP 文件信息：{exc}") from exc
    if archive_size > MAX_ARCHIVE_BYTES:
        raise ScanInputError(
            f"ZIP 压缩包超过 {MAX_ARCHIVE_BYTES} bytes 的输入上限。"
        )

    try:
        archive = zipfile.ZipFile(io.BytesIO(snapshot) if snapshot is not None else target, "r")
    except (OSError, ValueError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise ScanInputError(f"无法读取 ZIP：{exc}") from exc

    with archive:
        for info in archive.infolist():
            _check_cancelled(cancel_check)
            if info.is_dir():
                continue
            files_seen += 1
            path, suspicious = _normal_archive_path(info.filename)
            if files_seen > max_files:
                limited = True
                findings.append(_finding(
                    "file_count_limit", "info", "达到文件数量上限",
                    path, evidence=f"上限 {max_files} 个文件",
                    note="后续文件未检查。",
                ))
                break
            if suspicious:
                findings.append(_finding(
                    "unsafe_archive_path", "review", "ZIP 包含异常路径",
                    path, evidence=info.filename,
                    note="扫描器不会解压；该路径仍需人工确认。",
                ))
                continue
            if _skip_name(path):
                continue

            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                findings.append(_finding(
                    "archive_symlink", "review", "压缩包包含符号链接",
                    path, evidence="ZIP 条目标记为符号链接",
                    note="扫描器不会跟随符号链接。",
                ))
                continue
            if info.flag_bits & 0x1:
                findings.append(_finding(
                    "encrypted_entry", "review", "压缩包包含加密文件",
                    path, evidence="ZIP 条目标记为加密内容",
                    note="加密内容无法检查。",
                ))
                continue
            if info.file_size > max_file_bytes:
                limited = True
                findings.append(_finding(
                    "file_size_limit", "info", "文件超过单文件扫描上限",
                    path, evidence=f"声明大小 {info.file_size} bytes",
                    note=f"本次最多读取 {max_file_bytes} bytes；文件未完整检查。",
                ))
                continue
            if read_budget_spent >= max_total_bytes:
                limited = True
                findings.append(_finding(
                    "total_size_limit", "info", "达到总读取量上限",
                    path, evidence=f"读取预算已使用 {read_budget_spent} 字节",
                    note="读取失败也会占用预算，后续文件未检查。",
                ))
                break
            remaining = max_total_bytes - read_budget_spent
            budget = min(info.file_size, max_file_bytes, remaining)
            try:
                with archive.open(info, "r") as member:
                    data, consumed = _read_bounded(member, budget, cancel_check)
            except (OSError, RuntimeError, ValueError, EOFError, NotImplementedError, zipfile.BadZipFile, zlib.error) as exc:
                read_budget_spent += budget
                findings.append(_finding(
                    "entry_read_error", "review", "无法读取压缩包内文件",
                    path, evidence=type(exc).__name__,
                    note="该文件未被完整检查。",
                ))
                continue
            bytes_read += min(consumed, remaining)
            read_budget_spent += consumed
            truncated = info.file_size > len(data)
            files.append(SourceFile(path, data, truncated))
            if truncated:
                limited = True
                findings.append(_finding(
                    "entry_truncated", "info", "文件读取被限制截断",
                    path, evidence=f"扫描到前 {len(data)} bytes",
                    note="该文件只有前缀参与静态规则扫描。",
                ))

    return files, findings, files_seen, bytes_read, limited


def _validate_zip_directory(data: bytes) -> None:
    """Bound metadata entry count before ZipFile allocates ZipInfo objects."""
    floor = max(0, len(data) - 65_557)
    end = data.rfind(b"PK\x05\x06", floor)
    while end >= floor:
        if end + 22 <= len(data):
            comment_length = struct.unpack_from("<H", data, end + 20)[0]
            if end + 22 + comment_length == len(data):
                break
        end = data.rfind(b"PK\x05\x06", floor, end)
    if end < floor:
        raise ScanInputError("ZIP 目录记录无效或格式不支持。")
    disk, start_disk, disk_entries, entries, size, offset = struct.unpack_from("<4H2L", data, end + 4)
    if disk or start_disk or disk_entries != entries or entries == 0xffff or size == 0xffffffff or offset == 0xffffffff:
        raise ScanInputError("当前预检不支持分卷或 ZIP64 压缩包。")
    if entries > MAX_ARCHIVE_ENTRIES or size > end:
        raise ScanInputError("ZIP 目录过大或超过 20,000 条元数据记录上限。")
    cursor, actual = end - size, 0
    while cursor < end:
        if cursor + 46 > end or data[cursor:cursor + 4] != b"PK\x01\x02":
            raise ScanInputError("ZIP 中央目录不完整或格式不支持。")
        name_size, extra_size, comment_size = struct.unpack_from("<3H", data, cursor + 28)
        cursor += 46 + name_size + extra_size + comment_size
        actual += 1
        if actual > MAX_ARCHIVE_ENTRIES:
            raise ScanInputError("ZIP 元数据超过 20,000 条记录上限。")
    if cursor != end or actual != entries:
        raise ScanInputError("ZIP 目录条目数量或长度不一致。")


def _collect_directory(
    target: Path, max_files: int, max_file_bytes: int, max_total_bytes: int,
    cancel_check: CancelCheck | None = None,
) -> tuple[list[SourceFile], list[Finding], int, int, bool]:
    files: list[SourceFile] = []
    findings: list[Finding] = []
    bytes_read = 0
    read_budget_spent = 0
    files_seen = 0
    limited = False
    root = target.resolve()

    def on_walk_error(exc: OSError) -> None:
        error_path = ""
        if exc.filename:
            try:
                error_path = Path(exc.filename).relative_to(root).as_posix()
            except ValueError:
                error_path = Path(exc.filename).name
        findings.append(_finding(
            "directory_read_error", "review", "无法遍历部分文件夹",
            error_path, evidence=type(exc).__name__,
            note="结果可能不完整；请确认文件夹权限后重扫。",
        ))

    for current, dirs, names in os.walk(root, topdown=True, onerror=on_walk_error, followlinks=False):
        _check_cancelled(cancel_check)
        current_path = Path(current)
        kept_dirs: list[str] = []
        for dirname in dirs:
            _check_cancelled(cancel_check)
            dir_path = current_path / dirname
            if dirname in SKIP_DIRS or dirname == "__MACOSX":
                continue
            try:
                link_like = _is_link_like(dir_path)
            except OSError as exc:
                findings.append(_finding(
                    "directory_read_error", "review", "无法确认文件夹信息",
                    dir_path.relative_to(root).as_posix(), evidence=type(exc).__name__,
                    note="该文件夹未检查，请确认路径和读取权限。",
                ))
                continue
            if link_like:
                findings.append(_finding(
                    "directory_symlink", "review", "目录包含链接或重解析点",
                    dir_path.relative_to(root).as_posix(),
                    evidence="扫描器不会跟随符号链接",
                    note="链接目标未被扫描。",
                ))
                continue
            kept_dirs.append(dirname)
        dirs[:] = kept_dirs

        for name in names:
            _check_cancelled(cancel_check)
            path_obj = current_path / name
            relative = path_obj.relative_to(root).as_posix()
            files_seen += 1
            if files_seen > max_files:
                limited = True
                findings.append(_finding(
                    "file_count_limit", "info", "达到文件数量上限",
                    relative, evidence=f"上限 {max_files} 个文件",
                    note="后续文件未检查。",
                ))
                break
            try:
                if _is_link_like(path_obj):
                    findings.append(_finding(
                        "file_symlink", "review", "文件是链接或重解析点",
                        relative, evidence="扫描器不会跟随链接或重解析点",
                        note="目标内容未被扫描；云端占位文件可先复制到普通本地目录。",
                    ))
                    continue
                metadata = path_obj.stat(follow_symlinks=False)
                if not stat.S_ISREG(metadata.st_mode):
                    findings.append(_finding(
                        "non_regular_file", "review", "跳过非普通文件",
                        relative, evidence="文件系统项目不是普通文件",
                        note="扫描器只读普通文件，不读设备或管道。",
                    ))
                    continue
                size = metadata.st_size
            except OSError as exc:
                findings.append(_finding(
                    "stat_error", "review", "无法读取文件信息",
                    relative, evidence=type(exc).__name__, note="文件未被检查。",
                ))
                continue
            if size > max_file_bytes:
                limited = True
                findings.append(_finding(
                    "file_size_limit", "info", "文件超过单文件扫描上限",
                    relative, evidence=f"大小 {size} bytes",
                    note=f"本次最多读取 {max_file_bytes} bytes；文件未检查。",
                ))
                continue
            if read_budget_spent >= max_total_bytes:
                limited = True
                findings.append(_finding(
                    "total_size_limit", "info", "达到总读取量上限",
                    relative, evidence=f"读取预算已使用 {read_budget_spent} 字节",
                    note="读取失败也会占用预算，后续文件未检查。",
                ))
                break
            try:
                remaining = max_total_bytes - read_budget_spent
                budget = min(max_file_bytes, remaining)
                with path_obj.open("rb") as source:
                    data, consumed = _read_bounded(
                        source, budget, cancel_check
                    )
            except OSError as exc:
                read_budget_spent += budget
                findings.append(_finding(
                    "file_read_error", "review", "无法读取文件",
                    relative, evidence=type(exc).__name__, note="文件未被检查。",
                ))
                continue
            bytes_read += min(consumed, remaining)
            read_budget_spent += consumed
            truncated = size > len(data)
            files.append(SourceFile(relative, data, truncated))
            if truncated:
                limited = True
                findings.append(_finding(
                    "entry_truncated", "info", "文件读取被限制截断",
                    relative, evidence=f"扫描到前 {len(data)} bytes",
                    note="该文件只有前缀参与静态规则扫描。",
                ))

        if files_seen > max_files or (limited and read_budget_spent >= max_total_bytes):
            break

    return files, findings, files_seen, bytes_read, limited


def _looks_text(data: bytes) -> bool:
    return b"\x00" not in data[:8192]


def _mask_non_code(text: str, suffix: str, cancel_check: CancelCheck | None) -> tuple[str, list[int]]:
    """Mask common comments/strings while retaining offsets; not a full parser."""
    output = list(text)
    interpolations: list[int] = []
    i, size = 0, len(text)
    while i < size:
        if i % 4096 == 0:
            _check_cancelled(cancel_check)
        start = i
        if (suffix == ".gd" and text[i] == "#") or (suffix == ".cs" and text.startswith("//", i)):
            end = text.find("\n", i)
            i = size if end < 0 else end
        elif suffix == ".cs" and text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = size if end < 0 else end + 2
        elif text[i] in "\"'":
            quote = text[i]
            if suffix == ".cs" and quote == '"' and (text[max(0, i - 1):i] == "$" or text[max(0, i - 2):i] == "$@"):
                interpolations.append(i)
            delimiter = quote * 3 if text.startswith(quote * 3, i) else quote
            verbatim = suffix == ".cs" and i > 0 and text[i - 1] == "@" and delimiter == '"'
            i += len(delimiter)
            while i < size:
                if i % 4096 == 0:
                    _check_cancelled(cancel_check)
                if verbatim and text.startswith('""', i):
                    i += 2
                elif text.startswith(delimiter, i):
                    i += len(delimiter)
                    break
                elif text[i] == "\\" and not verbatim:
                    i += 2
                else:
                    i += 1
            i = min(i, size)
        else:
            i += 1
            continue
        for index in range(start, i):
            if text[index] not in "\r\n":
                output[index] = " "
    return "".join(output), interpolations


def _file_mode_argument(code: str, opening: int) -> tuple[str, int]:
    depth, start = 0, opening + 1
    arguments = []
    for index in range(opening, min(len(code), opening + 4096)):
        char = code[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
            if depth == 0:
                arguments.append(code[start:index])
                return (arguments[1] if len(arguments) > 1 else ""), index + 1
        elif char == "," and depth == 1:
            arguments.append(code[start:index])
            start = index + 1
    return "", opening + 1


def _code_hits(text: str, suffix: str, cancel_check: CancelCheck | None):
    masked, interpolations = _mask_non_code(text, suffix, cancel_check)
    starts = [i for i, char in enumerate(text) if char == "\n"]
    lines = text.splitlines()
    hits = []
    if interpolations:
        hits.append((interpolations[0], interpolations[0] + 1, "interpolated_string_uninspected", "info", "C# 插值表达式未分析"))
    for code, severity, title, pattern in RULES:
        for match in pattern.finditer(masked):
            if code == "network_api" and match.start() and masked[match.start() - 1] in "$%/":
                continue  # A shorthand node path is not proof of its runtime type.
            hits.append((match.start(), match.end(), code, severity, title))
    for match in FILE_OPEN_PATTERN.finditer(masked):
        mode, end = _file_mode_argument(masked, match.end() - 1)
        if WRITE_MODE_PATTERN.search(mode):
            hits.append((match.start(), end, "file_write_api", "review", "引用了文件写入或修改 API"))
        elif not re.fullmatch(r"(?:FileAccess\s*\.\s*)?(?:ModeFlags\s*\.\s*)?Read", mode.strip(), re.IGNORECASE):
            hits.append((match.start(), end, "unresolved_file_mode", "info", "文件打开模式未能确认"))
    for start, end, code, severity, title in sorted(hits):
        _check_cancelled(cancel_check)
        number = bisect_right(starts, start) + 1
        evidence = " ".join(text[start:end].split()) if "\n" in text[start:end] else lines[number - 1].strip()
        yield code, severity, title, number, evidence


def _scan_source_files(
    files: list[SourceFile], cancel_check: CancelCheck | None = None
) -> tuple[list[Finding], list[str], bool, int]:
    findings: list[Finding] = []
    licenses: list[str] = []
    finding_limit_reached = False
    scripts_checked = 0
    known_paths = {item.path.replace("\\", "/") for item in files}

    def record(finding: Finding) -> None:
        nonlocal finding_limit_reached
        if len(findings) < MAX_FINDINGS:
            findings.append(finding)
        else:
            finding_limit_reached = True

    for source in files:
        _check_cancelled(cancel_check)
        path = source.path.replace("\\", "/")
        basename = PurePosixPath(path).name.casefold()
        suffix = PurePosixPath(path).suffix.casefold()
        if basename in LICENSE_NAMES or basename.startswith(("license.", "license-", "license_")):
            licenses.append(path)
        if suffix in ARCHIVE_SUFFIXES:
            record(_finding(
                "nested_archive_not_inspected", "review", "包内还有未检查的压缩文件",
                path, evidence=f"文件后缀为 {suffix}",
                note="此原型只检查用户直接选择的 ZIP；不会展开或递归检查嵌套压缩包。",
            ))
            continue
        if suffix in BINARY_SUFFIXES:
            record(_finding(
                "native_or_binary_file", "review", "包含原生或可执行二进制文件",
                path, evidence=f"文件后缀为 {suffix or '未知'}",
                note="二进制内容不会被此原型反编译；请确认来源、用途和发布方式。",
            ))
        if suffix == ".gdextension":
            record(_finding(
                "native_extension_manifest", "review", "存在原生扩展声明，库行为未检查",
                path, note="此工具不解析 C/C++ 或反编译动态库；需要额外审查原生扩展。",
            ))
        if suffix not in {".gd", ".cs"}:
            continue
        if not _looks_text(source.data):
            record(_finding(
                "source_encoding_unreadable", "review", "脚本编码无法可靠识别",
                path, note="脚本含二进制或非 UTF-8 文本；本次未检查其中的代码规则。",
            ))
            continue
        if finding_limit_reached:
            continue
        try:
            text = source.data.decode("utf-8-sig")
        except UnicodeError:
            record(_finding(
                "source_encoding_unreadable", "review", "脚本不是有效的 UTF-8 文本",
                path, note="无法可靠解码；请确认文件编码后重扫。",
            ))
            continue
        scripts_checked += 1
        for code, severity, title, number, evidence in _code_hits(text, suffix, cancel_check):
            record(_finding(code, severity, title, path, number, evidence, RULE_NOTES[code]))
            if finding_limit_reached:
                break

    plugin_configs = [f for f in files if PurePosixPath(f.path).name.casefold() == "plugin.cfg"]
    for source in plugin_configs:
        _check_cancelled(cancel_check)
        try:
            parser = configparser.ConfigParser(interpolation=None, strict=False)
            parser.read_string(source.data.decode("utf-8-sig"))
            section = parser["plugin"] if parser.has_section("plugin") else None
        except (configparser.Error, UnicodeError):
            section = None
        if section is None:
            record(_finding(
                "plugin_config_unreadable", "review", "无法确认 plugin.cfg 的 [plugin] 设置",
                source.path, evidence="找不到可解析的 [plugin] 配置段",
                note="插件包可能使用不同结构；请人工查看入口文件。",
            ))
            continue
        script = section.get("script", "").strip().strip('"\'')
        if not script:
            record(_finding(
                "plugin_entry_missing", "review", "plugin.cfg 未声明 script 入口",
                source.path, evidence="[plugin] script = ... 缺失",
                note="请确认这是否为完整的 Godot 插件包。",
            ))
            continue
        normalized = script.replace("\\", "/")
        if normalized.startswith("res://"):
            normalized = posixpath.normpath(normalized[6:])
            matches = [p for p in known_paths if p == normalized or p.endswith("/" + normalized)]
        else:
            normalized = posixpath.normpath(posixpath.join(str(PurePosixPath(source.path).parent), normalized))
            matches = [p for p in known_paths if p == normalized]
        if not matches:
            case_matches = [p for p in known_paths if p.casefold() == normalized.casefold() or (
                script.startswith("res://") and p.casefold().endswith("/" + normalized.casefold())
            )]
            record(_finding(
                "plugin_entry_case_mismatch" if case_matches else "plugin_entry_not_found", "review",
                "入口脚本的路径大小写不一致" if case_matches else "找不到 plugin.cfg 声明的入口脚本",
                source.path, evidence=f"script = {script}",
                note="大小写不一致可能导致跨平台加载失败。" if case_matches else "相对路径按 plugin.cfg 所在文件夹查找；请确认插件是否完整。",
            ))

    if not plugin_configs:
        record(_finding(
            "plugin_config_missing", "info", "未找到 plugin.cfg",
            evidence="扫描文件清单中没有 plugin.cfg",
            note="输入可能是资源包、模板或插件子文件夹，不一定是完整 Godot 插件。",
        ))
    if not licenses:
        record(_finding(
            "license_file_missing", "review", "未找到常见名称的 LICENSE/COPYING 文件",
            evidence="在已读取文件的名称中没有匹配项",
            note="这不能单独证明没有授权；可能由商店页或其他位置提供。",
        ))
    if scripts_checked == 0:
        record(_finding("no_supported_scripts", "info", "没有可进行代码规则检查的脚本",
                        note="本次没有分析到 UTF-8 的 .gd/.cs；不能据此判断插件行为。"))
    return findings, sorted(set(licenses)), finding_limit_reached, scripts_checked


def scan_target(
    target: Path,
    max_files: int = DEFAULT_MAX_FILES,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    cancel_check: CancelCheck | None = None,
    file_observer: Callable[[list[SourceFile]], None] | None = None,
) -> ScanReport:
    _check_cancelled(cancel_check)
    if not target.exists():
        raise ScanInputError("输入路径不存在。")
    if _is_link_like(target):
        raise ScanInputError("输入路径本身是链接或重解析点；请选择普通本地目录或 ZIP。")
    if target.is_dir():
        files, initial, seen, read, limited = _collect_directory(
            target, max_files, max_file_bytes, max_total_bytes, cancel_check
        )
        kind = "directory"
    elif target.is_file() and target.suffix.casefold() == ".zip":
        with target.open("rb") as stream:
            snapshot, _ = _read_bounded(stream, MAX_ARCHIVE_BYTES + 1, cancel_check)
        if len(snapshot) > MAX_ARCHIVE_BYTES:
            raise ScanInputError("ZIP 超过 64 MiB 输入上限。")
        _validate_zip_directory(snapshot)
        input_sha256 = hashlib.sha256(snapshot).hexdigest()
        files, initial, seen, read, limited = _collect_zip(
            target, max_files, max_file_bytes, max_total_bytes, cancel_check, snapshot
        )
        kind = "zip"
    else:
        raise ScanInputError("输入必须是目录或 .zip 文件。")

    findings, licenses, source_findings_limited, scripts_checked = _scan_source_files(files, cancel_check)
    if kind == "directory":
        digest = hashlib.sha256()
        for item in sorted(files, key=lambda file: file.path):
            digest.update(json.dumps([item.path, len(item.data)], ensure_ascii=False).encode("utf-8"))
            digest.update(item.data)
        input_sha256 = digest.hexdigest()
    findings = initial + findings
    incomplete_codes = {
        "unsafe_archive_path", "archive_symlink", "encrypted_entry", "entry_read_error",
        "directory_read_error", "directory_symlink", "file_symlink", "non_regular_file",
        "stat_error", "file_read_error", "source_encoding_unreadable",
        "native_or_binary_file", "nested_archive_not_inspected", "plugin_config_unreadable",
        "no_supported_scripts", "native_extension_manifest",
        "unresolved_file_mode", "interpolated_string_uninspected",
    }
    incomplete = limited or any(f.code in incomplete_codes for f in findings)
    if source_findings_limited or len(findings) > MAX_FINDINGS:
        limited = True
        incomplete = True
        findings = findings[:MAX_FINDINGS - 1]
        findings.append(_finding(
            "finding_limit", "info", "达到报告条目上限",
            evidence=f"最多输出 {MAX_FINDINGS} 条",
            note="更多匹配可能存在，请缩小输入包后重扫。",
        ))

    limitations = [
        "本工具只提供静态线索，不是安全审计、恶意软件检测或许可证法律意见。",
        "不执行、不导入、不启用插件；不访问网络，也不把项目内容上传。",
        "使用简化词法过滤；不解析类型、数据流或跨文件封装，动态调用及特殊字符串语法仍可能漏报或误报。",
        "FileAccess 的模式参数最多检查 4,096 个字符；变量模式、C# 插值表达式等不在完整支持范围。",
        "API 线索仅检查 UTF-8 的 .gd/.cs 文件；默认跳过 .git、.godot、.import、node_modules、.venv 和 __pycache__。",
        "商店 AI 披露字段、远端仓库、发布者身份及 Godot 版本兼容性未经联网核实。",
    ]
    if incomplete:
        limitations.append("部分内容受扫描上限、读取失败或不支持的格式影响，未被检查；请查看对应线索。")

    _check_cancelled(cancel_check)
    if file_observer is not None:
        file_observer(files)
    return ScanReport(
        schema_version="0.3",
        generated_at_utc=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        target_name=target.name,
        input_kind=kind,
        files_seen=seen,
        files_scanned=len(files),
        bytes_read=read,
        limited=limited,
        license_files=licenses,
        findings=findings,
        limitations=limitations,
        incomplete=incomplete,
        input_sha256=input_sha256,
        fingerprint_scope="完整 ZIP 字节快照" if kind == "zip" else "仅已读取文件的路径与内容；非完整目录快照",
        scripts_checked=scripts_checked,
        file_manifest=[{"path": item.path, "sha256": hashlib.sha256(item.data).hexdigest(),
                        "bytes_read": len(item.data), "complete": not item.truncated}
                       for item in files],
    )


def report_to_dict(report: ScanReport, include_evidence: bool = False) -> dict:
    data = asdict(report)
    data["source_evidence_included"] = include_evidence
    if not include_evidence:
        for finding in data["findings"]:
            if finding["line"] is not None or finding["code"].startswith("plugin_entry"):
                finding["evidence"] = "（源码证据默认隐藏）"
    return data


def write_report(output: Path, content: str, source: Path) -> None:
    """Validate the destination and replace reports only after a full write."""
    destination = output.resolve()
    source_path = source.resolve()
    if destination == source_path or (source.is_dir() and source_path in destination.parents):
        raise ScanInputError("报告不能覆盖输入文件或写入被扫描目录。")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         prefix=".addoncheck-", suffix=".tmp",
                                         dir=destination.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def render_text(report: ScanReport, include_evidence: bool = False) -> str:
    kind_label = {"directory": "文件夹", "zip": "ZIP 压缩包"}.get(report.input_kind, report.input_kind)
    severity_label = {"review": "需查看", "info": "提示"}
    lines = [
        "Godot Addon Check — 静态检查报告",
        f"扫描器：{report.scanner_version}；规则：{report.ruleset_version}；代码规则检查 {report.scripts_checked} 份脚本",
        f"SHA-256：{report.input_sha256}（{report.fingerprint_scope}）",
        f"检查对象：{report.target_name}（{kind_label}）",
        f"文件：已读取 {report.files_scanned}/{report.files_seen} 个；读取 {report.bytes_read} 字节；存在未检查内容：{'是' if report.incomplete else '否'}",
        f"授权文件名线索：{', '.join(report.license_files) if report.license_files else '未发现常见名称'}",
        "",
        f"发现线索：{len(report.findings)} 条",
    ]
    for item in report.findings:
        location = item.path or "整个插件包"
        if item.line is not None:
            location += f":{item.line}"
        lines.append(f"[{severity_label.get(item.severity, item.severity)}] {item.title}（{item.code}）— {location}")
        if item.evidence:
            evidence = item.evidence if include_evidence or (item.line is None and not item.code.startswith("plugin_entry")) else "（源码证据默认隐藏）"
            lines.append(f"  证据：{evidence}")
        if item.note:
            lines.append(f"  建议：{item.note}")
    if not report.findings:
        lines.append("本次规则没有命中线索；这不代表插件安全。")
    if report.incomplete:
        lines.append("本次存在未检查的内容，请查看读取失败、文件格式或扫描上限提示。")
    lines.append("")
    lines.append("使用边界：")
    lines.extend(f"- {note}" for note in report.limitations)
    lines.append("报告包含源码线索和本地路径；分享前请检查是否含密钥、个人信息或私有代码。")
    return "\n".join(lines)


def render_html(report: ScanReport, include_evidence: bool = False) -> str:
    esc = html.escape
    kind_label = {"directory": "文件夹", "zip": "ZIP 压缩包"}.get(report.input_kind, report.input_kind)
    severity_label = {"review": "需查看", "info": "提示"}
    rows = []
    for finding in report.findings:
        evidence = finding.evidence if include_evidence or (finding.line is None and not finding.code.startswith("plugin_entry")) else "（源码证据默认隐藏）"
        location = finding.path or "整个插件包"
        if finding.line is not None:
            location += f":{finding.line}"
        rows.append(
            "<tr>"
            f"<td>{esc(severity_label.get(finding.severity, finding.severity))}</td>"
            f"<td><code>{esc(finding.code)}</code><br>{esc(finding.title)}</td>"
            f"<td><code>{esc(location)}</code></td>"
            f"<td><pre>{esc(evidence)}</pre><small>{esc(finding.note)}</small></td>"
            "</tr>"
        )
    if not rows:
        rows.append('<tr><td colspan="4">本次规则没有命中线索。这不是安全结论。</td></tr>')
    limitations = "".join(f"<li>{esc(note)}</li>" for note in report.limitations)
    license_text = "、".join(report.license_files) if report.license_files else "未发现常见名称（不代表没有授权）"
    return f"""<!doctype html>
<html lang="zh-Hans">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Godot Addon Check — {esc(report.target_name)}</title>
<style>
body{{font:16px/1.55 system-ui,sans-serif;max-width:1100px;margin:40px auto;padding:0 20px;color:#18212b;background:#f5f7fa}}
h1{{font-size:1.7rem}} .card{{background:#fff;border:1px solid #dce3eb;border-radius:12px;padding:18px;margin:16px 0}}
.table-wrap{{overflow-x:auto;background:#fff}} table{{width:100%;min-width:760px;border-collapse:collapse}} th,td{{text-align:left;padding:12px;border-bottom:1px solid #e5eaf0;vertical-align:top}}
th{{background:#eef3f8}} pre{{white-space:pre-wrap;overflow-wrap:anywhere;margin:0}} code{{font-family:ui-monospace,monospace}}
.notice{{border-left:5px solid #bd7320}} .muted{{color:#566575}}
</style>
</head>
<body>
<h1>Godot Addon Check</h1>
<p class="muted">本地静态检查报告 · {esc(report.generated_at_utc)} · 未执行插件</p>
<p class="muted">扫描器 {esc(report.scanner_version)} · 规则 {esc(report.ruleset_version)} · 代码规则检查 {report.scripts_checked} 份脚本 · 源码证据：{'已包含，请检查敏感信息' if include_evidence else '默认隐藏'}</p>
<section class="card"><strong>SHA-256：</strong><code>{esc(report.input_sha256)}</code><br><small>{esc(report.fingerprint_scope)}</small></section>
<section class="card"><strong>检查对象：</strong>{esc(report.target_name)}（{esc(kind_label)}）<br>
<strong>文件：</strong>已读取 {report.files_scanned}/{report.files_seen} 个 · 读取 {report.bytes_read} 字节 · 存在未检查内容：{'是' if report.incomplete else '否'}<br>
<strong>授权文件名线索：</strong>{esc(license_text)}</section>
<section class="card notice"><strong>注意：</strong>线索需要人工复核，不代表插件有问题；没有命中也不代表插件安全。报告含源码行和本地路径，分享前请检查是否有密钥、个人信息或私有代码。</section>
<h2>发现项</h2>
<div class="table-wrap"><table><thead><tr><th>级别</th><th>规则</th><th>位置</th><th>证据与说明</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>
<section class="card"><h2>限制</h2><ul>{limitations}</ul></section>
</body></html>"""


def _bounded_arg(parser: argparse.ArgumentParser, value: str, maximum: int, name: str) -> int:
    try:
        parsed = int(value)
    except ValueError:
        parser.error(f"{name}必须是整数。")
    if parsed < 1 or parsed > maximum:
        parser.error(f"{name}必须在 1 到 {maximum} 之间。")
    return parsed


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="只读扫描 Godot 插件目录或 ZIP；不解压、不执行、不联网。"
    )
    parser.add_argument("target", type=Path, help="本地插件目录或 .zip 文件")
    parser.add_argument("--json", dest="json_path", type=Path, help="可选 JSON 报告输出路径")
    parser.add_argument("--html", dest="html_path", type=Path, help="可选 HTML 报告输出路径")
    parser.add_argument("--include-source", action="store_true", help="主动在输出报告中包含源码证据；可能含敏感信息")
    parser.add_argument("--max-files", default=DEFAULT_MAX_FILES, help="扫描文件上限，默认 2000")
    parser.add_argument("--max-file-bytes", default=DEFAULT_MAX_FILE_BYTES, help="单文件字节上限，默认 1048576")
    parser.add_argument("--max-total-bytes", default=DEFAULT_MAX_TOTAL_BYTES, help="总读取字节上限，默认 33554432")
    args = parser.parse_args(argv)
    args.max_files = _bounded_arg(parser, str(args.max_files), 10_000, "--max-files")
    args.max_file_bytes = _bounded_arg(parser, str(args.max_file_bytes), 16_777_216, "--max-file-bytes")
    args.max_total_bytes = _bounded_arg(parser, str(args.max_total_bytes), 268_435_456, "--max-total-bytes")

    report_paths = [path for path in (args.json_path, args.html_path) if path is not None]
    try:
        resolved_outputs = [path.resolve() for path in report_paths]
        source_path = args.target.resolve()
    except (OSError, RuntimeError) as exc:
        print(f"无法确认文件路径：{exc}", file=sys.stderr)
        return 2
    if len(set(resolved_outputs)) != len(resolved_outputs):
        print("扫描失败：JSON 和 HTML 报告不能写入同一路径。", file=sys.stderr)
        return 2
    for output_path in resolved_outputs:
        if output_path == source_path or (
            args.target.is_dir() and source_path in output_path.parents
        ):
            print("扫描失败：报告不能覆盖输入文件或写入被扫描目录。", file=sys.stderr)
            return 2

    try:
        report = scan_target(args.target, args.max_files, args.max_file_bytes, args.max_total_bytes)
    except (ScanInputError, OSError) as exc:
        print(f"扫描失败：{exc}", file=sys.stderr)
        return 2

    try:
        if args.json_path:
            write_report(args.json_path, json.dumps(report_to_dict(report, args.include_source), ensure_ascii=False, indent=2) + "\n", args.target)
        if args.html_path:
            write_report(args.html_path, render_html(report, args.include_source), args.target)
    except (ScanInputError, OSError, RuntimeError) as exc:
        print(f"报告保存失败：{exc}", file=sys.stderr)
        return 2
    print(render_text(report, args.include_source))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
