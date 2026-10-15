"""Build a CLI bundle from the official, checksum-pinned Python embeddable release."""
import hashlib
from pathlib import Path
import shutil
import urllib.request
import urllib.error
import zipfile

ROOT = Path(__file__).resolve().parents[1]
URL = 'https://www.python.org/ftp/python/3.13.16/python-3.13.16-embed-amd64.zip'
SHA256 = '97dae5274cc54867065e8d5a3226e48c35017ed332a0fdb0e27d5b5821961297'


def build():
    download = ROOT / 'build/python-3.13.16-embed-amd64.zip'
    download.parent.mkdir(exist_ok=True)
    if not download.exists():
        with urllib.request.urlopen(URL, timeout=60) as response:
            data = response.read(33_554_433)
        if len(data) > 33_554_432 or hashlib.sha256(data).hexdigest() != SHA256:
            raise ValueError('Official runtime download fingerprint/size mismatch; do not execute')
        download.write_bytes(data)
    if hashlib.sha256(download.read_bytes()).hexdigest() != SHA256:
        raise ValueError('Cached runtime fingerprint mismatch')
    output = ROOT / 'dist/addoncheck'
    runtime = output / 'runtime'
    runtime.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(download) as archive:
        for entry in archive.infolist():
            path = (runtime / entry.filename).resolve()
            if runtime.resolve() not in path.parents:
                raise ValueError('Unexpected runtime archive path')
        archive.extractall(runtime)
    # Controlled local application path; do not enable site or user package discovery.
    (runtime / 'python313._pth').write_text('python313.zip\n.\n..\n', encoding='utf-8')
    package = output / 'addoncheck'
    package.mkdir(exist_ok=True)
    for name in ('__init__.py', '__main__.py', 'scanner.py', 'compare.py', 'report.py'):
        shutil.copy2(ROOT / 'addoncheck' / name, package / name)
    (output / 'addoncheck.cmd').write_text('@echo off\r\n"%~dp0runtime\\python.exe" -I -m addoncheck %*\r\nexit /b %errorlevel%\r\n', encoding='ascii', newline='')
    for name in ('LICENSE', 'README.md'):
        shutil.copy2(ROOT / name, output / name)
    (output / 'RUNTIME.txt').write_text(
        f'Official Python 3.13.16 Windows x64 embeddable runtime.\n{URL}\nSHA-256 {SHA256}\n'
        'Python/runtime notices are in runtime/LICENSE.txt; OpenSSL terms are in third-party/.\n'
        'Only python313._pth was changed to add the sibling application directory.\n'
        'This bundle is CLI-only; Tk is not included. No plugin ZIP is extracted or executed.\n', encoding='utf-8')
    notices = output / 'third-party'
    notices.mkdir(exist_ok=True)
    for name in ('LICENSE.txt', 'NOTICE'):
        url = f'https://raw.githubusercontent.com/openssl/openssl/openssl-3.5.9/{name}'
        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                content = response.read(1_048_577)
        except urllib.error.HTTPError as exc:
            if name == 'NOTICE' and exc.code == 404:
                continue  # The pinned upstream tag has no separate NOTICE file.
            raise
        if len(content) > 1_048_576:
            raise ValueError('Unexpected license size')
        (notices / ('OpenSSL-' + name)).write_bytes(content)
    print(output)


if __name__ == '__main__':
    build()
