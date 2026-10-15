"""Create original synthetic fixtures and an honest SVG of actual CLI output."""
from pathlib import Path
import html
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def generate():
    out = ROOT / 'examples'
    out.mkdir(exist_ok=True)
    for name, code in [('old', '@tool\nextends EditorPlugin\n'),
                       ('new', '@tool\nextends EditorPlugin\n# Example only; never executed by this tool.\nfunc example():\n    OS.execute("example_program", [])\n')]:
        with zipfile.ZipFile(out / f'{name}.zip', 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for path, value in {'plugin.cfg': '[plugin]\nname="Demo"\nscript="main.gd"', 'LICENSE': 'MIT', 'main.gd': code}.items():
                info = zipfile.ZipInfo('demo-' + name + '/' + path, date_time=(2026, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, value)
    cmd = [sys.executable, '-m', 'addoncheck', str(out / 'old.zip'), str(out / 'new.zip'),
           '--strip-wrapper', '--html', str(out / 'report.html'), '--json', str(out / 'report.json')]
    result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
    if result.returncode != 0:
        raise RuntimeError(result.stderr)
    (out / 'cli-output.txt').write_text(result.stdout, encoding='utf-8')
    # This is a typeset recording, deliberately labelled; it is not a GUI screenshot.
    lines = ['$ addoncheck old.zip new.zip --strip-wrapper --html report.html', '',
             *result.stdout.strip().splitlines()]
    formatted = []
    import textwrap
    for line in lines:
        formatted.extend(textwrap.wrap(line, width=104, break_long_words=False) or [''])
    height = 140 + len(formatted) * 23
    text = ''.join(f'<text x="30" y="{108 + i * 23}" fill="#d5f3e4">{html.escape(line)}</text>' for i, line in enumerate(formatted))
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="1140" height="{height}" viewBox="0 0 1140 {height}">'
           '<rect width="1140" height="100%" rx="14" fill="#132a22"/>'
           '<g font-family="monospace" font-size="16"><text x="30" y="36" fill="#ffffff">Godot Addon Check</text>'
           '<text x="30" y="63" fill="#93b4a5">Actual CLI output, typeset as SVG | synthetic demo | no plugin execution</text>'
           f'{text}</g></svg>')
    (out / 'cli-demo.svg').write_text(svg, encoding='utf-8')
    print('Generated original demo ZIPs, redacted reports, CLI transcript and SVG.')


if __name__ == '__main__':
    generate()
