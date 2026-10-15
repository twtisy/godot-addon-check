# Alpha validation

Date: 2026-10-16. Version: 0.4.1a1, rules godot-text-r4.

## Local evidence

- 54 unittest methods passed, no skipped tests: scanner, archive/path boundaries, CLI subprocesses and Tk callbacks/event loop.
- Renamed public package passed the same 54 methods independently of the original development module names.
- Official embedded Python 3.13.16 also passed 34 scanner/CLI methods (Tk is not bundled). Its temporary-directory tests needed the normal user execution context because sandbox ACLs denied access to newly created private temp directories.
- Wheel installed into a fresh virtual environment outside the source tree. Installed namespace path was verified.
- Windows x64 portable CLI ran with Python removed from PATH. This was the existing development host, not a clean Windows installation.
- 20 packaged CLI checks across the wheel and portable build: version, demo HTML/JSON export, change exit 1, self-compare exit 0, unknown exit 3 precedence, damaged ZIP exit 2, input overwrite refusal, source opt-in and two real source upgrades.

## Public-source instances

| Upstream | Versions | Same-byte files | Changed files | Other |
| --- | --- | ---: | ---: | --- |
| [GUT](https://github.com/bitwes/Gut) | 9.6.0 → 9.6.1 | 212 | 36 | 9 read only in new |
| [Dialogue Manager](https://github.com/nathanhoad/godot_dialogue_manager) | 4.0.3 → 4.1.0 | 170 | 16 | 3 unknown because scan scope was incomplete |

The two shared-file inventories were also checked using direct ZIP byte equality: 434 common files matched the comparison classification. These are repository source archives, not final installed binary packages. No upstream code or binaries were executed. Third-party ZIPs are not redistributed here.

## Limits and release scope

These checks support an alpha trial, not a stable/security-certified product. There is no independent user study, detection precision/recall estimate or adoption evidence. Dynamic/native behavior is not analyzed. The directory scanner is not an isolation boundary against hostile concurrent changes.

Full local tests used Windows/Python 3.11/Tk 8.6. The portable CLI also uses and exercises official Python 3.13.16. GitHub Actions is configured for Python 3.11/3.12/3.13; inspect the actual run before assuming a platform/version is green. The CLI is headless; optional GUI currently uses Chinese.

The first self-extracting one-file binary failed a local temporary-DLL extraction check. Both PyInstaller builds were excluded from release after inspecting their old local Python runtime. The release portable folder uses the official Python 3.13.16 embeddable runtime, verified against the Python.org SHA-256, with its license retained. No clean-machine, antivirus reputation, accessibility or complete browser visual validation is claimed.

For a first trial, compare two public ZIPs you already understand, inspect unknown scope, and check the result against your normal workflow. We want five independent trials, two voluntary repeat users and one real upgrade use before expanding features.
