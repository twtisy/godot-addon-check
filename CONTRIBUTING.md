# Contributing

Please start with a small, non-sensitive example and describe your actual ZIP-upgrade workflow.
Include OS, Python, scanner/rule versions, expected and actual results. Never attach secrets, private source or malware.
Run `python -m unittest discover -s tests -v` before a change. Keep the scanner offline and read-only,
preserve default export redaction and explicit unknown scope. Tk tests need a desktop session.
Real-user feedback and reproducible failures are more useful than star counts.
