# ASCEND Security — Desktop

ASCEND is a Windows-first defensive security application under active development.

## Current build
- Dark terminal-inspired desktop UI
- File and folder static scanning
- SHA-256 hashing
- Windows PE/MZ header inspection
- Suspicious extension and filename checks
- Selected execution-related string indicators
- URL and scam-message analysis
- Read-only process list
- Read-only network connection view
- Manual quarantine workflow
- Uses the ASCEND logo asset from the project

## Run from source
```text
python ascend.py
```

Python's standard library is used for the current development build. No file is executed during analysis.

## Important
This is not yet a full antivirus. A production-grade release will require hardened real-time components, signed updates, deeper reputation intelligence and isolated analysis infrastructure.
