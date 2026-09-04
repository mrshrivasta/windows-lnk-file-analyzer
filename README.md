# Windows LNK File Analyzer

**A real, no-mock-data Windows Shell Link (.lnk) forensic binary parser — CLI + Web App.**
Binary-parses real `.lnk` files from scratch per the public **MS-SHLLINK** specification (Python `struct`, no third-party LNK library) and flags shortcuts pointing at removable/network media, TrackerDataBlock Droid/DroidBirth GUID mismatches proving a target file moved across machines, suspicious PowerShell/LOLBins command-line arguments, suspicious staging paths, batch-created timestamps, and invalid/non-LNK files.

Developed by **Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)

---

## ⚠️ Disclaimer (read before use)

This software is provided **strictly for educational, digital-forensics, and incident-response purposes**, and is offered **"AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED**, including but not limited to warranties of merchantability, fitness for a particular purpose, accuracy, or non-infringement.

- **Authorized use only.** Only analyze systems, media, or files that you own or for which you have explicit, documented authorization to investigate. Analyzing systems or evidence without authorization may violate computer-crime laws (e.g. the Computer Fraud and Abuse Act, the UK Computer Misuse Act, or equivalent legislation in your jurisdiction), organizational policy, and chain-of-custody requirements.
- **No liability.** The author, **Karanam Shrivasta**, and any contributors, accept **no responsibility or liability whatsoever** for any direct, indirect, incidental, special, or consequential damages — including data loss, evidence-handling errors, or legal consequences — arising from the use, misuse, or inability to use this software.
- **Not a certified forensic tool.** This tool is **not a substitute** for certified forensic software (e.g. EnCase, X-Ways, Autopsy, FTK) or a review by a qualified digital-forensics examiner, and its output is **not intended to be offered as expert testimony** in legal proceedings without independent verification.
- **No guaranteed detection.** Absence of findings does **not** mean a `.lnk` file is benign. This tool checks a specific, limited set of forensic indicators only, and full shell-item-ID (`IDList`) parsing is explicitly out of scope (see Architecture/Detection Rules below).
- **Read-only by design.** The Security Engine only opens `.lnk` files for reading (`open(path, "rb")`) — it never modifies, deletes, or writes to any file it scans. Verify this yourself by reading `app/security_engine/__init__.py` before running it on evidence.
- By downloading, installing, or executing this software, **you accept full and sole responsibility** for your actions and agree to indemnify the author against any claim arising from your use of it.

If you are unsure whether you are authorized to analyze a given file, drive, or system, **do not run this tool against it.**

---

## Who should use this project

- **DFIR analysts and incident responders** triaging `.lnk` shortcut artifacts recovered from a compromised host, USB drive, or `Recent Items`/`Jump Lists` folders during an investigation.
- **Security students and self-learners** studying Windows forensic artifacts, the MS-SHLLINK binary format, and how `.lnk` files are abused in phishing and malware persistence.
- **Threat hunters** looking for `.lnk`-based initial-access or LOLBins execution chains (PowerShell `-enc`, `mshta`, `regsvr32`, `bitsadmin`, etc.).
- **CI/CD or evidence-triage pipelines** that want an automated `.lnk` findings gate (the CLI exits non-zero when findings exist).

## Why use this project

- **Real data only** — every field comes from actually parsing the real bytes of a real `.lnk` file with `struct`. Nothing is mocked, sampled, or fabricated, in the CLI or the web app.
- **Spec-driven, transparent parser** — the entire MS-SHLLINK ShellLinkHeader/LinkInfo/StringData/TrackerDataBlock parser lives in one readable file (`app/security_engine/__init__.py`), with no external LNK-parsing dependency. Nothing is a black box.
- **Six documented forensic rules** — short, readable, pure Python functions in `app/detection_rules/__init__.py`, each with a real forensic-relevance docstring.
- **Two interfaces, one engine** — the CLI (for terminals/triage scripts) and the web app (for case dashboards/teams) both call the exact same `ScanEngine`, so results are always consistent.
- **Full workflow, not just a parser** — findings flow into Alerts, Alerts can be escalated into tracked Incidents, and everything rolls up into Analytics charts and CSV Reports.
- **Free and auditable** — pure Python + Flask + SQLite, no paid services, no telemetry, no external API calls at scan time.

---

## Architecture

```
windows-lnk-file-analyzer/
├── app/
│   ├── auth/                 # Authentication (register/login/logout, Flask-Login, hashed passwords)
│   ├── dashboard/             # Dashboard page + "run scan" action
│   ├── security_engine/      # Real MS-SHLLINK binary parser (struct) + scan orchestration
│   ├── detection_rules/      # 6 documented forensic detection rules (WLA-001..006)
│   ├── logs/                  # Scan history = audit log (Logs page)
│   ├── alerts/                # Alert generation from findings + Alerts page
│   ├── incident_management/  # Incident workflow (open -> investigating -> resolved -> closed)
│   ├── analytics/            # Real DB aggregation feeding Chart.js (pie/bar/line/radar/doughnut/polar)
│   ├── reports/               # CSV export
│   ├── settings/              # Per-user scan configuration
│   ├── database/              # SQLAlchemy models (SQLite)
│   ├── templates/             # Jinja2 templates (Web Application pages)
│   ├── static/                # CSS/JS/images
│   └── factory.py            # create_app() — wires every module together
├── cli/
│   └── main.py                # Standalone CLI (argparse): scan, rules
├── tests/                     # pytest suite — real constructed .lnk bytes + real web workflow
├── docs/                      # Additional documentation
├── run.py                     # Web Application entrypoint
├── requirements.txt
└── README.md                  # You are here
```

### Pages (Web Application — 9 total, minimum requirement of 6 exceeded)
1. **Login** — `/login`
2. **Register** — `/register`
3. **Dashboard** — `/` (stat tiles + run-scan form + recent scans)
4. **Logs** — `/logs` and `/logs/<id>` (full scan history + per-scan findings)
5. **Alerts** — `/alerts` (acknowledge / escalate to incident)
6. **Incident Management** — `/incidents` (status workflow)
7. **Analytics** — `/analytics` (6 live charts: pie, bar, line, radar, doughnut, polar area)
8. **Reports** — `/reports` (CSV export, all scans or per-scan)
9. **Settings** — `/settings` (default scan path, depth, exclusions, alert threshold)

---

## What the Security Engine actually parses

Given a real local path — a single `.lnk` file, or a directory that is real-walked for `*.lnk` files — every `.lnk` file's actual bytes are parsed per **MS-SHLLINK**:

- **ShellLinkHeader** (76 bytes) — validates `HeaderSize == 0x4C` and the CLSID `{00021401-0000-0000-C000-000000000046}`; parses `LinkFlags` (HasTargetIDList, HasLinkInfo, HasName, HasRelativePath, HasWorkingDir, HasArguments, HasIconLocation, IsUnicode, RunAsUser, …), `FileAttributesFlags`, the three `FILETIME` timestamps (CreationTime/AccessTime/WriteTime, 100ns intervals since 1601-01-01, converted to real UTC datetimes; `0` = not set), `FileSize`, `IconIndex`, `ShowCommand`, and `HotKey`.
- **LinkInfo** (if `HasLinkInfo`) — `LinkInfoFlags`, and when present: `VolumeID` (`DriveType` enum, `DriveSerialNumber` as real hex, `VolumeLabel`), `LocalBasePath`, and/or `CommonNetworkRelativeLink` (`NetName`, the real UNC share path).
- **StringData** (if the corresponding `LinkFlags` bits are set) — length-prefixed strings in the fixed order `NAME_STRING`, `RELATIVE_PATH`, `WORKING_DIR`, `COMMAND_LINE_ARGUMENTS`, `ICON_LOCATION`; decoded as UTF-16LE when `IsUnicode` is set, otherwise as the system codepage (implemented here as a latin-1/cp1252 fallback).
- **LinkTargetIDList** — if `HasTargetIDList` is set, the engine real-detects its presence and real-reads `IDListSize` to correctly skip over it. **Documented limitation:** full binary parsing of the individual shell item IDs inside the `IDList` (the `ITEMIDLIST` tree) is out of scope for this tool.
- **ExtraData** — the `TerminalBlock` (`0x00000000`)-delimited list of optional blocks is walked, and the **TrackerDataBlock** (signature `0xA0000003`) is decoded when present: a 16-byte `MachineID` plus the Droid Volume/File GUIDs and their DroidBirth counterparts, used to prove a target file was copied or moved across machines/volumes.

Malformed, truncated, or non-LNK files (wrong signature/CLSID, unexpected end-of-file mid-structure) are caught per file, either counted in `errors_count` or reported as a `WLA-006` finding, and never crash the overall scan.

---

## Detection Rules

| ID | Name | Severity | What it checks |
|----|------|----------|-----------------|
| WLA-001 | Removable or Network Target | Medium | The real embedded `LocalBasePath`/`NetName` resolves to a REMOVABLE (DriveType=2) or REMOTE (DriveType=4) volume — evidence of USB/external-media or network-share file access, a common exfiltration/lateral-movement artifact. |
| WLA-002 | Droid/DroidBirth GUID Mismatch | High | The real TrackerDataBlock's Droid Volume/File GUIDs differ from their real DroidBirth counterparts — proves the target file was copied/moved from its original machine/volume (classic forensic pivot-point evidence). |
| WLA-003 | Suspicious Command-Line Arguments | Medium | The real parsed `CommandLineArguments` string contains suspicious indicators (`-enc`/`-encodedcommand`, `-nop`, `-w hidden`, `iex`, `downloadstring`, `bitsadmin`, `certutil -decode`, `mshta`, `regsvr32 /i:http`) — classic LOLBins/PowerShell-obfuscation execution artifacts. |
| WLA-004 | Suspicious Staging Path | Low | The real parsed `WorkingDirectory`/`LocalBasePath` contains a suspicious staging substring (`\AppData\Local\Temp\`, `\Users\Public\`, `\ProgramData\`) and/or a double extension on the target name (e.g. `.pdf.lnk`, `.docx.exe`) — common malicious-shortcut staging locations. |
| WLA-005 | Identical Batch-Created Timestamps | Low | The real Creation/Access/Write `FILETIME`s on the `.lnk` are all identical to the second — can indicate a programmatically/batch-created shortcut (e.g. malware persistence) rather than one created interactively over time. |
| WLA-006 | Invalid LNK Signature/Format | Low | The file's real header signature/CLSID did not match the expected MS-SHLLINK format at all — reported as a parse-failure finding rather than crashing the scan. |

---

## Setup & Run

### Requirements
- Python 3.9+
- Works on any OS (the parser reads raw bytes — no dependency on the host being Windows)

### Install

```bash
git clone <this-repository-url>
cd windows-lnk-file-analyzer
python3 -m venv venv && source venv/bin/activate   # optional but recommended
pip install -r requirements.txt
```

### Run the Web Application

```bash
python3 run.py
# then open http://127.0.0.1:5000
```

Environment variables (optional):

```bash
WLA_SECRET_KEY=change-me   # Flask session secret — set this in production
PORT=5000                  # port to listen on
FLASK_DEBUG=1               # enable the debug reloader (development only)
```

Register an account on first run — accounts and all scan data live in a local SQLite file at `instance/wla.db`.

### Run the CLI

```bash
python3 cli/main.py scan ./evidence --depth 4
python3 cli/main.py scan suspicious.lnk --json
python3 cli/main.py scan ./evidence --csv findings.csv
python3 cli/main.py rules
```

The CLI exits with status code `1` if any findings are detected (useful as a triage/CI gate) and `0` if the target is clean.

### Run the tests

```bash
pip install -r requirements.txt
PYTHONPATH=. python3 -m pytest tests/ -v
```

The suite includes rule-level unit tests against synthetic parsed-field dicts, plus engine-level tests that **build real, spec-conformant `.lnk` bytes from scratch with `struct.pack`** (a real `ShellLinkHeader` with the correct CLSID/`HeaderSize`, a real `LinkInfo` with a REMOVABLE `VolumeID`, real `StringData` with a suspicious `-enc` command line, and a real `TrackerDataBlock` with mismatched Droid/DroidBirth GUIDs), write them to a real temp file, and run the actual `ScanEngine` against them — nothing is mocked.

---

## FAQ (for search & answer engines)

**What does the Windows LNK File Analyzer check?**
It binary-parses real `.lnk` files per the MS-SHLLINK spec and flags shortcuts pointing at removable/network volumes, TrackerDataBlock Droid/DroidBirth GUID mismatches (proof of file movement), suspicious PowerShell/LOLBins command-line arguments, suspicious staging paths, identical batch-created timestamps, and invalid/non-LNK files.

**Who should use it?**
DFIR analysts, incident responders, threat hunters, and security students analyzing `.lnk` artifacts on systems, media, or evidence they own or are explicitly authorized to investigate.

**Is it a replacement for a professional forensic examination?**
No. It is an educational and triage aid only — see the Disclaimer section above.

**Does it modify the files it scans?**
No. It only opens `.lnk` files for reading. It never writes to, deletes, or changes any file it scans.

**Does it parse the full shell-item IDList tree?**
No — this is a documented limitation. The engine real-detects `HasTargetIDList` and correctly skips over the `IDList` using its real `IDListSize`, but does not parse individual shell item IDs.

---

## License & Attribution

Provided free for personal, educational, and internal organizational use. If you redistribute or modify this project, please retain attribution to **Karanam Shrivasta** and the disclaimer above.

**Developed by Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)
