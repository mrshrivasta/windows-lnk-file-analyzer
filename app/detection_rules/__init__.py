"""
Detection Rules — Windows LNK File Analyzer
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Each rule inspects the REAL fields parsed by app.security_engine.parse_lnk_bytes
for one .lnk file (passed in as a plain dict, so rules are pure, easily
unit-testable functions with no I/O of their own) and returns a Finding
dict if the condition is met. Every rule documents the real DFIR/forensic
reasoning behind it so a human reviewer can independently verify each hit
against the MS-SHLLINK specification.
"""
import re

# Severity scale used consistently across the whole project
SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_INFO = "low"

SUSPICIOUS_ARG_PATTERN = re.compile(
    r"(-enc\b|-encodedcommand|-nop\b|-w\s+hidden|iex\b|downloadstring|"
    r"bitsadmin|certutil\s+-decode|mshta|regsvr32\s+/i:https?)",
    re.IGNORECASE,
)

STAGING_PATH_MARKERS = (
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
    "\\programdata\\",
)

DOUBLE_EXTENSION_PATTERN = re.compile(r"\.[a-z0-9]{2,4}\.(lnk|exe|scr|bat|cmd|vbs|js)$", re.IGNORECASE)


def rule_removable_or_network_target(path, parsed):
    """WLA-001: The .lnk's real embedded LocalBasePath/NetName resolves to a
    REMOVABLE (DriveType=2) or REMOTE (DriveType=4) volume. This is real
    forensic evidence that the shortcut points at (or was created from)
    USB/external media or a network share — a common exfiltration or
    lateral-movement artifact in DFIR investigations."""
    drive_type = parsed.get("drive_type")
    net_name = parsed.get("net_name")
    if drive_type in ("REMOVABLE",) or net_name:
        target = parsed.get("local_base_path") or net_name or "unknown target"
        kind = "removable media" if drive_type == "REMOVABLE" else "a network share"
        return {
            "rule_id": "WLA-001",
            "rule_name": "Removable or Network Target",
            "severity": SEVERITY_MEDIUM,
            "description": (
                f"Shortcut target resolves to {kind} ({target}) — DriveType="
                f"{drive_type or 'REMOTE'}. Evidence of USB/external-media or "
                f"network-share file access."
            ),
        }
    return None


def rule_droid_birth_mismatch(path, parsed):
    """WLA-002: The real TrackerDataBlock's Droid Volume/File GUIDs differ
    from their real DroidBirth counterparts. Windows only updates the Droid
    (current) GUIDs when a file is copied/moved to a new volume, while the
    DroidBirth GUIDs remain fixed from creation — a mismatch is classic
    forensic pivot-point evidence that the target file travelled between
    machines or volumes since it was first created."""
    tracker = parsed.get("tracker")
    if not tracker:
        return None
    vol_mismatch = tracker["droid_volume_id"] != tracker["droid_birth_volume_id"]
    file_mismatch = tracker["droid_file_id"] != tracker["droid_birth_file_id"]
    if vol_mismatch or file_mismatch:
        return {
            "rule_id": "WLA-002",
            "rule_name": "Droid/DroidBirth GUID Mismatch",
            "severity": SEVERITY_HIGH,
            "description": (
                f"TrackerDataBlock shows Droid GUIDs differ from DroidBirth GUIDs "
                f"(machine_id={tracker['machine_id']!r}) — the target file was "
                f"copied or moved from its original machine/volume."
            ),
        }
    return None


def rule_suspicious_command_line_args(path, parsed):
    """WLA-003: The real parsed CommandLineArguments string contains
    suspicious indicators (-enc/-encodedcommand, -nop, -w hidden, iex,
    downloadstring, bitsadmin, certutil -decode, mshta, regsvr32 /i:http)
    — classic LOLBins/PowerShell-obfuscation execution artifacts routinely
    observed in .lnk-based phishing and malware delivery."""
    args = parsed.get("command_line_arguments") or ""
    match = SUSPICIOUS_ARG_PATTERN.search(args)
    if match:
        return {
            "rule_id": "WLA-003",
            "rule_name": "Suspicious Command-Line Arguments",
            "severity": SEVERITY_MEDIUM,
            "description": (
                f"CommandLineArguments contains suspicious indicator "
                f"{match.group(0)!r} in: {args[:200]!r}"
            ),
        }
    return None


def rule_suspicious_staging_path(path, parsed):
    """WLA-004: The real parsed WorkingDirectory or LocalBasePath contains a
    suspicious staging-location substring (AppData\\Local\\Temp,
    Users\\Public, ProgramData), optionally combined with a double
    extension on the target name (e.g. invoice.pdf.lnk, report.docx.exe) —
    common malicious-shortcut staging patterns used to disguise a payload
    as a document."""
    working_dir = (parsed.get("working_dir") or "").lower()
    local_base = (parsed.get("local_base_path") or "").lower()
    name = parsed.get("name_string") or parsed.get("relative_path") or path
    has_staging_marker = any(m in working_dir or m in local_base for m in STAGING_PATH_MARKERS)
    has_double_ext = bool(DOUBLE_EXTENSION_PATTERN.search(name)) or bool(
        DOUBLE_EXTENSION_PATTERN.search(local_base)
    )
    if has_staging_marker or has_double_ext:
        return {
            "rule_id": "WLA-004",
            "rule_name": "Suspicious Staging Path",
            "severity": SEVERITY_LOW,
            "description": (
                f"Working directory/local base path uses a common malicious-"
                f"shortcut staging location (working_dir={parsed.get('working_dir')!r}, "
                f"local_base_path={parsed.get('local_base_path')!r})"
                + (", with a double file extension on the target name." if has_double_ext else ".")
            ),
        }
    return None


def rule_identical_batch_timestamps(path, parsed):
    """WLA-005: The real Creation/Access/Write FILETIMEs on the .lnk file
    are all identical down to the second. Interactively-created shortcuts
    almost always have distinct creation/access/write times; three
    identical timestamps can indicate the shortcut was created
    programmatically/in bulk (e.g. by a malware persistence dropper) rather
    than by a user dragging a file in Explorer."""
    ctime = parsed.get("creation_time")
    atime = parsed.get("access_time")
    wtime = parsed.get("write_time")
    if ctime is None or atime is None or wtime is None:
        return None
    if ctime.replace(microsecond=0) == atime.replace(microsecond=0) == wtime.replace(microsecond=0):
        return {
            "rule_id": "WLA-005",
            "rule_name": "Identical Batch-Created Timestamps",
            "severity": SEVERITY_LOW,
            "description": (
                f"CreationTime, AccessTime, and WriteTime are all identical "
                f"({ctime.isoformat()}Z) — suggests a programmatically/batch-"
                f"created shortcut rather than one created interactively."
            ),
        }
    return None


def rule_invalid_lnk_signature(path, parsed):
    """WLA-006: The file's real header signature/CLSID did not match the
    expected MS-SHLLINK format at all. Reported as a parse-failure finding
    (informational/low) rather than crashing the scan, so analysts can spot
    renamed/corrupted/non-LNK files mixed into a target directory.

    Note: this rule is a documentation placeholder — ScanEngine emits the
    WLA-006 finding directly from the parse failure (before a context dict
    exists), since a file that fails to parse has no parsed fields to
    evaluate. It is listed here, and in ALL_RULES, so `cli/main.py rules`
    and the README enumerate all six rules in one place."""
    if parsed.get("_invalid_signature"):
        return {
            "rule_id": "WLA-006",
            "rule_name": "Invalid LNK Signature/Format",
            "severity": SEVERITY_LOW,
            "description": f"{path} does not conform to the MS-SHLLINK Shell Link format.",
        }
    return None


ALL_RULES = [
    rule_removable_or_network_target,
    rule_droid_birth_mismatch,
    rule_suspicious_command_line_args,
    rule_suspicious_staging_path,
    rule_identical_batch_timestamps,
    rule_invalid_lnk_signature,
]
