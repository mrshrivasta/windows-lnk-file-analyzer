"""Tests for the Security Engine and Detection Rules.

Two layers:
  1. Rule-level unit tests against synthetic "parsed" context dicts (no I/O)
     — exercises each of the 6 detection rules in isolation.
  2. Engine-level tests that build REAL, spec-conformant .lnk bytes from
     scratch with struct.pack (a real ShellLinkHeader with the correct
     CLSID/HeaderSize, real LinkInfo, real StringData, and a real
     TrackerDataBlock), write them to a real temp file, and run the actual
     ScanEngine against real host paths — nothing here is mocked.
"""
import os
import struct
import sys
import tempfile
import shutil
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.security_engine import ScanEngine, parse_lnk_bytes, LnkParseError, SHELL_LINK_CLSID
from app.detection_rules import (
    rule_removable_or_network_target,
    rule_droid_birth_mismatch,
    rule_suspicious_command_line_args,
    rule_suspicious_staging_path,
    rule_identical_batch_timestamps,
    ALL_RULES,
)

# ---------------------------------------------------------------------------
# Rule-level unit tests (synthetic context dicts, no I/O)
# ---------------------------------------------------------------------------


def test_rule_removable_target_fires():
    ctx = {"drive_type": "REMOVABLE", "local_base_path": "E:\\payload.exe", "net_name": None}
    result = rule_removable_or_network_target("x.lnk", ctx)
    assert result["rule_id"] == "WLA-001"


def test_rule_removable_target_ignores_fixed_drive():
    ctx = {"drive_type": "FIXED", "local_base_path": "C:\\Windows\\notepad.exe", "net_name": None}
    assert rule_removable_or_network_target("x.lnk", ctx) is None


def test_rule_network_target_fires():
    ctx = {"drive_type": None, "local_base_path": None, "net_name": "\\\\FILESERVER\\share\\doc.pdf"}
    result = rule_removable_or_network_target("x.lnk", ctx)
    assert result["rule_id"] == "WLA-001"


def test_rule_droid_birth_mismatch_fires():
    ctx = {
        "tracker": {
            "machine_id": "victim-pc",
            "droid_volume_id": "aa" * 16,
            "droid_file_id": "bb" * 16,
            "droid_birth_volume_id": "cc" * 16,
            "droid_birth_file_id": "bb" * 16,
        }
    }
    result = rule_droid_birth_mismatch("x.lnk", ctx)
    assert result["rule_id"] == "WLA-002"
    assert result["severity"] == "high"


def test_rule_droid_birth_mismatch_absent_when_equal():
    ctx = {
        "tracker": {
            "machine_id": "victim-pc",
            "droid_volume_id": "aa" * 16,
            "droid_file_id": "bb" * 16,
            "droid_birth_volume_id": "aa" * 16,
            "droid_birth_file_id": "bb" * 16,
        }
    }
    assert rule_droid_birth_mismatch("x.lnk", ctx) is None


def test_rule_droid_birth_mismatch_absent_when_no_tracker():
    assert rule_droid_birth_mismatch("x.lnk", {"tracker": None}) is None


def test_rule_suspicious_command_line_args_fires():
    ctx = {"command_line_arguments": "-nop -w hidden -enc SQBFAFgA"}
    result = rule_suspicious_command_line_args("x.lnk", ctx)
    assert result["rule_id"] == "WLA-003"


def test_rule_suspicious_command_line_args_clean():
    ctx = {"command_line_arguments": "/silent /norestart"}
    assert rule_suspicious_command_line_args("x.lnk", ctx) is None


def test_rule_suspicious_staging_path_fires_on_temp():
    ctx = {
        "working_dir": r"C:\Users\bob\AppData\Local\Temp" + "\\",
        "local_base_path": None,
        "name_string": "update.exe",
        "relative_path": None,
    }
    result = rule_suspicious_staging_path("x.lnk", ctx)
    assert result["rule_id"] == "WLA-004"


def test_rule_suspicious_staging_path_fires_on_double_extension():
    ctx = {
        "working_dir": None,
        "local_base_path": r"C:\Users\bob\Downloads\invoice.pdf.exe",
        "name_string": None,
        "relative_path": None,
    }
    result = rule_suspicious_staging_path("x.lnk", ctx)
    assert result["rule_id"] == "WLA-004"


def test_rule_suspicious_staging_path_clean():
    ctx = {
        "working_dir": r"C:\Program Files\Vendor",
        "local_base_path": r"C:\Program Files\Vendor\app.exe",
        "name_string": "app.exe",
        "relative_path": None,
    }
    assert rule_suspicious_staging_path("x.lnk", ctx) is None


def test_rule_identical_timestamps_fires():
    from datetime import datetime
    t = datetime(2024, 1, 1, 12, 0, 0)
    ctx = {"creation_time": t, "access_time": t, "write_time": t}
    result = rule_identical_batch_timestamps("x.lnk", ctx)
    assert result["rule_id"] == "WLA-005"


def test_rule_identical_timestamps_absent_when_different():
    from datetime import datetime, timedelta
    t = datetime(2024, 1, 1, 12, 0, 0)
    ctx = {"creation_time": t, "access_time": t + timedelta(days=1), "write_time": t}
    assert rule_identical_batch_timestamps("x.lnk", ctx) is None


def test_all_rules_list_has_six_entries():
    assert len(ALL_RULES) == 6


# ---------------------------------------------------------------------------
# Real binary construction helpers (spec-conformant per MS-SHLLINK)
# ---------------------------------------------------------------------------

def _build_lnk_bytes(
    local_base_path=None,
    drive_type=2,  # REMOVABLE
    command_line_arguments=None,
    working_dir=None,
    tracker_mismatch=False,
    creation_time=0,
    access_time=0,
    write_time=0,
):
    """Build real, spec-conformant .lnk bytes from scratch via struct.pack."""
    link_flags = 0
    if local_base_path:
        link_flags |= 0x00000002  # HasLinkInfo
    if working_dir:
        link_flags |= 0x00000010  # HasWorkingDir
    if command_line_arguments:
        link_flags |= 0x00000020  # HasArguments
    link_flags |= 0x00000080  # IsUnicode

    file_attributes = 0x20  # FILE_ATTRIBUTE_ARCHIVE
    file_size = 12345
    icon_index = 0
    show_command = 1
    hotkey = 0

    header = struct.pack(
        "<I16sIIQQQIiIH10s",
        0x4C,
        SHELL_LINK_CLSID,
        link_flags,
        file_attributes,
        creation_time,
        access_time,
        write_time,
        file_size,
        icon_index,
        show_command,
        hotkey,
        b"\x00" * 10,
    )
    assert len(header) == 76, len(header)

    body = b""

    if local_base_path:
        volume_label = b"USBDRIVE\x00"
        # VolumeID structure: VolumeIDSize(4) DriveType(4) DriveSerialNumber(4)
        # VolumeLabelOffset(4) VolumeLabel(var, null-terminated)
        vid_label_offset = 16
        volume_id = struct.pack("<III", drive_type, 0xDEADBEEF, vid_label_offset) + volume_label
        volume_id = struct.pack("<I", 4 + len(volume_id)) + volume_id

        local_base_path_bytes = local_base_path.encode("latin-1") + b"\x00"
        common_path_suffix_bytes = b"\x00"

        # LinkInfoHeaderSize covers: LinkInfoHeaderSize, LinkInfoFlags,
        # VolumeIDOffset, LocalBasePathOffset,
        # CommonNetworkRelativeLinkOffset, CommonPathSuffixOffset (6 * 4 = 24
        # bytes) -- variable-length data starts right after, at relative
        # offset 4 (LinkInfoSize) + 24 = 28 from the start of LinkInfo.
        link_info_header_size = 0x1C  # 28
        volume_id_offset = link_info_header_size
        local_base_path_offset = volume_id_offset + len(volume_id)
        common_network_relative_link_offset = 0
        common_path_suffix_offset = local_base_path_offset + len(local_base_path_bytes)

        link_info_flags = 0x00000001  # VolumeIDAndLocalBasePath
        link_info_body = struct.pack(
            "<IIIIII",
            link_info_header_size,
            link_info_flags,
            volume_id_offset,
            local_base_path_offset,
            common_network_relative_link_offset,
            common_path_suffix_offset,
        )
        link_info_variable = volume_id + local_base_path_bytes + common_path_suffix_bytes
        link_info_size = 4 + len(link_info_body) + len(link_info_variable)
        link_info = struct.pack("<I", link_info_size) + link_info_body + link_info_variable
        body += link_info

    def _string_data(s):
        encoded = s.encode("utf-16-le")
        return struct.pack("<H", len(s)) + encoded

    if working_dir:
        body += _string_data(working_dir)
    if command_line_arguments:
        body += _string_data(command_line_arguments)

    # ExtraData: TrackerDataBlock (signature 0xA0000003)
    machine_id = b"VICTIM-PC\x00\x00\x00\x00\x00\x00\x00"
    assert len(machine_id) == 16
    if tracker_mismatch:
        droid_volume = uuid.uuid4().bytes
        droid_file = uuid.uuid4().bytes
        droid_birth_volume = uuid.uuid4().bytes  # different from droid_volume -> mismatch
        droid_birth_file = uuid.uuid4().bytes
    else:
        droid_volume = uuid.uuid4().bytes
        droid_file = uuid.uuid4().bytes
        droid_birth_volume = droid_volume
        droid_birth_file = droid_file

    tracker_payload = struct.pack("<II", 0x58, 0) + machine_id + droid_volume + droid_file + droid_birth_volume + droid_birth_file
    tracker_block = struct.pack("<II", 8 + len(tracker_payload), 0xA0000003) + tracker_payload
    terminal_block = struct.pack("<I", 0)

    return header + body + tracker_block + terminal_block


# ---------------------------------------------------------------------------
# Engine-level tests against REAL constructed .lnk bytes
# ---------------------------------------------------------------------------

def test_parse_valid_lnk_bytes_round_trips_fields():
    raw = _build_lnk_bytes(
        local_base_path="E:\\payload.exe",
        drive_type=2,
        command_line_arguments="-nop -w hidden -enc SQBFAFgA",
        working_dir="E:\\",
    )
    parsed = parse_lnk_bytes(raw)
    assert parsed["drive_type"] == "REMOVABLE"
    assert parsed["local_base_path"] == "E:\\payload.exe"
    assert parsed["command_line_arguments"] == "-nop -w hidden -enc SQBFAFgA"
    assert parsed["tracker"]["machine_id"] == "VICTIM-PC"


def test_parse_rejects_bad_signature():
    raw = b"\x00" * 76
    try:
        parse_lnk_bytes(raw)
        assert False, "expected LnkParseError"
    except LnkParseError:
        pass


def test_engine_scans_real_lnk_file_and_fires_multiple_findings():
    tmpdir = tempfile.mkdtemp()
    try:
        lnk_path = os.path.join(tmpdir, "invoice.lnk")
        raw = _build_lnk_bytes(
            local_base_path="E:\\invoice.pdf.exe",
            drive_type=2,
            command_line_arguments="powershell.exe -nop -w hidden -enc SQBFAFgA",
            working_dir="E:\\AppData\\Local\\Temp\\",
            tracker_mismatch=True,
        )
        with open(lnk_path, "wb") as fh:
            fh.write(raw)

        engine = ScanEngine(tmpdir, max_depth=3)
        result = engine.run()

        assert result["files_scanned"] == 1
        assert result["errors_count"] == 0
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WLA-001" in rule_ids  # removable drive target
        assert "WLA-002" in rule_ids  # droid/droid-birth mismatch
        assert "WLA-003" in rule_ids  # suspicious command line
        for f in result["findings"]:
            assert f["file_path"] == lnk_path
            assert f["owner_uid"] is None
            assert f["owner_gid"] is None
    finally:
        shutil.rmtree(tmpdir)


def test_engine_scans_single_file_target():
    tmpdir = tempfile.mkdtemp()
    try:
        lnk_path = os.path.join(tmpdir, "clean.lnk")
        raw = _build_lnk_bytes(local_base_path="C:\\Program Files\\App\\app.exe", drive_type=3)
        with open(lnk_path, "wb") as fh:
            fh.write(raw)

        engine = ScanEngine(lnk_path)
        result = engine.run()
        assert result["files_scanned"] == 1
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WLA-001" not in rule_ids  # FIXED drive, no finding
    finally:
        shutil.rmtree(tmpdir)


def test_engine_handles_malformed_lnk_without_crashing():
    tmpdir = tempfile.mkdtemp()
    try:
        bad_path = os.path.join(tmpdir, "corrupt.lnk")
        with open(bad_path, "wb") as fh:
            fh.write(b"NOTALNKFILE" * 5)

        engine = ScanEngine(tmpdir, max_depth=3)
        result = engine.run()
        assert result["files_scanned"] == 1
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WLA-006" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_engine_ignores_non_lnk_files():
    tmpdir = tempfile.mkdtemp()
    try:
        with open(os.path.join(tmpdir, "notes.txt"), "w") as fh:
            fh.write("hello")

        engine = ScanEngine(tmpdir, max_depth=3)
        result = engine.run()
        assert result["files_scanned"] == 0
        assert result["findings"] == []
    finally:
        shutil.rmtree(tmpdir)


def test_engine_scan_of_empty_directory_runs_without_crashing():
    tmpdir = tempfile.mkdtemp()
    try:
        engine = ScanEngine(tmpdir, max_depth=2)
        result = engine.run()
        assert result["files_scanned"] == 0
        assert isinstance(result["findings"], list)
    finally:
        shutil.rmtree(tmpdir)
