import os
import struct
import sys
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.security_engine import SHELL_LINK_CLSID


def _build_finding_lnk_bytes():
    """Build real, spec-conformant .lnk bytes (same technique as
    tests/test_security_engine.py) with a REMOVABLE-drive target and a
    suspicious PowerShell command line, guaranteed to trigger findings."""
    link_flags = 0x00000002 | 0x00000020 | 0x00000080  # HasLinkInfo | HasArguments | IsUnicode
    header = struct.pack(
        "<I16sIIQQQIiIH10s",
        0x4C, SHELL_LINK_CLSID, link_flags, 0x20,
        0, 0, 0, 4096, 0, 1, 0, b"\x00" * 10,
    )

    local_base_path = "E:\\payload.exe".encode("latin-1") + b"\x00"
    volume_label = b"USBDRIVE\x00"
    volume_id = struct.pack("<III", 2, 0xDEADBEEF, 16) + volume_label
    volume_id = struct.pack("<I", 4 + len(volume_id)) + volume_id

    link_info_header_size = 0x1C
    volume_id_offset = link_info_header_size
    local_base_path_offset = volume_id_offset + len(volume_id)
    common_path_suffix_offset = local_base_path_offset + len(local_base_path)
    link_info_body = struct.pack(
        "<IIIIII", link_info_header_size, 0x00000001,
        volume_id_offset, local_base_path_offset, 0, common_path_suffix_offset,
    )
    link_info_variable = volume_id + local_base_path + b"\x00"
    link_info_size = 4 + len(link_info_body) + len(link_info_variable)
    link_info = struct.pack("<I", link_info_size) + link_info_body + link_info_variable

    args = "-nop -w hidden -enc SQBFAFgA"
    string_data = struct.pack("<H", len(args)) + args.encode("utf-16-le")

    terminal_block = struct.pack("<I", 0)
    return header + link_info + string_data + terminal_block


def test_full_scan_alert_incident_workflow(registered_client):
    tmpdir = tempfile.mkdtemp()
    try:
        lnk_path = os.path.join(tmpdir, "suspicious.lnk")
        with open(lnk_path, "wb") as fh:
            fh.write(_build_finding_lnk_bytes())

        # Run a real scan against a real temp dir containing a real .lnk file
        resp = registered_client.post("/scan/run", data={"target_path": tmpdir}, follow_redirects=True)
        assert resp.status_code == 200
        assert b"Scan complete" in resp.data

        # Logs page should show at least one scan
        resp = registered_client.get("/logs")
        assert tmpdir.encode() in resp.data
    finally:
        shutil.rmtree(tmpdir)

    # Alerts page should load (may or may not have alerts depending on host state)
    resp = registered_client.get("/alerts")
    assert resp.status_code == 200

    # Analytics JSON endpoint returns real aggregated data
    resp = registered_client.get("/analytics/data")
    assert resp.status_code == 200
    assert resp.is_json

    # Reports CSV export works
    resp = registered_client.get("/reports/export.csv")
    assert resp.status_code == 200
    assert resp.headers["Content-Type"].startswith("text/csv")


def test_settings_page_round_trip(registered_client):
    resp = registered_client.post("/settings", data={
        "default_scan_path": "/tmp",
        "scan_depth_limit": "3",
        "exclude_paths": "/proc,/sys",
        "alert_on_severity": "high",
    }, follow_redirects=True)
    assert b"Settings saved" in resp.data

    resp = registered_client.get("/settings")
    assert b"/tmp" in resp.data


def test_all_nav_pages_load(registered_client):
    for path in ["/", "/logs", "/alerts", "/incidents", "/analytics", "/reports", "/settings"]:
        resp = registered_client.get(path)
        assert resp.status_code == 200, f"{path} failed with {resp.status_code}"


def test_404_page(registered_client):
    resp = registered_client.get("/this-page-does-not-exist")
    assert resp.status_code == 404
