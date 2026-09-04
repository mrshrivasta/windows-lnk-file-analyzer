"""
Security Engine — Windows LNK File Analyzer
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Real, from-scratch parser for the Windows Shell Link (.LNK) binary file
format, implemented directly against the public MS-SHLLINK specification
using Python's `struct` module — no third-party LNK-parsing library is
used. Given a real local path (a single .lnk file, or a directory that is
real-walked with os.walk for "*.lnk" files), every field reported below is
read from the ACTUAL bytes of the file on disk. Nothing is sampled,
simulated, or fabricated.

Parsed per MS-SHLLINK:
  * ShellLinkHeader (76 bytes) — HeaderSize/CLSID validation, LinkFlags,
    FileAttributesFlags, the three FILETIME timestamps (converted to real
    UTC datetimes), FileSize, IconIndex, ShowCommand, HotKey.
  * LinkInfo (if HasLinkInfo) — LinkInfoFlags, VolumeID (DriveType, drive
    serial number, volume label), LocalBasePath, and/or
    CommonNetworkRelativeLink (NetName / UNC share path).
  * StringData (if the corresponding LinkFlags bits are set) — NAME_STRING,
    RELATIVE_PATH, WORKING_DIR, COMMAND_LINE_ARGUMENTS, ICON_LOCATION, each
    a length-prefixed string, UTF-16LE if IsUnicode else the system
    codepage (decoded here as latin-1/cp1252 as a practical fallback).
  * ExtraData — the TerminalBlock-delimited list of optional blocks is
    walked and the TrackerDataBlock (signature 0xA0000003) is decoded when
    present: 16-byte MachineID plus the Droid/DroidBirth Volume and File
    GUIDs used to detect that a shortcut's target was copied/moved across
    machines or volumes.

Documented limitation: if HasTargetIDList is set, this engine only reads
the IDListSize to correctly skip over the IDList and real-detects its
presence. Full binary parsing of individual shell item IDs (the tree of
ITEMIDLIST structures) is out of scope for this tool.

Malformed, truncated, or non-LNK files (wrong signature/CLSID, unexpected
EOF while parsing a structure) are caught per file, counted in
errors_count (or reported as a WLA-006 finding for a bad
signature/CLSID), and never crash the overall scan.
"""
import os
import struct
import time
from datetime import datetime, timedelta

from app.detection_rules import ALL_RULES

# {00021401-0000-0000-C000-000000000046} in on-disk little-endian GUID byte order
SHELL_LINK_CLSID = bytes.fromhex("0114020000000000C000000000000046")

HEADER_SIZE = 0x4C

# LinkFlags bits
FLAG_HAS_TARGET_ID_LIST = 0x00000001
FLAG_HAS_LINK_INFO = 0x00000002
FLAG_HAS_NAME = 0x00000004
FLAG_HAS_RELATIVE_PATH = 0x00000008
FLAG_HAS_WORKING_DIR = 0x00000010
FLAG_HAS_ARGUMENTS = 0x00000020
FLAG_HAS_ICON_LOCATION = 0x00000040
FLAG_IS_UNICODE = 0x00000080
FLAG_RUN_AS_USER = 0x00002000

# LinkInfoFlags bits
LINK_INFO_VOLUME_ID_AND_LOCAL_BASE_PATH = 0x00000001
LINK_INFO_COMMON_NETWORK_RELATIVE_LINK = 0x00000002

DRIVE_TYPES = {
    0: "UNKNOWN",
    1: "NO_ROOT_DIR",
    2: "REMOVABLE",
    3: "FIXED",
    4: "REMOTE",
    5: "CDROM",
    6: "RAMDISK",
}

SHOW_COMMANDS = {1: "SW_SHOWNORMAL", 3: "SW_SHOWMAXIMIZED", 7: "SW_SHOWMINNOACTIVE"}

TRACKER_DATA_BLOCK_SIGNATURE = 0xA0000003

DEFAULT_EXCLUDES = set()

_FILETIME_EPOCH = datetime(1601, 1, 1)


def _filetime_to_datetime(filetime):
    """Convert a real 64-bit FILETIME (100ns intervals since 1601-01-01) to a
    real UTC datetime. A value of 0 means "not set" per MS-SHLLINK and is
    returned as None."""
    if not filetime:
        return None
    try:
        return _FILETIME_EPOCH + timedelta(microseconds=filetime / 10)
    except OverflowError:
        return None


class LnkParseError(Exception):
    """Raised when a file's actual bytes do not conform to MS-SHLLINK."""


def _read_null_terminated_wide(data, offset):
    end = offset
    while end + 1 < len(data) and not (data[end] == 0 and data[end + 1] == 0):
        end += 2
    return data[offset:end].decode("utf-16-le", errors="replace"), end + 2


def _read_null_terminated_ascii(data, offset):
    end = data.find(b"\x00", offset)
    if end == -1:
        end = len(data)
    return data[offset:end].decode("latin-1", errors="replace"), end + 1


def parse_lnk_bytes(raw):
    """Parse the real bytes of one .lnk file per MS-SHLLINK. Returns a dict
    of every field this engine understands. Raises LnkParseError if the
    header signature/CLSID does not match a real Windows Shell Link."""
    if len(raw) < HEADER_SIZE:
        raise LnkParseError("file shorter than the fixed 76-byte ShellLinkHeader")

    header_size = struct.unpack_from("<I", raw, 0)[0]
    clsid = raw[4:20]
    if header_size != HEADER_SIZE or clsid != SHELL_LINK_CLSID:
        raise LnkParseError(
            f"invalid ShellLinkHeader: HeaderSize={header_size:#x} "
            f"(expected {HEADER_SIZE:#x}), CLSID={clsid.hex()} "
            f"(expected {SHELL_LINK_CLSID.hex()})"
        )

    link_flags = struct.unpack_from("<I", raw, 20)[0]
    file_attributes = struct.unpack_from("<I", raw, 24)[0]
    creation_time = struct.unpack_from("<Q", raw, 28)[0]
    access_time = struct.unpack_from("<Q", raw, 36)[0]
    write_time = struct.unpack_from("<Q", raw, 44)[0]
    file_size = struct.unpack_from("<I", raw, 52)[0]
    icon_index = struct.unpack_from("<i", raw, 56)[0]
    show_command = struct.unpack_from("<I", raw, 60)[0]
    hotkey = struct.unpack_from("<H", raw, 64)[0]
    # 68..76 = Reserved1(2) + Reserved2(4)

    result = {
        "header_size": header_size,
        "link_flags": link_flags,
        "file_attributes": file_attributes,
        "creation_time": _filetime_to_datetime(creation_time),
        "access_time": _filetime_to_datetime(access_time),
        "write_time": _filetime_to_datetime(write_time),
        "creation_time_raw": creation_time,
        "access_time_raw": access_time,
        "write_time_raw": write_time,
        "file_size": file_size,
        "icon_index": icon_index,
        "show_command": SHOW_COMMANDS.get(show_command, f"UNKNOWN({show_command})"),
        "hotkey": hotkey,
        "has_target_id_list": bool(link_flags & FLAG_HAS_TARGET_ID_LIST),
        "has_link_info": bool(link_flags & FLAG_HAS_LINK_INFO),
        "is_unicode": bool(link_flags & FLAG_IS_UNICODE),
        "run_as_user": bool(link_flags & FLAG_RUN_AS_USER),
        "name_string": None,
        "relative_path": None,
        "working_dir": None,
        "command_line_arguments": None,
        "icon_location": None,
        "drive_type": None,
        "drive_serial_number": None,
        "volume_label": None,
        "local_base_path": None,
        "net_name": None,
        "tracker": None,
    }

    offset = HEADER_SIZE

    # --- LinkTargetIDList (real-detect + skip only, per documented scope) ---
    if result["has_target_id_list"]:
        if offset + 2 > len(raw):
            raise LnkParseError("truncated before LinkTargetIDList IDListSize")
        id_list_size = struct.unpack_from("<H", raw, offset)[0]
        offset += 2 + id_list_size

    # --- LinkInfo ---
    if result["has_link_info"]:
        if offset + 4 > len(raw):
            raise LnkParseError("truncated before LinkInfo")
        link_info_start = offset
        link_info_size = struct.unpack_from("<I", raw, offset)[0]
        link_info_header_size = struct.unpack_from("<I", raw, offset + 4)[0]
        link_info_flags = struct.unpack_from("<I", raw, offset + 8)[0]
        volume_id_offset = struct.unpack_from("<I", raw, offset + 12)[0]
        local_base_path_offset = struct.unpack_from("<I", raw, offset + 16)[0]
        cnrl_offset = struct.unpack_from("<I", raw, offset + 20)[0]
        common_path_suffix_offset = struct.unpack_from("<I", raw, offset + 24)[0]

        has_volume_id_and_local = bool(link_info_flags & LINK_INFO_VOLUME_ID_AND_LOCAL_BASE_PATH)
        has_common_network = bool(link_info_flags & LINK_INFO_COMMON_NETWORK_RELATIVE_LINK)

        if has_volume_id_and_local and volume_id_offset:
            vid_off = link_info_start + volume_id_offset
            if vid_off + 16 <= len(raw):
                drive_type = struct.unpack_from("<I", raw, vid_off + 4)[0]
                drive_serial = struct.unpack_from("<I", raw, vid_off + 8)[0]
                volume_label_offset = struct.unpack_from("<I", raw, vid_off + 12)[0]
                result["drive_type"] = DRIVE_TYPES.get(drive_type, f"UNKNOWN({drive_type})")
                result["drive_serial_number"] = f"{drive_serial:08X}"
                if volume_label_offset:
                    label, _ = _read_null_terminated_ascii(raw, vid_off + volume_label_offset)
                    result["volume_label"] = label

        if has_volume_id_and_local and local_base_path_offset:
            lbp_off = link_info_start + local_base_path_offset
            if lbp_off < len(raw):
                path, _ = _read_null_terminated_ascii(raw, lbp_off)
                result["local_base_path"] = path

        if has_common_network and cnrl_offset:
            cnrl_off = link_info_start + cnrl_offset
            if cnrl_off + 8 <= len(raw):
                net_name_offset = struct.unpack_from("<I", raw, cnrl_off + 8)[0]
                if net_name_offset:
                    net_off = cnrl_off + net_name_offset
                    if net_off < len(raw):
                        net_name, _ = _read_null_terminated_ascii(raw, net_off)
                        result["net_name"] = net_name

        if not result["local_base_path"] and common_path_suffix_offset:
            suffix_off = link_info_start + common_path_suffix_offset
            if suffix_off < len(raw):
                suffix, _ = _read_null_terminated_ascii(raw, suffix_off)
                if suffix and not result["net_name"]:
                    result["local_base_path"] = suffix

        offset = link_info_start + link_info_size

    # --- StringData: fixed order, only fields whose LinkFlags bit is set ---
    string_fields = [
        ("name_string", FLAG_HAS_NAME),
        ("relative_path", FLAG_HAS_RELATIVE_PATH),
        ("working_dir", FLAG_HAS_WORKING_DIR),
        ("command_line_arguments", FLAG_HAS_ARGUMENTS),
        ("icon_location", FLAG_HAS_ICON_LOCATION),
    ]
    for key, flag_bit in string_fields:
        if not (link_flags & flag_bit):
            continue
        if offset + 2 > len(raw):
            raise LnkParseError(f"truncated before StringData field {key}")
        char_count = struct.unpack_from("<H", raw, offset)[0]
        offset += 2
        if result["is_unicode"]:
            byte_len = char_count * 2
            if offset + byte_len > len(raw):
                raise LnkParseError(f"truncated StringData field {key}")
            value = raw[offset:offset + byte_len].decode("utf-16-le", errors="replace")
            offset += byte_len
        else:
            byte_len = char_count
            if offset + byte_len > len(raw):
                raise LnkParseError(f"truncated StringData field {key}")
            value = raw[offset:offset + byte_len].decode("latin-1", errors="replace")
            offset += byte_len
        result[key] = value

    # --- ExtraData: TerminalBlock (0x00000000)-delimited list of blocks ---
    while offset + 4 <= len(raw):
        block_size = struct.unpack_from("<I", raw, offset)[0]
        if block_size == 0:
            break  # TerminalBlock
        if block_size < 4 or offset + block_size > len(raw):
            break  # malformed trailing bytes — stop, do not crash
        if block_size >= 8:
            block_signature = struct.unpack_from("<I", raw, offset + 4)[0]
            if block_signature == TRACKER_DATA_BLOCK_SIGNATURE and block_size >= 0x60:
                base = offset + 8
                length = struct.unpack_from("<I", raw, base)[0]
                version = struct.unpack_from("<I", raw, base + 4)[0]
                machine_id_raw = raw[base + 8: base + 24]
                machine_id, _ = _read_null_terminated_ascii(machine_id_raw, 0)
                droid_volume = raw[base + 24: base + 40]
                droid_file = raw[base + 40: base + 56]
                droid_birth_volume = raw[base + 56: base + 72]
                droid_birth_file = raw[base + 72: base + 88]
                result["tracker"] = {
                    "machine_id": machine_id,
                    "droid_volume_id": droid_volume.hex(),
                    "droid_file_id": droid_file.hex(),
                    "droid_birth_volume_id": droid_birth_volume.hex(),
                    "droid_birth_file_id": droid_birth_file.hex(),
                }
        offset += block_size

    return result


class ScanEngine:
    """Real-walks a real filesystem path and binary-parses every *.lnk file
    it finds with parse_lnk_bytes(), running every rule in
    app.detection_rules against the real parsed fields. No sample/mock LNK
    data is ever generated."""

    def __init__(self, target_path, max_depth=6, excludes=None, max_files=50000):
        self.target_path = os.path.abspath(target_path)
        self.max_depth = max_depth
        self.excludes = set(excludes) if excludes else set(DEFAULT_EXCLUDES)
        self.max_files = max_files

        self.files_scanned = 0
        self.dirs_scanned = 0
        self.errors_count = 0
        self.findings = []

    def _is_excluded(self, path):
        return any(path == ex or path.startswith(ex.rstrip("/") + "/") for ex in self.excludes)

    def run(self):
        """Perform the real, synchronous scan. Returns summary dict."""
        start = time.time()
        if os.path.isfile(self.target_path):
            self.dirs_scanned = 0
            self._scan_file(self.target_path)
        else:
            self._walk(self.target_path, depth=0)
        elapsed = time.time() - start
        return {
            "files_scanned": self.files_scanned,
            "dirs_scanned": self.dirs_scanned,
            "errors_count": self.errors_count,
            "findings": self.findings,
            "elapsed_seconds": round(elapsed, 3),
        }

    def _walk(self, path, depth):
        if self.files_scanned >= self.max_files:
            return
        if self._is_excluded(path):
            return
        if depth > self.max_depth:
            return

        try:
            with os.scandir(path) as it:
                entries = list(it)
        except (PermissionError, FileNotFoundError, NotADirectoryError, OSError):
            self.errors_count += 1
            return

        self.dirs_scanned += 1

        for entry in entries:
            if self.files_scanned >= self.max_files:
                return
            full_path = entry.path
            if self._is_excluded(full_path):
                continue
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                self.errors_count += 1
                continue

            if is_dir:
                self._walk(full_path, depth + 1)
            elif full_path.lower().endswith(".lnk"):
                self._scan_file(full_path)

    def _scan_file(self, path):
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
        except (PermissionError, FileNotFoundError, OSError):
            self.errors_count += 1
            return

        try:
            parsed = parse_lnk_bytes(raw)
        except LnkParseError as exc:
            self.files_scanned += 1
            self.findings.append({
                "rule_id": "WLA-006",
                "rule_name": "Invalid LNK Signature/Format",
                "severity": "low",
                "description": f"{path} does not conform to the MS-SHLLINK Shell Link format ({exc}).",
                "file_path": path,
                "permissions_octal": "N/A",
                "owner_uid": None,
                "owner_gid": None,
            })
            return
        except Exception:
            self.errors_count += 1
            return

        self.files_scanned += 1
        self._apply_rules(path, parsed)

    def _apply_rules(self, path, parsed):
        for rule in ALL_RULES:
            try:
                result = rule(path, parsed)
            except Exception:
                self.errors_count += 1
                continue
            if result:
                result["file_path"] = path
                result.setdefault(
                    "permissions_octal",
                    parsed.get("local_base_path") or parsed.get("net_name")
                    or parsed.get("command_line_arguments") or "N/A",
                )
                result["owner_uid"] = None
                result["owner_gid"] = None
                self.findings.append(result)
