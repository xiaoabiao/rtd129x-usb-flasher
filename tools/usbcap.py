#!/usr/bin/env python3
"""Decode a USB capture of the RTD129x wire-flash protocol.

Accepts either format:

* **USBPcap / pcapng** (``.pcapng``, ``.pcap``) -- what a Windows colleague
  produces with Wireshark + USBPcap.
* **usbmon text** (``/sys/kernel/debug/usb/usbmon/Nu``) -- what a Linux run
  produces.

It answers the questions the implementation could not settle by reasoning alone:

1. How many bytes does one ``WriteFile`` carry -- CBW and payload separately, or
   fused?
2. **Does the device answer every 256 KiB chunk, or only once per 2 MiB round?**
3. What status byte do those answers carry?
4. What are the exact 28 CBWCB bytes, to compare against our encoder?

Usage::

    python3 tools/usbcap.py capture.pcapng
    python3 tools/usbcap.py usbmon.txt --verbose
"""

from __future__ import annotations

import argparse
import struct
import sys
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Protocol constants (from the reverse engineering notes)
# ---------------------------------------------------------------------------

CBW_SIGNATURE = 0x43425355  # "USBC"
CSW_SIGNATURE = 0x53425355  # "USBS"
CBW_LEN = 43
CSW_LEN = 50
CSW_STATUS_OFFSET = 13

OPCODES = {
    0xF1: "SE_STORAGE",
    0xF2: "SINGLE_STATUS",
    0xF3: "NAND_WRITE",
    0xF4: "WRITE",
    0xF5: "USB_HWSETTING",
    0xF6: "WRITE_VERIFY",
    0xF9: "EFUSE_BURN",
    0xFA: "DDR_ENABLE",
    0xFB: "SINGLE_DATA",
    0xFC: "READ_VERIFY",
    0x1C: "SENSE",
}

STATUS_NAMES = {
    0x00: "PASS",
    0x01: "FAIL",
    0x02: "PHASE_ERROR",
    0x03: "WFILE",
}


@dataclass
class Record:
    """One bulk transfer, in capture order."""

    index: int
    direction: str  # "out" | "in"
    endpoint: int
    data: bytes
    timestamp: float = 0.0

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<{self.direction} ep={self.endpoint} {len(self.data)}B>"


@dataclass
class Frame:
    """A decoded CBW, its payload, and the status that answered it."""

    cbw: dict
    cbw_bytes: bytes
    payload: bytes
    csw: bytes | None
    csw_status: int | None
    records_between: list[Record] = field(default_factory=list)


# ---------------------------------------------------------------------------
# pcapng / USBPcap
# ---------------------------------------------------------------------------

# USBPcap's link layer. The header is 27 bytes in 1.x and 28 in 2.0; the
# difference is a trailing uint32, so parsing by declared length is safe.
USBPCAP_HEADER_MIN = 27
DLT_USBPCAP = 249
DLT_USBPCAP_ALT = 220  # some builds


def _parse_pcapng(blob: bytes) -> list[Record]:
    """Extract bulk transfers from a pcapng file."""
    out: list[Record] = []
    pos = 0
    index = 0
    while pos + 12 <= len(blob):
        block_type, block_len = struct.unpack_from("<II", blob, pos)
        if block_len < 12 or pos + block_len > len(blob):
            break
        body = blob[pos + 8 : pos + block_len - 4]

        if block_type == 0x00000006:  # Enhanced Packet Block
            if len(body) < 20:
                pos += block_len
                continue
            _iface, _ts_hi, _ts_lo, _cap_len, _orig_len = struct.unpack_from(
                "<IIIII", body, 0
            )
            packet = body[20:]
            rec = _parse_usbpcap_packet(packet, index)
            if rec is not None:
                out.append(rec)
                index += 1
        elif block_type == 0x00000003:  # Simple Packet Block
            packet = body[4:]
            rec = _parse_usbpcap_packet(packet, index)
            if rec is not None:
                out.append(rec)
                index += 1

        pos += block_len
    return out


def _parse_pcap(blob: bytes) -> list[Record]:
    """Extract bulk transfers from a classic pcap file."""
    if len(blob) < 24:
        return []
    magic = blob[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian, nano = "<", False
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian, nano = ">", False
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian, nano = "<", True
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian, nano = ">", True
    else:
        return []

    _magic, _vmaj, _vmin, _tz, _sig, _snap, link = struct.unpack_from(
        endian + "IHHiIII", blob, 0
    )
    out: list[Record] = []
    pos = 24
    index = 0
    scale = 1e-9 if nano else 1e-6
    while pos + 16 <= len(blob):
        ts_sec, ts_frac, cap_len, _orig = struct.unpack_from(endian + "IIII", blob, pos)
        pos += 16
        packet = blob[pos : pos + cap_len]
        pos += cap_len
        if link not in (DLT_USBPCAP, DLT_USBPCAP_ALT):
            continue
        rec = _parse_usbpcap_packet(packet, index)
        if rec is not None:
            rec.timestamp = ts_sec + ts_frac * scale
            out.append(rec)
            index += 1
    return out


def _parse_usbpcap_packet(packet: bytes, index: int) -> Record | None:
    """Decode one USBPcap pseudo-header plus its bulk payload.

    Frozen layout (USBPcap 1.5.x, what USBPcapCMD.exe writes)::

        u16 headerLen; u64 irpId; u32 status; u16 function; u8 info;
        u16 bus; u16 device; u8 endpoint; u8 transfer; u32 dataLength;  -- 27 bytes

    Some records (e.g. ``--inject-descriptors``) declare a 28-byte header; the
    data always starts at ``headerLen``, so we trust that field.
    """
    if len(packet) < USBPCAP_HEADER_MIN:
        return None
    header_len, _irp, status, _function, _info, _bus, _device, endpoint, transfer = (
        struct.unpack_from("<HQIHBHHBB", packet, 0)
    )
    if header_len < USBPCAP_HEADER_MIN or header_len > 64 or header_len > len(packet):
        return None
    (data_len,) = struct.unpack_from("<I", packet, 23)
    if transfer != 3:  # 3 == USBPCAP_TRANSFER_BULK
        return None
    if status != 0:  # failed IRP: no data worth decoding
        return None

    data = packet[header_len : header_len + data_len]
    if not data:
        return None

    # Bit 7 of the endpoint address selects direction.
    direction = "in" if endpoint & 0x80 else "out"
    return Record(index, direction, endpoint & 0x0F, bytes(data))


# ---------------------------------------------------------------------------
# usbmon text
# ---------------------------------------------------------------------------


def _parse_usbmon(text: str) -> list[Record]:
    """Extract bulk transfers from usbmon's text format.

    Lines look like::

        ffff8800b6a0d000 3222735255 C Ii:1:003:1 0:8 43 = 55534243...
        ffff8800b6a0d000 3222735340 S Bo:1:003:1 -115 1888 = ...

    We keep only ``C`` (callback = completed) lines carrying data.
    """
    out: list[Record] = []
    index = 0
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 7 or parts[2] != "C":
            continue
        # parts[3] is like "Ii:1:003:1" or "Bo:1:003:1"
        tag = parts[3]
        if len(tag) < 2 or tag[1] not in "ibo":
            continue
        if tag[1] == "i":
            continue  # isochronous
        direction = "out" if tag[1] == "o" else "in"
        try:
            ep = int(tag.split(":")[3])
            length = int(parts[5])
        except (IndexError, ValueError):
            continue
        if "=" not in line:
            continue
        hexpart = line.split("=", 1)[1].strip()
        try:
            data = bytes.fromhex(hexpart.replace(" ", ""))
        except ValueError:
            continue
        if not data:
            continue
        out.append(Record(index, direction, ep, data[:length] if length else data))
        index += 1
    return out


# ---------------------------------------------------------------------------
# Decoding
# ---------------------------------------------------------------------------


def parse_cbw(data: bytes) -> dict | None:
    """Decode a 43-byte Command Block Wrapper."""
    if len(data) < CBW_LEN:
        return None
    sig, tag, dlen, flags, indicator, cbwcb_len = struct.unpack_from("<IIIBBB", data, 0)
    if sig != CBW_SIGNATURE:
        return None
    cbwcb = data[15 : 15 + min(cbwcb_len, 28)]
    opcode = cbwcb[0] if cbwcb else 0
    lba = struct.unpack_from("<I", cbwcb, 2)[0] if len(cbwcb) >= 6 else 0
    return {
        "signature": sig,
        "tag": tag,
        "data_transfer_length": dlen,
        "flags": flags,
        "indicator": indicator,
        "cbwcb_length": cbwcb_len,
        "opcode": opcode,
        "opcode_name": OPCODES.get(opcode, f"0x{opcode:02x}"),
        "cmd_type": cbwcb[1] if len(cbwcb) >= 2 else 0,
        "lba": lba,
        "cbwcb": cbwcb,
        "raw": data[:CBW_LEN],
    }


def parse_csw(data: bytes) -> tuple[int, dict] | None:
    """Decode a status wrapper; returns ``(status_byte, fields)``."""
    if len(data) < CSW_LEN:
        return None
    sig, tag, residue = struct.unpack_from("<III", data, 0)
    if sig != CSW_SIGNATURE:
        return None
    status = data[CSW_STATUS_OFFSET]
    return status, {
        "signature": sig,
        "tag": tag,
        "residue": residue,
        "status": status,
        "status_name": STATUS_NAMES.get(status, f"0x{status:02x}"),
    }


def build_frames(records: list[Record]) -> list[Frame]:
    """Pair each CBW (and its payload) with the status that follows.

    The search for a status stops at the next CBW. Without that, a frame whose
    status never arrives swallows every later record while hunting for an IN
    transfer, and the report collapses to a couple of frames.
    """
    frames: list[Frame] = []
    i = 0
    while i < len(records):
        rec = records[i]
        if rec.direction != "out":
            i += 1
            continue
        cbw = parse_cbw(rec.data)
        if cbw is None:
            i += 1
            continue

        j = i + 1
        payload = b""
        if j < len(records):
            nxt = records[j]
            if nxt.direction == "out" and parse_cbw(nxt.data) is None:
                payload = nxt.data
                j += 1

        csw_bytes = None
        csw_status = None
        consumed: list[Record] = []
        while j < len(records):
            nxt = records[j]
            if nxt.direction == "in":
                parsed = parse_csw(nxt.data)
                if parsed is not None:
                    csw_status, _fields = parsed
                    csw_bytes = nxt.data[:CSW_LEN]
                    consumed.append(nxt)
                    j += 1
                    break
                consumed.append(nxt)
                j += 1
                continue
            # An OUT record: if it is a new CBW this frame has no status, so stop
            # rather than swallowing the rest of the capture.
            if parse_cbw(nxt.data) is not None:
                break
            consumed.append(nxt)
            j += 1

        frames.append(
            Frame(
                cbw=cbw,
                cbw_bytes=cbw["raw"],
                payload=payload,
                csw=csw_bytes,
                csw_status=csw_status,
                records_between=consumed,
            )
        )
        i = j
    return frames


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def report(records: list[Record], frames: list[Frame], verbose: bool) -> None:
    print(f"抓到的批量传输记录：{len(records)}")
    outs = sum(1 for r in records if r.direction == "out")
    ins = len(records) - outs
    print(f"  主机→设备 (OUT)：{outs}")
    print(f"  设备→主机 (IN) ：{ins}")
    print()

    if not frames:
        print("没有解析出任何 CBW。可能原因：")
        print("  * 抓包接口选错了（没抓到这块板子）")
        print("  * 抓的是控制传输而不是批量传输")
        print("  * 文件里只有 OUT 没有 IN")
        return

    print(f"解析出 CBW 帧：{len(frames)}")
    print()

    # --- the decisive statistic -------------------------------------------
    with_csw = [f for f in frames if f.csw is not None]
    print("=" * 68)
    print("关键结论：设备多久回一次状态？")
    print("=" * 68)
    print(f"  CBW 总数        : {len(frames)}")
    print(f"  收到 CSW 的总数 : {len(with_csw)}")
    if frames:
        ratio = len(frames) / max(len(with_csw), 1)
        print(f"  -> 平均每 {ratio:.2f} 个 CBW 收到 1 个 CSW")
    print()
    if len(with_csw) == len(frames):
        print("  判定：**每片都应答** -> 每片之后都要读 CSW")
    elif with_csw:
        # Count chunks between answers to spot the round size.
        gaps: list[int] = []
        last = -1
        for k, f in enumerate(frames):
            if f.csw is not None:
                gaps.append(k - last)
                last = k
        common = max(set(gaps), key=gaps.count) if gaps else 0
        print(f"  判定：**每 {common} 片应答一次**")
        if common in (7, 8, 9):
            print("        8 = 2 MiB / 256 KiB -> 每轮应答一次（轮末 LAST 之后）")
    else:
        print("  判定：**没有收到任何 CSW** -> 抓包可能不完整，或设备全程沉默")
    print()

    # --- status bytes -----------------------------------------------------
    statuses: dict[int, int] = {}
    for f in with_csw:
        if f.csw_status is not None:
            statuses[f.csw_status] = statuses.get(f.csw_status, 0) + 1
    if statuses:
        print("设备返回的状态字节分布：")
        for st, n in sorted(statuses.items()):
            print(f"  0x{st:02x} {STATUS_NAMES.get(st, '?'):<12} x{n}")
        print()

    # --- transfer sizes ---------------------------------------------------
    sizes: dict[int, int] = {}
    for f in frames:
        sizes[len(f.payload)] = sizes.get(len(f.payload), 0) + 1
    print("一次 WriteFile 的载荷大小分布：")
    for size, n in sorted(sizes.items()):
        print(f"  {size:>8} 字节  x{n}")
    print()

    # --- opcode / indicator summary ---------------------------------------
    by_op: dict[str, int] = {}
    for f in frames:
        by_op[f.cbw["opcode_name"]] = by_op.get(f.cbw["opcode_name"], 0) + 1
    print("操作码分布：")
    for name, n in sorted(by_op.items(), key=lambda kv: -kv[1]):
        print(f"  {name:<16} x{n}")
    print()

    inds: dict[int, int] = {}
    for f in frames:
        inds[f.cbw["indicator"]] = inds.get(f.cbw["indicator"], 0) + 1
    print("iIndicator 分布（1=FIRST 0=MIDDLE 3=LAST）：")
    for ind, n in sorted(inds.items()):
        print(f"  {ind}  x{n}")
    print()

    # --- LBA progression --------------------------------------------------
    lbas: list[tuple[str, int, int]] = []
    for f in frames:
        lbas.append((f.cbw["opcode_name"], f.cbw["lba"], f.cbw["indicator"]))
    print("前 30 帧的地址与指示符：")
    for k, (name, lba, ind) in enumerate(lbas[:30]):
        csw = frames[k].csw_status
        csw_s = "-" if csw is None else f"CSW 0x{csw:02x}"
        print(f"  {k:>3}. {name:<14} lba=0x{lba:<8x} ind={ind}  {csw_s}")
    if len(lbas) > 30:
        print(f"  ...（共 {len(lbas)} 帧）")
    print()

    if verbose:
        print("=" * 68)
        print("CBW 原始字节（前 5 帧）")
        print("=" * 68)
        for k, f in enumerate(frames[:5]):
            print(f"第 {k} 帧  ({len(f.cbw_bytes)} 字节)")
            for off in range(0, len(f.cbw_bytes), 8):
                chunk = f.cbw_bytes[off : off + 8]
                hexs = " ".join(f"{b:02x}" for b in chunk)
                print(f"  +{off:02x}  {hexs}")
            print()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("capture", help=".pcapng / .pcap / usbmon text file")
    ap.add_argument("-v", "--verbose", action="store_true", help="dump raw CBW bytes")
    args = ap.parse_args()

    blob = open(args.capture, "rb").read()

    # pcap/pcapng start with a magic number; anything else is usbmon text.
    if blob[:4] in (
        b"\x0a\x0d\x0d\x0a",  # pcapng
        b"\xd4\xc3\xb2\xa1",
        b"\xa1\xb2\xc3\xd4",
        b"\x4d\x3c\xb2\xa1",
        b"\xa1\xb2\x3c\x4d",
    ):
        if blob[:4] == b"\x0a\x0d\x0d\x0a":
            records = _parse_pcapng(blob)
            kind = "pcapng/USBPcap"
        else:
            records = _parse_pcap(blob)
            kind = "pcap/USBPcap"
    else:
        records = _parse_usbmon(blob.decode("utf-8", "replace"))
        kind = "usbmon text"

    print(f"输入格式：{kind}")
    print()
    report(records, build_frames(records), args.verbose)
    return 0


if __name__ == "__main__":
    sys.exit(main())
