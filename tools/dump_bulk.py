#!/usr/bin/env python3
"""Dump every bulk record of a USBPcap capture, in order, with status.

Used to see exactly where a flash stalled: which URB completed, which one
timed out, and what the device sent back.

Usage::

    python dump_bulk.py C:\\usbcap\\rust_fail.pcap
"""

from __future__ import annotations

import struct
import sys

TRANSFER = {0: "control", 1: "iso", 2: "interrupt", 3: "bulk"}


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else ""
    if not path:
        print(__doc__)
        return 2
    blob = open(path, "rb").read()
    magic = blob[:4]
    if magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                     b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        print("not a classic pcap")
        return 2
    endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    _m, _vmaj, _vmin, _tz, _sig, _snap, link = struct.unpack_from(endian + "IHHiIII", blob, 0)
    if link != 249:
        print(f"linktype {link} != 249")
        return 2
    scale = 1e-9 if nano else 1e-6
    pos = 24
    t0 = None
    n = 0
    print(f"{'#':>4} {'t(s)':>9} {'dir':<4} {'ep':>4} {'len':>8} {'cap':>7} {'status':>12} head")
    while pos + 16 <= len(blob):
        ts_sec, ts_frac, cap_len, _orig = struct.unpack_from(endian + "IIII", blob, pos)
        pos += 16
        pkt = blob[pos:pos + cap_len]
        pos += cap_len
        if len(pkt) < 27:
            continue
        header_len, _irp, status, _fun, _info, _bus, dev, ep, transfer = (
            struct.unpack_from("<HQIHBHHBB", pkt, 0))
        (data_len,) = struct.unpack_from("<I", pkt, 23)
        ts = ts_sec + ts_frac * scale
        if t0 is None:
            t0 = ts
        if transfer != 3:
            continue
        n += 1
        if n > 300:
            print("...")
            break
        data = pkt[header_len:header_len + min(data_len, 24)]
        d = "IN" if ep & 0x80 else "OUT"
        print(f"{n:>4} {ts - t0:>9.3f} {d:<4} 0x{ep:02x} {data_len:>8} {cap_len - header_len:>7} "
              f"0x{status:08x} {data.hex(' ')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
