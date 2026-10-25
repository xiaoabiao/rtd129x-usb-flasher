#!/usr/bin/env python3
"""Quick health-check of a USBPcap .pcap file (works even on a *growing* file).

Unlike ``usbcap.py`` (which decodes the flash protocol), this script only
answers "did the capture actually record anything, and from which device?".
That is what you need before trusting a protocol analysis.

Usage::

    python pcap_stats.py C:\\usbcap\\test.pcap
    python pcap_stats.py C:\\usbcap\\test.pcap --dump 10

It understands the USBPcap 1.x (27-byte) pseudo-header, and reports the
header length it saw so a version mismatch is obvious instead of silent.
"""

from __future__ import annotations

import argparse
import struct
import sys
from collections import Counter

TRANSFER_NAMES = {
    0: "control",
    1: "isochronous",
    2: "interrupt",
    3: "bulk",
}

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", False),
    b"\xa1\xb2\xc3\xd4": (">", False),
    b"\x4d\x3c\xb2\xa1": ("<", True),
    b"\xa1\xb2\x3c\x4d": (">", True),
}
DLT_USBPCAP = 249


def parse_usbpcap_header(pkt: bytes) -> dict | None:
    """Decode a USBPcap packet pseudo-header.

    The frozen layout (USBPcap 1.5.x, and what USBPcapCMD.exe writes today) is
    27 bytes::

        u16 headerLen; u64 irpId; u32 status; u16 function; u8 info;
        u16 bus; u16 device; u8 endpoint; u8 transfer; u32 dataLength;

    A 28-byte variant exists in USBPcap 2.0 betas; we detect it by the
    self-declared headerLen instead of guessing.
    """
    if len(pkt) < 27:
        return None
    header_len, irp, status, function, info, bus, device, endpoint, transfer = (
        struct.unpack_from("<HQIHBHHBB", pkt, 0)
    )
    if header_len < 27 or header_len > 64 or header_len > len(pkt):
        return None
    (data_len,) = struct.unpack_from("<I", pkt, 23)
    data = pkt[header_len : header_len + data_len]
    return {
        "header_len": header_len,
        "irp": irp,
        "status": status,
        "function": function,
        "info": info,
        "bus": bus,
        "device": device,
        "endpoint": endpoint,
        "transfer": transfer,
        "data_len": data_len,
        "data": data,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("capture")
    ap.add_argument("--dump", type=int, default=0, help="print first N packets")
    args = ap.parse_args()

    blob = open(args.capture, "rb").read()
    print(f"file      : {args.capture}")
    print(f"size      : {len(blob):,} bytes")

    magic = blob[:4]
    if magic not in PCAP_MAGICS:
        print("not a classic pcap file (magic mismatch) -- pcapng? use usbcap.py")
        return 1
    endian, nano = PCAP_MAGICS[magic]
    (magic_i, vmaj, vmin, tz, sig, snap, link) = struct.unpack_from(
        endian + "IHHiIII", blob, 0
    )
    print(f"pcap      : v{vmaj}.{vmin}  snaplen={snap}  linktype={link}"
          f"{'  <-- DLT_USBPCAP' if link == DLT_USBPCAP else ''}")
    if link != DLT_USBPCAP:
        print("WARNING: linktype is not USBPcap (249)")
        return 1

    pos = 24
    n = 0
    recs: list[dict] = []
    bad = 0
    first_ts = last_ts = None
    scale = 1e-9 if nano else 1e-6
    while pos + 16 <= len(blob):
        ts_sec, ts_frac, cap_len, _orig = struct.unpack_from(endian + "IIII", blob, pos)
        pos += 16
        pkt = blob[pos : pos + cap_len]
        pos += cap_len
        n += 1
        ts = ts_sec + ts_frac * scale
        if first_ts is None:
            first_ts = ts
        last_ts = ts
        hdr = parse_usbpcap_header(pkt)
        if hdr is None:
            bad += 1
            continue
        hdr["ts"] = ts
        hdr["cap_len"] = cap_len
        recs.append(hdr)

    print(f"packets   : {n}  (parsed {len(recs)}, unparsable {bad})")
    if recs:
        print(f"time span : {last_ts - first_ts:.3f} s"
              f"  ({first_ts:.3f} .. {last_ts:.3f})")
        print(f"headerLen : {sorted(Counter(r['header_len'] for r in recs))}")

    if not recs:
        print()
        print("=> EMPTY / UNUSABLE capture: nothing was recorded.")
        print("   * did USBPcapCMD really open \\\\.\\USBPcap1? (needs admin)")
        print("   * is the board on that root hub?")
        return 2

    print()
    print("transfer types:")
    for t, c in Counter(r["transfer"] for r in recs).most_common():
        print(f"  {TRANSFER_NAMES.get(t, t):<12} {c:>7}")

    print()
    print("per device (bus:device -> packets, bulk in/out):")
    devices = Counter((r["bus"], r["device"]) for r in recs)
    for (bus, dev), c in devices.most_common():
        bulk_out = sum(1 for r in recs if (r["bus"], r["device"]) == (bus, dev)
                       and r["transfer"] == 3 and not r["endpoint"] & 0x80)
        bulk_in = sum(1 for r in recs if (r["bus"], r["device"]) == (bus, dev)
                      and r["transfer"] == 3 and r["endpoint"] & 0x80)
        out_b = sum(r["data_len"] for r in recs if (r["bus"], r["device"]) == (bus, dev)
                    and r["transfer"] == 3 and not r["endpoint"] & 0x80)
        in_b = sum(r["data_len"] for r in recs if (r["bus"], r["device"]) == (bus, dev)
                   and r["transfer"] == 3 and r["endpoint"] & 0x80)
        print(f"  {bus}:{dev:<3} {c:>7}  bulk_out={bulk_out} ({out_b:,} B)"
              f"  bulk_in={bulk_in} ({in_b:,} B)")

    bulk = [r for r in recs if r["transfer"] == 3]
    if bulk:
        print()
        print("bulk endpoints:")
        for ep, c in Counter(r["endpoint"] for r in bulk).most_common():
            d = "IN " if ep & 0x80 else "OUT"
            print(f"  {d} ep=0x{ep:02x}  packets={c}")
    else:
        print()
        print("WARNING: no bulk transfers at all -- the flash traffic is not in this file.")

    if args.dump:
        print()
        print(f"first {args.dump} packets:")
        for r in recs[: args.dump]:
            d = "IN " if r["endpoint"] & 0x80 else "OUT"
            data = r["data"]
            head = data[:16].hex(" ")
            print(f"  t={r['ts'] - first_ts:8.3f}s {TRANSFER_NAMES.get(r['transfer'], r['transfer']):<10}"
                  f" {d} ep=0x{r['endpoint']:02x} dev={r['device']:<3} status={r['status']}"
                  f" len={r['data_len']:<7} {head}{' ...' if len(data) > 16 else ''}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
