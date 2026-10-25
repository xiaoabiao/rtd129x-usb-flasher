#!/usr/bin/env python3
"""Extract bulk-OUT payloads of a given size range from a USBPcap capture.

Written to pull the original tool's `factory.tar` writes (144896 / 145408 B)
out of a 2.4 GB capture, but generic enough for any payload hunt. Streams the
file, so a multi-GB pcap does not have to fit in memory.

Usage::

    python extract_payloads.py C:\\usbcap\\orig_factory.pcap --min-len 100000 --max-len 200000 --out C:\\usbcap\\factory

Writes ``<out>-<n>-<len>.bin`` per hit and prints the surrounding CBW.
"""

from __future__ import annotations

import argparse
import struct
import sys

OPCODES = {0xF5: "USB_HWSETTING", 0xFA: "DDR_ENABLE", 0xF4: "WRITE"}


def decode_cbw(data: bytes):
    if len(data) < 43 or data[:4] != b"USBC":
        return None
    (dlen,) = struct.unpack_from("<I", data, 8)
    cb = data[15:43]
    return {
        "opcode": cb[0],
        "type": cb[1],
        "lba": struct.unpack_from("<I", cb, 2)[0],
        "dlen": dlen,
        "ind": data[13],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("capture")
    ap.add_argument("--min-len", type=int, default=100_000)
    ap.add_argument("--max-len", type=int, default=200_000)
    ap.add_argument("--out", default="C:\\usbcap\\payload")
    args = ap.parse_args()

    f = open(args.capture, "rb")
    gh = f.read(24)
    if len(gh) < 24 or gh[:4] not in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        print("not a little-endian classic pcap", file=sys.stderr)
        return 2
    pos = 24
    n = 0
    hits = 0
    last_cbw = None
    while True:
        hdr = f.read(16)
        if len(hdr) < 16:
            break
        _ts, _fr, cap, _orig = struct.unpack("<IIII", hdr)
        pkt = f.read(cap)
        if len(pkt) < 27:
            break
        header_len, _irp, status, _fn, _info, _bus, _dev, ep, transfer = (
            struct.unpack_from("<HQIHBHHBB", pkt, 0))
        (data_len,) = struct.unpack_from("<I", pkt, 23)
        if transfer != 3 or status != 0 or ep & 0x80:
            continue
        data = pkt[header_len:header_len + data_len]
        cbw = decode_cbw(data)
        if cbw is not None:
            last_cbw = cbw
            print(f"CBW  {OPCODES.get(cbw['opcode'], hex(cbw['opcode'])):13s} "
                  f"type=0x{cbw['type']:02x} lba=0x{cbw['lba']:x} "
                  f"dlen=0x{cbw['dlen']:x} ind={cbw['ind']}")
            continue
        if args.min_len <= data_len <= args.max_len:
            hits += 1
            n += 1
            path = f"{args.out}-{n}-{data_len}.bin"
            with open(path, "wb") as out:
                out.write(data)
            ctx = ""
            if last_cbw:
                ctx = (f" (after CBW lba=0x{last_cbw['lba']:x} "
                       f"dlen=0x{last_cbw['dlen']:x} ind={last_cbw['ind']})")
            print(f"PAYLOAD {data_len} bytes, captured {len(data)} -> {path}{ctx}")
    print(f"done: {hits} payload(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
