#!/usr/bin/env python3
"""Detailed timeline of an RTD129x flash capture.

Prints, for every CBW frame: opcode/LBA/indicator, the data URBs that follow
(with their *original* lengths, since USBPcap truncates to snaplen), and the
CSW with its status byte and latency. Also reports inter-frame timing, which
is what decides whether the tool is synchronous (wait CSW, then next chunk) or
pipelined.

Usage::

    python analyze_flow.py C:\\usbcap\\golden_original.pcap            # summary + first 24 frames
    python analyze_flow.py C:\\usbcap\\golden_original.pcap --frames 40
"""

from __future__ import annotations

import argparse
import struct
import sys
from dataclasses import dataclass

CBW_SIG = 0x43425355
CSW_SIG = 0x53425355
OPCODES = {
    0xF1: "SE_STORAGE", 0xF2: "SINGLE_STATUS", 0xF3: "NAND_WRITE", 0xF4: "WRITE",
    0xF5: "USB_HWSETTING", 0xF6: "WRITE_VERIFY", 0xF9: "EFUSE_BURN",
    0xFA: "DDR_ENABLE", 0xFB: "SINGLE_DATA", 0xFC: "READ_VERIFY", 0x1C: "SENSE",
}
STATUS = {0: "PASS", 1: "FAIL", 2: "PHASE_ERROR", 3: "WFILE", 4: "WKEYFAIL",
          5: "WKEYPASS", 6: "RKEYFAIL"}


@dataclass
class Rec:
    ts: float
    direction: str
    endpoint: int
    data_len: int     # original length (before snaplen truncation)
    cap_len: int      # bytes actually stored in the pcap
    data: bytes       # truncated payload


def parse_pcap(path: str) -> list[Rec]:
    blob = open(path, "rb").read()
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
        raise SystemExit("not a classic pcap file")
    _magic, _vmaj, _vmin, _tz, _sig, _snap, link = struct.unpack_from(
        endian + "IHHiIII", blob, 0)
    if link != 249:
        raise SystemExit(f"not USBPcap linktype ({link})")
    scale = 1e-9 if nano else 1e-6
    pos, recs = 24, []
    while pos + 16 <= len(blob):
        ts_sec, ts_frac, cap_len, _orig = struct.unpack_from(endian + "IIII", blob, pos)
        pos += 16
        pkt = blob[pos:pos + cap_len]
        pos += cap_len
        if len(pkt) < 27:
            continue
        header_len, _irp, status, _fun, _info, _bus, _dev, ep, transfer = (
            struct.unpack_from("<HQIHBHHBB", pkt, 0))
        (data_len,) = struct.unpack_from("<I", pkt, 23)
        if transfer != 3 or status != 0:
            continue
        recs.append(Rec(ts_sec + ts_frac * scale,
                        "in" if ep & 0x80 else "out", ep & 0x0F,
                        data_len, len(pkt) - header_len, pkt[header_len:]))
    return recs


def decode_csw_sig(data: bytes) -> bool:
    return len(data) >= 50 and struct.unpack_from("<I", data, 0)[0] == CSW_SIG


def decode_cbw(data: bytes) -> dict | None:
    if len(data) < 43 or struct.unpack_from("<I", data, 0)[0] != CBW_SIG:
        return None
    _sig, tag, dlen, flags, indicator, cbwcb_len = struct.unpack_from("<IIIBBB", data, 0)
    cb = data[15:15 + min(cbwcb_len, 28)]
    return {
        "tag": tag, "dlen": dlen, "flags": flags, "indicator": indicator,
        "cbwcb": cb, "opcode": cb[0], "type": cb[1],
        "lba": struct.unpack_from("<I", cb, 2)[0], "raw": data[:43],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("capture")
    ap.add_argument("--frames", type=int, default=24)
    args = ap.parse_args()

    recs = parse_pcap(args.capture)
    print(f"bulk records: {len(recs)}  (out={sum(r.direction == 'out' for r in recs)}"
          f" in={sum(r.direction == 'in' for r in recs)})")
    if not recs:
        return 1
    t0 = recs[0].ts
    print(f"duration    : {recs[-1].ts - t0:.3f} s")

    # Build frames: CBW(out) [+ data URBs(out)] + CSW(in)
    # USBPcap also emits zero-length bulk records (URB bookkeeping) around the
    # real payload; skip those instead of treating them as data/CSW.
    frames = []
    i = 0
    while i < len(recs):
        r = recs[i]
        cbw = decode_cbw(r.data)
        if r.direction != "out" or cbw is None:
            i += 1
            continue
        j = i + 1
        data_urbs = []
        while j < len(recs) and recs[j].direction == "out":
            if decode_cbw(recs[j].data) is not None:
                break
            if recs[j].data_len > 0:
                data_urbs.append(recs[j])
            j += 1
        csw = None
        while j < len(recs) and recs[j].direction == "in":
            if decode_csw_sig(recs[j].data):
                csw = recs[j]
                j += 1
                break
            j += 1
        frames.append((r, cbw, data_urbs, csw))
        i = j

    print(f"CBW frames  : {len(frames)}")
    with_csw = [f for f in frames if f[3] is not None]
    print(f"with CSW    : {len(with_csw)}  ({len(with_csw)/max(len(frames),1)*100:.1f}%)")
    print()

    # ---- detail: first N frames --------------------------------------------
    print(f"=== first {args.frames} frames ===")
    print(f"{'#':>4} {'t(s)':>8} {'op':<14} {'lba':>9} {'ind':>3} {'dlen':>7} "
          f"{'urbs':>4} {'urbLens':<24} {'csw':>5} {'dt_csw(ms)':>10} {'gap_next(ms)':>12}")
    prev_csw_ts = None
    for k, (cbw_rec, cbw, urbs, csw) in enumerate(frames[: args.frames]):
        csw_s = "-"
        dt_csw = ""
        gap = ""
        if csw is not None:
            csw_s = f"0x{csw.data[13]:02x}" if len(csw.data) >= 14 else "?"
            dt_csw = f"{(csw.ts - (urbs[-1].ts if urbs else cbw_rec.ts))*1000:.2f}"
        if prev_csw_ts is not None:
            gap = f"{(cbw_rec.ts - prev_csw_ts)*1000:.2f}"
        if csw is not None:
            prev_csw_ts = csw.ts
        lens = ",".join(str(u.data_len) for u in urbs)
        print(f"{k:>4} {cbw_rec.ts - t0:>8.3f} {OPCODES.get(cbw['opcode'], hex(cbw['opcode'])):<14} "
              f"0x{cbw['lba']:>7x} {cbw['indicator']:>3} {cbw['dlen']:>7} {len(urbs):>4} "
              f"{lens:<24} {csw_s:>5} {dt_csw:>10} {gap:>12}")
    print()

    # ---- summary statistics -------------------------------------------------
    print("=== summary ===")
    from collections import Counter
    print("opcodes:", dict(Counter(OPCODES.get(c['opcode'], hex(c['opcode'])) for _, c, _, _ in frames)))
    print("indicators:", dict(Counter(c["indicator"] for _, c, _, _ in frames)))
    print("CSW status:", dict(Counter(f[3].data[13] for f in with_csw if len(f[3].data) >= 14)))
    print("CSW lengths:", dict(Counter(f[3].data_len for f in with_csw)))
    print("data-URB lengths:", dict(Counter(u.data_len for _, _, us, _ in frames for u in us)))
    print("URBs per frame:", dict(Counter(len(us) for _, _, us, _ in frames)))
    lat = [(f[3].ts - (f[2][-1].ts if f[2] else f[0].ts)) * 1000 for f in with_csw]
    if lat:
        print(f"CSW latency ms: min={min(lat):.2f} median={sorted(lat)[len(lat)//2]:.2f} max={max(lat):.2f}")
    gaps = []
    last = None
    for _r, _c, _u, csw in frames:
        if last is not None:
            gaps.append((_r.ts - last) * 1000)
        if csw is not None:
            last = csw.ts
    if gaps:
        g = sorted(gaps)
        print(f"CBW-after-CSW gap ms: min={g[0]:.2f} median={g[len(g)//2]:.2f} p95={g[int(len(g)*0.95)]:.2f} max={g[-1]:.2f}")
    print()

    # ---- raw CBW / payload / CSW of the interesting frames -----------------
    for idx in (0, 1, 2, 3):
        if idx >= len(frames):
            break
        cbw_rec, cbw, urbs, csw = frames[idx]
        print(f"frame {idx} CBW ({OPCODES.get(cbw['opcode'])}) raw:")
        for off in range(0, 43, 8):
            print(f"  +{off:02x}  " + " ".join(f"{b:02x}" for b in cbw["raw"][off:off + 8]))
        for u in urbs:
            head = u.data[:32]
            print(f"  payload URB: data_len={u.data_len} cap={u.cap_len} head={head.hex(' ')}")
        if csw is not None and len(csw.data) >= 50:
            print("  CSW: " + " ".join(f"{b:02x}" for b in csw.data[:20])
                  + f"  status@13=0x{csw.data[13]:02x}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
