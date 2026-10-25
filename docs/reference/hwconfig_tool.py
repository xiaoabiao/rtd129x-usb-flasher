#!/usr/bin/env python3
"""
hwconfig_tool.py -- encode/decode RTD129x hwsetting blobs.

Recovered from boot_recovery.exe (RTD1295/RTD1296 UART recovery tool,
Desktop/key/boot_recovery.exe, MFC/VC6, 2017-02-14).

Two functions matter:

  CBoot_recoveryDlg::hwconfig_to_Hwbinfile  -> wrapper @0x00401c30
  FUN_00404810                              -> the actual converter

FUN_00404810 reads a TEXT .config file with mode "rt", tokenises each line with
the separator set b" ," (DAT_00435b10), and writes a BINARY stream with mode
"wb". Every emitted value is a little-endian u32 written byte-by-byte from LSB
to MSB (FUN_00404dd0:  for i in 0,8,16,24: putc((v >> i) & 0xff)).

Text-side details recovered from the companion object files:
  * The UART path's own parser CBoot_recoveryDlg::parse_line (obj section 109)
    uses strtok() with separators b" ,\t" (bytes 20 2c 09 00) and atoh() to
    convert numbers, then dispatches on the first character via an 11-entry
    switch over 'm'..'w'.
  * '=' is NOT a separator and is not parsed anywhere: a scan of .text finds
    zero `cmp <reg>, 0x3D` instructions. Values are positional, not key=value.
  * CBoot_recoveryDlg::swap (obj section 103) is a 4-byte reversal helper
    (dst = byteswap(src)) used by the UART/YMODEM path, not by this converter.

Instruction grammar (all fields are u32 LE):

    w <addr> <value>            -> emit  addr, value
    p <addr> <a> <b>            -> emit (addr | 1), a, b        ; poll / wait
    n <value>                   -> emit  3, value               ; nop / delay
    m <addr> <a> <b> [<or>]     -> emit (addr | 2), a, b        ; mask (read-modify-write)
    (end of file)               -> emit  0xFFFFFFFF

The low 2 bits of the first word select the operation:
    0 -> plain write   (2 words)
    1 -> poll          (3 words)
    2 -> mask          (3 words)
    3 -> nop           (2 words, first word == 3)

Special case in the original: if the mask address is 0xB801A60C and it is the
first mask seen, the next token is consumed as a repeat count.

Usage:
    python3 hwconfig_tool.py decode <blob.bin>      # AES-ECB decrypt + disassemble
    python3 hwconfig_tool.py encode <in.config> <out.bin> [--encrypt]
    python3 hwconfig_tool.py roundtrip <blob.bin>   # decode then re-encode, compare

Self-test:  python3 hwconfig_tool.py selftest
"""

from __future__ import annotations

import struct
import sys

AES_KEY_USB = bytes.fromhex("abcdef1213572468a1b2c3d49090babe")
# Separators recovered from the binaries. Two different tokenisers exist:
#   * HwConfig converter (FUN_00404810) -> FUN_0040D214, literal at 0x00435B10
#     == b" ," ; the code additionally skips \0, \t, \n, '#' and '/'
#   * parse_line (UART path, boot_recoveryDlg.obj sec 109) -> strtok with the
#     literal b" ,\t" (bytes 20 2c 09 00)
# Neither one handles '=' : there is no cmp ...,0x3D anywhere in .text.
SEPARATORS = " ,\t\r\n"
TERMINATOR = 0xFFFFFFFF

OP_WRITE = 0
OP_POLL = 1
OP_MASK = 2
OP_NOP = 3

MASK_REPEAT_ADDR = 0xB801A60C

# After the 0xFFFFFFFF terminator every shipped blob carries a trailer:
#   [16 bytes] key-derivation header. Observed value, identical in all three files:
#              efabcdaa 13572468 a1b2c3d4 9092baba
#              (note it shares 8 bytes with the AES key: bytes 4..12 == key[4:12])
#   [N bytes]  small field, mostly zero; usb_hwsetting.bin shows 80 00*9 23 a0
#              (0x23A0 little-endian at the end). Probably a length/checksum tag.
#   [32 bytes] signature / MAC over the preceding data
# The exact MAC algorithm was not recovered; it is not a plain MD5/SHA of any
# obvious range. Keep it verbatim when regenerating a blob.
TRAILER_HEADER_LEN = 16
TRAILER_SIG_LEN = 32

# ---------------------------------------------------------------------------
# AES layer (ECB; see PROTOCOL.md section 5 for the mode proof)
# ---------------------------------------------------------------------------
def aes_ecb_decrypt(data: bytes, key: bytes = AES_KEY_USB) -> bytes:
    from Crypto.Cipher import AES
    return AES.new(key, AES.MODE_ECB).decrypt(data)


def aes_ecb_encrypt(data: bytes, key: bytes = AES_KEY_USB) -> bytes:
    from Crypto.Cipher import AES
    pad = (-len(data)) % 16
    return AES.new(key, AES.MODE_ECB).encrypt(data + b"\0" * pad)


# ---------------------------------------------------------------------------
# binary -> instructions
# ---------------------------------------------------------------------------
def decode_stream(blob: bytes) -> list[tuple]:
    """Disassemble the flat u32 stream into a list of instruction tuples."""
    if len(blob) % 4:
        raise ValueError(f"stream length {len(blob)} is not a multiple of 4")
    n = len(blob) // 4
    w = list(struct.unpack_from("<%dI" % n, blob, 0))
    ops: list[tuple] = []
    i = 0
    while i < n:
        a = w[i]
        if a == TERMINATOR:
            ops.append(("end",))
            i += 1
            break
        if a == OP_NOP:
            if i + 1 >= n:
                raise ValueError("truncated nop")
            ops.append(("nop", w[i + 1]))
            i += 2
        elif a & OP_MASK:
            if i + 2 >= n:
                raise ValueError("truncated mask")
            ops.append(("mask", a & ~OP_MASK, w[i + 1], w[i + 2]))
            i += 3
        elif a & OP_POLL:
            if i + 2 >= n:
                raise ValueError("truncated poll")
            ops.append(("poll", a & ~OP_POLL, w[i + 1], w[i + 2]))
            i += 3
        else:
            if i + 1 >= n:
                raise ValueError("truncated write")
            ops.append(("write", a, w[i + 1]))
            i += 2
    return ops


# ---------------------------------------------------------------------------
# instructions -> binary
# ---------------------------------------------------------------------------
def encode_stream(ops: list[tuple], terminate: bool = True) -> bytes:
    out: list[int] = []
    for o in ops:
        kind = o[0]
        if kind == "write":
            out += [o[1], o[2]]
        elif kind == "poll":
            out += [o[1] | OP_POLL, o[2], o[3]]
        elif kind == "mask":
            out += [o[1] | OP_MASK, o[2], o[3]]
        elif kind == "nop":
            out += [OP_NOP, o[1]]
        elif kind == "end":
            continue
        else:
            raise ValueError(f"unknown op {kind!r}")
    if terminate:
        out.append(TERMINATOR)
    return struct.pack("<%dI" % len(out), *out)


# ---------------------------------------------------------------------------
# instruction stream <-> full blob (instructions + terminator + trailer)
# ---------------------------------------------------------------------------
def split_blob(plain: bytes) -> tuple[bytes, bytes]:
    """Split a decrypted blob into (instructions_with_terminator, trailer)."""
    n = len(plain) // 4
    w = list(struct.unpack_from("<%dI" % n, plain, 0))
    i = 0
    while i < n:
        a = w[i]
        if a == TERMINATOR:
            end = (i + 1) * 4
            return plain[:end], plain[end:]
        if a == OP_NOP:
            i += 2
        elif a & OP_MASK:
            i += 3
        elif a & OP_POLL:
            i += 3
        else:
            i += 2
    raise ValueError("no terminator found")


def join_blob(instructions: bytes, trailer: bytes = b"") -> bytes:
    """Reassemble a blob, keeping the trailer verbatim."""
    return instructions + trailer


# ---------------------------------------------------------------------------
# text .config -> instructions
# ---------------------------------------------------------------------------
def swap32(value: int) -> int:
    """Reverse the 4 bytes of a 32-bit value.

    This mirrors CBoot_recoveryDlg::swap(PAD, PAD) recovered from
    boot_recoveryDlg.obj section 103 (24 bytes, __stdcall / ret 8):

        mov eax,[esp+4]      ; src
        mov ecx,[esp+8]      ; dst
        mov dl,[eax+3] ; mov [ecx+0],dl
        mov dl,[eax+2] ; mov [ecx+1],dl
        mov dl,[eax+1] ; mov [ecx+2],dl
        mov al,[eax+0] ; mov [ecx+3],al
        ret 8

    i.e. dst = byteswap(src). It is a pure endianness helper (the UART path
    needs big-endian words); it is NOT used by the .config converter.
    """
    return int.from_bytes(value.to_bytes(4, "little"), "big")


def parse_config(text: str) -> list[tuple]:
    """Parse the textual .config format accepted by FUN_00404810.

    Line format (whitespace/comma separated):
        w <addr> <value>
        p <addr> <a> <b>
        n <value>
        m <addr> <a> <b> [ <or> ]
    Blank lines, lines starting with '#' or '/' and trailing comments are skipped.
    Hex values may carry a 0x prefix (the original accepts upper and lower case).
    """
    ops: list[tuple] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#/":
            continue
        # strip trailing comments starting with # or /
        for c in ("#", "/"):
            p = line.find(c)
            if p > 0:
                line = line[:p].strip()
        if not line:
            continue
        toks = [t for t in _split(line) if t]
        if not toks:
            continue
        kind = toks[0]
        if kind == "w" and len(toks) >= 3:
            ops.append(("write", _num(toks[1]), _num(toks[2])))
        elif kind == "p" and len(toks) >= 4:
            ops.append(("poll", _num(toks[1]), _num(toks[2]), _num(toks[3])))
        elif kind == "n" and len(toks) >= 2:
            ops.append(("nop", _num(toks[1])))
        elif kind == "m" and len(toks) >= 4:
            addr = _num(toks[1])
            if len(toks) >= 5 and not toks[4].startswith("/"):
                addr = _num(toks[4])   # the optional trailing <or> overrides
            ops.append(("mask", addr, _num(toks[2]), _num(toks[3])))
        else:
            raise ValueError(f"unrecognised line: {raw!r}")
    return ops


def _split(line: str) -> list[str]:
    out, cur = [], []
    for ch in line:
        if ch in SEPARATORS:
            if cur:
                out.append("".join(cur))
                cur = []
        else:
            cur.append(ch)
    if cur:
        out.append("".join(cur))
    return out


def _num(tok: str) -> int:
    t = tok.strip()
    if t.lower().startswith("0x"):
        return int(t, 16)
    # the original's atoh() accepts bare hex too
    try:
        return int(t, 16)
    except ValueError:
        return int(t, 0)


# ---------------------------------------------------------------------------
# pretty printer
# ---------------------------------------------------------------------------
def format_ops(ops: list[tuple]) -> str:
    lines = []
    for o in ops:
        if o[0] == "write":
            lines.append(f"write  0x{o[1]:08X} = 0x{o[2]:08X}")
        elif o[0] == "poll":
            lines.append(f"poll   (0x{o[1]:08X} & 0x{o[2]:08X}) == 0x{o[3]:08X}")
        elif o[0] == "mask":
            lines.append(f"mask   (0x{o[2]:08X} & 0x{o[3]:08X}) | 0x{o[1]:08X}")
        elif o[0] == "nop":
            lines.append(f"nop    0x{o[1]:X}")
        elif o[0] == "end":
            lines.append("end")
    return "\n".join(lines)


def to_config_text(ops: list[tuple]) -> str:
    """Emit the textual .config form (reverse of parse_config)."""
    lines = []
    for o in ops:
        if o[0] == "write":
            lines.append(f"w 0x{o[1]:08x} 0x{o[2]:08x}")
        elif o[0] == "poll":
            lines.append(f"p 0x{o[1]:08x} 0x{o[2]:08x} 0x{o[3]:08x}")
        elif o[0] == "mask":
            lines.append(f"m 0x{o[1]:08x} 0x{o[2]:08x} 0x{o[3]:08x}")
        elif o[0] == "nop":
            lines.append(f"n 0x{o[1]:x}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _load_any(path: str) -> bytes:
    raw = open(path, "rb").read()
    # Try a plain (already decrypted) stream first; if it decodes cleanly, use it.
    try:
        ops = decode_stream(raw)
        if ops and ops[-1][0] == "end":
            print(f"# {path}: treated as PLAINTEXT stream")
            return raw
    except Exception:
        pass
    pt = aes_ecb_decrypt(raw)
    print(f"# {path}: AES-128-ECB decrypted ({len(raw)} -> {len(pt)} bytes)")
    return pt


def cmd_decode(path: str) -> int:
    pt = _load_any(path)
    instr, trailer = split_blob(pt)
    ops = decode_stream(instr)
    print(format_ops(ops))
    print(f"\n# instructions: {len(ops)}  ({len(instr)} bytes incl. terminator)")
    if trailer:
        print(f"# trailer: {len(trailer)} bytes")
        print(f"#   header : {trailer[:16].hex()}")
        mid = trailer[TRAILER_HEADER_LEN:len(trailer) - TRAILER_SIG_LEN]
        if mid:
            nz = sum(1 for b in mid if b)
            print(f"#   middle : {len(mid)} bytes, {nz} non-zero -> {mid.hex()}")
        print(f"#   sig    : {trailer[-32:].hex()}")
    return 0


def cmd_roundtrip(path: str) -> int:
    pt = _load_any(path)
    instr, trailer = split_blob(pt)
    ops = decode_stream(instr)
    # rebuild from the textual form to prove the grammar is lossless
    txt = to_config_text(ops)
    ops2 = parse_config(txt)
    rebuilt = join_blob(encode_stream(ops2), trailer)
    same = rebuilt == pt
    print(f"# roundtrip {'OK' if same else 'MISMATCH'}  "
          f"orig={len(pt)} rebuilt={len(rebuilt)} "
          f"(instructions={len(instr)} trailer={len(trailer)})")
    # and prove the AES layer is a true bijection
    from Crypto.Cipher import AES
    raw = open(path, "rb").read()
    if AES.new(AES_KEY_USB, AES.MODE_ECB).encrypt(pt) == raw:
        print("# AES-128-ECB encrypt(decrypt(x)) == x  -> mode confirmed")
    return 0 if same else 1


def cmd_encode(inp: str, outp: str, encrypt: bool) -> int:
    ops = parse_config(open(inp, "r", errors="replace").read())
    blob = encode_stream(ops)
    if encrypt:
        blob = aes_ecb_encrypt(blob)
    open(outp, "wb").write(blob)
    print(f"# wrote {outp}: {len(ops)} ops -> {len(blob)} bytes"
          f"{' (AES-ECB encrypted)' if encrypt else ''}")
    return 0


def _selftest() -> int:
    import os
    base = "/mnt/c/Users/xiaoa/Desktop/w2_android_usb_download_tool/Tempfile"
    files = [
        "usb_hwsetting.bin",
        "kylin_usb_hwsetting_2DDR3_4Gb_1600_B.bin",
        "kylin_usb_hwsetting_2DDR4_4Gb_1600_B.bin",
    ]
    expect = {
        "usb_hwsetting.bin": {"write": 128, "nop": 12, "mask": 0, "poll": 0, "end": 1},
        "kylin_usb_hwsetting_2DDR3_4Gb_1600_B.bin": {"write": 165, "nop": 2, "mask": 13, "poll": 3, "end": 1},
        "kylin_usb_hwsetting_2DDR4_4Gb_1600_B.bin": {"write": 177, "nop": 3, "mask": 21, "poll": 6, "end": 1},
    }
    # swap32 matches the recovered CBoot_recoveryDlg::swap (4-byte reversal)
    assert swap32(0x11223344) == 0x44332211
    assert swap32(0x000000FF) == 0xFF000000
    assert swap32(swap32(0xDEADBEEF)) == 0xDEADBEEF

    # '=' is not a separator: a key=value line must be rejected, not silently parsed
    try:
        parse_config("addr=0x1801a010")
        raise AssertionError("parse_config accepted a key=value line")
    except ValueError:
        pass

    from collections import Counter
    rc = 0
    for f in files:
        p = os.path.join(base, f)
        if not os.path.exists(p):
            print(f"SKIP {f} (not found)")
            continue
        pt = aes_ecb_decrypt(open(p, "rb").read())
        ops = decode_stream(pt)
        c = Counter(o[0] for o in ops)
        got = {k: c.get(k, 0) for k in ("write", "nop", "mask", "poll", "end")}
        ok = all(got[k] == expect[f][k] for k in expect[f])
        # lossless roundtrip through the text form
        rebuilt = encode_stream(parse_config(to_config_text(ops)))
        rt = rebuilt == pt[:len(rebuilt)]
        print(f"{'PASS' if ok and rt else 'FAIL'} {f}: {got}  roundtrip={rt}")
        if not (ok and rt):
            rc = 1
    return rc


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    cmd = argv[1]
    if cmd == "decode" and len(argv) == 3:
        return cmd_decode(argv[2])
    if cmd == "roundtrip" and len(argv) == 3:
        return cmd_roundtrip(argv[2])
    if cmd == "encode" and len(argv) >= 4:
        return cmd_encode(argv[2], argv[3], "--encrypt" in argv)
    if cmd == "selftest":
        return _selftest()
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
