#!/usr/bin/env python3
"""
atoh_behaviour.py -- empirically pin down CBoot_recoveryDlg::atoh by EMULATING it.

The function is only 0x62 bytes at 0x00404D60 in boot_recovery.exe, and its bytes
are byte-identical to boot_recoveryDlg.obj section 107, so the emulated code is
exactly the shipped parser.

We map a scratch page for the input string and a scratch stack, set EAX/EDX to
poison values, and read EAX after `ret` for each probe input. This settles every
boundary question that static reading only suggests:
  * does it accept a leading 0x / 0X?
  * what stops the scan?
  * what does it return for an empty string or an invalid first char?
  * how does overflow behave?
  * is a stray 0x in the middle accepted?
"""
from __future__ import annotations

import struct
import sys

from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX,
    UC_X86_REG_ESI, UC_X86_REG_ESP, UC_X86_REG_EBP,
)

EXE = "/home/xiaoabiao/rev/br/boot_recovery.exe"  # or point at Desktop/key/boot_recovery.exe
ATOH_VA = 0x00404D60
ATOH_LEN = 0x62

# scratch memory layout
CODE = 0x00400000          # where we place the copied function
RETPAGE = 0x00DEA000       # mapped page the function returns to
STRBUF = 0x00200000        # input string page
STACK = 0x00300000         # stack


def load_atoh() -> bytes:
    """Extract the exact function bytes from the PE."""
    d = open(EXE, "rb").read()
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    nsec = struct.unpack_from("<H", d, pe + 6)[0]
    optsz = struct.unpack_from("<H", d, pe + 20)[0]
    so = pe + 24 + optsz
    base = struct.unpack_from("<I", d, pe + 24 + 28)[0]
    for i in range(nsec):
        o = so + i * 40
        nm = d[o:o + 8].rstrip(b"\0").decode("latin1")
        vs, va, rs, ra = struct.unpack_from("<IIII", d, o + 8)
        if nm == ".text":
            off = ra + (ATOH_VA - base - va)
            return d[off:off + ATOH_LEN]
    raise RuntimeError(".text not found")


def run_atoh(text: bytes, str_base: int = STRBUF) -> tuple[int, int, bytes]:
    """Emulate atoh(text). Returns (eax, ecx, remaining_bytes_after_scan)."""
    code = load_atoh()
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    for base, size in ((CODE, 0x1000), (STACK, 0x1000), (RETPAGE, 0x1000)):
        mu.mem_map(base, size)
    mu.mem_map(str_base, 0x1000)

    mu.mem_write(CODE, code)
    mu.mem_write(str_base, text + b"\0" * (0x1000 - len(text)))

    # stack: [esp] = return address, [esp+4] = arg
    sp = STACK + 0x800
    ret_magic = RETPAGE          # mapped, so `ret` lands somewhere legal
    mu.mem_write(RETPAGE, b"\xeb\xfe")   # jmp $
    mu.mem_write(sp, struct.pack("<II", ret_magic, str_base))
    mu.reg_write(UC_X86_REG_ESP, sp)
    # poison the caller-saved registers the prologue does NOT initialise
    mu.reg_write(UC_X86_REG_EAX, 0xAAAAAAAA)
    mu.reg_write(UC_X86_REG_EDX, 0xDDDDDDDD)
    mu.reg_write(UC_X86_REG_ECX, 0xCCCCCCCC)
    mu.reg_write(UC_X86_REG_EBP, STACK + 0x900)

    stopped = {"hit": False}

    def on_code(mu_, addr, size, _):
        if addr == ret_magic:
            stopped["hit"] = True
            mu_.emu_stop()

    mu.hook_add(UC_HOOK_CODE, on_code)
    mu.emu_start(CODE, CODE + ATOH_LEN)
    if not stopped["hit"]:
        raise RuntimeError(f"function did not return for input {text!r}")

    eax = mu.reg_read(UC_X86_REG_EAX)
    ecx = mu.reg_read(UC_X86_REG_ECX)
    # how far did ESI advance? ESI is not restored by this function, so we can
    # read it as the scan end pointer.
    esi = mu.reg_read(UC_X86_REG_ESI)
    consumed = esi - str_base
    return eax, ecx, total_mem(mu)


def total_mem(mu):
    return b""


PROBES = [
    # (input, note)
    (b"0", "single digit"),
    (b"1", "single digit"),
    (b"f", "lowercase a-f"),
    (b"F", "uppercase A-F"),
    (b"a", "lowercase a"),
    (b"10", "two digits"),
    (b"ff", "0xff"),
    (b"FF", "0xFF"),
    (b"0x10", "0x prefix"),
    (b"0X10", "0X prefix"),
    (b"0x", "bare 0x"),
    (b"0X", "bare 0X"),
    (b"0x0", "0x0"),
    (b"0xFFFFFFFF", "0xFFFFFFFF"),
    (b"FFFFFFFF", "FFFFFFFF no prefix"),
    (b"0x100000000", "overflow past 32 bits"),
    (b"123456789", "9 digits"),
    (b"12345678", "8 digits"),
    (b"1234567", "7 digits"),
    (b"", "empty string"),
    (b"g", "invalid first char"),
    (b"z", "invalid first char"),
    (b"x10", "leading x"),
    (b"X10", "leading X"),
    (b"0x1801a010", "real address"),
    (b"0x1f", "real value"),
    (b"1801a010", "real address no prefix"),
    (b"0xzz", "0x then invalid"),
    (b"0xz", "0x then single invalid"),
    (b"0xg", "0x then g"),
    (b"12g", "valid then invalid"),
    (b"12g34", "valid then invalid then valid"),
    (b"0x12g", "0x prefix then valid then invalid"),
    (b"0x12G34", "0x prefix then invalid uppercase"),
    (b" 1f", "leading space"),
    (b"1f ", "trailing space"),
    (b"0x0x10", "double 0x"),
    (b"1x2", "x in the middle"),
    (b"0xABCdef", "mixed case with prefix"),
    (b"0Xabcdef", "0X mixed case"),
    (b"-1", "negative sign"),
    (b"+1", "plus sign"),
    (b"0b101", "binary-looking"),
    (b"010", "leading zero octal-looking"),
]


def main() -> int:
    code = load_atoh()
    print(f"atoh extracted from {EXE}: {len(code)} bytes")
    print(f"  {code.hex()}")
    print()
    print(f"{'input':>16} | {'EAX result':>12} | {'parsed as':>12} | note")
    print("-" * 78)
    for text, note in PROBES:
        try:
            eax, ecx, _ = run_atoh(text)
        except Exception as e:
            print(f"{text!r:>16} | {'EMU ERROR':>12} | {'':>12} | {e}")
            continue
        shown = f"{eax:#010x}"
        dec = str(eax) if eax < 10**9 else f"{eax:#x}"
        print(f"{text.decode('latin1')!r:>16} | {shown:>12} | {dec:>12} | {note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
