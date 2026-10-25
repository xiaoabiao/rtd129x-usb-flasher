#!/usr/bin/env python3
"""
atoh_reference.py -- exact reference implementation of CBoot_recoveryDlg::atoh,
recovered from boot_recovery.exe @0x00404D60 (98 bytes, byte-identical to
boot_recoveryDlg.obj section 107).

The disassembly is:

    00404D60  push esi
    00404D61  mov  esi, [esp+8]      ; esi = p
    00404D65  xor  eax, eax          ; result = 0
    00404D67  mov  cl, [esi]         ; cl = *p
    00404D69  inc  esi               ; p++
    00404D6A  test cl, cl
    00404D6C  je   404DC0            ; empty string -> return 0
    00404D6E  mov  edx, [esp+8]      ; edx = ORIGINAL pointer  (set once!)
    00404D72  cmp  cl, '0'           ; ---- loop head ----
    00404D75  jl   404D84
    00404D77  cmp  cl, '9'
    00404D7A  jg   404D84
    00404D7C  movsx edx, cl          ; decimal digit
    00404D7F  sub  edx, 0x30
    00404D82  jmp  404DB4
    00404D84  cmp  cl, 'a'
    00404D87  jl   404D96
    00404D89  cmp  cl, 'f'
    00404D8C  jg   404D96
    00404D8E  movsx edx, cl          ; lowercase hex
    00404D91  sub  edx, 0x57         ; 'a'-10
    00404D94  jmp  404DB4
    00404D96  cmp  cl, 'A'
    00404D99  jl   404DA8
    00404D9B  cmp  cl, 'F'
    00404D9E  jg   404DA8
    00404DA0  movsx edx, cl          ; uppercase hex
    00404DA3  sub  edx, 0x37         ; 'A'-10
    00404DA6  jmp  404DB4
    00404DA8  cmp  cl, 'X'
    00404DAB  je   404DB2
    00404DAD  cmp  cl, 'x'
    00404DB0  jne  404DC0            ; anything else -> stop, return result
    00404DB2  xor  eax, eax          ; <-- 'x'/'X' clears the accumulator
    00404DB4  mov  cl, [esi]         ; ---- commit ----
    00404DB6  shl  eax, 4
    00404DB9  add  eax, edx
    00404DBB  inc  esi
    00404DBC  test cl, cl
    00404DBE  jne  404D72            ; next char
    00404DC0  pop  esi
    00404DC1  ret

Key consequences, all confirmed against a Unicorn emulation of the real bytes:

1. Accepts an optional leading "0x"/"0X" -- but only ACCIDENTALLY.  The '0' digit
   sets edx = 0, then the 'x' branch does `xor eax,eax` and `add eax,edx` with
   edx still 0, so the accumulator is zeroed harmlessly and parsing continues.

2. If the string STARTS with 'x' or 'X' (no leading '0'), edx still holds the
   ORIGINAL POINTER, so the return value becomes pointer-derived garbage.  This
   is a genuine bug; the result depends on where the string lives in memory.

3. Scanning stops at the first character that is not [0-9a-fA-FxX] and returns
   whatever was accumulated so far.  Trailing garbage is silently ignored, and
   the caller is NOT told how many characters were consumed.

4. No whitespace skipping: a leading space returns 0 (stops immediately).

5. No sign handling: '-' and '+' both stop the scan and return 0.

6. Overflow is silent wraparound on 32 bits (each step is `eax = eax*16 + d`).

7. "0b101" is NOT binary: 'b' is a valid hex digit, so it parses as 0x0B101.

8. A bare "0x" returns 0.  "0x0x10" returns 0x10 (the second 'x' clears eax,
   then "10" is accumulated, and since edx==0 by then it stays clean).
"""

from __future__ import annotations


def atoh(text: bytes, pointer: int = 0x00200000) -> int:
    """Bit-exact reference model of CBoot_recoveryDlg::atoh.

    `pointer` is the address the string lives at; it only matters for the
    leading-'x' bug, but we take it so the model can reproduce that case too.
    """
    if isinstance(text, str):
        text = text.encode("latin1")

    # 00404D67..00404D6C: empty string short-circuit
    if not text or text[0] == 0:
        return 0

    eax = 0                  # xor eax,eax
    edx = pointer            # mov edx,[esp+8]   <-- only set ONCE
    i = 1                    # cl already loaded, esi already advanced
    c = text[0]

    while True:
        if 0x30 <= c <= 0x39:            # '0'..'9'
            edx = c - 0x30
        elif 0x61 <= c <= 0x66:          # 'a'..'f'
            edx = c - 0x57
        elif 0x41 <= c <= 0x46:          # 'A'..'F'
            edx = c - 0x37
        elif c in (0x58, 0x78):          # 'X' or 'x'
            eax = 0                      # 00404DB2  (does NOT touch edx)
        else:
            return eax & 0xFFFFFFFF      # 00404DC0

        # 00404DB4 commit
        if i >= len(text):
            nxt = 0
        else:
            nxt = text[i]
        eax = (eax << 4) & 0xFFFFFFFF
        eax = (eax + edx) & 0xFFFFFFFF
        i += 1
        if nxt == 0:
            return eax
        c = nxt


# ---------------------------------------------------------------------------
# self-test: compare the model against the real emulated bytes
# ---------------------------------------------------------------------------
def _selftest() -> int:
    import itertools
    import random
    import sys

    import os
    here = os.path.dirname(os.path.abspath(__file__))
    for cand in (here, "/home/xiaoabiao/rev/work"):
        if os.path.exists(os.path.join(cand, "atoh_behaviour.py")):
            sys.path.insert(0, cand)
            break
    try:
        from atoh_behaviour import run_atoh, STRBUF
    except Exception as e:
        print(f"SKIP: cannot import the Unicorn harness ({e})")
        return 0

    probes = [
        b"0", b"1", b"f", b"F", b"a", b"10", b"ff", b"FF",
        b"0x10", b"0X10", b"0x", b"0X", b"0x0", b"0xFFFFFFFF", b"FFFFFFFF",
        b"0x100000000", b"123456789", b"12345678", b"1234567", b"",
        b"g", b"z", b"x10", b"X10", b"0x1801a010", b"0x1f", b"1801a010",
        b"0xzz", b"0xz", b"0xg", b"12g", b"12g34", b"0x12g", b"0x12G34",
        b" 1f", b"1f ", b"0x0x10", b"1x2", b"0xABCdef", b"0Xabcdef",
        b"-1", b"+1", b"0b101", b"010",
    ]
    # plus randomised coverage
    alphabet = b"0123456789abcdefABCDEFxXgz -=+"
    rng = random.Random(0xC0FFEE)
    for _ in range(400):
        n = rng.randint(0, 12)
        probes.append(bytes(rng.choice(alphabet) for _ in range(n)))

    bad = 0
    for t in probes:
        want = run_atoh(t)[0]
        got = atoh(t, STRBUF)
        if want != got:
            bad += 1
            if bad <= 10:
                print(f"MISMATCH {t!r}: emulated={want:#010x} model={got:#010x}")
    total = len(probes)
    print(f"atoh model vs Unicorn emulation: {total - bad}/{total} inputs agree")
    if bad:
        print(f"FAIL ({bad} mismatches)")
        return 1
    print("PASS -- reference model is bit-exact on all probes")
    return 0


if __name__ == "__main__":
    raise SystemExit(_selftest())
