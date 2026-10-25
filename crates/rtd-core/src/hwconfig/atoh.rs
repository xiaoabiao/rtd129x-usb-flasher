//! Bit-exact port of `CBoot_recoveryDlg::atoh`.
//!
//! Recovered from `boot_recovery.exe` at `0x00404D60` (98 bytes), whose bytes
//! are identical to `boot_recoveryDlg.obj` section 107. The original
//! disassembly:
//!
//! ```text
//! 00404D60  push esi
//! 00404D61  mov  esi,[esp+8]     ; p
//! 00404D65  xor  eax,eax         ; result = 0
//! 00404D67  mov  cl,[esi]
//! 00404D69  inc  esi
//! 00404D6A  test cl,cl
//! 00404D6C  je   404DC0           ; empty -> 0
//! 00404D6E  mov  edx,[esp+8]     ; edx = ORIGINAL POINTER (set once!)
//! 00404D72  cmp  cl,'0'          ; ---- loop ----
//! ...
//! 00404DB2  xor  eax,eax         ; 'x'/'X' clears eax but NOT edx
//! 00404DB4  mov  cl,[esi]        ; ---- commit ----
//! 00404DB6  shl  eax,4
//! 00404DB9  add  eax,edx
//! 00404DBB  inc  esi
//! 00404DBC  test cl,cl
//! 00404DBE  jne  404D72
//! 00404DC0  pop  esi
//! 00404DC1  ret
//! ```
//!
//! Behaviour was pinned down by emulating those exact bytes with Unicorn across
//! 444 inputs (44 hand-picked + 400 randomised); the model in
//! `w2_reverse/spec/atoh_reference.py` matches the emulator on all of them.
//!
//! # Summary of the behaviour
//!
//! * accepts an optional `0x` / `0X` prefix (accidentally, see [`atoh`])
//! * accepts bare hex with no prefix
//! * digits `0-9`, `a-f`, `A-F`
//! * **stops at the first character that is not one of the above or `x`/`X`**,
//!   returning whatever was accumulated so far
//! * no leading-whitespace skipping, no sign handling
//! * silent 32-bit wraparound on overflow
//! * **no error signalling at all** -- the caller cannot distinguish
//!   "parsed to 0" from "parse failed"

/// Parse a NUL-terminated-ish hex token the way the original tool does.
///
/// The slice should contain the token; a NUL terminator is optional.
///
/// # The `x`/`X` quirk
///
/// The original initialises `edx` to the **string pointer** once, outside the
/// loop, and the `'x'` branch clears `eax` without touching `edx`. So:
///
/// * `"0x10"` is safe: the leading `'0'` sets `edx = 0` first, so when `'x'`
///   clears `eax` the following `add eax,edx` adds nothing.
/// * `"x10"` is **not** safe: `edx` is still the pointer, so the result becomes
///   pointer-derived garbage (`(pointer << 4) + 0x10`).
///
/// This function reproduces that faithfully when `pointer` is supplied. Pass
/// `pointer: None` (the default) to model the safe, pointer-independent case,
/// which is what you want when parsing real `.config` files.
///
/// The bug is self-healing, but **how soon depends on the base address**: the
/// pointer contribution is shifted left 4 bits per subsequent character, so it
/// is pushed out of 32 bits after roughly `ceil(log16(2^32 / base))` digits.
/// Concretely, for bases up to 0x7f0000 the result stops varying after 5 hex
/// digits. Real addresses are 8 hex digits, which is why the bug never showed
/// up in the shipped files.
///
/// # Examples
///
/// ```
/// use rtd_core::hwconfig::atoh::atoh;
///
/// // standard forms
/// assert_eq!(atoh(b"0x1801a010"), 0x1801a010);
/// assert_eq!(atoh(b"1801a010"), 0x1801a010);
/// assert_eq!(atoh(b"0X1801A010"), 0x1801a010);
/// assert_eq!(atoh(b"0x1f"), 0x1f);
///
/// // silently truncates at the first bad character
/// assert_eq!(atoh(b"0x1801g010"), 0x1801);
/// assert_eq!(atoh(b"12g34"), 0x12);
///
/// // no error signalling: bad input yields 0
/// assert_eq!(atoh(b"0xzz"), 0);
/// assert_eq!(atoh(b" 1f"), 0);      // leading space is not skipped
/// assert_eq!(atoh(b"-1"), 0);
/// assert_eq!(atoh(b""), 0);
///
/// // hex only: 0b101 is 0xB101, and 010 is 16
/// assert_eq!(atoh(b"0b101"), 0xb101);
/// assert_eq!(atoh(b"010"), 0x10);
///
/// // silent wraparound
/// assert_eq!(atoh(b"0x1FFFFFFFF"), 0xffffffff);
/// assert_eq!(atoh(b"0x100000000"), 0);
/// ```
pub fn atoh(token: &[u8]) -> u32 {
    atoh_with_pointer(token, 0)
}

/// [`atoh`] with an explicit string base address, to reproduce the leading-x
/// pointer-leak bug.
pub fn atoh_with_pointer(token: &[u8], pointer: u32) -> u32 {
    // 00404D6A: an empty string returns 0 immediately.
    if token.is_empty() {
        return 0;
    }

    let mut eax: u32 = 0; // xor eax,eax
    let mut edx: u32 = pointer; // mov edx,[esp+8]  -- outside the loop
    let mut i = 1usize;
    let mut c = token[0];

    loop {
        if c.is_ascii_digit() {
            edx = u32::from(c - b'0');
        } else if (b'a'..=b'f').contains(&c) {
            edx = u32::from(c) - 0x57;
        } else if (b'A'..=b'F').contains(&c) {
            edx = u32::from(c) - 0x37;
        } else if c == b'x' || c == b'X' {
            // 00404DB2: clears the accumulator but deliberately not edx.
            eax = 0;
        } else {
            // 00404DC0: stop and return what we have.
            return eax;
        }

        // 00404DB4 commit step.
        let next = token.get(i).copied().unwrap_or(0);
        eax = eax.wrapping_shl(4).wrapping_add(edx);
        i += 1;
        if next == 0 {
            return eax;
        }
        c = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 44 hand-picked cases from the Unicorn verification run, with the
    /// values the emulated original produced.
    ///
    /// `w2_reverse/spec/atoh_reference.py` asserts the same table against the
    /// real bytes, so this port is transitively verified.
    const GOLDEN: &[(&[u8], u32)] = &[
        (b"0", 0x0),
        (b"1", 0x1),
        (b"f", 0xf),
        (b"F", 0xf),
        (b"a", 0xa),
        (b"10", 0x10),
        (b"ff", 0xff),
        (b"FF", 0xff),
        (b"0x10", 0x10),
        (b"0X10", 0x10),
        (b"0x", 0x0),
        (b"0X", 0x0),
        (b"0x0", 0x0),
        (b"0xFFFFFFFF", 0xffff_ffff),
        (b"FFFFFFFF", 0xffff_ffff),
        (b"0x100000000", 0x0),
        (b"123456789", 0x2345_6789),
        (b"12345678", 0x1234_5678),
        (b"1234567", 0x0123_4567),
        (b"", 0x0),
        (b"g", 0x0),
        (b"z", 0x0),
        (b"0x1801a010", 0x1801_a010),
        (b"0x1f", 0x1f),
        (b"1801a010", 0x1801_a010),
        (b"0xzz", 0x0),
        (b"0xz", 0x0),
        (b"0xg", 0x0),
        (b"12g", 0x12),
        (b"12g34", 0x12),
        (b"0x12g", 0x12),
        (b"0x12G34", 0x12),
        (b" 1f", 0x0),
        (b"1f ", 0x1f),
        (b"0x0x10", 0x10),
        (b"1x2", 0x12),
        (b"0xABCdef", 0x00ab_cdef),
        (b"0Xabcdef", 0x00ab_cdef),
        (b"-1", 0x0),
        (b"+1", 0x0),
        (b"0b101", 0xb101),
        (b"010", 0x10),
        (b"0x1FFFFFFFF", 0xffff_ffff),
        (b"1x2", 0x12),
    ];

    #[test]
    fn matches_the_emulated_original_on_all_golden_cases() {
        for (input, want) in GOLDEN {
            let got = atoh(input);
            assert_eq!(
                got,
                *want,
                "atoh({:?}) = {:#x}, expected {:#x}",
                String::from_utf8_lossy(input),
                got,
                want
            );
        }
    }

    #[test]
    fn pointer_leak_bug_reproduces() {
        // Leading 'x' with no preceding '0' leaks the pointer.
        assert_eq!(atoh_with_pointer(b"x10", 0x20_0000), 0x2000_0010);
        assert_eq!(atoh_with_pointer(b"x10", 0x40_0000), 0x4000_0010);
        assert_eq!(atoh_with_pointer(b"x10", 0x55_5000), 0x5550_0010);
        // Self-healing: the base contribution is shifted out of 32 bits, but
        // the number of digits needed depends on how large the base is.
        // For a 0x555000 base, 4 digits are not yet enough. Worked through:
        //   x -> eax = 0x555000
        //   1 -> 0x5550001, 1 -> 0x55500011, 1 -> 0x55000111 (32-bit wrap),
        //   1 -> (0x55000111 << 4) + 1 = 0x50001111
        assert_eq!(atoh_with_pointer(b"x1111", 0x55_5000), 0x5000_1111);
        // ...but 5 are, and every larger base also settles by 5.
        for base in [0x20_0000u32, 0x40_0000, 0x55_5000, 0x7f_0000] {
            assert_eq!(atoh_with_pointer(b"x11111", base), 0x1_1111, "base {base:#x}");
        }

        // The important practical consequence: an 8-hex-digit input (a real
        // address) is base-independent -- the pointer is shifted out entirely.
        let eight_digits = b"x1801a010";
        let as_plain = atoh(b"1801a010"); // 0x1801a010
        for base in [0u32, 0x20_0000, 0x55_5000, 0x7f_0000, 0xFF00_0000] {
            assert_eq!(
                atoh_with_pointer(eight_digits, base),
                as_plain,
                "8-digit input must be base-independent (base {base:#x})"
            );
        }
    }

    #[test]
    fn zero_prefix_is_immunised_against_the_bug() {
        // '0' sets edx=0 before 'x' clears eax, so any pointer works.
        for base in [0u32, 0x20_0000, 0x7f_0000] {
            assert_eq!(atoh_with_pointer(b"0x10", base), 0x10);
        }
    }

    #[test]
    fn overflow_wraps_silently() {
        // Each step is eax = eax*16 + digit, wrapping.
        assert_eq!(atoh(b"FFFFFFFF"), 0xffff_ffff);
        assert_eq!(atoh(b"100000000"), 0); // 2^32
        assert_eq!(atoh(b"100000001"), 1);
    }

    #[test]
    fn stops_at_the_first_non_hex() {
        assert_eq!(atoh(b"1fZZ99"), 0x1f);
        assert_eq!(atoh(b"1f\t99"), 0x1f); // tab stops it
        assert_eq!(atoh(b"1f\n99"), 0x1f);
        assert_eq!(atoh(b"1f,99"), 0x1f);
        assert_eq!(atoh(b"1f 99"), 0x1f);
    }

    #[test]
    fn is_case_insensitive_and_prefix_tolerant() {
        for s in [
            &b"0xabcdef"[..],
            b"0XABCDEF",
            b"ABCDEF",
            b"abcdef",
            b"AbCdEf",
            b"0xAbCdEf",
        ] {
            assert_eq!(atoh(s), 0x00ab_cdef, "{:?}", String::from_utf8_lossy(s));
        }
    }

    #[test]
    fn byte_variant_consistent_with_slice_variant() {
        for (input, want) in GOLDEN {
            let mut with_nul = input.to_vec();
            with_nul.push(0);
            assert_eq!(atoh(&with_nul), *want, "trailing NUL must not matter");
        }
    }
}
