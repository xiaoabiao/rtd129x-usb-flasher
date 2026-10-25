//! The hwsetting instruction stream: `w` / `p` / `n` / `m` ops.
//!
//! Recovered from `FUN_00404810` in `boot_recovery.exe`, which reads a text
//! `.config` with mode `"rt"`, tokenises with the separator set `b" ,"`
//! (`DAT_00435B10`), and writes a binary stream with mode `"wb"`.
//!
//! Every field is a **little-endian u32**, written byte-by-byte from LSB to MSB
//! by `FUN_00404DD0`:
//!
//! ```text
//! for (i = 0; i != 0x20; i += 8) putc((v >> i) & 0xff)
//! ```
//!
//! # Grammar
//!
//! | mnemonic | text | emits | meaning |
//! |---|---|---|---|
//! | `w` | `w <addr> <value>` | `addr, value` | register write |
//! | `p` | `p <addr> <a> <b>` | `addr\|1, a, b` | poll until `(read & a) == b` |
//! | `n` | `n <value>` | `3, value` | nop / delay |
//! | `m` | `m <addr> <a> <b> [<or>]` | `addr\|2, a, b` | read-modify-write |
//! | — | end of file | `0xFFFFFFFF` | terminator |
//!
//! The **low 2 bits of the first word select the operation**, which is why the
//! addresses of `p` and `m` are OR-ed:
//!
//! ```text
//! first == 0xFFFFFFFF -> end
//! first == 3          -> nop  (2 words)
//! first & 2           -> mask (3 words)
//! first & 1           -> poll (3 words)
//! else                -> write (2 words)
//! ```
//!
//! The original logs each op as:
//!
//! ```text
//! write: 0x%08x = 0x%08x
//! poll:  0x%08x & 0x%08x = 0x%08x
//! nop:   0x%x
//! mask:  (0x%08x & 0x%08x) | 0x%08x, repeat=%d
//! ```

use crate::error::{Error, Result};

/// Stream terminator.
pub const TERMINATOR: u32 = 0xFFFF_FFFF;

/// Operation-selector bits in the first word.
pub const OP_BIT_POLL: u32 = 0x1;
/// Operation-selector bit for mask ops.
pub const OP_BIT_MASK: u32 = 0x2;
/// The `nop` opcode word.
pub const OP_NOP_WORD: u32 = 0x3;

/// Special address that consumes a trailing repeat count in the original.
pub const MASK_REPEAT_ADDR: u32 = 0xB801_A60C;

/// One hwsetting operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// `w addr value`
    Write {
        /// Register address.
        addr: u32,
        /// Value to write.
        value: u32,
    },
    /// `p addr mask want` — poll until `(read & mask) == want`.
    Poll {
        /// Register address (stored without the selector bit).
        addr: u32,
        /// Mask applied to the read value.
        mask: u32,
        /// Expected result.
        want: u32,
    },
    /// `m addr mask or` — read-modify-write `(read & mask) | or`.
    Mask {
        /// Register address (stored without the selector bit).
        addr: u32,
        /// Mask applied to the read value.
        mask: u32,
        /// Bits to OR in.
        or: u32,
    },
    /// `n value` — a delay / no-op.
    Nop {
        /// Delay parameter.
        value: u32,
    },
}

impl Op {
    /// Append this op's words to `out`.
    pub fn emit(&self, out: &mut Vec<u32>) {
        match *self {
            Op::Write { addr, value } => out.extend_from_slice(&[addr, value]),
            Op::Poll { addr, mask, want } => {
                out.extend_from_slice(&[addr | OP_BIT_POLL, mask, want])
            }
            Op::Mask { addr, mask, or } => out.extend_from_slice(&[addr | OP_BIT_MASK, mask, or]),
            Op::Nop { value } => out.extend_from_slice(&[OP_NOP_WORD, value]),
        }
    }

    /// How many u32 words this op occupies.
    pub fn words(&self) -> usize {
        match self {
            Op::Write { .. } | Op::Nop { .. } => 2,
            Op::Poll { .. } | Op::Mask { .. } => 3,
        }
    }

    /// Render in the original tool's log format.
    pub fn to_log_line(&self) -> String {
        match *self {
            Op::Write { addr, value } => format!("write: 0x{addr:08x} = 0x{value:08x}"),
            Op::Poll { addr, mask, want } => {
                format!("poll: 0x{addr:08x} & 0x{mask:08x} = 0x{want:08x}")
            }
            Op::Mask { addr, mask, or } => {
                format!("mask: (0x{addr:08x} & 0x{mask:08x}) | 0x{or:08x}")
            }
            Op::Nop { value } => format!("nop: 0x{value:x}"),
        }
    }
}

/// Encode a list of ops into the flat little-endian u32 stream, terminated.
pub fn encode(ops: &[Op]) -> Vec<u8> {
    let mut words = Vec::with_capacity(ops.len() * 3 + 1);
    for op in ops {
        op.emit(&mut words);
    }
    words.push(TERMINATOR);
    let mut out = Vec::with_capacity(words.len() * 4);
    for w in words {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out
}

/// Encode without the trailing terminator (used when comparing prefixes).
pub fn encode_unterminated(ops: &[Op]) -> Vec<u8> {
    let mut words = Vec::new();
    for op in ops {
        op.emit(&mut words);
    }
    let mut out = Vec::with_capacity(words.len() * 4);
    for w in words {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out
}

/// Decode a flat u32 stream into ops.
///
/// Stops at the terminator; the terminator itself is not returned. Any bytes
/// after the terminator are ignored (callers that care use
/// [`split_stream`]).
pub fn decode(stream: &[u8]) -> Result<(Vec<Op>, usize)> {
    if stream.len() % 4 != 0 {
        return Err(Error::HwConfig(format!(
            "instruction stream length {} is not a multiple of 4",
            stream.len()
        )));
    }
    let n = stream.len() / 4;
    let mut ops = Vec::new();
    let mut i = 0usize;

    while i < n {
        let a = read_word(stream, i);
        if a == TERMINATOR {
            return Ok((ops, (i + 1) * 4));
        }
        if a == OP_NOP_WORD {
            let v = read_word_checked(stream, i + 1, "nop")?;
            ops.push(Op::Nop { value: v });
            i += 2;
        } else if a & OP_BIT_MASK != 0 {
            let mask = read_word_checked(stream, i + 1, "mask")?;
            let or = read_word_checked(stream, i + 2, "mask")?;
            ops.push(Op::Mask {
                addr: a & !OP_BIT_MASK,
                mask,
                or,
            });
            i += 3;
        } else if a & OP_BIT_POLL != 0 {
            let mask = read_word_checked(stream, i + 1, "poll")?;
            let want = read_word_checked(stream, i + 2, "poll")?;
            ops.push(Op::Poll {
                addr: a & !OP_BIT_POLL,
                mask,
                want,
            });
            i += 3;
        } else {
            let value = read_word_checked(stream, i + 1, "write")?;
            ops.push(Op::Write { addr: a, value });
            i += 2;
        }
    }
    Err(Error::HwConfig(
        "instruction stream has no 0xFFFFFFFF terminator".into(),
    ))
}

/// Split a decoded plaintext blob into `(instructions, trailer)`.
///
/// Every shipped blob carries a trailer after the terminator: a 16-byte header,
/// a small zero-padded field and a 32-byte MAC. The original never writes it
/// (it comes from the firmware build), so we preserve it verbatim.
pub fn split_stream(plain: &[u8]) -> Result<(&[u8], &[u8])> {
    let end = find_terminator_end(plain)?;
    Ok((&plain[..end], &plain[end..]))
}

/// Byte offset just past the terminator.
pub fn find_terminator_end(plain: &[u8]) -> Result<usize> {
    let (_, consumed) = decode(plain)?;
    Ok(consumed)
}

fn read_word(b: &[u8], i: usize) -> u32 {
    let o = i * 4;
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn read_word_checked(b: &[u8], i: usize, what: &str) -> Result<u32> {
    if (i + 1) * 4 > b.len() {
        return Err(Error::HwConfig(format!("truncated {what} op")));
    }
    Ok(read_word(b, i))
}

/// Parse a textual `.config` into ops.
///
/// The tokeniser mirrors `FUN_0040D214` with the separator set `b" ,"`, and the
/// code additionally skips `\0`, `\t`, `\n`, `#` and `/`. The original is
/// **positional**: the first token is the mnemonic, the rest are numbers. There
/// is **no `=` handling anywhere** (a full `.text` scan of the original finds
/// zero `cmp <reg>, 0x3D` instructions), so `key=value` input is an error.
///
/// Numeric fields are parsed with [`super::atoh::atoh`], so they inherit its
/// tolerance: optional `0x`/`0X`, upper or lower case, silent truncation at the
/// first invalid character, and silent 32-bit wraparound.
pub fn parse_config(text: &str) -> Result<Vec<Op>> {
    let mut ops = Vec::new();
    for (lineno, raw) in text.lines().enumerate() {
        let line = strip_comment(raw);
        let line = line.trim_matches(|c: char| c == ' ' || c == ',' || c == '\t');
        if line.is_empty() {
            continue;
        }
        let toks: Vec<&str> = line
            .split([' ', ',', '\t'])
            .filter(|t| !t.is_empty())
            .collect();
        if toks.is_empty() {
            continue;
        }
        let num = |s: &str| super::atoh::atoh(s.as_bytes());
        let need = |n: usize, mn: &str| -> Result<()> {
            if toks.len() < n {
                return Err(Error::HwConfig(format!(
                    "line {}: `{mn}` needs {n} arguments, got {}: {:?}",
                    lineno + 1,
                    toks.len(),
                    raw.trim()
                )));
            }
            Ok(())
        };

        match toks[0] {
            "w" => {
                need(3, "w")?;
                ops.push(Op::Write {
                    addr: num(toks[1]),
                    value: num(toks[2]),
                });
            }
            "p" => {
                need(4, "p")?;
                ops.push(Op::Poll {
                    addr: num(toks[1]),
                    mask: num(toks[2]),
                    want: num(toks[3]),
                });
            }
            "n" => {
                need(2, "n")?;
                ops.push(Op::Nop {
                    value: num(toks[1]),
                });
            }
            "m" => {
                need(4, "m")?;
                // The original consumes an optional trailing token as the OR
                // value when the address is the special repeat marker.
                let addr = num(toks[1]);
                ops.push(Op::Mask {
                    addr,
                    mask: num(toks[2]),
                    or: num(toks[3]),
                });
            }
            other => {
                return Err(Error::HwConfig(format!(
                    "line {}: unknown mnemonic {other:?} (expected w/p/n/m): {:?}",
                    lineno + 1,
                    raw.trim()
                )));
            }
        }
    }
    Ok(ops)
}

/// Render ops back into `w`/`p`/`n`/`m` text.
pub fn to_config_text(ops: &[Op]) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    for op in ops {
        match *op {
            Op::Write { addr, value } => {
                let _ = writeln!(s, "w 0x{addr:08x} 0x{value:08x}");
            }
            Op::Poll { addr, mask, want } => {
                let _ = writeln!(s, "p 0x{addr:08x} 0x{mask:08x} 0x{want:08x}");
            }
            Op::Mask { addr, mask, or } => {
                let _ = writeln!(s, "m 0x{addr:08x} 0x{mask:08x} 0x{or:08x}");
            }
            Op::Nop { value } => {
                let _ = writeln!(s, "n 0x{value:x}");
            }
        }
    }
    s
}

/// Strip a `#` or `/` comment, mirroring the original's line skipping.
fn strip_comment(line: &str) -> &str {
    let mut end = line.len();
    for (i, c) in line.char_indices() {
        if c == '#' || c == '/' {
            end = i;
            break;
        }
    }
    &line[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_op_has_the_right_word_count() {
        assert_eq!(Op::Write { addr: 0, value: 0 }.words(), 2);
        assert_eq!(Op::Nop { value: 0 }.words(), 2);
        assert_eq!(
            Op::Poll {
                addr: 0,
                mask: 0,
                want: 0
            }
            .words(),
            3
        );
        assert_eq!(
            Op::Mask {
                addr: 0,
                mask: 0,
                or: 0
            }
            .words(),
            3
        );
    }

    #[test]
    fn selector_bits_are_or_ed_into_the_address() {
        let poll = Op::Poll {
            addr: 0x9800_E800,
            mask: 0xF,
            want: 0xD,
        };
        let mut w = Vec::new();
        poll.emit(&mut w);
        assert_eq!(w[0] & OP_BIT_POLL, OP_BIT_POLL);
        assert_eq!(w[0] & OP_BIT_MASK, 0, "poll must not set the mask bit");
        assert_eq!(w[0] & !0x3, 0x9800_E800);

        let mask = Op::Mask {
            addr: 0x9800_7030,
            mask: 0xFFFF_FFF3,
            or: 0x8,
        };
        let mut w = Vec::new();
        mask.emit(&mut w);
        assert_eq!(w[0] & OP_BIT_MASK, OP_BIT_MASK);
        assert_eq!(w[0] & !0x3, 0x9800_7030);
    }

    #[test]
    fn nop_word_is_literal_three() {
        let mut w = Vec::new();
        Op::Nop { value: 0x1000 }.emit(&mut w);
        assert_eq!(w, vec![3, 0x1000]);
    }

    #[test]
    fn encode_appends_the_terminator() {
        let blob = encode(&[Op::Write {
            addr: 0x1801_A010,
            value: 0x1F,
        }]);
        assert_eq!(blob.len(), 12);
        assert_eq!(&blob[0..4], &0x1801_A010u32.to_le_bytes());
        assert_eq!(&blob[4..8], &0x1Fu32.to_le_bytes());
        assert_eq!(&blob[8..12], &TERMINATOR.to_le_bytes());
    }

    #[test]
    fn round_trips_through_encode_and_decode() {
        let ops = vec![
            Op::Write {
                addr: 0x1801_A010,
                value: 0x1F,
            },
            Op::Nop { value: 0x1000 },
            Op::Poll {
                addr: 0x9800_E800,
                mask: 0xF,
                want: 0xD,
            },
            Op::Mask {
                addr: 0x9800_7030,
                mask: 0xFFFF_FFF3,
                or: 0x8,
            },
        ];
        let blob = encode(&ops);
        let (got, consumed) = decode(&blob).unwrap();
        assert_eq!(got, ops);
        assert_eq!(consumed, blob.len());
    }

    #[test]
    fn decode_rejects_a_stream_without_a_terminator() {
        let blob = encode_unterminated(&[Op::Write { addr: 1, value: 2 }]);
        assert!(decode(&blob).is_err());
    }

    #[test]
    fn decode_rejects_a_misaligned_stream() {
        assert!(decode(&[0u8; 7]).is_err());
    }

    #[test]
    fn parse_config_reads_all_four_mnemonics() {
        let text = "\
            w 0x1801a010 0x1f\n\
            n 0x1000\n\
            p 0x9800e800 0x0f 0x0d\n\
            m 0x98007030 0xfffffff3 0x08\n";
        let ops = parse_config(text).unwrap();
        assert_eq!(ops.len(), 4);
        assert_eq!(
            ops[0],
            Op::Write {
                addr: 0x1801_a010,
                value: 0x1f
            }
        );
        assert_eq!(ops[1], Op::Nop { value: 0x1000 });
        assert_eq!(
            ops[2],
            Op::Poll {
                addr: 0x9800_e800,
                mask: 0x0f,
                want: 0x0d
            }
        );
        assert_eq!(
            ops[3],
            Op::Mask {
                addr: 0x9800_7030,
                mask: 0xffff_fff3,
                or: 0x08
            }
        );
    }

    #[test]
    fn parse_config_accepts_commas_and_uppercase() {
        let ops = parse_config("w,0X1801A010,0X1F").unwrap();
        assert_eq!(
            ops[0],
            Op::Write {
                addr: 0x1801_a010,
                value: 0x1f
            }
        );
    }

    #[test]
    fn parse_config_skips_blanks_and_comments() {
        let text = "\n# a comment\n/ another\n   \nw 0x1 0x2\n";
        let ops = parse_config(text).unwrap();
        assert_eq!(ops.len(), 1);
    }

    #[test]
    fn parse_config_rejects_key_value_syntax() {
        // The original has no '=' handling at all.
        let err = parse_config("addr=0x1801a010").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown mnemonic"), "{msg}");
    }

    #[test]
    fn parse_config_rejects_unknown_mnemonics() {
        assert!(parse_config("z 0x1 0x2").is_err());
        assert!(parse_config("x 0x1").is_err());
    }

    #[test]
    fn parse_config_rejects_short_argument_lists() {
        assert!(parse_config("w 0x1").is_err());
        assert!(parse_config("p 0x1 0x2").is_err());
        assert!(parse_config("n").is_err());
        assert!(parse_config("m 0x1 0x2").is_err());
    }

    #[test]
    fn text_round_trip_is_lossless() {
        let ops = vec![
            Op::Write {
                addr: 0x1801_a010,
                value: 0x1f,
            },
            Op::Nop { value: 0x1000 },
            Op::Poll {
                addr: 0x9800_e800,
                mask: 0xf,
                want: 0xd,
            },
            Op::Mask {
                addr: 0x9800_7030,
                mask: 0xffff_fff3,
                or: 0x8,
            },
        ];
        let text = to_config_text(&ops);
        let back = parse_config(&text).unwrap();
        assert_eq!(back, ops);
    }

    #[test]
    fn split_stream_separates_the_trailer() {
        // The real trailers are 16-byte aligned, so use an aligned marker here;
        // the splitter itself does not require alignment, but a ragged trailer
        // would not be representative.
        // NOTE: the address must be 4-byte aligned; `addr = 1` would carry the
        // poll selector bit and decode as a poll op (see the module docs).
        let mut blob = encode(&[Op::Write {
            addr: 0x1800_0004,
            value: 2,
        }]);
        let marker = b"TRAILER_16BYTES!"; // 16 bytes
        blob.extend_from_slice(marker);
        let (instr, trailer) = split_stream(&blob).unwrap();
        assert_eq!(instr.len(), 12);
        assert_eq!(trailer, marker);
    }

    #[test]
    fn selector_bits_make_unaligned_addresses_ambiguous() {
        // The selector lives in the address word, so an address with bit0 set
        // is indistinguishable from a poll -- and it also changes how many
        // words the op consumes, shifting every following word. Build the raw
        // streams explicitly so the test states exactly what it means.

        // words: [addr|POLL, mask, want, TERMINATOR]
        // with addr=0 (bit0 came from the selector) this decodes as a poll.
        let mut words: Vec<u32> = vec![0x1, 0x2, 0x3];
        words.push(TERMINATOR);
        let mut raw = Vec::new();
        for w in &words {
            raw.extend_from_slice(&w.to_le_bytes());
        }
        let (ops, _) = decode(&raw).unwrap();
        assert_eq!(
            ops,
            vec![Op::Poll {
                addr: 0,
                mask: 2,
                want: 3
            }],
            "a word with bit0 set decodes as a poll"
        );

        // words: [addr|MASK, mask, or, TERMINATOR]
        let mut words: Vec<u32> = vec![0x2, 0x2, 0x3];
        words.push(TERMINATOR);
        let mut raw = Vec::new();
        for w in &words {
            raw.extend_from_slice(&w.to_le_bytes());
        }
        let (ops, _) = decode(&raw).unwrap();
        assert_eq!(
            ops,
            vec![Op::Mask {
                addr: 0,
                mask: 2,
                or: 3
            }],
            "a word with bit1 set decodes as a mask"
        );

        // Aligned addresses never set either bit, so a write survives intact
        // and the encoding is unambiguous. This is the property the real blobs
        // rely on: all 513 addresses across the three shipped files are
        // 4-byte aligned.
        for addr in [4u32, 0x100, 0x1800_0000, 0x9800_e800, 0x1801_a010] {
            assert_eq!(addr & 0b11, 0, "{addr:#x} should be aligned");
            let blob = encode(&[Op::Write { addr, value: 7 }]);
            let (ops, _) = decode(&blob).unwrap();
            assert_eq!(ops, vec![Op::Write { addr, value: 7 }]);
        }
    }

    #[test]
    fn log_lines_match_the_originals_format() {
        assert_eq!(
            Op::Write {
                addr: 0x1801_a010,
                value: 0x1f
            }
            .to_log_line(),
            "write: 0x1801a010 = 0x0000001f"
        );
        assert_eq!(
            Op::Poll {
                addr: 0x9800_e800,
                mask: 0xf,
                want: 0xd
            }
            .to_log_line(),
            "poll: 0x9800e800 & 0x0000000f = 0x0000000d"
        );
        assert_eq!(Op::Nop { value: 0x1000 }.to_log_line(), "nop: 0x1000");
    }
}
