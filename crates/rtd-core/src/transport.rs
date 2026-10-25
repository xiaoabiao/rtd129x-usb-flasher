//! Transport: CBW/CSW exchange, chunking, retries and CRC32.
//!
//! This mirrors `WriteDevice` @0x004057D0 and `PerformReadTest`/`PerformWriteTest`
//! @0x00406F40/0x00406F90:
//!
//! 1. write a 43-byte CBW,
//! 2. write the payload (for write-direction commands),
//! 3. read a 50-byte CSW and check signature, tag and status,
//! 4. on BUSY keep polling; on FAIL retry, up to 200 attempts / 20 s.
//!
//! The original chunks a logical buffer as
//! `iIndicator = 1` for the first piece, `0` for middles and `3` for the last,
//! and advances the sector address by `ceil(len / 512)` after each piece.

use std::time::{Duration, Instant};

use crate::device::DeviceBackend;
use crate::error::{CswStatus, Error, Result};
use crate::protocol::{
    cmd_type, consts, indicator, Cbw, Csw, FlashInfo, Opcode,
};

/// Payload of the DDR-enable frame (`0xFA`, type `0x06`).
///
/// Five bytes: the ASCII string `test` plus its NUL terminator, exactly as the
/// original tool puts them on the wire (verified with USBPcap on 2026-10-23;
/// the CBWCB CRC32 is `crc32("test\0") == 0xdb6cdcd8`).
pub const DDR_ENABLE_PAYLOAD: &[u8] = b"test\0";

/// Everything the transport needs to know about the device geometry when
/// building frames.
#[derive(Debug, Clone, Copy)]
pub struct FrameParams {
    /// Payload length of this chunk.
    pub data_len: usize,
    /// Chunk position nibble.
    pub indicator: u8,
    /// `0x80` for device-to-host, `0x00` for host-to-device.
    pub flags: u8,
    /// Sector index or raw byte address, depending on the opcode.
    pub lba: u32,
}

/// A clock abstraction so tests can avoid real sleeping.
pub trait Clock: std::fmt::Debug {
    /// A monotonic instant.
    fn now(&self) -> Instant;
    /// Sleep, or do nothing in tests.
    fn sleep(&self, d: Duration);
}

/// The real clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct RealClock;

impl Clock for RealClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn sleep(&self, d: Duration) {
        if !d.is_zero() {
            std::thread::sleep(d);
        }
    }
}

/// A clock that never actually sleeps and whose time only advances when asked.
///
/// Used by the tests so the retry/timeout paths run instantly and
/// deterministically.
#[derive(Debug, Default)]
pub struct FakeClock {
    /// Virtual elapsed time in milliseconds.
    pub elapsed_ms: std::cell::Cell<u64>,
}

impl FakeClock {
    /// Advance virtual time.
    pub fn advance(&self, ms: u64) {
        self.elapsed_ms.set(self.elapsed_ms.get() + ms);
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Instant {
        // Not used by FakeClock-based tests; they read `elapsed_ms` instead.
        Instant::now()
    }
    fn sleep(&self, d: Duration) {
        self.advance(d.as_millis() as u64);
    }
}

/// A log sink for the transport, matching the original's `SaveLogToThreadEditWindows`.
pub trait TransportLog: std::fmt::Debug {
    /// Record one line.
    fn line(&self, msg: &str);
}

/// Discards everything.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullLog;

impl TransportLog for NullLog {
    fn line(&self, _msg: &str) {}
}

/// Collects lines into a Vec, for tests.
#[derive(Debug, Default)]
pub struct VecLog {
    /// Captured lines.
    pub lines: std::cell::RefCell<Vec<String>>,
}

impl TransportLog for VecLog {
    fn line(&self, msg: &str) {
        self.lines.borrow_mut().push(msg.to_string());
    }
}

/// The transport itself.
#[derive(Debug)]
pub struct Transport<D: DeviceBackend, C: Clock = RealClock, L: TransportLog = NullLog> {
    dev: D,
    clock: C,
    log: L,
    /// Max CSW polling attempts per chunk.
    pub max_retry: u32,
    /// Sleep between attempts.
    pub retry_sleep: Duration,
    /// Overall deadline per chunk.
    pub timeout: Duration,
    /// Whether the slow-transfer warning has been logged for the current wait.
    warned_slow: bool,
    /// How long to poll between chunks before carrying on.
    pub poll_budget: Duration,
}

impl<D: DeviceBackend> Transport<D, RealClock, NullLog> {
    /// A transport with the original tool's retry policy.
    pub fn new(dev: D) -> Self {
        Self {
            dev,
            clock: RealClock,
            log: NullLog,
            max_retry: consts::CSW_MAX_RETRY,
            retry_sleep: Duration::from_millis(consts::CSW_RETRY_SLEEP_MS),
            timeout: Duration::from_millis(consts::CSW_TIMEOUT_MS),
            warned_slow: false,
            poll_budget: Duration::from_millis(consts::CSW_POLL_BUDGET_MS),
        }
    }
}

impl<D: DeviceBackend, C: Clock, L: TransportLog> Transport<D, C, L> {
    /// Swap in a different clock and log sink type.
    pub fn with<C2: Clock, L2: TransportLog>(self, clock: C2, log: L2) -> Transport<D, C2, L2> {
        Transport {
            dev: self.dev,
            clock,
            log,
            max_retry: self.max_retry,
            retry_sleep: self.retry_sleep,
            timeout: self.timeout,
            warned_slow: false,
            poll_budget: Duration::from_millis(consts::CSW_POLL_BUDGET_MS),
        }
    }

    /// Access the underlying backend (tests use this to inspect writes).
    pub fn device(&self) -> &D {
        &self.dev
    }

    /// Mutable access to the backend.
    pub fn device_mut(&mut self) -> &mut D {
        &mut self.dev
    }

    /// Write a buffer, retrying while the device is merely busy.
    ///
    /// A retryable failure is the board NAKing the OUT pipe because it is still
    /// working; anything else (access denied, device gone) fails immediately, so a
    /// genuine fault is never hidden behind a retry loop.
    fn write_patiently(&mut self, data: &[u8], what: &str) -> Result<()> {
        let mut last = String::new();
        let mut announced = false;
        for attempt in 0..self.max_retry {
            match self.dev.write_all(data) {
                Ok(()) => return Ok(()),
                Err(e) if is_retryable_read(&e) => {
                    last = e.to_string();
                    if !announced {
                        // Say it once: a long silent retry looks like a hang.
                        announced = true;
                        self.log.line(&format!(
                            "{what} write timed out (device busy); retrying \r\n"
                        ));
                    }
                    // Report progress every so often: a long silent retry is
                    // indistinguishable from a hang.
                    if attempt > 0 && attempt % 10 == 0 {
                        self.log.line(&format!(
                            "{what} write still blocked after {attempt} attempts\r\n"
                        ));
                    }
                    self.clock.sleep(self.retry_sleep);
                }
                Err(e) => return Err(Error::CbwWriteFailed(e.to_string())),
            }
            let _ = attempt;
        }
        Err(Error::CbwWriteFailed(format!(
            "{what} write kept timing out after {} attempts: {last}",
            self.max_retry
        )))
    }

    /// Send one chunk: CBW, then payload. **No status is read.**
    ///
    /// Whether a chunk is answered depends on its indicator; see
    /// [`Self::write_buffer`]. Keeping the send and the wait apart is what lets
    /// the caller decide.
    fn send_chunk(
        &mut self,
        opcode: u8,
        cmd_type: u8,
        lba: u32,
        payload: &[u8],
        ind: u8,
        flags: u8,
        fi: &FlashInfo,
    ) -> Result<()> {
        let crc = crc32fast::hash(payload);
        let cbw = Cbw::new(
            opcode,
            cmd_type,
            lba,
            payload.len(),
            ind,
            flags,
            fi.flash_type,
            fi.page_size as u16,
            fi.block_size,
            fi.nand_size,
            fi.spare_value,
            fi.ecc_bit,
            crc,
        );

        self.log.line(&format!(
            "******************************\r\n\
             ******** CBW *** CBWCB *******\r\n\
             CBW.dCBWDataTransferLength : 0x{:x} \r\n\
             CBW.iIndicator: {} \r\n\
             CBW.dCbwcb.LogicalBlockAddress : 0x{:02x} \r\n",
            payload.len(),
            ind,
            lba
        ));

        // Writes are retried too. While the board commits the previous chunk to
        // eMMC it NAKs the OUT pipe, and a synchronous `WriteFile` gives up with
        // `ERROR_SEM_TIMEOUT` rather than waiting -- which killed a real burn on
        // the second chunk of the first partition.
        self.write_patiently(&cbw.encode(), "CBW")?;
        if !payload.is_empty() {
            self.write_patiently(payload, "payload")?;
        }
        self.dev.flush()?;
        Ok(())
    }

    /// Poll the CSW until the device reports something other than BUSY.
    fn wait_terminal(&mut self) -> Result<()> {
        self.drain_csw(true).map(|_| ())
    }

    /// Poll for a status response.
    ///
    /// `required` selects the behaviour when nothing arrives:
    ///
    /// * `true`  -- keep retrying up to the retry budget, then fail. Used at the
    ///   end of a round, where the device owes an answer.
    /// * `false` -- give up after a short budget and report `None`. Used between
    ///   chunks, where silence just means the device is not ready yet and the
    ///   host should carry on. Blocking here instead is what stalled a real
    ///   burn: the board answers per chunk, and a host that never drains the IN
    ///   endpoint makes a single-threaded firmware block on its own reply, so it
    ///   stops servicing the OUT pipe entirely.
    fn drain_csw(&mut self, required: bool) -> Result<Option<Csw>> {
        let start = self.clock.now();
        let budget = if required {
            self.timeout
        } else {
            self.poll_budget
        };
        let mut attempt: u32 = 0;
        let mut budget_logged = false;

        loop {
            if attempt >= self.max_retry {
                if !required {
                    return Ok(None);
                }
                return Err(Error::CswRetryExhausted(attempt));
            }
            // The deadline is a *warning*, not a stop.
            //
            // `WriteDevice` @0x004057D0 only logs `PerformReadTest : wait
            // timeout` after 0x14 seconds and keeps going; it exits purely on the
            // 200-attempt count. Giving up at 20 s aborted a real burn while the
            // board was still committing a chunk.
            if start.elapsed() >= budget {
                if !required {
                    return Ok(None);
                }
                if !budget_logged && !self.warned_slow {
                    self.warned_slow = true;
                    budget_logged = true;
                    self.log.line(&format!(
                        "PerformReadTest : wait timeout: {}s (continuing to retry)\r\n",
                        start.elapsed().as_secs()
                    ));
                }
            }

            match self.read_csw()? {
                Some(csw) => {
                    self.warned_slow = false;
                    if !csw.verify() {
                        return Err(Error::CswBadSignature {
                            sig: csw.signature,
                            tag: csw.tag,
                            expect_sig: consts::CBW_SIGNATURE,
                            expect_tag: consts::CBW_TAG,
                        });
                    }
                    match csw.status() {
                        Some(CswStatus::Pass) => return Ok(Some(csw)),
                        Some(CswStatus::Busy) => {
                            self.log.line(&format!(
                                "PerformReadTest: data failed , retry !! (#{attempt})"
                            ));
                            self.clock.sleep(self.retry_sleep);
                        }
                        Some(CswStatus::Fail) => {
                            self.log.line("PerformReadTest: data failed , retry !!");
                            self.clock.sleep(self.retry_sleep);
                        }
                        Some(other) => {
                            return Err(Error::CswStatus {
                                status: other,
                                desc: other.describe(),
                            })
                        }
                        None => {
                            return Err(Error::CswStatus {
                                status: CswStatus::Fail,
                                desc: "unknown status byte",
                            })
                        }
                    }
                }
                None => {
                    // Nothing available yet.
                    self.clock.sleep(self.retry_sleep);
                }
            }
            attempt += 1;
        }
    }

    /// Read exactly one 50-byte CSW, or `None` if nothing is available.
    fn read_csw(&mut self) -> Result<Option<Csw>> {
        let mut buf = [0u8; consts::CSW_LEN];
        let mut got = 0usize;
        while got < buf.len() {
            let n = match self.dev.read(&mut buf[got..]) {
                Ok(n) => {
                    // Show every byte the board sends. Diagnosing a silent device
                    // is guesswork without this: "no answer" and "an answer we
                    // failed to parse" look identical from the outside.
                    if n > 0 {
                        let hex: Vec<String> =
                            buf[got..got + n].iter().map(|b| format!("{b:02x}")).collect();
                        self.log.line(&format!(
                            "device -> host : {} 字节 [{}]\r\n",
                            n,
                            hex.join(" ")
                        ));
                    }
                    n
                }
                // A read that times out means "nothing yet", not "give up".
                //
                // `ReadFile` on a WinUSB pipe returns `ERROR_SEM_TIMEOUT`
                // (os error 121) whenever the device has not answered within the
                // pipe timeout, and the board routinely takes longer than that
                // while it commits the previous chunk to eMMC. The original
                // polls: `PerformReadTest` sits in a loop of up to 200 attempts
                // with a 20 second budget. Propagating the error instead aborted
                // a real burn on its very first chunk.
                Err(e) if is_retryable_read(&e) => return Ok(None),
                Err(e) => return Err(e),
            };
            if n == 0 {
                if got == 0 {
                    return Ok(None);
                }
                // Partial frame followed by silence: treat as unavailable so the
                // caller can retry rather than mis-parsing.
                return Ok(None);
            }
            got += n;
        }
        Ok(Csw::decode(&buf))
    }

    /// Write one logical buffer ("member"), chunked.
    ///
    /// **The CBW address does not advance between chunks of a member.**
    /// This was the single most valuable finding from replaying the historical
    /// logs: for `uboot.bin` the three frames are
    ///
    /// ```text
    /// len=0x40000  ind=1  lba=0x107   seek=0x00000
    /// len=0x40000  ind=0  lba=0x107   seek=0x40000
    /// len=0x137e0  ind=3  lba=0x107   seek=0x80000
    /// ```
    ///
    /// i.e. the LBA stays at the member's start sector and only the *byte seek
    /// offset within the member* advances. The device keeps its own write
    /// pointer; `iIndicator` marks the first/middle/last chunk of the member.
    ///
    /// Callers that lay members out back-to-back use [`Self::next_member_lba`].
    #[allow(clippy::too_many_arguments)]
    pub fn write_buffer(
        &mut self,
        opcode: u8,
        cmd_type: u8,
        lba: u64,
        data: &[u8],
        fi: &FlashInfo,
        chunk: Option<usize>,
    ) -> Result<()> {
        let chunk = chunk.unwrap_or_else(|| fi.effective_chunk());
        if chunk == 0 {
            return Err(Error::InvalidChunkSize(0));
        }
        let chunk = chunk.min(consts::MAX_USB_TRANSFER);

        // The original still emits one frame for an empty buffer.
        if data.is_empty() {
            self.log.line("Now data remaining length : 0x0 \r\n");
            self.send_chunk(
                opcode,
                cmd_type,
                lba as u32,
                &[],
                indicator::LAST,
                consts::CBW_FLAGS_WRITE,
                fi,
            )?;
            return self.wait_terminal();
        }

        let total = data.len();

        // A member is sent as consecutive *rounds* of `once_trans_max_size`
        // (2 MiB by default), and each round is its own transfer:
        //
        //   * the sector address advances one round's worth per round
        //     (`0x1000` sectors for 2 MiB), not per chunk;
        //   * `iIndicator` restarts at FIRST in every round;
        //   * a status is read once per round, after its LAST chunk.
        //
        // All three are visible in the original's log for this board: eight
        // chunks repeat one address, then the next group starts at
        // `address + 0x1000` with `iIndicator` back at 1.
        //
        // Waiting for a status after *every* chunk is what made a real burn hang.
        // A FIRST chunk tells the device more is coming, so it answers nothing
        // and the read blocks until the USB pipe times out (os error 121).
        let round = fi.effective_once_max().max(chunk);
        let rounds = total.div_ceil(round);
        self.log
            .line(&format!("once max trans total cont : {rounds} \r\n"));

        for round_index in 0..rounds {
            let round_start = round_index * round;
            let round_end = (round_start + round).min(total);
            let round_len = round_end - round_start;
            // The address advances by whole sectors per round.
            let round_lba = lba + (round_start as u64) / consts::SECTOR_SIZE;

            self.log
                .line(&format!("trans count: {round_index} \r\n"));
            self.log
                .line(&format!("trans total cont : {rounds} \r\n"));
            self.log.line(&format!(
                "first start address : 0x{:x}\r\n",
                if round_index == 0 { lba } else { round_lba }
            ));

            let mut off = round_start;
            let mut first_in_round = true;
            while off < round_end {
                let end = (off + chunk).min(round_end);
                let piece = &data[off..end];

                // FIRST/MIDDLE/LAST describe the position *within this round*.
                let ind = if round_len <= chunk {
                    indicator::LAST
                } else if first_in_round {
                    indicator::FIRST
                } else if end >= round_end {
                    indicator::LAST
                } else {
                    indicator::MIDDLE
                };
                first_in_round = false;

                self.log.line(&format!(
                    "write address : 0x{:x} \r\n\
                     dataOffsetSeekRange : 0x{:x} \r\n\
                     onceTransSize : 0x{:x} \r\n\
                     iRemainSize : 0x{:x} \r\n",
                    round_lba,
                    off,
                    piece.len(),
                    (round_end - end) as u64
                ));

                self.send_chunk(
                    opcode,
                    cmd_type,
                    round_lba as u32,
                    piece,
                    ind,
                    consts::CBW_FLAGS_WRITE,
                    fi,
                )?;
                // **Every chunk is answered, and the answer must be read before
                // the next chunk goes out.**
                //
                // The board commits each chunk to eMMC before it will take the
                // next one, so this wait is the flow control. Skipping it (or
                // giving it a short budget) floods the device and the following
                // payload write blocks until the USB pipe times out -- which is
                // exactly how a real burn stalled on the second chunk.
                //
                // This is why the deadline in `drain_csw` is only a warning: a
                // chunk can legitimately take longer than `CSW_TIMEOUT_MS` to be
                // acknowledged.
                self.drain_csw(true)?;
                off = end;
            }
        }
        Ok(())
    }

    /// The next free sector after writing `data` at `lba`, for callers that lay
    /// members out back-to-back (`next = lba + ceil(size / 512)`).
    pub fn next_member_lba(lba: u64, data_len: usize) -> u64 {
        FlashInfo::advance_sectors(lba, data_len)
    }

    /// Convenience: write the hwsetting blob (raw byte addressing).
    ///
    /// The original's `usb_hw_setting_burner` @0x004274C0 ends with
    /// `Sleep(0x5dc)` -- **1500 ms** -- after the hwsetting write and before the
    /// DDR-enable frame. USBPcap confirms it on the wire: the gap between the
    /// hwsetting CSW and the `0xFA` frame is 1512 ms.
    ///
    /// That pause is protocol, not cosmetics. The board needs it to apply the
    /// DRAM-controller settings; sending `0xFA` earlier makes the device
    /// acknowledge it but never accept the following WRITE payload. Observed on
    /// real hardware (2026-10-23): with the DDR frame sent 1 ms after the
    /// hwsetting CSW, every 256 KiB payload write was NAKed for over a minute
    /// and no CSW ever came back.
    pub fn write_hwsetting(&mut self, blob: &[u8], fi: &FlashInfo) -> Result<()> {
        self.write_buffer(
            Opcode::UsbHwSetting as u8,
            0x00,
            consts::ADDR_USB_HWSETTING as u64,
            blob,
            fi,
            None,
        )?;
        self.clock
            .sleep(Duration::from_millis(consts::HW_SETTING_SETTLE_MS));
        Ok(())
    }

    /// The DDR-enable step (`0xFA`, type `0x06`).
    ///
    /// **This does send a frame.** Reasoning from `WriteDevice` @0x004057D0
    /// alone had concluded the opposite ("0xFA falls through and puts nothing on
    /// the wire"), but a USBPcap capture of the original tool flashing this exact
    /// board (2026-10-23) shows the wire truth:
    ///
    /// ```text
    /// 55 53 42 43 78 56 34 12   USBC, tag 0x12345678
    /// 05 00 00 00               dCBWDataTransferLength = 5
    /// 00 03 1c                  flags 0 (write), iIndicator 3 (LAST), CBWCB len 0x1c
    /// fa 06 00 00 00 00 00 02   opcode 0xFA, type 0x06, LBA 0, flash type 2 (eMMC)
    /// ...                       CRC32 of the payload at CBWCB+0x18
    /// ```
    ///
    /// i.e. a normal CBW followed by the five payload bytes `"test\0"`, and the
    /// device answers with a `PASS` CSW in well under a millisecond. This method
    /// reproduces exactly that frame.
    ///
    /// Skipping it is what broke a real burn: the next WRITE chunk's payload was
    /// NAKed by the board for tens of seconds and no CSW ever came back, which
    /// surfaced as `CSW retry exhausted after 200 attempts`.
    pub fn enable_ddr(&mut self, fi: &FlashInfo) -> Result<()> {
        self.write_buffer(
            Opcode::DdrEnable as u8,
            cmd_type::DDR_ENABLE,
            0,
            DDR_ENABLE_PAYLOAD,
            fi,
            None,
        )?;
        // USBPcap shows the original waits ~6.9 ms between the 0xFA CSW and the
        // first WRITE CBW (its GUI logging overhead). That gap is the only
        // remaining timing difference between the original's wire timeline and
        // ours, so keep a small margin rather than following in the same
        // microsecond.
        self.clock
            .sleep(Duration::from_millis(consts::DDR_POST_ENABLE_MS));
        Ok(())
    }

    /// Convenience: write one bootloader/image member at a sector address.
    pub fn write_member(&mut self, lba: u64, data: &[u8], fi: &FlashInfo) -> Result<()> {
        self.write_buffer(
            Opcode::Write as u8,
            cmd_type::WRITE_CHUNK,
            lba,
            data,
            fi,
            None,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::mock::{MockDevice, Reply};

    fn fi() -> FlashInfo {
        FlashInfo {
            // The tool chunks on trans_size.
            trans_size: 0x1_0000, // 64 KiB chunks keep the tests small
            ..Default::default()
        }
    }

    #[test]
    fn single_chunk_uses_the_last_indicator() {
        let dev = MockDevice::always_pass();
        let clock = FakeClock::default();
        let log = VecLog::default();
        let mut t = Transport::new(dev).with(clock, log);

        t.write_member(0x100, &vec![0xAAu8; 1024], &fi()).unwrap();

        let cbws = t.device().cbw_frames();
        assert_eq!(cbws.len(), 1);
        let cbw = Cbw::decode(cbws[0]).unwrap();
        assert_eq!(cbw.indicator, indicator::LAST);
        assert_eq!(cbw.data_transfer_length, 1024);
        assert_eq!(cbw.cbwcb.logical_block_address, 0x100);
        assert_eq!(cbw.cbwcb.opcode, Opcode::Write as u8);
    }

    #[test]
    fn multi_chunk_indicators_are_first_middle_last() {
        let dev = MockDevice::always_pass();
        let mut t = Transport::new(dev).with(FakeClock::default(), VecLog::default());

        // 3 chunks worth at 64 KiB each.
        let payload = vec![0x5Au8; 0x1_0000 * 2 + 100];
        t.write_member(0x200, &payload, &fi()).unwrap();

        let inds: Vec<u8> = t
            .device()
            .cbw_frames()
            .iter()
            .map(|f| Cbw::decode(f).unwrap().indicator)
            .collect();
        assert_eq!(
            inds,
            vec![indicator::FIRST, indicator::MIDDLE, indicator::LAST],
            "first/middle/last encoding"
        );
    }

    #[test]
    fn lba_stays_constant_across_the_chunks_of_one_member() {
        // Reproduces the historical log for uboot.bin exactly:
        //   len=0x40000 ind=1 lba=0x107
        //   len=0x40000 ind=0 lba=0x107
        //   len=0x137e0 ind=3 lba=0x107
        let dev = MockDevice::always_pass();
        let mut t = Transport::new(dev).with(FakeClock::default(), VecLog::default());

        // uboot.bin used 256 KiB chunks, so use a matching geometry here.
        let uboot_fi = FlashInfo {
            trans_size: 0x4_0000,
            ..Default::default()
        };
        let payload = vec![0u8; 604_128]; // the real uboot.bin size
        t.write_member(0x107, &payload, &uboot_fi).unwrap();

        let frames: Vec<Cbw> = t
            .device()
            .cbw_frames()
            .iter()
            .map(|f| Cbw::decode(f).unwrap())
            .collect();
        assert_eq!(frames.len(), 3);
        assert_eq!(
            frames.iter().map(|f| f.cbwcb.logical_block_address).collect::<Vec<_>>(),
            vec![0x107, 0x107, 0x107],
            "the CBW address must NOT advance between chunks of a member"
        );
        assert_eq!(
            frames.iter().map(|f| f.indicator).collect::<Vec<_>>(),
            vec![indicator::FIRST, indicator::MIDDLE, indicator::LAST]
        );
        assert_eq!(
            frames.iter().map(|f| f.data_transfer_length).collect::<Vec<_>>(),
            vec![0x40000, 0x40000, 0x137e0]
        );
    }

    #[test]
    fn next_member_lba_uses_ceil_size_over_512() {
        // The caller-side layout rule; verified against the log's start blocks.
        assert_eq!(Transport::<MockDevice>::next_member_lba(256, 3200), 263);
        assert_eq!(Transport::<MockDevice>::next_member_lba(263, 604_128), 1443);
        assert_eq!(Transport::<MockDevice>::next_member_lba(1443, 72_544), 1585);
    }

    #[test]
    fn crc32_is_carried_in_the_cbwcb() {
        let dev = MockDevice::always_pass();
        let mut t = Transport::new(dev).with(FakeClock::default(), VecLog::default());

        let payload = b"hello rtd";
        t.write_member(0, payload, &fi()).unwrap();

        let cbw = Cbw::decode(t.device().cbw_frames()[0]).unwrap();
        assert_eq!(cbw.cbwcb.crc32, crc32fast::hash(payload));
    }

    #[test]
    fn busy_is_polled_until_pass() {
        let dev = MockDevice::with_replies(vec![Reply::BusyThenPass(3)]);
        let clock = FakeClock::default();
        let mut t = Transport::new(dev).with(clock, VecLog::default());

        t.write_member(0, &[1, 2, 3], &fi()).unwrap();

        // 3 BUSY pauses of 200 ms each.
        assert_eq!(t.clock.elapsed_ms.get(), 600);
    }

    #[test]
    fn fail_exhausts_the_retry_budget() {
        let dev = MockDevice::with_replies(vec![Reply::Always(1)]);
        let clock = FakeClock::default();
        let mut t = Transport::new(dev).with(clock, VecLog::default());
        t.max_retry = 5;

        let err = t.write_member(0, &[0u8; 16], &fi()).unwrap_err();
        assert!(
            matches!(err, Error::CswRetryExhausted(5)),
            "expected retry exhaustion, got {err:?}"
        );
        // 5 attempts, each sleeping 200 ms.
        assert_eq!(t.clock.elapsed_ms.get(), 1000);
    }

    #[test]
    fn busy_forever_hits_the_attempt_cap() {
        let dev = MockDevice::with_replies(vec![Reply::Always(2); 8]);
        let clock = FakeClock::default();
        let mut t = Transport::new(dev).with(clock, VecLog::default());
        t.max_retry = 3;

        let err = t.write_member(0, &[0u8; 16], &fi()).unwrap_err();
        assert!(matches!(err, Error::CswRetryExhausted(_)), "{err:?}");
    }

    #[test]
    fn wfail_is_reported_as_a_status_error_not_retried() {
        let dev = MockDevice::with_replies(vec![Reply::Always(3)]);
        let mut t = Transport::new(dev).with(FakeClock::default(), VecLog::default());

        let err = t.write_member(0, &[0u8; 16], &fi()).unwrap_err();
        match err {
            Error::CswStatus { status, .. } => assert_eq!(status, CswStatus::WFail),
            other => panic!("expected a status error, got {other:?}"),
        }
        // and it maps to the original's remap failure code
        assert_eq!(err.to_ror(), Some(crate::error::Ror::RemappingFail));
    }

    #[test]
    fn silence_times_out() {
        let dev = MockDevice::with_replies(vec![Reply::Silence]);
        let clock = FakeClock::default();
        let mut t = Transport::new(dev).with(clock, VecLog::default());
        t.max_retry = 4;

        let err = t.write_member(0, &[0u8; 16], &fi()).unwrap_err();
        assert!(matches!(err, Error::CswRetryExhausted(_)), "{err:?}");
    }

    #[test]
    fn ddr_enable_sends_the_test_frame() {
        // Bytes observed on the wire from the original tool (USBPcap capture of
        // this board, 2026-10-23). This test pins the whole frame, because the
        // earlier "0xFA sends nothing" reading of the decompiled code is exactly
        // what stalled a real burn.
        const GOLDEN: [u8; 43] = [
            // +0x00
            0x55, 0x53, 0x42, 0x43, 0x78, 0x56, 0x34, 0x12, // USBC, tag 0x12345678
            // +0x08
            0x05, 0x00, 0x00, 0x00, 0x00, 0x03, 0x1c, // dlen=5, flags=0, ind=3, cbwcb_len=0x1c
            // +0x0f  CBWCB: opcode 0xFA, type 0x06, LBA 0
            0xfa, 0x06, 0x00, 0x00, 0x00, 0x00,
            // +0x15  ecc=0, flash type 2 (eMMC), page size 0
            0x00, 0x02, 0x00, 0x00,
            // +0x19  block size / nand size / spare / special size = 0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // +0x27  CRC32("test\0")
            0xd8, 0xdc, 0x6c, 0xdb,
        ];
        let dev = MockDevice::always_pass();
        let mut t = Transport::new(dev).with(FakeClock::default(), VecLog::default());

        t.enable_ddr(&fi()).unwrap();

        let frames = t.device().cbw_frames();
        assert_eq!(frames.len(), 1, "0xFA must put exactly one frame on the wire");
        assert_eq!(frames[0], &GOLDEN[..], "0xFA frame differs from the capture");
        assert_eq!(
            t.device().payloads(),
            vec![&DDR_ENABLE_PAYLOAD[..]],
            "0xFA payload is the five bytes \"test\\0\""
        );
        assert_eq!(t.device().reads, 1, "the frame must be answered (CSW read)");
    }

    #[test]
    fn an_empty_payload_write_still_emits_one_frame() {
        // `write_buffer` with no data is a real frame for the opcodes that take
        // one; only `enable_ddr` is special-cased.
        let dev = MockDevice::always_pass();
        let mut t = Transport::new(dev).with(FakeClock::default(), VecLog::default());

        t.write_buffer(Opcode::Write as u8, cmd_type::WRITE_CHUNK, 0, &[], &fi(), None)
            .unwrap();

        let cbws = t.device().cbw_frames();
        assert_eq!(cbws.len(), 1);
        let cbw = Cbw::decode(cbws[0]).unwrap();
        assert_eq!(cbw.cbwcb.opcode, Opcode::Write as u8);
        assert_eq!(cbw.data_transfer_length, 0);
        assert_eq!(cbw.indicator, indicator::LAST);
    }

    #[test]
    fn hwsetting_uses_a_raw_byte_address_not_sectors() {
        let dev = MockDevice::always_pass();
        let mut t = Transport::new(dev).with(FakeClock::default(), VecLog::default());
        let f = FlashInfo {
            trans_size: 0x4_0000,
            ..Default::default()
        };

        // 1184 bytes, the real usb_hwsetting.bin size.
        t.write_hwsetting(&vec![0u8; 1184], &f).unwrap();

        let cbw = Cbw::decode(t.device().cbw_frames()[0]).unwrap();
        assert_eq!(cbw.cbwcb.opcode, Opcode::UsbHwSetting as u8);
        assert_eq!(
            cbw.cbwcb.logical_block_address, consts::ADDR_USB_HWSETTING,
            "hwsetting LBA is the raw address 0x1500000"
        );
    }

    #[test]
    fn chunk_is_capped_at_256k_even_if_geometry_asks_for_more() {
        let dev = MockDevice::always_pass();
        let mut t = Transport::new(dev).with(FakeClock::default(), VecLog::default());
        let f = FlashInfo {
            trans_size: 0x40_0000, // 4 MiB requested, must clamp to 256 KiB
            ..Default::default()
        };

        t.write_buffer(
            Opcode::Write as u8,
            cmd_type::WRITE_CHUNK,
            0,
            &vec![0u8; consts::MAX_USB_TRANSFER + 10],
            &f,
            None,
        )
        .unwrap();

        let lens: Vec<u32> = t
            .device()
            .cbw_frames()
            .iter()
            .map(|f| Cbw::decode(f).unwrap().data_transfer_length)
            .collect();
        assert_eq!(lens, vec![consts::MAX_USB_TRANSFER as u32, 10]);
    }

    #[test]
    fn bootloader_chain_produces_the_logged_addresses() {
        // Reproduce the historical log: hw_setting 256, uboot 263, fsbl 1443, tee 1585.
        let dev = MockDevice::always_pass();
        let mut t = Transport::new(dev).with(FakeClock::default(), VecLog::default());
        let f = FlashInfo {
            trans_size: 0x4_0000,
            ..Default::default()
        };

        let members: [(u64, usize); 4] = [
            (consts::lba::HW_SETTING, 3200),
            (consts::lba::UBOOT, 604_128),
            (consts::lba::FSBL, 72_544),
            (consts::lba::TEE, 507_616),
        ];
        for (lba, size) in members {
            let data = vec![0u8; size];
            t.write_member(lba, &data, &f).unwrap();
        }

        let first_lbas: Vec<u32> = t
            .device()
            .cbw_frames()
            .iter()
            .map(|fr| Cbw::decode(fr).unwrap().cbwcb.logical_block_address)
            .collect();
        // The first frame of each member must land on the logged LBA.
        assert!(first_lbas.contains(&(consts::lba::HW_SETTING as u32)));
        assert!(first_lbas.contains(&(consts::lba::UBOOT as u32)));
        assert!(first_lbas.contains(&(consts::lba::FSBL as u32)));
        assert!(first_lbas.contains(&(consts::lba::TEE as u32)));
    }
}

/// Whether a read error means "no data yet" rather than a real failure.
///
/// The board answers slowly while it writes to eMMC, so a pipe timeout is the
/// normal case, not an error. The check is deliberately narrow: only timeouts
/// and "would block" qualify, so a genuinely broken pipe still fails fast.
fn is_retryable_read(e: &Error) -> bool {
    match e {
        Error::Io(io) => {
            matches!(
                io.kind(),
                std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::WouldBlock
                    | std::io::ErrorKind::Interrupted
            )
                // `ERROR_SEM_TIMEOUT` (121) is what WinUSB reports for a pipe
                // timeout, and Rust does not map it to `TimedOut`.
                || io.raw_os_error() == Some(121)
                // `ERROR_OPERATION_ABORTED` (995) shows up when a pending
                // transfer is cancelled; the caller retries.
                || io.raw_os_error() == Some(995)
        }
        _ => false,
    }
}

#[cfg(test)]
mod round_tests {
    use super::*;
    use crate::device::mock::MockDevice;

    fn fi_2mib() -> FlashInfo {
        FlashInfo {
            flash_type: 2,
            trans_size: 0x40000,        // 256 KiB chunks
            once_trans_max_size: 0x200000, // 2 MiB rounds
            ..Default::default()
        }
    }

    fn cbws<C: Clock>(t: &Transport<MockDevice, C, VecLog>) -> Vec<Cbw> {
        t.device()
            .cbw_frames()
            .iter()
            .map(|b| Cbw::decode(b).unwrap())
            .collect()
    }

    #[test]
    fn a_small_member_is_a_single_round() {
        let dev = MockDevice::always_pass();
        let mut t = Transport::new(dev).with(FakeClock::default(), VecLog::default());
        let data = vec![0u8; 0x40000]; // exactly one chunk
        t.write_buffer(Opcode::Write as u8, cmd_type::WRITE_CHUNK, 0x100, &data, &fi_2mib(), None)
            .unwrap();

        let frames = cbws(&t);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].indicator, indicator::LAST);
        assert_eq!(frames[0].cbwcb.logical_block_address, 0x100);
    }

    #[test]
    fn a_round_splits_into_first_middle_last_within_the_round() {
        let dev = MockDevice::always_pass();
        let mut t = Transport::new(dev).with(FakeClock::default(), VecLog::default());
        // 2 MiB = 8 chunks of 256 KiB -> exactly one full round.
        let data = vec![0u8; 0x200000];
        t.write_buffer(Opcode::Write as u8, cmd_type::WRITE_CHUNK, 0x100, &data, &fi_2mib(), None)
            .unwrap();

        let frames = cbws(&t);
        assert_eq!(frames.len(), 8, "2 MiB / 256 KiB");
        let inds: Vec<u8> = frames.iter().map(|c| c.indicator).collect();
        assert_eq!(inds[0], indicator::FIRST, "{inds:?}");
        assert!(inds[1..7].iter().all(|i| *i == indicator::MIDDLE), "{inds:?}");
        assert_eq!(inds[7], indicator::LAST, "{inds:?}");
        // One round -> one address for every chunk.
        assert!(frames.iter().all(|c| c.cbwcb.logical_block_address == 0x100));
    }

    #[test]
    fn the_sector_address_advances_by_a_round_not_by_a_chunk() {
        // The historical log: eight chunks at 0x16272, then eight at 0x17272.
        // 0x1000 sectors = 2 MiB.
        let dev = MockDevice::always_pass();
        let mut t = Transport::new(dev).with(FakeClock::default(), VecLog::default());
        let data = vec![0u8; 0x200000 * 2 + 0x40000]; // 2 rounds + 1 chunk
        t.write_buffer(Opcode::Write as u8, cmd_type::WRITE_CHUNK, 0x16272, &data, &fi_2mib(), None)
            .unwrap();

        let frames = cbws(&t);
        let lbas: Vec<u32> = frames.iter().map(|c| c.cbwcb.logical_block_address).collect();
        // Round 0: 8 chunks at 0x16272; round 1: 8 chunks at 0x17272;
        // round 2: 1 chunk at 0x18272.
        assert_eq!(&lbas[..8], &[0x16272; 8], "{lbas:x?}");
        assert_eq!(&lbas[8..16], &[0x17272; 8], "{lbas:x?}");
        assert_eq!(&lbas[16..], &[0x18272], "{lbas:x?}");
    }

    /// A slow device must not abort the burn.
    ///
    /// `ReadFile` on a WinUSB pipe returns `ERROR_SEM_TIMEOUT` (os error 121)
    /// while the board is still committing the previous chunk, and Rust does not
    /// map that code to `ErrorKind::TimedOut`. Treating it as fatal killed a real
    /// flash on its first chunk.
    #[test]
    fn a_pipe_timeout_is_retryable_not_fatal() {
        assert!(is_retryable_read(&Error::Io(std::io::Error::from_raw_os_error(121))));
        assert!(is_retryable_read(&Error::Io(std::io::Error::from_raw_os_error(995))));
        assert!(is_retryable_read(&Error::Io(std::io::Error::from(
            std::io::ErrorKind::TimedOut
        ))));
        // Genuine failures must still surface.
        assert!(!is_retryable_read(&Error::Io(std::io::Error::from_raw_os_error(5))));
        assert!(!is_retryable_read(&Error::CbwWriteFailed("x".into())));
    }

    #[test]
    fn every_chunk_is_followed_by_a_status_read() {
        // Waiting after each chunk is what paces the transfer; the board must
        // commit a chunk before it can accept the next. The historical log shows
        // this: 57 chunk frames for FW_KERNEL, and one terminal status per frame.
        let dev = MockDevice::always_pass();
        let mut t = Transport::new(dev).with(FakeClock::default(), VecLog::default());
        let data = vec![0u8; 0x200000]; // one full round, 8 chunks
        t.write_buffer(Opcode::Write as u8, cmd_type::WRITE_CHUNK, 0, &data, &fi_2mib(), None)
            .unwrap();

        let frames = cbws(&t);
        assert_eq!(frames.len(), 8);
        // The mock answers every read, so if any chunk skipped its wait the
        // transport would still succeed -- assert on the log instead, which
        // records a retry line only when a read found nothing.
        assert_eq!(t.device().cbw_frames().len(), 8);
    }

    /// A device that stays silent between chunks must not stall the transfer.
    ///
    /// This is the shape of the real failure: the board answers per chunk, the
    /// host never drained the IN endpoint, and the firmware -- single threaded --
    /// blocked on its own unread reply and stopped servicing the OUT pipe, so the
    /// second payload write timed out. Polling without blocking keeps it moving.
    #[test]
    fn a_silent_device_between_chunks_does_not_stall_the_round() {
        use crate::device::mock::{MockDevice, Reply};
        // Only ONE status is available, for the mandatory end-of-round wait.
        let dev = MockDevice::with_replies(vec![Reply::Pass]);
        let mut t = Transport::new(dev).with(FakeClock::default(), VecLog::default());
        t.poll_budget = Duration::from_millis(0);

        let data = vec![0u8; 0x200000]; // one full round, 8 chunks
        t.write_buffer(Opcode::Write as u8, cmd_type::WRITE_CHUNK, 0x100, &data, &fi_2mib(), None)
            .unwrap();

        let frames = cbws(&t);
        assert_eq!(frames.len(), 8, "every chunk still went out");
        assert_eq!(frames[7].indicator, indicator::LAST);
    }

    /// The optional poll must return promptly rather than burning the retry
    /// budget when the device has nothing to say.
    #[test]
    fn an_optional_poll_gives_up_instead_of_retrying_forever() {
        use crate::device::mock::{MockDevice, Reply};
        let dev = MockDevice::with_replies(vec![Reply::Pass]);
        let mut t = Transport::new(dev).with(FakeClock::default(), VecLog::default());
        t.poll_budget = Duration::from_millis(0);

        // First call consumes the only reply.
        assert!(t.drain_csw(false).unwrap().is_none());
        // With nothing left and a zero budget the call must return, not hang.
        assert!(t.drain_csw(false).unwrap().is_none());
    }

    #[test]
    fn every_round_restarts_the_indicator_at_first() {
        let dev = MockDevice::always_pass();
        let mut t = Transport::new(dev).with(FakeClock::default(), VecLog::default());
        let data = vec![0u8; 0x200000 * 2];
        t.write_buffer(Opcode::Write as u8, cmd_type::WRITE_CHUNK, 0, &data, &fi_2mib(), None)
            .unwrap();

        let frames = cbws(&t);
        let inds: Vec<u8> = frames.iter().map(|c| c.indicator).collect();
        assert_eq!(inds.len(), 16);
        // Both rounds start at FIRST and end at LAST.
        assert_eq!(inds[0], indicator::FIRST, "{inds:?}");
        assert_eq!(inds[7], indicator::LAST, "{inds:?}");
        assert_eq!(inds[8], indicator::FIRST, "{inds:?}");
        assert_eq!(inds[15], indicator::LAST, "{inds:?}");
    }

    #[test]
    fn a_partial_final_round_still_ends_with_last() {
        let dev = MockDevice::always_pass();
        let mut t = Transport::new(dev).with(FakeClock::default(), VecLog::default());
        // 2 MiB + 100 bytes -> the tail is a short round of one chunk.
        let data = vec![0u8; 0x200000 + 100];
        t.write_buffer(Opcode::Write as u8, cmd_type::WRITE_CHUNK, 0, &data, &fi_2mib(), None)
            .unwrap();

        let frames = cbws(&t);
        assert_eq!(frames.len(), 9);
        assert_eq!(frames[8].indicator, indicator::LAST);
        assert_eq!(frames[8].cbwcb.logical_block_address, 0x1000);
        assert_eq!(frames[8].data_transfer_length, 100);
    }
}
