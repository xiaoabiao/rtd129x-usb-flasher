//! An in-memory backend that replays canned CSW responses.
//!
//! This is how the historical debug logs are used as a regression corpus: feed
//! real recorded frames in and assert our encoder produces the same bytes.
//! It is also the basis for all the transport tests, which need no hardware.

use crate::device::DeviceBackend;
use crate::error::Result;
use crate::protocol::{consts, Csw};

/// What the mock should reply with for the next CSW read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    /// A normal PASS.
    Pass,
    /// Report BUSY `n` times, then PASS. Used to test polling.
    BusyThenPass(u32),
    /// Always report this status.
    Always(u8),
    /// Never answer (drives the timeout path).
    Silence,
}

/// A backend that records every write and replays scripted CSWs.
#[derive(Debug)]
pub struct MockDevice {
    /// Everything the transport has written, in order.
    pub writes: Vec<Vec<u8>>,
    /// Scripted replies, consumed one per CSW read.
    replies: Vec<Reply>,
    /// Index into `replies`.
    cursor: usize,
    /// Bytes waiting to be handed back by `read`.
    pending: Vec<u8>,
    /// Number of CSW reads performed.
    pub reads: u32,
}

impl MockDevice {
    /// A device that replies PASS to every CSW read, forever.
    pub fn always_pass() -> Self {
        Self {
            writes: Vec::new(),
            replies: Vec::new(),
            cursor: 0,
            pending: Vec::new(),
            reads: 0,
        }
    }

    /// A device driven by an explicit reply script.
    pub fn with_replies(replies: Vec<Reply>) -> Self {
        Self {
            writes: Vec::new(),
            replies,
            cursor: 0,
            pending: Vec::new(),
            reads: 0,
        }
    }

    /// Only the CBW frames written (43-byte writes).
    pub fn cbw_frames(&self) -> Vec<&[u8]> {
        self.writes
            .iter()
            .filter(|w| w.len() == consts::CBW_LEN)
            .map(|w| w.as_slice())
            .collect()
    }

    /// The payload writes (everything that is not a CBW frame).
    pub fn payloads(&self) -> Vec<&[u8]> {
        self.writes
            .iter()
            .filter(|w| w.len() != consts::CBW_LEN)
            .map(|w| w.as_slice())
            .collect()
    }

    fn next_reply(&mut self) -> Reply {
        let r = self
            .replies
            .get(self.cursor as usize)
            .copied()
            .unwrap_or(Reply::Pass);
        self.cursor += 1;
        r
    }

    /// Build a synthetic CSW with the given status.
    pub fn make_csw(status: u8) -> [u8; consts::CSW_LEN] {
        let mut b = [0u8; consts::CSW_LEN];
        b[0..4].copy_from_slice(&consts::CSW_SIGNATURE.to_le_bytes());
        b[4..8].copy_from_slice(&consts::CBW_TAG.to_le_bytes());
        b[consts::CSW_STATUS_OFFSET] = status;
        b
    }
}

impl DeviceBackend for MockDevice {
    fn write_all(&mut self, data: &[u8]) -> Result<()> {
        self.writes.push(data.to_vec());
        // A CBW frame triggers one scripted CSW reply.
        if data.len() == consts::CBW_LEN
            && u32::from_le_bytes(data[0..4].try_into().unwrap()) == consts::CBW_SIGNATURE
        {
            match self.next_reply() {
                Reply::Pass => self
                    .pending
                    .extend_from_slice(&Self::make_csw(0)),
                Reply::BusyThenPass(n) => {
                    for _ in 0..n {
                        self.pending
                            .extend_from_slice(&Self::make_csw(2));
                    }
                    self.pending
                        .extend_from_slice(&Self::make_csw(0));
                }
                Reply::Always(s) => self
                    .pending
                    .extend_from_slice(&Self::make_csw(s)),
                Reply::Silence => {}
            }
        }
        Ok(())
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.pending.is_empty() {
            return Ok(0);
        }
        let n = buf.len().min(self.pending.len());
        buf[..n].copy_from_slice(&self.pending[..n]);
        self.pending.drain(..n);
        self.reads += 1;
        Ok(n)
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }

    fn describe(&self) -> String {
        format!(
            "MockDevice(writes={}, reads={}, queued={})",
            self.writes.len(),
            self.reads,
            self.pending.len()
        )
    }
}

/// Parse the CSW a mock produced, for assertions.
pub fn parse_csw(bytes: &[u8]) -> Option<Csw> {
    Csw::decode(bytes)
}
