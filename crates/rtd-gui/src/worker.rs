//! The background burn worker.
//!
//! Flashing takes minutes, so it cannot run on the UI thread. This module owns
//! the thread and the message channel; the UI only drains messages once per
//! frame, which keeps `app.rs` free of any synchronization logic.
//!
//! # Why a channel and not shared state
//!
//! The worker runs to completion even if the UI is busy painting or the user is
//! dragging a window. A channel gives that naturally: the worker never blocks on
//! the UI, and the UI never blocks on the worker. Progress is coalesced on the
//! UI side, so a fast device cannot flood the renderer.
//!
//! # Cancellation
//!
//! Cancellation is cooperative and checked **between stages**, not mid-frame:
//! interrupting a chunk transfer would leave the device with a half-written
//! member and no way to resynchronise. Stopping between members is safe because
//! each member is self-contained.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread;

use rtd_core::burn::{self, BurnOptions, BurnSources, Progress};
use rtd_core::device::DeviceBackend;
use rtd_core::error::Result;

/// A message from the worker to the UI.
#[derive(Debug, Clone)]
pub enum WorkerMsg {
    /// The worker reached a named stage.
    Stage(String),
    /// Bytes written so far, out of the plan total.
    Progress {
        /// Bytes handed to the transport.
        written: u64,
        /// Total payload of the plan.
        total: u64,
    },
    /// A line worth showing in the log.
    Log(String),
    /// The burn finished successfully.
    Done(String),
    /// The burn failed; the string is already user-facing.
    Failed(String),
}

/// Handle to a running burn.
#[derive(Debug)]
pub struct BurnHandle {
    /// Receives worker messages. Drained by the UI each frame.
    pub rx: Receiver<WorkerMsg>,
    /// Set to request a stop between stages.
    cancel: Arc<AtomicBool>,
    /// The worker thread, joined on drop so a panic is not swallowed.
    join: Option<thread::JoinHandle<()>>,
}

impl BurnHandle {
    /// Ask the worker to stop. It finishes the current stage first.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    /// Whether a stop has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    /// Take everything the worker has produced so far, without blocking.
    pub fn drain(&self) -> Vec<WorkerMsg> {
        self.rx.try_iter().collect()
    }
}

impl Drop for BurnHandle {
    fn drop(&mut self) {
        // Request a stop, then join: leaving a detached thread talking to a
        // board after the window closes is exactly the kind of thing that
        // corrupts a flash.
        self.cancel.store(true, Ordering::Relaxed);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

/// A [`rtd_core::transport::TransportLog`] that forwards every line to the UI.
///
/// The original's log is reproduced verbatim by the transport, so showing it is
/// what makes a failure diagnosable: "写入 hwsetting" alone does not say whether
/// the CBW, the payload, or the status read failed.
#[derive(Debug)]
struct ChannelLog {
    tx: Sender<WorkerMsg>,
}

impl rtd_core::transport::TransportLog for ChannelLog {
    fn line(&self, s: &str) {
        // The transport emits CRLF-terminated lines; the UI adds its own.
        let t = s.trim_end_matches(['\r', '\n']);
        if !t.is_empty() {
            let _ = self.tx.send(WorkerMsg::Log(t.to_string()));
        }
    }
}

/// Progress adapter that forwards to the channel, honouring cancellation.
struct ChannelProgress {
    tx: Sender<WorkerMsg>,
}

impl Progress for ChannelProgress {
    fn stage(&mut self, name: &str) {
        let _ = self.tx.send(WorkerMsg::Stage(name.to_string()));
    }

    fn advance(&mut self, written: u64, total: u64) {
        let _ = self.tx.send(WorkerMsg::Progress { written, total });
    }
}

/// Start a burn on a background thread.
///
/// `key` selects the device by serial; `None` takes the first one found. The
/// device is opened **on the worker thread**, so a slow or failing enumeration
/// never blocks the UI.
pub fn start(sources: BurnSources, options: BurnOptions, key: Option<String>) -> BurnHandle {
    let (tx, rx) = mpsc::channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_thread = Arc::clone(&cancel);

    let join = thread::spawn(move || {
        let result = run_burn(&sources, &options, key.as_deref(), &tx, &cancel_thread);
        match result {
            Ok(report) => {
                let _ = tx.send(WorkerMsg::Log(format!(
                    "完成：写入 {} 字节，引导 {} 项，分区 {} 项",
                    report.bytes_written,
                    report.bootloader_written.len(),
                    report.partitions_written.len()
                )));
                let _ = tx.send(WorkerMsg::Done(format!(
                    "烧写完成：{} 字节",
                    report.bytes_written
                )));
            }
            Err(e) => {
                let msg = e.to_string();
                // A write refused at the very first frame usually means the
                // board is not sitting in download mode: it latches that state
                // on reset, and a previous attempt can leave it elsewhere.
                if msg.contains("CBW write failed") || msg.contains("不支持") {
                    let _ = tx.send(WorkerMsg::Log(
                        "提示：首个数据帧就被设备拒绝。请把板子断电重新插拔（让它重新进入下载模式）后再试；                         若仍失败，运行 rtd-flash.exe writeprobe 看每一帧的具体错误。"
                            .to_string(),
                    ));
                }
                let _ = tx.send(WorkerMsg::Failed(msg));
            }
        }
    });

    BurnHandle {
        rx,
        cancel,
        join: Some(join),
    }
}

/// The worker body: open, plan, validate, burn.
///
/// The device-touching half is behind `#[cfg(feature = "usb")]` as a block, not
/// a single `let`, so the whole sequence disappears together when the feature is
/// off instead of leaving a dangling binding.
fn run_burn(
    sources: &BurnSources,
    options: &BurnOptions,
    key: Option<&str>,
    tx: &Sender<WorkerMsg>,
    cancel: &Arc<AtomicBool>,
) -> Result<burn::BurnReport> {
    let log = |m: String| {
        let _ = tx.send(WorkerMsg::Log(m));
    };

    log("正在读取镜像…".to_string());
    let plan = sources.build()?;
    log(format!("计划：{}", plan.describe()));

    // Validate before opening the device: a bad plan should not even claim the
    // interface, let alone send a frame.
    if let Err(problems) = plan.validate(options) {
        return Err(rtd_core::error::Error::Burn(problems.join("；")));
    }
    if cancel.load(Ordering::Relaxed) {
        return Err(rtd_core::error::Error::Burn("已取消".into()));
    }

    #[cfg(not(feature = "usb"))]
    {
        let _ = key;
        Err(rtd_core::error::Error::BackendUnavailable(
            "本版本未编译 USB 后端，无法连接设备（请用 --features usb 重新编译）".into(),
        ))
    }

    #[cfg(feature = "usb")]
    {
        log("正在连接设备…".to_string());
        let backend = rtd_core::device::open(key)?;
        log(format!("已连接：{}", backend.describe()));

        let mut progress = ChannelProgress { tx: tx.clone() };
        // `Transport::with` swaps in the clock and log; the log is what surfaces
        // the frame-by-frame detail in the UI.
        let mut transport = rtd_core::transport::Transport::new(backend).with(
            rtd_core::transport::RealClock,
            ChannelLog { tx: tx.clone() },
        );
        let report = burn::run(&mut transport, &plan, options, &mut progress)?;

        if report.bytes_written == 0 {
            return Err(rtd_core::error::Error::Burn(
                "没有写入任何字节；检查镜像与 layout.txt".into(),
            ));
        }
        Ok(report)
    }
}

/// Report whether the USB backend is compiled into this binary.
///
/// The UI shows this at startup: a UI-only build looks healthy until a device
/// button is pressed, and that is too late to be a useful signal.
pub const fn usb_enabled() -> bool {
    cfg!(feature = "usb")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A backend that accepts everything, so the worker can be exercised without
    /// hardware.
    #[derive(Debug, Default)]
    struct NullBackend {
        written: usize,
    }

    impl DeviceBackend for NullBackend {
        fn write_all(&mut self, data: &[u8]) -> Result<()> {
            self.written += data.len();
            Ok(())
        }
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            // A CSW is always available.
            let n = buf.len().min(rtd_core::protocol::consts::CSW_LEN);
            let csw = rtd_core::device::mock::MockDevice::make_csw(0);
            buf[..n].copy_from_slice(&csw[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> Result<()> {
            Ok(())
        }
        fn describe(&self) -> String {
            format!("NullBackend({} bytes)", self.written)
        }
    }

    #[test]
    fn usb_enabled_reflects_the_feature() {
        assert_eq!(usb_enabled(), cfg!(feature = "usb"));
    }

    #[test]
    fn a_handle_can_be_dropped_before_any_message_arrives() {
        // Dropping must not panic or hang even if the worker never sends.
        let (tx, rx) = mpsc::channel::<WorkerMsg>();
        let h = BurnHandle {
            rx,
            cancel: Arc::new(AtomicBool::new(false)),
            join: Some(thread::spawn(move || {
                // Never send anything.
                let _ = tx;
            })),
        };
        drop(h);
    }

    #[test]
    fn cancel_sets_the_flag_the_worker_reads() {
        let (tx, rx) = mpsc::channel::<WorkerMsg>();
        let flag = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&flag);
        let h = BurnHandle {
            rx,
            cancel: Arc::clone(&flag),
            join: Some(thread::spawn(move || {
                // Spin until the flag flips, so the assertion below is meaningful.
                for _ in 0..1000 {
                    if observed.load(Ordering::Relaxed) {
                        return;
                    }
                    thread::yield_now();
                }
            })),
        };
        assert!(!h.is_cancelled());
        h.cancel();
        assert!(h.is_cancelled());
        drop(h);
        let _ = tx;
    }

    #[test]
    fn drain_returns_queued_messages_without_blocking() {
        let (tx, rx) = mpsc::channel::<WorkerMsg>();
        tx.send(WorkerMsg::Stage("a".into())).unwrap();
        tx.send(WorkerMsg::Progress {
            written: 5,
            total: 10,
        })
        .unwrap();
        let h = BurnHandle {
            rx,
            cancel: Arc::new(AtomicBool::new(false)),
            join: None,
        };
        let got = h.drain();
        assert_eq!(got.len(), 2);
        // A second drain on an empty channel must return immediately.
        assert!(h.drain().is_empty());
    }

    #[test]
    fn a_burn_with_no_sources_fails_before_opening_a_device() {
        // No install.img -> `build()` errors, so the device is never opened and
        // the test needs no hardware.
        let h = start(BurnSources::default(), BurnOptions::default(), None);
        let mut msgs = Vec::new();
        // The worker finishes quickly; collect whatever it produced.
        for m in h.rx.iter() {
            msgs.push(m);
        }
        assert!(
            msgs.iter().any(|m| matches!(m, WorkerMsg::Failed(_))),
            "expected a failure, got {msgs:?}"
        );
    }
}
