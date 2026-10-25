//! Application state and the actions that mutate it — **no GUI code**.
//!
//! Splitting the state machine out of the rendering is what makes the GUI
//! testable: every button in `app.rs` is a thin call into a method here, and
//! `tests/` can drive this module headlessly.
//!
//! The flow mirrors the original dialog:
//!
//! 1. pick `install.img` (and optionally a `SYSTEM.ini`)
//! 2. inspect it: project layout, partition table, bootloader members
//! 3. enumerate devices
//! 4. choose burn options
//! 5. start, watch progress and the log

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use rtd_core::device::filter::{self, UsbDeviceInfo};
use rtd_core::error::Result;
use rtd_core::hwconfig::HwSetting;
use rtd_core::image::{self, Partition, ProjectKind, SystemIni};
use rtd_core::protocol::{FlashInfo, Opcode};

/// Severity of a log line.
///
/// The `Ord` order is **by increasing severity**, and the derive gets that from
/// the declaration order:
///
/// ```text
/// Trace < Info < Warn < Error
/// ```
///
/// This matters because the log filter is `level >= Warn`. An earlier version
/// declared `Trace` last, which made it sort *above* `Error` and leaked raw
/// protocol chatter into the "warnings only" view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// The original tool's raw protocol chatter; lowest priority.
    Trace,
    /// Routine progress.
    Info,
    /// Something notable but not fatal.
    Warn,
    /// A failure.
    Error,
}

/// One log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    /// Severity.
    pub level: Level,
    /// Which device it came from, when known.
    pub device: Option<String>,
    /// Text.
    pub text: String,
}

impl LogLine {
    /// An info line.
    pub fn info(text: impl Into<String>) -> Self {
        Self {
            level: Level::Info,
            device: None,
            text: text.into(),
        }
    }
    /// A warning line.
    pub fn warn(text: impl Into<String>) -> Self {
        Self {
            level: Level::Warn,
            device: None,
            text: text.into(),
        }
    }
    /// An error line.
    pub fn error(text: impl Into<String>) -> Self {
        Self {
            level: Level::Error,
            device: None,
            text: text.into(),
        }
    }
    /// A trace line (raw protocol dump).
    pub fn trace(text: impl Into<String>) -> Self {
        Self {
            level: Level::Trace,
            device: None,
            text: text.into(),
        }
    }
    /// Attach a device key.
    pub fn for_device(mut self, key: impl Into<String>) -> Self {
        self.device = Some(key.into());
        self
    }
}

/// How full a bounded log ring is.
pub const LOG_CAPACITY: usize = 20_000;

/// What a device worker is doing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceState {
    /// Discovered, not started.
    Idle,
    /// Working, with a stage label and 0..=100 progress.
    Working {
        /// Human-readable stage.
        stage: String,
        /// Percent complete, 0..=100.
        percent: u8,
    },
    /// Finished successfully.
    Done,
    /// Failed with a message.
    Failed(String),
    /// Cancelled by the user.
    Cancelled,
}

impl DeviceState {
    /// Whether the worker has stopped.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            DeviceState::Done | DeviceState::Failed(_) | DeviceState::Cancelled
        )
    }

    /// Short label for the table.
    pub fn label(&self) -> &str {
        match self {
            DeviceState::Idle => "空闲",
            DeviceState::Working { .. } => "烧写中",
            DeviceState::Done => "完成",
            DeviceState::Failed(_) => "失败",
            DeviceState::Cancelled => "已取消",
        }
    }
}

/// One row in the device table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRow {
    /// The discovered device.
    pub info: UsbDeviceInfo,
    /// Current worker state.
    pub state: DeviceState,
    /// Wall-clock seconds the run took, once finished.
    pub elapsed_s: Option<u32>,
}

impl DeviceRow {
    /// Stable identity (serial, else `bus:address`).
    pub fn key(&self) -> String {
        self.info.key()
    }
}

/// The burn options, mirroring `SYSTEM.ini`'s `[SYSTEM]` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurnOptions {
    /// Compare after writing (`COMPARE DATA`).
    pub compare_data: bool,
    /// Burn the factory area (`BURN FACTORY`).
    pub burn_factory: bool,
    /// Burn secure storage (`BURN SE STORAGE`).
    pub burn_se_storage: bool,
    /// Burn eFuse (`ONLY BURN EFUSE`).
    pub only_burn_efuse: bool,
    /// NAS enable (`NAS ENABLE`).
    pub nas_enable: bool,
    /// LK enable (`LK ENABLE`).
    pub lk_enable: bool,
    /// Single-write mode (`SINGLE MODE`).
    pub single_mode: bool,
    /// Go-DDR hack for the 1195 (`GO DDR`).
    pub go_ddr: bool,
}

impl Default for BurnOptions {
    fn default() -> Self {
        // Mirrors the shipped SYSTEM.ini: LK on, everything else off.
        Self {
            compare_data: false,
            burn_factory: false,
            burn_se_storage: false,
            only_burn_efuse: false,
            nas_enable: false,
            lk_enable: true,
            single_mode: false,
            go_ddr: false,
        }
    }
}

impl BurnOptions {
    /// Read the options out of a parsed `SYSTEM.ini`.
    pub fn from_ini(ini: &SystemIni) -> Self {
        let d = Self::default();
        Self {
            compare_data: ini.compare_data.unwrap_or(d.compare_data),
            burn_factory: ini.burn_factory.unwrap_or(d.burn_factory),
            burn_se_storage: ini.burn_se_storage.unwrap_or(d.burn_se_storage),
            only_burn_efuse: ini.only_burn_efuse.unwrap_or(d.only_burn_efuse),
            nas_enable: ini.nas_enable.unwrap_or(d.nas_enable),
            lk_enable: ini.lk_enable.unwrap_or(d.lk_enable),
            single_mode: ini.single_mode.unwrap_or(d.single_mode),
            go_ddr: ini.go_ddr.unwrap_or(d.go_ddr),
        }
    }

    /// Features this build does **not** implement, and why.
    ///
    /// Both are deliberate scope decisions: NAND bad-block remapping needs the
    /// 2290-line `nand_burner` path, and secure-key burning needs the absent
    /// `GenKeyBag.exe`. The GUI surfaces these instead of silently ignoring the
    /// checkbox.
    pub fn unsupported(&self, flash_type: u8) -> Vec<&'static str> {
        let mut out = Vec::new();
        if flash_type != 2 {
            out.push("本版本未实现 NAND/NOR 烧写");
        }
        if self.burn_se_storage {
            out.push("烧写安全存储需要 GenKeyBag.exe，原包中未提供");
        }
        if self.only_burn_efuse {
            out.push("eFuse 烧写需要安全密钥流程（未实现）");
        }
        out
    }
}

/// What is loaded from disk.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoadedImage {
    /// Path of the image.
    pub path: PathBuf,
    /// Detected project layout.
    pub project: ProjectKind,
    /// Partition table parsed from `layout.txt`.
    pub partitions: Vec<Partition>,
    /// Bootloader members with their planned sectors.
    pub bootloader: Vec<(String, usize, u64)>,
    /// Path of the `SYSTEM.ini` in use, if any.
    pub system_ini_path: Option<PathBuf>,
    /// Geometry derived from `SYSTEM.ini`.
    pub flash_info: FlashInfo,
    /// Raw `SYSTEM.ini`, when loaded.
    pub system_ini: Option<SystemIni>,
    /// The plan the burner would execute, for an accurate preview: it includes
    /// the factory-area writes and the streamed-member markers, which the plain
    /// `layout.txt` view cannot show. Cheap to build -- large payloads stay in
    /// the archive and are never read here.
    pub plan: Option<rtd_core::burn::BurnPlan>,
}

/// The whole application state.
#[derive(Debug)]
pub struct AppState {
    /// Image currently loaded.
    pub image: Option<LoadedImage>,
    /// Devices and their per-device state.
    pub devices: Vec<DeviceRow>,
    /// Burn options.
    pub options: BurnOptions,
    /// Bounded log ring.
    pub log: VecDeque<LogLine>,
    /// Only show warnings and errors.
    pub log_warnings_only: bool,
    /// Whether a run is in progress.
    pub running: bool,
    /// Path typed into the image field.
    pub image_path_input: String,
    /// Path typed into the SYSTEM.ini field.
    pub ini_path_input: String,
    /// hwsetting blob currently open in the editor, if any.
    pub hwsetting: Option<HwSetting>,
    /// Path the hwsetting came from.
    pub hwsetting_path: Option<PathBuf>,
    /// Last error shown to the user.
    pub last_error: Option<String>,
    /// Status line.
    pub status: String,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    /// A fresh state with a clean log.
    pub fn new() -> Self {
        let mut s = Self {
            image: None,
            devices: Vec::new(),
            options: BurnOptions::default(),
            log: VecDeque::with_capacity(1024),
            log_warnings_only: false,
            running: false,
            image_path_input: String::new(),
            ini_path_input: String::new(),
            hwsetting: None,
            hwsetting_path: None,
            last_error: None,
            status: "ready".into(),
        };
        s.push_log(LogLine::info("RTD129x 线刷工具已就绪"));
        s
    }

    // -- logging -----------------------------------------------------------

    /// Append a log line, dropping the oldest when the ring is full.
    pub fn push_log(&mut self, line: LogLine) {
        if self.log.len() >= LOG_CAPACITY {
            self.log.pop_front();
        }
        self.log.push_back(line);
    }

    /// The lines that should be displayed, given the filter.
    pub fn visible_log(&self) -> impl Iterator<Item = &LogLine> {
        let warnings_only = self.log_warnings_only;
        self.log
            .iter()
            .filter(move |l| !warnings_only || l.level >= Level::Warn)
    }

    /// Number of error lines currently retained.
    pub fn error_count(&self) -> usize {
        self.log.iter().filter(|l| l.level == Level::Error).count()
    }

    // -- image -------------------------------------------------------------

    /// Load an `install.img`: list members, detect the project, parse the
    /// partition table.
    ///
    /// Nothing is extracted to disk; the tar is streamed to read `layout.txt`
    /// in memory. (The original unpacks to `UnTarTmp` because it shells out to
    /// helpers; we do not need to.)
    pub fn load_image(&mut self, path: &Path) -> Result<()> {
        self.last_error = None;
        let members = image::install_img::list_members(path)?;
        self.push_log(LogLine::info(format!(
            "{}：{} 个成员",
            path.display(),
            members.len()
        )));

        // Find the project directory anywhere in the member paths. Scanning
        // only the first component fails on the very common `./package5/...`
        // spelling, because that component is just `.`.
        let project = match image::install_img::detect_project_in_members(
            members.iter().map(|(n, _)| n.as_str()),
        ) {
            Ok(p) => p,
            Err(e) => {
                // Say what the archive does contain -- "not found" alone leaves
                // the user with nothing to act on.
                let tops = image::install_img::top_level_entries(
                    members.iter().map(|(n, _)| n.as_str()),
                    12,
                );
                self.push_log(LogLine::error(format!(
                    "无法识别镜像布局；顶层条目：{}",
                    tops.join(", ")
                )));
                return Err(e);
            }
        };
        self.push_log(LogLine::info(format!("项目布局：{:?}", project)));

        // Read layout.txt out of the archive without extracting.
        // Empty for a flat image, where `layout.txt` is at the archive root.
        let layout_prefix = project.member_prefix();
        let mut layout = read_member(path, &layout_prefix, image::install_img::LAYOUT_FILE)?;
        if layout.is_none() {
            // Project detection keys off an `omv/`-style directory, but the
            // CM360 line-flash packages keep `layout.txt` at the archive root
            // next to it -- the burner finds it by basename, so the preview
            // must too instead of logging a bogus "not found".
            layout = read_member(path, "", image::install_img::LAYOUT_FILE)?;
        }
        let partitions = match layout {
            Some(bytes) => {
                let text = String::from_utf8_lossy(&bytes).into_owned();
                let parts = image::layout_txt::parse(&text)?;
                self.push_log(LogLine::info(format!(
                    "layout.txt：{} 个分区",
                    parts.len()
                )));
                parts
            }
            None => {
                self.push_log(LogLine::warn("镜像中未找到 layout.txt"));
                Vec::new()
            }
        };

        // Bootloader members, when the image carries them.
        let bootloader = members
            .iter()
            .filter_map(|(name, size)| {
                let base = name.rsplit(['/', '\\']).next()?;
                image::Member::from_file_name(base).map(|m| (m.file_name().to_string(), *size as usize, m))
            })
            .map(|(name, size, m)| (name, size, m.logged_lba().unwrap_or(0)))
            .collect::<Vec<_>>();

        // SYSTEM.ini, if the user supplied one, drives the geometry.
        let (ini, ini_path) = match &self.image_path_input {
            _ if !self.ini_path_input.trim().is_empty() => {
                let p = PathBuf::from(self.ini_path_input.trim());
                match SystemIni::from_path(&p) {
                    Ok(s) => {
                        self.push_log(LogLine::info(format!("配置文件：{}", p.display())));
                        self.options = BurnOptions::from_ini(&s);
                        (Some(s), Some(p))
                    }
                    Err(e) => {
                        self.push_log(LogLine::warn(format!("配置文件已忽略：{e}")));
                        (None, None)
                    }
                }
            }
            _ => (None, None),
        };
        let flash_info = ini
            .as_ref()
            .map(|s| s.flash_info())
            .unwrap_or_default();

        // Build the plan the burner would actually execute, for an accurate
        // preview. This only walks tar headers and reads small members (layout,
        // factory.tar), so a 7.8 GB package previews in about a second -- the
        // streamed partitions stay in the archive.
        let preview_plan = rtd_core::burn::BurnSources {
            install_img: Some(path.to_path_buf()),
            bootloader_tar: None,
            hwsetting: None,
            system_ini: ini_path.clone(),
        }
        .build()
        .ok();
        let (total, count) = match &preview_plan {
            Some(plan) => (plan.total_bytes(), plan.partitions.len()),
            None => (
                partitions.iter().map(|p| p.size).sum(),
                partitions.len(),
            ),
        };
        self.push_log(LogLine::info(format!(
            "镜像总负载 {} 字节，共 {} 个写入项（含 factory 区）",
            total, count
        )));

        self.image = Some(LoadedImage {
            path: path.to_path_buf(),
            project,
            partitions,
            bootloader,
            system_ini_path: ini_path,
            flash_info,
            system_ini: ini,
            plan: preview_plan,
        });
        self.status = format!("已加载 {}", path.display());
        Ok(())
    }

    /// The opcodes this plan would send, in order. Used for the summary panel
    /// and asserted in the tests.
    pub fn planned_opcodes(&self) -> Vec<Opcode> {
        let mut out = Vec::new();
        let Some(img) = &self.image else {
            return out;
        };
        out.push(Opcode::UsbHwSetting);
        out.push(Opcode::DdrEnable);
        if !img.bootloader.is_empty() {
            out.extend(std::iter::repeat(Opcode::Write).take(img.bootloader.len()));
        }
        let writes = img
            .plan
            .as_ref()
            .map_or(img.partitions.len(), |p| p.partitions.len());
        out.extend(std::iter::repeat(Opcode::Write).take(writes));
        if self.options.compare_data {
            out.push(Opcode::ReadVerify);
        }
        if self.options.only_burn_efuse {
            out.push(Opcode::EfuseBurn);
        }
        out
    }

    // -- devices -----------------------------------------------------------

    /// Replace the device list, keeping existing per-device state for keys that
    /// are still present (so a refresh does not reset progress).
    pub fn set_devices(&mut self, mut found: Vec<UsbDeviceInfo>) {
        filter::sort_stable(&mut found);
        let previous: Vec<DeviceRow> = std::mem::take(&mut self.devices);
        self.devices = found
            .into_iter()
            .map(|info| {
                let key = info.key();
                let old = previous.iter().find(|r| r.key() == key);
                DeviceRow {
                    info,
                    state: old.map(|o| o.state.clone()).unwrap_or(DeviceState::Idle),
                    elapsed_s: old.and_then(|o| o.elapsed_s),
                }
            })
            .collect();
    }

    /// Devices that should be burned (all of them, honouring the limit).
    pub fn selected_devices(&self) -> Vec<&DeviceRow> {
        self.devices
            .iter()
            .filter(|d| !d.state.is_terminal())
            .collect()
    }

    /// Mark every device as working on `stage`.
    pub fn begin_run(&mut self, stage: &str) {
        self.running = true;
        for d in &mut self.devices {
            d.state = DeviceState::Working {
                stage: stage.into(),
                percent: 0,
            };
            d.elapsed_s = None;
        }
        self.status = "烧写中".into();
    }

    /// Update the stage label on every device that is still working.
    ///
    /// The worker drives all attached devices from one thread, so a stage change
    /// applies to all of them at once.
    pub fn set_progress_stage(&mut self, stage: &str) {
        for d in &mut self.devices {
            if let DeviceState::Working { percent, .. } = d.state {
                d.state = DeviceState::Working {
                    stage: stage.to_string(),
                    percent,
                };
            }
        }
    }

    /// Update the percentage on every device from byte counts.
    ///
    /// `total == 0` is treated as "unknown" and leaves the percentage alone,
    /// rather than reporting a misleading 0%.
    pub fn set_progress_bytes(&mut self, written: u64, total: u64) {
        let percent = if total == 0 {
            return;
        } else {
            ((written.saturating_mul(100) / total).min(100)) as u8
        };
        for d in &mut self.devices {
            if let DeviceState::Working { stage, .. } = &d.state {
                let stage = stage.clone();
                d.state = DeviceState::Working { stage, percent };
            }
        }
    }

    /// Update one device's stage and percentage.
    pub fn set_progress(&mut self, key: &str, stage: &str, percent: u8) {
        if let Some(d) = self.devices.iter_mut().find(|d| d.key() == key) {
            d.state = DeviceState::Working {
                stage: stage.into(),
                percent: percent.min(100),
            };
        }
    }

    /// Mark one device finished.
    pub fn finish_device(&mut self, key: &str, state: DeviceState, elapsed_s: u32) {
        if let Some(d) = self.devices.iter_mut().find(|d| d.key() == key) {
            d.state = state;
            d.elapsed_s = Some(elapsed_s);
        }
        if self.devices.iter().all(|d| d.state.is_terminal()) {
            self.running = false;
            self.status = "已完成".into();
        }
    }

    /// Ask for cancellation (the worker checks this between chunks).
    pub fn request_cancel(&mut self) {
        self.running = false;
        for d in &mut self.devices {
            if !d.state.is_terminal() {
                d.state = DeviceState::Cancelled;
            }
        }
        self.status = "已取消".into();
        self.push_log(LogLine::warn("用户取消"));
    }

    /// Overall progress across all devices, 0..=100.
    pub fn overall_percent(&self) -> u8 {
        if self.devices.is_empty() {
            return 0;
        }
        let sum: u32 = self
            .devices
            .iter()
            .map(|d| match &d.state {
                DeviceState::Working { percent, .. } => *percent as u32,
                DeviceState::Done => 100,
                _ => 0,
            })
            .sum();
        (sum / self.devices.len() as u32) as u8
    }

    /// Blocking reasons that prevent a run from starting.
    pub fn start_blockers(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.image.is_none() {
            out.push("请先加载 install.img".into());
        }
        if self.devices.is_empty() {
            out.push("未连接设备（正在查找 0bda:1195）".into());
        }
        if self.running {
            out.push("已有烧写任务进行中".into());
        }
        if let Some(img) = &self.image {
            for msg in self.options.unsupported(img.flash_info.flash_type) {
                out.push(msg.to_string());
            }
        }
        out
    }

    /// Whether the Start button should be enabled.
    pub fn can_start(&self) -> bool {
        self.start_blockers().is_empty()
    }

    // -- hwsetting ---------------------------------------------------------

    /// Open a hwsetting blob for inspection/editing.
    pub fn load_hwsetting(&mut self, path: &Path) -> Result<()> {
        let bytes = std::fs::read(path)?;
        let hw = HwSetting::from_encrypted(&bytes)?;
        let counts = hw.counts();
        self.push_log(LogLine::info(format!(
            "{}：{} 条指令（w{} / p{} / m{} / n{}），尾部 {} 字节",
            path.file_name().unwrap_or_default().to_string_lossy(),
            counts.total(),
            counts.write,
            counts.poll,
            counts.mask,
            counts.nop,
            hw.trailer.len()
        )));
        self.hwsetting = Some(hw);
        self.hwsetting_path = Some(path.to_path_buf());
        self.status = format!("hwsetting {}", path.display());
        Ok(())
    }

    /// The hwsetting as editable `.config` text.
    pub fn hwsetting_text(&self) -> String {
        self.hwsetting
            .as_ref()
            .map(|h| rtd_core::hwconfig::op::to_config_text(&h.ops))
            .unwrap_or_default()
    }

    /// Replace the instruction list from `.config` text, keeping the trailer.
    ///
    /// This is the supported regeneration path: the trailer's MAC was never
    /// recovered, so it is reused verbatim from the loaded blob.
    pub fn set_hwsetting_text(&mut self, text: &str) -> Result<()> {
        let hw = self
            .hwsetting
            .as_mut()
            .ok_or_else(|| rtd_core::error::Error::HwConfig("尚未加载 hwsetting".into()))?;
        hw.ops = rtd_core::hwconfig::op::parse_config(text)?;
        hw.validate_trailer()?;
        let counts = hw.counts();
        self.push_log(LogLine::info(format!(
            "hwsetting 已修改：{} 条指令（w{} / p{} / m{} / n{}）",
            counts.total(),
            counts.write,
            counts.poll,
            counts.mask,
            counts.nop
        )));
        Ok(())
    }

    /// Write the current hwsetting back out, encrypted.
    pub fn save_hwsetting(&self, path: &Path) -> Result<()> {
        let hw = self
            .hwsetting
            .as_ref()
            .ok_or_else(|| rtd_core::error::Error::HwConfig("尚未加载 hwsetting".into()))?;
        let enc = hw.to_encrypted()?;
        std::fs::write(path, enc)?;
        Ok(())
    }
}

/// Read one member out of a tar, streaming, without extracting anything.
fn read_member(image: &Path, dir_prefix: &str, file: &str) -> Result<Option<Vec<u8>>> {
    use std::io::Read;
    let f = std::fs::File::open(image)?;
    let mut ar = tar::Archive::new(std::io::BufReader::new(f));
    let want = format!("{dir_prefix}{file}");
    for entry in ar
        .entries()
        .map_err(|e| rtd_core::error::Error::Image(e.to_string()))?
    {
        let mut entry = entry.map_err(|e| rtd_core::error::Error::Image(e.to_string()))?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let name = entry
            .path()
            .map_err(|e| rtd_core::error::Error::Image(e.to_string()))?
            .to_string_lossy()
            .replace('\\', "/");
        // A flat image has `layout.txt` at the root, so an empty prefix must
        // match the basename exactly rather than any nested file of that name.
        let hit = if dir_prefix.is_empty() {
            let base = name.rsplit('/').next().unwrap_or(&name);
            base.eq_ignore_ascii_case(file)
        } else {
            name == want || name.ends_with(&format!("/{file}"))
        };
        if hit {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            return Ok(Some(buf));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(vid: u16, pid: u16, addr: u8, serial: Option<&str>) -> UsbDeviceInfo {
        UsbDeviceInfo {
            bus: 0,
            address: addr,
            vendor_id: vid,
            product_id: pid,
            serial: serial.map(str::to_string),
            product: None,
            interface_count: 1,
        }
    }

    fn tmp(tag: &str) -> PathBuf {
        let base = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into());
        let p = PathBuf::from(base).join(format!("rtd-gui-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn new_state_is_ready_and_has_one_log_line() {
        let s = AppState::new();
        assert_eq!(s.log.len(), 1);
        assert!(!s.running);
        assert!(s.image.is_none());
        assert!(s.devices.is_empty());
        assert_eq!(s.overall_percent(), 0);
    }

    #[test]
    fn log_is_bounded() {
        let mut s = AppState::new();
        for i in 0..(LOG_CAPACITY + 500) {
            s.push_log(LogLine::info(format!("line {i}")));
        }
        assert_eq!(s.log.len(), LOG_CAPACITY);
        // the oldest were dropped, so the tail is retained
        assert!(s.log.back().unwrap().text.contains(&format!("{}", LOG_CAPACITY + 499)));
    }

    #[test]
    fn log_filter_keeps_only_warnings_and_errors() {
        let mut s = AppState::new();
        // Discard the startup line so the counts below are unambiguous.
        s.log.clear();
        s.push_log(LogLine::info("i"));
        s.push_log(LogLine::warn("w"));
        s.push_log(LogLine::error("e"));
        s.push_log(LogLine::trace("t"));

        // Filter off: every retained line is visible, severity notwithstanding.
        s.log_warnings_only = false;
        assert_eq!(s.visible_log().count(), 4);
        assert_eq!(s.visible_log().count(), s.log.len());

        // Filter on: only Warn and Error survive. `Trace` must NOT, which is
        // what pins the `Ord` order as Trace < Info < Warn < Error.
        s.log_warnings_only = true;
        let kept: Vec<&str> = s.visible_log().map(|l| l.text.as_str()).collect();
        assert_eq!(kept, vec!["w", "e"]);
        assert_eq!(s.error_count(), 1);
    }

    #[test]
    fn level_orders_by_increasing_severity() {
        assert!(Level::Trace < Level::Info);
        assert!(Level::Info < Level::Warn);
        assert!(Level::Warn < Level::Error);
        assert!(Level::Trace < Level::Error);
        // The filter threshold is `>= Warn`, so trace/info must be below it.
        assert!(Level::Trace < Level::Warn);
        assert!(Level::Info < Level::Warn);
    }

    #[test]
    fn devices_are_sorted_and_state_survives_a_refresh() {
        let mut s = AppState::new();
        s.set_devices(vec![
            dev(0x0BDA, 0x1195, 9, Some("bbb")),
            dev(0x0BDA, 0x1195, 1, Some("aaa")),
            dev(0x1234, 0x5678, 5, Some("other")),
        ]);
        // the filter is applied by the caller (usb::list_devices); set_devices
        // only sorts, so all three land here
        assert_eq!(s.devices.len(), 3);
        assert_eq!(s.devices[0].key(), "aaa");

        // progress then a refresh must not reset it
        s.set_progress("aaa", "writing", 42);
        s.set_devices(vec![
            dev(0x0BDA, 0x1195, 9, Some("bbb")),
            dev(0x0BDA, 0x1195, 1, Some("aaa")),
        ]);
        let aaa = s.devices.iter().find(|d| d.key() == "aaa").unwrap();
        assert_eq!(
            aaa.state,
            DeviceState::Working {
                stage: "writing".into(),
                percent: 42
            }
        );
    }

    #[test]
    fn run_lifecycle_sets_and_clears_running() {
        let mut s = AppState::new();
        s.set_devices(vec![
            dev(0x0BDA, 0x1195, 1, Some("a")),
            dev(0x0BDA, 0x1195, 2, Some("b")),
        ]);
        s.begin_run("hwsetting");
        assert!(s.running);
        s.set_progress("a", "hwsetting", 50);
        s.finish_device("a", DeviceState::Done, 12);
        assert!(s.running, "one device is still working");
        // 'b' still working -> overall is (100 + 0)/2
        assert_eq!(s.overall_percent(), 50);
        s.finish_device("b", DeviceState::Done, 13);
        assert!(!s.running, "all devices terminal");
        assert_eq!(s.overall_percent(), 100);
    }

    #[test]
    fn cancel_marks_pending_devices() {
        let mut s = AppState::new();
        s.set_devices(vec![dev(0x0BDA, 0x1195, 1, Some("a"))]);
        s.begin_run("start");
        s.request_cancel();
        assert!(!s.running);
        assert_eq!(s.devices[0].state, DeviceState::Cancelled);
        assert!(s.devices[0].state.is_terminal());
    }

    #[test]
    fn start_blockers_explain_what_is_missing() {
        let mut s = AppState::new();
        let b = s.start_blockers();
        assert!(b.iter().any(|m| m.contains("install.img")), "{b:?}");
        assert!(b.iter().any(|m| m.contains("未连接设备")), "{b:?}");
        assert!(!s.can_start());
    }

    #[test]
    fn nand_and_efuse_are_reported_as_unsupported() {
        let mut s = AppState::new();
        s.set_devices(vec![dev(0x0BDA, 0x1195, 1, Some("a"))]);
        // an eMMC image would be fine; fake a NAND geometry
        s.image = Some(LoadedImage {
            path: PathBuf::from("x.img"),
            project: ProjectKind::Generic,
            partitions: vec![],
            bootloader: vec![],
            system_ini_path: None,
            flash_info: FlashInfo {
                flash_type: 0, // NAND
                ..Default::default()
            },
            system_ini: None,
            plan: None,
        });
        let blockers = s.start_blockers();
        assert!(
            blockers.iter().any(|m| m.contains("NAND")),
            "{blockers:?}"
        );

        s.options.only_burn_efuse = true;
        let blockers = s.start_blockers();
        assert!(
            blockers.iter().any(|m| m.contains("eFuse")),
            "{blockers:?}"
        );
        assert!(!s.can_start());
    }

    #[test]
    fn an_emmc_image_with_a_device_can_start() {
        let mut s = AppState::new();
        s.set_devices(vec![dev(0x0BDA, 0x1195, 1, Some("a"))]);
        s.image = Some(LoadedImage {
            path: PathBuf::from("x.img"),
            project: ProjectKind::Package5,
            partitions: vec![],
            bootloader: vec![],
            system_ini_path: None,
            flash_info: FlashInfo::default(), // eMMC
            system_ini: None,
            plan: None,
        });
        assert_eq!(s.start_blockers(), Vec::<String>::new());
        assert!(s.can_start());
    }

    #[test]
    fn loading_a_synthetic_image_detects_the_project_and_layout() {
        let root = tmp("loadimg");
        let img = root.join("install.img");
        image::install_img::write_fixture_image(
            &img,
            ProjectKind::Package5,
            &[
                (
                    "layout.txt",
                    b"target=FW_KERNEL offset=0x3000000 size=0x800000\n".as_slice(),
                ),
                ("bootcode.bin", b"abc".as_slice()),
            ],
        )
        .unwrap();

        let mut s = AppState::new();
        s.load_image(&img).unwrap();
        let loaded = s.image.as_ref().unwrap();
        assert_eq!(loaded.project, ProjectKind::Package5);
        assert_eq!(loaded.partitions.len(), 1);
        assert_eq!(loaded.partitions[0].offset, 0x300_0000);
        assert_eq!(loaded.partitions[0].size, 0x80_0000);
        assert!(
            s.log.iter().any(|l| l.text.contains("layout.txt：1 个分区")),
            "log was: {:?}",
            s.log.iter().map(|l| &l.text).collect::<Vec<_>>()
        );
    }

    #[test]
    fn loading_an_image_builds_the_real_burn_plan_for_preview() {
        // The preview must be the plan the burner would run (factory writes,
        // streaming markers), not just `layout.txt`. This wires `load_image`
        // through `BurnSources::build`.
        let root = tmp("previewplan");
        let img = root.join("install.img");
        image::install_img::write_fixture_image(
            &img,
            ProjectKind::Package5,
            &[
                (
                    "layout.txt",
                    b"target=FW_KERNEL offset=0x3000000 size=0x800000\n".as_slice(),
                ),
                ("kernel.bin", b"abc".as_slice()),
            ],
        )
        .unwrap();

        let mut s = AppState::new();
        s.load_image(&img).unwrap();
        let loaded = s.image.as_ref().unwrap();
        let plan = loaded.plan.as_ref().expect("preview plan built");
        assert_eq!(plan.partitions.len(), 1);
        assert_eq!(plan.partitions[0].payload_len(), 3, "kernel.bin payload");
        assert_eq!(plan.total_bytes(), 3);

        // The opcode summary follows the real plan's write count.
        let writes = s
            .planned_opcodes()
            .iter()
            .filter(|o| **o == Opcode::Write)
            .count();
        assert_eq!(writes, plan.partitions.len());
    }

    /// Build a tar whose member names carry the given prefix.
    ///
    /// `write_fixture_image` always emits clean `package5/...` names, but real
    /// archives routinely store `./package5/...`, which is the spelling that
    /// broke project detection.
    fn write_prefixed_image(path: &Path, prefix: &str, project: &str, layout: &[u8]) {
        let f = std::fs::File::create(path).unwrap();
        let mut b = tar::Builder::new(f);
        let name = format!("{prefix}{project}/layout.txt");
        let mut h = tar::Header::new_ustar();
        h.set_size(layout.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, &name, layout).unwrap();

        let payload = vec![0u8; 512];
        let name = format!("{prefix}{project}/bootcode.bin");
        let mut h = tar::Header::new_ustar();
        h.set_size(payload.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, &name, payload.as_slice()).unwrap();
        b.finish().unwrap();
    }

    #[test]
    fn a_dot_slash_prefixed_image_loads() {
        // Regression: an image with `./package5/...` names used to fail with
        // "cannot get untartemp project filename", because only the first path
        // component was inspected and that component is `.`.
        let root = tmp("dot-prefix");
        let img = root.join("install.img");
        write_prefixed_image(
            &img,
            "./",
            "package5",
            b"target=FW_KERNEL offset=0x3000000 size=0x800000\n",
        );

        let mut s = AppState::new();
        s.load_image(&img).unwrap();
        let loaded = s.image.as_ref().unwrap();
        assert_eq!(loaded.project, ProjectKind::Package5);
        assert_eq!(loaded.partitions.len(), 1);
        assert_eq!(loaded.partitions[0].target, "FW_KERNEL");
    }

    #[test]
    fn a_deeply_nested_image_loads() {
        let root = tmp("nested-proj");
        let img = root.join("install.img");
        write_prefixed_image(
            &img,
            "out/images/w2/",
            "omv",
            b"target=A offset=0x0 size=0x100\n",
        );

        let mut s = AppState::new();
        s.load_image(&img).unwrap();
        assert_eq!(s.image.as_ref().unwrap().project, ProjectKind::Omv);
    }

    #[test]
    fn a_failed_detection_lists_what_the_archive_contains() {
        // The error alone is not actionable; the log must say what was found.
        let root = tmp("bad-layout");
        let img = root.join("install.img");
        {
            let f = std::fs::File::create(&img).unwrap();
            let mut b = tar::Builder::new(f);
            let mut h = tar::Header::new_ustar();
            h.set_size(4);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, "weird/stuff.bin", b"abcd".as_slice())
                .unwrap();
            b.finish().unwrap();
        }

        let mut s = AppState::new();
        let err = s.load_image(&img).unwrap_err();
        assert!(err.to_string().contains("package 5 or omv or generic"), "{err}");
        assert!(
            s.log.iter().any(|l| l.text.contains("顶层条目") && l.text.contains("weird")),
            "the log should name the entries that were found: {:?}",
            s.log.iter().map(|l| &l.text).collect::<Vec<_>>()
        );
    }

    #[test]
    fn an_image_without_a_project_directory_is_rejected() {
        let root = tmp("noproj");
        let img = root.join("install.img");
        image::install_img::write_fixture_image(
            &img,
            ProjectKind::Generic,
            &[("other.txt", b"x".as_slice())],
        )
        .unwrap();
        // Rename the member so the project dir is unrecognised: easiest is to
        // build a tar manually with no project directory at all.
        let f = std::fs::File::create(&img).unwrap();
        let mut b = tar::Builder::new(f);
        let mut h = tar::Header::new_ustar();
        h.set_size(1);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, "random/file.txt", b"x".as_slice()).unwrap();
        b.finish().unwrap();

        let mut s = AppState::new();
        let err = s.load_image(&img).unwrap_err();
        assert!(
            err.to_string().contains("package 5 or omv or generic"),
            "{err}"
        );
    }

    #[test]
    fn system_ini_supplies_the_geometry_and_options() {
        let root = tmp("ini");
        let ini = root.join("SYSTEM.ini");
        std::fs::write(
            &ini,
            "[MULTI FLASH TYPE]\nFLASH COMBO TYPE=EMMC\n\
             [INFORMATION]\nONE WRITE SIZE=2\nWRITE RANGE=256\n\
             [SYSTEM]\nLK ENABLE=1\nBURN FACTORY=1\nCOMPARE DATA=1\n",
        )
        .unwrap();
        let img = root.join("install.img");
        image::install_img::write_fixture_image(
            &img,
            ProjectKind::Generic,
            &[("layout.txt", b"target=A offset=0x0 size=0x100\n".as_slice())],
        )
        .unwrap();

        let mut s = AppState::new();
        s.ini_path_input = ini.to_string_lossy().into_owned();
        s.load_image(&img).unwrap();

        let loaded = s.image.as_ref().unwrap();
        assert_eq!(loaded.flash_info.trans_size, 256 * 1024);
        assert_eq!(loaded.flash_info.effective_chunk(), 256 * 1024);
        assert!(loaded.system_ini.is_some());
        assert_eq!(s.options.lk_enable, true);
        assert_eq!(s.options.burn_factory, true);
        assert_eq!(s.options.compare_data, true);
    }

    #[test]
    fn planned_opcodes_follow_the_protocol_order() {
        let mut s = AppState::new();
        s.image = Some(LoadedImage {
            path: PathBuf::from("x"),
            project: ProjectKind::Generic,
            partitions: vec![Partition {
                target: "A".into(),
                offset: 0,
                size: 0x100,
                name: None,
                line: 1,
            }],
            bootloader: vec![("hw_setting.bin".into(), 3200, 256)],
            system_ini_path: None,
            flash_info: FlashInfo::default(),
            system_ini: None,
            plan: None,
        });
        let ops = s.planned_opcodes();
        assert_eq!(ops[0], Opcode::UsbHwSetting, "hwsetting always comes first");
        assert_eq!(ops[1], Opcode::DdrEnable, "then DDR enable");
        assert_eq!(ops[2], Opcode::Write, "then the bootloader member");
        assert_eq!(ops[3], Opcode::Write, "then the partition");

        s.options.compare_data = true;
        assert_eq!(*s.planned_opcodes().last().unwrap(), Opcode::ReadVerify);
    }

    #[test]
    fn hwsetting_load_edit_and_save_round_trips() {
        let root = tmp("hw");
        // Build a blob from ops plus the known trailer header.
        let hw = HwSetting {
            ops: vec![
                rtd_core::hwconfig::op::Op::Write {
                    addr: 0x1801_a010,
                    value: 0x1f,
                },
                rtd_core::hwconfig::op::Op::Nop { value: 0x1000 },
            ],
            trailer: {
                let mut t = HwSetting::default_trailer();
                t.extend(std::iter::repeat(0u8).take(12));
                t.extend(std::iter::repeat(0xAB).take(32));
                t
            },
        };
        let path = root.join("hw.bin");
        std::fs::write(&path, hw.to_encrypted().unwrap()).unwrap();

        let mut s = AppState::new();
        s.load_hwsetting(&path).unwrap();
        assert_eq!(s.hwsetting.as_ref().unwrap().ops.len(), 2);

        // edit through the text view
        let text = s.hwsetting_text();
        assert!(text.contains("w 0x1801a010 0x0000001f"), "{text}");
        let edited = "w 0x1801a010 0x0000002f\nn 0x2000\n";
        s.set_hwsetting_text(edited).unwrap();
        assert_eq!(s.hwsetting.as_ref().unwrap().ops.len(), 2);

        // save and re-read: the ops survive and the trailer is unchanged
        let out = root.join("hw_out.bin");
        s.save_hwsetting(&out).unwrap();
        let back = HwSetting::from_encrypted(&std::fs::read(&out).unwrap()).unwrap();
        assert_eq!(back.ops, s.hwsetting.as_ref().unwrap().ops);
        assert_eq!(back.trailer, s.hwsetting.as_ref().unwrap().trailer);
    }

    #[test]
    fn editing_without_a_loaded_hwsetting_is_an_error() {
        let mut s = AppState::new();
        assert!(s.set_hwsetting_text("w 0x1 0x2").is_err());
        assert!(s.save_hwsetting(Path::new("/tmp/x")).is_err());
    }
}
