//! Full burn orchestration: turn an image on disk into frames on the wire.
//!
//! This is the layer that was missing between "we can parse an image" and "we
//! can flash a board". It owns the **order** of operations; [`Transport`] owns
//! the framing and retries.
//!
//! # The sequence
//!
//! Recovered from the original's worker thread and confirmed against its debug
//! log:
//!
//! 1. **hwsetting** — `0xF5` at raw byte address `0x0150_0000` (not a sector).
//!    The blob is sent verbatim; whatever produced it (`.config` + AES) is the
//!    caller's business.
//! 2. **DDR enable** — `0xFA` / type `0x06`, zero-length payload.
//! 3. **bootloader members** — `0xF4` / type `0x01`, laid out back-to-back from
//!    sector 256 with `next = lba + ceil(size/512)`.
//! 4. **partitions** — `0xF4` / type `0x01` at `offset / 512` from `layout.txt`.
//! 5. **verify** — optional `0xFC`.
//!
//! # What this module deliberately does not do
//!
//! * **NAND** bad-block remapping (the 2290-line `nand_burner` path).
//! * **Secure keys** — the shipped package has no `GenKeyBag.exe`, so eFuse and
//!   secure-storage steps are refused rather than half-implemented.
//!
//! Both are reported as [`BurnError::Unsupported`] instead of being skipped
//! silently, because a partial burn is worse than a refused one.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::device::DeviceBackend;
use crate::error::{Error, Result};
use crate::image::{bootloader, install_img, layout_txt, Member};
use crate::protocol::{cmd_type, consts, FlashInfo, Opcode};
use crate::transport::{Clock, RealClock, Transport, TransportLog};

/// Members larger than this are streamed from the archive instead of being read
/// into memory. Small ones (layout files, MBR, factory area) stay in RAM because
/// that keeps the code paths simple.
///
/// The threshold has to sit below the smallest real partition but well above
/// everything that is convenient to hold; 64 MiB does both.
pub const STREAM_THRESHOLD: u64 = 64 << 20;

/// A payload that lives inside `install.img` and is streamed while burning.
///
/// The 7.8 GB CM360 package carries ~7.5 GB of partitions. Reading those into
/// memory (the old behaviour) is what made the Rust port unusable for exactly
/// the images this tool exists for, so large members stay in the archive and are
/// read 2 MiB at a time -- one original "round" -- while writing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberRef {
    /// The `install.img` to read from.
    pub image: PathBuf,
    /// Archive member name, exactly as returned by `list_members`.
    pub name: String,
    /// Byte offset of the member's payload inside the archive.
    pub data_offset: u64,
    /// Payload length in bytes.
    pub len: u64,
}

/// One partition to write, with its payload.
#[derive(Clone, PartialEq, Eq)]
pub struct PartitionWrite {
    /// `target=` name from `layout.txt`, verbatim.
    pub target: String,
    /// Byte offset from `layout.txt`.
    pub offset: u64,
    /// Declared size from `layout.txt`.
    pub size: u64,
    /// The bytes to write. Empty means "declared but no payload found", or
    /// "payload is streamed" when [`Self::member`] is set.
    pub data: Vec<u8>,
    /// When set, the payload lives inside the image archive and is streamed at
    /// burn time instead of being held in memory. `data` stays empty then.
    pub member: Option<MemberRef>,
}

impl Default for PartitionWrite {
    fn default() -> Self {
        Self {
            target: String::new(),
            offset: 0,
            size: 0,
            data: Vec::new(),
            member: None,
        }
    }
}

impl fmt::Debug for PartitionWrite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PartitionWrite")
            .field("target", &self.target)
            .field("offset", &format_args!("{:#x}", self.offset))
            .field("size", &format_args!("{:#x}", self.size))
            .field("data_len", &self.data.len())
            .finish()
    }
}

impl PartitionWrite {
    /// The device writes by sector, so the byte offset is divided by 512.
    ///
    /// A non-multiple offset is an error rather than a silent truncation: the
    /// original would round down and corrupt the neighbouring partition.
    pub fn lba(&self) -> Result<u64> {
        if self.offset % consts::SECTOR_SIZE != 0 {
            return Err(Error::Image(format!(
                "partition {} has offset {:#x}, not a multiple of {}",
                self.target,
                self.offset,
                consts::SECTOR_SIZE
            )));
        }
        Ok(self.offset / consts::SECTOR_SIZE)
    }

    /// Payload length in bytes, whichever representation holds it.
    pub fn payload_len(&self) -> u64 {
        match &self.member {
            Some(m) => m.len,
            None => self.data.len() as u64,
        }
    }

    /// Whether there is anything to write at all.
    pub fn has_payload(&self) -> bool {
        self.payload_len() > 0
    }

    /// Whether the payload fits the declared slot.
    ///
    /// `layout.txt` declares the partition *slot* size, and real images are not
    /// padded to it: `p1.img` is 8192 bytes smaller than `PART0`'s slot. The
    /// original writes exactly the payload length, so a payload that is smaller
    /// is normal -- only one that is *larger* would run into the next partition.
    pub fn is_size_consistent(&self) -> bool {
        self.payload_len() == 0 || self.payload_len() <= self.size
    }
}

/// Everything needed to flash one board.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BurnPlan {
    /// The hwsetting blob, already in its final on-wire form.
    pub hwsetting: Option<Vec<u8>>,
    /// Bootloader members in the order they will be written.
    pub bootloader: Vec<(String, Vec<u8>, u64)>,
    /// Image partitions.
    pub partitions: Vec<PartitionWrite>,
    /// Verify after writing (`0xFC`).
    pub verify: bool,
    /// Flash geometry; supplies the chunk size.
    pub flash_info: FlashInfo,
}

impl BurnPlan {
    /// Total payload bytes across every step, for progress reporting.
    pub fn total_bytes(&self) -> u64 {
        let hw = self.hwsetting.as_ref().map(|b| b.len() as u64).unwrap_or(0);
        let bl: u64 = self.bootloader.iter().map(|(_, d, _)| d.len() as u64).sum();
        let pt: u64 = self.partitions.iter().map(|p| p.payload_len()).sum();
        hw + bl + pt
    }

    /// A short human-readable summary, used in the UI before starting.
    pub fn describe(&self) -> String {
        format!(
            "hwsetting {} / bootloader {} 个 / 分区 {} 个 / 共 {:.1} MB",
            if self.hwsetting.is_some() { "有" } else { "无" },
            self.bootloader.len(),
            self.partitions.len(),
            self.total_bytes() as f64 / 1_048_576.0
        )
    }

    /// Reject plans that cannot be executed correctly.
    ///
    /// Checked **before** any bytes go out, so a bad plan never reaches a board.
    pub fn validate(&self, options: &BurnOptions) -> std::result::Result<(), Vec<String>> {
        let mut problems = Vec::new();

        let has_payload = !self.bootloader.is_empty()
            || self.partitions.iter().any(|p| p.has_payload());

        // A hwsetting-only plan is legitimate: it configures DDR and stops, which
        // is how a bare board is brought up. Anything *more* than that needs the
        // hwsetting first -- writing partitions to an unconfigured DRAM
        // controller cannot work.
        if has_payload && self.hwsetting.is_none() {
            problems.push("缺少 hwsetting（DDR 没有配置，写进去也起不来）".to_string());
        }
        if self.hwsetting.is_none() && !has_payload {
            problems.push("没有任何要写入的内容".to_string());
        }

        // The device writes 512-byte sectors; an unaligned offset would land in
        // the middle of the previous partition.
        for p in &self.partitions {
            if let Err(e) = p.lba() {
                problems.push(e.to_string());
            }
            if !p.is_size_consistent() {
                problems.push(format!(
                    "分区 {} 声明 {} 字节但实际有 {} 字节",
                    p.target.trim(),
                    p.size,
                    p.data.len()
                ));
            }
            if p.target.starts_with("FACTORY") && p.data.len() as u64 > consts::FACTORY_MAX_SIZE {
                problems.push(format!(
                    "factory 区数据 {} 字节，超过 {} 字节上限",
                    p.data.len(),
                    consts::FACTORY_MAX_SIZE
                ));
            }
        }

        if self.flash_info.effective_chunk() == 0 {
            problems.push("分片大小为 0（检查 SYSTEM.ini 的 WRITE RANGE）".to_string());
        }

        // Refuse the paths this build does not implement.
        if let Some(msg) = options.unsupported_message(self.flash_info.flash_type) {
            problems.push(msg);
        }

        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems)
        }
    }
}

/// Options that change which steps run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BurnOptions {
    /// Burn the factory area. Not implemented.
    pub burn_factory: bool,
    /// Burn secure storage. Needs the absent `GenKeyBag.exe`.
    pub burn_se_storage: bool,
    /// Burn eFuse only. Needs the secure-key pipeline.
    pub only_burn_efuse: bool,
    /// Compare after writing.
    pub compare_data: bool,
}

impl BurnOptions {
    /// The first option that this build cannot honour, if any.
    pub fn unsupported_message(&self, flash_type: u8) -> Option<String> {
        if flash_type != 2 {
            return Some(format!(
                "本版本只实现 eMMC 烧写（FLASH TYPE={flash_type}）；NAND/NOR 需要 nand_burner 的坏块重映射"
            ));
        }
        if self.only_burn_efuse {
            return Some("eFuse 烧写需要安全密钥流程，原包未提供 GenKeyBag.exe".to_string());
        }
        if self.burn_se_storage {
            return Some("烧写安全存储需要 GenKeyBag.exe，原包未提供".to_string());
        }
        if self.burn_factory {
            return Some("工厂区烧写未实现".to_string());
        }
        None
    }
}

/// Progress callback.
///
/// Kept as a trait rather than a channel so the core stays free of any
/// concurrency model; the GUI adapts it to whatever it needs.
pub trait Progress {
    /// Called before a named stage begins.
    fn stage(&mut self, _name: &str) {}
    /// Called as bytes are written. `total` is [`BurnPlan::total_bytes`].
    fn advance(&mut self, _written: u64, _total: u64) {}
}

/// A [`Progress`] that ignores everything, for callers that do not care.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoProgress;

impl Progress for NoProgress {}

/// What actually happened.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BurnReport {
    /// Frames sent for the hwsetting blob.
    pub hwsetting_bytes: u64,
    /// Bootloader members written, by name.
    pub bootloader_written: Vec<String>,
    /// Partitions written, by target name.
    pub partitions_written: Vec<String>,
    /// Total payload bytes handed to the transport.
    pub bytes_written: u64,
    /// Whether a verify pass ran.
    pub verified: bool,
}

/// Execute a plan.
///
/// The order is fixed and matches the original; see the module docs.
pub fn run<D, C, L, P>(
    transport: &mut Transport<D, C, L>,
    plan: &BurnPlan,
    options: &BurnOptions,
    progress: &mut P,
) -> Result<BurnReport>
where
    D: DeviceBackend,
    C: Clock,
    L: TransportLog,
    P: Progress,
{
    // Fail before touching the device.
    if let Err(problems) = plan.validate(options) {
        return Err(Error::Burn(problems.join("；")));
    }

    let fi = &plan.flash_info;
    let total = plan.total_bytes();
    let mut written = 0u64;
    let mut report = BurnReport::default();

    // 1) hwsetting ---------------------------------------------------------
    if let Some(blob) = &plan.hwsetting {
        progress.stage("写入 hwsetting");
        transport.write_hwsetting(blob, fi)?;
        written += blob.len() as u64;
        report.hwsetting_bytes = blob.len() as u64;
        report.bytes_written = written;
        progress.advance(written, total);

        // 2) DDR enable -- always follows the hwsetting blob.
        progress.stage("启动 DDR");
        transport.enable_ddr(fi)?;
    }

    // 3) bootloader --------------------------------------------------------
    for (name, data, lba) in &plan.bootloader {
        progress.stage(&format!("写入 {name}"));
        transport.write_member(*lba, data, fi)?;
        written += data.len() as u64;
        report.bytes_written = written;
        report.bootloader_written.push(name.clone());
        progress.advance(written, total);
    }

    // 4) partitions --------------------------------------------------------
    for p in &plan.partitions {
        if !p.has_payload() {
            // Declared in layout.txt but no payload in the image. Skipping is
            // correct -- the original does the same -- but it is worth knowing.
            continue;
        }
        progress.stage(&format!("写入 {}", p.target.trim()));
        let lba = p.lba()?;
        match &p.member {
            // Large members stay inside the archive: read one 2 MiB "round" at a
            // time and hand it to the same chunking code. This is what makes the
            // 7.8 GB package possible without gigabytes of RAM, and it keeps the
            // round/indicator/LBA sequence identical (a 2 MiB slice produces
            // exactly one round of eight 256 KiB chunks).
            Some(m) => {
                use std::io::{Read as _, Seek as _, SeekFrom};
                const SLICE: u64 = 2 << 20;
                let mut f = std::fs::File::open(&m.image)?;
                f.seek(SeekFrom::Start(m.data_offset))?;
                let mut buf = vec![0u8; SLICE as usize];
                let mut off = 0u64;
                while off < m.len {
                    let n = (m.len - off).min(SLICE) as usize;
                    f.read_exact(&mut buf[..n])?;
                    let slice_lba = lba + off / consts::SECTOR_SIZE;
                    transport.write_buffer(
                        Opcode::Write as u8,
                        cmd_type::WRITE_CHUNK,
                        slice_lba,
                        &buf[..n],
                        fi,
                        None,
                    )?;
                    off += n as u64;
                    written += n as u64;
                    report.bytes_written = written;
                    progress.advance(written, total);
                }
            }
            None => {
                transport.write_member(lba, &p.data, fi)?;
                written += p.data.len() as u64;
                report.bytes_written = written;
                progress.advance(written, total);
            }
        }
        report.partitions_written.push(p.target.trim().to_string());
    }

    // 5) verify ------------------------------------------------------------
    if plan.verify || options.compare_data {
        progress.stage("校验");
        // A verify is a read of the same region; the transport exposes the
        // read path separately, so this records intent and reports honestly
        // rather than pretending a write-only pass verified anything.
        report.verified = false;
    }

    Ok(report)
}

// ---------------------------------------------------------------------------
// Building a plan from files on disk
// ---------------------------------------------------------------------------

/// Where the pieces of a burn come from.
#[derive(Debug, Clone)]
pub struct BurnSources {
    /// `install.img` (a ustar archive).
    pub install_img: Option<PathBuf>,
    /// `bootloader.tar`.
    pub bootloader_tar: Option<PathBuf>,
    /// The on-wire hwsetting blob (already encrypted).
    pub hwsetting: Option<PathBuf>,
    /// `SYSTEM.ini`, for the geometry.
    pub system_ini: Option<PathBuf>,
}

impl Default for BurnSources {
    fn default() -> Self {
        Self {
            install_img: None,
            bootloader_tar: None,
            hwsetting: None,
            system_ini: None,
        }
    }
}

impl BurnSources {
    /// Build a plan by reading every configured source.
    ///
    /// Missing optional pieces are skipped; a missing `install.img` is an error
    /// because there would be nothing to flash.
    pub fn build(&self) -> Result<BurnPlan> {
        let mut plan = BurnPlan::default();

        // Geometry from SYSTEM.ini, falling back to the shipped defaults so a
        // burn is still possible when the ini is absent.
        plan.flash_info = match &self.system_ini {
            Some(p) => crate::image::SystemIni::from_path(p)?.flash_info(),
            None => FlashInfo {
                flash_type: 2,                 // eMMC
                trans_size: 256 * 1024,        // WRITE RANGE=256 KiB
                once_trans_max_size: 2 << 20,  // ONE WRITE SIZE=2 MiB
                ..Default::default()
            },
        };

        if let Some(p) = &self.hwsetting {
            plan.hwsetting = Some(std::fs::read(p)?);
        }

        if let Some(p) = &self.bootloader_tar {
            let (members, _next) = bootloader::load(p)?;
            plan.bootloader = members
                .into_iter()
                .map(|m| (m.member.file_name().to_string(), m.data, m.lba))
                .collect();
        }

        if let Some(img) = &self.install_img {
            plan.partitions = read_partitions(img)?;

            // The original also writes the factory area at two fixed places:
            // `calculate_factory_block_start_address` @0x00432050 returns page
            // 4352 (0x220000) and page 8448 (0x420000), matching its log lines
            // `factory address icon[0] - starpage : 4352` / `: 8448`.
            //
            // It does **not** write the image's `factory.tar` verbatim: it
            // untars it, adds `layout.txt`, re-tars everything under
            // `tmp/factory/`, pads the archive to 10 KiB, and then patches the
            // first block with the archive length and an `RTK\0` magic. U-Boot's
            // factory reader looks for exactly that
            // (`[FAC] No factory data in eMMC` without it), and a burn whose
            // factory area is a bare tar boots only as far as the U-Boot prompt.
            if let Some(factory) = build_factory_blob(img)? {
                for (page, label) in [
                    (consts::FACTORY_START_PAGE_A, "FACTORY_A"),
                    (consts::FACTORY_START_PAGE_B, "FACTORY_B"),
                ] {
                    plan.partitions.push(PartitionWrite { member: None,
                        target: format!("{label}（factory 区）"),
                        offset: page * consts::SECTOR_SIZE,
                        size: factory.len() as u64,
                        data: factory.clone(),
                    });
                }
            }
        }

        Ok(plan)
    }
}

/// Lowercase, drop the directory part and any extension, keep alphanumerics.
///
/// `fw_tbl.bin` -> `fwtbl`, `low-region.img` -> `lowregion`.
fn normalize_common(s: &str) -> String {
    let base = s.rsplit(['/', '\\']).next().unwrap_or(s);
    let stem = base.split('.').next().unwrap_or(base);
    stem.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Normalise a `layout.txt` **target** for matching: `FW_FWTBL` -> `fwtbl`.
///
/// Only the target side has the `FW_` prefix stripped. It must not be stripped
/// from file names, because there `fw_` is often part of the name itself:
/// `fw_tbl.bin` is the firmware table, and stripping would leave `tbl`, which
/// matches nothing.
pub fn normalize_target(s: &str) -> String {
    let base = s.rsplit(['/', '\\']).next().unwrap_or(s);
    let stem = base.split('.').next().unwrap_or(base);
    let bare = if stem.len() > 3 {
        match stem.get(..3) {
            Some(p) if p.eq_ignore_ascii_case("fw_") => &stem[3..],
            _ => stem,
        }
    } else {
        stem
    };
    normalize_common(bare)
}

/// Normalise a **file name** for matching: no prefix stripping.
pub fn normalize_file(s: &str) -> String {
    normalize_common(s)
}

/// Read `layout.txt` from an image and pull each partition's payload.
///
/// Partitions whose declared target has no matching member are returned with an
/// empty payload so the caller can report them, rather than being dropped.
pub fn read_partitions(image: &Path) -> Result<Vec<PartitionWrite>> {
    // Locate layout.txt, then read every member once.
    let members = install_img::list_members(image)?;
    let layout_name = members
        .iter()
        .find(|(n, _)| n.ends_with(install_img::LAYOUT_FILE))
        .map(|(n, _)| n.clone())
        .ok_or_else(|| {
            Error::Image("install.img 里没有 layout.txt，无法确定分区布局".into())
        })?;

    let layout_bytes = read_member(image, &layout_name)?;
    let text = String::from_utf8_lossy(&layout_bytes).into_owned();
    let declared = layout_txt::parse(&text)?;

    let mut out = Vec::new();
    for p in declared {
        let mut pw = PartitionWrite {
            target: p.target.clone(),
            offset: p.offset,
            size: p.size,
            data: Vec::new(),
            member: None,
        };
        if let Some((name, size)) = locate_member(&members, &p) {
            if *size > STREAM_THRESHOLD {
                // Large member: remember where its payload lives and stream it at
                // burn time. Nothing of a 7.8 GB image ends up in RAM.
                if let Some((data_offset, len)) = install_img::member_data_range(image, name)? {
                    pw.member = Some(MemberRef {
                        image: image.to_path_buf(),
                        name: name.clone(),
                        data_offset,
                        len,
                    });
                } else {
                    pw.data = read_member(image, name)?;
                }
            } else {
                pw.data = read_member(image, name)?;
            }
        }
        out.push(pw);
    }
    Ok(out)
}

/// Build the factory-area blob exactly as the original tool does.
///
/// Recovered byte-for-byte from a USBPcap capture of the original tool writing
/// this board (2026-10-23), cross-checked against its log
/// (`factory address icon[0] - starpage : 4352` / `: 8448`, CBW length
/// `0x23600`/`0x23800`):
///
/// ```text
/// [ tar archive: tmp/factory/ (dir), tmp/factory/env.txt, tmp/factory/layout.txt ]
///   -- padded to a 10 KiB blocking factor
/// [ 512-byte copy of the archive's first block, whose tail is patched:
///     +0x1F8  u32  archive length
///     +0x1FC  "RTK\0"                      <- what U-Boot's factory reader wants
///     +0x094  tar checksum, recomputed after the patch ]
/// [ 1024 zero bytes ]
/// ```
///
/// The source files come from the image's own `factory.tar` (in the CM360
/// images that is a single `env.txt`, the 128 KiB boot environment) plus the
/// image's `layout.txt`, which the original copies into the factory area too.
/// Member names inside the shipped tar may be root-relative or already carry the
/// `tmp/factory/` prefix; both are normalised to exactly one prefix.
fn build_factory_blob(image: &Path) -> Result<Option<Vec<u8>>> {
    use std::io::Read as _;

    let members = install_img::list_members(image)?;
    let Some(factory_name) = members
        .iter()
        .find(|(n, _)| {
            let base = n.rsplit(['/', '\\']).next().unwrap_or(n);
            base.eq_ignore_ascii_case("factory.tar")
        })
        .map(|(n, _)| n.clone())
    else {
        return Ok(None);
    };
    let factory_tar = read_member(image, &factory_name)?;

    // Everything inside the shipped factory.tar becomes `tmp/factory/<name>`.
    //
    // Images come in two shapes: root-relative (`env.txt`, the older CM360
    // builds) and already-prefixed (`tmp/factory/env.txt`, what the original
    // tool's own "blank factory.tar" contains). Prefixing an already-prefixed
    // name silently produces `tmp/factory/tmp/factory/env.txt`, U-Boot then
    // cannot find the environment, falls back to the default one, and the FW
    // table it loads fails its signature check -- the board stops at `BPI-W2>`.
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    {
        let mut ar = tar::Archive::new(std::io::Cursor::new(factory_tar));
        let entries = ar.entries().map_err(|e| Error::Image(e.to_string()))?;
        for entry in entries {
            let mut entry = entry.map_err(|e| Error::Image(e.to_string()))?;
            if !entry.header().entry_type().is_file() {
                continue;
            }
            let path = entry
                .path()
                .map_err(|e| Error::Image(e.to_string()))?
                .to_string_lossy()
                .replace('\\', "/");
            let rel = path.trim_start_matches("./");
            let rel = rel.strip_prefix("tmp/factory/").unwrap_or(rel);
            if rel.is_empty() {
                continue;
            }
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            // A later duplicate replaces the earlier one.
            files.retain(|(n, _)| n != rel);
            files.push((rel.to_string(), buf));
        }
    }

    // The bootloader finds the flash layout inside the factory area.
    let layout_name = members
        .iter()
        .find(|(n, _)| n.ends_with(install_img::LAYOUT_FILE))
        .map(|(n, _)| n.clone())
        .ok_or_else(|| Error::Image("install.img 里没有 layout.txt，无法生成 factory 区".into()))?;
    files.push(("layout.txt".to_string(), read_member(image, &layout_name)?));

    // Build the tar archive.
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        builder.mode(tar::HeaderMode::Complete);

        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Directory);
        h.set_mode(0o040666);
        h.set_uid(0);
        h.set_gid(0);
        h.set_size(0);
        h.set_mtime(0);
        h.set_path("tmp/factory/")?;
        h.set_cksum();
        builder.append(&h, std::io::empty())?;

        for (name, data) in &files {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Regular);
            h.set_mode(0o0100666);
            h.set_uid(0);
            h.set_gid(0);
            h.set_size(data.len() as u64);
            h.set_mtime(0);
            h.set_path(format!("tmp/factory/{name}"))?;
            h.set_cksum();
            builder.append(&h, data.as_slice())?;
        }
        builder.finish()?;
    }

    // The original writes 10 KiB records (`tar` blocking factor 20).
    const BLOCK: usize = 10 * 1024;
    let padded = tar_bytes.len().div_ceil(BLOCK) * BLOCK;
    tar_bytes.resize(padded, 0);

    // Patch the factory header, then fix the checksum it invalidated.
    tar_bytes[0x1F8..0x1FC].copy_from_slice(&(padded as u32).to_le_bytes());
    tar_bytes[0x1FC..0x200].copy_from_slice(b"RTK\0");
    let checksum = tar_checksum(&tar_bytes[..512]);
    let field = format!("{checksum:06o}\0 ");
    tar_bytes[0x94..0x9C].copy_from_slice(field.as_bytes());

    // Trailer: repeat the patched first block, then 1 KiB of zeros.
    let head = tar_bytes[..512].to_vec();
    tar_bytes.extend_from_slice(&head);
    tar_bytes.resize(tar_bytes.len() + 1024, 0);
    Ok(Some(tar_bytes))
}

/// Standard tar header checksum over a 512-byte block.
fn tar_checksum(block: &[u8]) -> u32 {
    block
        .iter()
        .enumerate()
        .map(|(i, &b)| if (0x94..0x9C).contains(&i) { b' ' as u32 } else { b as u32 })
        .sum()
}

/// Find the archive member holding a partition's payload.
///
/// Resolution order, most authoritative first:
///
/// 1. **` name=` from `layout.txt`.** This is the field the original actually
///    uses: `LoadFlashLayout` @0x004186D0 parses `target=`, `offset=`, `size=`
///    and then ` name=`, and `get_target_directory_name` @0x0040F420 looks the
///    file up by that value. When it is present it is the answer.
/// 2. The trimmed `target=` name, matched exactly. Some images omit `name=` and
///    simply name the file after the target.
/// 3. A normalised comparison, which is what flat images with names like
///    `FW_FWTBL` / `fw_tbl.bin` need.
fn locate_member<'a>(
    members: &'a [(String, u64)],
    p: &layout_txt::Partition,
) -> Option<&'a (String, u64)> {
    // 1) The authoritative ` name=` field.
    if let Some(name) = p.name.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let base_want = name.rsplit(['/', '\\']).next().unwrap_or(name);
        if let Some(hit) = members.iter().find(|(n, _)| {
            let base = n.rsplit(['/', '\\']).next().unwrap_or(n);
            base.eq_ignore_ascii_case(base_want)
        }) {
            return Some(hit);
        }
    }

    // 2) The target name used verbatim as a file name.
    let want = p.display_target();
    if let Some(hit) = members.iter().find(|(n, _)| {
        let base = n.rsplit(['/', '\\']).next().unwrap_or(n);
        base.eq_ignore_ascii_case(want)
    }) {
        return Some(hit);
    }

    // 3) Normalised fallback.
    let norm = normalize_target(&p.target);
    if norm.is_empty() {
        return None;
    }
    members.iter().find(|(n, _)| normalize_file(n) == norm)
}

/// One row of [`explain_partition_matching`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionMatch {
    /// The `target=` value, verbatim.
    pub target: String,
    /// Byte offset.
    pub offset: u64,
    /// Declared size.
    pub size: u64,
    /// The ` name=` value, when the layout carries one.
    pub name_field: Option<String>,
    /// The archive member that would be flashed, if any.
    pub matched: Option<String>,
}

impl PartitionMatch {
    /// How the member was found, for reporting.
    pub fn how(&self) -> &'static str {
        match (&self.matched, &self.name_field) {
            (None, _) => "未找到",
            (Some(_), Some(_)) => "name= 字段",
            (Some(_), None) => "按名称匹配",
        }
    }
}

/// Describe how each declared partition maps onto the files in an image.
///
/// A target with no payload has `matched: None`. When a burn would skip
/// partitions, this is what says which and why.
pub fn explain_partition_matching(image: &Path) -> Result<Vec<PartitionMatch>> {
    let members = install_img::list_members(image)?;
    let layout_name = members
        .iter()
        .find(|(n, _)| n.ends_with(install_img::LAYOUT_FILE))
        .map(|(n, _)| n.clone())
        .ok_or_else(|| Error::Image("install.img 里没有 layout.txt".into()))?;
    let text = String::from_utf8_lossy(&read_member(image, &layout_name)?).into_owned();
    let declared = layout_txt::parse(&text)?;

    Ok(declared
        .into_iter()
        .map(|p| {
            let hit = locate_member(&members, &p).map(|(n, _)| n.clone());
            PartitionMatch {
                target: p.target.clone(),
                offset: p.offset,
                size: p.size,
                name_field: p.name.clone(),
                matched: hit,
            }
        })
        .collect())
}

/// Read one member out of a tar by its exact stored path.
fn read_member(image: &Path, want: &str) -> Result<Vec<u8>> {
    use std::io::Read;
    let f = std::fs::File::open(image)?;
    let mut ar = tar::Archive::new(std::io::BufReader::new(f));
    for entry in ar.entries().map_err(|e| Error::Image(e.to_string()))? {
        let mut entry = entry.map_err(|e| Error::Image(e.to_string()))?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let name = entry
            .path()
            .map_err(|e| Error::Image(e.to_string()))?
            .to_string_lossy()
            .replace('\\', "/");
        if name == want.replace('\\', "/") {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            return Ok(buf);
        }
    }
    Err(Error::Image(format!("{want} 不在镜像里")))
}

/// Which bootloader member a file is, for callers that only have a directory.
pub fn member_for_file(name: &str) -> Option<Member> {
    Member::from_file_name(name)
}

/// Default `Transport` type used by the GUI worker.
pub type RealTransport<D> = Transport<D, RealClock, crate::transport::VecLog>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::mock::{MockDevice, Reply};
    use crate::protocol::cbw::Cbw;
    use crate::protocol::indicator;
    use crate::protocol::opcode::{cmd_type, Opcode};

    fn emmc() -> FlashInfo {
        FlashInfo {
            flash_type: 2,
            trans_size: 256 * 1024,
            once_trans_max_size: 2 << 20,
            ..Default::default()
        }
    }

    /// Decode every CBW the mock recorded.
    ///
    /// `MockDevice` stores raw bytes, so the tests parse them with the very
    /// decoder the device would use -- which also means a framing regression
    /// shows up here rather than being masked by a test-only accessor.
    fn cbows(dev: &MockDevice) -> Vec<Cbw> {
        dev.cbw_frames()
            .iter()
            .map(|b| Cbw::decode(b).expect("mock recorded a malformed CBW"))
            .collect()
    }

    #[test]
    fn a_full_burn_emits_the_stages_in_the_recorded_order() {
        let plan = BurnPlan {
            hwsetting: Some(vec![0xAA; 3200]),
            bootloader: vec![
                ("hw_setting.bin".into(), vec![1u8; 3200], 256),
                ("uboot.bin".into(), vec![2u8; 604_128], 263),
            ],
            partitions: vec![PartitionWrite { member: None,
                target: "FW_KERNEL ".into(),
                offset: 0x300_0000,
                size: 4,
                data: vec![3u8; 4],
            }],
            verify: false,
            flash_info: emmc(),
        };

        let dev = MockDevice::with_replies(vec![Reply::Pass; 16]);
        let mut t = Transport::new(dev);
        let got = run(&mut t, &plan, &BurnOptions::default(), &mut NoProgress).unwrap();

        let frames = cbows(t.device());
        let opcodes: Vec<u8> = frames.iter().map(|c| c.cbwcb.opcode).collect();

        // The hwsetting blob goes first, then the 0xFA DDR-enable frame, then
        // the member writes. (The DDR-enable frame is on the wire: USBPcap of
        // the original tool, 2026-10-23.)
        assert_eq!(opcodes[0], Opcode::UsbHwSetting as u8, "{opcodes:?}");
        assert_eq!(opcodes[1], Opcode::DdrEnable as u8, "{opcodes:?}");
        assert!(
            opcodes[2..].iter().all(|o| *o == Opcode::Write as u8),
            "unexpected opcode after the DDR-enable frame: {opcodes:?}"
        );

        assert_eq!(got.hwsetting_bytes, 3200);
        assert_eq!(got.bootloader_written.len(), 2);
        assert_eq!(got.partitions_written, vec!["FW_KERNEL"]);
        assert_eq!(got.bytes_written, 3200 + 3200 + 604_128 + 4);
        assert!(!got.verified, "a write-only pass must not claim verification");
    }

    #[test]
    fn the_hwsetting_frame_uses_a_raw_byte_address_not_a_sector() {
        let plan = BurnPlan {
            hwsetting: Some(vec![0xAA; 3200]),
            flash_info: emmc(),
            ..Default::default()
        };
        let dev = MockDevice::with_replies(vec![Reply::Pass; 4]);
        let mut t = Transport::new(dev);
        run(&mut t, &plan, &BurnOptions::default(), &mut NoProgress).unwrap();

        let first = &cbows(t.device())[0];
        assert_eq!(first.cbwcb.opcode, Opcode::UsbHwSetting as u8);
        assert_eq!(
            first.cbwcb.logical_block_address, consts::ADDR_USB_HWSETTING,
            "the hwsetting address is a byte address, not a sector number"
        );
        assert_eq!(first.data_transfer_length, 3200);
    }

    #[test]
    fn ddr_enable_sends_the_test_frame_after_hwsetting() {
        let plan = BurnPlan {
            hwsetting: Some(vec![0xAA; 16]),
            flash_info: emmc(),
            ..Default::default()
        };
        let dev = MockDevice::with_replies(vec![Reply::Pass; 4]);
        let mut t = Transport::new(dev);
        run(&mut t, &plan, &BurnOptions::default(), &mut NoProgress).unwrap();

        // The hwsetting frame, then the 0xFA DDR-enable frame. The second is not
        // a no-op: the original puts a 5-byte `test\0` payload on the wire and
        // the device answers it (USBPcap, 2026-10-23).
        let all = cbows(t.device());
        assert_eq!(
            all.len(),
            2,
            "{:?}",
            all.iter().map(|c| c.cbwcb.opcode).collect::<Vec<_>>()
        );
        assert_eq!(all[0].cbwcb.opcode, Opcode::UsbHwSetting as u8);
        assert_eq!(all[1].cbwcb.opcode, Opcode::DdrEnable as u8);
        assert_eq!(all[1].cbwcb.cmd_type, cmd_type::DDR_ENABLE);
        assert_eq!(all[1].data_transfer_length, 5);
        assert_eq!(all[1].indicator, indicator::LAST);
        let payloads = t.device().payloads();
        assert_eq!(
            payloads[1], b"test\0",
            "the DDR-enable payload is the five bytes \"test\\0\""
        );
    }

    #[test]
    fn bootloader_members_keep_their_own_lba_across_chunks() {
        // uboot is 604128 bytes -> 3 chunks at 256 KiB, all at lba 0x107.
        let plan = BurnPlan {
            hwsetting: Some(vec![0xAA; 16]),
            bootloader: vec![("uboot.bin".into(), vec![2u8; 604_128], 0x107)],
            flash_info: emmc(),
            ..Default::default()
        };
        let dev = MockDevice::with_replies(vec![Reply::Pass; 8]);
        let mut t = Transport::new(dev);
        run(&mut t, &plan, &BurnOptions::default(), &mut NoProgress).unwrap();

        let all = cbows(t.device());
        let uboot: Vec<&Cbw> = all
            .iter()
            .filter(|c| c.cbwcb.logical_block_address == 0x107)
            .collect();
        assert_eq!(uboot.len(), 3, "604128 bytes / 256 KiB = 3 frames");
        assert!(
            uboot.iter().all(|c| c.cbwcb.opcode == Opcode::Write as u8),
            "all uboot chunks are writes"
        );
        // The decisive property: the address does not advance between chunks.
        let lbas: Vec<u32> = uboot.iter().map(|c| c.cbwcb.logical_block_address).collect();
        assert_eq!(lbas, vec![0x107, 0x107, 0x107]);
    }

    #[test]
    fn partitions_are_addressed_by_offset_over_sector_size() {
        let p = PartitionWrite { member: None,
            target: "A".into(),
            offset: 0x300_0000,
            size: 4,
            data: vec![0; 4],
        };
        assert_eq!(p.lba().unwrap(), 0x300_0000 / 512);
        assert!(p.is_size_consistent());
    }

    #[test]
    fn an_unaligned_partition_offset_is_rejected() {
        let p = PartitionWrite { member: None,
            target: "A".into(),
            offset: 0x300_0001,
            size: 4,
            data: vec![0; 4],
        };
        let err = p.lba().unwrap_err().to_string();
        assert!(err.contains("not a multiple of"), "{err}");
    }

    #[test]
    fn validation_refuses_a_plan_with_no_hwsetting() {
        let plan = BurnPlan {
            partitions: vec![PartitionWrite { member: None,
                target: "A".into(),
                offset: 0,
                size: 1,
                data: vec![0],
            }],
            flash_info: emmc(),
            ..Default::default()
        };
        let problems = plan.validate(&BurnOptions::default()).unwrap_err();
        assert!(
            problems.iter().any(|p| p.contains("hwsetting")),
            "{problems:?}"
        );
    }

    #[test]
    fn validation_refuses_nand_and_key_paths() {
        let mut plan = BurnPlan {
            hwsetting: Some(vec![0; 16]),
            partitions: vec![PartitionWrite { member: None,
                target: "A".into(),
                offset: 0,
                size: 1,
                data: vec![0],
            }],
            flash_info: emmc(),
            ..Default::default()
        };

        // NAND is out of scope for this build.
        plan.flash_info.flash_type = 0;
        let p = plan.validate(&BurnOptions::default()).unwrap_err();
        assert!(p.iter().any(|m| m.contains("eMMC")), "{p:?}");

        // eFuse needs the absent key tool.
        plan.flash_info.flash_type = 2;
        let opts = BurnOptions {
            only_burn_efuse: true,
            ..Default::default()
        };
        let p = plan.validate(&opts).unwrap_err();
        assert!(p.iter().any(|m| m.contains("eFuse")), "{p:?}");
    }

    #[test]
    fn a_refused_plan_sends_nothing_to_the_device() {
        let plan = BurnPlan {
            hwsetting: None, // invalid on purpose
            flash_info: emmc(),
            ..Default::default()
        };
        let dev = MockDevice::with_replies(vec![Reply::Pass; 4]);
        let mut t = Transport::new(dev);
        let err = run(&mut t, &plan, &BurnOptions::default(), &mut NoProgress).unwrap_err();
        assert!(matches!(err, Error::Burn(_)), "{err}");
        assert!(
            t.device().cbw_frames().is_empty(),
            "validation must run before any frame is emitted"
        );
    }

    #[test]
    fn a_partition_with_no_payload_is_skipped_not_faked() {
        let plan = BurnPlan {
            hwsetting: Some(vec![0; 16]),
            partitions: vec![PartitionWrite { member: None,
                target: "EMPTY ".into(),
                offset: 0,
                size: 4096,
                data: Vec::new(),
            }],
            flash_info: emmc(),
            ..Default::default()
        };
        let dev = MockDevice::with_replies(vec![Reply::Pass; 4]);
        let mut t = Transport::new(dev);
        let r = run(&mut t, &plan, &BurnOptions::default(), &mut NoProgress).unwrap();
        assert!(r.partitions_written.is_empty());
        assert_eq!(r.bytes_written, 16, "only the hwsetting blob went out");
    }

    #[test]
    fn progress_is_monotonic_and_ends_at_the_total() {
        #[derive(Default)]
        struct Rec {
            seen: Vec<(u64, u64)>,
            stages: Vec<String>,
        }
        impl Progress for Rec {
            fn stage(&mut self, n: &str) {
                self.stages.push(n.to_string())
            }
            fn advance(&mut self, w: u64, t: u64) {
                self.seen.push((w, t))
            }
        }

        let plan = BurnPlan {
            hwsetting: Some(vec![0; 100]),
            bootloader: vec![("b".into(), vec![0; 200], 0)],
            partitions: vec![PartitionWrite { member: None,
                target: "P".into(),
                offset: 0,
                size: 300,
                data: vec![0; 300],
            }],
            flash_info: emmc(),
            ..Default::default()
        };
        let total = plan.total_bytes();
        assert_eq!(total, 600);

        let dev = MockDevice::with_replies(vec![Reply::Pass; 8]);
        let mut t = Transport::new(dev);
        let mut rec = Rec::default();
        run(&mut t, &plan, &BurnOptions::default(), &mut rec).unwrap();

        assert!(!rec.seen.is_empty());
        assert!(
            rec.seen.windows(2).all(|w| w[0].0 <= w[1].0),
            "progress went backwards: {:?}",
            rec.seen
        );
        assert_eq!(rec.seen.last().unwrap().0, total, "must end at 100%");
        assert!(rec.stages.iter().any(|s| s.contains("hwsetting")));
        assert!(rec.stages.iter().any(|s| s.contains("DDR")));
        assert_eq!(rec.stages.iter().filter(|s| s.contains("写入")).count(), 3);
    }

    #[test]
    fn target_normalisation_matches_real_flat_image_names() {
        // Observed on an RTD1296 CM360 image: layout.txt targets on the left,
        // the payload files on the right.
        for (target, file) in [
            ("FW_MBR", "mbr.bin"),
            ("FW_FWTBL", "fw_tbl.bin"),
            ("FW_LOW_REGION", "low-region.img"),
            ("FW_P1", "p1.img"),
            ("FW_P2", "p2.img"),
        ] {
            assert_eq!(
                normalize_target(target),
                normalize_file(file),
                "{target} should match {file}"
            );
        }
    }

    #[test]
    fn the_fw_prefix_is_only_stripped_from_targets() {
        // `fw_tbl.bin`'s `fw_` is part of the name (firmware table), not the
        // layout's prefix convention. Stripping it there yields `tbl`, which
        // matches nothing -- a real bug this pins down.
        assert_eq!(normalize_target("FW_FWTBL"), "fwtbl");
        assert_eq!(normalize_file("fw_tbl.bin"), "fwtbl");
        assert_ne!(normalize_file("fw_tbl.bin"), "tbl");

        // A 3-character stem is left alone rather than sliced oddly.
        assert_eq!(normalize_file("fw"), "fw");
        assert_eq!(normalize_file("a"), "a");
        assert_eq!(normalize_target("FW_P1"), "p1");
    }

    #[test]
    fn normalisation_drops_directories_and_extensions() {
        assert_eq!(normalize_file("./package5/p1.img"), "p1");
        assert_eq!(normalize_file("dir\\sub\\low-region.img"), "lowregion");
        assert_eq!(normalize_file("noext"), "noext");
        assert_eq!(normalize_file("a.b.c"), "a");
        assert_eq!(normalize_target("FW_LOW_REGION"), "lowregion");
    }

    #[test]
    fn a_flat_image_is_detected_and_its_partitions_match() {
        use crate::image::ProjectKind;
        let base = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into());
        let root = std::path::PathBuf::from(base).join(format!("rtd-flat-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let img = root.join("install.img");

        // Exactly the shape reported from the field: no project directory, the
        // layout and the payloads side by side at the archive root.
        {
            let f = std::fs::File::create(&img).unwrap();
            let mut b = tar::Builder::new(f);
            let mut put = |name: &str, data: &[u8]| {
                let mut h = tar::Header::new_ustar();
                h.set_size(data.len() as u64);
                h.set_mode(0o644);
                h.set_cksum();
                b.append_data(&mut h, name, data).unwrap();
            };
            put(
                "layout.txt",
                b"target=FW_MBR offset=0x0 size=0x200\n                  target=FW_FWTBL offset=0x1000 size=0x1000\n                  target=FW_LOW_REGION offset=0x2000 size=0x100\n",
            );
            put("mbr.bin", &[0x33u8; 0x200]);
            put("fw_tbl.bin", &[0x11u8; 0x1000]);
            put("low-region.img", &[0x22u8; 0x100]);
            put("p2.img", &[0x55u8; 16]); // no matching target
            b.finish().unwrap();
        }

        // Detection must reach Flat rather than erroring.
        assert_eq!(
            crate::image::install_img::detect_project_in_members(
                crate::image::install_img::list_members(&img)
                    .unwrap()
                    .iter()
                    .map(|(n, _)| n.as_str())
            )
            .unwrap(),
            ProjectKind::Flat
        );

        let parts = read_partitions(&img).unwrap();
        assert_eq!(parts.len(), 3);
        assert!(parts.iter().all(|p| !p.data.is_empty()), "{parts:?}");
        assert_eq!(parts[0].data[0], 0x33);
        assert_eq!(parts[1].data[0], 0x11);
        assert_eq!(parts[2].data[0], 0x22);

        // The explain helper agrees with what the burn would do.
        let rows = explain_partition_matching(&img).unwrap();
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().all(|r| r.matched.is_some()), "{rows:?}");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_name_field_is_authoritative_when_present() {
        use crate::image::layout_txt;
        let members = vec![
            ("mbr.bin".to_string(), 512u64),
            ("weird-name.bin".to_string(), 512u64),
        ];

        // ` name=` wins even when it disagrees with the target name.
        let p = layout_txt::Partition {
            target: "FW_MBR".into(),
            offset: 0,
            size: 512,
            name: Some("weird-name.bin".into()),
            line: 1,
        };
        assert_eq!(locate_member(&members, &p).unwrap().0, "weird-name.bin");

        // Without ` name=`, the target name is used verbatim.
        let p = layout_txt::Partition {
            target: "mbr.bin".into(),
            offset: 0,
            size: 512,
            name: None,
            line: 1,
        };
        assert_eq!(locate_member(&members, &p).unwrap().0, "mbr.bin");

        // A blank ` name=` must not shadow the fallbacks.
        let p = layout_txt::Partition {
            target: "mbr.bin".into(),
            offset: 0,
            size: 512,
            name: Some("   ".into()),
            line: 1,
        };
        assert_eq!(locate_member(&members, &p).unwrap().0, "mbr.bin");

        // A ` name=` that matches nothing falls through to normalisation.
        let p = layout_txt::Partition {
            target: "FW_MBR".into(),
            offset: 0,
            size: 512,
            name: Some("absent.bin".into()),
            line: 1,
        };
        assert_eq!(locate_member(&members, &p).unwrap().0, "mbr.bin");
    }

    #[test]
    fn a_layout_with_name_fields_parses_and_matches() {
        // The format the original writes: `LoadFlashLayout` @0x004186D0 reads
        // `target=`, `offset=`, `size=`, then ` name=`.
        let text = "target=FW_FWTBL offset=0x1000 size=0x1000 name=fw_tbl.bin\n";
        let parts = crate::image::layout_txt::parse(text).unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].target, "FW_FWTBL");
        assert_eq!(parts[0].offset, 0x1000);
        assert_eq!(parts[0].size, 0x1000);
        assert_eq!(parts[0].name.as_deref(), Some("fw_tbl.bin"));

        let members = vec![("fw_tbl.bin".to_string(), 0x1000u64)];
        assert_eq!(locate_member(&members, &parts[0]).unwrap().0, "fw_tbl.bin");
    }

    #[test]
    fn describe_reports_the_shape_of_the_plan() {
        let plan = BurnPlan {
            hwsetting: Some(vec![0; 1024]),
            bootloader: vec![("a".into(), vec![0; 1024], 0)],
            partitions: vec![],
            flash_info: emmc(),
            ..Default::default()
        };
        let d = plan.describe();
        assert!(d.contains("bootloader 1"), "{d}");
        assert!(d.contains("分区 0"), "{d}");
    }

    #[test]
    fn a_plan_built_from_real_files_burns_in_the_right_order() {
        // End-to-end through the real file readers: a synthetic install.img plus
        // a bootloader tar, exactly as `BurnSources::build` would see them.
        let base = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into());
        let root = std::path::PathBuf::from(base).join(format!("rtd-burn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        // install.img: layout.txt declaring one partition, plus its payload.
        let img = root.join("install.img");
        let payload = vec![0x5Au8; 4096];
        crate::image::install_img::write_fixture_image(
            &img,
            crate::image::ProjectKind::Package5,
            &[
                (
                    "layout.txt",
                    b"target=FW_FWTBL offset=0x0 size=0x1000\n".as_slice(),
                ),
                ("FW_FWTBL", payload.as_slice()),
            ],
        )
        .unwrap();

        // bootloader.tar with one member.
        let tar_path = root.join("bootloader.tar");
        {
            let f = std::fs::File::create(&tar_path).unwrap();
            let mut b = tar::Builder::new(f);
            let data = vec![0xA5u8; 3200];
            let mut h = tar::Header::new_ustar();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, "hw_setting.bin", data.as_slice())
                .unwrap();
            b.finish().unwrap();
        }

        // The hwsetting blob, already in on-wire form.
        let hw = root.join("usb_hwsetting.bin");
        std::fs::write(&hw, vec![0x11u8; 1184]).unwrap();

        let sources = BurnSources {
            install_img: Some(img),
            bootloader_tar: Some(tar_path),
            hwsetting: Some(hw),
            system_ini: None, // falls back to the eMMC defaults
        };
        let plan = sources.build().unwrap();

        // Geometry fell back to the shipped defaults.
        assert_eq!(plan.flash_info.flash_type, 2);
        assert_eq!(plan.flash_info.effective_chunk(), 256 * 1024);
        assert_eq!(plan.hwsetting.as_ref().unwrap().len(), 1184);
        assert_eq!(plan.bootloader.len(), 1);
        assert_eq!(plan.bootloader[0].0, "hw_setting.bin");
        assert_eq!(plan.bootloader[0].2, consts::lba::HW_SETTING);

        // The partition payload was located by target name.
        assert_eq!(plan.partitions.len(), 1);
        // No trailing space: a `layout.txt` field value stops at the first
        // separator, so the `Layout_Type` spelling can never be stored here.
        // Matching therefore goes through `display_target()`, which trims.
        assert_eq!(plan.partitions[0].target, "FW_FWTBL");
        assert_eq!(plan.partitions[0].target.trim(), "FW_FWTBL");
        assert_eq!(plan.partitions[0].data.len(), 4096);
        assert!(plan.partitions[0].is_size_consistent());

        plan.validate(&BurnOptions::default()).unwrap();

        let dev = MockDevice::with_replies(vec![Reply::Pass; 16]);
        let mut t = Transport::new(dev);
        let r = run(&mut t, &plan, &BurnOptions::default(), &mut NoProgress).unwrap();

        assert_eq!(r.bytes_written, 1184 + 3200 + 4096);
        assert_eq!(r.bootloader_written, vec!["hw_setting.bin"]);
        assert_eq!(r.partitions_written, vec!["FW_FWTBL"]);

        let frames = cbows(t.device());
        assert_eq!(frames[0].cbwcb.opcode, Opcode::UsbHwSetting as u8);
        // Then the 0xFA DDR-enable frame, then the member writes.
        assert_eq!(frames[1].cbwcb.opcode, Opcode::DdrEnable as u8);
        assert_eq!(frames[2].cbwcb.opcode, Opcode::Write as u8);
        // The bootloader member lands at sector 256, the partition at offset 0.
        assert_eq!(
            u64::from(frames[2].cbwcb.logical_block_address),
            consts::lba::HW_SETTING
        );
        assert_eq!(frames[3].cbwcb.logical_block_address, 0);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_image_without_layout_txt_is_reported_clearly() {
        let base = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into());
        let root = std::path::PathBuf::from(base).join(format!("rtd-nolayout-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        let img = root.join("install.img");
        crate::image::install_img::write_fixture_image(
            &img,
            crate::image::ProjectKind::Generic,
            &[("random.bin", b"x".as_slice())],
        )
        .unwrap();

        let err = read_partitions(&img).unwrap_err().to_string();
        assert!(err.contains("layout.txt"), "{err}");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_first_frame_after_a_chunk_carries_the_right_indicator() {
        // 600 KiB at 256 KiB per chunk -> FIRST, MIDDLE, LAST.
        let plan = BurnPlan {
            hwsetting: Some(vec![0xAA; 16]),
            bootloader: vec![("big.bin".into(), vec![7u8; 600 * 1024], 0x200)],
            flash_info: emmc(),
            ..Default::default()
        };
        let dev = MockDevice::with_replies(vec![Reply::Pass; 8]);
        let mut t = Transport::new(dev);
        run(&mut t, &plan, &BurnOptions::default(), &mut NoProgress).unwrap();

        let all = cbows(t.device());
        let inds: Vec<u8> = all
            .iter()
            .filter(|c| c.cbwcb.logical_block_address == 0x200)
            .map(|c| c.indicator)
            .collect();
        assert_eq!(inds.len(), 3, "600 KiB / 256 KiB = 3 chunks");
        assert_eq!(inds[0], crate::protocol::indicator::FIRST, "{inds:?}");
        assert_eq!(inds[1], crate::protocol::indicator::MIDDLE, "{inds:?}");
        assert_eq!(inds[2], crate::protocol::indicator::LAST, "{inds:?}");
    }

    #[test]
    fn factory_blob_matches_the_format_the_original_tool_emits() {
        // Structure recovered from a USBPcap capture of the original tool
        // (2026-10-23): a 10 KiB-padded tar, whose first block is patched with
        // the archive length and the `RTK\0` magic, followed by that block again
        // and 1 KiB of zeros.
        let base = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into());
        let root = std::path::PathBuf::from(base).join(format!("rtd-factory-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        // The image's factory.tar: one env.txt, like the CM360 images.
        let env = vec![b'A'; 4096];
        let mut factory_tar = Vec::new();
        {
            let mut b = tar::Builder::new(&mut factory_tar);
            let mut h = tar::Header::new_gnu();
            h.set_size(env.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, "env.txt", env.as_slice()).unwrap();
            b.finish().unwrap();
        }
        let img = root.join("install.img");
        crate::image::install_img::write_fixture_image(
            &img,
            crate::image::ProjectKind::Package5,
            &[
                (
                    "layout.txt",
                    b"target=FW_KERNEL offset=0x0 size=0x1000\n".as_slice(),
                ),
                ("omv/factory.tar", factory_tar.as_slice()),
            ],
        )
        .unwrap();

        let blob = build_factory_blob(&img).unwrap().expect("factory blob");
        assert_eq!(&blob[0x1FC..0x200], b"RTK\0");
        let padded = u32::from_le_bytes(blob[0x1F8..0x1FC].try_into().unwrap()) as usize;
        assert_eq!(padded % (10 * 1024), 0);
        assert_eq!(blob.len(), padded + 512 + 1024);
        assert_eq!(&blob[padded..padded + 512], &blob[..512], "trailer block");

        // The patched header must still carry a valid tar checksum.
        let want = tar_checksum(&blob[..512]);
        let field = std::str::from_utf8(&blob[0x94..0x9A]).unwrap();
        assert_eq!(u32::from_str_radix(field.trim(), 8).unwrap(), want);
        assert_eq!(blob[0x9A], 0);
        assert_eq!(blob[0x9B], b' ');

        // And the archive parses, with both entries present.
        let mut ar = tar::Archive::new(std::io::Cursor::new(blob[..padded].to_vec()));
        let names: Vec<String> = ar
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().any(|n| n == "tmp/factory/env.txt"), "{names:?}");
        assert!(names.iter().any(|n| n == "tmp/factory/layout.txt"), "{names:?}");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn factory_blob_accepts_an_already_prefixed_factory_tar() {
        // Newer CM360 packages ship `omv/factory.tar` already in the generated
        // shape (`tmp/factory/env.txt`). It must not be prefixed a second time:
        // U-Boot would look for `tmp/factory/env.txt`, miss it, fall back to the
        // default environment and then fail the FW-table signature check.
        let base = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into());
        let root = std::path::PathBuf::from(base)
            .join(format!("rtd-factory-pre-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        let env = vec![b'B'; 2048];
        let mut factory_tar = Vec::new();
        {
            let mut b = tar::Builder::new(&mut factory_tar);
            let mut h = tar::Header::new_gnu();
            h.set_size(env.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, "tmp/factory/env.txt", env.as_slice())
                .unwrap();
            b.finish().unwrap();
        }
        let img = root.join("install.img");
        crate::image::install_img::write_fixture_image(
            &img,
            crate::image::ProjectKind::Package5,
            &[
                (
                    "layout.txt",
                    b"target=FW_KERNEL offset=0x0 size=0x1000\n".as_slice(),
                ),
                ("omv/factory.tar", factory_tar.as_slice()),
            ],
        )
        .unwrap();

        let blob = build_factory_blob(&img).unwrap().expect("factory blob");
        let padded = u32::from_le_bytes(blob[0x1F8..0x1FC].try_into().unwrap()) as usize;
        let mut ar = tar::Archive::new(std::io::Cursor::new(blob[..padded].to_vec()));
        let names: Vec<String> = ar
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(
            names.iter().any(|n| n == "tmp/factory/env.txt"),
            "{names:?}"
        );
        assert!(
            !names.iter().any(|n| n.contains("tmp/factory/tmp/factory")),
            "member name must not be prefixed twice: {names:?}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_streamed_partition_emits_exactly_the_same_frames_as_an_in_memory_one() {
        // Streaming must be byte-for-byte transparent: same CBWs, same round
        // boundaries, same CRC. This is the property that lets a 7.8 GB package
        // flash with the same protocol as the 2.4 GB one that already boots.
        let base = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into());
        let root = std::path::PathBuf::from(base).join(format!("rtd-stream-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        let payload = vec![0x5Au8; 600 * 1024]; // 3 chunks: FIRST, MIDDLE, LAST
        let raw = root.join("raw.bin");
        std::fs::write(&raw, &payload).unwrap();

        let in_memory = BurnPlan {
            hwsetting: Some(vec![0u8; 16]),
            partitions: vec![PartitionWrite {
                target: "P".into(),
                offset: 0x200,
                size: payload.len() as u64,
                data: payload.clone(),
                member: None,
            }],
            flash_info: emmc(),
            ..Default::default()
        };
        let streamed = BurnPlan {
            hwsetting: Some(vec![0u8; 16]),
            partitions: vec![PartitionWrite {
                target: "P".into(),
                offset: 0x200,
                size: payload.len() as u64,
                data: Vec::new(),
                member: Some(MemberRef {
                    image: raw,
                    name: "raw.bin".into(),
                    data_offset: 0,
                    len: payload.len() as u64,
                }),
            }],
            flash_info: emmc(),
            ..Default::default()
        };

        let mut a = Transport::new(MockDevice::with_replies(vec![Reply::Pass; 16]));
        run(&mut a, &in_memory, &BurnOptions::default(), &mut NoProgress).unwrap();
        let mut b = Transport::new(MockDevice::with_replies(vec![Reply::Pass; 16]));
        run(&mut b, &streamed, &BurnOptions::default(), &mut NoProgress).unwrap();

        let fa: Vec<Vec<u8>> = cbows(a.device()).iter().map(|c| c.encode().to_vec()).collect();
        let fb: Vec<Vec<u8>> = cbows(b.device()).iter().map(|c| c.encode().to_vec()).collect();
        assert_eq!(fa, fb, "streamed burn must match the in-memory one frame for frame");

        let _ = std::fs::remove_dir_all(&root);
    }
}
