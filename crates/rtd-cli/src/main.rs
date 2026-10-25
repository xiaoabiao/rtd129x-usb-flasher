//! `rtd-flash` — command-line front end.
//!
//! Phase 1 only wires up the protocol layer so it can be exercised without
//! hardware. Device and image commands land in later phases.

#[cfg(feature = "usb")]
use rtd_core::device::filter;
use rtd_core::device::mock::MockDevice;
use rtd_core::hwconfig::{self, HwSetting};
use rtd_core::image;
use rtd_core::protocol::{cmd_type, consts, indicator, Cbw, Csw, FlashInfo, Opcode};
use rtd_core::transport::{Transport, VecLog};

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("selftest") | None => {
            selftest();
            Ok(())
        }
        Some("cbw") => {
            demo_cbw();
            Ok(())
        }
        Some("replay") => {
            demo_replay();
            Ok(())
        }
        Some("hwsetting") => {
            demo_hwsetting();
            Ok(())
        }
        Some("image") => {
            demo_image(args.get(1).map(String::as_str))?;
            Ok(())
        }
        Some("devices") => {
            list_devices_cmd()?;
            Ok(())
        }
        Some("writeprobe") => {
            writeprobe_cmd(args.get(1).map(String::as_str))?;
            Ok(())
        }
        Some("inspect") => {
            inspect_cmd(args.get(1).map(String::as_str))?;
            Ok(())
        }
        Some("ddr") => {
            ddr_cmd();
            Ok(())
        }
        Some("probe") => {
            probe_cmd(args.get(1).map(String::as_str))?;
            Ok(())
        }
        Some("plan") => {
            plan_cmd(args.get(1).map(String::as_str), args.get(2).map(String::as_str))?;
            Ok(())
        }
        Some("burn") => {
            burn_cmd(args.get(1).map(String::as_str), args.get(2).map(String::as_str))?;
            Ok(())
        }
        Some(other) => {
            eprintln!("unknown command: {other}");
            eprintln!(
                "usage: rtd-flash [selftest|cbw|replay|hwsetting|image [path]|devices|probe [key]|plan <install.img> [ddr-type]|burn <install.img> [ddr-type]|ddr|inspect <install.img>|writeprobe [key]]"
            );
            std::process::exit(2);
        }
    }
}

/// Print the frame sizes and a decoded sample so a human can eyeball them.
fn demo_cbw() {
    let cbw = Cbw::new(
        Opcode::Write as u8,
        cmd_type::WRITE_CHUNK,
        0x0107,
        0x40000,
        indicator::FIRST,
        0,
        2,
        0,
        0,
        0,
        0,
        0,
        0xDEAD_BEEF,
    );
    let bytes = cbw.encode();
    println!("CBW ({} bytes):", bytes.len());
    for (i, chunk) in bytes.chunks(8).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        println!("  +{:#04x}  {}", i * 8, hex.join(" "));
    }

    let mut raw = [0u8; 50];
    raw[0..4].copy_from_slice(&rtd_core::protocol::CSW_SIGNATURE.to_le_bytes());
    raw[4..8].copy_from_slice(&rtd_core::protocol::CBW_TAG.to_le_bytes());
    let csw = Csw::decode(&raw).expect("valid csw");
    println!(
        "CSW: {} bytes, status at +{}, value {:?}",
        Csw::LEN,
        rtd_core::protocol::CSW_STATUS_OFFSET,
        csw.status()
    );

    let fi = FlashInfo::default();
    println!(
        "FlashInfo: {} bytes, effective chunk {:#x}",
        fi.encode().len(),
        fi.effective_chunk()
    );
}

/// Drive the whole eMMC burn sequence against the mock backend.
///
/// This is the Phase 1 acceptance demo: it shows the exact frames the tool
/// would put on the wire, without needing a board.
fn demo_replay() {
    let dev = MockDevice::always_pass();
    let log = VecLog::default();
    let mut t = Transport::new(dev).with(rtd_core::transport::FakeClock::default(), log);

    // Chunking follows trans_size (SYSTEM.ini `WRITE RANGE=256` KiB).
    let mut fi = FlashInfo::default();
    fi.trans_size = 0x4_0000;

    println!("=== simulated eMMC burn sequence ===\n");

    // 1) hwsetting -> 0x1500000, then DDR enable
    let hwsetting = vec![0xA5u8; 1184];
    t.write_hwsetting(&hwsetting, &fi).expect("hwsetting");
    t.enable_ddr(&fi).expect("ddr enable");
    println!("[1] hwsetting  {} bytes -> 0x{:X}, then 0xFA DDR enable",
             hwsetting.len(), consts::ADDR_USB_HWSETTING);

    // 2) bootloader members at the verified LBAs
    let members: [(&str, u64, usize); 4] = [
        ("hw_setting.bin", consts::lba::HW_SETTING, 3200),
        ("uboot.bin",      consts::lba::UBOOT,      604_128),
        ("fsbl.bin",       consts::lba::FSBL,       72_544),
        ("tee.bin",        consts::lba::TEE,        507_616),
    ];
    println!("\n[2] bootloader members");
    for (name, lba, size) in members {
        let blob = vec![0x5Au8; size];
        t.write_member(lba, &blob, &fi).expect("member");
        println!("    {name:16} {size:>8} bytes -> LBA {lba}");
    }

    // 3) one image partition
    println!("\n[3] image partitions (layout.txt driven)");
    let part = vec![0x11u8; 0x3_0000];
    t.write_member(0x8000, &part, &fi).expect("partition");
    println!("    FW_KERNEL       {:>8} bytes -> LBA 0x8000", part.len());

    println!("\n=== frames the transport produced ===");
    let frames = t.device().cbw_frames();
    println!("CBW frames: {}", frames.len());
    for (i, f) in frames.iter().enumerate() {
        let cbw = Cbw::decode(f).expect("decode");
        let op = Opcode::from_u8(cbw.cbwcb.opcode)
            .map(|o| o.name().to_string())
            .unwrap_or_else(|| format!("0x{:02X}", cbw.cbwcb.opcode));
        if i < 12 || i >= frames.len() - 2 {
            println!(
                "  #{:<3} op={:<14} lba=0x{:<9X} len=0x{:<6X} ind={} crc32=0x{:08X}",
                i,
                op,
                cbw.cbwcb.logical_block_address,
                cbw.data_transfer_length,
                cbw.indicator,
                cbw.cbwcb.crc32
            );
        } else if i == 12 {
            println!("  ...");
        }
    }
    println!("\ntotal CBWs: {}, payload writes: {}",
             frames.len(), t.device().payloads().len());

    let total: usize = frames
        .iter()
        .map(|f| Cbw::decode(f).unwrap().data_transfer_length as usize)
        .sum();
    println!("total payload: {} bytes ({:.2} MiB)", total, total as f64 / 1048576.0);
}

/// Enumerate attached RTD129x devices.
fn list_devices_cmd() -> anyhow::Result<()> {
    #[cfg(feature = "usb")]
    {
        let devs = rtd_core::device::usb::list_devices()?;
        if devs.is_empty() {
            println!("no RTD129x device found (looking for 0bda:1195)");
            return Ok(());
        }
        println!("{:>5}  {:>8}  {:<40}  {}", "addr", "key", "description", "ifaces");
        let mut list = devs.clone();
        filter::sort_stable(&mut list);
        for d in &list {
            println!(
                "{:>5}  {:>8}  {:<40}  {}",
                d.address,
                d.key(),
                d.describe(),
                d.interface_count
            );
        }
        if let Some(issue) = filter::check_limit(list.len(), 8) {
            match issue {
                filter::LimitIssue::NoneFound => {}
                filter::LimitIssue::TooMany { found, limit } => {
                    println!("\nnote: {found} devices attached but MAX USB CONNECTION={limit}")
                }
            }
        }
        Ok(())
    }
    #[cfg(not(feature = "usb"))]
    {
        let reason = rtd_core::device::USB_DISABLED;
        anyhow::bail!("USB backend unavailable: {reason}");
    }
}

/// Find out exactly which write fails, and with what error.
///
/// `WriteFile` on the board's UMDF device can return `ERROR_NOT_SUPPORTED`,
/// which says nothing about *which* request was refused. This walks the real
/// transport sequence one step at a time -- a valid CBW, then the payload, then
/// the CSW read -- and reports each result. The CBW it sends is a status query,
/// which is harmless whatever state the board is in.
#[cfg(feature = "usb")]
fn writeprobe_cmd(key: Option<&str>) -> anyhow::Result<()> {
    use rtd_core::protocol::{cbw::Cbw, consts};

    let mut dev = rtd_core::device::open(key)?;
    println!("已打开：{}", dev.describe());
    println!();

    // 1) A zero-length write. Nothing reaches the device, so this isolates the
    //    "can this handle be written to at all" question from payload size.
    match dev.write_all(&[]) {
        Ok(()) => println!("  写入 0 字节        : OK"),
        Err(e) => println!("  写入 0 字节        : 失败 -- {e}"),
    }

    // 2) A real CBW (43 bytes) for the sense/status opcode. This is the exact
    //    frame the transport sends first, so if it is refused the problem is the
    //    handle or the driver, not the payload.
    let fi = rtd_core::protocol::FlashInfo::default();
    let bytes = Cbw::sense_query(&fi).encode();
    println!("  CBW 长度           : {} 字节", bytes.len());
    match dev.write_all(&bytes) {
        Ok(()) => println!("  写入 CBW           : OK"),
        Err(e) => println!("  写入 CBW           : 失败 -- {e}"),
    }
    match dev.flush() {
        Ok(()) => println!("  FlushFileBuffers   : OK"),
        Err(e) => println!("  FlushFileBuffers   : 失败 -- {e}"),
    }

    // 3) Larger writes, to see whether the length is what the driver objects to.
    for n in [512usize, 4096, consts::MAX_USB_TRANSFER as usize] {
        let buf = vec![0u8; n];
        match dev.write_all(&buf) {
            Ok(()) => println!("  写入 {n:>7} 字节   : OK"),
            Err(e) => println!("  写入 {n:>7} 字节   : 失败 -- {e}"),
        }
    }

    // 4) A read on a worker thread, so a silent device cannot hang the probe.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = [0u8; consts::CSW_LEN];
        let _ = tx.send(dev.read(&mut buf).map(|n| n));
    });
    match rx.recv_timeout(std::time::Duration::from_secs(5)) {
        Ok(Ok(n)) => println!("  读取 CSW           : OK（{n} 字节）"),
        Ok(Err(e)) => println!("  读取 CSW           : 失败 -- {e}"),
        Err(_) => println!("  读取 CSW           : 5 秒内无响应（设备未回话）"),
    }

    println!();
    println!("说明：若 0 字节写入就失败，问题在句柄本身（驱动或打开方式）；");
    println!("      若只有大写入失败，问题在传输长度。");
    Ok(())
}

/// Drive the whole eMMC burn sequence against the mock backend.
///
/// This is the Phase 1 acceptance demo: it shows the exact frames the tool
/// would put on the wire, without needing a board.

#[cfg(not(feature = "usb"))]
fn writeprobe_cmd(_key: Option<&str>) -> anyhow::Result<()> {
    anyhow::bail!("本版本未编译 USB 后端（--features usb）");
}

/// Dump the structure of an `install.img`, for when detection fails.
///
/// Prints the detected project layout, every top-level entry, and the member
/// list. When the tool cannot work out an image's layout, this is what says why.
fn inspect_cmd(image: Option<&str>) -> anyhow::Result<()> {
    use rtd_core::image::install_img;

    let Some(image) = image else {
        anyhow::bail!("usage: rtd-flash inspect <install.img>");
    };
    let image = std::path::PathBuf::from(image);
    if !image.is_file() {
        anyhow::bail!("{} 不存在", image.display());
    }

    let members = install_img::list_members(&image)?;
    println!("镜像      : {}", image.display());
    println!("大小      : {} 字节", std::fs::metadata(&image)?.len());
    println!("成员数    : {}", members.len());
    println!();

    // Detection result, with the reason when it fails.
    match install_img::detect_project_in_members(members.iter().map(|(n, _)| n.as_str())) {
        Ok(k) => println!("项目布局  : {:?}  (目录名 {})", k, k.dir_name()),
        Err(e) => println!("项目布局  : 未识别 -- {e}"),
    }
    println!();

    let tops = install_img::top_level_entries(members.iter().map(|(n, _)| n.as_str()), 40);
    println!("顶层条目（{} 个）：", tops.len());
    for t in &tops {
        println!("  {t}");
    }
    println!();

    // A prefix histogram, which reveals the nesting depth at a glance.
    println!("成员列表（前 40 个）：");
    for (i, (name, size)) in members.iter().take(40).enumerate() {
        println!("  {:>3}. {:>12}  {}", i + 1, size, name);
    }
    if members.len() > 40 {
        println!("  ...（共 {} 个）", members.len());
    }
    println!();

    // The raw layout text, so a parsing disagreement is visible directly.
    match rtd_core::image::install_img::read_layout_text(&image) {
        Ok(t) => {
            println!("layout.txt 原文：");
            for line in t.lines().take(40) {
                if !line.trim().is_empty() {
                    println!("  | {}", line.trim_end());
                }
            }
            println!();
        }
        Err(e) => println!("layout.txt 读取失败：{e}\n"),
    }

    // The decisive section for a flat image: which layout.txt target maps to
    // which file. A target with no file is a partition that would be skipped.
    match rtd_core::burn::explain_partition_matching(&image) {
        Ok(rows) => {
            println!("分区匹配（layout.txt → 镜像文件）：");
            for r in &rows {
                let file = match &r.matched {
                    Some(f) => f.clone(),
                    None => "*** 没有对应文件 ***".to_string(),
                };
                let name = match &r.name_field {
                    Some(n) => format!("name={}", n.trim()),
                    None => "name=(缺)".to_string(),
                };
                println!(
                    "  {:<18} off={:#010x} size={:#09x}  {:<24} ->  {}  [{}]",
                    r.target.trim(),
                    r.offset,
                    r.size,
                    name,
                    file,
                    r.how()
                );
            }
            let missing = rows.iter().filter(|r| r.matched.is_none()).count();
            if missing > 0 {
                println!();
                println!("  ⚠ {missing} 个分区没有对应文件，会被跳过");
            }
            println!();
        }
        Err(e) => println!("分区匹配：无法解析 layout.txt -- {e}\n"),
    }

    // The files that actually drive a burn.
    let has_layout = members.iter().any(|(n, _)| n.ends_with("layout.txt"));
    println!("含 layout.txt : {}", if has_layout { "是" } else { "否" });
    let looks_like_project = tops.iter().any(|t| {
        install_img::ProjectKind::from_dir_name(t).is_some()
    });
    println!(
        "顶层含项目目录: {}",
        if looks_like_project { "是" } else { "否" }
    );
    Ok(())
}

/// List the DRAM configurations and which hwsetting blob each resolves to.
fn ddr_cmd() {
    use rtd_core::ddr::{DdrType, HwSettingSearch};

    let search = HwSettingSearch {
        tool_dir: std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf())),
        image_dir: std::env::current_dir().ok(),
    };

    println!("{:<12} {:<14} {:<38} {}", "类型", "说明", "hwsetting 文件", "状态");
    println!("{}", "-".repeat(86));
    for d in DdrType::ALL {
        let file = d.hwsetting_file();
        let status = if search.is_available(d) { "找到" } else { "--" };
        println!(
            "{:<12} {:<14} {:<38} {}",
            d.label(),
            d.describe(),
            file,
            status
        );
    }
    println!();
    println!("说明：只有 DDR 代际（DDR3/DDR4）会改变 hwsetting，容量不影响。");
    if let Some((p, kind)) = search.find(None) {
        println!("通用 blob：{} [{}]", p.display(), kind.label());
    } else {
        println!("通用 blob：未找到（usb_hwsetting.bin）");
    }
}

/// Burn an image to the attached board, with the transport's own log on stdout.
///
/// This is the scriptable counterpart of the GUI's "开始烧写": it resolves the
/// same sources (image + bootloader.tar + hwsetting blob + SYSTEM.ini), prints
/// the plan, then runs it. Used for hardware tests where a GUI round trip would
/// only get in the way.
fn burn_cmd(image: Option<&str>, ddr_arg: Option<&str>) -> anyhow::Result<()> {
    #[cfg(not(feature = "usb"))]
    {
        let _ = (image, ddr_arg);
        anyhow::bail!("本版本未编译 USB 后端（用 --features usb 重新编译）");
    }
    #[cfg(feature = "usb")]
    {
        use std::io::Write as _;

        use rtd_core::burn::{BurnOptions, BurnSources, Progress};
        use rtd_core::transport::{RealClock, TransportLog};

        let Some(image) = image else {
            anyhow::bail!("usage: rtd-flash burn <install.img> [ddr-type]");
        };
        let image = std::path::PathBuf::from(image);
        if !image.is_file() {
            anyhow::bail!("{} 不存在", image.display());
        }
        let ddr = match ddr_arg {
            Some(a) => match rtd_core::ddr::DdrType::from_label(a) {
                Some(d) => Some(d),
                None => {
                    let all: Vec<&str> =
                        rtd_core::ddr::DdrType::ALL.iter().map(|d| d.label()).collect();
                    anyhow::bail!("未知 DDR 类型 {a:?}；可选：{}", all.join(", "));
                }
            },
            None => None,
        };

        // Same source resolution as `plan`.
        let dir = image.parent().unwrap_or(std::path::Path::new(".")).to_path_buf();
        let mut tar = None;
        for cand in [dir.join("bootloader.tar"), dir.join("Tempfile/bootloader.tar")] {
            if cand.is_file() {
                tar = Some(cand);
                break;
            }
        }
        let search = rtd_core::ddr::HwSettingSearch {
            tool_dir: std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.to_path_buf())),
            image_dir: Some(dir.clone()),
        };
        let hw = search.find(ddr).map(|(p, _)| p);
        let mut ini = None;
        let cand = dir.join("SYSTEM.ini");
        if cand.is_file() {
            ini = Some(cand);
        }

        let sources = BurnSources {
            install_img: Some(image.clone()),
            bootloader_tar: tar,
            hwsetting: hw,
            system_ini: ini,
        };
        let plan = sources.build()?;
        println!("镜像 : {}", image.display());
        println!("计划 : {}", plan.describe());
        plan.validate(&BurnOptions::default())
            .map_err(|p| anyhow::anyhow!("计划校验失败：{}", p.join("；")))?;

        let backend = rtd_core::device::open(None)?;
        println!("设备 : {}", backend.describe());

        #[derive(Debug)]
        struct StdoutLog;
        impl TransportLog for StdoutLog {
            fn line(&self, msg: &str) {
                print!("{msg}");
                let _ = std::io::stdout().flush();
            }
        }

        struct CliProgress {
            last_pct: u64,
        }
        impl Progress for CliProgress {
            fn stage(&mut self, name: &str) {
                println!("\n== {name} ==");
                let _ = std::io::stdout().flush();
            }
            fn advance(&mut self, written: u64, total: u64) {
                let pct = if total == 0 { 100 } else { written * 100 / total };
                if pct >= self.last_pct + 2 || written == total {
                    self.last_pct = pct;
                    print!("\r进度 {pct:>3}%  ({written}/{total})");
                    let _ = std::io::stdout().flush();
                }
            }
        }

        let mut transport = rtd_core::transport::Transport::new(backend).with(RealClock, StdoutLog);
        let mut progress = CliProgress { last_pct: 0 };
        let report = rtd_core::burn::run(&mut transport, &plan, &BurnOptions::default(), &mut progress)?;

        println!();
        println!(
            "烧写完成：{} 字节（hwsetting {}，引导 {} 项，分区 {} 项）",
            report.bytes_written,
            report.hwsetting_bytes,
            report.bootloader_written.len(),
            report.partitions_written.len()
        );
        Ok(())
    }
}

/// Show exactly what a burn would write, without touching a device.
///
/// Flashing is destructive and slow, so there needs to be a way to check the
/// plan first. This reads the image and prints the frame sequence the burn would
/// produce, then stops.
fn plan_cmd(image: Option<&str>, ddr_arg: Option<&str>) -> anyhow::Result<()> {
    let Some(image) = image else {
        anyhow::bail!("usage: rtd-flash plan <install.img> [ddr-type]");
    };

    // The DDR choice selects the hwsetting blob. Without one, the generic
    // `usb_hwsetting.bin` is used, which may not match the board.
    let ddr = match ddr_arg {
        Some(a) => match rtd_core::ddr::DdrType::from_label(a) {
            Some(d) => Some(d),
            None => {
                let all: Vec<&str> = rtd_core::ddr::DdrType::ALL.iter().map(|d| d.label()).collect();
                anyhow::bail!("未知 DDR 类型 {a:?}；可选：{}", all.join(", "));
            }
        },
        None => None,
    };
    let image = std::path::PathBuf::from(image);
    if !image.is_file() {
        anyhow::bail!("{} 不存在", image.display());
    }

    // Optional siblings, exactly as the GUI would find them.
    let dir = image.parent().unwrap_or(std::path::Path::new("."));
    let mut tar = None;
    for cand in [dir.join("bootloader.tar"), dir.join("Tempfile/bootloader.tar")] {
        if cand.is_file() {
            tar = Some(cand);
            break;
        }
    }
    let search = rtd_core::ddr::HwSettingSearch {
        tool_dir: std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf())),
        image_dir: Some(dir.to_path_buf()),
    };
    let resolved = search.find(ddr);
    let hw = resolved.as_ref().map(|(p, _)| p.clone());
    let mut ini = None;
    let cand = dir.join("SYSTEM.ini");
    if cand.is_file() {
        ini = Some(cand);
    }

    let sources = rtd_core::burn::BurnSources {
        install_img: Some(image.clone()),
        bootloader_tar: tar,
        hwsetting: hw,
        system_ini: ini,
    };
    println!("镜像      : {}", image.display());
    println!("bootloader: {}", sources.bootloader_tar.as_ref().map_or("(未找到)".into(), |p| p.display().to_string()));
    match (&resolved, ddr) {
        (Some((p, kind)), Some(d)) => println!(
            "hwsetting : {}  [{}，对应 {}]",
            p.display(),
            kind.label(),
            d.describe()
        ),
        (Some((p, kind)), None) => println!(
            "hwsetting : {}  [{}]  ⚠ 未指定 DDR 类型",
            p.display(),
            kind.label()
        ),
        (None, _) => println!("hwsetting : (未找到)  ⚠ 没有它无法配置 DDR"),
    }
    println!("SYSTEM.ini: {}", sources.system_ini.as_ref().map_or("(未找到，用默认参数)".into(), |p| p.display().to_string()));
    println!();

    let plan = sources.build()?;
    println!("== 烧写计划 ==");
    println!("  {}", plan.describe());
    println!(
        "  分片 {:#x}   flash_type {}",
        plan.flash_info.effective_chunk(),
        plan.flash_info.flash_type
    );
    println!();

    // The exact frame sequence, which is what a reviewer actually needs to see.
    println!("== 帧序列 ==");
    let mut n = 0usize;
    if let Some(blob) = &plan.hwsetting {
        n += 1;
        let frames = blob.len().div_ceil(plan.flash_info.effective_chunk().max(1));
        println!(
            "  {n:>3}. USB_HWSETTING  addr={:#x}  {} 字节  {} 帧",
            rtd_core::protocol::consts::ADDR_USB_HWSETTING,
            blob.len(),
            frames.max(1)
        );
        n += 1;
        println!("  {n:>3}. DDR_ENABLE     type=0x06  5 字节  payload=\"test\\0\"");
    }
    for (name, data, lba) in &plan.bootloader {
        n += 1;
        let frames = data.len().div_ceil(plan.flash_info.effective_chunk().max(1)).max(1);
        println!("  {n:>3}. WRITE          lba={lba:<6} {name:<18} {:>9} 字节  {frames} 帧", data.len());
    }
    for p in &plan.partitions {
        if !p.has_payload() {
            println!("      (跳过 {} — 镜像里没有对应内容)", p.target.trim());
            continue;
        }
        n += 1;
        let frames = p
            .payload_len()
            .div_ceil(plan.flash_info.effective_chunk().max(1) as u64)
            .max(1);
        println!(
            "  {n:>3}. WRITE          lba={:<6} {:<18} {:>9} 字节  {frames} 帧{}",
            p.lba()?,
            p.target.trim(),
            p.payload_len(),
            if p.member.is_some() { "  （流式）" } else { "" }
        );
    }
    println!();
    println!("共 {n} 个阶段，{} 字节", plan.total_bytes());

    if ddr.is_none() {
        println!();
        println!("提示：未指定 DDR 类型，用的是通用 hwsetting。请确认它匹配你的板子：");
        println!("      rtd-flash plan <install.img> <DDR 类型>");
    }

    match plan.validate(&rtd_core::burn::BurnOptions::default()) {
        Ok(()) => println!("校验通过 —— 可以烧写"),
        Err(problems) => {
            println!("校验未通过：");
            for p in problems {
                println!("  - {p}");
            }
            anyhow::bail!("计划不可执行");
        }
    }
    Ok(())
}

/// Open the board and report the claimed endpoints.
///
/// This is deliberately **read-only**: it claims the interface and prints what
/// it found, but never sends a CBW. That makes it safe to run at any point and
/// it isolates "can we talk to the device at all" from "is the flash protocol
/// correct".
fn probe_cmd(key: Option<&str>) -> anyhow::Result<()> {
    #[cfg(feature = "usb")]
    {
        use rtd_core::device::DeviceBackend;

        let found = rtd_core::device::usb::list_devices()?;
        if found.is_empty() {
            anyhow::bail!("no RTD129x device found (looking for 0bda:1195)");
        }
        println!("found {} target device(s):", found.len());
        for d in &found {
            println!("  {}  {}", d.key(), d.describe());
        }

        println!();
        match key {
            Some(k) => println!("opening {k} ..."),
            None => println!("opening first device ..."),
        }

        // `device::open` picks the right backend: on Windows the board is bound
        // to the UMDF driver, which needs CreateFile rather than the WinUSB API.
        match rtd_core::device::open(key) {
            Ok(b) => {
                println!("OPENED  {}", b.describe());
                println!();
                println!("No data was sent (read-only probe).");
                Ok(())
            }
            Err(e) => {
                println!("OPEN FAILED: {e}");
                anyhow::bail!("could not open the device");
            }
        }
    }
    #[cfg(not(feature = "usb"))]
    {
        let _ = key;
        anyhow::bail!("USB backend unavailable: {}", rtd_core::device::USB_DISABLED);
    }
}

/// Decode the shipped hwsetting blobs and show the instruction mix.
fn demo_hwsetting() {
    use std::path::PathBuf;
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root")
        .join("fixtures/hwsetting");

    println!("=== hwsetting blobs (AES-128-ECB) ===\n");
    for entry in std::fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "bin"))
    {
        let path = entry.path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let Ok(bytes) = std::fs::read(&path) else { continue };
        match HwSetting::from_encrypted(&bytes) {
            Ok(hw) => {
                let c = hw.counts();
                println!("{}", name);
                println!(
                    "  {} bytes -> {} ops (write {} / poll {} / mask {} / nop {})",
                    bytes.len(),
                    c.total(),
                    c.write,
                    c.poll,
                    c.mask,
                    c.nop
                );
                println!("  trailer {} bytes", hw.trailer.len());
                for op in hw.ops.iter().take(3) {
                    println!("    {}", op.to_log_line());
                }
                if let Some(op) = hw.ops.iter().find(|o| {
                    matches!(o, hwconfig::op::Op::Poll { .. } | hwconfig::op::Op::Mask { .. })
                }) {
                    println!("    ...{}", op.to_log_line());
                }
                // Prove the round trip on the real bytes.
                match hw.to_encrypted() {
                    Ok(re) if re == bytes => println!("  round trip: byte-identical OK"),
                    Ok(re) => println!("  round trip: MISMATCH ({} vs {})", re.len(), bytes.len()),
                    Err(e) => println!("  round trip error: {e}"),
                }
            }
            Err(e) => println!("{name}: ERROR {e}"),
        }
        println!();
    }
}

/// Inspect an install.img, or the bundled fixtures when no path is given.
fn demo_image(path: Option<&str>) -> anyhow::Result<()> {
    use std::path::PathBuf;
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root")
        .join("fixtures/image");

    match path {
        Some(p) => {
            let p = PathBuf::from(p);
            println!("=== {} ===", p.display());
            for (name, size) in image::install_img::list_members(&p)? {
                println!("  {size:>12}  {name}");
            }
        }
        None => {
            let tar = fixtures.join("bootloader.tar");
            println!("=== {} ===", tar.display());
            let (members, next) = image::bootloader::load(&tar)?;
            println!(
                "{:>16}  {:>10}  {:>8}  {:>8}",
                "member", "bytes", "lba", "sectors"
            );
            for m in &members {
                println!(
                    "{:>16}  {:>10}  {:>8}  {:>8}",
                    m.member.file_name(),
                    m.data.len(),
                    m.lba,
                    m.sectors()
                );
            }
            println!("next free sector: {next}");
            println!();

            // Also show the SYSTEM.ini projection.
            let ini = fixtures.join("system_ini_sample.ini");
            if ini.exists() {
                let s = image::SystemIni::from_path(&ini)?;
                let fi = s.flash_info();
                println!("=== SYSTEM.ini projection ===");
                println!("  flash type        : {:?}", s.flash_type);
                println!("  combo type        : {:?}", s.flash_combo_type);
                println!("  ddr type          : {:?}", s.ddr_type);
                println!("  write range       : {:?} KiB -> trans_size {:#x}", s.write_range, fi.trans_size);
                println!("  one write size    : {:?} MiB -> once_trans_max {:#x}", s.one_write_size, fi.once_trans_max_size);
                println!("  effective chunk   : {:#x}", fi.effective_chunk());
                println!("  burn factory      : {:?}", s.burn_factory);
                println!("  burn se storage   : {:?}", s.burn_se_storage);
                println!("  only burn efuse   : {:?}", s.only_burn_efuse);
            } else {
                println!("(copy SYSTEM.ini to {} for the config demo)", ini.display());
            }
        }
    }
    Ok(())
}

/// Lightweight sanity checks that do not need hardware.
fn selftest() {
    let mut ok = true;

    macro_rules! check {
        ($name:expr, $cond:expr) => {{
            let pass = $cond;
            println!("[{}] {}", if pass { " ok " } else { "FAIL" }, $name);
            ok &= pass;
        }};
    }

    let cbw = Cbw::new(
        Opcode::Write as u8,
        cmd_type::WRITE_CHUNK,
        0x0107,
        0x40000,
        indicator::FIRST,
        0,
        2,
        0,
        0,
        0,
        0,
        0,
        0xDEAD_BEEF,
    );
    let enc = cbw.encode();
    check!("CBW is 43 bytes", enc.len() == 43);
    check!(
        "CBW signature is 'USBC' little-endian",
        enc[0..4] == [0x55, 0x53, 0x42, 0x43]
    );
    check!(
        "CBW tag is 0x12345678 little-endian",
        enc[4..8] == [0x78, 0x56, 0x34, 0x12]
    );
    check!("bCBWCBLength is 28 at +0x0E", enc[0x0E] == 28);
    check!("opcode lands at +0x0F", enc[0x0F] == Opcode::Write as u8);
    check!("CBW round-trips", Cbw::decode(&enc) == Some(cbw));

    check!("CSW_LEN is 50", Csw::LEN == 50);
    check!(
        "CSW status offset is 13",
        rtd_core::protocol::CSW_STATUS_OFFSET == 13
    );
    check!(
        "CBWCB length constant is 28",
        rtd_core::protocol::CBW_CBWCB_LEN == 28
    );

    let fi = FlashInfo::default();
    check!("FlashInfo encodes to 64 bytes", fi.encode().len() == 64);
    check!(
        "FlashInfo size_of is 64",
        std::mem::size_of::<FlashInfo>() == 64
    );

    // The verified bootloader LBA chain.
    let mut lba = rtd_core::protocol::lba::HW_SETTING;
    lba = FlashInfo::advance_sectors(lba, 3200);
    let uboot_ok = lba == rtd_core::protocol::lba::UBOOT;
    lba = FlashInfo::advance_sectors(lba, 604128);
    let fsbl_ok = lba == rtd_core::protocol::lba::FSBL;
    lba = FlashInfo::advance_sectors(lba, 72544);
    let tee_ok = lba == rtd_core::protocol::lba::TEE;
    check!(
        "bootloader LBA chain 256 -> 263 -> 1443 -> 1585",
        uboot_ok && fsbl_ok && tee_ok
    );

    check!(
        "all 11 opcodes decode",
        (0u8..=255).filter(|v| Opcode::from_u8(*v).is_some()).count() == 11
    );

    println!();
    if ok {
        println!("selftest PASSED");
    } else {
        println!("selftest FAILED");
        std::process::exit(1);
    }
}
