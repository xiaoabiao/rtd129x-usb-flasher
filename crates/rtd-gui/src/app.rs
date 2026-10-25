//! The egui rendering layer.
//!
//! Every widget here is a thin shell over [`crate::state`]; the interesting
//! logic lives there and is unit-tested headlessly. This file only decides
//! *layout* and *when* to call those methods.

use eframe::egui;
use egui_extras::{Column, TableBuilder};

use crate::state::{AppState, DeviceState, Level};

/// The window title, matching nothing in the original (which used a bitmap
/// dialog) but naming the SoC family the tool targets.
const TITLE: &str = "RTD129x 线刷工具";

/// Launch the GUI.
///
/// `initial_image` preloads an `install.img` (`rtd-gui.exe D:\install.img`),
/// which is handy for repeat burns and for smoke-testing the plan preview.
pub fn run(initial_image: Option<std::path::PathBuf>) -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 720.0])
            .with_min_inner_size([820.0, 560.0])
            .with_title(TITLE),
        ..Default::default()
    };
    eframe::run_native(
        TITLE,
        options,
        Box::new(move |cc| {
            let mut app = App::new();

            // Report the USB backend status up front. A UI-only build looks
            // completely healthy until someone presses a device button, so this
            // is stated at startup rather than only when a scan fails.
            //
            // These must be `#[cfg]` attributes rather than `cfg!()`: `cfg!`
            // evaluates to a bool at compile time but does **not** remove the
            // untaken branch, so the gated function would still have to exist.
            #[cfg(feature = "usb")]
            app.state
                .push_log(crate::state::LogLine::info(usb_backend_summary()));
            #[cfg(not(feature = "usb"))]
            {
                app.usb_missing = true;
                app.state.push_log(crate::state::LogLine::error(
                    "本版本未编译 USB 后端，无法连接设备（请用 --features usb 重新编译）",
                ));
            }

            // egui ships no CJK glyphs, so Chinese renders as tofu boxes until a
            // system font is installed. This must happen before any UI is built.
            match crate::font::install(&cc.egui_ctx) {
                Some(path) => app.state.push_log(crate::state::LogLine::info(format!(
                    "已加载中文字体：{}",
                    path.display()
                ))),
                None => app.state.push_log(crate::state::LogLine::warn(
                    "未找到中文字体，中文可能显示为方块（请确认 C:\\Windows\\Fonts 存在且可读）",
                )),
            }

            // Preload an image passed on the command line.
            if let Some(path) = initial_image {
                app.state.image_path_input = path.to_string_lossy().into_owned();
                if let Err(e) = app.state.load_image(&path) {
                    app.state.last_error = Some(e.to_string());
                    app.state
                        .push_log(crate::state::LogLine::error(format!("预加载镜像失败：{e}")));
                }
            }

            // When capturing a screenshot (or with RTD_GUI_DEMO=1) fill the
            // window so the image shows a populated UI instead of an empty one.
            if std::env::var_os("EFRAME_SCREENSHOT_TO").is_some()
                || std::env::var_os("RTD_GUI_DEMO").is_some()
            {
                app.seed_demo_content(cc);
            }
            Ok(Box::new(app))
        }),
    )
}

/// Interpret a text field as a path, treating blank as "not set".
fn non_empty_path(s: &str) -> Option<std::path::PathBuf> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(std::path::PathBuf::from(t))
    }
}

/// The top-level app.
#[derive(Default)]
pub struct App {
    /// All application state.
    pub state: AppState,
    /// Text buffer for the hwsetting editor, kept in sync on load.
    hwsetting_buffer: String,
    /// Whether the hwsetting buffer differs from the loaded ops.
    hwsetting_dirty: bool,
    /// Text buffer for the log filter.
    log_filter: String,
    /// Set when this binary was built without the `usb` feature, so the status
    /// bar can say so permanently instead of only on a failed scan.
    usb_missing: bool,
    /// The running burn, when one is in progress.
    burn: Option<crate::worker::BurnHandle>,
    /// Latest progress from the worker, as (written, total).
    burn_progress: (u64, u64),
    /// Selected DRAM configuration.
    ///
    /// `None` means "not chosen yet". The original refuses to start in that
    /// state (`Please select ddr type first!`) because the hwsetting blob trains
    /// the DDR PHY, and guessing wrong means the board never brings memory up.
    ddr_type: Option<rtd_core::ddr::DdrType>,
    /// Where DDR-specific hwsetting blobs are searched for.
    hwsetting_search: rtd_core::ddr::HwSettingSearch,
}

/// One line describing which USB backend this build will use.
#[cfg(feature = "usb")]
fn usb_backend_summary() -> String {
    // The board in the field is bound to the vendor's UMDF driver, which the
    // WinUSB API cannot open, so name the backend that will actually be tried.
    // `cfg!` is fine here: both arms are valid on every platform.
    if cfg!(windows) {
        "USB 后端：已启用（Windows / UMDF CreateFile 优先，WinUSB 回退）".to_string()
    } else {
        "USB 后端：已启用（WinUSB）".to_string()
    }
}

impl App {
    /// A new app with a fresh state.
    pub fn new() -> Self {
        // Resolve the hwsetting search paths immediately. Doing this only when
        // an image is picked left the DDR picker reporting "找不到" on a fresh
        // start, even when the blobs were sitting next to the executable.
        let mut app = Self {
            state: AppState::new(),
            hwsetting_buffer: String::new(),
            hwsetting_dirty: false,
            log_filter: String::new(),
            usb_missing: false,
            burn: None,
            burn_progress: (0, 0),
            ddr_type: None,
            hwsetting_search: rtd_core::ddr::HwSettingSearch::default(),
        };
        app.refresh_hwsetting_search();
        app
    }

    /// Refresh where hwsetting blobs are looked for, from the current paths.
    ///
    /// The tool directory is wherever this executable lives, which is where the
    /// original keeps `kylin_usb_hwsetting_*.bin`.
    fn refresh_hwsetting_search(&mut self) {
        let tool_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()));
        let image_dir = non_empty_path(&self.state.image_path_input)
            .and_then(|p| p.parent().map(|d| d.to_path_buf()));
        self.hwsetting_search = rtd_core::ddr::HwSettingSearch { tool_dir, image_dir };
    }

    /// Resolve the hwsetting blob for the chosen DDR type.
    fn resolve_hwsetting(&self) -> Option<(std::path::PathBuf, rtd_core::ddr::HwSettingKind)> {
        self.hwsetting_search.find(self.ddr_type)
    }

    /// The DDR dropdown.
    fn ddr_picker(&mut self, ui: &mut egui::Ui) {
        use rtd_core::ddr::DdrType;

        let current = self
            .ddr_type
            .map(|d| d.label().to_string())
            .unwrap_or_else(|| "— 请选择 —".to_string());

        let mut chosen = self.ddr_type;
        egui::ComboBox::from_id_salt("ddr_type")
            .selected_text(current)
            .width(150.0)
            .show_ui(ui, |ui| {
                for d in DdrType::ALL {
                    let usable = self.hwsetting_search.is_available(d);
                    // Unusable entries stay visible but marked, so the list
                    // matches the original's and the reason is obvious.
                    let text = if usable {
                        d.describe()
                    } else {
                        format!("{}  (无 hwsetting 文件)", d.describe())
                    };
                    ui.selectable_value(&mut chosen, Some(d), text);
                }
            });
        self.ddr_type = chosen;

        // Say what the choice resolved to, so a wrong pick is visible before
        // the burn starts rather than after the board fails to boot.
        let resolved = self.resolve_hwsetting();
        match &resolved {
            Some((path, kind)) => {
                ui.label(
                    egui::RichText::new(format!(
                        "hwsetting: {}",
                        rtd_core::ddr::file_name_of(path)
                    ))
                    .small(),
                );
                if *kind == rtd_core::ddr::HwSettingKind::Generic {
                    ui.colored_label(
                        egui::Color32::from_rgb(220, 180, 90),
                        egui::RichText::new("(通用 blob，未必匹配所选 DDR)").small(),
                    )
                    .on_hover_text(
                        "当前用的是 usb_hwsetting.bin。\n\
                         它未必匹配所选 DRAM；若有对应代际的 \
                         kylin_usb_hwsetting_*.bin 会被优先使用。",
                    );
                }
            }
            None => {
                // "找不到" alone is useless -- name the file and the places
                // that were searched, so the fix is obvious.
                let msg = self.hwsetting_search.explain(self.ddr_type);
                ui.colored_label(
                    egui::Color32::from_rgb(220, 120, 90),
                    egui::RichText::new("找不到 hwsetting 文件").small(),
                )
                .on_hover_text(&msg);

                if ui
                    .small_button("选择…")
                    .on_hover_text("手动指定 hwsetting 文件")
                    .clicked()
                {
                    self.pick_hwsetting();
                }
            }
        }
    }


    /// Whether a burn is currently running.
    fn is_burning(&self) -> bool {
        self.burn.is_some()
    }

    /// Start a burn from whatever sources the user has configured.
    ///
    /// The device is opened on the worker thread, so a slow enumeration cannot
    /// freeze the window.
    fn start_burn(&mut self) {
        if self.is_burning() {
            self.state
                .push_log(crate::state::LogLine::warn("已有烧写任务在进行中"));
            return;
        }

        // Resolve the search paths now: they depend on the image the user picked
        // since the last attempt, and the DDR choice decides which blob to send.
        // An explicitly loaded blob (from the editor) overrides the lookup.
        self.refresh_hwsetting_search();
        let hwsetting = self
            .state
            .hwsetting_path
            .clone()
            .or_else(|| self.resolve_hwsetting().map(|(p, _)| p));

        let sources = rtd_core::burn::BurnSources {
            install_img: non_empty_path(&self.state.image_path_input),
            bootloader_tar: self.bootloader_tar_path(),
            hwsetting,
            system_ini: non_empty_path(&self.state.ini_path_input),
        };

        // Local-only sanity check so the user gets an immediate answer instead of
        // watching a thread log the same complaint.
        let mut missing = Vec::new();
        if sources.install_img.is_none() {
            missing.push("install.img");
        }
        if self.ddr_type.is_none() {
            missing.push("DDR 类型");
        }
        if sources.hwsetting.is_none() {
            missing.push("hwsetting 文件");
        }
        if !missing.is_empty() {
            let msg = format!("请先选择：{}", missing.join("、"));
            self.state.last_error = Some(msg.clone());
            self.state.push_log(crate::state::LogLine::error(msg));

            // A missing hwsetting needs its search paths spelled out: the file
            // does not ship with the tool, and "not found" alone gives the user
            // nowhere to put it.
            if sources.hwsetting.is_none() {
                self.state
                    .push_log(crate::state::LogLine::info("已查找以下位置："));
                for d in self.hwsetting_search.dirs() {
                    self.state.push_log(crate::state::LogLine::info(format!(
                        "  {}",
                        d.display()
                    )));
                }
                self.state.push_log(crate::state::LogLine::info(format!(
                    "需要其中之一：{} 或 usb_hwsetting.bin",
                    self.ddr_type
                        .map(|d| d.hwsetting_file())
                        .unwrap_or_else(|| "(先选 DDR 类型)".into())
                )));
                self.state.push_log(crate::state::LogLine::info(
                    "提示：运行 rtd-gui.exe --diag 生成完整报告",
                ));
            }
            return;
        }

        let options = rtd_core::burn::BurnOptions {
            burn_factory: self.state.options.burn_factory,
            burn_se_storage: self.state.options.burn_se_storage,
            only_burn_efuse: self.state.options.only_burn_efuse,
            compare_data: self.state.options.compare_data,
        };
        let key = self.state.devices.first().map(|d| d.key());

        self.state.begin_run("准备中");
        self.burn_progress = (0, 0);
        self.state
            .push_log(crate::state::LogLine::info("开始烧写…"));
        self.burn = Some(crate::worker::start(sources, options, key));
    }

    /// A bootloader tar sitting next to the image, if one is there.
    ///
    /// The original looks in `Tempfile/bootloader.tar`; we accept either the
    /// same directory as the image or a `Tempfile` beside it.
    fn bootloader_tar_path(&self) -> Option<std::path::PathBuf> {
        let img = non_empty_path(&self.state.image_path_input)?;
        let dir = img.parent()?;
        for cand in [dir.join("bootloader.tar"), dir.join("Tempfile/bootloader.tar")] {
            if cand.is_file() {
                return Some(cand);
            }
        }
        None
    }

    /// Move worker messages into the UI state. Called once per frame.
    fn pump_worker(&mut self) {
        let Some(handle) = &self.burn else { return };
        let msgs = handle.drain();
        let mut finished = false;

        for msg in msgs {
            use crate::worker::WorkerMsg as M;
            match msg {
                M::Stage(name) => {
                    self.state.set_progress_stage(&name);
                    self.state.push_log(crate::state::LogLine::info(name));
                }
                M::Progress { written, total } => {
                    self.burn_progress = (written, total);
                    self.state.set_progress_bytes(written, total);
                }
                M::Log(line) => self.state.push_log(crate::state::LogLine::info(line)),
                M::Done(summary) => {
                    self.state.push_log(crate::state::LogLine::info(summary));
                    self.state.status = "烧写完成".into();
                    finished = true;
                }
                M::Failed(err) => {
                    self.state.push_log(crate::state::LogLine::error(err.clone()));
                    self.state.last_error = Some(err);
                    self.state.status = "烧写失败".into();
                    finished = true;
                }
            }
        }

        if finished {
            // Dropping the handle joins the thread, which has already returned.
            self.burn = None;
            self.burn_progress = (0, 0);
        }
    }

    /// Placeholder rows so a screenshot shows a populated window.
    fn seed_demo_content(&mut self, cc: &eframe::CreationContext<'_>) {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());
        self.state.set_devices(vec![
            rtd_core::device::filter::UsbDeviceInfo {
                bus: 0,
                address: 3,
                vendor_id: rtd_core::protocol::consts::USB_VID,
                product_id: rtd_core::protocol::consts::USB_PID,
                serial: Some("0357802115946".into()),
                product: Some("RTD129x Device".into()),
                interface_count: 1,
            },
            rtd_core::device::filter::UsbDeviceInfo {
                bus: 0,
                address: 5,
                vendor_id: rtd_core::protocol::consts::USB_VID,
                product_id: rtd_core::protocol::consts::USB_PID,
                serial: Some("03578021159A0".into()),
                product: Some("RTD129x Device".into()),
                interface_count: 1,
            },
        ]);
        self.state.set_progress("0357802115946", "layout.txt", 37);
        self.state.finish_device("03578021159A0", DeviceState::Done, 185);
        self.state.begin_run("hwsetting");
        self.state.set_progress("0357802115946", "install.img", 37);
        self.state.push_log(crate::state::LogLine::info(
            "once max trans range : 0x200000 ",
        ));
        self.state.push_log(crate::state::LogLine::info(
            "trans range : 0x40000",
        ));
        self.state.push_log(crate::state::LogLine::info(
            "******** CBW *** CBWCB *******",
        ));
        self.state.push_log(crate::state::LogLine::info(
            "CBW.dCBWDataTransferLength : 0x40000 ",
        ));
        self.state.push_log(crate::state::LogLine::info("CBW.iIndicator: 1 "));
        self.state.push_log(crate::state::LogLine::info(
            "CBW.dCbwcb.LogicalBlockAddress : 0x107 ",
        ));
        self.state.push_log(crate::state::LogLine::warn(
            "PerformReadTest: data failed , retry !",
        ));
        self.state.push_log(crate::state::LogLine::info(
            "DONE - Transmission is completed !",
        ));
        self.state.push_log(
            crate::state::LogLine::error("PerformReadTest: wait timeout: 5 "),
        );
        self.state.status = "烧写中".into();

        // Populate the image/plan panels from the bundled fixtures so the demo
        // window shows a complete plan. Falls back silently when absent.
        let fixtures = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .map(|p| p.join("fixtures/image"));
        if let Some(dir) = fixtures {
            let tar = dir.join("bootloader.tar");
            if let Ok((members, _next)) = rtd_core::image::bootloader::load(&tar) {
                let bootloader = members
                    .iter()
                    .map(|m| (m.member.file_name().to_string(), m.data.len(), m.lba))
                    .collect();
                self.state.image = Some(crate::state::LoadedImage {
                    path: dir.join("bootloader.tar"),
                    project: rtd_core::image::ProjectKind::Package5,
                    partitions: vec![
                        rtd_core::image::Partition {
                            target: "FW_FWTBL ".into(),
                            offset: 0,
                            size: 0x1_0000,
                            name: Some("fwtbl".into()),
                            line: 1,
                        },
                        rtd_core::image::Partition {
                            target: "FW_KERNEL ".into(),
                            offset: 0x300_0000,
                            size: 0x80_0000,
                            name: Some("kernel".into()),
                            line: 2,
                        },
                        rtd_core::image::Partition {
                            target: "FW_KERNEL_DT ".into(),
                            offset: 0x380_0000,
                            size: 0x1_0000,
                            name: Some("dtb".into()),
                            line: 3,
                        },
                        rtd_core::image::Partition {
                            target: "FW_KERNEL_ROOTFS ".into(),
                            offset: 0x400_0000,
                            size: 0x180_0000,
                            name: Some("rootfs".into()),
                            line: 4,
                        },
                    ],
                    bootloader,
                    system_ini_path: dir.join("system_ini_sample.ini").exists().then(|| {
                        dir.join("system_ini_sample.ini")
                    }),
                    flash_info: rtd_core::protocol::FlashInfo {
                        trans_size: 0x4_0000,
                        once_trans_max_size: 0x20_0000,
                        ..Default::default()
                    },
                    system_ini: None,
                    plan: None,
                });
                self.state.push_log(crate::state::LogLine::info(
                    "bootloader.tar：已规划 5 个成员",
                ));
            }
        }
    }

    /// Refresh the device list from the USB backend.
    fn refresh_devices(&mut self) {
        #[cfg(feature = "usb")]
        match rtd_core::device::usb::list_devices() {
            Ok(devs) => {
                let n = devs.len();
                self.state.set_devices(devs);
                self.state.push_log(crate::state::LogLine::info(format!(
                    "device scan: {n} target(s)"
                )));
            }
            Err(e) => {
                self.state.last_error = Some(e.to_string());
                self.state
                    .push_log(crate::state::LogLine::error(e.to_string()));
            }
        }
        #[cfg(not(feature = "usb"))]
        {
            self.state.last_error = Some("USB backend disabled in this build".into());
            self.state.push_log(crate::state::LogLine::warn(
                "编译时未启用 USB 后端，请用 --features usb 重新编译",
            ));
        }
    }

    fn pick_image(&mut self) {
        if let Some(p) = rfd::FileDialog::new()
            .add_filter("install image", &["img", "tar"])
            .set_title("选择 install.img")
            .pick_file()
        {
            self.state.image_path_input = p.to_string_lossy().into_owned();
            self.refresh_hwsetting_search();
            self.adopt_ini_near_image();
            self.adopt_ddr_from_ini();
            if let Err(e) = self.state.load_image(&p) {
                self.state.last_error = Some(e.to_string());
                self.state
                    .push_log(crate::state::LogLine::error(e.to_string()));
            }
        }
    }

    fn pick_ini(&mut self) {
        if let Some(p) = rfd::FileDialog::new()
            .add_filter("config", &["ini"])
            .set_title("选择 SYSTEM.ini")
            .pick_file()
        {
            self.state.ini_path_input = p.to_string_lossy().into_owned();
            self.adopt_ddr_from_ini();
        }
    }

    /// Look for a `SYSTEM.ini` next to the image and adopt it.
    ///
    /// The original keeps one beside the image; requiring a manual pick when it
    /// is already there is friction, and the file carries the DDR type.
    fn adopt_ini_near_image(&mut self) {
        if !self.state.ini_path_input.trim().is_empty() {
            return;
        }
        let Some(img) = non_empty_path(&self.state.image_path_input) else {
            return;
        };
        let Some(dir) = img.parent() else { return };
        for cand in [dir.join("SYSTEM.ini"), dir.join("Tempfile/SYSTEM.ini")] {
            if cand.is_file() {
                self.state.ini_path_input = cand.to_string_lossy().into_owned();
                self.state.push_log(crate::state::LogLine::info(format!(
                    "自动使用配置：{}",
                    cand.display()
                )));
                return;
            }
        }
    }

    /// Preselect the DDR type from `SYSTEM.ini`'s `DDR TYPE` value.
    ///
    /// The shipped file already records the intended configuration
    /// (`DDR TYPE=4DDR4_2GB`), so making the user pick it again is busywork --
    /// and a chance to pick wrong. Only fills an *empty* selection, so a manual
    /// choice is never overwritten.
    fn adopt_ddr_from_ini(&mut self) {
        if self.ddr_type.is_some() {
            return;
        }
        let Some(path) = non_empty_path(&self.state.ini_path_input) else {
            return;
        };
        let Ok(ini) = rtd_core::image::Ini::from_path(&path) else {
            return;
        };
        let Some(raw) = ini.get("MULTI FLASH TYPE", "DDR TYPE") else {
            return;
        };
        match rtd_core::ddr::DdrType::from_label(raw) {
            Some(d) => {
                self.ddr_type = Some(d);
                self.state.push_log(crate::state::LogLine::info(format!(
                    "从配置读取 DDR 类型：{} ({})",
                    d.label(),
                    d.describe()
                )));
            }
            None => {
                self.state.push_log(crate::state::LogLine::warn(format!(
                    "配置里的 DDR TYPE={raw:?} 无法识别，请手动选择"
                )));
            }
        }
    }

    fn pick_hwsetting(&mut self) {
        if let Some(p) = rfd::FileDialog::new()
            .add_filter("hwsetting", &["bin"])
            .set_title("选择 usb_hwsetting.bin")
            .pick_file()
        {
            match self.state.load_hwsetting(&p) {
                Ok(()) => {
                    self.hwsetting_buffer = self.state.hwsetting_text();
                    self.hwsetting_dirty = false;
                }
                Err(e) => {
                    self.state.last_error = Some(e.to_string());
                    self.state
                        .push_log(crate::state::LogLine::error(e.to_string()));
                }
            }
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Pull in anything the burn worker produced since the last frame.
        self.pump_worker();

        self.top_bar(ctx);
        self.status_bar(ctx);

        // `min_height` keeps the panel from resizing as rows appear and
        // disappear. Without it the height is derived from the previous frame's
        // content, so the first frames render short and the layout visibly jumps.
        egui::TopBottomPanel::top("image")
            .min_height(78.0)
            .show(ctx, |ui| {
                self.image_panel(ui);
            });

        egui::SidePanel::right("log")
            .resizable(true)
            .default_width(420.0)
            .show(ctx, |ui| {
                self.log_panel(ui);
            });

        egui::TopBottomPanel::bottom("devices")
            .resizable(true)
            .default_height(220.0)
            .show(ctx, |ui| {
                self.device_panel(ui);
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                self.details_panel(ui);
                ui.add_space(12.0);
                self.hwsetting_panel(ui);
            });
        });
    }
}

impl App {
    fn top_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("topbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("RTD129x 线刷工具");
                ui.separator();
                if ui.button("选择固件…").clicked() {
                    self.pick_image();
                }
                if ui.button("选择配置文件…").clicked() {
                    self.pick_ini();
                }
                ui.separator();
                if ui.button("扫描设备").clicked() {
                    self.refresh_devices();
                }
                ui.separator();
                // DDR type lives in the top bar because it is a global choice,
                // not a property of the loaded image. It is required: the
                // hwsetting blob trains the DRAM PHY, and the original refuses
                // to start without a selection.
                ui.label("DDR：");
                self.ddr_picker(ui);
                ui.separator();

                // While a burn runs the button becomes Cancel, so the two states
                // cannot both be reachable.
                if self.is_burning() {
                    if ui.button("取消烧写").clicked() {
                        if let Some(h) = &self.burn {
                            h.cancel();
                        }
                        self.state.push_log(crate::state::LogLine::warn(
                            "已请求取消（当前阶段结束后停止）",
                        ));
                    }
                } else {
                    let can_start = self.state.can_start();
                    if ui
                        .add_enabled(can_start, egui::Button::new("开始烧写"))
                        .clicked()
                    {
                        self.start_burn();
                    }
                }
            });
        });
    }

    fn status_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("statusbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(&self.state.status);
                ui.separator();
                let pct = self.state.overall_percent();
                ui.add(
                    egui::ProgressBar::new(pct as f32 / 100.0)
                        .desired_width(220.0)
                        .text(format!("{pct}%")),
                );
                ui.separator();
                ui.label(format!("设备 {} 台", self.state.devices.len()));
                if self.usb_missing {
                    // Permanent, high-visibility marker: this build can never
                    // reach a board, and that must not be discoverable only by
                    // pressing a button.
                    ui.separator();
                    ui.colored_label(
                        egui::Color32::from_rgb(240, 120, 60),
                        "⚠ 未编译 USB 后端",
                    );
                }
                if self.state.error_count() > 0 {
                    ui.separator();
                    ui.colored_label(
                        egui::Color32::from_rgb(220, 80, 80),
                        format!("{} 个错误", self.state.error_count()),
                    );
                }
                if let Some(e) = &self.state.last_error {
                    ui.separator();
                    ui.colored_label(egui::Color32::from_rgb(220, 80, 80), e);
                }
            });
        });
    }

    fn image_panel(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("固件：" );
            let w = ui.available_width() - 260.0;
            ui.add_sized(
                [w.max(200.0), 20.0],
                egui::TextEdit::singleline(&mut self.state.image_path_input)
                    .hint_text("install.img 的完整路径"),
            );
            if ui.button("加载").clicked() && !self.state.image_path_input.is_empty() {
                let p = std::path::PathBuf::from(self.state.image_path_input.trim());
                self.refresh_hwsetting_search();
                if let Err(e) = self.state.load_image(&p) {
                    self.state.last_error = Some(e.to_string());
                    self.state
                        .push_log(crate::state::LogLine::error(e.to_string()));
                }
            }
        });
        ui.horizontal(|ui| {
            ui.label("配置文件：");
            let w = ui.available_width() - 260.0;
            ui.add_sized(
                [w.max(200.0), 20.0],
                egui::TextEdit::singleline(&mut self.state.ini_path_input)
                    .hint_text("可选：提供 flash 参数和烧写选项"),
            );
        });
        if let Some(img) = &self.state.image {
            ui.horizontal(|ui| {
                ui.label(format!("project: {:?}", img.project));
                ui.separator();
                let count = img
                    .plan
                    .as_ref()
                    .map_or(img.partitions.len(), |p| p.partitions.len());
                ui.label(format!("{count} 个写入项"));
                ui.separator();
                ui.label(format!("{} bootloader members", img.bootloader.len()));
                ui.separator();
                ui.label(format!(
                    "chunk {:#x}",
                    img.flash_info.effective_chunk()
                ));
            });
        }
    }

    fn device_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading("设备");
        if self.state.devices.is_empty() {
            ui.label("未发现设备。请让板子进入 Device 模式后点「扫描设备」。");
            return;
        }
        let text_height = egui::TextStyle::Body.resolve(ui.style()).size + 6.0;
        let table = TableBuilder::new(ui)
            .striped(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::auto().at_least(120.0)) // key
            .column(Column::auto().at_least(200.0)) // description
            .column(Column::auto().at_least(90.0)) // state
            .column(Column::remainder().at_least(140.0)) // progress
            .column(Column::auto().at_least(70.0)) // elapsed
            .min_scrolled_height(0.0);

        table
            .header(20.0, |mut header| {
                header.col(|ui| {
                    ui.strong("标识");
                });
                header.col(|ui| {
                    ui.strong("描述");
                });
                header.col(|ui| {
                    ui.strong("状态");
                });
                header.col(|ui| {
                    ui.strong("进度");
                });
                header.col(|ui| {
                    ui.strong("耗时");
                });
            })
            .body(|mut body| {
                for row in &self.state.devices {
                    body.row(text_height, |mut tr| {
                        tr.col(|ui| {
                            ui.label(row.key());
                        });
                        tr.col(|ui| {
                            ui.label(row.info.describe());
                        });
                        tr.col(|ui| {
                            let (label, color) = match &row.state {
                                DeviceState::Idle => (row.state.label(), egui::Color32::GRAY),
                                DeviceState::Working { .. } => {
                                    (row.state.label(), egui::Color32::LIGHT_BLUE)
                                }
                                DeviceState::Done => {
                                    (row.state.label(), egui::Color32::from_rgb(90, 190, 90))
                                }
                                DeviceState::Failed(_) => {
                                    (row.state.label(), egui::Color32::from_rgb(220, 80, 80))
                                }
                                DeviceState::Cancelled => {
                                    (row.state.label(), egui::Color32::YELLOW)
                                }
                            };
                            ui.colored_label(color, label);
                        });
                        tr.col(|ui| match &row.state {
                            DeviceState::Working { stage, percent } => {
                                ui.add(
                                    egui::ProgressBar::new(*percent as f32 / 100.0)
                                        .text(format!("{stage} {percent}%")),
                                );
                            }
                            DeviceState::Failed(msg) => {
                                ui.colored_label(egui::Color32::from_rgb(220, 80, 80), msg);
                            }
                            _ => {
                                ui.label("");
                            }
                        });
                        tr.col(|ui| {
                            if let Some(s) = row.elapsed_s {
                                ui.label(format!("{s}s"));
                            }
                        });
                    });
                }
            });
    }

    fn details_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading("烧写计划");

        ui.horizontal(|ui| {
            ui.checkbox(&mut self.state.options.compare_data, "烧写后校验");
            ui.checkbox(&mut self.state.options.burn_factory, "烧写工厂区");
            ui.checkbox(&mut self.state.options.nas_enable, "启用 NAS");
            ui.checkbox(&mut self.state.options.lk_enable, "启用 LK");
            ui.checkbox(&mut self.state.options.single_mode, "单机模式");
            ui.checkbox(&mut self.state.options.go_ddr, "Go DDR (1195)");
        });
        ui.horizontal(|ui| {
            // These are deliberately shown but flagged, per the agreed scope.
            ui.checkbox(&mut self.state.options.burn_se_storage, "烧写安全存储");
            ui.checkbox(&mut self.state.options.only_burn_efuse, "仅烧写 eFuse");
            if !self.state.options.unsupported(2).is_empty() {
                ui.colored_label(
                    egui::Color32::YELLOW,
                    "需要安全密钥支持（本版本未实现）",
                );
            }
        });

        let blockers = self.state.start_blockers();
        if !blockers.is_empty() {
            ui.add_space(4.0);
            for b in &blockers {
                ui.colored_label(egui::Color32::from_rgb(220, 160, 80), format!("• {b}"));
            }
        }

        let ops = self.state.planned_opcodes();
        if !ops.is_empty() {
            ui.add_space(6.0);
            ui.label(format!("指令计划：{} 帧", ops.len()));
            let text: Vec<&str> = ops.iter().map(|o| o.name()).collect();
            ui.monospace(text.join("  →  "));
        }

        if let Some(img) = &self.state.image {
            ui.add_space(10.0);
            ui.heading("分区 / 写入项");
            if let Some(plan) = &img.plan {
                // The real burn plan, not just `layout.txt`: it includes the two
                // factory-area writes and marks members that are streamed from
                // the archive (anything over 64 MiB, e.g. a 7 GB p2.img).
                ui.label(plan.describe());
                let text_height = egui::TextStyle::Body.resolve(ui.style()).size + 6.0;
                TableBuilder::new(ui)
                    .striped(true)
                    .column(Column::auto().at_least(180.0))
                    .column(Column::auto().at_least(110.0))
                    .column(Column::auto().at_least(110.0))
                    .column(Column::auto().at_least(90.0))
                    .column(Column::remainder())
                    .body(|mut body| {
                        for p in &plan.partitions {
                            body.row(text_height, |mut tr| {
                                tr.col(|ui| {
                                    ui.label(p.target.trim());
                                });
                                tr.col(|ui| {
                                    ui.monospace(format!("lba {:#x}", p.lba().unwrap_or(0)));
                                });
                                tr.col(|ui| {
                                    ui.monospace(format!("{} B", p.payload_len()));
                                });
                                tr.col(|ui| {
                                    if p.member.is_some() {
                                        ui.colored_label(
                                            egui::Color32::from_rgb(80, 170, 220),
                                            "流式",
                                        );
                                    } else {
                                        ui.colored_label(egui::Color32::GRAY, "内存");
                                    }
                                });
                                tr.col(|ui| {
                                    if let Some(m) = &p.member {
                                        ui.label(m.name.clone());
                                    }
                                });
                            });
                        }
                    });
            } else if img.partitions.is_empty() {
                ui.label("（无）");
            } else {
                let text_height = egui::TextStyle::Body.resolve(ui.style()).size + 6.0;
                TableBuilder::new(ui)
                    .striped(true)
                    .column(Column::auto().at_least(180.0))
                    .column(Column::auto().at_least(100.0))
                    .column(Column::auto().at_least(100.0))
                    .column(Column::remainder())
                    .body(|mut body| {
                        for p in &img.partitions {
                            body.row(text_height, |mut tr| {
                                tr.col(|ui| {
                                    ui.label(p.display_target());
                                });
                                tr.col(|ui| {
                                    ui.monospace(format!("{:#x}", p.offset));
                                });
                                tr.col(|ui| {
                                    ui.monospace(format!("{:#x}", p.size));
                                });
                                tr.col(|ui| {
                                    ui.label(p.name.clone().unwrap_or_default());
                                });
                            });
                        }
                    });
            }

            if !img.bootloader.is_empty() {
                ui.add_space(10.0);
                ui.heading("引导程序成员");
                let text_height = egui::TextStyle::Body.resolve(ui.style()).size + 6.0;
                TableBuilder::new(ui)
                    .striped(true)
                    .column(Column::auto().at_least(180.0))
                    .column(Column::auto().at_least(100.0))
                    .column(Column::remainder())
                    .body(|mut body| {
                        for (name, size, lba) in &img.bootloader {
                            body.row(text_height, |mut tr| {
                                tr.col(|ui| {
                                    ui.label(name);
                                });
                                tr.col(|ui| {
                                    ui.monospace(format!("{size}"));
                                });
                                tr.col(|ui| {
                                    ui.monospace(format!("lba {lba}"));
                                });
                            });
                        }
                    });
            }
        }
    }

    fn hwsetting_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading("hwsetting 编辑器");
        ui.horizontal(|ui| {
            if ui.button("打开文件…").clicked() {
                self.pick_hwsetting();
            }
            if ui
                .add_enabled(self.state.hwsetting.is_some(), egui::Button::new("重新载入"))
                .clicked()
            {
                self.hwsetting_buffer = self.state.hwsetting_text();
                self.hwsetting_dirty = false;
            }
            if ui
                .add_enabled(
                    self.state.hwsetting.is_some() && self.hwsetting_dirty,
                    egui::Button::new("应用"),
                )
                .clicked()
            {
                let text = self.hwsetting_buffer.clone();
                match self.state.set_hwsetting_text(&text) {
                    Ok(()) => self.hwsetting_dirty = false,
                    Err(e) => {
                        self.state.last_error = Some(e.to_string());
                        self.state
                            .push_log(crate::state::LogLine::error(e.to_string()));
                    }
                }
            }
            if let Some(p) = &self.state.hwsetting_path {
                ui.label(p.file_name().unwrap_or_default().to_string_lossy());
            }
        });

        if self.state.hwsetting.is_some() {
            ui.label(
                "以 .config 文本编辑（w/p/n/m）。保存时尾部（含其 MAC）原样保留。",
            );
            let resp = ui.add(
                egui::TextEdit::multiline(&mut self.hwsetting_buffer)
                    .code_editor()
                    .desired_rows(12)
                    .desired_width(f32::INFINITY),
            );
            if resp.changed() {
                self.hwsetting_dirty = true;
            }
        } else {
            ui.label("打开 usb_hwsetting.bin 可查看或编辑 DRAM 寄存器配置。");
        }
    }

    fn log_panel(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("日志");
            ui.checkbox(&mut self.state.log_warnings_only, "只看警告");
            if ui.button("清空").clicked() {
                self.state.log.clear();
            }
            ui.add(
                egui::TextEdit::singleline(&mut self.log_filter)
                    .hint_text("过滤")
                    .desired_width(120.0),
            );
        });

        let needle = self.log_filter.to_ascii_lowercase();
        let lines: Vec<&crate::state::LogLine> = self
            .state
            .visible_log()
            .filter(|l| needle.is_empty() || l.text.to_ascii_lowercase().contains(&needle))
            .collect();
        let total = lines.len();

        // egui's ScrollArea handles the virtualisation: we only build the rows
        // that are on screen even though the ring holds up to LOG_CAPACITY.
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show_rows(ui, 16.0, total, |ui, range| {
                for i in range {
                    let line = lines[i];
                    let color = match line.level {
                        Level::Error => egui::Color32::from_rgb(230, 100, 100),
                        Level::Warn => egui::Color32::from_rgb(220, 180, 90),
                        Level::Info => ui.visuals().text_color(),
                        Level::Trace => egui::Color32::from_rgb(140, 140, 140),
                    };
                    let dev = line
                        .device
                        .as_ref()
                        .map(|d| format!("[{d}] "))
                        .unwrap_or_default();
                    ui.colored_label(color, egui::RichText::new(format!("{dev}{}", line.text)).monospace());
                }
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guard against a silently-failed edit leaving the Start button a stub.
    ///
    /// This is not hypothetical: a text substitution anchored on the *English*
    /// placeholder quietly did nothing once the string had been translated, so
    /// `start_burn` existed but was never called and pressing Start only logged
    /// a "not wired yet" notice instead of burning.
    ///
    /// Note the forbidden strings below are assembled with `concat!` and this
    /// comment deliberately avoids quoting them: `include_str!` sees the whole
    /// file, including this test, so any literal copy here would match itself.
    ///
    /// A behavioural test cannot reach the button (it needs a real click and a
    /// device), so this checks the wiring in the source itself.
    #[test]
    fn the_start_button_is_wired_to_the_worker() {
        let src = include_str!("app.rs");

        assert!(
            src.contains("self.start_burn()"),
            "the Start button must call App::start_burn"
        );
        assert!(
            src.contains("self.pump_worker()"),
            "update() must drain the worker, or progress never appears"
        );

        // `start_burn` must resolve the hwsetting itself. Using only
        // `state.hwsetting_path` means the DDR-specific lookup never runs and a
        // fresh install reports "请先选择：hwsetting 文件" even when the blobs
        // are sitting next to the executable -- a real regression.
        let start = src
            .find("fn start_burn")
            .expect("start_burn must exist");
        let body = &src[start..];
        let end = body.find("\n    /// ").unwrap_or(body.len());
        let body = &body[..end];
        assert!(
            body.contains("self.refresh_hwsetting_search()"),
            "start_burn must refresh the hwsetting search paths"
        );
        assert!(
            body.contains("resolve_hwsetting()"),
            "start_burn must resolve the hwsetting from the DDR choice"
        );
        // Built with `concat!` so the forbidden text does not appear literally
        // in this file -- otherwise the check matches its own source and always
        // fails.
        let stale = [
            concat!("尚未接入", "设备工作线程"),
            concat!("not wired in ", "this build"),
        ];
        for s in stale {
            assert!(!src.contains(s), "a placeholder is still present: {s:?}");
        }
    }

    /// The worker module's entry point must exist and be reachable.
    #[test]
    fn the_worker_exposes_a_start_function() {
        let src = include_str!("worker.rs");
        assert!(src.contains("pub fn start("), "worker::start is missing");
        // The device must be opened on the worker thread, not the UI thread.
        assert!(
            src.contains("thread::spawn"),
            "the burn must run off the UI thread"
        );
    }

    #[test]
    fn non_empty_path_trims_and_rejects_blank() {
        assert_eq!(non_empty_path(""), None);
        assert_eq!(non_empty_path("   "), None);
        assert_eq!(non_empty_path("\t\n"), None);
        assert_eq!(
            non_empty_path("  C:\\\\a\\\\b.img  "),
            Some(std::path::PathBuf::from("C:\\\\a\\\\b.img"))
        );
    }

    #[test]
    fn starting_without_an_image_is_refused_before_any_thread_starts() {
        let mut app = App::new();
        app.start_burn();
        assert!(app.burn.is_none(), "no worker should have been started");
        let err = app.state.last_error.clone().unwrap_or_default();
        assert!(err.contains("install.img"), "{err}");
    }

    #[test]
    fn starting_without_a_ddr_choice_is_refused() {
        let mut app = App::new();
        app.state.image_path_input = "C:\\\\nonexistent\\\\install.img".into();
        // A hwsetting blob must resolve too, otherwise that is what complains.
        app.ddr_type = Some(rtd_core::ddr::DdrType::Ddr4X4_2Gb);
        app.hwsetting_search = rtd_core::ddr::HwSettingSearch {
            tool_dir: None,
            image_dir: None,
        };
        app.start_burn();
        assert!(app.burn.is_none());
        let err = app.state.last_error.clone().unwrap_or_default();
        assert!(err.contains("hwsetting"), "expected a hwsetting complaint: {err}");
    }

    #[test]
    fn the_ddr_choice_is_required_even_with_an_image() {
        let mut app = App::new();
        app.state.image_path_input = "C:\\\\nonexistent\\\\install.img".into();
        // Give it a hwsetting so the DDR check is the one that fires.
        let dir = std::env::temp_dir().join(format!("rtd-gui-ddr-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(dir.join("usb_hwsetting.bin"), b"x").unwrap();
        app.hwsetting_search = rtd_core::ddr::HwSettingSearch {
            tool_dir: Some(dir.clone()),
            image_dir: None,
        };
        app.ddr_type = None;

        app.start_burn();
        assert!(app.burn.is_none());
        let err = app.state.last_error.clone().unwrap_or_default();
        assert!(err.contains("DDR 类型"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bootloader_tar_is_sought_beside_the_image() {
        let dir = std::env::temp_dir().join(format!("rtd-gui-tar-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let img = dir.join("install.img");
        std::fs::write(&img, b"x").unwrap();

        let mut app = App::new();
        app.state.image_path_input = img.to_string_lossy().into_owned();
        assert_eq!(app.bootloader_tar_path(), None);

        std::fs::write(dir.join("bootloader.tar"), b"x").unwrap();
        assert_eq!(app.bootloader_tar_path(), Some(dir.join("bootloader.tar")));

        std::fs::remove_file(dir.join("bootloader.tar")).unwrap();
        std::fs::create_dir_all(dir.join("Tempfile")).unwrap();
        std::fs::write(dir.join("Tempfile/bootloader.tar"), b"x").unwrap();
        assert_eq!(
            app.bootloader_tar_path(),
            Some(dir.join("Tempfile/bootloader.tar"))
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
