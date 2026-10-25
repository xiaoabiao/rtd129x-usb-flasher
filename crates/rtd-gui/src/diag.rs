//! `--diag`: report where the tool looks for its input files.
//!
//! A burn needs two things that do not ship with the tool: a DRAM-specific
//! hwsetting blob, and the image itself. When one is missing the UI can only say
//! so; this says *where it looked*, which is what turns "请先选择" into an
//! actionable report.

use std::path::PathBuf;

use rtd_core::ddr::{DdrType, HwSettingKind, HwSettingSearch};

/// Build a report and print it, also writing it next to the executable.
pub fn report() {
    let text = build();
    println!("{text}");
    // A GUI process launched by double-click has nowhere to print, so the file
    // is the reliable channel.
    if let Ok(exe) = std::env::current_exe() {
        let out = exe.with_file_name("diag-report.txt");
        let _ = std::fs::write(&out, &text);
        println!("(also written to {})", out.display());
    }
}

fn build() -> String {
    let mut s = String::new();

    let exe = std::env::current_exe().ok();
    let cwd = std::env::current_dir().ok();
    s.push_str("== 路径 ==\n");
    s.push_str(&format!(
        "  可执行文件 : {}\n",
        exe.as_ref().map_or("(未知)".into(), |p| p.display().to_string())
    ));
    s.push_str(&format!(
        "  工具目录   : {}\n",
        exe.as_ref()
            .and_then(|p| p.parent())
            .map_or("(未知)".into(), |p| p.display().to_string())
    ));
    s.push_str(&format!(
        "  当前目录   : {}\n",
        cwd.as_ref().map_or("(未知)".into(), |p| p.display().to_string())
    ));

    // The GUI derives the search from the executable; mirror that exactly.
    let tool_dir = exe.as_ref().and_then(|p| p.parent().map(PathBuf::from));
    let search = HwSettingSearch {
        tool_dir,
        image_dir: None,
    };

    s.push_str("\n== hwsetting 查找路径（按顺序）==\n");
    for d in search.dirs() {
        let exists = if d.is_dir() { "存在" } else { "不存在" };
        s.push_str(&format!("  [{exists}] {}\n", d.display()));
    }

    s.push_str("\n== 每种 DDR 类型的解析结果 ==\n");
    for d in DdrType::ALL {
        let want = d.hwsetting_file();
        match search.find(Some(d)) {
            Some((p, kind)) => {
                let tag = match kind {
                    HwSettingKind::DdrSpecific => "专用",
                    HwSettingKind::Generic => "通用回退",
                };
                s.push_str(&format!(
                    "  {:<12} -> {} [{}]  {}\n",
                    d.label(),
                    p.display(),
                    tag,
                    want
                ));
            }
            None => s.push_str(&format!("  {:<12} -> 未找到  (需要 {})\n", d.label(), want)),
        }
    }

    s.push_str("\n== 结论 ==\n");
    match search.find(None) {
        Some((p, kind)) => s.push_str(&format!(
            "  找到 hwsetting：{}\n  类型：{}\n",
            p.display(),
            match kind {
                HwSettingKind::DdrSpecific => "DDR 专用",
                HwSettingKind::Generic => "通用（未必匹配所选 DDR）",
            }
        )),
        None => {
            s.push_str("  没有找到任何 hwsetting 文件。\n");
            s.push_str("  请把下列任一文件放进上面任一「存在」的目录（建议新建 hwsetting 子目录）：\n");
            s.push_str("    kylin_usb_hwsetting_2DDR4_4Gb_1600_B.bin\n");
            s.push_str("    kylin_usb_hwsetting_2DDR3_4Gb_1600_B.bin\n");
            s.push_str("    usb_hwsetting.bin\n");
            s.push_str("  它们来自原工具的 Tempfile/ 目录。\n");
        }
    }

    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_report_names_every_ddr_type_and_lists_paths() {
        let t = build();
        for d in DdrType::ALL {
            assert!(t.contains(d.label()), "missing {} in report", d.label());
        }
        assert!(t.contains("hwsetting 查找路径"));
        assert!(t.contains("可执行文件"));
        // It must always reach a conclusion, found or not.
        assert!(t.contains("== 结论 =="));
    }
}
