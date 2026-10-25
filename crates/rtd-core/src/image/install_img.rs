//! `install.img` handling: unpacking and project-layout detection.
//!
//! `install.img` is a **standard ustar archive**. This is not an assumption:
//! the PDB exposes `tarlib/tarHeaderAscii/<unnamed-type-header> size=512` with
//! the canonical field offsets (`filename[100]`, `filemode[8]`, …,
//! `magicwithversion[8]`, `filenameprefix[155]`, `padding[12]`), and
//! `tarlib/tarFormatType` enumerates `V7 / OldGNU / GNU / USTAR / POSIX`.
//! The Rust `tar` crate reads it directly -- the original's bundled `tar.exe`
//! is used only for *creating* `factory.tar`, never for unpacking the image.
//!
//! # Three project layouts
//!
//! After unpacking, the image contains a project directory whose name depends on
//! how the image was built. `get_target_projet_directory_file_name` @0x0040F940
//! probes three candidates in this order:
//!
//! ```text
//! 0x0040F981  push "\\package5"     <- Android package-5 layout
//! 0x0040F995  push "\\omv"          <- OpenMediaVault / NAS layout
//! 0x0040F9A6  push "\\generic"      <- generic Linux layout
//! ```
//!
//! Failing all three produces:
//! `"Cannot get untartemp project filename (package 5 or omv or generic linux)!"`

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// The project layout of an unpacked image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProjectKind {
    /// `package5` — the Android/OpenWrt package layout.
    /// `package5` — the Android/OpenWrt package layout.
    Package5,
    /// `omv` — OpenMediaVault / NAS.
    Omv,
    /// `generic` — generic Linux.
    #[default]
    Generic,
    /// No project directory: `layout.txt` and the payloads sit at the archive
    /// root.
    ///
    /// Seen in the field on an RTD1296 CM360 wire-flash image, which contains
    /// `layout.txt`, `mbr.bin`, `fw_tbl.bin`, `low-region.img`, `p1.img`,
    /// `p2.img` and so on with no enclosing directory. The original tool would
    /// reject this archive outright; supporting it costs little and is strictly
    /// more general.
    Flat,
}

impl ProjectKind {
    /// The directory name, exactly as the original probes it.
    ///
    /// Empty for [`ProjectKind::Flat`], which has no enclosing directory.
    pub fn dir_name(self) -> &'static str {
        match self {
            ProjectKind::Package5 => "package5",
            ProjectKind::Omv => "omv",
            ProjectKind::Generic => "generic",
            ProjectKind::Flat => "",
        }
    }

    /// The prefix to look for when locating a member inside the archive.
    ///
    /// `Flat` has none, so `layout.txt` is matched at the root.
    pub fn member_prefix(self) -> String {
        match self.dir_name() {
            "" => String::new(),
            d => format!("{d}/"),
        }
    }

    /// The probe order used by the original.
    pub const PROBE_ORDER: [ProjectKind; 3] = [
        ProjectKind::Package5,
        ProjectKind::Omv,
        ProjectKind::Generic,
    ];

    /// Identify from a directory name, case-insensitively.
    pub fn from_dir_name(name: &str) -> Option<Self> {
        let n = name.trim().to_ascii_lowercase();
        Some(match n.as_str() {
            "package5" => ProjectKind::Package5,
            "omv" => ProjectKind::Omv,
            "generic" => ProjectKind::Generic,
            _ => return None,
        })
    }
}

/// Layout file name inside the project directory.
pub const LAYOUT_FILE: &str = "layout.txt";

/// A summary of what was found in an unpacked image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageSummary {
    /// The detected project layout.
    pub project: ProjectKind,
    /// Path of the project directory inside the unpack root.
    pub project_dir: PathBuf,
    /// Path of `layout.txt`, if present.
    pub layout_path: Option<PathBuf>,
    /// Total bytes of regular files found.
    pub total_bytes: u64,
    /// Number of regular files found.
    pub file_count: usize,
}

/// Find the project directory anywhere in one tar member path.
///
/// Scans **every** path component rather than only the first, and skips `.` and
/// `..`. Archives routinely store `./package5/layout.txt`, and a first-component
/// check sees only `.` and gives up -- which is exactly the failure that produced
/// a spurious "cannot get untartemp project filename".
///
/// Both separators are accepted because tars written on Windows can carry `\`.
pub fn detect_project_in_path(path: &str) -> Option<ProjectKind> {
    for comp in path.split(['/', '\\']) {
        if comp.is_empty() || comp == "." || comp == ".." {
            continue;
        }
        if let Some(k) = ProjectKind::from_dir_name(comp) {
            return Some(k);
        }
    }
    None
}

/// Detect the project layout from a list of tar member paths.
///
/// Probing order follows the original (`package5`, then `omv`, then `generic`),
/// not the order members happen to appear in the archive.
pub fn detect_project_in_members<'a, I>(names: I) -> Result<ProjectKind>
where
    I: IntoIterator<Item = &'a str>,
{
    let names: Vec<&str> = names.into_iter().collect();
    let mut found: Vec<ProjectKind> = Vec::new();
    for n in &names {
        if let Some(k) = detect_project_in_path(n) {
            if !found.contains(&k) {
                found.push(k);
            }
        }
    }
    for kind in ProjectKind::PROBE_ORDER {
        if found.contains(&kind) {
            return Ok(kind);
        }
    }

    // No project directory. Check for the flat layout before giving up: a
    // `layout.txt` directly in the archive is a complete, usable image.
    let flat = names.iter().any(|n| {
        let base = n.rsplit(['/', '\\']).next().unwrap_or(n);
        base.eq_ignore_ascii_case(LAYOUT_FILE)
    });
    if flat {
        return Ok(ProjectKind::Flat);
    }

    Err(Error::Image(format!(
        "cannot get untartemp project filename (package 5 or omv or generic linux)!   \
         archive has {} entries",
        names.len()
    )))
}

/// Read `layout.txt` out of an image as text.
///
/// `inspect` prints it verbatim so an offset disagreement between the file and
/// the burn plan can be seen directly instead of inferred.
pub fn read_layout_text(image: &Path) -> Result<String> {
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
        if name.rsplit('/').next().unwrap_or(&name).eq_ignore_ascii_case(LAYOUT_FILE) {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            return Ok(String::from_utf8_lossy(&buf).into_owned());
        }
    }
    Err(Error::Image("install.img 里没有 layout.txt".into()))
}

/// The distinct first path components of a member list, for diagnostics.
///
/// When detection fails this is what the user needs to see: it shows what the
/// archive actually contains instead of only what was expected.
pub fn top_level_entries<'a, I>(names: I, limit: usize) -> Vec<String>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut out: Vec<String> = Vec::new();
    for n in names {
        let first = n
            .split(['/', '\\'])
            .find(|c| !c.is_empty() && *c != "." && *c != "..")
            .unwrap_or("(root)");
        let entry = first.to_string();
        if !out.contains(&entry) {
            out.push(entry);
        }
        if out.len() >= limit {
            break;
        }
    }
    out.sort();
    out
}

/// Detect the project layout inside an unpacked image root.
///
/// Mirrors the original's ordered probe. Returns the layout and its directory.
pub fn detect_project(untar_root: &Path) -> Result<(ProjectKind, PathBuf)> {
    for kind in ProjectKind::PROBE_ORDER {
        // The original probes for the name at any depth below the temp root in
        // practice; we check the root itself and then one level down, which
        // covers both `UnTarTmp/package5` and `UnTarTmp/<something>/package5`.
        let direct = untar_root.join(kind.dir_name());
        if direct.is_dir() {
            return Ok((kind, direct));
        }
    }
    // Fall back to a bounded scan for a directory with a known name.
    if let Some(found) = scan_for_project(untar_root, 0, 4)? {
        return Ok(found);
    }
    Err(Error::Image(format!(
        "cannot get untartemp project filename (package 5 or omv or generic linux)!   \
         looked under {}",
        untar_root.display()
    )))
}

fn scan_for_project(dir: &Path, depth: usize, max: usize) -> Result<Option<(ProjectKind, PathBuf)>> {
    if depth > max {
        return Ok(None);
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(None),
    };
    let mut subdirs = Vec::new();
    for e in entries.flatten() {
        let p = e.path();
        if !p.is_dir() {
            continue;
        }
        let Some(name) = p.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if let Some(kind) = ProjectKind::from_dir_name(name) {
            return Ok(Some((kind, p)));
        }
        subdirs.push(p);
    }
    for d in subdirs {
        if let Some(hit) = scan_for_project(&d, depth + 1, max)? {
            return Ok(Some(hit));
        }
    }
    Ok(None)
}

/// Extract `install.img` into `dest` and summarise what is inside.
///
/// `dest` must not already exist, so a partial extraction is never mistaken for
/// a complete one. The archive is read with the `tar` crate; nothing is
/// executed.
pub fn extract(image: &Path, dest: &Path) -> Result<ImageSummary> {
    if dest.exists() {
        return Err(Error::Image(format!(
            "destination {} already exists; refusing to overwrite",
            dest.display()
        )));
    }
    std::fs::create_dir_all(dest)?;

    let f = std::fs::File::open(image)?;
    let mut ar = tar::Archive::new(std::io::BufReader::new(f));
    ar.set_preserve_permissions(false);
    ar.set_overwrite(false);
    // Reject entries that would escape the destination.
    ar.set_unpack_xattrs(false);
    ar.unpack(dest).map_err(|e| {
        Error::Image(format!(
            "failed to unpack {} into {}: {e}",
            image.display(),
            dest.display()
        ))
    })?;

    let (project, project_dir) = detect_project(dest)?;
    let layout_path = {
        let p = project_dir.join(LAYOUT_FILE);
        p.is_file().then_some(p)
    };
    let (file_count, total_bytes) = walk_stats(dest)?;

    Ok(ImageSummary {
        project,
        project_dir,
        layout_path,
        total_bytes,
        file_count,
    })
}

fn walk_stats(dir: &Path) -> Result<(usize, u64)> {
    let mut count = 0usize;
    let mut bytes = 0u64;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            match e.file_type() {
                Ok(ft) if ft.is_dir() => stack.push(p),
                Ok(ft) if ft.is_file() => {
                    count += 1;
                    bytes += e.metadata().map(|m| m.len()).unwrap_or(0);
                }
                _ => {}
            }
        }
    }
    Ok((count, bytes))
}

/// List the members of an `install.img` without extracting it.
///
/// Useful for the UI: it can show what is inside before committing to a burn.
pub fn list_members(image: &Path) -> Result<Vec<(String, u64)>> {
    let f = std::fs::File::open(image)?;
    let mut ar = tar::Archive::new(std::io::BufReader::new(f));
    let mut out = Vec::new();
    for entry in ar.entries().map_err(|e| Error::Image(e.to_string()))? {
        let entry = entry.map_err(|e| Error::Image(e.to_string()))?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry
            .path()
            .map_err(|e| Error::Image(e.to_string()))?
            .to_string_lossy()
            .into_owned();
        out.push((path, entry.size()));
    }
    Ok(out)
}

/// Locate a regular member's payload inside an `install.img` archive.
///
/// Returns `(data_offset, size)`, where `data_offset` is the absolute byte offset
/// of the payload **inside the image file**. The burner uses this to stream large
/// partitions instead of loading them into memory.
///
/// The headers are walked directly instead of going through `tar::Archive`
/// because the caller needs seek offsets, and it has to keep working past the
/// 4 GiB mark -- in the 7.8 GB package the rootfs partitions live there, which is
/// exactly what a 32-bit tool cannot address.
pub fn member_data_range(image: &Path, want: &str) -> Result<Option<(u64, u64)>> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    let mut f = std::fs::File::open(image)?;
    let file_len = f.metadata()?.len();
    let want = want.trim_start_matches("./").replace('\\', "/");

    let mut pos: u64 = 0;
    let mut block = [0u8; 512];
    let mut long_name: Option<String> = None;

    while pos + 512 <= file_len {
        f.seek(SeekFrom::Start(pos))?;
        f.read_exact(&mut block)?;
        if block.iter().all(|&b| b == 0) {
            break; // end-of-archive marker
        }
        let mut name = String::from_utf8_lossy(&block[0..100])
            .trim_end_matches('\0')
            .to_string();
        let size = parse_tar_octal(&block[124..136]);
        let typeflag = block[156];
        if let Some(long) = long_name.take() {
            name = long;
        }
        let prefix = String::from_utf8_lossy(&block[345..500])
            .trim_end_matches('\0')
            .to_string();
        pos += 512;

        if typeflag == b'L' {
            // GNU long name: the payload is the next entry's path.
            let mut buf = vec![0u8; size as usize];
            f.seek(SeekFrom::Start(pos))?;
            f.read_exact(&mut buf)?;
            long_name = Some(
                String::from_utf8_lossy(&buf)
                    .trim_end_matches('\0')
                    .to_string(),
            );
            pos += size.div_ceil(512) * 512;
            continue;
        }

        let full = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let full = full.trim_start_matches("./").replace('\\', "/");
        if full == want && (typeflag == b'0' || typeflag == 0) {
            return Ok(Some((pos, size)));
        }
        pos += size.div_ceil(512) * 512;
    }
    Ok(None)
}

/// Parse a numeric tar header field: octal, or GNU base-256 for huge values.
fn parse_tar_octal(field: &[u8]) -> u64 {
    if field.is_empty() {
        return 0;
    }
    if field[0] & 0x80 != 0 {
        // GNU base-256: big-endian, the 0x80 bit is the flag itself.
        let mut v: u64 = (field[0] & 0x7f) as u64;
        for b in &field[1..] {
            v = (v << 8) | *b as u64;
        }
        return v;
    }
    let mut v: u64 = 0;
    for &b in field {
        match b {
            0 | b' ' => continue,
            b'0'..=b'7' => v = v * 8 + (b - b'0') as u64,
            _ => break,
        }
    }
    v
}

/// Build a minimal, well-formed `install.img` containing one file under a
/// project directory. Used by the tests.
pub fn write_fixture_image(
    dest: &Path,
    project: ProjectKind,
    files: &[(&str, &[u8])],
) -> Result<()> {
    let f = std::fs::File::create(dest)?;
    let mut b = tar::Builder::new(f);
    for (name, data) in files {
        let path = format!("{}/{}", project.dir_name(), name);
        let mut h = tar::Header::new_ustar();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, &path, *data)
            .map_err(|e| Error::Image(e.to_string()))?;
    }
    b.finish().map_err(|e| Error::Image(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let base = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into());
        let p = PathBuf::from(base).join(format!("rtd-imgtest-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn project_names_and_probe_order_match_the_original() {
        assert_eq!(ProjectKind::Package5.dir_name(), "package5");
        assert_eq!(ProjectKind::Omv.dir_name(), "omv");
        assert_eq!(ProjectKind::Generic.dir_name(), "generic");
        assert_eq!(
            ProjectKind::PROBE_ORDER,
            [
                ProjectKind::Package5,
                ProjectKind::Omv,
                ProjectKind::Generic
            ],
            "the original probes 0x40F981, 0x40F995, 0x40F9A6 in this order"
        );
        assert_eq!(
            ProjectKind::from_dir_name("Package5"),
            Some(ProjectKind::Package5)
        );
        assert_eq!(ProjectKind::from_dir_name("OMV"), Some(ProjectKind::Omv));
        assert_eq!(ProjectKind::from_dir_name("nope"), None);
    }

    #[test]
    fn the_dot_slash_prefix_is_found() {
        // The classic tar spelling `./package5/...`. Checking only the first
        // path component sees `.` and gives up, which is exactly the bug that
        // produced a spurious "cannot get untartemp project filename".
        assert_eq!(
            detect_project_in_path("./package5/layout.txt"),
            Some(ProjectKind::Package5)
        );
        assert_eq!(
            detect_project_in_path("./omv/boot/bzImage"),
            Some(ProjectKind::Omv)
        );
        assert_eq!(
            detect_project_in_path("./generic/rootfs.tar"),
            Some(ProjectKind::Generic)
        );
    }

    #[test]
    fn backslash_separators_are_found() {
        // Tars written on Windows can carry `\\`.
        assert_eq!(
            detect_project_in_path(".\\package5\\layout.txt"),
            Some(ProjectKind::Package5)
        );
        assert_eq!(
            detect_project_in_path("out\\omv\\layout.txt"),
            Some(ProjectKind::Omv)
        );
    }

    #[test]
    fn nested_project_directories_are_found() {
        assert_eq!(
            detect_project_in_path("out/images/w2/omv/layout.txt"),
            Some(ProjectKind::Omv)
        );
        assert_eq!(
            detect_project_in_path("a/b/c/generic/x"),
            Some(ProjectKind::Generic)
        );
    }

    #[test]
    fn dot_and_dotdot_components_are_skipped() {
        assert_eq!(detect_project_in_path("../package5/x"), Some(ProjectKind::Package5));
        assert_eq!(detect_project_in_path("./././omv/x"), Some(ProjectKind::Omv));
        assert_eq!(detect_project_in_path("."), None);
        assert_eq!(detect_project_in_path(".."), None);
        assert_eq!(detect_project_in_path(""), None);
        assert_eq!(detect_project_in_path("some/other/path"), None);
    }

    #[test]
    fn detection_over_a_member_list_uses_the_probe_order() {
        // `generic` appears first in the archive, but `package5` must win
        // because that is the order the original probes in.
        let names = [
            "x/generic/a",
            "x/omv/b",
            "x/package5/layout.txt",
        ];
        assert_eq!(
            detect_project_in_members(names).unwrap(),
            ProjectKind::Package5
        );

        // With no `package5`, `omv` beats `generic`.
        let names = ["x/generic/a", "x/omv/b"];
        assert_eq!(detect_project_in_members(names).unwrap(), ProjectKind::Omv);

        // Only `generic` present.
        let names = ["x/generic/a"];
        assert_eq!(
            detect_project_in_members(names).unwrap(),
            ProjectKind::Generic
        );
    }

    #[test]
    fn a_list_with_no_project_reports_the_original_message() {
        let err = detect_project_in_members(["random/a", "./b", "../c"])
            .unwrap_err()
            .to_string();
        assert!(err.contains("package 5 or omv or generic linux"), "{err}");
    }

    #[test]
    fn top_level_entries_reports_what_is_actually_there() {
        let names = [
            "./package5/layout.txt",
            "./package5/boot.img",
            "docs/readme.txt",
        ];
        let tops = top_level_entries(names, 10);
        // `.` is skipped, so the real top level is what a user needs to see.
        assert_eq!(tops, vec!["docs", "package5"]);

        // The limit is honoured.
        let names = ["a/1", "b/2", "c/3", "d/4"];
        assert_eq!(top_level_entries(names, 2).len(), 2);
    }

    #[test]
    fn detects_each_layout_directly() {
        for kind in ProjectKind::PROBE_ORDER {
            let root = tmpdir(&format!("direct-{}", kind.dir_name()));
            std::fs::create_dir_all(root.join(kind.dir_name())).unwrap();
            let (got, dir) = detect_project(&root).unwrap();
            assert_eq!(got, kind);
            assert!(dir.ends_with(kind.dir_name()));
        }
    }

    #[test]
    fn probe_order_prefers_package5_over_omv() {
        let root = tmpdir("order");
        std::fs::create_dir_all(root.join("omv")).unwrap();
        std::fs::create_dir_all(root.join("package5")).unwrap();
        let (got, _) = detect_project(&root).unwrap();
        assert_eq!(got, ProjectKind::Package5, "the original tries package5 first");
    }

    #[test]
    fn detects_a_nested_layout() {
        let root = tmpdir("nested");
        std::fs::create_dir_all(root.join("images/w2/omv")).unwrap();
        let (got, dir) = detect_project(&root).unwrap();
        assert_eq!(got, ProjectKind::Omv);
        assert!(dir.ends_with("omv"));
    }

    #[test]
    fn missing_layout_reports_the_original_message() {
        let root = tmpdir("missing");
        let err = detect_project(&root).unwrap_err().to_string();
        assert!(
            err.contains("package 5 or omv or generic linux"),
            "error should echo the original wording: {err}"
        );
    }

    #[test]
    fn extracts_a_synthetic_image_and_finds_the_layout() {
        let root = tmpdir("extract");
        let img = root.join("install.img");
        let layout = b"target=FW_KERNEL offset=0x3000000 size=0x800000\n";
        write_fixture_image(
            &img,
            ProjectKind::Package5,
            &[("layout.txt", layout), ("bootcode.bin", &[0xAA; 512])],
        )
        .unwrap();

        let members = list_members(&img).unwrap();
        let names: Vec<&str> = members.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"package5/layout.txt"));

        let dest = root.join("out");
        let summary = extract(&img, &dest).unwrap();
        assert_eq!(summary.project, ProjectKind::Package5);
        assert_eq!(summary.file_count, 2);
        assert_eq!(summary.total_bytes, layout.len() as u64 + 512);
        let lp = summary.layout_path.expect("layout.txt should be found");
        assert_eq!(std::fs::read(&lp).unwrap(), layout);

        // The extracted layout.txt must parse.
        let text = String::from_utf8(std::fs::read(&lp).unwrap()).unwrap();
        let parts = crate::image::layout_txt::parse(&text).unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].target, "FW_KERNEL");
    }

    #[test]
    fn refuses_to_extract_into_an_existing_directory() {
        let root = tmpdir("exists");
        let img = root.join("install.img");
        write_fixture_image(&img, ProjectKind::Generic, &[("a", b"x")]).unwrap();
        let dest = root.join("out");
        std::fs::create_dir_all(&dest).unwrap();
        assert!(extract(&img, &dest).is_err(), "must not clobber");
    }

    #[test]
    fn missing_image_is_an_error() {
        let root = tmpdir("noimg");
        assert!(list_members(&root.join("nope.img")).is_err());
    }

    #[test]
    fn listing_a_non_tar_is_an_error() {
        let root = tmpdir("nottar");
        let p = root.join("bad.img");
        std::fs::write(&p, b"this is definitely not a tar archive").unwrap();
        assert!(list_members(&p).is_err());
    }

    #[test]
    fn round_trips_all_three_layouts() {
        for kind in ProjectKind::PROBE_ORDER {
            let root = tmpdir(&format!("rt-{}", kind.dir_name()));
            let img = root.join("install.img");
            write_fixture_image(
                &img,
                kind,
                &[("layout.txt", b"target=A offset=0x0 size=0x100\n")],
            )
            .unwrap();
            let summary = extract(&img, &root.join("out")).unwrap();
            assert_eq!(summary.project, kind);
            assert!(summary.layout_path.is_some());
        }
    }

    #[test]
    fn member_data_range_points_at_the_payload() {
        // The streaming burner seeks to this offset, so it has to be exactly the
        // payload's first byte -- for every member, including ones after a large
        // predecessor.
        let root = tmpdir("range");
        let img = root.join("install.img");
        let a = vec![0xAAu8; 700];
        let b = b"second member payload".to_vec();
        write_fixture_image(
            &img,
            ProjectKind::Package5,
            &[("a.bin", a.as_slice()), ("b.bin", b.as_slice())],
        )
        .unwrap();

        let members = list_members(&img).unwrap();
        let bname = members
            .iter()
            .find(|(n, _)| n.ends_with("b.bin"))
            .expect("b.bin in the fixture")
            .0
            .clone();
        let (off, size) = member_data_range(&img, &bname).unwrap().expect("range");
        assert_eq!(size, b.len() as u64);
        let blob = std::fs::read(&img).unwrap();
        assert_eq!(&blob[off as usize..(off + size) as usize], &b[..]);

        // And an absent member is `None`, not an error.
        assert!(member_data_range(&img, "nope.bin").unwrap().is_none());
    }
}
