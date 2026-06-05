use std::{
    env,
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    process::Command,
};

fn main() {
    println!("cargo:rerun-if-changed=assets/app-icon.ico");
    println!("cargo:rerun-if-changed=assets/app-icon.rc");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let target = env::var("TARGET").unwrap_or_default();
    if target.contains("msvc") {
        embed_with_rc(&target);
    } else {
        embed_with_windres(&target);
    }
}

fn embed_with_windres(target: &str) {
    let manifest_dir = manifest_dir();
    let out_dir = out_dir();
    let rc_file = manifest_dir.join("assets/app-icon.rc");
    let object_file = out_dir.join("app-icon.o");
    let windres = find_command(windres_candidates(target))
        .unwrap_or_else(|| panic!("failed to find windres for Windows target {target}"));

    run(
        &windres,
        [
            OsStr::new("assets/app-icon.rc"),
            OsStr::new("-O"),
            OsStr::new("coff"),
            OsStr::new("-o"),
            object_file.as_os_str(),
        ],
        &manifest_dir,
    );
    println!("cargo:rustc-link-arg={}", object_file.display());

    if !rc_file.is_file() {
        panic!("missing Windows icon resource file: {}", rc_file.display());
    }
}

fn embed_with_rc(target: &str) {
    let manifest_dir = manifest_dir();
    let out_dir = out_dir();
    let resource_file = out_dir.join("app-icon.res");
    let rc = find_command(rc_candidates(target))
        .unwrap_or_else(|| panic!("failed to find rc.exe or llvm-rc for Windows MSVC target"));

    run(
        &rc,
        [
            OsStr::new("/nologo"),
            OsStr::new("/fo"),
            resource_file.as_os_str(),
            OsStr::new("assets/app-icon.rc"),
        ],
        &manifest_dir,
    );
    println!("cargo:rustc-link-arg={}", resource_file.display());
}

fn manifest_dir() -> PathBuf {
    env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .expect("CARGO_MANIFEST_DIR is not set")
}

fn out_dir() -> PathBuf {
    env::var_os("OUT_DIR")
        .map(PathBuf::from)
        .expect("OUT_DIR is not set")
}

fn windres_candidates(target: &str) -> Vec<OsString> {
    let mut candidates = env_candidate("WINDRES");
    if target.starts_with("x86_64-") {
        candidates.push("x86_64-w64-mingw32-windres".into());
    } else if target.starts_with("i686-") || target.starts_with("i586-") {
        candidates.push("i686-w64-mingw32-windres".into());
    }
    candidates.push("windres".into());
    candidates
}

fn rc_candidates(target: &str) -> Vec<OsString> {
    let mut candidates = env_candidate("RC");
    candidates.push("rc.exe".into());
    candidates.push("llvm-rc".into());
    candidates.extend(windows_sdk_rc_candidates(target));
    candidates
}

fn env_candidate(name: &str) -> Vec<OsString> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .into_iter()
        .collect()
}

fn find_command(candidates: Vec<OsString>) -> Option<OsString> {
    candidates
        .into_iter()
        .find(|candidate| Command::new(candidate).arg("--version").output().is_ok())
}

fn windows_sdk_rc_candidates(target: &str) -> Vec<OsString> {
    let Some(arch) = windows_sdk_arch(target) else {
        return Vec::new();
    };
    let mut candidates = Vec::new();
    for root in [
        env::var_os("ProgramFiles(x86)"),
        env::var_os("ProgramFiles"),
    ]
    .into_iter()
    .flatten()
    {
        let kit_bin = PathBuf::from(root)
            .join("Windows Kits")
            .join("10")
            .join("bin");
        let Ok(entries) = std::fs::read_dir(kit_bin) else {
            continue;
        };
        let mut versioned = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path().join(arch).join("rc.exe"))
            .filter(|path| path.is_file())
            .map(OsString::from)
            .collect::<Vec<_>>();
        versioned.sort();
        versioned.reverse();
        candidates.extend(versioned);
    }
    candidates
}

fn windows_sdk_arch(target: &str) -> Option<&'static str> {
    if target.starts_with("x86_64-") {
        Some("x64")
    } else if target.starts_with("i686-") || target.starts_with("i586-") {
        Some("x86")
    } else if target.starts_with("aarch64-") {
        Some("arm64")
    } else {
        None
    }
}

fn run<I, S>(program: &OsStr, args: I, current_dir: &Path)
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let status = Command::new(program)
        .args(args)
        .current_dir(current_dir)
        .status()
        .unwrap_or_else(|err| panic!("failed to run {}: {err}", program.to_string_lossy()));
    if !status.success() {
        panic!("{} failed with {status}", program.to_string_lossy());
    }
}
