use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

#[cfg(unix)]
const PRIVATE_DIR_MODE: u32 = 0o700;
#[cfg(unix)]
const PRIVATE_FILE_MODE: u32 = 0o600;

pub fn create_private_dir_all(path: impl AsRef<Path>) -> Result<()> {
    let path = path.as_ref();
    if path.as_os_str().is_empty() {
        return Ok(());
    }
    fs::create_dir_all(path)
        .with_context(|| format!("failed to create private dir {}", path.display()))?;
    set_private_dir_permissions(path)
}

pub fn write_private_file(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> Result<()> {
    let path = path.as_ref();
    create_private_parent(path)?;
    let mut file = private_write_options()
        .open(path)
        .with_context(|| format!("failed to open private file {}", path.display()))?;
    set_private_file_permissions(path)?;
    file.write_all(contents.as_ref())
        .with_context(|| format!("failed to write private file {}", path.display()))?;
    file.flush()
        .with_context(|| format!("failed to flush private file {}", path.display()))?;
    set_private_file_permissions(path)
}

pub fn open_private_append(path: impl AsRef<Path>) -> Result<File> {
    let path = path.as_ref();
    create_private_parent(path)?;
    let file = private_append_options()
        .open(path)
        .with_context(|| format!("failed to open private file {}", path.display()))?;
    set_private_file_permissions(path)?;
    Ok(file)
}

pub fn replace_private_file(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> Result<()> {
    let path = path.as_ref();
    create_private_parent(path)?;
    let tmp = private_temp_path(path);
    write_private_file(&tmp, contents)?;
    let result = match fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            fs::remove_file(path)
                .with_context(|| format!("failed to replace {}", path.display()))?;
            fs::rename(&tmp, path).with_context(|| {
                format!("failed to move {} into {}", tmp.display(), path.display())
            })
        }
        Err(err) => Err(err)
            .with_context(|| format!("failed to move {} into {}", tmp.display(), path.display())),
    };
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result?;
    set_private_file_permissions(path)
}

fn create_private_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .filter(|parent| !parent.exists())
    {
        create_private_dir_all(parent)?;
    }
    Ok(())
}

fn private_write_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(PRIVATE_FILE_MODE);
    options
}

fn private_append_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options.mode(PRIVATE_FILE_MODE);
    options
}

fn private_temp_path(path: &Path) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("tabbymew");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    parent.join(format!(".{file_name}.{}.{}.tmp", std::process::id(), nanos))
}

#[cfg(unix)]
fn set_private_dir_permissions(path: &Path) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_DIR_MODE)).with_context(|| {
        format!(
            "failed to set private dir permissions on {}",
            path.display()
        )
    })
}

#[cfg(not(unix))]
fn set_private_dir_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_FILE_MODE)).with_context(|| {
        format!(
            "failed to set private file permissions on {}",
            path.display()
        )
    })
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    #[cfg(unix)]
    fn private_file_helpers_set_unix_modes() -> Result<()> {
        let dir =
            std::env::temp_dir().join(format!("tabbymew-fs-security-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        create_private_dir_all(&dir)?;
        assert_eq!(fs::metadata(&dir)?.permissions().mode() & 0o777, 0o700);

        let path = dir.join("state.json");
        write_private_file(&path, b"first\n")?;
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);

        replace_private_file(&path, b"second\n")?;
        assert_eq!(fs::read_to_string(&path)?, "second\n");
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);

        {
            let mut file = open_private_append(&path)?;
            file.write_all(b"third\n")?;
        }
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);

        fs::remove_dir_all(dir)?;
        Ok(())
    }
}
