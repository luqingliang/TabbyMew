use std::{fs, path::Path};

use anyhow::{Context, Result};

use crate::fs_security;

use super::{PREFERENCES_VERSION, RuntimePreferences};

pub fn load_preferences(path: impl AsRef<Path>) -> Result<RuntimePreferences> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(RuntimePreferences::default());
    }
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read preferences file {}", path.display()))?;
    let mut preferences: RuntimePreferences = serde_json::from_str(&text)
        .with_context(|| format!("failed to parse preferences file {}", path.display()))?;
    if preferences.version == 0 {
        preferences.version = PREFERENCES_VERSION;
    }
    Ok(preferences)
}

pub fn save_preferences(path: impl AsRef<Path>, preferences: &RuntimePreferences) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs_security::create_private_dir_all(parent)
            .with_context(|| format!("failed to create preferences dir {}", parent.display()))?;
    }
    let mut preferences = preferences.clone();
    preferences.version = PREFERENCES_VERSION;
    let text = serde_json::to_string_pretty(&preferences)
        .context("failed to serialize runtime preferences")?;
    fs_security::write_private_file(path, format!("{text}\n"))
        .with_context(|| format!("failed to write preferences file {}", path.display()))
}

pub fn update_preferences(
    path: impl AsRef<Path>,
    update: impl FnOnce(&mut RuntimePreferences),
) -> Result<RuntimePreferences> {
    let path = path.as_ref();
    let mut preferences = load_preferences(path).unwrap_or_default();
    update(&mut preferences);
    save_preferences(path, &preferences)?;
    Ok(preferences)
}
