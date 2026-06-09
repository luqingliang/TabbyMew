#[cfg(any(target_os = "macos", test))]
use std::collections::BTreeMap;
#[cfg(target_os = "macos")]
use std::process::Command;
#[cfg(target_os = "macos")]
use std::sync::{Mutex, OnceLock};

#[cfg(any(target_os = "macos", test))]
use anyhow::Context;
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::platform;

const NO_LOCAL_SYSTEM_PROXY_TARGET: &str =
    "no compatible local HTTP, SOCKS, or hybrid inbound is configured";

#[cfg(any(target_os = "macos", test))]
const MACOS_SCUTIL: &str = "/usr/sbin/scutil";
#[cfg(target_os = "windows")]
const WINDOWS_PROXY_OVERRIDE: &str = "localhost;127.*;[::1];<local>";

#[cfg(any(target_os = "macos", test))]
type CommandRunner<'a> = dyn Fn(&str, &[String]) -> Result<String> + 'a;
#[cfg(any(target_os = "macos", test))]
type SystemProxyApplier<'a> =
    dyn Fn(Option<&SystemProxyTarget>, SystemProxySwitch) -> Result<()> + 'a;
#[cfg(any(target_os = "windows", test))]
type WindowsProxyReader<'a> = dyn Fn() -> Result<WindowsProxyState> + 'a;
#[cfg(any(target_os = "windows", test))]
type WindowsProxyApplier<'a> =
    dyn Fn(Option<&SystemProxyTarget>, SystemProxySwitch) -> Result<()> + 'a;

mod core;

#[cfg(any(target_os = "macos", test))]
mod macos;
mod shared;

#[cfg(any(target_os = "windows", test))]
mod windows;

#[cfg(any(target_os = "macos", test))]
use self::macos::*;
use self::shared::*;
#[cfg(any(target_os = "windows", test))]
use self::windows::*;

pub use core::*;

#[cfg(test)]
mod tests;
