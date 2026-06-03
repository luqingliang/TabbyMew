use anyhow::Result;

pub const DEFAULT_NOFILE_SOFT_LIMIT: u64 = 8192;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NofileLimitChange {
    pub previous_soft: String,
    pub soft: String,
    pub hard: String,
}

#[cfg(unix)]
pub fn raise_nofile_soft_limit(target: u64) -> Result<Option<NofileLimitChange>> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    let Some(desired) = desired_nofile_soft_limit(limit.rlim_cur, limit.rlim_max, target) else {
        return Ok(None);
    };

    let change = NofileLimitChange {
        previous_soft: format_rlimit(limit.rlim_cur),
        soft: format_rlimit(desired),
        hard: format_rlimit(limit.rlim_max),
    };
    limit.rlim_cur = desired;
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(Some(change))
}

#[cfg(not(unix))]
pub fn raise_nofile_soft_limit(_target: u64) -> Result<Option<NofileLimitChange>> {
    Ok(None)
}

#[cfg(unix)]
fn desired_nofile_soft_limit(
    current: libc::rlim_t,
    hard: libc::rlim_t,
    target: u64,
) -> Option<libc::rlim_t> {
    if current == libc::RLIM_INFINITY {
        return None;
    }
    let target = target as libc::rlim_t;
    if current >= target {
        return None;
    }
    let desired = if hard == libc::RLIM_INFINITY {
        target
    } else {
        target.min(hard)
    };
    (desired > current).then_some(desired)
}

#[cfg(unix)]
fn format_rlimit(value: libc::rlim_t) -> String {
    if value == libc::RLIM_INFINITY {
        "unlimited".to_string()
    } else {
        value.to_string()
    }
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;

    #[test]
    fn computes_desired_nofile_soft_limit() {
        for (current, hard, target, expected) in [
            (8192, 8192, 8192, None),
            (libc::RLIM_INFINITY, libc::RLIM_INFINITY, 8192, None),
            (256, 16384, 8192, Some(8192)),
            (256, libc::RLIM_INFINITY, 8192, Some(8192)),
            (256, 4096, 8192, Some(4096)),
        ] {
            assert_eq!(
                desired_nofile_soft_limit(current, hard, target),
                expected,
                "current={current}, hard={hard}, target={target}"
            );
        }
    }
}
