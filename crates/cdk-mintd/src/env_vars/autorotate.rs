//! Autorotate environment variables

use std::env;

use crate::config::{AutoPrune, Autorotate};

pub const ENV_AUTOROTATE_ENABLED: &str = "CDK_MINTD_AUTOROTATE_ENABLED";
pub const ENV_AUTOROTATE_CHECK_INTERVAL_SECONDS: &str =
    "CDK_MINTD_AUTOROTATE_CHECK_INTERVAL_SECONDS";
pub const ENV_AUTOROTATE_ROTATION_BY_TIME_SECONDS: &str =
    "CDK_MINTD_AUTOROTATE_ROTATION_BY_TIME_SECONDS";
pub const ENV_AUTOROTATE_ROTATION_BY_TOKEN_COUNT: &str =
    "CDK_MINTD_AUTOROTATE_ROTATION_BY_TOKEN_COUNT";
pub const ENV_AUTOROTATE_GRACE_PERIOD_SECONDS: &str = "CDK_MINTD_AUTOROTATE_GRACE_PERIOD_SECONDS";
pub const ENV_AUTOROTATE_PRUNE_ENABLED: &str = "CDK_MINTD_AUTOROTATE_PRUNE_ENABLED";
pub const ENV_AUTOROTATE_PRUNE_BATCH_SIZE: &str = "CDK_MINTD_AUTOROTATE_PRUNE_BATCH_SIZE";

/// Treat the literal string `null` (any case) or an empty string as "disable
/// this side of the trigger." Any other value is parsed as a u64 and stored as
/// `Some(_)`.
fn parse_optional_u64(value: &str) -> Option<Option<u64>> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("null") {
        return Some(None);
    }
    trimmed.parse::<u64>().ok().map(Some)
}

impl Autorotate {
    pub fn from_env(&self) -> Self {
        let mut out = self.clone();

        if let Ok(v) = env::var(ENV_AUTOROTATE_ENABLED) {
            if let Ok(b) = v.parse::<bool>() {
                out.enabled = b;
            }
        }

        if let Ok(v) = env::var(ENV_AUTOROTATE_CHECK_INTERVAL_SECONDS) {
            if let Ok(n) = v.parse::<u64>() {
                out.check_interval_seconds = n;
            }
        }

        if let Ok(v) = env::var(ENV_AUTOROTATE_ROTATION_BY_TIME_SECONDS) {
            if let Some(parsed) = parse_optional_u64(&v) {
                out.rotation_by_time_seconds = parsed;
            }
        }

        if let Ok(v) = env::var(ENV_AUTOROTATE_ROTATION_BY_TOKEN_COUNT) {
            if let Some(parsed) = parse_optional_u64(&v) {
                out.rotation_by_token_count = parsed;
            }
        }

        if let Ok(v) = env::var(ENV_AUTOROTATE_GRACE_PERIOD_SECONDS) {
            if let Ok(n) = v.parse::<u64>() {
                out.grace_period_seconds = n;
            }
        }

        out.prune = out.prune.from_env();
        out
    }
}

impl AutoPrune {
    pub fn from_env(&self) -> Self {
        let mut out = self.clone();

        if let Ok(v) = env::var(ENV_AUTOROTATE_PRUNE_ENABLED) {
            if let Ok(b) = v.parse::<bool>() {
                out.enabled = b;
            }
        }

        if let Ok(v) = env::var(ENV_AUTOROTATE_PRUNE_BATCH_SIZE) {
            if let Ok(n) = v.parse::<usize>() {
                out.batch_size = n;
            }
        }

        out
    }
}
