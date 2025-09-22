//! litd environment variables

use std::env;
use std::path::PathBuf;

use crate::config::Litd;

pub const ENV_LITD_ADDRESS: &str = "CDK_MINTD_LITD_ADDRESS";
pub const ENV_LITD_CERT_FILE: &str = "CDK_MINTD_LITD_CERT_FILE";
pub const ENV_LITD_LND_MACAROON_FILE: &str = "CDK_MINTD_LITD_LND_MACAROON_FILE";
pub const ENV_LITD_TAPD_MACAROON_FILE: &str = "CDK_MINTD_LITD_TAPD_MACAROON_FILE";
pub const ENV_LITD_FEE_PERCENT: &str = "CDK_MINTD_LITD_FEE_PERCENT";
pub const ENV_LITD_RESERVE_FEE_MIN: &str = "CDK_MINTD_LITD_RESERVE_FEE_MIN";
pub const ENV_LITD_TLS_DOMAIN: &str = "CDK_MINTD_LITD_TLS_DOMAIN";

impl Litd {
    pub fn from_env(mut self) -> Self {
        if let Ok(address) = env::var(ENV_LITD_ADDRESS) {
            self.address = address;
        }

        if let Ok(cert_path) = env::var(ENV_LITD_CERT_FILE) {
            self.cert_file = PathBuf::from(cert_path);
        }

        if let Ok(macaroon_path) = env::var(ENV_LITD_LND_MACAROON_FILE) {
            self.lnd_macaroon_file = PathBuf::from(macaroon_path);
        }
        if let Ok(macaroon_path) = env::var(ENV_LITD_TAPD_MACAROON_FILE) {
            self.tapd_macaroon_file = PathBuf::from(macaroon_path);
        }

        if let Ok(fee_str) = env::var(ENV_LITD_FEE_PERCENT) {
            if let Ok(fee) = fee_str.parse() {
                self.fee_percent = fee;
            }
        }

        if let Ok(reserve_fee_str) = env::var(ENV_LITD_RESERVE_FEE_MIN) {
            if let Ok(reserve_fee) = reserve_fee_str.parse::<u64>() {
                self.reserve_fee_min = reserve_fee.into();
            }
        }

        if let Ok(domain) = env::var(ENV_LITD_TLS_DOMAIN) {
            if !domain.is_empty() { self.tls_domain = Some(domain); }
        }

        self
    }
}


