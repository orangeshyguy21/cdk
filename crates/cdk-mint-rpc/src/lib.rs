#![doc = include_str!("../README.md")]

pub mod proto;

mod federation_setup_provider;
mod federation_status_provider;
mod provider_error;
mod wallet_info;

pub mod mint_rpc_cli;

pub use federation_setup_provider::{DynFederationSetupProvider, FederationSetupProvider};
pub use federation_status_provider::{DynFederationStatusProvider, FederationStatusProvider};
pub use proto::*;
pub use provider_error::{ProviderError, ProviderErrorKind};
pub use wallet_info::{
    DynWalletInfoProvider, WalletAddressPage, WalletInfoError, WalletInfoProvider,
    WalletTransactionPage,
};
