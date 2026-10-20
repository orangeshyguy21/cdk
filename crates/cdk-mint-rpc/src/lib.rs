#![doc = include_str!("../README.md")]

pub mod proto;

mod federation_setup_provider;
mod wallet_info;

pub mod mint_rpc_cli;

pub use federation_setup_provider::{
    DynFederationSetupProvider, FederationSetupError, FederationSetupErrorKind,
    FederationSetupProvider,
};
pub use proto::*;
pub use wallet_info::{
    DynWalletInfoProvider, WalletAddressPage, WalletInfoError, WalletInfoProvider,
    WalletTransactionPage,
};
