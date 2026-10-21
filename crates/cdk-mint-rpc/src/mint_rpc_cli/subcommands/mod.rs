//! Subcommands for the mint RPC CLI

mod federation;
mod federation_setup;
mod info;
mod keyset;
mod output;
mod payment_method;
mod quote;
mod wallet;

pub use self::federation::{
    federation, FederationCommand, FederationMembersCommand, FederationStatusCommand,
};
pub use self::federation_setup::{
    federation_setup, ApproveSetupCommand, CreateSetupCommand, FederationSetupCommand,
    JoinSetupCommand,
};
pub use self::info::{
    add_contact, add_url, get_info, remove_contact, remove_url, update_icon_url,
    update_long_description, update_motd, update_name, update_short_description, update_tos_url,
    AddContactCommand, AddUrlCommand, RemoveContactCommand, RemoveUrlCommand, UpdateIconUrlCommand,
    UpdateLongDescriptionCommand, UpdateMotdCommand, UpdateNameCommand,
    UpdateShortDescriptionCommand, UpdateTosUrlCommand,
};
pub use self::keyset::{rotate_next_keyset, RotateNextKeysetCommand};
pub use self::output::OutputCommand;
pub use self::payment_method::{
    update_disabled, update_melt_method, update_mint_method, UpdateDisabledCommand,
    UpdateMeltMethodCommand, UpdateMintMethodCommand,
};
pub use self::quote::{
    get_quote_ttl, update_mint_quote_state, update_quote_ttl, UpdateMintQuoteStateCommand,
    UpdateQuoteTtlCommand,
};
pub use self::wallet::{
    create_wallet_deposit_address, get_wallet_balance, list_wallet_addresses,
    list_wallet_transactions, WalletPaginationCommand,
};
