//! CDK mint proto types

/// Read-only status service for a running federation member
pub mod federation {
    tonic::include_proto!("cdk_mint_federation_v1");
}

/// Federation setup service, served before a mint exists
pub mod federation_setup {
    tonic::include_proto!("cdk_mint_federation_setup_v1");
}

/// Mint metadata administration service
pub mod info {
    tonic::include_proto!("cdk_mint_info_v1");
}

/// Keyset administration service
pub mod keyset {
    tonic::include_proto!("cdk_mint_keyset_v1");
}

/// Payment method administration service
pub mod payment_method {
    tonic::include_proto!("cdk_mint_payment_method_v1");
}

/// Quote administration service
pub mod quote {
    tonic::include_proto!("cdk_mint_quote_v1");
}

/// On-chain wallet information service
pub mod wallet {
    tonic::include_proto!("cdk_mint_wallet_v1");
}

mod server;

pub use server::{
    FederationSetupRPCServer, MintMutationGuard, MintMutationGuardError, MintRPCServer,
};
