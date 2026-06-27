//! Automatic keyset rotation and database pruning.
//!
//! See `docs/autorotate.md` for the design.

use std::sync::Arc;
use std::time::Duration;

use cdk_common::database;
use cdk_common::nut02::KeySetVersion;
use cdk_common::util::unix_time;
use cdk_common::CurrencyUnit;
use tokio::sync::Notify;

use crate::mint::Mint;
use crate::Error;

/// Runtime configuration for the autorotate supervisor.
#[derive(Debug, Clone)]
pub struct AutorotateConfig {
    /// Master switch.
    pub enabled: bool,
    /// Interval between supervisor evaluations.
    pub check_interval: Duration,
    /// Rotate when keyset age in seconds is `>=` this. `None` disables the
    /// time trigger.
    pub rotation_by_time_seconds: Option<u64>,
    /// Token-count trigger (controls DB-row growth, not transactions).
    /// Rotate when `issued_count + redeemed_count >=` this — i.e. when the
    /// combined count of ecash tokens this keyset has issued (blind
    /// signatures) and tokens of this keyset that have been spent (proofs)
    /// reaches the threshold. Each user transaction moves multiple tokens,
    /// so this is not a per-transaction count. `None` disables the trigger.
    pub rotation_by_token_count: Option<u64>,
    /// Grace period in seconds applied to `final_expiry` on the just-
    /// deactivated keyset.
    pub grace_period_seconds: u64,
    /// Pruning configuration.
    pub prune: AutoPruneConfig,
}

const ONE_DAY_SECS: u64 = 24 * 60 * 60;
/// "Mint Standard" defaults: keysets rotate every 180 days, redeemable for an
/// additional 360 days before prune is eligible.
const STANDARD_ROTATION_BY_TIME_SECS: u64 = 180 * ONE_DAY_SECS;
const STANDARD_GRACE_PERIOD_SECS: u64 = 360 * ONE_DAY_SECS;

impl Default for AutorotateConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            check_interval: Duration::from_secs(3600),
            rotation_by_time_seconds: Some(STANDARD_ROTATION_BY_TIME_SECS),
            rotation_by_token_count: Some(100_000),
            grace_period_seconds: STANDARD_GRACE_PERIOD_SECS,
            prune: AutoPruneConfig::default(),
        }
    }
}

/// Pruning configuration for soft-deleted keysets.
#[derive(Debug, Clone)]
pub struct AutoPruneConfig {
    /// When true, the supervisor removes proofs and blind signatures for
    /// keysets whose `final_expiry` has elapsed.
    pub enabled: bool,
    /// Per-tick cap on rows removed per table per keyset. `None` means no cap.
    pub batch_size: Option<usize>,
}

impl Default for AutoPruneConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            batch_size: Some(10_000),
        }
    }
}

impl Mint {
    /// Spawn the autorotate supervisor. Idempotent: a second call is a no-op
    /// while the supervisor is already running. Stopping is handled by
    /// `Mint::stop()`.
    pub async fn start_autorotate(&self, config: AutorotateConfig) -> Result<(), Error> {
        let mut task_state = self.task_state.lock().await;
        if task_state.autorotate_handle.is_some() {
            tracing::debug!("Autorotate supervisor already running");
            return Ok(());
        }

        if !config.enabled {
            tracing::info!("Autorotate supervisor disabled by configuration");
            return Ok(());
        }

        if config.rotation_by_time_seconds.is_none()
            && config.rotation_by_token_count.is_none()
            && !config.prune.enabled
        {
            tracing::info!(
                "Autorotate supervisor: all triggers (time, volume, prune) are off; not starting"
            );
            return Ok(());
        }

        let shutdown = Arc::new(Notify::new());
        let shutdown_clone = shutdown.clone();
        let mint_clone = Arc::new(self.clone());

        let handle = tokio::spawn(async move {
            run_supervisor(mint_clone, config, shutdown_clone).await;
        });

        task_state.autorotate_shutdown = Some(shutdown);
        task_state.autorotate_handle = Some(handle);
        tracing::info!("Autorotate supervisor started");
        Ok(())
    }
}

async fn run_supervisor(mint: Arc<Mint>, config: AutorotateConfig, shutdown: Arc<Notify>) {
    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                tracing::info!("Autorotate supervisor shutting down");
                break;
            }
            _ = tokio::time::sleep(config.check_interval) => {}
        }

        if let Err(e) = tick(&mint, &config).await {
            tracing::error!("Autorotate supervisor tick failed: {}", e);
        }
    }
}

async fn tick(mint: &Mint, config: &AutorotateConfig) -> Result<(), Error> {
    let mut keysets = mint.signatory.keysets().await?.keysets;
    let mut rotated = false;

    if config.rotation_by_time_seconds.is_some() || config.rotation_by_token_count.is_some() {
        for keyset in &keysets {
            if !keyset.active || keyset.unit == CurrencyUnit::Auth {
                continue;
            }
            if should_rotate(mint, config, keyset).await? {
                rotate(mint, config, keyset).await?;
                rotated = true;
            }
        }
    }

    if config.prune.enabled {
        if rotated {
            keysets = mint.signatory.keysets().await?.keysets;
        }
        let now = unix_time();
        for keyset in &keysets {
            if keyset.active {
                continue;
            }
            let Some(expiry) = keyset.final_expiry else {
                continue;
            };
            if expiry >= now {
                continue;
            }
            prune_keyset(mint, config, &keyset.id).await?;
        }
    }

    Ok(())
}

async fn should_rotate(
    mint: &Mint,
    config: &AutorotateConfig,
    keyset: &cdk_signatory::signatory::SignatoryKeySet,
) -> Result<bool, Error> {
    let now = unix_time();

    let time_due = match config.rotation_by_time_seconds {
        Some(max_age) => {
            // Saturating_sub guards against clock skew putting valid_from > now.
            now.saturating_sub(get_valid_from(mint, &keyset.id).await?) >= max_age
        }
        None => false,
    };
    if time_due {
        tracing::info!(
            "Autorotate: keyset {} due to rotate by age (>= {}s)",
            keyset.id,
            config.rotation_by_time_seconds.unwrap_or(0)
        );
        return Ok(true);
    }

    let volume_due = match config.rotation_by_token_count {
        Some(max_vol) => {
            let (issued, redeemed) = mint.localstore.get_keyset_counts(&keyset.id).await?;
            issued.saturating_add(redeemed) >= max_vol
        }
        None => false,
    };
    if volume_due {
        tracing::info!(
            "Autorotate: keyset {} due to rotate by token count (>= {})",
            keyset.id,
            config.rotation_by_token_count.unwrap_or(0)
        );
    }
    Ok(volume_due)
}

/// `SignatoryKeySet` doesn't carry `valid_from`; read it from the local keys
/// store when available, otherwise treat the keyset as never-due by age.
async fn get_valid_from(mint: &Mint, id: &cdk_common::nuts::Id) -> Result<u64, Error> {
    let Some(keys_store) = mint.keys_localstore.as_ref() else {
        return Ok(u64::MAX);
    };
    match keys_store.get_keyset_info(id).await {
        Ok(Some(info)) => Ok(info.valid_from),
        Ok(None) => Ok(u64::MAX),
        Err(e) => {
            tracing::warn!("Autorotate: failed to read keyset_info for {}: {:?}", id, e);
            Ok(u64::MAX)
        }
    }
}

async fn rotate(
    mint: &Mint,
    config: &AutorotateConfig,
    old: &cdk_signatory::signatory::SignatoryKeySet,
) -> Result<(), Error> {
    let old_id = old.id;
    let use_v2 = matches!(old.id.get_version(), KeySetVersion::Version01);

    let new_info = mint
        .rotate_keyset(
            old.unit.clone(),
            old.amounts.clone(),
            old.input_fee_ppk,
            use_v2,
            None,
        )
        .await?;

    tracing::info!(
        "Autorotate: rotated keyset for unit {:?}, old={}, new={}",
        old.unit,
        old_id,
        new_info.id
    );

    let Some(keys_store) = mint.keys_localstore.as_ref() else {
        tracing::warn!(
            "Autorotate: no keys_localstore attached; cannot stamp final_expiry on {}. \
             Keyset will not become eligible for pruning automatically.",
            old_id
        );
        return Ok(());
    };

    let expiry = unix_time().saturating_add(config.grace_period_seconds);
    let mut tx = keys_store.begin_transaction().await?;
    if let Err(e) = tx.set_keyset_final_expiry(&old_id, Some(expiry)).await {
        tracing::error!(
            "Autorotate: failed to stamp final_expiry on {}: {:?}",
            old_id,
            e
        );
        if let Err(re) = tx.rollback().await {
            tracing::warn!(
                "Autorotate: rollback after failed stamp also failed: {:?}",
                re
            );
        }
        return Err(e.into());
    }
    tx.commit().await?;
    tracing::info!(
        "Autorotate: stamped final_expiry={} on deactivated keyset {}",
        expiry,
        old_id
    );

    Ok(())
}

async fn prune_keyset(
    mint: &Mint,
    config: &AutorotateConfig,
    keyset_id: &cdk_common::nuts::Id,
) -> Result<(), Error> {
    let limit = match config.prune.batch_size {
        Some(0) | None => None,
        Some(n) => Some(n),
    };

    let mut tx = mint.localstore.begin_transaction().await?;

    let outcome: Result<(usize, usize), database::Error> = async {
        let sigs = tx
            .delete_blind_signatures_by_keyset_id(keyset_id, limit)
            .await?;
        let proofs = tx.delete_proofs_by_keyset_id(keyset_id, limit).await?;
        Ok((sigs, proofs))
    }
    .await;

    let (sigs, proofs) = match outcome {
        Ok(pair) => pair,
        Err(e) => {
            if let Err(re) = tx.rollback().await {
                tracing::warn!(
                    "Autorotate: rollback after failed prune also failed: {:?}",
                    re
                );
            }
            return Err(e.into());
        }
    };
    tx.commit().await?;

    if sigs > 0 || proofs > 0 {
        tracing::info!(
            "Autorotate prune: keyset {} removed {} blind_signatures, {} proofs",
            keyset_id,
            sigs,
            proofs
        );
    }
    Ok(())
}
