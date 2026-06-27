//! SQL database implementation of the Mint
//!
//! This is a generic SQL implementation for the mint storage layer. Any database can be plugged in
//! as long as standard ANSI SQL is used, as Postgres and SQLite would understand it.
//!
//! This implementation also has a rudimentary but standard migration and versioning system.
//!
//! The trait expects an asynchronous interaction, but it also provides tools to spawn blocking
//! clients in a pool and expose them to an asynchronous environment, making them compatible with
//! Mint.
use std::fmt::Debug;
use std::sync::Arc;

use async_trait::async_trait;
use cdk_common::database::{self, DbTransactionFinalizer, Error, MintDatabase};

use crate::common::migrate;
use crate::database::{ConnectionWithTransaction, DatabaseExecutor};
use crate::pool::{DatabasePool, Pool, PooledResource};

mod auth;
mod completed_operations;
mod keys;
mod keyvalue;
mod proofs;
mod quotes;
mod saga;
mod signatures;

#[rustfmt::skip]
mod migrations {
    include!(concat!(env!("OUT_DIR"), "/migrations_mint.rs"));
}

pub use auth::SQLMintAuthDatabase;
#[cfg(feature = "prometheus")]
use cdk_prometheus::METRICS;
use migrations::MIGRATIONS;

/// Mint SQL Database
#[derive(Debug, Clone)]
pub struct SQLMintDatabase<RM>
where
    RM: DatabasePool + 'static,
{
    pub(crate) pool: Arc<Pool<RM>>,
}

/// SQL Transaction Writer
#[allow(missing_debug_implementations)]
pub struct SQLTransaction<RM>
where
    RM: DatabasePool + 'static,
{
    pub(crate) inner: ConnectionWithTransaction<RM::Connection, PooledResource<RM>>,
}

/// Delete rows from `table` where `keyset_id_col` matches, optionally capped
/// to `limit` rows. `pk_col` is the primary key column used to implement the
/// `LIMIT` via a subquery (postgres does not accept `LIMIT` on `DELETE`).
///
/// Caller is responsible for ensuring `table`, `pk_col`, and `keyset_id_col`
/// are not attacker-controlled — they are interpolated into the SQL.
pub(crate) async fn delete_by_keyset_with_limit<RM>(
    tx: &SQLTransaction<RM>,
    table: &str,
    pk_col: &str,
    keyset_id_col: &str,
    keyset_id: &str,
    limit: Option<usize>,
) -> Result<usize, Error>
where
    RM: DatabasePool + 'static,
{
    use crate::stmt::query;
    let deleted = match limit {
        Some(n) if n > 0 => {
            let sql = format!(
                "DELETE FROM {table} WHERE {pk_col} IN (\
                    SELECT {pk_col} FROM {table} WHERE {keyset_id_col} = :keyset_id LIMIT :limit\
                )"
            );
            query(&sql)?
                .bind("keyset_id", keyset_id.to_string())
                .bind("limit", n as i64)
                .execute(&tx.inner)
                .await?
        }
        _ => {
            let sql = format!("DELETE FROM {table} WHERE {keyset_id_col} = :keyset_id");
            query(&sql)?
                .bind("keyset_id", keyset_id.to_string())
                .execute(&tx.inner)
                .await?
        }
    };
    Ok(deleted)
}

impl<RM> SQLMintDatabase<RM>
where
    RM: DatabasePool + 'static,
{
    /// Creates a new instance
    pub async fn new<X>(db: X) -> Result<Self, Error>
    where
        X: Into<RM::Config>,
    {
        let pool = Pool::new(db.into());

        Self::migrate(pool.get().await.map_err(|e| Error::Database(Box::new(e)))?).await?;

        Ok(Self { pool })
    }

    /// Migrate
    async fn migrate(conn: PooledResource<RM>) -> Result<(), Error> {
        let tx = ConnectionWithTransaction::new(conn).await?;
        migrate(&tx, RM::Connection::name(), MIGRATIONS).await?;
        tx.commit().await?;
        Ok(())
    }
}

#[async_trait]
impl<RM> database::MintTransaction<Error> for SQLTransaction<RM> where RM: DatabasePool + 'static {}

#[async_trait]
impl<RM> DbTransactionFinalizer for SQLTransaction<RM>
where
    RM: DatabasePool + 'static,
{
    type Err = Error;

    async fn commit(self: Box<Self>) -> Result<(), Error> {
        let result = self.inner.commit().await;
        #[cfg(feature = "prometheus")]
        {
            let success = result.is_ok();
            METRICS.record_mint_operation("transaction_commit", success);
            METRICS.record_mint_operation_histogram("transaction_commit", success, 1.0);
        }

        Ok(result?)
    }

    async fn rollback(self: Box<Self>) -> Result<(), Error> {
        let result = self.inner.rollback().await;

        #[cfg(feature = "prometheus")]
        {
            let success = result.is_ok();
            METRICS.record_mint_operation("transaction_rollback", success);
            METRICS.record_mint_operation_histogram("transaction_rollback", success, 1.0);
        }
        Ok(result?)
    }
}

#[async_trait]
impl<RM> MintDatabase<Error> for SQLMintDatabase<RM>
where
    RM: DatabasePool + 'static,
{
    async fn begin_transaction(
        &self,
    ) -> Result<Box<dyn database::MintTransaction<Error> + Send + Sync>, Error> {
        let tx = SQLTransaction {
            inner: ConnectionWithTransaction::new(
                self.pool
                    .get()
                    .await
                    .map_err(|e| Error::Database(Box::new(e)))?,
            )
            .await?,
        };

        Ok(Box::new(tx))
    }
}
