# Autorotate & Auto-Prune Plan

## Goal

Add two cooperating background systems to `cdk-mintd`:

1. **Autorotate** — automatically rotate the mint's active keyset(s) when either a time threshold or a volume threshold is reached, whichever comes first.
2. **Auto-prune** — once an inactive keyset has been soft-deleted (its `final_expiry` / `valid_to` has elapsed), opt-in pruning removes all related proofs and blind signatures from the database.

Autorotate defaults **on**. Auto-prune defaults **off** because it is destructive: any ecash from the pruned keyset can no longer be honored.

## Design overview

A single background task — the **rotation supervisor** — wakes on a configurable interval and, per active keyset (per `CurrencyUnit`), evaluates triggers and acts:

```
            ┌──────────────────────────┐
            │ rotation supervisor tick │
            └──────────────┬───────────┘
                           │  for each active keyset
            ┌──────────────▼──────────────┐
            │  time trigger?              │── yes ──┐
            │  volume trigger?            │── yes ──┤
            └──────────────┬──────────────┘         │
                           │ no                     ▼
                           ▼                  rotate_keyset()
                       continue              + set final_expiry on
                                              the now-inactive keyset
                                                    │
            ┌──────────────────────────────────────┐
            │  for each inactive keyset            │
            │  final_expiry elapsed?               │── yes ──┐
            └──────────────────────────────────────┘         │
                                                              ▼
                                                       prune_keyset()
                                                       (if opt-in)
```

The supervisor is hosted alongside the existing payment-supervisor task in [crates/cdk/src/mint/mod.rs](crates/cdk/src/mint/mod.rs#L320-L351) (`start_background_services` / `stop`). It is spawned on startup with its own `Notify` shutdown signal so it joins cleanly.

## Configuration

New section in `Settings` ([crates/cdk-mintd/src/config.rs](crates/cdk-mintd/src/config.rs#L647)):

```toml
[autorotate]
# Master switch for the supervisor itself. Default true.
enabled = true

# How often the supervisor evaluates triggers (seconds).
# Should be << time_threshold. Default 3600 (1 hour).
check_interval_seconds = 3600

# Time-based trigger: rotate when active keyset age >= this.
# Default: 90 days (7776000). Set to null to disable the time trigger.
max_keyset_age_seconds = 7776000

# Volume-based trigger: rotate when (issued blind sigs + redeemed proofs)
# count for the active keyset >= this.
# Default: 100000. Set to null to disable the volume trigger.
max_keyset_volume = 100000

# Grace period applied to a keyset's final_expiry at the moment it is
# rotated out. Wallets get this long to redeem old ecash before the
# keyset becomes eligible for pruning. Default 90 days.
inactive_grace_seconds = 7776000

# --- Pruning (destructive, opt-in) ---
[autorotate.prune]
# When true, the supervisor will remove proofs and blind signatures
# for keysets whose final_expiry has elapsed. Default false.
enabled = false

# Optional per-tick cap on rows removed to avoid long-running deletes.
# 0 means no cap. Default 10000.
batch_size = 10000
```

Both `max_keyset_age_seconds` and `max_keyset_volume` are `Option<u64>` in the Rust struct: omitting the key (or writing `null`) disables that side of the trigger. If both are null and `enabled = true` the supervisor still runs (it can still prune) but never auto-rotates — log a `tracing::warn!` once at startup so operators know.

Per-unit overrides are out of scope for v1: settings apply to every active keyset the mint advertises. We can add `[autorotate.units.sat]`-style overrides later if needed.

## Triggers

### Time trigger

Enabled when `max_keyset_age_seconds` is `Some(_)`. A keyset is due for rotation when:

```
now() - keyset.valid_from >= max_keyset_age_seconds
```

`valid_from` already exists on `MintKeySetInfo` ([crates/cdk-common/src/mint.rs:1006](crates/cdk-common/src/mint.rs#L1006)).

### Volume trigger

Enabled when `max_keyset_volume` is `Some(_)`. Volume for a keyset = `count(blind_signatures where keyset_id = K) + count(proofs where keyset_id = K AND state = 'SPENT')`.

We avoid running `COUNT(*)` on every tick by piggy-backing on the existing **`keyset_amounts`** table ([crates/cdk-sql-common/src/mint/migrations/sqlite/20251102000000_create_keyset_amounts.sql](crates/cdk-sql-common/src/mint/migrations/sqlite/20251102000000_create_keyset_amounts.sql)). That table already tracks per-keyset `total_issued`, `total_redeemed`, `fee_collected` as **amount sums**; we add two sibling columns for **transaction counts**:

```sql
ALTER TABLE keyset_amounts ADD COLUMN issued_count BIGINT NOT NULL DEFAULT 0;
ALTER TABLE keyset_amounts ADD COLUMN redeemed_count BIGINT NOT NULL DEFAULT 0;
```

The existing upsert sites already touch this row:

- `add_blind_signatures` — [crates/cdk-sql-common/src/mint/signatures.rs:128, :168](crates/cdk-sql-common/src/mint/signatures.rs#L128) — extend the upsert to also bump `issued_count = issued_count + 1` per signature.
- Proof state transition to SPENT — [crates/cdk-sql-common/src/mint/proofs.rs:217](crates/cdk-sql-common/src/mint/proofs.rs#L217) — extend the upsert to also bump `redeemed_count = redeemed_count + 1` per proof.

A one-shot backfill in the migration seeds the new columns from `blind_signature` and `proof`:

```sql
UPDATE keyset_amounts SET issued_count = (
  SELECT COUNT(*) FROM blind_signature WHERE blind_signature.keyset_id = keyset_amounts.keyset_id
);
UPDATE keyset_amounts SET redeemed_count = (
  SELECT COUNT(*) FROM proof
  WHERE proof.keyset_id = keyset_amounts.keyset_id AND proof.state = 'SPENT'
);
```

The trigger fires when `issued_count + redeemed_count >= max_keyset_volume`.

A new DB read method `get_keyset_counts(&Id) -> Result<(u64, u64)>` (or a small struct on `KeysDatabase`) returns the pair so the supervisor doesn't have to know about the table layout. The existing amount-based `get_total_redeemed` / `get_total_issued` ([crates/cdk-common/src/database/mint/mod.rs:448, :503](crates/cdk-common/src/database/mint/mod.rs#L448)) remain unchanged for fee-collection / accounting consumers.

### Whichever-comes-first

The supervisor evaluates whichever triggers are configured and rotates if any are true. Either trigger may be `null`; if both are `null` no auto-rotation happens (prune can still run). The supervisor itself can be turned off with `autorotate.enabled = false`.

## Rotation flow

For each active keyset that trips a trigger:

1. Call `Mint::rotate_keyset(unit, amounts, input_fee_ppk, use_keyset_v2, final_expiry=None)` ([crates/cdk/src/mint/keysets/mod.rs:74](crates/cdk/src/mint/keysets/mod.rs#L74)). This already:
   - Generates the next keyset via the signatory.
   - Marks the previous keyset inactive.
   - Refreshes the in-memory `self.keysets` cache.
2. **Set `final_expiry` on the keyset we just deactivated** to `now() + inactive_grace_seconds`. The existing rotation path does not do this — we need a small addition: either extend the signatory `rotate_keyset` return to identify the now-inactive keyset, or query `get_keyset_infos` after rotation and update the one whose `active=false` and `final_expiry is None`. A new DB method `set_keyset_final_expiry(id, ts)` on `KeysDatabaseTransaction` keeps this targeted.
3. Decide `amounts` / `input_fee_ppk` / `use_keyset_v2` for the new keyset from the same values the old one used (read from `MintKeySetInfo`), unless the operator changed config since.
4. Log the rotation (`tracing::info!`) with old id, new id, trigger reason.

This is the same write path the mgmt RPC `rotate_next_keyset` already uses ([crates/cdk-mint-rpc/src/proto/server.rs:762](crates/cdk-mint-rpc/src/proto/server.rs#L762)) — operators can still trigger manually.

## Soft-delete semantics

A keyset is **soft-deleted** when both:

- `active = false`, and
- `final_expiry.is_some_and(|t| t < now())` (the existing `MintKeySetInfo::is_expired()` already encodes this — [crates/cdk-common/src/mint.rs:1024](crates/cdk-common/src/mint.rs#L1024)).

Soft-deleted keysets:

- Are **filtered out** of `/v1/keysets`. Update `Mint::keysets` ([crates/cdk/src/mint/keysets/mod.rs:43](crates/cdk/src/mint/keysets/mod.rs#L43)) to exclude any keyset where `MintKeySetInfo::is_expired()` returns true (alongside the existing `Auth` filter). `/v1/keys/{id}` will continue to 404 with `UnknownKeySet` once the keyset is fully pruned, but during the soft-deleted-but-not-yet-pruned window we also drop the keyset from the in-memory cache used by `keyset_pubkeys` ([keysets/mod.rs:15](crates/cdk/src/mint/keysets/mod.rs#L15)) so historical-id lookups return 404 cleanly.
- Are eligible for **prune** if the operator opted in.

The existing schema already has a `valid_to` column ([crates/cdk-sql-common/src/mint/migrations/sqlite/20240612124932_init.sql:23](crates/cdk-sql-common/src/mint/migrations/sqlite/20240612124932_init.sql#L23)) which is the storage for `final_expiry` ([crates/cdk-sql-common/src/mint/keys.rs:51](crates/cdk-sql-common/src/mint/keys.rs#L51)). **No new "valid_to" column is needed** — we just start populating it on auto-rotation.

## Pruning

When `autorotate.prune.enabled = true`, on each supervisor tick:

1. List keysets where `active = false AND final_expiry IS NOT NULL AND final_expiry < now()`.
2. For each, delete in a single transaction:
   - All rows from `blind_signatures` where `keyset_id = K`.
   - All rows from `proof` where `keyset_id = K`.
   - The keyset's `issued_count` / `redeemed_count` row is left at the keyset row (we keep the keyset metadata so the id remains queryable — wallets that ask `/v1/keys/{id}` get a 404 / `UnknownKeySet` once the in-memory cache no longer holds it, which is fine, ecash is unredeemable anyway).
3. Respect `batch_size`: stop after that many rows; pick up next tick.

New DB methods on `Database` / its writer trait:

- `delete_proofs_by_keyset_id(&Id, limit: Option<usize>) -> Result<usize>` — returns rows removed.
- `delete_blind_signatures_by_keyset_id(&Id, limit: Option<usize>) -> Result<usize>`.

These belong on `ProofsTransaction` and `SignaturesTransaction` in [crates/cdk-common/src/database/mint/mod.rs](crates/cdk-common/src/database/mint/mod.rs).

Pruning operates inside a DB transaction per keyset so a crash mid-prune doesn't leave a partial state inconsistent with the counters.

## Code touchpoints

| Concern | File | Change |
|---|---|---|
| Config struct | [crates/cdk-mintd/src/config.rs](crates/cdk-mintd/src/config.rs#L647) | Add `Autorotate { enabled, check_interval_seconds, max_keyset_age_seconds, max_keyset_volume, inactive_grace_seconds, prune: Prune { enabled, batch_size } }` and a field on `Settings`. |
| Env vars | [crates/cdk-mintd/src/env_vars/mod.rs](crates/cdk-mintd/src/env_vars/mod.rs) | New `autorotate.rs` mirroring the pattern of `limits.rs`. |
| Background supervisor | [crates/cdk/src/mint/mod.rs](crates/cdk/src/mint/mod.rs#L320) | Spawn alongside the existing payment supervisor; thread a `Notify` for shutdown. |
| Rotation entry | [crates/cdk/src/mint/keysets/mod.rs](crates/cdk/src/mint/keysets/mod.rs#L74) | Add a helper `auto_rotate_due_keysets(&AutorotateConfig) -> Vec<RotationEvent>` that wraps `rotate_keyset` and stamps `final_expiry` on the outgoing keyset. |
| Volume counters | sqlite/postgres impls of `add_blind_signatures` and the spent-proof upsert | Extend existing `keyset_amounts` upserts at [signatures.rs:128, :168](crates/cdk-sql-common/src/mint/signatures.rs#L128) and [proofs.rs:217](crates/cdk-sql-common/src/mint/proofs.rs#L217) to also bump `issued_count` / `redeemed_count` by 1 per row. |
| Counter read API | [crates/cdk-common/src/database/mint/mod.rs](crates/cdk-common/src/database/mint/mod.rs#L138) | New `KeysDatabase::get_keyset_counts(&Id) -> Result<(u64, u64)>`. |
| `/v1/keysets` filter | [crates/cdk/src/mint/keysets/mod.rs:43](crates/cdk/src/mint/keysets/mod.rs#L43) | Skip keysets where `is_expired()` is true. |
| Prune | new module `crates/cdk/src/mint/prune.rs` | `prune_soft_deleted(&PruneConfig)`; called by the supervisor. |
| DB schema migration | `crates/cdk-sql-common/src/mint/migrations/{sqlite,postgres}/2026MMDDhhmmss_keyset_amounts_counts.sql` | Add `issued_count`, `redeemed_count` to `keyset_amounts` with backfill. |
| RPC surface (optional) | [crates/cdk-mint-rpc/src/proto/server.rs](crates/cdk-mint-rpc/src/proto/server.rs#L762) | Add `force_autorotate_tick` for operator-triggered evaluation; useful for tests. Not strictly required for v1. |

## Migration

One new SQL migration per backend, adding counts to the existing `keyset_amounts` table:

```sql
ALTER TABLE keyset_amounts ADD COLUMN issued_count BIGINT NOT NULL DEFAULT 0;
ALTER TABLE keyset_amounts ADD COLUMN redeemed_count BIGINT NOT NULL DEFAULT 0;

-- Backfill from existing data. Any keyset_amounts row missing for a
-- keyset that has signatures/proofs was already filled by the
-- 20251102 migration, so we only update here.
UPDATE keyset_amounts SET issued_count = (
  SELECT COUNT(*) FROM blind_signature
  WHERE blind_signature.keyset_id = keyset_amounts.keyset_id
);
UPDATE keyset_amounts SET redeemed_count = (
  SELECT COUNT(*) FROM proof
  WHERE proof.keyset_id = keyset_amounts.keyset_id
    AND proof.state = 'SPENT'
);
```

Backfill runs once at upgrade; ongoing maintenance is per-transaction increments in the same upserts that already maintain `total_issued` / `total_redeemed`.

## Testing

- **Unit (cdk)**: trigger evaluator — given a fake clock and a `MintKeySetInfo` + counters, asserts the rotate / no-rotate decision matrix (time only, volume only, both, neither, disabled).
- **Integration**: a test in `cdk-integration-tests` that:
  - sets `max_keyset_age_seconds = 2`, `check_interval_seconds = 1`, mints once, sleeps, asserts a rotation happened and the old keyset has a populated `final_expiry`;
  - then sets `inactive_grace_seconds = 2`, `prune.enabled = true`, sleeps past expiry, asserts proofs+sigs for the old keyset are gone and unrelated keysets are untouched.
- **Manual**: `cdk-cli` mint→swap→melt loop while autorotate runs on a tight cycle; verify wallet still works through a rotation.

## Risks & open questions

- **Pruning a keyset that still has UNSPENT proofs**: technically the holder can't redeem them post-expiry anyway, but it means a forensic record disappears. The grace period (`inactive_grace_seconds`, default 90 days) is the main mitigation; operators wanting more safety can extend it or leave `prune.enabled = false` and prune manually.
- **In-flight transactions during rotation**: `rotate_keyset` already handles activation/inactivation atomically via the signatory. Swap/melt sagas that started against the previous active keyset must still complete — they reference `keyset_id` directly, not "the active one," so this is already safe. Worth a regression test.
- **Counter drift**: counters are bumped inside the same DB transaction as the insert, so under normal operation they cannot drift. A rare edge: hand-written DB modifications. We document that the counters are authoritative for the volume trigger; the optional `force_autorotate_tick` RPC can also re-derive from `COUNT(*)` if we want a periodic reconciliation pass — out of scope for v1.
- **Per-unit thresholds**: deferred to v2. v1 uses one config for all units.
- **Code default `enabled = false`**: the in-code default is off so an upgrade can't silently begin rotating keysets. The shipped `example.config.toml` flips it on for new mints. This is a deliberate asymmetry — code default protects upgrades, example file gives new operators the recommended setting.

## Follow-up: signatory refactor (deferred)

Two changes belong in the `Signatory` trait rather than where v1 puts them. Both are deferred because they fan out across the signatory crate and the gRPC surface.

### A. Add `valid_from` to `SignatoryKeySet`

**Scope** (~6 files):
- [crates/cdk-signatory/src/signatory.rs](crates/cdk-signatory/src/signatory.rs#L71) — add `valid_from: u64` field; update the `From<&SignatoryKeySet> for KeySet` / `MintKeySetInfo` conversions.
- [crates/cdk-signatory/src/db_signatory.rs](crates/cdk-signatory/src/db_signatory.rs) — populate from `MintKeySetInfo::valid_from` on load.
- `crates/cdk-signatory/src/proto/{signatory.proto, client.rs, server.rs}` — extend proto, plumb through.
- [crates/cdk/src/mint/autorotate.rs](crates/cdk/src/mint/autorotate.rs) — delete the `get_valid_from` helper and read `keyset.valid_from` directly.

**Repercussions of delay**: v1 carries a `get_valid_from` helper that does an extra `keys_localstore.get_keyset_info(id)` per active keyset per tick when the time trigger is on. At the default `check_interval_seconds = 3600` and the typical 1–2 active keysets per mint, that's 1–2 additional point-lookups per hour — negligible. The user-visible behavior is identical. **Safe to delay indefinitely.**

### B. Stamp the outgoing keyset's `final_expiry` inside the signatory's rotate transaction

The first draft of this plan proposed a separate `Signatory::set_keyset_final_expiry` method. That's unnecessary — the signatory's existing `rotate_keyset` already runs a transaction ([db_signatory.rs:239-242](crates/cdk-signatory/src/db_signatory.rs#L239)) that contains both the new keyset insert and the active-flag swap. Extending that path to also stamp the outgoing keyset is strictly less surface area and works for remote signatories for free because the field flows over the wire.

**Scope** (~5 files):
- [crates/cdk-signatory/src/signatory.rs](crates/cdk-signatory/src/signatory.rs#L44) — add `outgoing_final_expiry: Option<u64>` to `RotateKeyArguments`.
- [crates/cdk-signatory/src/db_signatory.rs](crates/cdk-signatory/src/db_signatory.rs#L239) — inside the existing tx, before `set_active_keyset`, look up the current active id for the unit and call `tx.set_keyset_final_expiry(&outgoing_id, Some(expiry))` when the field is set. The `set_keyset_final_expiry` writer method already exists ([cdk-common/src/database/mint/mod.rs](crates/cdk-common/src/database/mint/mod.rs#L137); v1 added it for the workaround path).
- `crates/cdk-signatory/src/proto/{signatory.proto, client.rs, server.rs}` — add the field to the proto and pass it through.
- [crates/cdk/src/mint/keysets/mod.rs](crates/cdk/src/mint/keysets/mod.rs#L74) and the `cdk-mint-rpc` caller — thread the new field through `Mint::rotate_keyset`.
- [crates/cdk/src/mint/autorotate.rs](crates/cdk/src/mint/autorotate.rs) — replace the post-rotate `keys_localstore` stamp with `outgoing_final_expiry: Some(now + grace)` in the existing `rotate_keyset` call. Delete `get_valid_from`'s fallback path (and ideally land (A) so the time trigger doesn't need keys_localstore either).
- [crates/cdk/src/mint/mod.rs](crates/cdk/src/mint/mod.rs#L67) — drop the `keys_localstore: Option<...>` field and the `set_keys_localstore` setter.
- [crates/cdk/src/mint/builder.rs](crates/cdk/src/mint/builder.rs#L639) — drop the `Arc::clone(&keystore)` plumbing in `build_with_seed`.

**Repercussions of delay**:
- **Remote signatories don't auto-stamp `final_expiry`.** In v1, the mint reaches into a local `keys_localstore: Option<Arc<dyn MintKeysDatabase>>` to write `final_expiry` after the signatory's rotate call returns. When the signatory is remote (gRPC) the mint has no direct keys-DB handle, so autorotate logs a warning and skips the stamp. The rotation itself still happens (new keyset active, old keyset inactive), but the old keyset's `final_expiry` stays `None` → it never becomes eligible for prune. Operators with remote signatories effectively get autorotate without auto-prune until this lands.
- **`Mint::set_keys_localstore` is a post-construction setter footgun.** Anyone constructing `Mint` via `Mint::new()` directly (rather than the builder's `build_with_seed`) won't get final_expiry stamping unless they remember to call the setter. The builder path attaches it correctly, so this only bites custom integrations.
- **Slight design smell.** The optional field on `Mint` and the in-line warning in `rotate()` are obvious tells that this isn't the final shape. Reviewers will (correctly) point at it.

**Recommendation**: land (B) before the first release that operators with remote signatories rely on for production rotation. Until then, (B)'s absence is documented behavior, not a bug. (A) can wait indefinitely; doing it alongside (B) is convenient since both touch the signatory crate.

## Rollout

1. Land migration + counter bumps (no behavior change yet — the new columns just track data).
2. Land `/v1/keysets` soft-delete filter (small standalone change, easy to revert).
3. Land config + supervisor with `enabled = true` for autorotate, `prune.enabled = false`. Defaults: 90-day age, 100k volume.
4. Document in `DEVELOPMENT.md` and the example `config.toml`.
5. Operators can flip `prune.enabled = true` after they have observed at least one full rotation cycle in their environment.
