# Feature Request: Keyset Autorotate & Auto-Prune

## Summary

Add two cooperating background systems to `cdk-mintd` so operators stop having to babysit keyset lifecycle:

1. **Autorotate** — automatically rotate the mint's active keyset(s) once a time or volume threshold is hit, whichever comes first.
2. **Auto-prune** — once a rotated-out keyset has aged past its grace period, optionally delete the proofs and blind signatures tied to it so the database does not grow forever.

Autorotate is intended to default **on**; auto-prune defaults **off** because it is destructive (ecash issued under a pruned keyset can no longer be redeemed).

## Why

Today, keyset rotation on a CDK mint is a manual operator action (RPC call or restart with new config). In practice this means:

- Long-lived mints accumulate one keyset per epoch with no clear retirement policy.
- The `proof` and `blind_signature` tables grow without bound — even for keysets that are years past use and have effectively no chance of redemption.
- Operators who *do* rotate on a schedule end up writing their own cron + RPC glue outside the mint, which is brittle and undocumented.

A built-in supervisor that handles "rotate when the active keyset is old or busy, then later clean up the dead ones" gives operators a sensible default and makes the mint self-maintaining for the common case.

## What it does (operator's view)

- A configurable background task wakes on an interval (sensible default).
- For each active keyset, it checks two triggers — **age** (e.g. 90 days since `valid_from`) and **volume** (e.g. 100k issued + redeemed elements). Either or both can be disabled.
- If a trigger fires, the supervisor performs the same rotation that today's mgmt RPC `rotate_next_keyset` performs, and additionally stamps a `final_expiry` on the keyset it just retired (today, this field is left empty on manual rotations too — autorotate fills the gap).
- Retired keysets remain queryable until `final_expiry` elapses, giving wallets a grace window (some default) to redeem outstanding ecash. After that they are filtered from `/v1/keysets`.
- Once a keyset is past `final_expiry`, **if the operator opted into pruning**, the supervisor removes its proofs and blind signatures in bounded batches.

All of this is exposed through a single `[autorotate]` config section with sensible defaults, plus env-var equivalents.

## What it does NOT do (v1 scope)

- No per-unit thresholds — one config applies to every `CurrencyUnit` the mint advertises.
- No automatic reconciliation of volume counters against `COUNT(*)`; counters are incremented at the same time as the underlying inserts.
- No new public API surface for wallets. The change is entirely server-side; wallet behavior around expired/unknown keysets is already specified by NUT-02.
- No deletion of keyset metadata rows — only the proofs and signatures. The keyset id stays queryable (and returns 404 with the existing `UnknownKeySet` error) so that a wallet that hangs on to old state gets a clean answer.

## Areas of the codebase that need to change

At a high level, this touches five layers. None of them require a brand-new abstraction; each is an extension of something that already exists.

1. **Configuration & env vars** in `cdk-mintd`. A new `[autorotate]` section with a nested `[autorotate.prune]` subsection, and matching env-var bindings.
2. **Mint background services** in `cdk` (the crate). The mint already starts a payment-event supervisor on startup and joins it on shutdown — the rotation supervisor lives alongside it with the same lifecycle hooks.
3. **Keyset rotation entry point** in `cdk`. Today's `Mint::rotate_keyset` handles the active/inactive swap but does not set `final_expiry` on the outgoing keyset. The autorotate flow needs the outgoing keyset's expiry stamped as part of the rotation transaction. Cleanest landing is in the signatory's rotate transaction so it works for both local and remote signatories.
4. **Volume tracking** in `cdk-sql-common` (and the `Database` trait it implements). A `keyset_amounts` table already exists for per-keyset *amount* totals. The volume trigger needs **transaction counts** per keyset (issued blind sigs, redeemed proofs). New columns on that table, bumped at the same insert sites that already update the amount totals, plus a one-shot backfill from `blind_signature` / `proof`.
5. **Soft-delete & prune** in `cdk`. The `/v1/keysets` response filters out keysets whose `final_expiry` has elapsed. A new prune routine (gated by the opt-in flag) deletes proofs and signatures for those keysets in bounded batches, inside a per-keyset transaction.

Plus one DB migration per backend (sqlite, postgres) to add the new counter columns and backfill them.

## Suggested PR breakpoints

Each of these is independently revertable. Earlier PRs are pure additions with no behavioral change; behavior only flips on at PR #3.

1. **Counters migration + bumps.** Add the two count columns on `keyset_amounts`, backfill from existing data, and extend the existing upsert sites to also increment counts on signature issue and proof spend. No new behavior; just new data being tracked. Ships with a read API for `(issued_count, redeemed_count)`.
2. **Soft-delete filter on `/v1/keysets`.** Stop advertising keysets whose `final_expiry` has elapsed. Standalone, small, easy to revert. Today nothing populates `final_expiry` automatically so this is a no-op until PR #3 turns it on — which is exactly what we want for safe staging.
3. **Autorotate supervisor + config.** New `[autorotate]` config block, env-var plumbing, and the background task that evaluates triggers and calls the existing rotation path with `final_expiry` populated on the outgoing keyset. Auto-prune is configurable here but defaults off. The example config ships with autorotate on; the in-code default stays off to protect existing deployments on upgrade.
4. **Auto-prune routine.** The destructive half — delete-by-keyset-id methods on the proofs and signatures DB traits, plus the supervisor branch that calls them in batches when prune is opted into. Lands behind its config flag from day one.
5. **(Optional) signatory refactor follow-ups.** Two cleanups that are nice but not required for v1:
   - Add `valid_from` to the signatory's keyset struct so the time trigger doesn't need an extra DB hop per tick.
   - Move the `final_expiry` stamp on the outgoing keyset into the signatory's rotate transaction itself, so remote-signatory deployments get it for free (in v1 the mint stamps it client-side, which works for local signatories but is skipped for remote ones with a logged warning).

   These are deferred because they cross the signatory crate's proto + client + server surface, and the v1 workaround is functionally correct for the local-signatory case that covers most deployments today.

## Risks

- **Pruning is destructive by design.** Once the supervisor deletes a keyset's proofs and signatures, any outstanding ecash from that keyset is unredeemable. The grace window is the only mitigation. Prune defaults off, and **operators should only enable it if they fully understand the repercussions** — namely that any holder who has not redeemed by the end of the grace window loses that ecash permanently, with no recovery path on the mint side.
- **In-flight swaps/melts during rotation.** Rotation is already atomic at the signatory layer, and saga code references a `keyset_id` rather than "the currently active one," so in-flight transactions complete against the keyset they started under. Worth an integration test rather than a redesign.
- **Counter drift.** Counters are bumped in the same transaction as the row insert, so under normal operation they cannot drift. The only realistic drift source is hand-edited DB state, which is out of scope.

## Acceptance criteria

- A mint with default config and no operator intervention rotates its keyset(s) on age and/or volume.
- Retired keysets disappear from `/v1/keysets` once their `final_expiry` elapses; the id remains queryable until pruned.
- With prune opted in, proofs and blind signatures for expired keysets are deleted; counters and the keyset metadata row remain.
- With prune opted out (the default), nothing is deleted regardless of how old a retired keyset is.
- Existing manual rotation via the mgmt RPC continues to work unchanged.
- An upgrade from a release without this feature does not silently start rotating; the in-code default for the supervisor is off, and the shipped example config opts in.
