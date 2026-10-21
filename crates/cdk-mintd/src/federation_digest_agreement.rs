//! Digest agreement between federation member statuses.
//!
//! This is the comparison behind `federation status --require-converged` and
//! `--require-no-digest-alerts`, returned as data so callers other than the
//! CLI can report it. It reads only the cheap status fields. The exact
//! materialized-state comparison stays with `federation compare-digests`.

use std::collections::BTreeMap;

use cdk_common::federation::{FederationApplicationDigest, FederationJournalDigest, MemberId};

use crate::federation_status::FederationLocalStatusResponse;

/// Overall result of comparing member statuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DigestAgreementState {
    /// No statuses were compared.
    Unknown,
    /// Every member is at the same point with the same digests.
    Converged,
    /// Members differ in height, session, or a missing digest, but nothing
    /// contradicts.
    Converging,
    /// A member reports a digest alert or two members contradict each other.
    Diverged,
}

/// What two members disagree on at the same operation count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DigestConflictKind {
    /// Different accepted-operation order.
    OrderDigest,
    /// Different audited state for the same checkpoint.
    CheckpointAudit,
    /// Different applied results.
    ApplicationDigest,
}

/// Two members that contradict each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DigestConflict {
    pub(crate) kind: DigestConflictKind,
    pub(crate) first: MemberId,
    pub(crate) second: MemberId,
    pub(crate) operation_count: u64,
}

/// Position shared by the members of one group.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct DigestGroupKey {
    pub(crate) operation_count: u64,
    pub(crate) aleph_bft_session: u64,
    pub(crate) order_digest: FederationJournalDigest,
    pub(crate) application_digest: Option<FederationApplicationDigest>,
}

/// Members that report the same position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DigestGroup {
    pub(crate) key: DigestGroupKey,
    pub(crate) members: Vec<MemberId>,
    pub(crate) ready_count: usize,
}

/// Comparison of a set of member statuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DigestAgreement {
    /// Members compared, in input order.
    pub(crate) compared_members: Vec<MemberId>,
    /// Members grouped by position, lowest operation count first.
    pub(crate) groups: Vec<DigestGroup>,
    /// Members whose state audit latched a digest mismatch, in input order.
    pub(crate) digest_alert_members: Vec<MemberId>,
    /// Members that omitted their application digest, in input order.
    pub(crate) missing_application_digest_members: Vec<MemberId>,
    /// The first compared member, which the others are measured against.
    pub(crate) reference_member: Option<MemberId>,
    /// Members whose session or application frontier differs from the
    /// reference member's, in input order.
    pub(crate) differing_members: Vec<MemberId>,
    /// At most one conflict per pair, the most fundamental one, in input pair
    /// order.
    pub(crate) conflicts: Vec<DigestConflict>,
}

impl DigestAgreement {
    pub(crate) fn from_statuses<'a, I>(statuses: I) -> Self
    where
        I: IntoIterator<Item = &'a FederationLocalStatusResponse>,
    {
        let statuses = statuses.into_iter().collect::<Vec<_>>();
        let mut groups = BTreeMap::<DigestGroupKey, DigestGroup>::new();
        for status in &statuses {
            let peer = &status.peer_status;
            let key = DigestGroupKey {
                operation_count: peer.operation_count,
                aleph_bft_session: peer.aleph_bft_session,
                order_digest: peer.latest_order_digest,
                application_digest: peer.application_digest,
            };
            let group = groups.entry(key.clone()).or_insert_with(|| DigestGroup {
                key,
                members: Vec::new(),
                ready_count: 0,
            });
            group.members.push(peer.member_id);
            if status.sync_ready {
                group.ready_count = group.ready_count.saturating_add(1);
            }
        }
        for group in groups.values_mut() {
            group.members.sort_unstable();
        }

        let reference = statuses.first().copied();
        let differing_members = match reference {
            Some(reference) => statuses
                .iter()
                .skip(1)
                .filter(|status| {
                    !status
                        .peer_status
                        .has_same_application_state(&reference.peer_status)
                })
                .map(|status| status.peer_status.member_id)
                .collect(),
            None => Vec::new(),
        };

        let mut conflicts = Vec::new();
        for (index, status) in statuses.iter().enumerate() {
            for other in statuses.iter().skip(index + 1) {
                if let Some(kind) = pair_conflict(status, other) {
                    conflicts.push(DigestConflict {
                        kind,
                        first: status.peer_status.member_id,
                        second: other.peer_status.member_id,
                        operation_count: status.peer_status.operation_count,
                    });
                }
            }
        }

        Self {
            compared_members: statuses
                .iter()
                .map(|status| status.peer_status.member_id)
                .collect(),
            groups: groups.into_values().collect(),
            digest_alert_members: statuses
                .iter()
                .filter(|status| status.has_digest_alert())
                .map(|status| status.peer_status.member_id)
                .collect(),
            missing_application_digest_members: statuses
                .iter()
                .filter(|status| status.peer_status.application_digest.is_none())
                .map(|status| status.peer_status.member_id)
                .collect(),
            reference_member: reference.map(|status| status.peer_status.member_id),
            differing_members,
            conflicts,
        }
    }

    pub(crate) fn state(&self) -> DigestAgreementState {
        if self.compared_members.is_empty() {
            return DigestAgreementState::Unknown;
        }
        if !self.digest_alert_members.is_empty() || !self.conflicts.is_empty() {
            return DigestAgreementState::Diverged;
        }
        if !self.missing_application_digest_members.is_empty() || !self.differing_members.is_empty()
        {
            return DigestAgreementState::Converging;
        }
        DigestAgreementState::Converged
    }
}

/// The most fundamental way two members contradict each other at the same
/// operation count, if any.
fn pair_conflict(
    status: &FederationLocalStatusResponse,
    other: &FederationLocalStatusResponse,
) -> Option<DigestConflictKind> {
    let peer = &status.peer_status;
    let other = &other.peer_status;
    if peer.operation_count != other.operation_count {
        return None;
    }
    if peer.latest_order_digest != other.latest_order_digest {
        return Some(DigestConflictKind::OrderDigest);
    }
    if peer.latest_audited_checkpoint_id == other.latest_audited_checkpoint_id
        && peer.materialized_state_digest != other.materialized_state_digest
    {
        return Some(DigestConflictKind::CheckpointAudit);
    }
    if peer.application_digest != other.application_digest {
        return Some(DigestConflictKind::ApplicationDigest);
    }
    None
}
