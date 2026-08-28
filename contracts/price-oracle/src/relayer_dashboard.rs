//! # Relayer Dashboard (#267)
//!
//! Aggregates per-relayer operational metrics — volume, accuracy, latency, fee and
//! reward earnings, per-asset breakdown, and a comparative percentile rank against
//! every other approved relayer — into a single [`RelayerDashboard`] snapshot.
//!
//! Follows the same pragmatic, counter-based approach as `analytics.rs`'s
//! `get_source_analytics`: metrics are derived from a handful of running sums/counts
//! updated incrementally on the hot submission path, rather than a full historical
//! time-series, to keep per-submission storage overhead flat.

use soroban_sdk::{Address, Env, Vec};

use crate::types::{DataKey, RelayerAssetStat, RelayerDashboard};

/// Approximate number of ledgers per day, assuming Stellar's ~5-second ledger close
/// time. Used to convert a relayer's submission count into a submissions/day rate.
pub const LEDGERS_PER_DAY: u32 = 17_280;

/// Records incremental per-submission stats (latency + per-asset counts) used by the
/// dashboard. Called internally by `relayer.rs` after a submission is stored.
pub fn record_relayer_submission_stats(
    env: &Env,
    relayer: &Address,
    asset: &Address,
    observation_timestamp: u64,
    ledger_timestamp: u64,
) {
    // Latency: absolute distance between the observation timestamp and ledger close.
    let latency = if ledger_timestamp >= observation_timestamp {
        ledger_timestamp - observation_timestamp
    } else {
        observation_timestamp - ledger_timestamp
    };
    let latency_key = DataKey::RelayerLatencySum(relayer.clone());
    let latency_sum: u64 = env.storage().persistent().get(&latency_key).unwrap_or(0u64);
    env.storage()
        .persistent()
        .set(&latency_key, &latency_sum.saturating_add(latency));
    env.storage().persistent().extend_ttl(
        &latency_key,
        crate::storage::LEDGER_THRESHOLD,
        crate::storage::LEDGER_BUMP,
    );

    // Per-asset submission count, tracking newly-seen assets in an enumerable list.
    let list_key = DataKey::RelayerAssetList(relayer.clone());
    let mut assets: Vec<Address> = env
        .storage()
        .persistent()
        .get(&list_key)
        .unwrap_or(Vec::new(env));
    if !assets.contains(asset) {
        assets.push_back(asset.clone());
        env.storage().persistent().set(&list_key, &assets);
        env.storage().persistent().extend_ttl(
            &list_key,
            crate::storage::LEDGER_THRESHOLD,
            crate::storage::LEDGER_BUMP,
        );
    }

    let count_key = DataKey::RelayerAssetCount(relayer.clone(), asset.clone());
    let count: u64 = env.storage().persistent().get(&count_key).unwrap_or(0u64);
    env.storage()
        .persistent()
        .set(&count_key, &count.saturating_add(1));
    env.storage().persistent().extend_ttl(
        &count_key,
        crate::storage::LEDGER_THRESHOLD,
        crate::storage::LEDGER_BUMP,
    );
}

/// Builds and returns the aggregated [`RelayerDashboard`] for `relayer`.
///
/// Returns a dashboard populated with zeroed metrics if `relayer` has never
/// submitted or is not (or is no longer) approved.
pub fn get_relayer_dashboard(env: &Env, relayer: Address) -> RelayerDashboard {
    let total_submissions = crate::relayer::get_relayer_submission_count(env, relayer.clone());
    let failed_submissions = crate::relayer_bonds::get_relayer_failure_count(env, relayer.clone());

    let success_rate_denom = total_submissions
        .saturating_add(failed_submissions as u64)
        .max(1);
    let success_rate_bps = ((total_submissions.saturating_mul(10_000)) / success_rate_denom) as u32;

    let latency_sum: u64 = env
        .storage()
        .persistent()
        .get(&DataKey::RelayerLatencySum(relayer.clone()))
        .unwrap_or(0u64);
    let avg_latency_seconds = if total_submissions > 0 {
        latency_sum / total_submissions
    } else {
        0
    };

    let submissions_per_day = match crate::relayer::get_relayer_info(env, relayer.clone()) {
        Some(info) => {
            let elapsed_ledgers = env
                .ledger()
                .sequence()
                .saturating_sub(info.approved_at_ledger);
            let elapsed_days = (elapsed_ledgers / LEDGERS_PER_DAY).max(1) as u64;
            total_submissions / elapsed_days
        }
        None => 0,
    };

    let fee_earnings = crate::relayer::get_relayer_fee_balance(env, relayer.clone());
    let reward_earnings = crate::relayer_bonds::get_relayer_reward_balance(env, relayer.clone());
    let bond_deposited = crate::relayer_bonds::get_relayer_bond_balance(env, relayer.clone());

    let percentile_rank = compute_percentile_rank(env, total_submissions);
    let per_asset = collect_per_asset_stats(env, &relayer);

    RelayerDashboard {
        relayer,
        total_submissions,
        failed_submissions,
        success_rate_bps,
        submissions_per_day,
        avg_latency_seconds,
        fee_earnings,
        reward_earnings,
        bond_deposited,
        percentile_rank,
        per_asset,
    }
}

/// Percentile rank (0-100) of `total_submissions` among every approved relayer in the
/// [`DataKey::RelayerRegistry`]: the percentage of relayers whose own submission
/// count is at or below this one's.
fn compute_percentile_rank(env: &Env, total_submissions: u64) -> u32 {
    let registry: Vec<Address> = env
        .storage()
        .persistent()
        .get(&DataKey::RelayerRegistry)
        .unwrap_or(Vec::new(env));

    let total_relayers = registry.len();
    if total_relayers == 0 {
        return 0;
    }

    let mut le_count: u32 = 0;
    for i in 0..registry.len() {
        let other = registry.get_unchecked(i);
        let other_count = crate::relayer::get_relayer_submission_count(env, other);
        if other_count <= total_submissions {
            le_count += 1;
        }
    }

    (le_count * 100) / total_relayers
}

fn collect_per_asset_stats(env: &Env, relayer: &Address) -> Vec<RelayerAssetStat> {
    let asset_list: Vec<Address> = env
        .storage()
        .persistent()
        .get(&DataKey::RelayerAssetList(relayer.clone()))
        .unwrap_or(Vec::new(env));

    let mut per_asset: Vec<RelayerAssetStat> = Vec::new(env);
    for i in 0..asset_list.len() {
        let asset = asset_list.get_unchecked(i);
        let submissions: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::RelayerAssetCount(relayer.clone(), asset.clone()))
            .unwrap_or(0u64);
        per_asset.push_back(RelayerAssetStat { asset, submissions });
    }
    per_asset
}
