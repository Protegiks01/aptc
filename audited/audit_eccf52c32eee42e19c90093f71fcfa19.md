# Audit Report

## Title
Indexer Lacks Independent Validation of Withdrawal Timing in Delegation Pool Events

## Summary
The Aptos indexer blindly trusts `WithdrawStakeEvent` data emitted by the delegation pool contract without independently validating that withdrawals respect lockup period constraints. This creates a defense-in-depth gap where bugs in on-chain validation logic would propagate to indexed data without detection.

## Finding Description

The delegation pool contract enforces lockup periods before allowing stake withdrawals. When a delegator calls `withdraw()`, the contract validates withdrawal timing before emitting `WithdrawStakeEvent`: [1](#0-0) 

The validation checks that either:
1. The withdrawal's lockup cycle has ended (`withdrawal_olc.index < pool.observed_lockup_cycle.index`), OR
2. Special early withdrawal conditions are met (`can_withdraw_pending_inactive()`) [2](#0-1) 

However, the indexer processing code simply parses and stores event data without any timing validation: [3](#0-2) 

The indexer extracts `delegator_address`, `pool_address`, and `amount_withdrawn` from the event and stores them directly to the database without checking:
- Whether the lockup period has actually ended
- The current `observed_lockup_cycle` state
- Timestamp comparisons against `locked_until_secs`

This violates defense-in-depth principles. If the on-chain validation logic contains bugs (e.g., incorrect `observed_lockup_cycle` updates, race conditions in synchronization logic, or timestamp manipulation), the indexer will faithfully record invalid withdrawals as valid, misleading downstream applications and users. [4](#0-3) [5](#0-4) 

## Impact Explanation

This issue is classified as **Low Severity** per the Aptos bug bounty criteria because:

1. **Off-chain only**: This affects indexer data integrity, not on-chain state or consensus
2. **No direct fund loss**: Cannot cause theft, minting, or freezing of funds
3. **Requires on-chain bug**: Only manifests if the on-chain validation has bugs
4. **Data quality issue**: Creates incorrect historical records, not protocol violations

Per the bounty program, Low Severity includes "Minor information leaks, Non-critical implementation bugs" - this fits as a non-critical data quality issue in off-chain infrastructure.

## Likelihood Explanation

**Moderate likelihood** that this gap could cause issues:

1. **Complexity of lockup logic**: The delegation pool has complex lockup cycle tracking with multiple edge cases (validator going inactive, synchronization logic, observed lockup cycle advancement)
2. **Historical context**: Staking systems across multiple blockchains have had lockup-related bugs
3. **Dependency on correctness**: The indexer provides critical data for user interfaces, analytics platforms, and third-party integrations
4. **No redundant checks**: Single point of failure if on-chain validation fails

However, requires an on-chain bug to manifest actual harm.

## Recommendation

Implement independent validation in the indexer by tracking delegation pool state:

```rust
impl DelegatedStakingActivity {
    pub fn from_transaction(transaction: &APITransaction) -> anyhow::Result<Vec<Self>> {
        let mut delegator_activities = vec![];
        // ... existing parsing code ...
        
        for (index, event) in events.iter().enumerate() {
            // ... existing code ...
            
            if let Some(staking_event) = StakeEvent::from_event(...) {
                match staking_event {
                    StakeEvent::WithdrawStakeEvent(inner) => {
                        // NEW: Validate withdrawal timing
                        if !Self::validate_withdrawal_timing(
                            conn, 
                            &inner.pool_address, 
                            &inner.delegator_address,
                            txn_version
                        )? {
                            tracing::warn!(
                                "Invalid withdrawal timing detected at version {}: pool={}, delegator={}",
                                txn_version, inner.pool_address, inner.delegator_address
                            );
                            // Optionally: mark as suspicious or skip indexing
                        }
                        
                        DelegatedStakingActivity { /* ... */ }
                    },
                    // ... other events ...
                }
            }
        }
        Ok(delegator_activities)
    }
    
    fn validate_withdrawal_timing(
        conn: &mut PgPoolConnection,
        pool_address: &str,
        delegator_address: &str,
        txn_version: i64,
    ) -> anyhow::Result<bool> {
        // Query delegation pool state from write set to check:
        // 1. Current observed_lockup_cycle
        // 2. Delegator's pending withdrawal lockup cycle
        // 3. Validator status and locked_until_secs
        // Return false if withdrawal appears premature
        todo!("Implement validation logic")
    }
}
```

The indexer should track delegation pool resources and validate that withdrawal events only occur when:
1. The delegator's pending withdrawal lockup cycle is less than the current observed lockup cycle, OR
2. The validator is inactive AND current block timestamp ≥ locked_until_secs

## Proof of Concept

This cannot be demonstrated with a standalone PoC because it requires:
1. First introducing a bug in the on-chain validation logic (which doesn't exist currently)
2. Then showing the indexer fails to detect it

However, the lack of validation can be confirmed by code inspection: [6](#0-5) 

The `from_transaction` function contains no validation logic for withdrawal timing - it only parses event fields and stores them.

**Notes**

This finding represents a **defense-in-depth gap** rather than a directly exploitable vulnerability. The indexer's design philosophy of trusting on-chain events is reasonable, but adding validation would:
- Catch potential bugs in complex on-chain logic
- Provide early detection of anomalies
- Improve data reliability for downstream consumers
- Serve as a sanity check against unexpected behavior

The lack of validation does not break the indexer's primary function (accurately recording on-chain events) but reduces resilience against on-chain bugs.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/delegation_pool.move (L725-728)
```text
    public fun can_withdraw_pending_inactive(pool_address: address): bool {
        stake::get_validator_state(pool_address) == VALIDATOR_STATUS_INACTIVE &&
            timestamp::now_seconds() >= stake::get_lockup_secs(pool_address)
    }
```

**File:** aptos-move/framework/aptos-framework/sources/delegation_pool.move (L1754-1759)
```text
        let (withdrawal_exists, withdrawal_olc) = pending_withdrawal_exists(pool, delegator_address);
        // exit if no withdrawal or (it is pending and cannot withdraw pending_inactive stake from stake pool)
        if (!(
            withdrawal_exists &&
                (withdrawal_olc.index < pool.observed_lockup_cycle.index || can_withdraw_pending_inactive(pool_address))
        )) { return };
```

**File:** aptos-move/framework/aptos-framework/sources/delegation_pool.move (L2009-2009)
```text
        let lockup_cycle_ended = inactive > pool.total_coins_inactive;
```

**File:** aptos-move/framework/aptos-framework/sources/delegation_pool.move (L2113-2127)
```text
        // advance lockup cycle on delegation pool if already ended on stake pool (AND stake explicitly inactivated)
        if (lockup_cycle_ended) {
            // capture inactive coins over all ended lockup cycles (including this ending one)
            let (_, inactive, _, _) = stake::get_stake(pool_address);
            pool.total_coins_inactive = inactive;

            // advance lockup cycle on the delegation pool
            pool.observed_lockup_cycle.index = pool.observed_lockup_cycle.index + 1;
            // start new lockup cycle with a fresh shares pool for `pending_inactive` stake
            table::add(
                &mut pool.inactive_shares,
                pool.observed_lockup_cycle,
                pool_u64::create_with_scaling_factor(SHARES_SCALING_FACTOR)
            );
        };
```

**File:** crates/indexer/src/models/stake_models/delegator_activities.rs (L29-93)
```rust
impl DelegatedStakingActivity {
    /// Pretty straightforward parsing from known delegated staking events
    pub fn from_transaction(transaction: &APITransaction) -> anyhow::Result<Vec<Self>> {
        let mut delegator_activities = vec![];
        let (txn_version, events) = match transaction {
            APITransaction::UserTransaction(txn) => (txn.info.version.0 as i64, &txn.events),
            APITransaction::BlockMetadataTransaction(txn) => {
                (txn.info.version.0 as i64, &txn.events)
            },
            _ => return Ok(delegator_activities),
        };
        for (index, event) in events.iter().enumerate() {
            let event_type = event.typ.to_string();
            let event_index = index as i64;
            if let Some(staking_event) =
                StakeEvent::from_event(event_type.as_str(), &event.data, txn_version)?
            {
                let activity = match staking_event {
                    StakeEvent::AddStakeEvent(inner) => DelegatedStakingActivity {
                        transaction_version: txn_version,
                        event_index,
                        delegator_address: standardize_address(&inner.delegator_address),
                        pool_address: standardize_address(&inner.pool_address),
                        event_type: event_type.clone(),
                        amount: u64_to_bigdecimal(inner.amount_added),
                    },
                    StakeEvent::UnlockStakeEvent(inner) => DelegatedStakingActivity {
                        transaction_version: txn_version,
                        event_index,
                        delegator_address: standardize_address(&inner.delegator_address),
                        pool_address: standardize_address(&inner.pool_address),
                        event_type: event_type.clone(),
                        amount: u64_to_bigdecimal(inner.amount_unlocked),
                    },
                    StakeEvent::WithdrawStakeEvent(inner) => DelegatedStakingActivity {
                        transaction_version: txn_version,
                        event_index,
                        delegator_address: standardize_address(&inner.delegator_address),
                        pool_address: standardize_address(&inner.pool_address),
                        event_type: event_type.clone(),
                        amount: u64_to_bigdecimal(inner.amount_withdrawn),
                    },
                    StakeEvent::ReactivateStakeEvent(inner) => DelegatedStakingActivity {
                        transaction_version: txn_version,
                        event_index,
                        delegator_address: standardize_address(&inner.delegator_address),
                        pool_address: standardize_address(&inner.pool_address),
                        event_type: event_type.clone(),
                        amount: u64_to_bigdecimal(inner.amount_reactivated),
                    },
                    StakeEvent::DistributeRewardsEvent(inner) => DelegatedStakingActivity {
                        transaction_version: txn_version,
                        event_index,
                        delegator_address: "".to_string(),
                        pool_address: standardize_address(&inner.pool_address),
                        event_type: event_type.clone(),
                        amount: u64_to_bigdecimal(inner.rewards_amount),
                    },
                    _ => continue,
                };
                delegator_activities.push(activity);
            }
        }
        Ok(delegator_activities)
    }
```
