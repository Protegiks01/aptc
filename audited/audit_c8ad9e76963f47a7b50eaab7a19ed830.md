# Audit Report

## Title
Integer Overflow in Indexer Version Casting Causes Database Update Failures

## Summary
The stake processor's `from_transaction()` methods cast blockchain version numbers from `u64` to `i64` for PostgreSQL storage. When version numbers exceed `i64::MAX` (9,223,372,036,854,775,807), the cast wraps to negative values, breaking version comparison logic in database upsert operations and preventing newer data from updating older records.

## Finding Description

The indexer processes blockchain transactions and stores staking-related data in PostgreSQL. Transaction version numbers originating from the blockchain are `u64` type, but are cast to `i64` for database storage.

In multiple model files, version extraction performs an unchecked cast: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

The database schema defines all version fields as `Int8` (PostgreSQL BIGINT = i64): [6](#0-5) [7](#0-6) [8](#0-7) 

Critical database upsert operations use version comparisons to ensure only newer data updates existing records: [9](#0-8) [10](#0-9) [11](#0-10) 

**The Vulnerability**: When `u64` version ≥ 9,223,372,036,854,775,808 (i64::MAX + 1), the cast `as i64` produces negative values due to two's complement wrapping. For example:
- Version 9,223,372,036,854,775,808 → -9,223,372,036,854,775,808
- Version 18,446,744,073,709,551,615 (u64::MAX) → -1

The WHERE clause `old_version <= new_version` evaluates to FALSE when old_version is positive and new_version is negative, preventing database updates and freezing the indexer with stale data.

## Impact Explanation

This qualifies as **Medium Severity** per Aptos bug bounty criteria: "State inconsistencies requiring intervention."

When triggered:
1. **Indexer Data Staleness**: All current staking tables (`current_staking_pool_voter`, `current_delegator_balances`, `current_delegated_staking_pool_balances`) stop updating
2. **API Query Failures**: GraphQL queries return outdated validator voting information, delegator balances, and staking pool states
3. **Governance Impact**: Proposal vote tracking becomes unreliable for versions beyond the overflow point
4. **Manual Intervention Required**: Database schema migration and data backfill necessary to recover

**Crucially**: This affects ONLY the indexer service, not blockchain consensus, execution, or fund safety. The core blockchain continues operating normally. However, applications relying on indexer APIs for staking/governance data would receive incorrect information.

## Likelihood Explanation

**Extremely Low in Near-Term**: Requires approximately 9.2 quintillion (9.2 × 10¹⁸) transactions. At 10,000 TPS sustained 24/7, this takes ~29 million years.

**However**: This represents a architectural time-bomb that will eventually trigger if the blockchain operates long-term. The Aptos codebase demonstrates awareness of this pattern in other contexts: [12](#0-11) 

The defensive comment explicitly acknowledges i64 overflow risks when handling version numbers.

## Recommendation

**Immediate Fix**: Change database schema and model types from `i64` to PostgreSQL `NUMERIC` (arbitrary precision) to accommodate full u64 range:

```rust
// In models
pub struct ProposalVote {
    pub transaction_version: BigDecimal,  // Instead of i64
    // ...
}

impl ProposalVote {
    pub fn from_transaction(transaction: &APITransaction) -> anyhow::Result<Vec<Self>> {
        // ...
        let txn_version = BigDecimal::from(user_txn.info.version.0);  // No cast
        // ...
    }
}
```

**Schema Migration**:
```sql
ALTER TABLE proposal_votes ALTER COLUMN transaction_version TYPE NUMERIC(20,0);
ALTER TABLE delegated_staking_activities ALTER COLUMN transaction_version TYPE NUMERIC(20,0);
ALTER TABLE current_staking_pool_voter ALTER COLUMN last_transaction_version TYPE NUMERIC(20,0);
-- (Apply to all affected tables)
```

**Alternative**: Use u64 with custom Diesel serialization, though NUMERIC is simpler for PostgreSQL compatibility.

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_version_overflow_behavior() {
        // Demonstrate the overflow issue
        let version_at_max: u64 = i64::MAX as u64;  // 9,223,372,036,854,775,807
        let version_beyond_max: u64 = (i64::MAX as u64) + 1;  // 9,223,372,036,854,775,808
        
        let cast_at_max = version_at_max as i64;
        let cast_beyond_max = version_beyond_max as i64;
        
        assert_eq!(cast_at_max, 9_223_372_036_854_775_807);
        assert_eq!(cast_beyond_max, -9_223_372_036_854_775_808);  // Wraps to negative!
        
        // Simulate the WHERE clause comparison
        let old_version: i64 = 1_000_000;  // Existing database value
        let new_version: i64 = cast_beyond_max;  // New transaction version (wrapped)
        
        // This comparison FAILS when it should succeed
        assert!(!(old_version <= new_version));  // FALSE - update prevented!
        
        println!("Version overflow demonstrated:");
        println!("  u64 version {} casts to i64 {}", version_beyond_max, cast_beyond_max);
        println!("  WHERE {} <= {} evaluates to FALSE", old_version, new_version);
        println!("  Database update BLOCKED despite newer version");
    }
}
```

**Notes**

This vulnerability is confirmed in the codebase but has extremely low likelihood given current blockchain throughput. The issue represents defensive programming concern rather than imminent exploit risk. The indexer is an auxiliary service - its failure does not compromise blockchain consensus, validator operations, or fund security. Applications should implement fallback mechanisms and not rely solely on indexer data for critical operations.

### Citations

**File:** crates/indexer/src/models/stake_models/proposal_votes.rs (L35-35)
```rust
                let txn_version = user_txn.info.version.0 as i64;
```

**File:** crates/indexer/src/models/stake_models/delegator_activities.rs (L34-36)
```rust
            APITransaction::UserTransaction(txn) => (txn.info.version.0 as i64, &txn.events),
            APITransaction::BlockMetadataTransaction(txn) => {
                (txn.info.version.0 as i64, &txn.events)
```

**File:** crates/indexer/src/models/stake_models/staking_pool_voter.rs (L32-37)
```rust
            APITransaction::UserTransaction(txn) => (txn.info.version.0 as i64, &txn.info.changes),
            APITransaction::GenesisTransaction(txn) => {
                (txn.info.version.0 as i64, &txn.info.changes)
            },
            APITransaction::BlockMetadataTransaction(txn) => {
                (txn.info.version.0 as i64, &txn.info.changes)
```

**File:** crates/indexer/src/models/stake_models/delegator_pools.rs (L99-99)
```rust
            let txn_version = user_txn.info.version.0 as i64;
```

**File:** crates/indexer/src/models/stake_models/delegator_balances.rs (L327-327)
```rust
            let txn_version = user_txn.info.version.0 as i64;
```

**File:** crates/indexer/src/schema.rs (L296-296)
```rust
        last_transaction_version -> Int8,
```

**File:** crates/indexer/src/schema.rs (L471-471)
```rust
        transaction_version -> Int8,
```

**File:** crates/indexer/src/schema.rs (L628-628)
```rust
        transaction_version -> Int8,
```

**File:** crates/indexer/src/processors/stake_processor.rs (L154-156)
```rust
            Some(
                " WHERE current_staking_pool_voter.last_transaction_version <= EXCLUDED.last_transaction_version ",
            ),
```

**File:** crates/indexer/src/processors/stake_processor.rs (L225-227)
```rust
            Some(
                " WHERE current_delegator_balances.last_transaction_version <= EXCLUDED.last_transaction_version ",
            ),
```

**File:** crates/indexer/src/processors/stake_processor.rs (L305-307)
```rust
            Some(
                " WHERE current_delegated_staking_pool_balances.last_transaction_version <= EXCLUDED.last_transaction_version ",
            ),
```

**File:** ecosystem/node-checker/src/checker/state_sync_version.rs (L45-46)
```rust
        // We convert to i64 to avoid potential overflow if somehow the ledger version went backwards.
        let target_progress = latest_target_version as i64 - previous_target_version as i64;
```
