# Audit Report

## Title
Indexer Silent Supply Tracking Failure Due to Missing CoinInfo Metadata

## Summary
The coin indexer can silently fail to record all supply changes when AptosCoin metadata is missing from the `coin_infos` table, resulting in permanent, undetectable gaps in supply history without any error indication.

## Finding Description

The `coin_supply` table schema does not enforce continuous transaction_version tracking. [1](#0-0)  Supply records are only created when aggregator table writes occur, making gaps expected by design.

However, a critical implementation flaw exists in the supply tracking logic. The coin processor queries for AptosCoin metadata at the start of each batch: [2](#0-1) 

If this query returns `None` (no AptosCoin entry found), the supply extraction logic silently skips all supply changes: [3](#0-2) 

The vulnerability occurs because:
1. The indexer can be configured to start from any version via `STARTING_VERSION` environment variable [4](#0-3) 
2. The runtime uses this config to skip genesis if set: [5](#0-4) 
3. If genesis (version 0) is skipped, AptosCoin info is never indexed
4. All subsequent supply changes are silently dropped with no error raised
5. Transactions are marked as successfully processed despite missing supply data

## Impact Explanation

**Medium Severity** - This meets the "State inconsistencies requiring intervention" category. While this doesn't affect on-chain consensus or funds directly (the blockchain state remains correct), it creates permanent data integrity issues in the indexer that:

- Provide incorrect supply history to users and applications
- Could mask malicious minting/burning events from historical queries
- Require manual intervention to detect and repair
- Cannot be detected by normal monitoring (no errors raised)
- Violate data completeness guarantees expected by indexer consumers

Note: This is **not** a critical blockchain vulnerability as it only affects the off-chain indexer service, not the core consensus or on-chain state.

## Likelihood Explanation

**High Likelihood** of occurrence in specific scenarios:
- Operator misconfiguration during indexer deployment (setting `STARTING_VERSION > 0`)
- Database backup/restore operations that exclude genesis data
- Indexer restart scenarios with partial database state
- Testing/development environments where operators commonly skip genesis

The issue is particularly insidious because it fails silently with no indication that supply tracking has stopped working.

## Recommendation

Add explicit validation to ensure AptosCoin metadata exists before processing transactions:

```rust
// In process_transactions method, after line 286:
let maybe_aptos_coin_info = &CoinInfoQuery::get_by_coin_type(
    AptosCoinType::type_tag().to_canonical_string(),
    &mut conn,
)
.unwrap();

// ADD THIS VALIDATION:
if maybe_aptos_coin_info.is_none() {
    return Err(TransactionProcessingError::ProcessingError((
        anyhow::anyhow!(
            "AptosCoin metadata not found in coin_infos table. \
             Indexer must process genesis transaction (version 0) first. \
             Current starting version: {}",
            start_version
        ),
        start_version,
        end_version,
        self.name(),
    )));
}
```

Additionally, add startup validation in `runtime.rs` to prevent skipping genesis:

```rust
// After line 176, add:
if processor_enum == Processor::CoinProcessor && start_version > 0 {
    warn!(
        "CoinProcessor starting from version {} may miss AptosCoin initialization. \
         Consider starting from version 0 (genesis) for complete supply tracking.",
        start_version
    );
}
```

## Proof of Concept

```rust
// Reproduction steps:
// 1. Start fresh indexer with empty database
// 2. Set environment variable: STARTING_VERSION=1000
// 3. Start coin processor
// 4. Observe: All transactions are marked successful
// 5. Query coin_supply table: Empty (no supply records)
// 6. No errors in logs

#[tokio::test]
async fn test_missing_coin_info_silent_failure() {
    // Setup database and processor
    let conn_pool = setup_test_db();
    let processor = CoinTransactionProcessor::new(conn_pool.clone());
    
    // Create test transaction with supply change at version 1000
    let txn = create_test_transaction_with_supply_change(1000);
    
    // Process without AptosCoin info in database
    let result = processor.process_transactions(vec![txn], 1000, 1000).await;
    
    // Transaction processing succeeds
    assert!(result.is_ok());
    
    // But coin_supply table is empty - data silently lost!
    let supply_records = query_coin_supply(&mut conn_pool.get().unwrap());
    assert_eq!(supply_records.len(), 0); // VULNERABILITY: No supply recorded
}
```

## Notes

This vulnerability specifically affects the **indexer service**, which is an off-chain data availability component, not the core blockchain consensus or state management. The on-chain supply values remain correct and are not affected by this issue. This is primarily a data integrity concern for applications relying on indexer historical data.

### Citations

**File:** crates/indexer/src/schema.rs (L94-106)
```rust
diesel::table! {
    coin_supply (transaction_version, coin_type_hash) {
        transaction_version -> Int8,
        #[max_length = 64]
        coin_type_hash -> Varchar,
        #[max_length = 5000]
        coin_type -> Varchar,
        supply -> Numeric,
        transaction_timestamp -> Timestamp,
        transaction_epoch -> Int8,
        inserted_at -> Timestamp,
    }
}
```

**File:** crates/indexer/src/processors/coin_processor.rs (L280-286)
```rust
        // get aptos_coin info for supply tracking
        // TODO: This only needs to be fetched once. Need to persist somehow
        let maybe_aptos_coin_info = &CoinInfoQuery::get_by_coin_type(
            AptosCoinType::type_tag().to_canonical_string(),
            &mut conn,
        )
        .unwrap();
```

**File:** crates/indexer/src/models/coin_models/coin_supply.rs (L31-96)
```rust
    pub fn from_write_table_item(
        write_table_item: &APIWriteTableItem,
        maybe_aptos_coin_info: &Option<CoinInfoQuery>,
        txn_version: i64,
        txn_timestamp: chrono::NaiveDateTime,
        txn_epoch: i64,
    ) -> anyhow::Result<Option<Self>> {
        if let Some(aptos_coin_info) = maybe_aptos_coin_info {
            // Return early if we don't have the aptos aggregator table info
            if aptos_coin_info.supply_aggregator_table_key.is_none()
                || aptos_coin_info.supply_aggregator_table_handle.is_none()
            {
                return Ok(None);
            }
            if let Some(data) = &write_table_item.data {
                // Return early if not aggregator table type
                if !(data.key_type == "address" && data.value_type == "u128") {
                    return Ok(None);
                }
                // Return early if not aggregator table handle
                if &write_table_item.handle.to_string()
                    != aptos_coin_info
                        .supply_aggregator_table_handle
                        .as_ref()
                        .unwrap()
                {
                    return Ok(None);
                }
                // Return early if not aptos coin aggregator key
                let table_key = data
                    .key
                    .as_str()
                    .context(format!("key is not a string: {:?}", data.key))?;
                if table_key
                    != aptos_coin_info
                        .supply_aggregator_table_key
                        .as_ref()
                        .unwrap()
                {
                    return Ok(None);
                }
                // Everything matches. Get the coin supply
                let supply = data
                    .value
                    .as_str()
                    .map(|s| s.parse::<BigDecimal>())
                    .context(format!(
                        "value is not a string: {:?}, table_item {:?}, version {}",
                        data.value, write_table_item, txn_version
                    ))?
                    .context(format!(
                        "cannot parse string as u128: {:?}, version {}",
                        data.value, txn_version
                    ))?;
                return Ok(Some(Self {
                    transaction_version: txn_version,
                    coin_type_hash: aptos_coin_info.coin_type_hash.clone(),
                    coin_type: aptos_coin_info.coin_type.clone(),
                    supply,
                    transaction_timestamp: txn_timestamp,
                    transaction_epoch: txn_epoch,
                }));
            }
        }
        Ok(None)
    }
```

**File:** config/src/config/indexer_config.rs (L43-47)
```rust
    /// If set, will ignore database contents and start processing from the specified version.
    /// This will not delete any database contents, just transactions as it reprocesses them.
    /// Alternatively can set the `STARTING_VERSION` env var
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub starting_version: Option<u64>,
```

**File:** crates/indexer/src/runtime.rs (L173-176)
```rust
    let start_version = match config.starting_version {
        None => starting_version_from_db_short,
        Some(version) => version,
    };
```
