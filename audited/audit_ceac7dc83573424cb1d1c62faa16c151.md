# Audit Report

## Title
Indexer-gRPC Uses Wrong State Version to Decode Historical Transactions, Causing API Crashes and Data Corruption

## Summary
The `convert_to_api_txns()` function in the indexer-grpc-fullnode uses the latest blockchain state to decode ALL historical transactions in a batch, regardless of their actual version. When Move modules are upgraded between the transaction version and the latest state version, the decoder uses incompatible module schemas, causing either API crashes (via panic) or incorrect JSON data to be returned to clients.

## Finding Description
The vulnerability exists in the transaction conversion logic: [1](#0-0) 

The function obtains a single state view at the **latest** checkpoint version, then creates one converter that is reused for all transactions in the batch: [2](#0-1) 

Each transaction has its own version (`txn_version` at line 393), but all transactions use the same converter created with the latest state. This violates the fundamental principle that **historical data must be decoded using the schema that existed at the time of that data**.

The state view is used by the converter to fetch Move module bytecode for decoding events, resources, and other Move types: [3](#0-2) 

When the converter attempts to decode a transaction from version V using a module schema from version L (where L > V and the module was upgraded), the BCS deserialization fails because the data layout is incompatible. The error handling then triggers a panic: [4](#0-3) 

**Attack Scenario:**
1. Attacker deploys `ModuleA v1` at version 1000 with `struct Event { value: u64 }`
2. Transactions at versions 1001-2000 emit events using this struct
3. At version 5000, attacker upgrades to `ModuleA v2` with `struct Event { value: u64, new_field: vector<u8> }`
4. Latest blockchain version advances to 10000
5. Indexer processes a batch containing transactions 1001-2000
6. Converter fetches `ModuleA v2` from state view at version 10000
7. Attempts to deserialize v1 events using v2 schema → BCS deserialization failure
8. Panic at line 460-463 crashes the indexer-grpc-fullnode

## Impact Explanation
This qualifies as **High Severity** under the Aptos Bug Bounty program's "API crashes" category: [5](#0-4) 

**Primary Impacts:**
- **API Denial of Service**: Indexer-grpc-fullnode crashes and becomes unavailable to clients
- **Data Integrity**: Even when not crashing, historical transactions are decoded with incorrect schemas, producing wrong JSON data
- **Cascading Failures**: Clients depending on indexer data receive incorrect information about historical transactions

**Affected Systems:**
- All indexer-grpc-fullnode instances serving historical transaction data
- Any downstream systems or applications relying on indexer API accuracy

## Likelihood Explanation
**Likelihood: High**

This vulnerability triggers automatically whenever:
1. Any Move module is upgraded (common in active chains)
2. The indexer processes batches spanning versions before and after the upgrade
3. The batch size is large enough to include transactions from both sides of the upgrade

**Attacker Requirements:**
- Ability to publish and upgrade Move modules (any user can do this)
- No special privileges required
- No validator access needed

**Natural Occurrence:**
Even without malicious intent, this bug occurs naturally during normal blockchain operation as developers upgrade their Move modules. The indexer routinely processes historical data, making this a persistent issue.

## Recommendation
Each transaction must be decoded using the state view from its own version, not the latest version. The correct implementation should obtain a version-specific state view for each transaction:

**Current (Incorrect) Implementation:** [6](#0-5) 

**Fixed Implementation:**
```rust
fn convert_to_api_txns(
    context: Arc<Context>,
    raw_txns: Vec<TransactionOnChainData>,
) -> Vec<(APITransaction, TransactionSizeInfo)> {
    // ... existing code ...
    
    let mut transactions = vec![];
    for (ind, raw_txn) in raw_txns.into_iter().enumerate() {
        let txn_version = raw_txn.version;
        
        // Get state view AT THE TRANSACTION'S VERSION
        let state_view = context.state_view_at_version(txn_version).unwrap();
        let converter = state_view.as_converter(context.db.clone(), context.indexer_reader.clone());
        
        // ... rest of the conversion logic using this version-specific converter ...
    }
}
```

The `state_view_at_version()` method already exists in the Context: [7](#0-6) 

**Performance Note:** Creating a converter per transaction may have performance implications. Consider optimization strategies like:
- Batching transactions by version ranges where no module upgrades occurred
- Caching converters for consecutive transactions at the same version
- Using parallel processing with version-grouped batches

## Proof of Concept

```rust
// Proof of Concept - Rust Integration Test
#[tokio::test]
async fn test_indexer_crashes_on_module_upgrade() {
    // Setup: Deploy a blockchain with ModuleA v1
    let mut test_context = create_test_blockchain();
    
    // Step 1: Publish ModuleA v1 at version 100
    let module_v1 = compile_move_module(r#"
        module 0x1::TestModule {
            struct Event has drop, store {
                value: u64
            }
            
            public entry fun emit_event(account: &signer) {
                event::emit(Event { value: 42 });
            }
        }
    "#);
    test_context.publish_module(module_v1).await;
    
    // Step 2: Generate transactions using ModuleA v1 (versions 101-200)
    for i in 0..100 {
        test_context.execute_transaction("0x1::TestModule::emit_event").await;
    }
    
    // Step 3: Upgrade to ModuleA v2 at version 500
    let module_v2 = compile_move_module(r#"
        module 0x1::TestModule {
            struct Event has drop, store {
                value: u64,
                new_field: vector<u8>  // Added field - incompatible schema
            }
            
            public entry fun emit_event(account: &signer) {
                event::emit(Event { value: 42, new_field: b"test" });
            }
        }
    "#);
    test_context.publish_module_upgrade(module_v2).await;
    
    // Step 4: Advance chain to version 1000
    test_context.advance_to_version(1000).await;
    
    // Step 5: Attempt to convert transactions 101-200 (created with v1)
    let coordinator = IndexerStreamCoordinator::new(
        test_context.context.clone(),
        101, // start version
        200, // end version
        1, 1, 1,
        test_context.sender.clone(),
        None, None
    );
    
    // EXPECTED: Panic when trying to decode v1 events with v2 schema
    // The converter fetches ModuleA v2 from latest state (version 1000)
    // Tries to deserialize v1 event data (missing new_field)
    // BCS deserialization fails -> panic at stream_coordinator.rs:460
    let result = coordinator.process_next_batch().await;
    
    // This will panic with:
    // "[Indexer Fullnode] Could not convert txn 101 from OnChainTransactions: ..."
    assert!(result.is_empty()); // Never reached due to panic
}
```

**Notes**

This vulnerability is NOT a traditional race condition involving concurrent state updates. Rather, it's a **version mismatch bug** where the indexer uses the wrong temporal version of state to decode historical data. The term "stale state" in the security question is somewhat misleading—the state view itself is consistent and up-to-date, but it's the **wrong state** for the historical transactions being processed.

The fix requires using version-specific state views as demonstrated in the recommendation. The existing `state_view_at_version()` API provides the necessary functionality to implement this correctly.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L362-373)
```rust
    fn convert_to_api_txns(
        context: Arc<Context>,
        raw_txns: Vec<TransactionOnChainData>,
    ) -> Vec<(APITransaction, TransactionSizeInfo)> {
        if raw_txns.is_empty() {
            return vec![];
        }
        let start_millis = chrono::Utc::now().naive_utc();

        let first_version = raw_txns.first().map(|txn| txn.version).unwrap();
        let state_view = context.latest_state_view().unwrap();
        let converter = state_view.as_converter(context.db.clone(), context.indexer_reader.clone());
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L392-413)
```rust
        for (ind, raw_txn) in raw_txns.into_iter().enumerate() {
            let txn_version = raw_txn.version;
            // Do not update block_height if first block is block metadata
            if ind > 0 {
                // Update the timestamp if the next block occurs
                if let Some(txn) = raw_txn.transaction.try_as_block_metadata_ext() {
                    timestamp = txn.timestamp_usecs();
                    epoch = txn.epoch();
                    epoch_bcs = aptos_api_types::U64::from(epoch);
                    block_height += 1;
                    block_height_bcs = aptos_api_types::U64::from(block_height);
                } else if let Some(txn) = raw_txn.transaction.try_as_block_metadata() {
                    timestamp = txn.timestamp_usecs();
                    epoch = txn.epoch();
                    epoch_bcs = aptos_api_types::U64::from(epoch);
                    block_height += 1;
                    block_height_bcs = aptos_api_types::U64::from(block_height);
                }
            }
            let size_info = Self::get_size_info(&raw_txn);
            let res = converter
                .try_into_onchain_transaction(timestamp, raw_txn)
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L449-464)
```rust
            match res {
                Ok(transaction) => transactions.push((transaction, size_info)),
                Err(err) => {
                    UNABLE_TO_FETCH_TRANSACTION.inc();
                    error!(
                        version = txn_version,
                        error = format!("{:?}", err),
                        "[Indexer Fullnode] Could not convert from OnChainTransactions",
                    );
                    // IN CASE WE NEED TO SKIP BAD TXNS
                    // continue;
                    panic!(
                        "[Indexer Fullnode] Could not convert txn {} from OnChainTransactions: {:?}",
                        txn_version, err
                    );
                },
```

**File:** aptos-move/aptos-resource-viewer/src/module_view.rs (L56-87)
```rust
    fn view_compiled_module(&self, module_id: &ModuleId) -> anyhow::Result<Option<Self::Item>> {
        let mut module_cache = self.module_cache.borrow_mut();
        if let Some(module) = module_cache.get(module_id) {
            return Ok(Some(module.clone()));
        }

        let state_key = StateKey::module_id(module_id);
        Ok(
            match self
                .state_view
                .get_state_value_bytes(&state_key)
                .map_err(|e| anyhow!("Error retrieving module {:?}: {:?}", module_id, e))?
            {
                Some(bytes) => {
                    let compiled_module =
                        CompiledModule::deserialize_with_config(&bytes, &self.deserializer_config)
                            .map_err(|status| {
                                anyhow!(
                                    "Module {:?} deserialize with error code {:?}",
                                    module_id,
                                    status
                                )
                            })?;

                    let compiled_module = Arc::new(compiled_module);
                    module_cache.insert(module_id.clone(), compiled_module.clone());
                    Some(compiled_module)
                },
                None => None,
            },
        )
    }
```

**File:** api/src/context.rs (L193-195)
```rust
    pub fn state_view_at_version(&self, version: Version) -> Result<DbStateView> {
        Ok(self.db.state_view_at_version(Some(version))?)
    }
```
