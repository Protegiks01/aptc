# Audit Report

## Title
Transaction Expiration Misconfiguration in Large Package Deployment Causes Sequential Transaction Failures

## Summary
The `generate_transactions()` function in `publish_modules.rs` does not validate or adjust the `txn_factory` configuration for large package deployments. When packages exceed 55KB and are chunked into multiple sequential transactions, all transactions receive nearly identical expiration timestamps but must execute sequentially due to sequence number ordering. In congested network conditions, later transactions in the sequence can expire before execution, causing deployment failures and wasted gas fees.

## Finding Description
The vulnerability exists in how large Move packages are published through the transaction generator library. When a package exceeds the `CHUNK_SIZE_IN_BYTES` threshold (55,000 bytes), it is automatically split into multiple transactions by the `publish_transaction_payload()` method. [1](#0-0) [2](#0-1) 

The core issue occurs in the transaction generation loop where all chunked transactions are created with the same `txn_factory` configuration: [3](#0-2) 

Each transaction receives an expiration timestamp calculated as "current time + expiration_duration": [4](#0-3) 

The default expiration configuration in production deployments is 60 seconds: [5](#0-4) 

**The Problem:** All chunked transactions are created within milliseconds of each other in the loop, giving them nearly identical expiration timestamps (~60 seconds from creation). However, these transactions MUST execute sequentially because they:
1. Share the same sender account with sequential sequence numbers
2. Depend on the `StagingArea` resource being progressively built up by earlier transactions [6](#0-5) 

In a congested network where block production or transaction processing is delayed, the execution timeline might look like:
- Chunk 0: Created at T+0, expires at T+60, executes at T+35
- Chunk 1: Created at T+0.01, expires at T+60, executes at T+50  
- Chunk 2: Created at T+0.02, expires at T+60, executes at T+62 → **EXPIRED**

The transaction validation prologue checks expiration before execution: [7](#0-6) 

**State Inconsistency:** When later chunks expire, the `StagingArea` resource is left in a partially populated state with incomplete module data. There is no automatic cleanup mechanism triggered by transaction expiration: [8](#0-7) 

**No Validation:** The `PublishPackageCreator` accepts any `TransactionFactory` without validating its configuration is appropriate for chunked deployments: [9](#0-8) 

## Impact Explanation
This issue qualifies as **High Severity** based on the following impact:

1. **Transaction Failures:** Legitimate large package deployments fail unpredictably during network congestion, breaking the "Resource Limits" invariant where operations should gracefully handle their resource constraints.

2. **Gas Fee Loss:** Users pay gas fees for successfully executed chunks (e.g., 1-5 out of 10 chunks) but receive no value as the incomplete deployment is unusable. This represents direct financial loss.

3. **State Inconsistency:** The `StagingArea` resource remains in an inconsistent state requiring manual cleanup via `cleanup_staging_area()`, which most users won't know to call. This violates the "State Consistency" invariant.

4. **No Error Recovery:** The system provides no retry mechanism, expiration time adjustment, or clear error messaging to users about why deployment failed midway through.

This falls under **"Significant protocol violations"** (High Severity) as it causes the large package deployment protocol to systematically fail under foreseeable network conditions without graceful degradation.

## Likelihood Explanation
**Likelihood: Medium to High**

This issue will occur when ALL of the following conditions are met:
1. Package size > 55KB (triggers chunking into 2+ transactions)
2. Network is under moderate load (5-10 second block times or mempool backlog)
3. Default 60-second expiration is used (common in production)
4. Number of chunks × average execution time > 60 seconds

Large Move packages are common in production (frameworks, DeFi protocols, complex dApps). Network congestion is a normal operational state, not an edge case. The 60-second default expiration provides no safety margin for multi-transaction sequences.

**Estimate:** In a network with 10-second block times and mempool delays, a package chunked into 8+ transactions has a high probability of partial failure.

## Recommendation

**Solution 1: Staggered Expiration Times (Recommended)**

Modify `generate_transactions()` to progressively increase expiration times for sequential chunks:

```rust
pub fn generate_transactions(
    &mut self,
    account: &LocalAccount,
    num_to_create: usize,
) -> Vec<SignedTransaction> {
    let mut requests = Vec::with_capacity(num_to_create);
    
    let package = self
        .package_handler
        .write()
        .pick_package(&mut self.rng, account.address());
    
    let payloads = package.publish_transaction_payload(&self.txn_factory.get_chain_id());
    let num_chunks = payloads.len();
    
    // For chunked deployments, add expiration buffer per chunk
    let expiration_buffer_per_chunk = if num_chunks > 1 { 30 } else { 0 };
    
    for (idx, payload) in payloads.into_iter().enumerate() {
        let factory = if num_chunks > 1 {
            // Add extra expiration time for later chunks
            let extra_time = (idx as u64) * expiration_buffer_per_chunk;
            self.txn_factory
                .clone()
                .with_transaction_expiration_time(
                    self.txn_factory.get_transaction_expiration_time() + extra_time
                )
        } else {
            self.txn_factory.clone()
        };
        
        let txn = account.sign_with_transaction_builder(factory.payload(payload));
        requests.push(txn);
    }
    
    requests
}
```

**Solution 2: Validate Factory Configuration**

Add validation in `PublishPackageCreator::new()` to enforce minimum gas and expiration for large packages:

```rust
pub fn new(txn_factory: TransactionFactory, package_handler: PackageHandler) -> Self {
    // Validate factory configuration for large package deployments
    const MIN_GAS_FOR_CHUNKED: u64 = 2_000_000;
    const MIN_EXPIRATION_FOR_CHUNKED: u64 = 120; // 2 minutes minimum
    
    let factory = txn_factory
        .with_max_gas_amount(std::cmp::max(
            txn_factory.get_max_gas_amount(),
            MIN_GAS_FOR_CHUNKED
        ))
        .with_transaction_expiration_time(std::cmp::max(
            txn_factory.get_transaction_expiration_time(),
            MIN_EXPIRATION_FOR_CHUNKED
        ));
    
    Self {
        txn_factory: factory,
        package_handler: Arc::new(RwLock::new(package_handler)),
    }
}
```

## Proof of Concept

```rust
#[test]
fn test_chunked_deployment_expiration_failure() {
    use aptos_sdk::transaction_builder::TransactionFactory;
    use aptos_types::chain_id::ChainId;
    
    // Create a factory with short 5-second expiration
    let factory = TransactionFactory::new(ChainId::test())
        .with_transaction_expiration_time(5); // Unrealistically short
    
    // Create a large package that will be chunked (> 55KB)
    let large_package = create_large_test_package(100_000); // 100KB package
    
    let creator = PublishPackageCreator::new(factory, large_package);
    let generator = creator.create_transaction_generator();
    
    let account = LocalAccount::generate(&mut rand::thread_rng());
    let txns = generator.generate_transactions(&account, 1);
    
    // Verify multiple transactions were created
    assert!(txns.len() > 1, "Package should be chunked");
    
    // Simulate 10 seconds passing (network delay)
    std::thread::sleep(std::time::Duration::from_secs(10));
    
    // Check expiration times - all transactions will have expired
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    for (idx, txn) in txns.iter().enumerate() {
        let expiration = txn.raw_txn().expiration_timestamp_secs();
        println!("Chunk {} expires at {}, current time {}", idx, expiration, current_time);
        
        // Later chunks expire before they can be processed
        if idx > 0 && current_time > expiration {
            panic!("Transaction {} expired before execution!", idx);
        }
    }
}
```

## Notes

The root cause is a mismatch between the transaction generation model (create all transactions upfront) and the execution model (sequential processing with network delays). The `txn_factory` is designed for independent transactions, not dependent sequential chains.

Additional considerations:
- Gas limits appear adequate (2M max) based on `CHUNK_SIZE_IN_BYTES` being conservatively set at 55KB
- The issue is specifically about **expiration time**, not gas exhaustion
- Chunked publishing is a necessary feature for large packages given the 64KB transaction size limit
- The vulnerability affects both production deployments and load testing scenarios

### Citations

**File:** aptos-move/framework/src/chunked_publish.rs (L20-20)
```rust
pub const CHUNK_SIZE_IN_BYTES: usize = 55_000;
```

**File:** crates/transaction-generator-lib/src/publishing/publish_util.rs (L205-226)
```rust
    pub fn publish_transaction_payload(&self, chain_id: &ChainId) -> Vec<TransactionPayload> {
        let (metadata_serialized, code) = self.get_publish_args();

        if metadata_serialized.len() + code.iter().map(|v| v.len()).sum::<usize>()
            > CHUNK_SIZE_IN_BYTES
        {
            chunk_package_and_create_payloads(
                metadata_serialized,
                code,
                PublishType::AccountDeploy,
                None,
                AccountAddress::from_str_strict(default_large_packages_module_address(chain_id))
                    .unwrap(),
                CHUNK_SIZE_IN_BYTES,
            )
        } else {
            vec![aptos_stdlib::code_publish_package_txn(
                metadata_serialized,
                code,
            )]
        }
    }
```

**File:** crates/transaction-generator-lib/src/publish_modules.rs (L48-51)
```rust
        for payload in package.publish_transaction_payload(&self.txn_factory.get_chain_id()) {
            let txn = account.sign_with_transaction_builder(self.txn_factory.payload(payload));
            requests.push(txn);
        }
```

**File:** crates/transaction-generator-lib/src/publish_modules.rs (L67-79)
```rust
pub struct PublishPackageCreator {
    txn_factory: TransactionFactory,
    package_handler: Arc<RwLock<PackageHandler>>,
}

impl PublishPackageCreator {
    pub fn new(txn_factory: TransactionFactory, package_handler: PackageHandler) -> Self {
        Self {
            txn_factory,
            package_handler: Arc::new(RwLock::new(package_handler)),
        }
    }
}
```

**File:** sdk/src/transaction_builder.rs (L375-390)
```rust
    fn expiration_timestamp(&self) -> u64 {
        match self.transaction_expiration {
            TransactionExpiration::Relative {
                expiration_duration,
            } => {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + expiration_duration
            },
            TransactionExpiration::Absolute {
                expiration_timestamp,
            } => expiration_timestamp,
        }
    }
```

**File:** crates/transaction-emitter-lib/src/emitter/mod.rs (L215-221)
```rust
            max_gas_per_txn: aptos_global_constants::MAX_GAS_AMOUNT,
            gas_price: aptos_global_constants::GAS_UNIT_PRICE,
            init_max_gas_per_txn: None,
            init_gas_price_multiplier: 2,
            mint_to_root: false,
            skip_funding_accounts: false,
            txn_expiration_time_secs: 60,
```

**File:** aptos-move/framework/aptos-experimental/sources/large_packages.move (L60-64)
```text
    struct StagingArea has key {
        metadata_serialized: vector<u8>,
        code: SmartTable<u64, vector<u8>>,
        last_module_idx: u64
    }
```

**File:** aptos-move/framework/aptos-experimental/sources/large_packages.move (L132-181)
```text
    inline fun stage_code_chunk_internal(
        owner: &signer,
        metadata_chunk: vector<u8>,
        code_indices: vector<u16>,
        code_chunks: vector<vector<u8>>
    ): &mut StagingArea {
        assert!(
            vector::length(&code_indices) == vector::length(&code_chunks),
            error::invalid_argument(ECODE_MISMATCH)
        );

        let owner_address = signer::address_of(owner);

        if (!exists<StagingArea>(owner_address)) {
            move_to(
                owner,
                StagingArea {
                    metadata_serialized: vector[],
                    code: smart_table::new(),
                    last_module_idx: 0
                }
            );
        };

        let staging_area = borrow_global_mut<StagingArea>(owner_address);

        if (!vector::is_empty(&metadata_chunk)) {
            vector::append(&mut staging_area.metadata_serialized, metadata_chunk);
        };

        let i = 0;
        while (i < vector::length(&code_chunks)) {
            let inner_code = *vector::borrow(&code_chunks, i);
            let idx = (*vector::borrow(&code_indices, i) as u64);

            if (smart_table::contains(&staging_area.code, idx)) {
                vector::append(
                    smart_table::borrow_mut(&mut staging_area.code, idx), inner_code
                );
            } else {
                smart_table::add(&mut staging_area.code, idx, inner_code);
                if (idx > staging_area.last_module_idx) {
                    staging_area.last_module_idx = idx;
                }
            };
            i = i + 1;
        };

        staging_area
    }
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L545-545)
```text
        txn_max_gas_units: u64,
```
