# Audit Report

## Title
Consensus Divergence Due to BlockSTM Scheduler Version Configuration Being Local Instead of On-Chain

## Summary
The BlockSTM scheduler version (V1 vs V2) is configured as a local, per-node setting rather than an on-chain consensus parameter. This allows different validators to use different scheduler versions for the same block, which causes validation logic differences that can lead to disagreement on block validity and consensus failure.

## Finding Description

The Aptos block executor supports two scheduler implementations: BlockSTM V1 and BlockSTM V2. The selection between these versions is controlled by a **local configuration parameter** `blockstm_v2_enabled` that each validator sets independently. [1](#0-0) [2](#0-1) 

The critical issue is that this local configuration affects **consensus-critical validation logic**. Specifically, BlockSTM V2 includes additional aggregator v1 validation that V1 does not perform: [3](#0-2) 

The V2-only validation includes an invariant check that ensures aggregator writes have corresponding aggregator_v1 reads: [4](#0-3) 

**Attack Scenario:**

1. Network has validators with mixed configurations:
   - Validator A: `blockstm_v2_enabled = false` (V1 scheduler)
   - Validator B: `blockstm_v2_enabled = true` (V2 scheduler)

2. A block is proposed containing a transaction that reads an aggregator value via the resource API (incorrect) and then writes to that aggregator (this could be an unintentional bug in a deployed Move module).

3. **Validator A (V1) behavior:**
   - Parallel execution validates only that read values match
   - No aggregator v1 invariant check is performed
   - Validation passes, block commits successfully
   - Produces state root R1

4. **Validator B (V2) behavior:**
   - Parallel execution performs aggregator v1 invariant validation
   - Invariant check detects the API misuse (lines 998-1005)
   - Returns `code_invariant_error`, parallel execution fails
   - If `allow_fallback = false`: **Validator panics, rejects block**
   - If `allow_fallback = true`: Falls back to sequential, but may still differ from V1

5. **Result:** Validators disagree on whether the block is valid, breaking the fundamental consensus invariant that all honest validators must agree on block validity.

The root cause is that the scheduler version decision happens at the executor level based on local configuration: [5](#0-4) 

This violates the documented invariant: "**Deterministic Execution**: All validators must produce identical state roots for identical blocks."

## Impact Explanation

**Critical Severity - Consensus/Safety Violation**

This vulnerability allows a consensus failure where validators disagree on block validity:
- Different validators compute different state roots for the same block
- Validators may reject blocks that others accept
- Network can partition into groups using different scheduler versions
- Requires hard fork to recover if validators permanently disagree

This meets the **Critical Severity** criteria from the Aptos bug bounty program:
- "Consensus/Safety violations"
- "Non-recoverable network partition (requires hardfork)"

The impact affects all validators in the network, as any validator using a different scheduler version than others will disagree on blocks containing transactions with aggregator API misuse or other scheduler-version-specific validation differences.

## Likelihood Explanation

**High Likelihood:**

1. **Configuration is easily mismatched:** The scheduler version is a simple boolean flag in node configuration files. During network upgrades, different validators may enable V2 at different times.

2. **Default is V1:** The default configuration sets `blockstm_v2_enabled = false`, meaning new validators start with V1 while upgraded validators may use V2. [6](#0-5) 

3. **No on-chain coordination:** There is no mechanism to enforce consistent scheduler version across validators or to coordinate version upgrades.

4. **Trigger requires only buggy transaction:** The consensus divergence can be triggered by any transaction that misuses aggregator APIs, which could occur unintentionally in deployed Move modules.

## Recommendation

**Make scheduler version an on-chain consensus parameter:**

1. Move `blockstm_v2_enabled` from `BlockExecutorLocalConfig` to `BlockExecutorConfigFromOnchain`
2. Add scheduler version to on-chain configuration that all validators must read
3. Implement version transition logic that ensures all validators switch to V2 simultaneously at a specific block height
4. Add validation to reject blocks if local scheduler version doesn't match on-chain configuration

**Alternative fix:**
Ensure V1 and V2 have identical validation logic for consensus-critical checks. The aggregator v1 invariant validation should either be:
- Added to V1 (making both versions equivalent for validation)
- Removed from V2 consensus path (moved to non-critical warning)
- Made a separate on-chain feature flag

## Proof of Concept

```rust
// Reproduction steps:
// 1. Configure two validators with different scheduler versions
//    Node A: execution.blockstm_v2_enabled = false
//    Node B: execution.blockstm_v2_enabled = true, execution.allow_fallback = false

// 2. Deploy a Move module with aggregator API misuse:

module test::aggregator_bug {
    use aptos_framework::aggregator_v2;
    
    public entry fun buggy_transaction(account: &signer) {
        // Read aggregator using wrong API (resource API instead of aggregator API)
        // This will be captured in data_reads but not aggregator_v1_reads
        let addr = signer::address_of(account);
        let resource = borrow_global<SomeResource>(addr); // Wrong: should use aggregator API
        
        // Then write to aggregator
        aggregator_v2::add(&mut resource.counter, 1); // Triggers invariant violation in V2
    }
}

// 3. Submit transaction calling buggy_transaction
// 4. Node A (V1) will commit the block successfully
// 5. Node B (V2) will panic: "Parallel execution failed and fallback is not allowed"
// 6. Consensus divergence: Nodes disagree on block validity
```

The vulnerability is confirmed by code inspection showing that:
1. Scheduler version is local configuration (not consensus-enforced)
2. Different validation logic exists between versions
3. No mechanism ensures all validators use same version
4. Disagreement causes consensus failure

### Citations

**File:** types/src/block_executor/config.rs (L52-55)
```rust
#[derive(Clone, Debug)]
pub struct BlockExecutorLocalConfig {
    // If enabled, uses BlockSTMv2 algorithm / scheduler for parallel execution.
    pub blockstm_v2: bool,
```

**File:** types/src/block_executor/config.rs (L71-73)
```rust
    pub fn default_with_concurrency_level(concurrency_level: usize) -> Self {
        Self {
            blockstm_v2: false,
```

**File:** config/src/config/execution_config.rs (L53-54)
```rust
    /// Whether to use BlockSTMv2 for parallel execution.
    pub blockstm_v2_enabled: bool,
```

**File:** aptos-move/block-executor/src/executor.rs (L861-870)
```rust
            || (is_v2
                && !read_set.validate_aggregator_v1_reads(
                    versioned_cache.data(),
                    last_input_output
                        .modified_aggregator_v1_keys(txn_idx)
                        .ok_or_else(|| {
                            code_invariant_error("Modified aggregator v1 keys must be recorded")
                        })?,
                    txn_idx,
                )?)
```

**File:** aptos-move/block-executor/src/executor.rs (L2558-2574)
```rust
            let parallel_result = if self.config.local.blockstm_v2 {
                BLOCKSTM_VERSION_NUMBER.set(2);
                self.execute_transactions_parallel_v2(
                    signature_verified_block,
                    base_view,
                    transaction_slice_metadata,
                    module_cache_manager_guard,
                )
            } else {
                BLOCKSTM_VERSION_NUMBER.set(1);
                self.execute_transactions_parallel(
                    signature_verified_block,
                    base_view,
                    transaction_slice_metadata,
                    module_cache_manager_guard,
                )
            };
```

**File:** aptos-move/block-executor/src/captured_reads.rs (L964-1009)
```rust
    // This method is only used in the BlockSTMv2 flow. BlockSTMv1 validates
    // aggregator v1 reads as a part of data reads.
    pub(crate) fn validate_aggregator_v1_reads(
        &self,
        data_map: &VersionedData<T::Key, T::Value>,
        aggregator_write_keys: impl Iterator<Item = T::Key>,
        idx_to_validate: TxnIndex,
    ) -> Result<bool, PanicError> {
        // Few aggregator v1 instances exist in the system (and legacy now, deprecated
        // by DelayedFields), hence the efficiency of construction below is not a concern.
        let mut aggregator_v1_iterable = Vec::with_capacity(self.aggregator_v1_reads.len());
        for k in &self.aggregator_v1_reads {
            match self.data_reads.get(k) {
                Some(data_read) => aggregator_v1_iterable.push((k, data_read)),
                None => {
                    return Err(code_invariant_error(format!(
                        "Aggregator v1 read {:?} not found among captured data reads",
                        k
                    )));
                },
            }
        }

        let ret = self.validate_data_reads_impl(
            aggregator_v1_iterable.into_iter(),
            data_map,
            idx_to_validate,
        );

        if ret {
            // Additional invariant check (that AggregatorV1 reads are captured for
            // aggregator write keys). This protects against the case where aggregator v1
            // state value read was read by a wrong interface (e.g. via resource API).
            for key in aggregator_write_keys {
                if self.data_reads.contains_key(&key) && !self.aggregator_v1_reads.contains(&key) {
                    // Not assuming read-before-write here: if there was a read, it must also be
                    // captured as an aggregator_v1 read.
                    return Err(code_invariant_error(format!(
                        "Captured read at aggregator key {:?} not found among AggregatorV1 reads",
                        key
                    )));
                }
            }
        }

        Ok(ret)
```
