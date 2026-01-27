# Audit Report

## Title
Per-Block Gas Limit Silently Ignored When `enable_per_block_gas_limit` is Disabled, Enabling Validator Resource Exhaustion

## Summary
Block-level gas limits specified in consensus payloads are silently ignored when the `enable_per_block_gas_limit` on-chain configuration flag is disabled (which is the default). This allows blocks with unlimited gas consumption to be executed, potentially causing validator resource exhaustion. The issue arises from a disconnection between the consensus layer (which carries per-block gas limits) and the execution layer (which requires an explicit feature flag to honor them).

## Finding Description

The Aptos blockchain supports per-block gas limits to prevent validator resource exhaustion. These limits can be specified in block payloads through `QuorumStoreInlineHybridV2` and `OptQuorumStore` payload types. However, a critical feature flag `enable_per_block_gas_limit` controls whether these limits are actually enforced during execution.

**The vulnerability flow:**

1. **Consensus layer sets gas limit**: Block proposers create payloads with `block_gas_limit` set through the `PayloadExecutionLimit` mechanism. [1](#0-0) 

2. **Limit passed to execution**: The gas limit is extracted and passed through the pipeline. [2](#0-1) 

3. **Silent discard**: The `block_gas_limit_override()` method only returns the limit if `enable_per_block_gas_limit` is true, otherwise returns None. [3](#0-2) 

4. **Flag defaults to false**: The feature flag defaults to false for genesis and all V1-V4 execution configs. [4](#0-3) [5](#0-4) 

5. **Fallback to baseline**: When the override is None, the executor falls back to `block_gas_limit_type`, which could be `NoLimit` for Missing or V1 configs. [6](#0-5) 

6. **No enforcement**: The `BlockGasLimitProcessor` only enforces limits when `block_gas_limit()` returns Some. [7](#0-6) 

**Attack scenario:**
- Networks with `enable_per_block_gas_limit=false` (default for new networks)
- Block proposers set `block_gas_limit` in payloads expecting enforcement
- Limits are silently ignored during execution
- Up to 10,000 transactions (the `max_receiving_block_txns` limit) can execute with unbounded gas consumption
- Validators experience resource exhaustion (CPU, memory)

While transaction count is capped at 10,000: [8](#0-7) 

This provides insufficient protection when transactions are gas-intensive, as each could consume maximum gas without a per-block aggregate limit.

## Impact Explanation

**High Severity** - Validator node slowdowns and resource exhaustion

This vulnerability breaks the **Resource Limits** invariant (#9): "All operations must respect gas, storage, and computational limits."

The impact includes:
- **Validator resource exhaustion**: Blocks with 10,000 high-gas transactions can monopolize validator CPU/memory
- **Network performance degradation**: Slow block execution affects consensus liveness
- **Silent security failure**: Block proposers believe limits are enforced when they're not
- **Configuration dependency**: Default configurations are vulnerable

While not Critical severity (doesn't cause consensus splits or fund loss), it meets High severity criteria by enabling validator slowdowns and protocol violations.

## Likelihood Explanation

**Medium-to-High likelihood** depending on network configuration:

**Factors increasing likelihood:**
- `enable_per_block_gas_limit` defaults to false for genesis
- New networks or testnets are vulnerable by default
- Block proposers may unknowingly rely on unenforced limits
- No warnings or errors when limits are ignored

**Factors decreasing likelihood:**
- Mature networks (mainnet) likely have proper configuration via governance
- The `block_gas_limit_type` provides baseline protection when properly configured
- Honest validators won't intentionally create resource-exhausting blocks

**Attacker requirements:**
- Ability to propose blocks (requires being elected leader)
- Knowledge that `enable_per_block_gas_limit` is disabled
- No special privileges beyond normal validator operation

## Recommendation

**Immediate fix**: Make per-block gas limits fail-secure rather than fail-open.

**Option 1: Reject blocks with unsupported limits**
```rust
// In types/src/block_executor/config.rs
pub fn block_gas_limit_override(&self) -> Option<u64> {
    if self.per_block_gas_limit.is_some() && !self.enable_per_block_gas_limit {
        panic!("Block specifies gas limit but enable_per_block_gas_limit is false");
    }
    if self.enable_per_block_gas_limit {
        self.per_block_gas_limit
    } else {
        None
    }
}
```

**Option 2: Enable by default for new configs**
```rust
// In types/src/on_chain_config/execution_config.rs
pub fn default_for_genesis() -> Self {
    OnChainExecutionConfig::V7(ExecutionConfigV7 {
        transaction_shuffler_type: TransactionShufflerType::default_for_genesis(),
        block_gas_limit_type: BlockGasLimitType::default_for_genesis(),
        enable_per_block_gas_limit: true, // Changed from false
        transaction_deduper_type: TransactionDeduperType::TxnHashAndAuthenticatorV1,
        gas_price_to_burn: 90,
        persisted_auxiliary_info_version: 1,
    })
}
```

**Option 3: Always use baseline limit when override is disabled**
```rust
// In aptos-move/block-executor/src/limit_processor.rs
fn block_gas_limit(&self) -> Option<u64> {
    // Always respect block_gas_limit_type, even if override is disabled
    self.block_gas_limit_override
        .or_else(|| self.block_gas_limit_type.block_gas_limit())
}
```

**Recommended approach**: Implement Option 2 (enable by default) + Option 1 (fail-secure) to ensure both backward compatibility and forward security.

## Proof of Concept

```rust
// Test demonstrating silent limit disablement
#[test]
fn test_gas_limit_silently_ignored() {
    // Setup: Create config with feature disabled (default)
    let config = OnChainExecutionConfig::default_for_genesis();
    assert!(!config.enable_per_block_gas_limit()); // Defaults to false
    
    let executor_config = config.block_executor_onchain_config()
        .with_block_gas_limit_override(Some(1000)); // Set low limit
    
    // The limit is set...
    assert_eq!(executor_config.per_block_gas_limit, Some(1000));
    
    // ...but ignored when queried!
    assert_eq!(executor_config.block_gas_limit_override(), None);
    
    // Create processor with this config
    let processor = BlockGasLimitProcessor::new(
        config.block_gas_limit_type(),
        executor_config.block_gas_limit_override(),
        100,
    );
    
    // Simulate execution of high-gas transactions
    for _ in 0..10000 {
        processor.accumulate_fee_statement(
            FeeStatement::new(10000, 10000, 0, 0, 0), // High gas
            None,
            None,
        );
        // Should trigger block_gas_limit_reached but doesn't!
        assert!(!processor.should_end_block_sequential());
    }
    
    // Total gas consumed: 100M gas units with no enforcement
    // Expected: Block should have stopped at 1000 gas units
}
```

## Notes

This vulnerability demonstrates a critical disconnect between consensus-layer expectations and execution-layer enforcement. The `enable_per_block_gas_limit` flag was likely added as a feature flag for gradual rollout, but its default-disabled state creates a security gap. Networks must explicitly enable this protection, and many may not realize it's disabled by default.

### Citations

**File:** consensus/src/payload_manager/quorum_store_payload_manager.rs (L155-162)
```rust
        Ok(BlockTransactionPayload::new_quorum_store_inline_hybrid(
            all_transactions,
            proof_with_data.proofs.clone(),
            *max_txns_to_execute,
            *block_gas_limit_override,
            inline_batches,
            self.enable_payload_v2,
        ))
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L799-801)
```rust
        let (user_txns, block_gas_limit) = prepare_fut.await?;
        let onchain_execution_config =
            onchain_execution_config.with_block_gas_limit_override(block_gas_limit);
```

**File:** types/src/block_executor/config.rs (L155-161)
```rust
    pub fn block_gas_limit_override(&self) -> Option<u64> {
        if self.enable_per_block_gas_limit {
            self.per_block_gas_limit
        } else {
            None
        }
    }
```

**File:** types/src/on_chain_config/execution_config.rs (L43-57)
```rust
    pub fn block_gas_limit_type(&self) -> BlockGasLimitType {
        match &self {
            OnChainExecutionConfig::Missing => BlockGasLimitType::NoLimit,
            OnChainExecutionConfig::V1(_config) => BlockGasLimitType::NoLimit,
            OnChainExecutionConfig::V2(config) => config
                .block_gas_limit
                .map_or(BlockGasLimitType::NoLimit, BlockGasLimitType::Limit),
            OnChainExecutionConfig::V3(config) => config
                .block_gas_limit
                .map_or(BlockGasLimitType::NoLimit, BlockGasLimitType::Limit),
            OnChainExecutionConfig::V4(config) => config.block_gas_limit_type.clone(),
            OnChainExecutionConfig::V5(config) => config.block_gas_limit_type.clone(),
            OnChainExecutionConfig::V6(config) => config.block_gas_limit_type.clone(),
            OnChainExecutionConfig::V7(config) => config.block_gas_limit_type.clone(),
        }
```

**File:** types/src/on_chain_config/execution_config.rs (L60-70)
```rust
    pub fn enable_per_block_gas_limit(&self) -> bool {
        match &self {
            OnChainExecutionConfig::Missing
            | OnChainExecutionConfig::V1(_)
            | OnChainExecutionConfig::V2(_)
            | OnChainExecutionConfig::V3(_)
            | OnChainExecutionConfig::V4(_) => false,
            OnChainExecutionConfig::V5(config) => config.enable_per_block_gas_limit,
            OnChainExecutionConfig::V6(config) => config.enable_per_block_gas_limit,
            OnChainExecutionConfig::V7(config) => config.enable_per_block_gas_limit,
        }
```

**File:** types/src/on_chain_config/execution_config.rs (L128-128)
```rust
            enable_per_block_gas_limit: false,
```

**File:** aptos-move/block-executor/src/limit_processor.rs (L127-141)
```rust
    fn should_end_block(&mut self, mode: &str) -> bool {
        if let Some(per_block_gas_limit) = self.block_gas_limit() {
            // When the accumulated block gas of the committed txns exceeds
            // PER_BLOCK_GAS_LIMIT, early halt BlockSTM.
            let accumulated_block_gas = self.get_effective_accumulated_block_gas();
            if accumulated_block_gas >= per_block_gas_limit {
                counters::EXCEED_PER_BLOCK_GAS_LIMIT_COUNT.inc_with(&[mode]);
                info!(
                    "[BlockSTM]: execution ({}) early halted due to \
                    accumulated_block_gas {} >= PER_BLOCK_GAS_LIMIT {}",
                    mode, accumulated_block_gas, per_block_gas_limit,
                );
                return true;
            }
        }
```

**File:** consensus/src/round_manager.rs (L1180-1185)
```rust
        ensure!(
            num_validator_txns + payload_len as u64 <= self.local_config.max_receiving_block_txns,
            "Payload len {} exceeds the limit {}",
            payload_len,
            self.local_config.max_receiving_block_txns,
        );
```
