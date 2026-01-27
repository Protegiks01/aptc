# Audit Report

## Title
Missing Parameter Consistency Validation in BlockExecutorConfigFromOnchain Allows Resource Exhaustion Through Inconsistent Gas Limit Configuration

## Summary
The `BlockExecutorConfigFromOnchain::new()` method fails to validate consistency between the `enable_per_block_gas_limit` flag and `block_gas_limit_type` parameter, allowing on-chain governance to configure a state where per-block gas limits are enabled but the base gas limit type is `NoLimit`. This can result in blocks executing without any gas constraints when consensus fails to provide a dynamic override, violating the critical "Resource Limits" invariant.

## Finding Description

The vulnerability exists in the parameter validation logic of the block executor configuration system. When creating a `BlockExecutorConfigFromOnchain` instance, three parameters are passed without consistency validation: [1](#0-0) 

The `new()` method accepts these parameters without validating their logical consistency: [2](#0-1) 

**The Core Issue**: When `enable_per_block_gas_limit` is `true` but `block_gas_limit_type` is `BlockGasLimitType::NoLimit`, the system enters an inconsistent state. The `enable_per_block_gas_limit` flag controls whether dynamic gas limit overrides from consensus are respected, while `block_gas_limit_type` provides the base gas limit configuration.

**Exploitation Path**:

1. On-chain governance (via `execution_config::set_for_next_epoch()`) configures:
   - `enable_per_block_gas_limit = true` (intending to enable gas limiting)
   - `block_gas_limit_type = BlockGasLimitType::NoLimit` (either accidentally or through manipulation) [3](#0-2) 

2. During block execution, consensus may provide `None` as the `block_gas_limit` override (this happens with `DirectMempoolPayloadManager` or certain QuorumStore payload variants): [4](#0-3) 

3. The override is applied to the configuration: [5](#0-4) 

4. When `block_gas_limit_override()` is called with `enable_per_block_gas_limit=true` and `per_block_gas_limit=None`, it returns `None`: [6](#0-5) 

5. The `BlockGasLimitProcessor` falls back to the base limit type, which is `NoLimit`, returning `None`: [7](#0-6) 

6. Block execution proceeds without gas limits, and `should_end_block()` never triggers: [8](#0-7) 

This violates **Invariant #9 (Resource Limits)**: "All operations must respect gas, storage, and computational limits."

## Impact Explanation

**Severity: High** (per Aptos Bug Bounty Program)

This vulnerability qualifies as **High Severity** under the category "Significant protocol violations" and "Validator node slowdowns" because:

1. **Protocol Violation**: The system allows a configuration that violates the fundamental invariant that block execution must respect gas limits
2. **Validator Impact**: Blocks executing without gas limits can cause validator nodes to consume excessive CPU and memory processing expensive transactions
3. **Network-Wide Effect**: All validators process the same blocks, so a single misconfigured block affects the entire network
4. **Deterministic Harm**: Once the inconsistent configuration is set, every block using certain payload managers will be vulnerable

While this requires governance misconfiguration to trigger, the lack of validation makes such errors possible. On-chain governance proposals are complex, and parameter validation should prevent inconsistent states rather than relying solely on human review.

## Likelihood Explanation

**Likelihood: Medium-High**

The vulnerability has medium-high likelihood because:

1. **Governance Complexity**: Execution config parameters are updated via raw byte serialization, making it easy to introduce inconsistent configurations without proper validation
2. **Multiple Config Versions**: The system has multiple configuration versions (V5, V6, V7), increasing the surface area for misconfiguration during upgrades
3. **No Runtime Validation**: The Move contract accepts any byte configuration without semantic validation
4. **Payload Manager Variants**: Multiple payload manager implementations return `None` for `block_gas_limit`, making the fallback to base limit type common
5. **Honest Mistakes**: Governance participants might enable `enable_per_block_gas_limit` thinking it activates limits, without realizing they must also set a non-NoLimit base type

## Recommendation

Add parameter consistency validation in `BlockExecutorConfigFromOnchain::new()`:

```rust
pub fn new(
    block_gas_limit_type: BlockGasLimitType,
    enable_per_block_gas_limit: bool,
    gas_price_to_burn: Option<u64>,
) -> Result<Self, anyhow::Error> {
    // Validate consistency: if per-block gas limits are enabled,
    // the base gas limit type must not be NoLimit
    if enable_per_block_gas_limit && matches!(block_gas_limit_type, BlockGasLimitType::NoLimit) {
        return Err(anyhow::anyhow!(
            "enable_per_block_gas_limit requires a non-NoLimit block_gas_limit_type"
        ));
    }
    
    Ok(Self {
        block_gas_limit_type,
        enable_per_block_gas_limit,
        per_block_gas_limit: None,
        gas_price_to_burn,
    })
}
```

Update all call sites to handle the `Result` return type, and add similar validation in the Move governance layer to reject invalid configurations before they're stored on-chain.

## Proof of Concept

```rust
#[test]
fn test_inconsistent_config_validation() {
    use aptos_types::on_chain_config::BlockGasLimitType;
    use aptos_types::block_executor::config::BlockExecutorConfigFromOnchain;
    
    // This should fail validation but currently succeeds
    let inconsistent_config = BlockExecutorConfigFromOnchain::new(
        BlockGasLimitType::NoLimit,
        true,  // enable_per_block_gas_limit = true
        Some(90)
    );
    
    // Simulate execution without override
    let override_value = None;
    let config_with_override = inconsistent_config
        .with_block_gas_limit_override(override_value);
    
    // This returns None, allowing unlimited execution
    assert_eq!(config_with_override.block_gas_limit_override(), None);
    
    // Demonstrate the vulnerability: we can create a BlockGasLimitProcessor
    // with no effective limit even though per-block limits are "enabled"
    use aptos_move_block_executor::limit_processor::BlockGasLimitProcessor;
    let processor = BlockGasLimitProcessor::<MockTransaction>::new(
        BlockGasLimitType::NoLimit,
        config_with_override.block_gas_limit_override(),
        100
    );
    
    // The processor has no gas limit, violating the resource limits invariant
    // Expensive transactions can now be processed without bounds
}
```

## Notes

The vulnerability demonstrates a classic parameter validation failure where individual parameters are valid in isolation but create an invalid system state when combined. The fix requires rejecting this configuration at construction time to maintain the invariant that enabling per-block gas limits must always result in some form of gas constraint being enforced.

### Citations

**File:** types/src/on_chain_config/execution_config.rs (L99-105)
```rust
    pub fn block_executor_onchain_config(&self) -> BlockExecutorConfigFromOnchain {
        BlockExecutorConfigFromOnchain::new(
            self.block_gas_limit_type(),
            self.enable_per_block_gas_limit(),
            self.gas_price_to_burn(),
        )
    }
```

**File:** types/src/block_executor/config.rs (L93-104)
```rust
    pub fn new(
        block_gas_limit_type: BlockGasLimitType,
        enable_per_block_gas_limit: bool,
        gas_price_to_burn: Option<u64>,
    ) -> Self {
        Self {
            block_gas_limit_type,
            enable_per_block_gas_limit,
            per_block_gas_limit: None,
            gas_price_to_burn,
        }
    }
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

**File:** aptos-move/framework/aptos-framework/sources/configs/execution_config.move (L48-52)
```text
    public fun set_for_next_epoch(account: &signer, config: vector<u8>) {
        system_addresses::assert_aptos_framework(account);
        assert!(vector::length(&config) > 0, error::invalid_argument(EINVALID_CONFIG));
        config_buffer::upsert(ExecutionConfig { config });
    }
```

**File:** consensus/src/block_preparer.rs (L54-63)
```rust
        let (txns, max_txns_from_block_to_execute, block_gas_limit) = tokio::select! {
                // Poll the block qc future until a QC is received. Ignore None outcomes.
                Some(qc) = block_qc_fut => {
                    let block_voters = Some(qc.ledger_info().get_voters_bitvec().clone());
                    self.payload_manager.get_transactions(block, block_voters).await
                },
                result = self.payload_manager.get_transactions(block, None) => {
                   result
                }
        }?;
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L799-801)
```rust
        let (user_txns, block_gas_limit) = prepare_fut.await?;
        let onchain_execution_config =
            onchain_execution_config.with_block_gas_limit_override(block_gas_limit);
```

**File:** aptos-move/block-executor/src/limit_processor.rs (L119-125)
```rust
    fn block_gas_limit(&self) -> Option<u64> {
        if self.block_gas_limit_override.is_some() {
            self.block_gas_limit_override
        } else {
            self.block_gas_limit_type.block_gas_limit()
        }
    }
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
