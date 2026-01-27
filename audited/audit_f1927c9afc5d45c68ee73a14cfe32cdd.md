# Audit Report

## Title
Consensus Divergence Due to Local Configuration Control of Block Execution Failure Handling

## Summary
The `discard_failed_blocks` configuration parameter is a **local, per-node setting** that controls whether failed block executions are discarded or cause errors. Different validators can have different values for this setting, causing consensus divergence when code invariant errors occur during block execution. Validators with `discard_failed_blocks=true` will produce valid blocks (with all transactions discarded), while validators with `discard_failed_blocks=false` will fail to produce blocks, breaking the "Deterministic Execution" invariant. [1](#0-0) 

## Finding Description

When `code_invariant_error()` is triggered during parallel execution (e.g., from the `DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR` status code), BlockSTM falls back to sequential execution. If sequential execution also fails with the same error, the behavior diverges based on the **local node configuration**: [2](#0-1) 

The critical issue is that `discard_failed_blocks` is defined in `BlockExecutorLocalConfig` (marked as "Local, per-node configuration"), NOT in `BlockExecutorConfigFromOnchain` (which is "required to be the same across all nodes"): [3](#0-2) 

The configuration flow shows this is set from individual node configurations: [4](#0-3) [5](#0-4) [6](#0-5) 

**Attack Scenario:**
1. A block contains transactions that trigger code invariant errors during execution (e.g., due to delayed field bugs or BlockSTM race conditions)
2. All validators' parallel execution fails and falls back to sequential
3. Sequential execution also fails with `DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR`
4. **Validator A** (configured with `discard_failed_blocks=true`): Returns `Ok(BlockOutput)` with all transactions marked as discarded - **produces state root SA**
5. **Validator B** (configured with `discard_failed_blocks=false`): Returns `Err(BlockExecutionError)` - **cannot produce a block**
6. Consensus breaks because validators cannot agree on the block outcome

## Impact Explanation

**Critical Severity** - This is a **Consensus/Safety violation** as defined in the Aptos bug bounty program. When validators have different `discard_failed_blocks` settings and a code invariant error occurs:

- Validators that can produce blocks (with discarded transactions) will vote to commit
- Validators that cannot produce blocks will not vote or will vote differently
- This breaks the fundamental invariant: "All validators must produce identical state roots for identical blocks"
- The network could experience liveness failure or chain splits requiring intervention

The impact is amplified because:
1. Code invariant errors can be triggered by subtle timing issues in parallel execution
2. Node operators may unknowingly configure this setting differently
3. The default value is `false`, but some validators may enable it for "robustness"

## Likelihood Explanation

**High Likelihood** because:

1. **Configuration Variance is Expected**: Different node operators independently configure their validators. There's no enforcement that `discard_failed_blocks` must be uniform across all validators.

2. **Code Invariant Errors Can Occur**: The codebase explicitly handles these errors, indicating they are anticipated scenarios (e.g., from delayed field operations, BlockSTM race conditions, or resource group serialization failures). [7](#0-6) 

3. **No Warning in Documentation**: The configuration system does not warn operators that this local setting affects global consensus behavior.

## Recommendation

**Fix: Convert `discard_failed_blocks` to an on-chain configuration parameter**

Move `discard_failed_blocks` from `BlockExecutorLocalConfig` to `BlockExecutorConfigFromOnchain` so all validators must use the same value:

```rust
// In types/src/block_executor/config.rs

#[derive(Clone, Debug)]
pub struct BlockExecutorLocalConfig {
    pub blockstm_v2: bool,
    pub concurrency_level: usize,
    pub allow_fallback: bool,
    // REMOVE: pub discard_failed_blocks: bool,  
    pub module_cache_config: BlockExecutorModuleCacheLocalConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlockExecutorConfigFromOnchain {
    pub block_gas_limit_type: BlockGasLimitType,
    enable_per_block_gas_limit: bool,
    per_block_gas_limit: Option<u64>,
    gas_price_to_burn: Option<u64>,
    // ADD: Consensus-critical parameter
    pub discard_failed_blocks: bool,
}
```

Alternatively, **enforce uniform configuration** through consensus configuration validation, ensuring all validators have the same `discard_failed_blocks` value before participating in consensus.

## Proof of Concept

```rust
// Conceptual PoC - demonstrates the divergence

// Validator Node A configuration (node_config_a.yaml):
// execution:
//   discard_failed_blocks: true

// Validator Node B configuration (node_config_b.yaml):
// execution:
//   discard_failed_blocks: false

// When a block with code invariant errors is executed:

// On Validator A:
let config_a = BlockExecutorConfig {
    local: BlockExecutorLocalConfig {
        discard_failed_blocks: true,  // From local config
        // ... other fields
    },
    // ...
};
// Result: Ok(BlockOutput { transactions: [all discarded], ... })
// State root: Hash(empty block with error statuses)

// On Validator B:
let config_b = BlockExecutorConfig {
    local: BlockExecutorLocalConfig {
        discard_failed_blocks: false,  // From local config
        // ... other fields
    },
    // ...
};
// Result: Err(BlockExecutionError::FatalBlockExecutorError(...))
// Cannot produce state root - execution failed

// Consensus divergence:
// - Validator A: votes to commit block with state root SA
// - Validator B: cannot vote or votes nil (no valid block)
// - Network splits or stalls
```

## Notes

This vulnerability exists because the execution layer's failure handling policy (`discard_failed_blocks`) was implemented as a local optimization/robustness feature without considering its impact on consensus determinism. Any local configuration that affects block execution outcomes must be consensus-critical and enforced uniformly across all validators.

The issue is exacerbated by the hardcoded `allow_fallback: true` setting, which ensures all validators attempt the fallback path, but then diverge based on their local `discard_failed_blocks` configuration when that fallback also fails. [8](#0-7)

### Citations

**File:** types/src/block_executor/config.rs (L51-64)
```rust
/// Local, per-node configuration.
#[derive(Clone, Debug)]
pub struct BlockExecutorLocalConfig {
    // If enabled, uses BlockSTMv2 algorithm / scheduler for parallel execution.
    pub blockstm_v2: bool,
    pub concurrency_level: usize,
    // If specified, parallel execution fallbacks to sequential, if issue occurs.
    // Otherwise, if there is an error in either of the execution, we will panic.
    pub allow_fallback: bool,
    // If true, we will discard the failed blocks and continue with the next block.
    // (allow_fallback needs to be set)
    pub discard_failed_blocks: bool,
    pub module_cache_config: BlockExecutorModuleCacheLocalConfig,
}
```

**File:** types/src/block_executor/config.rs (L82-90)
```rust
/// Configuration from on-chain configuration, that is
/// required to be the same across all nodes.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlockExecutorConfigFromOnchain {
    pub block_gas_limit_type: BlockGasLimitType,
    enable_per_block_gas_limit: bool,
    per_block_gas_limit: Option<u64>,
    gas_price_to_burn: Option<u64>,
}
```

**File:** aptos-move/block-executor/src/executor.rs (L2250-2257)
```rust
                ExecutionStatus::DelayedFieldsCodeInvariantError(msg) => {
                    if let Some(commit_hook) = &self.transaction_commit_hook {
                        commit_hook.on_execution_aborted(idx as TxnIndex);
                    }
                    alert!("Sequential execution DelayedFieldsCodeInvariantError error by transaction {}: {}", idx as TxnIndex, msg);
                    return Err(SequentialBlockExecutionError::ErrorToReturn(
                        BlockExecutionError::FatalBlockExecutorError(code_invariant_error(msg)),
                    ));
```

**File:** aptos-move/block-executor/src/executor.rs (L2648-2666)
```rust
        if self.config.local.discard_failed_blocks {
            // We cannot execute block, discard everything (including block metadata and validator transactions)
            // (TODO: maybe we should add fallback here to first try BlockMetadataTransaction alone)
            let error_code = match sequential_error {
                BlockExecutionError::FatalBlockExecutorError(_) => {
                    StatusCode::DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR
                },
                BlockExecutionError::FatalVMError(_) => {
                    StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR
                },
            };
            let ret = (0..signature_verified_block.num_txns())
                .map(|_| E::Output::discard_output(error_code))
                .collect();
            return Ok(BlockOutput::new(ret, None));
        }

        Err(sequential_error)
    }
```

**File:** config/src/config/execution_config.rs (L45-46)
```rust
    /// Enabled discarding blocks that fail execution due to BlockSTM/VM issue.
    pub discard_failed_blocks: bool,
```

**File:** aptos-node/src/utils.rs (L62-63)
```rust
    AptosVM::set_concurrency_level_once(effective_concurrency_level as usize);
    AptosVM::set_discard_failed_blocks(node_config.execution.discard_failed_blocks);
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3110-3119)
```rust
        let config = BlockExecutorConfig {
            local: BlockExecutorLocalConfig {
                blockstm_v2: AptosVM::get_blockstm_v2_enabled(),
                concurrency_level: AptosVM::get_concurrency_level(),
                allow_fallback: true,
                discard_failed_blocks: AptosVM::get_discard_failed_blocks(),
                module_cache_config: BlockExecutorModuleCacheLocalConfig::default(),
            },
            onchain: onchain_config,
        };
```
