# Audit Report

## Title
Consensus Divergence via Configuration-Dependent Error Handling in Block Execution

## Summary

The `discard_failed_blocks` configuration flag creates a critical consensus divergence vulnerability. When block execution fails, validators with different configuration values produce different execution outcomes—some successfully executing the block with discarded transactions, others rejecting it with errors. This breaks deterministic execution and can cause consensus failure or network fork.

## Finding Description

The vulnerability exists in the block executor's error handling logic, specifically in how it processes execution failures based on local node configuration.

**The Core Issue:**

The `discard_failed_blocks` boolean is a **local per-node configuration** (not from on-chain config) that determines block execution error handling behavior: [1](#0-0) [2](#0-1) 

This configuration flows through the system: [3](#0-2) [4](#0-3) [5](#0-4) 

**The Divergent Execution Paths:**

When both parallel and sequential block execution fail, the block executor checks this configuration: [6](#0-5) 

- **Path 1** (`discard_failed_blocks = true`): Returns `Ok(BlockOutput)` where all transactions are marked with `Discard` status and assigned error codes
- **Path 2** (`discard_failed_blocks = false`): Returns `Err(sequential_error)` causing block execution to fail

**Consensus Impact:**

The discarded transactions are separated from committed transactions: [7](#0-6) [8](#0-7) 

Only transactions in `to_commit` are included in the transaction accumulator hash, which becomes the `executed_state_id` used in consensus voting: [9](#0-8) 

**Result:** Validators with different configurations produce:
1. Different execution statuses (Success vs. Error)
2. Different state roots (different `to_commit` transaction sets)
3. Different vote data for the same block

This violates the **Deterministic Execution** invariant: "All validators must produce identical state roots for identical blocks."

## Impact Explanation

**Critical Severity** - Consensus/Safety Violation (up to $1,000,000 per Aptos bug bounty):

1. **Consensus Safety Break**: Validators cannot reach agreement on block execution results when they have different configurations, directly violating BFT consensus assumptions.

2. **Network Partition Risk**: 
   - If < 1/3 validators are misconfigured: Those validators cannot participate, reducing network resilience
   - If ≥ 1/3 validators are misconfigured: Complete consensus halt
   - If configurations are split ~50/50: Risk of network fork with different state roots

3. **Breaks Core Invariant**: Violates Invariant #1 (Deterministic Execution) - the foundational requirement that all honest validators must produce identical results for identical inputs.

4. **No Attacker Resources Required**: Exploitation only requires:
   - Configuration asymmetry between validators (can occur through misconfiguration, rolling updates, or network issues)
   - Triggering execution errors (via naturally occurring errors or crafted transactions causing BlockSTM issues)

## Likelihood Explanation

**High Likelihood** in production environments:

1. **Configuration Drift**: Validators may have different configurations due to:
   - Staggered software updates
   - Manual configuration differences
   - Recovery from failures with different configs
   - Testing enabled on some validators

2. **Natural Trigger Conditions**: Block execution errors can occur naturally through:
   - BlockSTM incarnation threshold violations
   - Resource group serialization errors  
   - VM invariant violations
   - Code invariant errors during complex transactions

3. **Attackers Can Force Errors**: Sophisticated attackers can craft transaction patterns that trigger BlockSTM execution failures without requiring validator access.

4. **Silent Failure Mode**: The misconfiguration may not be immediately apparent until an execution error occurs, making it a latent vulnerability.

## Recommendation

**Immediate Fix**: Remove the local configuration option and enforce uniform error handling across all validators.

```rust
// In types/src/block_executor/config.rs
pub struct BlockExecutorLocalConfig {
    pub blockstm_v2: bool,
    pub concurrency_level: usize,
    pub allow_fallback: bool,
    // REMOVE: pub discard_failed_blocks: bool,
    pub module_cache_config: BlockExecutorModuleCacheLocalConfig,
}
```

**Alternative Approaches** (if discard functionality is needed):

1. **Move to On-Chain Configuration**: Make `discard_failed_blocks` part of `BlockExecutorConfigFromOnchain` so all validators must use the same value: [10](#0-9) 

2. **Disable for Consensus Execution**: Only allow discarding in non-consensus contexts (replay, state sync), never during normal block processing:

```rust
if self.config.local.discard_failed_blocks && !is_consensus_block {
    // discard logic
} else {
    Err(sequential_error)
}
```

3. **Explicit Protocol Version**: Tie the behavior to a feature flag that requires on-chain governance activation, ensuring network-wide coordination.

## Proof of Concept

**Rust Reproduction Steps:**

1. Configure two validator nodes with different settings:
   ```yaml
   # Validator A (validator_a.yaml)
   execution:
     discard_failed_blocks: true
   
   # Validator B (validator_b.yaml)  
   execution:
     discard_failed_blocks: false
   ```

2. Deploy a transaction sequence that triggers BlockSTM execution errors (e.g., high-contention transactions causing incarnation threshold violations)

3. Observe the execution results:
   - Validator A: Executes block successfully, all transactions discarded with error codes
   - Validator B: Block execution fails with `ExecutorError`

4. Check vote data:
   - Validator A: Votes on block with state root from empty/minimal `to_commit`
   - Validator B: Does not vote (execution failed)

5. Result: Consensus cannot reach quorum agreement on this block

**Expected Behavior**: All validators should handle execution errors identically, either all discarding or all failing, based on network-wide coordinated configuration.

**Notes:**

The vulnerability is particularly insidious because:
- It's a **latent configuration issue** that only manifests when execution errors occur
- It affects **consensus safety**, not just liveness
- It can be triggered **without privileged access** through carefully crafted transactions
- Detection requires comparing execution results across validators during error conditions

### Citations

**File:** config/src/config/execution_config.rs (L46-46)
```rust
    pub discard_failed_blocks: bool,
```

**File:** config/src/config/execution_config.rs (L88-88)
```rust
            discard_failed_blocks: false,
```

**File:** aptos-node/src/utils.rs (L63-63)
```rust
    AptosVM::set_discard_failed_blocks(node_config.execution.discard_failed_blocks);
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L471-482)
```rust
    pub fn set_discard_failed_blocks(enable: bool) {
        // Only the first call succeeds, due to OnceCell semantics.
        DISCARD_FAILED_BLOCKS.set(enable).ok();
    }

    /// Get the discard failed blocks flag if already set, otherwise return default (false)
    pub fn get_discard_failed_blocks() -> bool {
        match DISCARD_FAILED_BLOCKS.get() {
            Some(enable) => *enable,
            None => false,
        }
    }
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

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L373-377)
```rust
        let (to_retry, to_discard) = Self::extract_retries_and_discards(
            &mut transactions,
            &mut transaction_outputs,
            &mut persisted_auxiliary_infos,
        );
```

**File:** execution/executor-types/src/execution_output.rs (L157-160)
```rust
    // List of all transactions to be committed, including StateCheckpoint/BlockEpilogue if needed.
    pub to_commit: TransactionsToKeep,
    pub to_discard: TransactionsWithOutput,
    pub to_retry: TransactionsWithOutput,
```

**File:** execution/executor-types/src/state_compute_result.rs (L87-89)
```rust
    pub fn root_hash(&self) -> HashValue {
        self.ledger_update_output.transaction_accumulator.root_hash
    }
```

**File:** types/src/block_executor/config.rs (L84-90)
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlockExecutorConfigFromOnchain {
    pub block_gas_limit_type: BlockGasLimitType,
    enable_per_block_gas_limit: bool,
    per_block_gas_limit: Option<u64>,
    gas_price_to_burn: Option<u64>,
}
```
