# Audit Report

## Title
Consensus Safety Violation: ExecutionConfig Version Deserialization Failure Causes Silent Fallback to Incompatible Defaults

## Summary
When validators running different code versions attempt to deserialize an on-chain `ExecutionConfig` during epoch transitions, nodes with older code that cannot deserialize newer config versions silently fall back to the `Missing` variant with incompatible default values. This causes different validators to execute blocks with different transaction ordering parameters, producing divergent state roots and breaking consensus safety.

## Finding Description

The `OnChainExecutionConfig` enum uses versioned structs (V1 through V7) with the `Missing` variant positioned between V3 and V4 for backwards compatibility: [1](#0-0) 

During epoch transitions, consensus extracts the execution config from on-chain state by calling `payload.get()`: [2](#0-1) 

When BCS deserialization fails (e.g., old node encounters V7 variant index), the code logs a warning but continues execution: [3](#0-2) 

It then falls back to the `Missing` configuration using `default_if_missing()`: [4](#0-3) 

The `default_if_missing()` method returns the `Missing` enum variant: [5](#0-4) 

**The Critical Problem**: The `Missing` variant provides fundamentally different execution parameters. For transaction shuffling, it returns `NoShuffling`: [6](#0-5) 

Meanwhile, V7 configs (and the default for genesis) use `UseCaseAware` shuffling: [7](#0-6) 

**Consensus Divergence Path**:

When a block is inserted into the block store, ALL validators (not just the proposer) build an execution pipeline for that block: [8](#0-7) 

The pipeline's `prepare_block()` step shuffles transactions based on the configured shuffler: [9](#0-8) 

The shuffler type is determined by `create_transaction_shuffler()` which returns either `NoOpShuffler` (for NoShuffling) or `UseCaseAwareShuffler` (for UseCaseAware): [10](#0-9) 

**Why This Breaks Consensus**: BlockSTM requires transactions to be executed in a preset serialization order, and this input order determines the final state root: [11](#0-10) [12](#0-11) 

When validators shuffle transactions differently (NoOpShuffler vs UseCaseAwareShuffler), they provide different input orders to BlockSTM, resulting in different state roots. This violates the fundamental consensus invariant that all honest validators must agree on state transitions.

**BCS Deserialization Behavior**: BCS cannot deserialize enum variants with unknown variant indices. The codebase search confirms that when a variant tag exceeds the known variants, deserialization fails with an error, forcing the fallback to `Missing`.

## Impact Explanation

**Severity: CRITICAL** (Aptos Bug Bounty: up to $1,000,000)

This vulnerability meets multiple Critical severity criteria:

1. **Consensus/Safety Violations**: Different validators produce different state roots for identical block inputs, violating the fundamental deterministic execution invariant that underpins AptosBFT safety guarantees. Validators cannot form quorum certificates when they disagree on state roots.

2. **Non-recoverable Network Partition**: Once validators diverge on execution parameters, they cannot reconcile without manual intervention. The network splits into incompatible factions (old validators with `Missing` config vs. new validators with V7 config) that cannot reach consensus. This requires a hardfork to resolve.

3. **Network Availability**: If >1/3 of validators are on old code, consensus cannot make progress. If both factions have significant stake, the network experiences a permanent split with competing chains.

4. **User Fund Safety**: Transactions may be confirmed on one fork but not the other, leading to double-spend scenarios or fund loss during reconciliation.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability triggers automatically during normal network operations:

1. **Trigger Condition**: Governance upgrades ExecutionConfig to a version unknown to some validators. This is the standard process for introducing new execution features.

2. **Inevitability**: The vulnerability manifests during ANY ExecutionConfig version upgrade where validators haven't all upgraded their code simultaneously. Rolling upgrades are operationally necessary for large validator sets.

3. **No Attacker Required**: This is a deployment bug in the protocol itself, not an attack requiring malicious intent.

4. **No Special Privileges**: The normal governance process (which validator operators participate in) triggers the vulnerability.

The only ways to avoid this are: (a) require 100% validator code upgrades before governance proposals, which is operationally impractical and slows network evolution, or (b) never upgrade ExecutionConfig versions, which prevents the network from adopting new features.

## Recommendation

Implement a version compatibility check in the execution config deserialization path:

1. **Add explicit version negotiation**: Before falling back to `Missing`, check if the on-chain config version exceeds the node's known version. If so, halt the node with a clear error message requiring an upgrade, rather than silently using incompatible defaults.

2. **Add on-chain version checks**: Modify the Move governance module to verify that validator versions are compatible with the proposed ExecutionConfig version before allowing the proposal to pass.

3. **Add version advertisement**: Have validators advertise their supported ExecutionConfig versions during epoch transitions, and prevent epoch changes if incompatible versions are detected.

4. **Graceful degradation**: If backward compatibility is required, ensure that `Missing` provides execution parameters that are provably compatible with all versioned configs (e.g., by using the lowest-common-denominator approach for all parameters).

Example fix for immediate mitigation:

```rust
// In consensus/src/epoch_manager.rs, around line 1191-1203
if let Err(error) = &onchain_execution_config {
    error!(
        "CRITICAL: Failed to deserialize ExecutionConfig: {}. \
        This indicates the on-chain config version is newer than this node supports. \
        The node MUST be upgraded before continuing to avoid consensus divergence.",
        error
    );
    // Halt the node rather than continuing with incompatible defaults
    panic!("ExecutionConfig version incompatibility detected - upgrade required");
}
```

## Proof of Concept

The vulnerability can be demonstrated through the following scenario:

1. Deploy a network with validators running code that only knows V1-V6 enum variants
2. Submit a governance proposal to update ExecutionConfig to V7 with UseCaseAware shuffling
3. Observe that validators fail to deserialize with error logged at line 1192
4. Observe fallback to `Missing` at line 1203
5. Insert a test block and observe different validators calling different shufflers
6. Verify that validators produce different state roots for the same block
7. Confirm that consensus cannot form quorum certificates

While a full working PoC would require a multi-validator testnet setup, the code path is deterministic and the vulnerability is evident from the code structure documented above with precise citations.

### Citations

**File:** types/src/on_chain_config/execution_config.rs (L12-24)
```rust
pub enum OnChainExecutionConfig {
    V1(ExecutionConfigV1),
    V2(ExecutionConfigV2),
    V3(ExecutionConfigV3),
    /// To maintain backwards compatibility on replay, we must ensure that any new features resolve
    /// to previous behavior (before OnChainExecutionConfig was registered) in case of Missing.
    Missing,
    // Reminder: Add V4 and future versions here, after Missing (order matters for enums).
    V4(ExecutionConfigV4),
    V5(ExecutionConfigV5),
    V6(ExecutionConfigV6),
    V7(ExecutionConfigV7),
}
```

**File:** types/src/on_chain_config/execution_config.rs (L29-40)
```rust
    pub fn transaction_shuffler_type(&self) -> TransactionShufflerType {
        match &self {
            OnChainExecutionConfig::Missing => TransactionShufflerType::NoShuffling,
            OnChainExecutionConfig::V1(config) => config.transaction_shuffler_type.clone(),
            OnChainExecutionConfig::V2(config) => config.transaction_shuffler_type.clone(),
            OnChainExecutionConfig::V3(config) => config.transaction_shuffler_type.clone(),
            OnChainExecutionConfig::V4(config) => config.transaction_shuffler_type.clone(),
            OnChainExecutionConfig::V5(config) => config.transaction_shuffler_type.clone(),
            OnChainExecutionConfig::V6(config) => config.transaction_shuffler_type.clone(),
            OnChainExecutionConfig::V7(config) => config.transaction_shuffler_type.clone(),
        }
    }
```

**File:** types/src/on_chain_config/execution_config.rs (L124-133)
```rust
    pub fn default_for_genesis() -> Self {
        OnChainExecutionConfig::V7(ExecutionConfigV7 {
            transaction_shuffler_type: TransactionShufflerType::default_for_genesis(),
            block_gas_limit_type: BlockGasLimitType::default_for_genesis(),
            enable_per_block_gas_limit: false,
            transaction_deduper_type: TransactionDeduperType::TxnHashAndAuthenticatorV1,
            gas_price_to_burn: 90,
            persisted_auxiliary_info_version: 1,
        })
    }
```

**File:** types/src/on_chain_config/execution_config.rs (L137-139)
```rust
    pub fn default_if_missing() -> Self {
        OnChainExecutionConfig::Missing
    }
```

**File:** consensus/src/epoch_manager.rs (L1179-1179)
```rust
        let onchain_execution_config: anyhow::Result<OnChainExecutionConfig> = payload.get();
```

**File:** consensus/src/epoch_manager.rs (L1191-1193)
```rust
        if let Err(error) = &onchain_execution_config {
            warn!("Failed to read on-chain execution config {}", error);
        }
```

**File:** consensus/src/epoch_manager.rs (L1202-1203)
```rust
        let execution_config = onchain_execution_config
            .unwrap_or_else(|_| OnChainExecutionConfig::default_if_missing());
```

**File:** consensus/src/block_storage/block_store.rs (L490-496)
```rust
            pipeline_builder.build_for_consensus(
                &pipelined_block,
                parent_block.pipeline_futs().ok_or_else(|| {
                    anyhow::anyhow!("Parent future doesn't exist, potentially epoch ended")
                })?,
                callback,
            );
```

**File:** consensus/src/block_preparer.rs (L100-104)
```rust
            let mut shuffled_txns = {
                let _timer = TXN_SHUFFLE_SECONDS.start_timer();

                txn_shuffler.shuffle(deduped_txns)
            };
```

**File:** consensus/src/transaction_shuffler/mod.rs (L69-99)
```rust
    match shuffler_type {
        NoShuffling => {
            info!("Using no-op transaction shuffling");
            Arc::new(NoOpShuffler {})
        },
        DeprecatedSenderAwareV1(_) => {
            info!("Using no-op sender aware shuffling v1");
            Arc::new(NoOpShuffler {})
        },
        SenderAwareV2(_) => {
            unreachable!("SenderAware shuffler is no longer supported.")
        },
        DeprecatedFairness => {
            unreachable!("DeprecatedFairness shuffler is no longer supported.")
        },
        UseCaseAware {
            sender_spread_factor,
            platform_use_case_spread_factor,
            user_use_case_spread_factor,
        } => {
            let config = use_case_aware::Config {
                sender_spread_factor,
                platform_use_case_spread_factor,
                user_use_case_spread_factor,
            };
            info!(
                config = ?config,
                "Using use case aware transaction shuffling."
            );
            Arc::new(use_case_aware::UseCaseAwareShuffler { config })
        },
```

**File:** aptos-move/block-executor/src/lib.rs (L4-8)
```rust
/**
The high level parallel execution logic is implemented in 'executor.rs'. The
input of parallel executor is a block of transactions, containing a sequence
of n transactions tx_1, tx_2, ..., tx_n (this defines the preset serialization
order tx_1< tx_2< ...<tx_n).
```

**File:** aptos-move/block-executor/src/lib.rs (L57-58)
```rust
preset serialization order dictates that the transactions must be committed in
order, a successful validation of an incarnation does not guarantee that it can
```
