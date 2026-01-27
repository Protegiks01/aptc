# Audit Report

## Title
Silent Disabling of Critical Block Gas Limits Due to Fallback to Missing Execution Config

## Summary
When on-chain execution configuration fails to load during epoch transitions, both the consensus observer and main consensus epoch manager silently fall back to `OnChainExecutionConfig::Missing`, which disables all per-block gas limits and output size restrictions. This creates a critical consensus safety risk where nodes with different config load success rates could execute blocks differently, leading to state divergence.

## Finding Description

The vulnerability exists in two critical code paths that handle epoch configuration:

**Consensus Observer Path:** [1](#0-0) 

**Main Consensus Epoch Manager Path:** [2](#0-1) 

When `OnChainExecutionConfig` extraction fails, both code paths use `unwrap_or_else(|_| OnChainExecutionConfig::default_if_missing())`, which returns the `Missing` variant. This variant is designed for backwards compatibility but has dangerous security implications: [3](#0-2) 

When queried, the `Missing` variant returns security-critical defaults that disable protections: [4](#0-3) [5](#0-4) 

The `BlockGasLimitType::NoLimit` setting causes all gas limit checks to be bypassed in the block executor: [6](#0-5) [7](#0-6) 

The configuration flows through the execution pipeline where it's used to create the block executor config: [8](#0-7) [9](#0-8) 

This configuration is then used during block execution to enforce limits: [10](#0-9) [11](#0-10) 

**Failure Scenarios:**

The deserialization can fail due to: [12](#0-11) 

Failures occur when:
1. BCS deserialization errors (corrupted data, incompatible version updates)
2. On-chain config resource not yet initialized during network upgrades
3. Database corruption or read failures
4. State sync issues during node startup

**Consensus Safety Violation:**

If different nodes experience different config load outcomes:
- **Node A** successfully loads config → enforces gas limits → halts block after limit
- **Node B** fails to load config → no limits → executes entire block
- **Result:** Different state roots for identical blocks → consensus split → chain fork

This violates the fundamental **Deterministic Execution** invariant.

## Impact Explanation

**Critical Severity - Consensus Safety Violation**

This vulnerability meets **Critical** severity criteria under the Aptos Bug Bounty program:
- **Consensus/Safety violations**: Different nodes can produce different state roots for the same block
- **Non-recoverable network partition**: State divergence would require hardfork to resolve

The impact is severe because:

1. **Silent Failure**: Only logged as warning, no fail-safe mechanism
2. **Security Feature Bypass**: Disables block gas limits, block output limits, and gas burning
3. **Resource Exhaustion**: Blocks could contain unlimited transactions leading to memory exhaustion
4. **Consensus Split Risk**: Non-deterministic execution across the network
5. **Systemic Issue**: Affects both consensus observers and validator nodes

The vulnerability enables:
- Blocks with arbitrarily many transactions (only limited by per-tx gas, not per-block)
- Excessive state growth and storage exhaustion
- Block execution times that exceed consensus timeouts
- Different nodes reaching different conclusions about block validity

## Likelihood Explanation

**Medium-High Likelihood**

While direct exploitation by external attackers is difficult, the vulnerability can trigger through:

1. **Network Upgrades**: When execution config format changes, nodes with different code versions may deserialize differently
2. **State Sync Issues**: Nodes joining or catching up may process reconfig events before state is fully synced
3. **Database Corruption**: Local storage issues can cause config read failures on specific nodes
4. **Race Conditions**: During epoch transitions, timing differences could cause inconsistent config states

The likelihood is elevated because:
- The pattern appears in TWO critical paths (consensus observer and epoch manager)
- Only requires partial network inconsistency, not majority
- Silent failure mode means operators won't detect the issue until consensus breaks
- Historical precedent: blockchain networks have experienced config-related forks

## Recommendation

**Immediate Fix:**

Replace silent fallback with fail-safe behavior that halts the node rather than proceeding with disabled security features:

```rust
// In epoch_state.rs and epoch_manager.rs
let execution_config = onchain_execution_config
    .expect("CRITICAL: Failed to load on-chain execution config. Node must halt to prevent consensus inconsistency.");
```

**Defense-in-Depth Improvements:**

1. **Validation Layer**: Add explicit validation that execution config is not `Missing` after epoch start
2. **Consensus Check**: Include execution config hash in block proposals to detect mismatches
3. **Monitoring**: Add metrics/alerts when default configs are used
4. **Graceful Degradation**: If fallback is required, use safe defaults with strict limits rather than `NoLimit`

**Alternative Safe Default:**

```rust
pub fn safe_fallback_for_emergency() -> Self {
    OnChainExecutionConfig::V7(ExecutionConfigV7 {
        transaction_shuffler_type: TransactionShufflerType::NoShuffling,
        block_gas_limit_type: BlockGasLimitType::ComplexLimitV1 {
            effective_block_gas_limit: 10000, // Conservative emergency limit
            execution_gas_effective_multiplier: 1,
            io_gas_effective_multiplier: 1,
            conflict_penalty_window: 1,
            use_granular_resource_group_conflicts: false,
            use_module_publishing_block_conflict: false,
            block_output_limit: Some(1_000_000), // 1MB emergency limit
            include_user_txn_size_in_block_output: true,
            add_block_limit_outcome_onchain: false,
        },
        enable_per_block_gas_limit: true,
        transaction_deduper_type: TransactionDeduperType::TxnHashAndAuthenticatorV1,
        gas_price_to_burn: 90,
        persisted_auxiliary_info_version: 0,
    })
}
```

## Proof of Concept

**Scenario: Config Deserialization Failure Leading to Consensus Split**

```rust
// Test demonstrating the vulnerability
#[test]
fn test_execution_config_failure_causes_nolimit() {
    use aptos_types::on_chain_config::{OnChainExecutionConfig, BlockGasLimitType};
    
    // Simulate config load failure
    let config_result: Result<OnChainExecutionConfig, anyhow::Error> = 
        Err(anyhow::anyhow!("Simulated deserialization failure"));
    
    // Current vulnerable code path
    let execution_config = config_result
        .unwrap_or_else(|_| OnChainExecutionConfig::default_if_missing());
    
    // Verify security features are disabled
    assert_eq!(execution_config.block_gas_limit_type(), BlockGasLimitType::NoLimit);
    assert_eq!(execution_config.enable_per_block_gas_limit(), false);
    assert_eq!(execution_config.block_gas_limit_type().block_gas_limit(), None);
    assert_eq!(execution_config.block_gas_limit_type().block_output_limit(), None);
    
    // This configuration allows unlimited block execution
    // If Node A has proper config and Node B has Missing config,
    // they will disagree on when to stop block execution
    println!("CRITICAL: Block gas limits are completely disabled!");
}
```

**Consensus Split Scenario:**

1. Network performs governance upgrade to modify execution config
2. Config is stored with new serialization format (e.g., V7 → V8)
3. Some validators have updated code, others running older version
4. Older validators fail deserialization → fall back to `Missing` → `NoLimit`
5. Newer validators successfully load config → enforce limits
6. Block proposer creates block with 1000 transactions (exceeding limit)
7. **Node A (new)**: Executes 500 txns, hits gas limit, produces state root X
8. **Node B (old)**: Executes all 1000 txns, produces state root Y
9. **Result**: X ≠ Y → Consensus failure → Chain fork

## Notes

The root cause is a design anti-pattern where **backwards compatibility** (`default_if_missing()`) is prioritized over **security** and **determinism**. The `Missing` variant was intended for replay compatibility but creates a dangerous failure mode during live operation.

The vulnerability is particularly insidious because:
- Errors are only logged as warnings, not surfaced as critical failures
- The system appears to continue operating normally
- Consensus breaks only manifest when blocks exceed limits on some nodes but not others
- No automatic recovery mechanism exists

This represents a systemic risk requiring immediate remediation before it can cause production network disruption.

### Citations

**File:** consensus/src/consensus_observer/observer/epoch_state.rs (L168-179)
```rust
    // Extract the execution config (or use the default if it's missing)
    let onchain_execution_config: anyhow::Result<OnChainExecutionConfig> = on_chain_configs.get();
    if let Err(error) = &onchain_execution_config {
        error!(
            LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                "Failed to read on-chain execution config! Error: {:?}",
                error
            ))
        );
    }
    let execution_config =
        onchain_execution_config.unwrap_or_else(|_| OnChainExecutionConfig::default_if_missing());
```

**File:** consensus/src/epoch_manager.rs (L1179-1203)
```rust
        let onchain_execution_config: anyhow::Result<OnChainExecutionConfig> = payload.get();
        let onchain_randomness_config_seq_num: anyhow::Result<RandomnessConfigSeqNum> =
            payload.get();
        let randomness_config_move_struct: anyhow::Result<RandomnessConfigMoveStruct> =
            payload.get();
        let onchain_jwk_consensus_config: anyhow::Result<OnChainJWKConsensusConfig> = payload.get();
        let dkg_state = payload.get::<DKGState>();

        if let Err(error) = &onchain_consensus_config {
            warn!("Failed to read on-chain consensus config {}", error);
        }

        if let Err(error) = &onchain_execution_config {
            warn!("Failed to read on-chain execution config {}", error);
        }

        if let Err(error) = &randomness_config_move_struct {
            warn!("Failed to read on-chain randomness config {}", error);
        }

        self.epoch_state = Some(epoch_state.clone());

        let consensus_config = onchain_consensus_config.unwrap_or_default();
        let execution_config = onchain_execution_config
            .unwrap_or_else(|_| OnChainExecutionConfig::default_if_missing());
```

**File:** types/src/on_chain_config/execution_config.rs (L43-58)
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
    }
```

**File:** types/src/on_chain_config/execution_config.rs (L60-71)
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
    }
```

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

**File:** types/src/on_chain_config/execution_config.rs (L137-139)
```rust
    pub fn default_if_missing() -> Self {
        OnChainExecutionConfig::Missing
    }
```

**File:** types/src/on_chain_config/execution_config.rs (L169-173)
```rust
    fn deserialize_into_config(bytes: &[u8]) -> Result<Self> {
        let raw_bytes: Vec<u8> = bcs::from_bytes(bytes)?;
        bcs::from_bytes(&raw_bytes)
            .map_err(|e| format_err!("[on-chain config] Failed to deserialize into config: {}", e))
    }
```

**File:** types/src/on_chain_config/execution_config.rs (L316-325)
```rust
    pub fn block_gas_limit(&self) -> Option<u64> {
        match self {
            BlockGasLimitType::NoLimit => None,
            BlockGasLimitType::Limit(limit) => Some(*limit),
            BlockGasLimitType::ComplexLimitV1 {
                effective_block_gas_limit,
                ..
            } => Some(*effective_block_gas_limit),
        }
    }
```

**File:** aptos-move/block-executor/src/limit_processor.rs (L127-157)
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

        if let Some(per_block_output_limit) = self.block_gas_limit_type.block_output_limit() {
            let accumulated_output = self.get_accumulated_approx_output_size();
            if accumulated_output >= per_block_output_limit {
                counters::EXCEED_PER_BLOCK_OUTPUT_LIMIT_COUNT.inc_with(&[mode]);
                info!(
                    "[BlockSTM]: execution ({}) early halted due to \
                    accumulated_output {} >= PER_BLOCK_OUTPUT_LIMIT {}",
                    mode, accumulated_output, per_block_output_limit,
                );
                return true;
            }
        }

        false
    }
```

**File:** consensus/src/pipeline/execution_client.rs (L560-563)
```rust
        let transaction_shuffler =
            create_transaction_shuffler(onchain_execution_config.transaction_shuffler_type());
        let block_executor_onchain_config: aptos_types::block_executor::config::BlockExecutorConfigFromOnchain =
            onchain_execution_config.block_executor_onchain_config();
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L787-802)
```rust
    async fn execute(
        prepare_fut: TaskFuture<PrepareResult>,
        parent_block_execute_fut: TaskFuture<ExecuteResult>,
        rand_check: TaskFuture<RandResult>,
        executor: Arc<dyn BlockExecutorTrait>,
        block: Arc<Block>,
        validator: Arc<[AccountAddress]>,
        onchain_execution_config: BlockExecutorConfigFromOnchain,
        persisted_auxiliary_info_version: u8,
    ) -> TaskResult<ExecuteResult> {
        let mut tracker = Tracker::start_waiting("execute", &block);
        parent_block_execute_fut.await?;
        let (user_txns, block_gas_limit) = prepare_fut.await?;
        let onchain_execution_config =
            onchain_execution_config.with_block_gas_limit_override(block_gas_limit);

```

**File:** consensus/src/pipeline/pipeline_builder.rs (L856-868)
```rust
        let start = Instant::now();
        tokio::task::spawn_blocking(move || {
            executor
                .execute_and_update_state(
                    (block.id(), txns, auxiliary_info).into(),
                    block.parent_id(),
                    onchain_execution_config,
                )
                .map_err(anyhow::Error::from)
        })
        .await
        .expect("spawn blocking failed")?;
        Ok(start.elapsed())
```
