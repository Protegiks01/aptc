# Audit Report

## Title
Consensus Split Due to Config Version Deserialization Mismatch in `block_gas_limit_type()`

## Summary
A critical consensus vulnerability exists where validators running different software versions deserialize the same on-chain execution config differently, causing divergent block gas limit enforcement and network partition. When a governance proposal upgrades `OnChainExecutionConfig` from V3 to V4+, validators with older binaries fail BCS deserialization and silently fall back to `Missing` variant (returning `NoLimit`), while upgraded validators correctly parse the config with specific gas limits. This causes different validators to execute different numbers of transactions from the same proposed block, producing different state roots and triggering a consensus split.

## Finding Description

The vulnerability exists in the interaction between Rust enum versioning and BCS deserialization for the `OnChainExecutionConfig` type. The enum defines variants V1 through V7, with `Missing` placed between V3 and V4 for backwards compatibility. [1](#0-0) 

When validators with old binaries (compiled with V1-V3 enum definition) attempt to deserialize a V4+ config, BCS deserialization fails because the variant index doesn't exist in their compiled code. The error is caught and the system falls back to the `Missing` variant. [2](#0-1) 

The same fallback pattern occurs in the consensus observer. [3](#0-2) 

The `default_if_missing()` method explicitly returns the `Missing` variant. [4](#0-3) 

The `block_gas_limit_type()` method returns different values based on the config version. For `Missing`, it returns `NoLimit`. For V4-V7, it returns the actual configured `block_gas_limit_type` value. [5](#0-4) 

This config is extracted once at epoch start and cached for the entire epoch. [6](#0-5) 

The `BlockGasLimitProcessor` uses this configuration to determine when to halt block execution. When the gas limit is reached during transaction execution, it sets remaining transactions to `SkipRest` status, preventing their execution. [7](#0-6) 

The `should_end_block_parallel()` method checks if accumulated gas exceeds the limit. For `NoLimit`, the check returns false and all transactions execute. For `ComplexLimitV1` with a specific limit, the check returns true when the limit is reached. [8](#0-7) 

**Attack Scenario:**
1. Network operates with V3 config, all validators synchronized
2. Governance proposal upgrades to V4 with `ComplexLimitV1 { effective_block_gas_limit: 20000, ... }`
3. 70% of validators upgrade their software to support V4 parsing
4. 30% of validators haven't upgraded yet
5. New epoch activates, config is cached per-validator
6. Block proposed with 100 transactions totaling 40,000 gas:
   - **Upgraded validators**: Parse V4 successfully, `BlockGasLimitProcessor` stops execution at transaction 50 (when 20,000 gas reached), compute state root X
   - **Old validators**: Fail to parse V4, fall back to `Missing` → `NoLimit`, execute all 100 transactions, compute state root Y
7. X ≠ Y → Consensus split, network partition

## Impact Explanation

**Critical Severity** - This vulnerability meets the "Consensus/Safety Violations" category for critical impact:

- **Different validators compute different state roots for identical blocks**: The fundamental consensus invariant is violated because validators execute different numbers of transactions from the same proposed block
- **Non-recoverable network partition**: The network splits into two incompatible chains (one following upgraded validators, one following old validators)
- **Requires hardfork to resolve**: Manual intervention is needed to reconcile the split and restore consensus
- **Total loss of liveness**: If neither partition achieves 2f+1 voting power, the entire network halts indefinitely

This directly matches the Aptos bug bounty program's highest severity category (up to $1,000,000) for consensus/safety violations where chain splits occur without requiring >1/3 Byzantine validators.

## Likelihood Explanation

**High Likelihood** - This will occur whenever:

1. A governance proposal upgrades `OnChainExecutionConfig` to V4, V5, V6, or V7
2. Not all validators have upgraded their software binaries to understand the new enum variants
3. The new config version includes `BlockGasLimitType::ComplexLimitV1` with specific limits (default for genesis is 20,000 gas)

This is not theoretical - validator software upgrades are coordinated but imperfect in operational reality. Validators may lag behind for legitimate reasons: testing periods, deployment schedules, operational procedures, or unforeseen issues. The default genesis configuration uses V7 with `ComplexLimitV1`. [9](#0-8) 

**No safeguards exist**: The governance proposal validation only checks that the config value is correctly written to blockchain state, not that all validators can deserialize it. [10](#0-9) 

## Recommendation

Implement validator binary version compatibility checks before allowing config upgrades:

1. **Add version compatibility validation**: Before applying a new `OnChainExecutionConfig` version, validate that all active validators are running binaries that support the new enum variant
2. **Explicit version requirements**: Store minimum required binary version for each config version in the on-chain config
3. **Fail-fast on deserialization**: Instead of silently falling back to `Missing`, validators should halt and alert operators when they cannot deserialize the on-chain config
4. **Coordinated upgrades**: Require 100% validator upgrade confirmation before activating new config versions through governance

Example fix for the deserialization error handling:
```rust
// Instead of silent fallback:
let execution_config = onchain_execution_config
    .unwrap_or_else(|_| OnChainExecutionConfig::default_if_missing());

// Use fail-fast:
let execution_config = onchain_execution_config
    .expect("CRITICAL: Cannot deserialize OnChainExecutionConfig - binary upgrade required");
```

## Proof of Concept

The vulnerability can be demonstrated by:

1. Starting a local testnet with validators running V3-compatible binaries
2. Submitting a governance proposal to upgrade to V4 with `ComplexLimitV1 { effective_block_gas_limit: 20000, ... }`
3. Upgrading only 70% of validator binaries to V4-compatible versions
4. Proposing a block with 100 transactions totaling 40,000 gas
5. Observing that upgraded validators execute 50 transactions while old validators execute all 100
6. Verifying different state roots and consensus failure

Test configuration showing V4 usage: [11](#0-10) 

The block executor initializes the gas limit processor with the cached config: [12](#0-11) 

## Notes

This vulnerability is particularly dangerous because:
- The fallback to `Missing` is silent (only logs a warning)
- It manifests at epoch boundaries when configs are cached
- No mechanism exists to detect the mismatch before consensus splits
- V4+ configs are actively used in production (default_for_genesis returns V7)
- The impact is immediate and requires hardfork to recover

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

**File:** types/src/on_chain_config/execution_config.rs (L122-133)
```rust
    /// The default values to use for new networks, e.g., devnet, forge.
    /// Features that are ready for deployment can be enabled here.
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

**File:** consensus/src/consensus_observer/observer/epoch_state.rs (L169-179)
```rust
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

**File:** consensus/src/pipeline/execution_client.rs (L560-580)
```rust
        let transaction_shuffler =
            create_transaction_shuffler(onchain_execution_config.transaction_shuffler_type());
        let block_executor_onchain_config: aptos_types::block_executor::config::BlockExecutorConfigFromOnchain =
            onchain_execution_config.block_executor_onchain_config();
        let transaction_deduper =
            create_transaction_deduper(onchain_execution_config.transaction_deduper_type());
        let randomness_enabled = onchain_consensus_config.is_vtxn_enabled()
            && onchain_randomness_config.randomness_enabled();

        let aux_version = onchain_execution_config.persisted_auxiliary_info_version();

        self.execution_proxy.new_epoch(
            &epoch_state,
            payload_manager,
            transaction_shuffler,
            block_executor_onchain_config,
            transaction_deduper,
            randomness_enabled,
            onchain_consensus_config.clone(),
            aux_version,
            network_sender,
```

**File:** aptos-move/block-executor/src/txn_last_input_output.rs (L362-372)
```rust
        if txn_idx < num_txns - 1
            && block_limit_processor.should_end_block_parallel()
            && !skips_rest
        {
            if output_wrapper.output_status_kind == OutputStatusKind::Success {
                must_create_epilogue_txn |= !output_before_guard.has_new_epoch_event();
                drop(output_before_guard);
                output_wrapper.output_status_kind = OutputStatusKind::SkipRest;
            }
            skips_rest = true;
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

**File:** aptos-move/aptos-release-builder/src/components/mod.rs (L504-508)
```rust
            ReleaseEntry::Execution(execution_config) => {
                if !wait_until_equals(client_opt, execution_config, *MAX_ASYNC_RECONFIG_TIME) {
                    bail!("Consensus config mismatch: Expected {:?}", execution_config);
                }
            },
```

**File:** testsuite/smoke-test/src/execution.rs (L114-127)
```rust
async fn block_epilogue_upgrade_test() {
    let (swarm, mut cli, _faucet) = SwarmBuilder::new_local(2)
        .with_aptos()
        // Start with V1
        .with_init_genesis_config(Arc::new(|genesis_config| {
            genesis_config.execution_config = OnChainExecutionConfig::V4(ExecutionConfigV4 {
                transaction_shuffler_type: TransactionShufflerType::NoShuffling,
                block_gas_limit_type: BlockGasLimitType::NoLimit,
                transaction_deduper_type: TransactionDeduperType::TxnHashAndAuthenticatorV1,
            });
        }))
        .build_with_cli(0)
        .await;

```

**File:** aptos-move/block-executor/src/executor.rs (L1726-1730)
```rust
        let block_limit_processor = ExplicitSyncWrapper::new(BlockGasLimitProcessor::new(
            self.config.onchain.block_gas_limit_type.clone(),
            self.config.onchain.block_gas_limit_override(),
            num_txns,
        ));
```
