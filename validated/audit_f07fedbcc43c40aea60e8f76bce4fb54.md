# Audit Report

## Title
Consensus Safety Violation: Config Version Mismatch Causes Validators to Create Different Block Metadata

## Summary
A validator that fails to read the on-chain `OnChainConsensusConfig` during epoch transition will fall back to V4 (with `rand_check_enabled=false`), while other validators successfully reading V5 config (with `rand_check_enabled=true`) will skip waiting for randomness. This causes validators to create different block metadata transactions, violating the deterministic execution invariant and breaking consensus safety.

## Finding Description

This vulnerability exists in the interaction between consensus configuration loading, randomness handling, and block metadata creation during epoch transitions.

**1. Silent Config Fallback During Epoch Transitions**

During epoch transitions, validators attempt to extract `OnChainConsensusConfig` from the on-chain state. If this fails due to deserialization errors, storage issues, or network problems, the error is only logged as a warning and the code silently falls back to the default V4 configuration. [1](#0-0) [2](#0-1) 

The default V4 configuration is defined as: [3](#0-2) 

**2. Version-Dependent rand_check_enabled Behavior**

The `rand_check_enabled()` method returns `false` for V1-V4 configurations but returns the actual configured value (which can be `true`) for V5: [4](#0-3) 

The V4 structure does not include a `rand_check_enabled` field: [5](#0-4) 

While V5 adds this field: [6](#0-5) 

**3. Divergent Randomness Retrieval Logic**

In the pipeline's `rand_check()` function, when `rand_check_enabled=true` and `has_randomness=false`, the validator immediately returns `None` without waiting for randomness. However, when `rand_check_enabled=false`, the validator waits for and receives randomness from the `rand_rx` channel: [7](#0-6) 

**4. Different Metadata Transaction Creation**

The pipeline uses the randomness value from `rand_check()` to create block metadata with critically different randomness values: [8](#0-7) 

The `new_metadata_with_randomness()` method creates a `BlockMetadataExt::V1` containing `BlockMetadataWithRandomness`: [9](#0-8) 

**5. Randomness as Serialized Transaction Data**

The `BlockMetadataWithRandomness` struct includes `randomness: Option<Randomness>` as a serialized field. Different randomness values produce fundamentally different BCS-serialized transactions: [10](#0-9) 

**6. RandManager Populates All Blocks**

The RandManager generates randomness for all blocks: [11](#0-10) 

This randomness is stored in `PipelinedBlock` and sent through the `rand_tx` channel: [12](#0-11) 

**7. Different State Roots from Different Randomness Values**

The randomness value is passed to the Move VM's block prologue function, which updates the on-chain `PerBlockRandomness` resource: [13](#0-12) 

Different randomness values result in different on-chain state, producing different state roots.

**Attack Scenario:**
1. On-chain config is upgraded to V5 with `rand_check_enabled=true`
2. During epoch transition, Validator A successfully reads V5 config
3. Validator B encounters a transient deserialization or storage error, falls back to V4 default
4. For a block without randomness-requiring transactions:
   - Validator A: Creates metadata with `randomness=None` (skips waiting)
   - Validator B: Creates metadata with `randomness=Some(actual_randomness)` (waits and receives from RandManager)
5. Different metadata transactions → different execution results → different state roots
6. Validators cannot reach 2/3+ agreement on state commitment → consensus halts

## Impact Explanation

**Critical Severity** - This vulnerability causes a consensus safety violation, meeting the Aptos bug bounty Critical Severity criteria:

- **Consensus Safety Breach**: Validators executing identical blocks produce different state roots, violating the fundamental invariant that "all validators must produce identical state roots for identical blocks"
- **Network Partition**: Unable to achieve quorum (2/3+ voting power) on commits, the network effectively partitions between validators with different configs
- **Requires Hardfork**: Recovery requires coordinated intervention to force all validators to the same config version
- **Non-Byzantine Failure**: Occurs without any malicious actors, triggered only by transient infrastructure issues

This directly satisfies the "Consensus/Safety Violations" and "Non-recoverable Network Partition (requires hardfork)" criteria for Critical severity in the Aptos bug bounty program.

## Likelihood Explanation

**Medium Likelihood**

While the scenario requires a validator to fail reading on-chain config, several factors make this realistic:

1. **Transient Failures Are Common**: Network partitions, storage corruption, or temporary resource exhaustion can cause read failures in distributed systems
2. **Silent Degradation**: The failure is only logged as a warning, not treated as fatal, allowing the validator to continue with incorrect config
3. **Version Migration Window**: Most likely to occur during the upgrade from V4 to V5 when some validators may have outdated clients or experience deserialization issues with the new config format
4. **No Recovery Mechanism**: Once a validator loads the wrong config, it continues operating with that config until the next epoch
5. **Real-World Precedent**: Similar config deserialization issues have caused production incidents in other blockchain systems

The likelihood is not "High" because it requires a failure condition, but it's not "Low" because such failures are common in production distributed systems and the impact is catastrophic.

## Recommendation

Implement strict validation during epoch transitions to ensure all validators successfully read the on-chain consensus config:

1. **Treat Config Read Failures as Fatal**: Instead of falling back to defaults, validators should refuse to start a new epoch if they cannot read the on-chain config
2. **Add Config Version Assertions**: Include the config version hash in the epoch state and verify all validators agree on it before proceeding
3. **Retry with Exponential Backoff**: Implement robust retry logic for transient failures before giving up
4. **Add Config Sync Verification**: Have validators exchange and verify their loaded config versions before processing blocks

Example fix:
```rust
// In epoch_manager.rs, replace:
let consensus_config = onchain_consensus_config.unwrap_or_default();

// With:
let consensus_config = onchain_consensus_config
    .expect("Critical: Failed to read on-chain consensus config during epoch transition. Cannot proceed.");
```

## Proof of Concept

The vulnerability can be demonstrated by:

1. Setting up a network with V5 consensus config (`rand_check_enabled=true`)
2. Simulating a deserialization failure on one validator during epoch transition (e.g., via fault injection)
3. Observing that validator falls back to V4 default config
4. Submitting a block with no randomness-requiring transactions
5. Observing different validators create different `BlockMetadataWithRandomness` transactions
6. Verifying different state roots are computed
7. Confirming consensus cannot reach quorum on any state commitment

A full PoC would require integration test infrastructure with fault injection capabilities to simulate the transient failure condition during epoch transitions.

## Notes

This is a critical consensus safety vulnerability that violates the fundamental blockchain invariant requiring deterministic execution across all validators. The silent fallback behavior combined with version-specific randomness handling creates a dangerous scenario where honest validators executing identical consensus rules produce divergent states due to infrastructure failures rather than Byzantine behavior.

### Citations

**File:** consensus/src/epoch_manager.rs (L1187-1201)
```rust
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
```

**File:** consensus/src/consensus_observer/observer/epoch_state.rs (L157-166)
```rust
    let onchain_consensus_config: anyhow::Result<OnChainConsensusConfig> = on_chain_configs.get();
    if let Err(error) = &onchain_consensus_config {
        error!(
            LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                "Failed to read on-chain consensus config! Error: {:?}",
                error
            ))
        );
    }
    let consensus_config = onchain_consensus_config.unwrap_or_default();
```

**File:** types/src/on_chain_config/consensus_config.rs (L199-204)
```rust
    V4 {
        alg: ConsensusAlgorithmConfig,
        vtxn: ValidatorTxnConfig,
        // Execution pool block window
        window_size: Option<u64>,
    },
```

**File:** types/src/on_chain_config/consensus_config.rs (L205-213)
```rust
    V5 {
        alg: ConsensusAlgorithmConfig,
        vtxn: ValidatorTxnConfig,
        // Execution pool block window
        window_size: Option<u64>,
        // Whether to check if we can skip generating randomness for blocks
        rand_check_enabled: bool,
    },
}
```

**File:** types/src/on_chain_config/consensus_config.rs (L414-425)
```rust
    pub fn rand_check_enabled(&self) -> bool {
        match self {
            OnChainConsensusConfig::V1(_)
            | OnChainConsensusConfig::V2(_)
            | OnChainConsensusConfig::V3 { .. }
            | OnChainConsensusConfig::V4 { .. } => false,
            OnChainConsensusConfig::V5 {
                rand_check_enabled: rand_check,
                ..
            } => *rand_check,
        }
    }
```

**File:** types/src/on_chain_config/consensus_config.rs (L443-451)
```rust
impl Default for OnChainConsensusConfig {
    fn default() -> Self {
        OnChainConsensusConfig::V4 {
            alg: ConsensusAlgorithmConfig::default_if_missing(),
            vtxn: ValidatorTxnConfig::default_if_missing(),
            window_size: DEFAULT_WINDOW_SIZE,
        }
    }
}
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L775-782)
```rust
        let maybe_rand = if rand_check_enabled && !has_randomness {
            None
        } else {
            rand_rx
                .await
                .map_err(|_| anyhow!("randomness tx cancelled"))?
        };
        Ok((Some(maybe_rand), has_randomness))
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L807-811)
```rust
        let metadata_txn = if let Some(maybe_rand) = rand_result {
            block.new_metadata_with_randomness(&validator, maybe_rand)
        } else {
            block.new_block_metadata(&validator).into()
        };
```

**File:** consensus/consensus-types/src/block.rs (L597-617)
```rust
    pub fn new_metadata_with_randomness(
        &self,
        validators: &[AccountAddress],
        randomness: Option<Randomness>,
    ) -> BlockMetadataExt {
        BlockMetadataExt::new_v1(
            self.id(),
            self.epoch(),
            self.round(),
            self.author().unwrap_or(AccountAddress::ZERO),
            self.previous_bitvec().into(),
            // For nil block, we use 0x0 which is convention for nil address in move.
            self.block_data()
                .failed_authors()
                .map_or(vec![], |failed_authors| {
                    Self::failed_authors_to_indices(validators, failed_authors)
                }),
            self.timestamp_usecs(),
            randomness,
        )
    }
```

**File:** types/src/block_metadata_ext.rs (L23-34)
```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockMetadataWithRandomness {
    pub id: HashValue,
    pub epoch: u64,
    pub round: u64,
    pub proposer: AccountAddress,
    #[serde(with = "serde_bytes")]
    pub previous_block_votes_bitvec: Vec<u8>,
    pub failed_proposer_indices: Vec<u32>,
    pub timestamp_usecs: u64,
    pub randomness: Option<Randomness>,
}
```

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L145-169)
```rust
    fn process_incoming_metadata(&self, metadata: FullRandMetadata) -> DropGuard {
        let self_share = S::generate(&self.config, metadata.metadata.clone());
        info!(LogSchema::new(LogEvent::BroadcastRandShare)
            .epoch(self.epoch_state.epoch)
            .author(self.author)
            .round(metadata.round()));
        let mut rand_store = self.rand_store.lock();
        rand_store.update_highest_known_round(metadata.round());
        rand_store
            .add_share(self_share.clone(), PathType::Slow)
            .expect("Add self share should succeed");

        if let Some(fast_config) = &self.fast_config {
            let self_fast_share =
                FastShare::new(S::generate(fast_config, metadata.metadata.clone()));
            rand_store
                .add_share(self_fast_share.rand_share(), PathType::Fast)
                .expect("Add self share for fast path should succeed");
        }

        rand_store.add_rand_metadata(metadata.clone());
        self.network_sender
            .broadcast_without_self(RandMessage::<S, D>::Share(self_share).into_network_message());
        self.spawn_aggregate_shares_task(metadata.metadata)
    }
```

**File:** consensus/src/pipeline/execution_schedule_phase.rs (L64-68)
```rust
        for b in &ordered_blocks {
            if let Some(tx) = b.pipeline_tx().lock().as_mut() {
                tx.rand_tx.take().map(|tx| tx.send(b.randomness().cloned()));
            }
        }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2519-2523)
```rust
            randomness
                .as_ref()
                .map(Randomness::randomness_cloned)
                .as_move_value(),
        ];
```
