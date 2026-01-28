# Audit Report

## Title
Consensus Split via Randomness Configuration Divergence Leading to Non-Deterministic Block Execution

## Summary
Validators with divergent `randomness_override_seq_num` configurations execute identical blocks with different transaction types (`BlockMetadata` vs `BlockMetadataExt`), producing distinct state roots that break consensus safety and cause network partition.

## Finding Description

The `randomness_override_seq_num` parameter in `NodeConfig` creates a consensus safety violation through a fundamental design flaw: it allows **local configuration to override consensus-critical execution behavior** without any cross-validator validation. [1](#0-0) 

**Attack Flow:**

1. **Configuration Divergence**: During emergency randomness stall recovery, the documented procedure instructs validators to set `randomness_override_seq_num = X+1`. [2](#0-1)  If validators set different values due to miscommunication, partial rollouts, or typos, they enter divergent states.

2. **Independent Override Check**: At epoch start, each validator independently evaluates whether to disable randomness: [3](#0-2) 

3. **Divergent Randomness Configuration**: The `from_configs()` method returns `Off` if the local override exceeds the on-chain sequence number, otherwise uses the on-chain configuration: [4](#0-3) 

4. **Different Randomness Flags**: Validators compute different `is_randomness_enabled` flags based on their divergent configurations: [5](#0-4) 

5. **Non-Deterministic Transaction Construction**: During block execution, validators independently construct different metadata transaction types based on their local `is_randomness_enabled` flag: [6](#0-5) 

6. **Transaction Type Divergence**: The different metadata types map to distinct `Transaction` enum variants with different serialization and execution semantics: [7](#0-6) 

**Example Scenario:**
- On-chain `RandomnessConfigSeqNum.seq_num = 0`, randomness config = V2 (enabled)
- Validator A: `randomness_override_seq_num = 0` → uses V2 → `randomness_enabled = true` → creates `BlockMetadataExt`
- Validator B: `randomness_override_seq_num = 999` → uses Off → `randomness_enabled = false` → creates `BlockMetadata`
- Both execute the same block with different transaction lists → different state roots → consensus failure

## Impact Explanation

**Severity: Critical** - Consensus/Safety Violation ($1,000,000 category)

This vulnerability breaks the fundamental **deterministic execution invariant**: "All honest validators must produce identical state roots for identical blocks." The impact includes:

1. **Consensus Safety Violation**: Validators cannot reach 2f+1 agreement on execution results because they produce different state roots. The safety rules validation explicitly checks for execution consistency: [8](#0-7) 

2. **Non-Recoverable Network Partition**: The chain splits into incompatible forks based on configuration groups. Validators with the same override values form separate quorums that cannot interoperate, requiring hardfork recovery.

3. **Total Loss of Liveness**: Block production halts when no configuration group holds 2f+1 stake, causing complete network unavailability.

This precisely matches the Aptos Bug Bounty **Critical Severity** criteria: "Consensus/Safety violations" and "Non-recoverable network partition (requires hardfork)."

## Likelihood Explanation

**Likelihood: Medium-High**

This vulnerability can manifest through realistic operational scenarios **without requiring malicious behavior**:

1. **Documented Emergency Procedure**: The recovery process explicitly instructs validators to modify this configuration during randomness stalls, creating a window for divergence if coordination fails.

2. **Partial Rollout Risk**: During incident response, validators restart sequentially. Early-restarting validators may process epochs with different configurations than late-restarting ones.

3. **Communication Failures**: Network partitions or communication delays during emergency recovery can cause validators to independently apply different override values.

4. **Configuration Errors**: Typos (e.g., `10` vs `100`), copy-paste errors, or misreading documentation can introduce divergence.

5. **No Consensus Validation**: The system provides **zero** consensus-level validation that all validators use the same override value. The only feedback is a local warning log: [9](#0-8) 

The existing test only validates the happy path where all validators coordinate perfectly: [10](#0-9) 

## Recommendation

**Fix 1: Consensus-Level Override Validation**

Add a consensus check that validates all validators have compatible override values before allowing epoch transitions:

```rust
// In EpochManager::start_new_epoch()
fn validate_randomness_override_consistency(
    &self,
    validator_overrides: Vec<(AccountAddress, u64)>,
) -> Result<()> {
    let unique_overrides: HashSet<_> = validator_overrides.iter().map(|(_, v)| v).collect();
    ensure!(
        unique_overrides.len() == 1,
        "Inconsistent randomness_override_seq_num across validators: {:?}",
        validator_overrides
    );
    Ok(())
}
```

**Fix 2: On-Chain Override Coordination**

Replace the local configuration with an on-chain emergency override resource that requires 2f+1 validator signatures, ensuring atomic coordination:

```move
// In randomness_config_seqnum.move
public fun emergency_override(
    validator_signatures: vector<ValidatorSignature>,
    new_seq_num: u64
) acquires RandomnessConfigSeqNum {
    // Validate 2f+1 signatures
    // Atomically update seq_num
}
```

**Fix 3: Transaction Type Consensus**

Include the randomness flag in the block proposal so all validators execute identical transaction lists:

```rust
// In Block struct
pub struct Block {
    // ... existing fields
    randomness_enabled_flag: bool, // Proposer's view, binding for all validators
}
```

## Proof of Concept

```rust
// testsuite/smoke-test/src/randomness/randomness_divergence_test.rs
#[tokio::test]
async fn test_randomness_config_divergence_breaks_consensus() {
    let (mut swarm, _cli, _faucet) = SwarmBuilder::new_local(4)
        .with_init_genesis_config(Arc::new(|conf| {
            conf.randomness_config_override = Some(OnChainRandomnessConfig::V2(ConfigV2::default()));
        }))
        .build()
        .await;

    // Set divergent override values
    for (idx, validator) in swarm.validators_mut().enumerate() {
        validator.stop();
        let config_path = validator.config_path();
        let mut config = OverrideNodeConfig::load_config(config_path.clone()).unwrap();
        
        // Validators 0-1: override = 0 (randomness ON)
        // Validators 2-3: override = 999 (randomness OFF)
        config.override_config_mut().randomness_override_seq_num = if idx < 2 { 0 } else { 999 };
        
        config.save_config(config_path).unwrap();
        validator.start().unwrap();
    }

    // Wait for epoch transition
    tokio::time::sleep(Duration::from_secs(30)).await;

    // Consensus should fail - validators produce different state roots
    let liveness_check = swarm.liveness_check(Instant::now().add(Duration::from_secs(60))).await;
    assert!(liveness_check.is_err(), "Network should halt due to consensus divergence");
}
```

**Expected Result**: The network halts because validators 0-1 create `Transaction::BlockMetadataExt` while validators 2-3 create `Transaction::BlockMetadata`, producing irreconcilable state roots.

### Citations

**File:** config/src/config/node_config.rs (L78-81)
```rust
    /// In a randomness stall, set this to be on-chain `RandomnessConfigSeqNum` + 1.
    /// Once enough nodes restarted with the new value, the chain should unblock with randomness disabled.
    #[serde(default)]
    pub randomness_override_seq_num: u64,
```

**File:** aptos-move/framework/aptos-framework/sources/configs/randomness_config_seqnum.move (L1-9)
```text
/// Randomness stall recovery utils.
///
/// When randomness generation is stuck due to a bug, the chain is also stuck. Below is the recovery procedure.
/// 1. Ensure more than 2/3 stakes are stuck at the same version.
/// 1. Every validator restarts with `randomness_override_seq_num` set to `X+1` in the node config file,
///    where `X` is the current `RandomnessConfigSeqNum` on chain.
/// 1. The chain should then be unblocked.
/// 1. Once the bug is fixed and the binary + framework have been patched,
///    a governance proposal is needed to set `RandomnessConfigSeqNum` to be `X+2`.
```

**File:** consensus/src/epoch_manager.rs (L1213-1221)
```rust
        if self.randomness_override_seq_num > onchain_randomness_config_seq_num.seq_num {
            warn!("Randomness will be force-disabled by local config!");
        }

        let onchain_randomness_config = OnChainRandomnessConfig::from_configs(
            self.randomness_override_seq_num,
            onchain_randomness_config_seq_num.seq_num,
            randomness_config_move_struct.ok(),
        );
```

**File:** types/src/on_chain_config/randomness_config.rs (L138-151)
```rust
    /// Used by DKG and Consensus on a new epoch to determine the actual `OnChainRandomnessConfig` to be used.
    pub fn from_configs(
        local_seqnum: u64,
        onchain_seqnum: u64,
        onchain_raw_config: Option<RandomnessConfigMoveStruct>,
    ) -> Self {
        if local_seqnum > onchain_seqnum {
            Self::default_disabled()
        } else {
            onchain_raw_config
                .and_then(|onchain_raw| OnChainRandomnessConfig::try_from(onchain_raw).ok())
                .unwrap_or_else(OnChainRandomnessConfig::default_if_missing)
        }
    }
```

**File:** consensus/src/pipeline/execution_client.rs (L566-567)
```rust
        let randomness_enabled = onchain_consensus_config.is_vtxn_enabled()
            && onchain_randomness_config.randomness_enabled();
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L806-811)
```rust
        // if randomness is disabled, the metadata skips DKG and triggers immediate reconfiguration
        let metadata_txn = if let Some(maybe_rand) = rand_result {
            block.new_metadata_with_randomness(&validator, maybe_rand)
        } else {
            block.new_block_metadata(&validator).into()
        };
```

**File:** types/src/transaction/mod.rs (L2956-2970)
```rust
    /// Transaction to update the block metadata resource at the beginning of a block,
    /// when on-chain randomness is disabled.
    BlockMetadata(BlockMetadata),

    /// Transaction to let the executor update the global state tree and record the root hash
    /// in the TransactionInfo
    /// The hash value inside is unique block id which can generate unique hash of state checkpoint transaction
    StateCheckpoint(HashValue),

    /// Transaction that only proposed by a validator mainly to update on-chain configs.
    ValidatorTransaction(ValidatorTransaction),

    /// Transaction to update the block metadata resource at the beginning of a block,
    /// when on-chain randomness is enabled.
    BlockMetadataExt(BlockMetadataExt),
```

**File:** consensus/safety-rules/src/safety_rules.rs (L395-403)
```rust
        if !old_ledger_info
            .commit_info()
            .match_ordered_only(new_ledger_info.commit_info())
        {
            return Err(Error::InconsistentExecutionResult(
                old_ledger_info.commit_info().to_string(),
                new_ledger_info.commit_info().to_string(),
            ));
        }
```

**File:** testsuite/smoke-test/src/randomness/randomness_stall_recovery.rs (L64-84)
```rust
    info!("Hot-fixing all validators.");
    for (idx, validator) in swarm.validators_mut().enumerate() {
        info!("Stopping validator {}.", idx);
        validator.stop();
        let config_path = validator.config_path();
        let mut validator_override_config =
            OverrideNodeConfig::load_config(config_path.clone()).unwrap();
        validator_override_config
            .override_config_mut()
            .randomness_override_seq_num = 1;
        validator_override_config
            .override_config_mut()
            .consensus
            .sync_only = false;
        info!("Updating validator {} config.", idx);
        validator_override_config.save_config(config_path).unwrap();
        info!("Restarting validator {}.", idx);
        validator.start().unwrap();
        info!("Let validator {} bake for 5 secs.", idx);
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
```
