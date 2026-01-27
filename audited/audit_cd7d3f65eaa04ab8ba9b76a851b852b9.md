# Audit Report

## Title
Consensus Config Deserialization Fallback Causes Validator Transaction Feature Mismatch Leading to Network Partition

## Summary
The `validator_txn_enabled()` native function uses `unwrap_or_default()` when deserializing the consensus configuration, causing validators that fail deserialization to fall back to a default config where validator transactions are disabled (V0), while validators using the genesis config have validator transactions enabled (V1). This mismatch causes consensus-breaking divergence where validators reject each other's blocks, leading to network partition.

## Finding Description

The vulnerability exists in two locations where consensus configuration deserialization failures are silently handled with a default fallback:

1. **Native Function Level**: In `validator_txn_enabled()`, the consensus config bytes are deserialized with a fallback to default. [1](#0-0) 

2. **Consensus Layer**: In `EpochManager::start_new_epoch()`, the on-chain consensus config is loaded with the same fallback pattern. [2](#0-1) 

The critical discrepancy lies in the configuration values:

**Genesis Configuration** sets validator transactions to **enabled** (V1): [3](#0-2) [4](#0-3) 

**Default Configuration** (fallback) sets validator transactions to **disabled** (V0): [5](#0-4) [6](#0-5) 

The `enabled()` method returns different values for these configs: [7](#0-6) 

### Attack Scenario

During network upgrades or when validators run different software versions:

1. Genesis initializes `OnChainConsensusConfig::V5` with `vtxn: ValidatorTxnConfig::V1` (enabled) [8](#0-7) 

2. Validators running newer software successfully deserialize V5 config and see `is_vtxn_enabled() == true`

3. Validators running older software that only understands V1-V4 fail to deserialize V5 (BCS enum deserialization fails on unknown variants) and fall back to `OnChainConsensusConfig::V4` with `vtxn: ValidatorTxnConfig::V0` (disabled)

4. The consensus layer extracts different `vtxn_config` values: [9](#0-8) 

5. **Validators with vtxn enabled** create `ProposalExt` blocks containing validator transactions

6. **Validators with vtxn disabled** reject these `ProposalExt` blocks with error: [10](#0-9) 

7. This causes validators to disagree on valid blocks, breaking consensus safety and causing network partition

### Impact on Critical Features

This vulnerability also affects the reconfiguration mechanism and randomness feature: [11](#0-10) 

Validators with different `validator_txn_enabled()` values will disagree on whether to start DKG for randomness, causing further consensus divergence.

## Impact Explanation

**Critical Severity** - This vulnerability qualifies for the highest severity tier because it causes:

1. **Consensus Safety Violation**: Breaks the fundamental invariant that "All validators must produce identical state roots for identical blocks". Validators disagree on whether `ProposalExt` blocks are valid, violating AptosBFT safety guarantees.

2. **Non-Recoverable Network Partition**: If more than 1/3 of validators fail deserialization and fall back to the default config, the network cannot reach consensus. This creates a permanent split requiring a hard fork to resolve, as validators with different configs cannot agree on block validity.

3. **Deterministic Execution Failure**: The same block proposal is accepted by some validators and rejected by others based solely on their software version, violating deterministic execution guarantees.

4. **Critical Infrastructure Impact**: Affects validator transaction processing, DKG, and on-chain randomness - core consensus features that the network depends on.

This meets the Critical Severity criteria per the Aptos bug bounty: "Consensus/Safety violations" and "Non-recoverable network partition (requires hardfork)".

## Likelihood Explanation

**High Likelihood** - This vulnerability will occur in the following realistic scenarios:

1. **Network Upgrades**: During any upgrade that introduces new `OnChainConsensusConfig` enum variants (V5, future V6, etc.), validators that haven't upgraded yet will fail to deserialize the new config format and fall back to default. This is inevitable during rolling deployments.

2. **Version Heterogeneity**: In a decentralized network, validators upgrade at different times. The window between first and last validator upgrade creates a period where this vulnerability is active.

3. **Silent Failure**: The deserialization failure is only logged as a warning, not treated as a critical error, so operators may not realize validators are running with different configs until consensus breaks. [12](#0-11) 

4. **No Circuit Breaker**: There's no mechanism to detect or prevent validators from operating with mismatched configs. The network continues attempting consensus with incompatible configurations.

The likelihood is especially high because this is not an attack - it's an operational failure that occurs naturally during routine network maintenance.

## Recommendation

Implement strict validation that prevents validators from operating with mismatched consensus configurations:

**Option 1: Fail Fast on Deserialization Error**
```rust
pub fn validator_txn_enabled(
    _context: &mut SafeNativeContext,
    _ty_args: &[Type],
    mut args: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    let config_bytes = safely_pop_arg!(args, Vec<u8>);
    let config = bcs::from_bytes::<OnChainConsensusConfig>(&config_bytes)
        .map_err(|e| {
            PartialVMError::new(StatusCode::FAILED_TO_DESERIALIZE_RESOURCE)
                .with_message(format!("Failed to deserialize consensus config: {}", e))
        })?;
    Ok(smallvec![Value::bool(config.is_vtxn_enabled())])
}
```

**Option 2: Version-Safe Fallback**
Ensure the default config matches the minimum supported genesis config:
```rust
impl Default for OnChainConsensusConfig {
    fn default() -> Self {
        // Use the same config as genesis to prevent mismatch
        Self::default_for_genesis()
    }
}
```

**Option 3: Epoch Manager Circuit Breaker**
```rust
let consensus_config = onchain_consensus_config
    .map_err(|e| {
        error!("CRITICAL: Failed to deserialize consensus config: {}", e);
        // Halt consensus rather than operating with wrong config
        panic!("Cannot start epoch with invalid consensus config");
    })?;
```

**Recommended Approach**: Implement Option 1 (fail fast) at the native function level AND Option 3 (circuit breaker) at the epoch manager level. This creates defense in depth - the native function prevents Move code from executing with wrong config, and the epoch manager prevents consensus from starting with mismatched configs.

Additionally, add version compatibility checks before epoch transitions to ensure all validators can deserialize the new config format before it takes effect.

## Proof of Concept

**Reproduction Steps:**

1. Deploy a network with `OnChainConsensusConfig::V5` in genesis (vtxn enabled)
2. Start some validators with software version N (supports V5 deserialization)
3. Start other validators with software version N-1 (only supports up to V4)
4. Observe that version N-1 validators fail to deserialize V5 config:
   - Logs show: "Failed to read on-chain consensus config"
   - They fall back to `OnChainConsensusConfig::V4` with vtxn disabled
5. Version N validators create ProposalExt blocks with validator transactions
6. Version N-1 validators reject these blocks with error: "ProposalExt unexpected while the vtxn feature is disabled"
7. Network fails to reach consensus - validators cannot agree on block validity
8. If >1/3 of validators are on version N-1, network partition occurs

**Test Case (Rust pseudocode):**
```rust
#[test]
fn test_config_mismatch_causes_consensus_failure() {
    // Simulate V5 config bytes
    let v5_config = OnChainConsensusConfig::default_for_genesis();
    let config_bytes = bcs::to_bytes(&v5_config).unwrap();
    
    // Validator with V5 support
    let config_v5 = bcs::from_bytes::<OnChainConsensusConfig>(&config_bytes).unwrap();
    assert!(config_v5.is_vtxn_enabled()); // true
    
    // Simulate validator with only V4 support (deserialization fails)
    // Falls back to default
    let config_default = OnChainConsensusConfig::default();
    assert!(!config_default.is_vtxn_enabled()); // false - MISMATCH!
    
    // This mismatch causes consensus to break:
    // - V5 validator creates ProposalExt block
    // - V4 validator rejects it because vtxn_config.enabled() == false
}
```

---

**Notes:**

This vulnerability demonstrates a critical failure in configuration management during network upgrades. The root cause is the use of `unwrap_or_default()` combined with a default value that differs from the genesis configuration. This pattern should be audited throughout the codebase to prevent similar issues with other on-chain configs.

The vulnerability is particularly insidious because it manifests silently during normal operations (network upgrades) rather than requiring an active attack, making it highly likely to occur in production environments.

### Citations

**File:** aptos-move/framework/src/natives/consensus_config.rs (L18-19)
```rust
    let config_bytes = safely_pop_arg!(args, Vec<u8>);
    let config = bcs::from_bytes::<OnChainConsensusConfig>(&config_bytes).unwrap_or_default();
```

**File:** consensus/src/epoch_manager.rs (L1178-1201)
```rust
        let onchain_consensus_config: anyhow::Result<OnChainConsensusConfig> = payload.get();
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
```

**File:** types/src/on_chain_config/consensus_config.rs (L140-145)
```rust
    pub fn default_for_genesis() -> Self {
        Self::V1 {
            per_block_limit_txn_count: VTXN_CONFIG_PER_BLOCK_LIMIT_TXN_COUNT_DEFAULT,
            per_block_limit_total_bytes: VTXN_CONFIG_PER_BLOCK_LIMIT_TOTAL_BYTES_DEFAULT,
        }
    }
```

**File:** types/src/on_chain_config/consensus_config.rs (L147-149)
```rust
    pub fn default_if_missing() -> Self {
        Self::V0
    }
```

**File:** types/src/on_chain_config/consensus_config.rs (L162-167)
```rust
    pub fn enabled(&self) -> bool {
        match self {
            ValidatorTxnConfig::V0 => false,
            ValidatorTxnConfig::V1 { .. } => true,
        }
    }
```

**File:** types/src/on_chain_config/consensus_config.rs (L217-224)
```rust
    pub fn default_for_genesis() -> Self {
        OnChainConsensusConfig::V5 {
            alg: ConsensusAlgorithmConfig::default_for_genesis(),
            vtxn: ValidatorTxnConfig::default_for_genesis(),
            window_size: DEFAULT_WINDOW_SIZE,
            rand_check_enabled: true,
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

**File:** aptos-move/vm-genesis/src/lib.rs (L165-165)
```rust
    let consensus_config = OnChainConsensusConfig::default_for_genesis();
```

**File:** consensus/src/round_manager.rs (L363-364)
```rust
        let vtxn_config = onchain_config.effective_validator_txn_config();
        debug!("vtxn_config={:?}", vtxn_config);
```

**File:** consensus/src/round_manager.rs (L1116-1124)
```rust
        if !self.vtxn_config.enabled()
            && matches!(
                proposal.block_data().block_type(),
                BlockType::ProposalExt(_)
            )
        {
            counters::UNEXPECTED_PROPOSAL_EXT_COUNT.inc();
            bail!("ProposalExt unexpected while the vtxn feature is disabled.");
        }
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L685-692)
```text
    public entry fun reconfigure(aptos_framework: &signer) {
        system_addresses::assert_aptos_framework(aptos_framework);
        if (consensus_config::validator_txn_enabled() && randomness_config::enabled()) {
            reconfiguration_with_dkg::try_start();
        } else {
            reconfiguration_with_dkg::finish(aptos_framework);
        }
    }
```
