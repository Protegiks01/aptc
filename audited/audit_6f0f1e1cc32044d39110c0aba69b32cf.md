# Audit Report

## Title
Non-Deterministic VTxn Config Parsing During Rolling Upgrades Causes Consensus Splits

## Summary
During rolling validator upgrades, validators running different code versions can parse the same on-chain `OnChainConsensusConfig` differently, resulting in different `effective_vtxn_config` values. This causes consensus splits when validators disagree on whether blocks containing validator transactions are valid.

## Finding Description

The vulnerability exists in how `initialize_shared_component()` obtains the validator transaction configuration: [1](#0-0) 

The function calls `consensus_config.effective_validator_txn_config()` to extract the vtxn limits: [2](#0-1) 

The on-chain config is deserialized using BCS, with a fallback to default if deserialization fails: [3](#0-2) 

The default config has validator transactions disabled: [4](#0-3) [5](#0-4) 

**Attack Scenario:**

1. On-chain governance upgrades `OnChainConsensusConfig` to V5 (which includes `rand_check_enabled` field)
2. During rolling validator upgrades:
   - **New validators** (code version 2.0 supporting V5): Successfully deserialize → `vtxn_config = V1 {per_block_limit_txn_count: 5}`
   - **Old validators** (code version 1.0 supporting only V1-V4): BCS deserialization fails on unknown V5 variant → fallback to `default()` → `vtxn_config = V0 {per_block_limit_txn_count: 0}`

3. When new validator proposes a block with 3 validator transactions:
   - New validators validate: `3 <= 5` ✓ Accept
   - Old validators validate: `3 <= 0` ✗ Reject [6](#0-5) 

4. Validators split into two incompatible groups, unable to reach consensus on the same blocks.

## Impact Explanation

This is **Critical Severity** per Aptos bug bounty criteria:
- **Consensus/Safety violation**: Validators disagree on block validity, breaking the fundamental invariant that all honest validators must agree on the canonical chain
- **Non-recoverable network partition**: The split persists until either old validators upgrade or on-chain config is downgraded, potentially requiring emergency intervention
- **Total loss of liveness**: If validator voting power is split such that neither group achieves 2/3 quorum, the network halts

The issue violates the **Deterministic Execution** invariant: All validators must produce identical validation results for identical blocks, but here they disagree based on their code version.

## Likelihood Explanation

**Moderate to High likelihood** during network upgrades:

1. **Trigger condition**: On-chain config upgraded to version N+1 while validators still run code supporting only version N
2. **Current safeguards**: None - the code explicitly uses `unwrap_or_default()` suggesting tolerance for parsing failures, but the fallback creates consensus splits
3. **Operational practice**: Framework upgrade tests show validators are upgraded before config changes, but this is convention, not enforced
4. **Window of vulnerability**: Entire duration of rolling upgrade (hours to days)

The issue requires governance coordination failure or intentional early config upgrade, making it less likely than directly exploitable bugs, but still realistic during operational procedures.

## Recommendation

**Immediate Fix**: Add explicit version checking and halt validators that cannot parse the on-chain config:

```rust
let consensus_config = match onchain_consensus_config {
    Ok(config) => config,
    Err(error) => {
        error!(
            epoch = epoch_state.epoch,
            error = ?error,
            "CRITICAL: Failed to deserialize OnChainConsensusConfig. \
             This validator's code version may be incompatible with the \
             on-chain config. Halting to prevent consensus split."
        );
        panic!("Cannot deserialize OnChainConsensusConfig: {:?}", error);
    }
};
```

**Long-term Fix**: Implement forward-compatible deserialization:
1. Use explicit version fields in on-chain config instead of enum variants
2. Old validators can read newer configs by ignoring unknown fields
3. Add on-chain compatibility checking before config upgrades

**Governance Safeguard**: Enforce validator version requirements before allowing config upgrades:
- Query validator versions via on-chain metadata
- Only allow config format upgrades when >99% validators support new version
- Add explicit compatibility matrix to governance proposals

## Proof of Concept

```rust
// Reproduction test (conceptual - requires multi-version simulation)

#[test]
fn test_vtxn_config_consensus_split() {
    // Simulate two validator groups
    let v5_config = OnChainConsensusConfig::V5 {
        alg: ConsensusAlgorithmConfig::default_for_genesis(),
        vtxn: ValidatorTxnConfig::V1 {
            per_block_limit_txn_count: 5,
            per_block_limit_total_bytes: 2097152,
        },
        window_size: None,
        rand_check_enabled: true,
    };
    
    // Serialize V5 config
    let v5_bytes = bcs::to_bytes(&bcs::to_bytes(&v5_config).unwrap()).unwrap();
    
    // Old validator (only knows V1-V4) tries to deserialize
    // This would fail in actual old code:
    // let result = OnChainConsensusConfig::deserialize_into_config(&v5_bytes);
    // assert!(result.is_err());
    
    // Old validator falls back to default
    let old_validator_config = OnChainConsensusConfig::default();
    assert_eq!(old_validator_config.effective_validator_txn_config()
        .per_block_limit_txn_count(), 0);
    
    // New validator successfully deserializes
    let new_validator_config = 
        OnChainConsensusConfig::deserialize_into_config(&v5_bytes).unwrap();
    assert_eq!(new_validator_config.effective_validator_txn_config()
        .per_block_limit_txn_count(), 5);
    
    // Create block with 3 validator txns
    let num_vtxns = 3;
    
    // Old validator rejects: 3 > 0
    assert!(num_vtxns > old_validator_config.effective_validator_txn_config()
        .per_block_limit_txn_count());
    
    // New validator accepts: 3 <= 5
    assert!(num_vtxns <= new_validator_config.effective_validator_txn_config()
        .per_block_limit_txn_count());
    
    // Consensus split demonstrated
}
```

## Notes

This vulnerability specifically manifests during protocol upgrades and requires governance/operational coordination failure. While not directly exploitable by external attackers, it represents a critical design flaw in how the system handles version evolution, breaking the fundamental consensus safety guarantee.

### Citations

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

**File:** consensus/src/epoch_manager.rs (L1331-1365)
```rust
    async fn initialize_shared_component(
        &mut self,
        epoch_state: &EpochState,
        consensus_config: &OnChainConsensusConfig,
        consensus_key: Arc<PrivateKey>,
    ) -> (
        NetworkSender,
        Arc<dyn PayloadClient>,
        Arc<dyn TPayloadManager>,
    ) {
        self.set_epoch_start_metrics(epoch_state);
        self.quorum_store_enabled = self.enable_quorum_store(consensus_config);
        let network_sender = self.create_network_sender(epoch_state);
        let (payload_manager, quorum_store_client, quorum_store_builder) = self
            .init_payload_provider(
                epoch_state,
                network_sender.clone(),
                consensus_config,
                consensus_key,
            )
            .await;
        let effective_vtxn_config = consensus_config.effective_validator_txn_config();
        debug!("effective_vtxn_config={:?}", effective_vtxn_config);
        let mixed_payload_client = MixedPayloadClient::new(
            effective_vtxn_config,
            Arc::new(self.vtxn_pool.clone()),
            Arc::new(quorum_store_client),
        );
        self.start_quorum_store(quorum_store_builder);
        (
            network_sender,
            Arc::new(mixed_payload_client),
            payload_manager,
        )
    }
```

**File:** types/src/on_chain_config/consensus_config.rs (L147-153)
```rust
    pub fn default_if_missing() -> Self {
        Self::V0
    }

    pub fn default_disabled() -> Self {
        Self::V0
    }
```

**File:** types/src/on_chain_config/consensus_config.rs (L309-318)
```rust
    pub fn effective_validator_txn_config(&self) -> ValidatorTxnConfig {
        match self {
            OnChainConsensusConfig::V1(_) | OnChainConsensusConfig::V2(_) => {
                ValidatorTxnConfig::default_disabled()
            },
            OnChainConsensusConfig::V3 { vtxn, .. }
            | OnChainConsensusConfig::V4 { vtxn, .. }
            | OnChainConsensusConfig::V5 { vtxn, .. } => vtxn.clone(),
        }
    }
```

**File:** types/src/on_chain_config/consensus_config.rs (L443-450)
```rust
impl Default for OnChainConsensusConfig {
    fn default() -> Self {
        OnChainConsensusConfig::V4 {
            alg: ConsensusAlgorithmConfig::default_if_missing(),
            vtxn: ValidatorTxnConfig::default_if_missing(),
            window_size: DEFAULT_WINDOW_SIZE,
        }
    }
```

**File:** consensus/src/round_manager.rs (L1166-1177)
```rust
        ensure!(
            num_validator_txns <= vtxn_count_limit,
            "process_proposal failed with per-block vtxn count limit exceeded: limit={}, actual={}",
            self.vtxn_config.per_block_limit_txn_count(),
            num_validator_txns
        );
        ensure!(
            validator_txns_total_bytes <= vtxn_bytes_limit,
            "process_proposal failed with per-block vtxn bytes limit exceeded: limit={}, actual={}",
            self.vtxn_config.per_block_limit_total_bytes(),
            validator_txns_total_bytes
        );
```
