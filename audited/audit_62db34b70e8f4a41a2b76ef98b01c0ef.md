# Audit Report

## Title
Consensus Configuration Deserialization Failures Cause Silent Fallback to Incompatible Default Parameters Leading to Consensus Splits

## Summary
When `OnChainConsensusConfig` deserialization fails due to I/O errors, BCS format errors, or database corruption during epoch transitions, nodes silently fall back to hardcoded default consensus parameters that may differ from the network's actual on-chain configuration. This causes nodes with different configurations to reject each other's blocks, leading to consensus disagreements and potential network splits without requiring any malicious actors.

## Finding Description

The vulnerability exists in how consensus configuration is loaded during epoch transitions across multiple components: [1](#0-0) [2](#0-1) [3](#0-2) 

When `OnChainConsensusConfig` is retrieved from on-chain state via `payload.get()`, the method performs two rounds of BCS deserialization: [4](#0-3) 

If deserialization fails (due to corrupted on-chain state, disk I/O errors, or format mismatches), the code logs a warning/error but falls back to `OnChainConsensusConfig::default()`: [5](#0-4) 

The default configuration returns:
- `quorum_store_enabled: true` (via `ConsensusAlgorithmConfig::default_if_missing()`)
- `order_vote_enabled: false`
- `window_size: None`
- `vtxn: ValidatorTxnConfig::V0` (disabled) [6](#0-5) 

**Critical Impact on Consensus**: The `quorum_store_enabled` flag directly determines payload type validation in `Payload::verify()`: [7](#0-6) 

When a node with `quorum_store_enabled: true` (from default fallback) receives a block with `Payload::DirectMempool` from a node correctly configured with `quorum_store_enabled: false`, the verification fails at the catchall case returning "Wrong payload type" error, causing the block to be rejected.

**Attack Scenario**:
1. Network is configured with `quorum_store_enabled: false` via on-chain governance
2. Node A successfully loads the on-chain config: `quorum_store_enabled = false`
3. Node B experiences a transient BCS deserialization error (e.g., disk I/O error during state read, corrupted on-chain config bytes in state storage)
4. Node B logs error and falls back to default: `quorum_store_enabled = true`
5. Proposer (Node A) creates block with `Payload::DirectMempool` (matching its config)
6. Node B attempts verification: calls `verify()` with `quorum_store_enabled: true`
7. The match statement hits the catchall `(_, _)` case at line 626-630
8. Node B rejects the block as invalid payload type
9. Consensus split occurs: Node A accepts the block, Node B rejects it

This breaks the **Consensus Safety** invariant: "AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine".

## Impact Explanation

**Severity: HIGH** - Significant Protocol Violations

This vulnerability causes consensus disagreements that can lead to:

1. **Consensus Splits**: Nodes operating with different consensus configurations will reject each other's blocks, causing the validator set to fragment into incompatible groups
2. **Liveness Failures**: If enough nodes fall back to incorrect defaults, the network may fail to reach quorum on new blocks
3. **Non-Deterministic Behavior**: Unlike a coordinated attack, this can happen randomly to different nodes at different times based on transient infrastructure failures
4. **Cascading Failures**: Once a node falls back to defaults, it remains in that incorrect state for the entire epoch unless restarted

The impact meets **High Severity** criteria per the Aptos bug bounty program as it causes "significant protocol violations" and can cause "validator node slowdowns" or effective denial of consensus service to affected nodes.

While this doesn't meet Critical severity (requires no hardfork to recover, as nodes can restart to reload correct config), it significantly compromises network integrity and availability.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

This vulnerability can be triggered by:

1. **Transient I/O Errors**: Disk read failures during on-chain config loading from state storage
2. **Database Corruption**: Corrupted bytes in the on-chain config resource in AptosDB
3. **State Sync Issues**: Incomplete or corrupted state during state synchronization
4. **Memory Corruption**: Rare but possible in production environments under load
5. **Race Conditions**: Concurrent access to state storage during epoch transitions

No attacker action is required - this can happen naturally due to infrastructure failures. Production blockchain validators commonly experience transient I/O errors, making this a realistic scenario.

The vulnerability is present in:
- Main consensus epoch manager (validators)
- Consensus observer (fullnodes)  
- JWK consensus epoch manager
- DKG epoch manager

Any component loading `OnChainConsensusConfig` is affected, increasing the attack surface.

## Recommendation

Implement strict validation and halt node operation when consensus configuration cannot be loaded reliably:

```rust
// In extract_on_chain_configs and start_new_epoch methods

let onchain_consensus_config: anyhow::Result<OnChainConsensusConfig> = on_chain_configs.get();
let consensus_config = match onchain_consensus_config {
    Ok(config) => config,
    Err(error) => {
        error!(
            "CRITICAL: Failed to load on-chain consensus config: {:?}. Cannot proceed with potentially incompatible configuration.",
            error
        );
        // Halt the node or enter safe mode rather than falling back to defaults
        return Err(anyhow::anyhow!(
            "Cannot start epoch without valid consensus configuration: {}",
            error
        ));
    }
};
```

**Key Changes**:
1. Remove `unwrap_or_default()` pattern for consensus-critical configuration
2. Return error and halt epoch initialization on config load failure
3. Require node operator intervention (restart, state recovery) rather than silent fallback
4. Log CRITICAL level message to alert operators immediately
5. Consider adding consensus config validation hash to quorum certificates to detect mismatches

**Alternative Approach**: 
- Cache the last successfully loaded consensus config in persistent storage
- On deserialization failure, attempt to load from cache
- Only halt if both on-chain and cached config loading fail
- Add telemetry to detect and alert on config loading failures across the network

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use aptos_types::on_chain_config::{OnChainConfigPayload, OnChainConsensusConfig};
    use std::collections::HashMap;
    
    #[test]
    fn test_consensus_config_deserialization_failure_causes_wrong_default() {
        // Simulate a network configured with quorum_store_enabled: false (V1 config)
        let network_consensus_config = OnChainConsensusConfig::V1(ConsensusConfigV1::default());
        assert_eq!(network_consensus_config.quorum_store_enabled(), false);
        
        // Node A successfully deserializes the config
        let node_a_config = network_consensus_config.clone();
        assert_eq!(node_a_config.quorum_store_enabled(), false);
        
        // Node B experiences deserialization error and falls back to default
        // Simulating the unwrap_or_default() pattern
        let deserialization_result: Result<OnChainConsensusConfig, anyhow::Error> = 
            Err(anyhow::anyhow!("BCS deserialization failed"));
        let node_b_config = deserialization_result.unwrap_or_default();
        
        // Node B gets incompatible default (V4 with quorum_store enabled)
        assert_eq!(node_b_config.quorum_store_enabled(), true);
        
        // This configuration mismatch causes consensus disagreement:
        // Node A creates Payload::DirectMempool
        // Node B expects Payload::InQuorumStore
        // Node B rejects Node A's blocks as "Wrong payload type"
        
        println!("Node A config (correct): quorum_store_enabled = {}", 
                 node_a_config.quorum_store_enabled());
        println!("Node B config (fallback default): quorum_store_enabled = {}", 
                 node_b_config.quorum_store_enabled());
        println!("Consensus disagreement: Node B will reject Node A's DirectMempool payloads");
        
        // Verify the configs are incompatible
        assert_ne!(
            node_a_config.quorum_store_enabled(), 
            node_b_config.quorum_store_enabled(),
            "Configuration mismatch detected - would cause consensus split"
        );
    }
    
    #[test]
    fn test_payload_verification_fails_with_mismatched_config() {
        // Create a DirectMempool payload (what Node A with quorum_store disabled would send)
        let payload = Payload::DirectMempool(vec![]);
        
        // Node B with quorum_store_enabled: true tries to verify
        let verifier = create_test_validator_verifier();
        let proof_cache = ProofCache::new(100);
        
        // This should fail with "Wrong payload type" error
        let result = payload.verify(&verifier, &proof_cache, true);
        
        assert!(result.is_err(), "Payload verification should fail with mismatched config");
        assert!(result.unwrap_err().to_string().contains("Wrong payload type"),
                "Error should indicate payload type mismatch");
    }
}
```

**Notes**:
- This vulnerability requires no attacker - only transient infrastructure failures
- The silent fallback to incompatible defaults makes debugging difficult for node operators
- Multiple consensus-critical components are affected, increasing likelihood
- The fix requires removing the permissive error handling and enforcing strict config validation

### Citations

**File:** consensus/src/consensus_observer/observer/epoch_state.rs (L156-166)
```rust
    // Extract the consensus config (or use the default if it's missing)
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

**File:** crates/aptos-jwk-consensus/src/epoch_manager.rs (L172-175)
```rust
        let features = payload.get::<Features>().unwrap_or_default();
        let jwk_consensus_config = payload.get::<OnChainJWKConsensusConfig>();
        let onchain_observed_jwks = payload.get::<ObservedJWKs>().ok();
        let onchain_consensus_config = payload.get::<OnChainConsensusConfig>().unwrap_or_default();
```

**File:** types/src/on_chain_config/consensus_config.rs (L46-52)
```rust
    pub fn default_if_missing() -> Self {
        Self::JolteonV2 {
            main: ConsensusConfigV1::default(),
            quorum_store_enabled: true,
            order_vote_enabled: false,
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

**File:** types/src/on_chain_config/consensus_config.rs (L464-469)
```rust
    fn deserialize_into_config(bytes: &[u8]) -> Result<Self> {
        let raw_bytes: Vec<u8> = bcs::from_bytes(bytes)?;
        bcs::from_bytes(&raw_bytes)
            .map_err(|e| format_err!("[on-chain config] Failed to deserialize into config: {}", e))
    }
}
```

**File:** consensus/consensus-types/src/common.rs (L574-632)
```rust
    pub fn verify(
        &self,
        verifier: &ValidatorVerifier,
        proof_cache: &ProofCache,
        quorum_store_enabled: bool,
    ) -> anyhow::Result<()> {
        match (quorum_store_enabled, self) {
            (false, Payload::DirectMempool(_)) => Ok(()),
            (true, Payload::InQuorumStore(proof_with_status)) => {
                Self::verify_with_cache(&proof_with_status.proofs, verifier, proof_cache)
            },
            (true, Payload::InQuorumStoreWithLimit(proof_with_status)) => Self::verify_with_cache(
                &proof_with_status.proof_with_data.proofs,
                verifier,
                proof_cache,
            ),
            (true, Payload::QuorumStoreInlineHybrid(inline_batches, proof_with_data, _))
            | (true, Payload::QuorumStoreInlineHybridV2(inline_batches, proof_with_data, _)) => {
                Self::verify_with_cache(&proof_with_data.proofs, verifier, proof_cache)?;
                Self::verify_inline_batches(
                    inline_batches.iter().map(|(info, txns)| (info, txns)),
                )?;
                Ok(())
            },
            (true, Payload::OptQuorumStore(OptQuorumStorePayload::V1(p))) => {
                let proof_with_data = p.proof_with_data();
                Self::verify_with_cache(&proof_with_data.batch_summary, verifier, proof_cache)?;
                Self::verify_inline_batches(
                    p.inline_batches()
                        .iter()
                        .map(|batch| (batch.info(), batch.transactions())),
                )?;
                Self::verify_opt_batches(verifier, p.opt_batches())?;
                Ok(())
            },
            (true, Payload::OptQuorumStore(OptQuorumStorePayload::V2(p))) => {
                if true {
                    bail!("OptQuorumStorePayload::V2 cannot be accepted yet");
                }
                #[allow(unreachable_code)]
                {
                    let proof_with_data = p.proof_with_data();
                    Self::verify_with_cache(&proof_with_data.batch_summary, verifier, proof_cache)?;
                    Self::verify_inline_batches(
                        p.inline_batches()
                            .iter()
                            .map(|batch| (batch.info(), batch.transactions())),
                    )?;
                    Self::verify_opt_batches(verifier, p.opt_batches())?;
                    Ok(())
                }
            },
            (_, _) => Err(anyhow::anyhow!(
                "Wrong payload type. Expected Payload::InQuorumStore {} got {} ",
                quorum_store_enabled,
                self
            )),
        }
    }
```
