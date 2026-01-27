# Audit Report

## Title
Consensus Configuration Fallback Inconsistency Causes Validator Divergence During Epoch Changes

## Summary
The `default_if_missing()` fallback for `OnChainConsensusConfig` uses inconsistent consensus parameters compared to the genesis configuration, specifically setting `order_vote_enabled: false` instead of `true`. When validators fail to fetch the on-chain consensus config during epoch changes, they silently fall back to these inconsistent defaults, causing them to diverge from the network's expected consensus behavior and potentially leading to state inconsistencies and consensus disagreements.

## Finding Description

The vulnerability exists in the fallback mechanism for on-chain consensus configuration during epoch changes. The codebase defines two different default configurations:

1. **Genesis default**: [1](#0-0) 
   - Sets `order_vote_enabled: true`

2. **Missing config fallback**: [2](#0-1) 
   - Sets `order_vote_enabled: false`

During epoch initialization, the consensus config is fetched with silent fallback: [3](#0-2) 

The issue is that if the config fetch fails (due to network issues, deserialization errors, or corrupted data), only a warning is logged, and the validator silently uses the inconsistent default.

The `order_vote_enabled` flag controls critical consensus behaviors:

**1. Recovery Logic**: Different root certificate construction [4](#0-3) 

**2. State Synchronization**: Conditional fork handling [5](#0-4) 

**3. Certificate Validation**: Methods that panic if called with wrong flag value [6](#0-5) 

When validators operate with different `order_vote_enabled` values:
- They construct different recovery data structures with incompatible root certificates
- During fast-forward sync, some validators fetch additional fork blocks while others skip this step
- They have divergent internal state representations of the same blockchain
- They may call methods that are incompatible with their actual configuration, causing panics or incorrect behavior

## Impact Explanation

**Severity: Medium to High**

This vulnerability can cause:

1. **State Inconsistencies**: Validators with mismatched `order_vote_enabled` settings will have different internal representations of the blockchain state, violating the "Deterministic Execution" and "State Consistency" invariants.

2. **Consensus Disagreements**: Affected validators may fail to properly validate or sync with the rest of the network, potentially causing voting failures or inability to reach consensus.

3. **Validator Stuck in Recovery**: A validator with the wrong setting may fail during recovery or sync operations when methods are called with incompatible flag values, causing panics or errors.

4. **Potential Chain Divergence**: In worst-case scenarios, if multiple validators are affected simultaneously, this could lead to temporary chain splits requiring manual intervention.

This meets **Medium Severity** criteria per the Aptos bug bounty program: "State inconsistencies requiring intervention." It could escalate to **High Severity** if it causes significant protocol violations affecting multiple validators.

## Likelihood Explanation

**Likelihood: Medium**

This issue can be triggered by:

1. **Transient Network Failures**: During epoch changes, temporary network disruptions can prevent successful config fetches
2. **Deserialization Errors**: The config requires double BCS deserialization [7](#0-6) , which can fail with corrupted or incompatible data
3. **Malicious Peers**: An adversary could provide corrupted epoch change proofs to cause deserialization failures
4. **Storage Issues**: Temporary storage corruption or read failures during critical epoch transitions

The silent fallback behavior (only logging a warning) makes this particularly dangerous because:
- Operators may not immediately notice the configuration mismatch
- The validator continues operating with incorrect parameters
- The issue only manifests during recovery or sync operations, which may be delayed

The vulnerability is not theoretical—any validator experiencing config fetch failures during epoch changes will be affected.

## Recommendation

**Fix 1: Make defaults consistent**

Align `default_if_missing()` with `default_for_genesis()`: [2](#0-1) 

Change to:
```rust
pub fn default_if_missing() -> Self {
    Self::JolteonV2 {
        main: ConsensusConfigV1::default(),
        quorum_store_enabled: true,
        order_vote_enabled: true,  // Changed from false to true
    }
}
```

**Fix 2: Make fallback explicit and fail-safe**

Instead of silently falling back, require explicit handling: [8](#0-7) 

Change to:
```rust
if let Err(error) = &onchain_consensus_config {
    error!("CRITICAL: Failed to read on-chain consensus config: {}", error);
    // Either panic or enter safe mode
    panic!("Cannot proceed without valid consensus config");
}
let consensus_config = onchain_consensus_config.unwrap();
```

**Fix 3: Add validation check**

Add runtime validation to detect mismatched configurations:
```rust
// After fetching config, validate it matches network expectations
if consensus_config.order_vote_enabled() != expected_order_vote_enabled {
    panic!("Consensus config mismatch: order_vote_enabled={} but expected={}",
           consensus_config.order_vote_enabled(), expected_order_vote_enabled);
}
```

**Recommended approach**: Implement Fix 1 (consistency) AND add explicit error handling (Fix 2 variant that enters safe recovery mode rather than silent fallback).

## Proof of Concept

```rust
// Reproduction steps to demonstrate the vulnerability:

#[test]
fn test_config_fallback_inconsistency() {
    use aptos_types::on_chain_config::{
        OnChainConsensusConfig, ConsensusAlgorithmConfig
    };
    
    // Network initialized with genesis config
    let genesis_config = OnChainConsensusConfig::default_for_genesis();
    assert_eq!(genesis_config.order_vote_enabled(), true);
    
    // Validator fails to fetch config and uses default
    let fallback_config = OnChainConsensusConfig::default();
    assert_eq!(fallback_config.order_vote_enabled(), false);
    
    // CRITICAL: These two configs are incompatible!
    // Validators using genesis_config vs fallback_config will:
    // 1. Call different code paths during recovery
    // 2. Construct different root certificates
    // 3. Handle forks differently during sync
    // 4. Have incompatible internal states
    
    println!("Genesis order_vote_enabled: {}", genesis_config.order_vote_enabled());
    println!("Fallback order_vote_enabled: {}", fallback_config.order_vote_enabled());
    println!("MISMATCH DETECTED - Consensus divergence possible!");
}

// To trigger in practice:
// 1. Initialize network with genesis config (order_vote_enabled: true)
// 2. During epoch change, simulate config fetch failure on one validator:
//    - Corrupt the on-chain config bytes
//    - Cause network timeout during payload fetch
//    - Trigger deserialization error
// 3. Affected validator falls back to default (order_vote_enabled: false)
// 4. During next recovery/sync, observe state divergence:
//    - Check persistent_liveness_storage.rs line 519 execution path
//    - Monitor sync_manager.rs line 413 fork handling
//    - Validator will have different RecoveryData than peers
```

## Notes

The root cause is that `default_if_missing()` was designed to provide safe defaults when the on-chain config has never been initialized, but it's also used as a fallback during fetch failures in an already-running network. These two scenarios require different default values—the former can use conservative defaults, but the latter must match the network's actual configuration.

The silent warning-only error handling exacerbates this issue by not alerting operators to the configuration mismatch until consensus problems manifest.

Additional affected components beyond those cited:
- Block storage operations: [9](#0-8) 
- Buffer manager: [10](#0-9) 
- Recovery manager: [11](#0-10) 

This vulnerability demonstrates that careful attention must be paid to fallback mechanisms in distributed consensus systems, as silent configuration mismatches can lead to subtle but critical divergences.

### Citations

**File:** types/src/on_chain_config/consensus_config.rs (L30-36)
```rust
    pub fn default_for_genesis() -> Self {
        Self::JolteonV2 {
            main: ConsensusConfigV1::default(),
            quorum_store_enabled: true,
            order_vote_enabled: true,
        }
    }
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

**File:** types/src/on_chain_config/consensus_config.rs (L464-468)
```rust
    fn deserialize_into_config(bytes: &[u8]) -> Result<Self> {
        let raw_bytes: Vec<u8> = bcs::from_bytes(bytes)?;
        bcs::from_bytes(&raw_bytes)
            .map_err(|e| format_err!("[on-chain config] Failed to deserialize into config: {}", e))
    }
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

**File:** consensus/src/persistent_liveness_storage.rs (L244-262)
```rust
        let (root_ordered_cert, root_commit_cert) = if order_vote_enabled {
            // We are setting ordered_root same as commit_root. As every committed block is also ordered, this is fine.
            // As the block store inserts all the fetched blocks and quorum certs and execute the blocks, the block store
            // updates highest_ordered_cert accordingly.
            let root_ordered_cert =
                WrappedLedgerInfo::new(VoteData::dummy(), latest_ledger_info_sig.clone());
            (root_ordered_cert.clone(), root_ordered_cert)
        } else {
            let root_ordered_cert = quorum_certs
                .iter()
                .find(|qc| qc.commit_info().id() == root_block.id())
                .ok_or_else(|| format_err!("No LI found for root: {}", root_id))?
                .clone()
                .into_wrapped_ledger_info();
            let root_commit_cert = root_ordered_cert
                .create_merged_with_executed_state(latest_ledger_info_sig)
                .expect("Inconsistent commit proof and evaluation decision, cannot commit block");
            (root_ordered_cert, root_commit_cert)
        };
```

**File:** consensus/src/block_storage/sync_manager.rs (L413-459)
```rust
        if !order_vote_enabled {
            // TODO: this is probably still necessary, but need to think harder, it's pretty subtle
            // check if highest_commit_cert comes from a fork
            // if so, we need to fetch it's block as well, to have a proof of commit.
            let highest_commit_certified_block =
                highest_commit_cert.certified_block(order_vote_enabled)?;
            if !blocks
                .iter()
                .any(|block| block.id() == highest_commit_certified_block.id())
            {
                info!(
                    "Found forked QC {}, fetching it as well",
                    highest_commit_cert
                );
                BLOCKS_FETCHED_FROM_NETWORK_WHILE_FAST_FORWARD_SYNC.inc_by(1);

                // Only retrieving one block here, we can simply use TargetBlockRetrieval::TargetBlockId
                let target_block_retrieval_payload =
                    TargetBlockRetrieval::TargetBlockId(highest_commit_certified_block.id());
                let mut additional_blocks = retriever
                    .retrieve_blocks_in_range(
                        highest_commit_certified_block.id(),
                        1,
                        target_block_retrieval_payload,
                        highest_commit_cert
                            .ledger_info()
                            .get_voters(&retriever.validator_addresses()),
                    )
                    .await?;

                assert_eq!(additional_blocks.len(), 1);
                let block = additional_blocks.pop().expect("blocks are empty");
                assert_eq!(
                    block.id(),
                    highest_commit_certified_block.id(),
                    "Expecting in the retrieval response, for commit certificate fork, first block should be {}, but got {}",
                    highest_commit_certified_block.id(),
                    block.id(),
                );
                blocks.push(block);
                quorum_certs.push(
                    highest_commit_cert
                        .clone()
                        .into_quorum_cert(order_vote_enabled)?,
                );
            }
        }
```

**File:** consensus/consensus-types/src/wrapped_ledger_info.rs (L64-71)
```rust
    pub fn certified_block(&self, order_vote_enabled: bool) -> anyhow::Result<&BlockInfo> {
        ensure!(
            !order_vote_enabled,
            "wrapped_ledger_info.certified_block should not be called when order votes are enabled"
        );
        self.verify_consensus_data_hash()?;
        Ok(self.vote_data.proposed())
    }
```

**File:** consensus/src/block_storage/block_store.rs (L98-98)
```rust
    order_vote_enabled: bool,
```

**File:** consensus/src/pipeline/buffer_manager.rs (L156-156)
```rust
    order_vote_enabled: bool,
```

**File:** consensus/src/recovery_manager.rs (L37-37)
```rust
    order_vote_enabled: bool,
```
