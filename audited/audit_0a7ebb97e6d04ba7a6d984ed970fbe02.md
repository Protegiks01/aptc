Based on my comprehensive analysis of the Aptos Core codebase, I have validated this security claim and confirm it is a **VALID HIGH severity vulnerability**.

# Audit Report

## Title
Consensus Configuration Deserialization Failures Cause Silent Fallback to Incompatible Default Parameters Leading to Consensus Splits

## Summary
When `OnChainConsensusConfig` deserialization fails during epoch transitions due to I/O errors or database corruption, nodes silently fall back to hardcoded default consensus parameters (`quorum_store_enabled: true`) that may differ from the network's actual on-chain configuration. This causes nodes with different configurations to reject each other's blocks, leading to consensus disagreements and liveness failures without requiring any malicious actors.

## Finding Description

During epoch transitions, the consensus configuration is loaded from on-chain state via `payload.get()` which performs two rounds of BCS deserialization. [1](#0-0) 

When deserialization fails, the code logs a warning but continues execution by falling back to `OnChainConsensusConfig::default()`. [2](#0-1) 

The default configuration returns `quorum_store_enabled: true` via `ConsensusAlgorithmConfig::default_if_missing()`. [3](#0-2) [4](#0-3) 

This flag is then used to set `self.quorum_store_enabled` during epoch initialization. [5](#0-4) [6](#0-5) 

When processing proposals, this flag is passed through the verification pipeline to `Payload::verify()`. [7](#0-6) [8](#0-7) 

The `Payload::verify()` method validates that the payload type matches the `quorum_store_enabled` configuration, rejecting mismatches with "Wrong payload type" error. [9](#0-8) 

When verification fails, the proposal is logged as invalid and **dropped without forwarding to the round manager**, meaning the node will not vote on this block. [10](#0-9) 

**Consensus Split Scenario:**
1. Network configured with `quorum_store_enabled: false` via governance
2. Node A successfully loads config: `quorum_store_enabled = false`
3. Node B experiences disk I/O error during config read, falls back to default: `quorum_store_enabled = true`
4. Node A proposes block with `Payload::DirectMempool` (matching its config)
5. Node B verifies with `quorum_store_enabled: true`, hits catchall case, rejects block
6. Node B drops the proposal without voting
7. If enough nodes (>1/3) are affected, network loses liveness

This breaks the consensus safety invariant that AptosBFT must maintain agreement under < 1/3 Byzantine nodes.

## Impact Explanation

**Severity: HIGH** - Significant Protocol Violations

This vulnerability causes consensus disagreements leading to:

1. **Consensus Fragmentation**: Nodes with different configurations reject each other's blocks, fragmenting the validator set
2. **Liveness Failures**: If sufficient nodes fall back to incompatible defaults, the network cannot reach quorum
3. **Non-Deterministic Failures**: Can occur randomly to different nodes based on infrastructure state
4. **Persistent Incorrect State**: Nodes remain misconfigured for the entire epoch unless manually restarted

This meets **High Severity** criteria per the Aptos bug bounty program as it causes "significant protocol violations" and "validator node slowdowns" through consensus disagreement.

It does not meet Critical severity because:
- No fund loss occurs
- Recovery is possible via node restart (no hardfork required)
- Requires specific infrastructure failure conditions

## Likelihood Explanation

**Likelihood: MEDIUM**

Triggering conditions:
1. **Transient I/O Errors**: Disk read failures during on-chain config loading from AptosDB
2. **Database Corruption**: Corrupted bytes in the consensus config resource
3. **State Sync Issues**: Incomplete state during synchronization
4. **Concurrent Access**: Race conditions during epoch transition state reads

This can occur naturally in production environments where validators experience infrastructure issues. The vulnerability affects multiple components that load `OnChainConsensusConfig`:
- Main consensus epoch manager (validators)
- Consensus observer (fullnodes) [11](#0-10) 
- JWK consensus epoch manager
- DKG epoch manager

No attacker action is required. While not extremely common (depends on infrastructure reliability and epoch transition frequency), the impact when triggered is significant enough to warrant attention.

## Recommendation

Replace the silent fallback behavior with explicit failure handling:

1. **Fail-Stop Approach** (Recommended): If on-chain config deserialization fails, the node should halt and require operator intervention rather than continuing with potentially incompatible defaults
2. **Retry with Exponential Backoff**: Implement retry logic before falling back
3. **Config Validation**: Add cross-validation with peer nodes to detect config mismatches before starting the epoch
4. **Alerting**: Emit critical alerts when fallback occurs, not just warnings

The current pattern of `unwrap_or_default()` is unsafe for critical consensus parameters where different defaults can cause network-wide disagreement.

## Proof of Concept

The vulnerability exists in the current codebase and can be demonstrated by:

1. Setting up a network with `quorum_store_enabled: false` via on-chain governance
2. Simulating disk I/O error on one validator during epoch transition (inject fault during `payload.get()` call)
3. Observing that the affected node falls back to `quorum_store_enabled: true`
4. The affected node will reject all `Payload::DirectMempool` blocks from correctly configured nodes
5. Monitor consensus metrics to observe the node's inability to participate in voting

This demonstrates the consensus disagreement without requiring any malicious actors.

### Citations

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

**File:** consensus/src/epoch_manager.rs (L1342-1342)
```rust
        self.quorum_store_enabled = self.enable_quorum_store(consensus_config);
```

**File:** consensus/src/epoch_manager.rs (L1523-1526)
```rust
    fn enable_quorum_store(&mut self, onchain_config: &OnChainConsensusConfig) -> bool {
        fail_point!("consensus::start_new_epoch::disable_qs", |_| false);
        onchain_config.quorum_store_enabled()
    }
```

**File:** consensus/src/epoch_manager.rs (L1577-1599)
```rust
            let quorum_store_enabled = self.quorum_store_enabled;
            let quorum_store_msg_tx = self.quorum_store_msg_tx.clone();
            let buffered_proposal_tx = self.buffered_proposal_tx.clone();
            let round_manager_tx = self.round_manager_tx.clone();
            let my_peer_id = self.author;
            let max_num_batches = self.config.quorum_store.receiver_max_num_batches;
            let max_batch_expiry_gap_usecs =
                self.config.quorum_store.batch_expiry_gap_when_init_usecs;
            let payload_manager = self.payload_manager.clone();
            let pending_blocks = self.pending_blocks.clone();
            self.bounded_executor
                .spawn(async move {
                    match monitor!(
                        "verify_message",
                        unverified_event.clone().verify(
                            peer_id,
                            &epoch_state.verifier,
                            &proof_cache,
                            quorum_store_enabled,
                            peer_id == my_peer_id,
                            max_num_batches,
                            max_batch_expiry_gap_usecs,
                        )
```

**File:** consensus/src/epoch_manager.rs (L1612-1619)
```rust
                        Err(e) => {
                            error!(
                                SecurityEvent::ConsensusInvalidMessage,
                                remote_peer = peer_id,
                                error = ?e,
                                unverified_event = unverified_event
                            );
                        },
```

**File:** consensus/src/round_manager.rs (L120-122)
```rust
            UnverifiedEvent::ProposalMsg(p) => {
                if !self_message {
                    p.verify(peer_id, validator, proof_cache, quorum_store_enabled)?;
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
