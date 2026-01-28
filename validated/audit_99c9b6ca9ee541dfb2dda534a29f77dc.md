# Audit Report

## Title
Byzantine Signature Grinding Attack via Unbounded OptProposalMsg Verification

## Summary
A Byzantine proposer can force validators to perform expensive cryptographic verification operations multiple times for the same consensus round by sending OptProposalMsg variants with different payloads. The verification happens before deduplication checks, enabling a computational resource exhaustion attack that can degrade validator performance.

## Finding Description
The vulnerability exists in the consensus message processing pipeline where expensive cryptographic verification occurs before any duplicate proposal detection.

When an `OptProposalMsg` is received in the `EpochManager`, it immediately spawns an asynchronous verification task on the bounded executor without checking for duplicates: [1](#0-0) 

This verification performs two expensive cryptographic operations in parallel using `rayon::join`: [2](#0-1) 

The payload verification checks ProofOfStore signatures, which are cached by `BatchInfoExt`: [3](#0-2) [4](#0-3) 

Since different payloads have different `BatchInfoExt` keys, the cache provides no protection against proposals with varying payloads.

The QC verification performs BLS aggregate signature verification without any caching mechanism: [5](#0-4) 

The duplicate proposal check only happens later in `process_proposal` after verification completes: [6](#0-5) 

The `UnequivocalProposerElection` tracks duplicates by comparing block IDs for the same round: [7](#0-6) 

**Attack Scenario:**

A Byzantine proposer can:
1. Create N different `OptProposalMsg` instances for round R with the same epoch and grandparent QC but different payloads
2. Broadcast all N messages to validators  
3. Each validator spawns N verification tasks
4. Each task performs expensive cryptographic operations (QC + payload verification)
5. Only after all N verifications complete does the duplicate detection reject them

The bounded executor limits concurrency but doesn't prevent the attack - it only provides backpressure. An attacker can still saturate the verification queue and force redundant expensive computations.

Note: This same vulnerability pattern also affects regular `ProposalMsg`: [8](#0-7) 

## Impact Explanation
This is a **Medium Severity** vulnerability per the Aptos bug bounty criteria ($10,000 tier):

**Validator Node Slowdowns**: A Byzantine proposer can saturate validator CPU resources with redundant verification tasks, causing processing delays. This can lead to:
- Slower processing of legitimate proposals
- Potential timeout rounds if validators are overwhelmed
- Degraded consensus performance during the attacker's proposer rounds

The attack does NOT cause:
- Loss of funds
- Consensus safety violations  
- Permanent network partition
- Total liveness failure

The impact is **temporary** and **localized** to rounds where the Byzantine validator is elected as proposer. The bounded executor provides some mitigation by limiting concurrent tasks. Consensus will timeout and progress to the next round, so this doesn't create permanent harm.

This aligns with "Limited Protocol Violations" and "Temporary liveness issues" in the Medium Severity tier rather than the High Severity "Validator Node Slowdowns" category because the impact is not permanent or catastrophic.

## Likelihood Explanation
**High likelihood of exploitation:**

1. **Low barrier to entry**: Any validator with Byzantine behavior (within the < 1/3 threat model) can execute this when elected as proposer
2. **Simple execution**: Only requires constructing multiple valid `OptProposalMsg` with different payloads and broadcasting them
3. **No cryptographic breaks needed**: Uses legitimate message formats with valid signatures
4. **Hard to distinguish from network issues**: Multiple proposals could appear as network retries or timing issues
5. **Repeatable**: Can be executed in every round where the attacker is the proposer
6. **Amplification**: One malicious proposer forces all N validators to perform N×(QC verification + payload verification)

The attack is technically feasible and economically rational for a Byzantine actor seeking to degrade network performance.

## Recommendation
Implement duplicate proposal detection **before** expensive cryptographic verification:

1. **Early deduplication in EpochManager**: Check for duplicate proposals by (epoch, round, proposer) before spawning verification tasks
2. **Add QC verification caching**: Cache verified QC signatures to avoid redundant BLS verification
3. **Lightweight pre-checks**: Validate basic message structure and proposer eligibility before expensive crypto operations
4. **Rate limiting per proposer**: Limit the number of concurrent verification tasks per proposer to bound the attack surface

Example fix location: [9](#0-8) 

Add a duplicate tracking mechanism before line 1587 that checks if a proposal for (epoch, round, proposer) is already being verified or has been processed.

## Proof of Concept
A Byzantine validator can execute this attack by:

```rust
// Pseudocode for attack
let byzantine_proposer = get_proposer_for_round(current_round);
if byzantine_proposer == self.address {
    let base_proposal = create_opt_proposal(current_round);
    
    // Create N variants with different payloads
    for i in 0..N {
        let different_payload = create_unique_payload(i);
        let variant = OptProposalMsg::new(
            OptBlockData::new(
                vec![],
                different_payload, // Different BatchInfo entries
                self.author,
                base_proposal.epoch(),
                base_proposal.round(),
                base_proposal.timestamp_usecs(),
                base_proposal.parent().clone(),
                base_proposal.grandparent_qc().clone(), // Same QC
            ),
            base_proposal.sync_info().clone(),
        );
        
        // Broadcast to all validators
        network.broadcast(variant);
    }
    // All validators now verify N times before detecting duplicates
}
```

Each validator will spawn N verification tasks on the bounded executor, each performing:
- BLS aggregate signature verification on the grandparent QC (no caching)
- Multi-signature verification on each BatchInfo in the payload (cache miss due to different BatchInfo)

The duplicate detection in `UnequivocalProposerElection::is_valid_proposal` only triggers after all N verifications complete in `process_proposal`.

**Notes**

- This vulnerability affects BOTH `OptProposalMsg` and regular `ProposalMsg` as they share the same verification-before-deduplication pattern
- The bounded executor provides limited protection but doesn't prevent the attack
- The severity is Medium rather than High because the impact is temporary and limited to the attacker's proposer rounds
- This is a protocol design flaw, not a simple network DoS attack (which would be out of scope)

### Citations

**File:** consensus/src/epoch_manager.rs (L1562-1586)
```rust
        let maybe_unverified_event = self.check_epoch(peer_id, consensus_msg).await?;

        if let Some(unverified_event) = maybe_unverified_event {
            // filter out quorum store messages if quorum store has not been enabled
            match self.filter_quorum_store_events(peer_id, &unverified_event) {
                Ok(true) => {},
                Ok(false) => return Ok(()), // This occurs when the quorum store is not enabled, but the recovery mode is enabled. We filter out the messages, but don't raise any error.
                Err(err) => return Err(err),
            }
            // same epoch -> run well-formedness + signature check
            let epoch_state = self
                .epoch_state
                .clone()
                .ok_or_else(|| anyhow::anyhow!("Epoch state is not available"))?;
            let proof_cache = self.proof_cache.clone();
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
```

**File:** consensus/src/epoch_manager.rs (L1587-1599)
```rust
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

**File:** consensus/consensus-types/src/opt_proposal_msg.rs (L110-119)
```rust
        let (payload_verify_result, qc_verify_result) = rayon::join(
            || {
                self.block_data()
                    .payload()
                    .verify(validator, proof_cache, quorum_store_enabled)
            },
            || self.block_data().grandparent_qc().verify(validator),
        );
        payload_verify_result?;
        qc_verify_result?;
```

**File:** consensus/consensus-types/src/proof_of_store.rs (L616-616)
```rust
pub type ProofCache = Cache<BatchInfoExt, AggregateSignature>;
```

**File:** consensus/consensus-types/src/proof_of_store.rs (L635-650)
```rust
    pub fn verify(&self, validator: &ValidatorVerifier, cache: &ProofCache) -> anyhow::Result<()> {
        let batch_info_ext: BatchInfoExt = self.info.clone().into();
        if let Some(signature) = cache.get(&batch_info_ext) {
            if signature == self.multi_signature {
                return Ok(());
            }
        }
        let result = validator
            .verify_multi_signatures(&self.info, &self.multi_signature)
            .context(format!(
                "Failed to verify ProofOfStore for batch: {:?}",
                self.info
            ));
        if result.is_ok() {
            cache.insert(batch_info_ext, self.multi_signature.clone());
        }
```

**File:** consensus/consensus-types/src/quorum_cert.rs (L143-147)
```rust
        self.ledger_info()
            .verify_signatures(validator)
            .context("Fail to verify QuorumCert")?;
        self.vote_data.verify()?;
        Ok(())
```

**File:** consensus/src/round_manager.rs (L1195-1200)
```rust
        ensure!(
            self.proposer_election.is_valid_proposal(&proposal),
            "[RoundManager] Proposer {} for block {} is not a valid proposer for this round or created duplicate proposal",
            author,
            proposal,
        );
```

**File:** consensus/src/liveness/unequivocal_proposer_election.rs (L61-86)
```rust
            let mut already_proposed = self.already_proposed.lock();
            // detect if the leader proposes more than once in this round
            match block.round().cmp(&already_proposed.0) {
                Ordering::Greater => {
                    already_proposed.0 = block.round();
                    already_proposed.1 = block.id();
                    true
                },
                Ordering::Equal => {
                    if already_proposed.1 != block.id() {
                        error!(
                            SecurityEvent::InvalidConsensusProposal,
                            "Multiple proposals from {} for round {}: {} and {}",
                            author,
                            block.round(),
                            already_proposed.1,
                            block.id()
                        );
                        false
                    } else {
                        true
                    }
                },
                Ordering::Less => false,
            }
        })
```

**File:** consensus/consensus-types/src/proposal_msg.rs (L97-100)
```rust
        let (payload_result, sig_result) = rayon::join(
            || {
                self.proposal().payload().map_or(Ok(()), |p| {
                    p.verify(validator, proof_cache, quorum_store_enabled)
```
