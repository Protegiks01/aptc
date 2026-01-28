# Audit Report

## Title
Byzantine Signature Grinding Attack via Unbounded OptProposalMsg Verification

## Summary
A Byzantine proposer can force validators to perform redundant expensive cryptographic verification operations by sending multiple OptProposalMsg variants with different payloads for the same consensus round. The verification pipeline processes these messages before duplicate detection, enabling a computational resource exhaustion attack that degrades validator performance.

## Finding Description

The vulnerability exists in the consensus message processing pipeline where expensive cryptographic verification occurs before any duplicate proposal detection.

When an `OptProposalMsg` is received, the `EpochManager` immediately spawns an asynchronous verification task on the bounded executor without checking for duplicates. [1](#0-0) 

This verification performs two expensive cryptographic operations in parallel using `rayon::join` - payload verification and grandparent QC verification. [2](#0-1) 

The payload verification uses a ProofCache that keys on `BatchInfoExt`, meaning different payloads with different batch information will have different cache keys and bypass the cache entirely. [3](#0-2) 

The QC verification performs BLS aggregate signature verification with no caching mechanism at all. [4](#0-3) 

The duplicate proposal check only happens later in `process_proposal` through the `UnequivocalProposerElection` mechanism, which compares block IDs for the same round. [5](#0-4) [6](#0-5) 

**Attack Scenario:**

A Byzantine proposer can:
1. Create N different `OptProposalMsg` instances for round R with identical epoch and grandparent QC but different payloads (different transactions/batches)
2. Broadcast all N messages to validators through the network
3. Each validator spawns N verification tasks on the bounded executor
4. Each task performs expensive cryptographic operations (QC signature verification + payload ProofOfStore verification)
5. The bounded executor processes up to 16 concurrent verifications (default configuration) and queues the rest [7](#0-6) 
6. Only after all verifications complete does the duplicate detection in `is_valid_proposal` reject them

The bounded executor limits concurrency but doesn't prevent the attack - it provides backpressure by blocking on `acquire_permit()`, but an attacker can still saturate the verification queue with redundant expensive computations.

Note: This same vulnerability pattern also affects regular `ProposalMsg` which uses identical verification logic with `rayon::join`. [8](#0-7) 

## Impact Explanation

This is a **Medium Severity** vulnerability per the Aptos bug bounty criteria ($10,000 tier), aligning with "Limited Protocol Violations" and "Temporary liveness issues."

**Impact:**
- **Validator CPU Saturation**: Byzantine proposers can force redundant cryptographic verifications, consuming validator CPU resources
- **Processing Delays**: Legitimate proposals may experience slower processing due to verification queue saturation
- **Potential Timeout Rounds**: If validators are sufficiently overwhelmed, they may timeout on legitimate proposals
- **Degraded Consensus Performance**: Network performance degrades during rounds where the attacker is proposer

**Limitations:**
- Attack is **temporary** and **localized** to rounds where the Byzantine validator is elected as proposer
- Does NOT cause: Loss of funds, consensus safety violations, permanent network partition, or total liveness failure
- Bounded executor (default 16 concurrent tasks) provides partial mitigation
- Consensus timeout mechanisms ensure the network progresses to the next round
- Security events are logged when duplicate proposals are detected

The impact is NOT permanent or catastrophic enough for High Severity "Validator Node Slowdowns" ($50k tier), but represents a valid protocol-level resource exhaustion vulnerability causing temporary degradation.

## Likelihood Explanation

**High likelihood of exploitation:**

1. **Low barrier to entry**: Any validator exhibiting Byzantine behavior (within the < 1/3 BFT threshold) can execute this attack when elected as proposer
2. **Simple execution**: Only requires constructing multiple valid `OptProposalMsg` with different payloads (different transaction batches) and broadcasting them to the network
3. **No cryptographic breaks needed**: Uses legitimate message formats with valid BLS signatures - all messages pass cryptographic verification
4. **Hard to distinguish from benign behavior**: Multiple proposals could appear as network retries, clock skew, or timing issues during normal operation
5. **Repeatable**: Can be executed in every round where the attacker is elected as proposer (1/N probability per round for N validators)
6. **Amplification factor**: One malicious proposer forces all N validators in the network to perform N×(QC verification + payload verification) operations

The attack is technically feasible, requires no special access beyond validator status, and is economically rational for a Byzantine actor seeking to degrade network performance without triggering obvious consensus violations.

## Recommendation

Implement early duplicate detection before spawning expensive verification tasks:

1. **Add pre-verification duplicate check**: Before spawning verification on the bounded executor, check if a proposal has already been received for the same (epoch, round, proposer) tuple. Track this in a lightweight cache in `EpochManager`.

2. **Implement QC verification caching**: Cache verified grandparent QCs similar to how payload ProofOfStore signatures are cached. Use QC digest as the cache key.

3. **Add rate limiting per proposer**: Limit the number of unverified proposals that can be queued per proposer to prevent queue saturation.

4. **Consider fail-fast validation**: Perform lightweight validity checks (correct round, valid proposer for round) before expensive cryptographic verification.

Example mitigation approach:
```rust
// In EpochManager, before spawning verification
let proposal_key = (proposal.epoch(), proposal.round(), proposal.proposer());
if self.pending_proposals.contains_key(&proposal_key) {
    // Duplicate proposal, reject without verification
    return Ok(());
}
self.pending_proposals.insert(proposal_key, ());
```

## Proof of Concept

The vulnerability can be demonstrated by:

1. Setting up a local Aptos testnet with multiple validator nodes
2. Implementing a Byzantine proposer that, when elected, constructs multiple `OptProposalMsg` instances with:
   - Same epoch and round
   - Same grandparent QC
   - Different payloads (different transaction batches)
3. Broadcasting all messages simultaneously to all validators
4. Monitoring validator CPU usage and verification queue depth
5. Observing that all N messages trigger full cryptographic verification before duplicate detection rejects them

Expected behavior: Validators perform N full verifications (QC + payload) before rejecting duplicates.

Proper behavior: Only the first proposal should trigger full verification; subsequent duplicates should be rejected early.

---

**Notes:**
- This is a protocol-level resource exhaustion vulnerability, distinct from network-layer DoS attacks which are out of scope
- The vulnerability exists in both OptProposalMsg and ProposalMsg verification pipelines
- While mitigations exist (bounded executor, timeouts), they limit impact rather than prevent the attack
- The attack exploits a design inefficiency where expensive operations occur before cheap duplicate checks
- Impact is temporary and localized, justifying Medium rather than High severity classification

### Citations

**File:** consensus/src/epoch_manager.rs (L1587-1600)
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
                    ) {
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

**File:** consensus/consensus-types/src/proof_of_store.rs (L635-641)
```rust
    pub fn verify(&self, validator: &ValidatorVerifier, cache: &ProofCache) -> anyhow::Result<()> {
        let batch_info_ext: BatchInfoExt = self.info.clone().into();
        if let Some(signature) = cache.get(&batch_info_ext) {
            if signature == self.multi_signature {
                return Ok(());
            }
        }
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

**File:** crates/bounded-executor/src/executor.rs (L41-52)
```rust
    /// Spawn a [`Future`] on the `BoundedExecutor`. This function is async and
    /// will block if the executor is at capacity until one of the other spawned
    /// futures completes. This function returns a [`JoinHandle`] that the caller
    /// can `.await` on for the results of the [`Future`].
    pub async fn spawn<F>(&self, future: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let permit = self.acquire_permit().await;
        self.executor.spawn(future_with_permit(future, permit))
    }
```

**File:** consensus/consensus-types/src/proposal_msg.rs (L97-110)
```rust
        let (payload_result, sig_result) = rayon::join(
            || {
                self.proposal().payload().map_or(Ok(()), |p| {
                    p.verify(validator, proof_cache, quorum_store_enabled)
                })
            },
            || {
                self.proposal()
                    .validate_signature(validator)
                    .map_err(|e| format_err!("{:?}", e))
            },
        );
        payload_result?;
        sig_result?;
```
