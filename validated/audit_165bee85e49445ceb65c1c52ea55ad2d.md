# Audit Report

## Title
Unbounded Dealer Count in DKG Transcript Verification Enables Computational DoS Attack

## Summary
A malicious validator can submit a DKG transcript with an excessive number of dealer proofs (up to the full validator set size), forcing all validators to perform expensive multi-exponentiation operations during verification without any early bounds checking, causing computational resource exhaustion and validator slowdowns.

## Finding Description

The DKG (Distributed Key Generation) transcript verification flow contains a computational DoS vulnerability where the number of dealers (and their associated Schnorr proofs) is not validated before performing expensive cryptographic operations.

**Attack Flow:**

1. During DKG, validators generate individual transcripts and aggregate them to reach quorum (typically 2/3+1 of validators).

2. A malicious validator collects transcripts from ALL validators in the network (not just quorum) and aggregates them using the `aggregate_with` function, which unconditionally appends all dealer proofs without size limits. [1](#0-0) 

3. The attacker submits this maximally-aggregated transcript as a DKG validator transaction to their local validator transaction pool. When the malicious validator becomes a block proposer, this transcript is included in their proposed block. [2](#0-1) 

4. When other validators receive and process the proposal containing this transaction, consensus verification calls `vtxn.verify()` which performs voting power checks but only validates that the aggregated power meets or exceeds quorum threshold, not that it's within reasonable bounds. [3](#0-2)  The voting power check only ensures `aggregated_voting_power >= quorum_voting_power`, allowing transcripts with all validators to pass. [4](#0-3) 

5. Subsequently, during block execution, the VM calls `DefaultDKG::verify_transcript` without any check on the number of dealers. [5](#0-4) 

6. The verification function only validates that dealer indices are valid (within validator set bounds), but does NOT check if the number of dealers is reasonable or exceeds what's necessary for quorum. [6](#0-5) 

7. The verification proceeds to the underlying PVSS transcript verification, which calls `batch_verify_soks` to extract and verify all proof-of-knowledge elements. [7](#0-6) 

8. The `batch_verify_soks` function calls `pok_batch_verify` with all dealer proofs. [8](#0-7) 

9. The `pok_batch_verify` function allocates vectors with capacity `2*n+1` and performs multi-exponentiation with all `2*n+1` bases, where `n` is the number of dealer proofs. [9](#0-8) 

**The Critical Vulnerability:**

For a network with 500 validators:
- **Normal case**: ~334 dealers (2/3 quorum) = 669 multi-exponentiations
- **Attack case**: 500 dealers (all validators) = 1,001 multi-exponentiations  
- **Overhead**: ~50% additional computation per validator

The multi-exponentiation operation on BLS12-381 elliptic curve points is computationally expensive (O(n) group operations with logarithmic factors). Forcing this on ALL validators synchronously during block verification can cause:
- Increased block processing latency
- CPU resource exhaustion
- Delayed consensus progress
- Potential timeout failures in block verification

**Why This Breaks Security Invariants:**

This violates the Resource Limits security invariant: "All operations must respect gas, storage, and computational limits." The verification performs unbounded computation proportional to the number of dealers without checking if it exceeds reasonable limits before executing the expensive cryptographic operations.

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos bug bounty program for the following reasons:

1. **Validator Node Slowdowns**: The attack directly causes increased computational load on all validator nodes through resource exhaustion. While "Validator node slowdowns" is typically categorized as High severity, this specific case warrants Medium severity due to:
   - The computational overhead (~50%) is significant but not catastrophic
   - The base case already involves expensive operations, limiting the delta
   - Attack can only occur when the malicious validator becomes proposer (periodic but not constant)

2. **Network-Wide Impact**: Every validator must verify the malicious transcript when processing the block, affecting the entire network synchronously during that block's execution.

3. **Repeatable Attack**: The attacker can include such transcripts in every block they propose across different epochs, sustaining the DoS effect over time.

**Severity Justification:**
- Not Critical: Does not cause fund loss, consensus violations, network halts, or permanent damage
- Not High: Does not cause crashes, permanent degradation, or API failures
- Medium: Causes computational resource exhaustion with temporary but significant performance impact that can be repeated periodically

## Likelihood Explanation

**Likelihood: Medium-High**

**Attacker Requirements:**
- Must be a validator in the current epoch (achievable through staking - open participation)
- Must collect transcripts from all validators during DKG (publicly available through network gossip)
- Must wait to become block proposer (happens periodically through leader election)

**Execution Complexity:**
- Low technical complexity - simply continue aggregating legitimate transcripts beyond quorum
- No cryptographic attacks or signature forgery required
- Can be automated and repeated in every epoch where the attacker is a validator

**Detection Difficulty:**
- The malicious transcript contains valid signatures and proofs from real validators
- Appears cryptographically legitimate and passes all existing validation checks
- No mechanism exists to distinguish "excessive but valid" from "optimal" transcript sizes
- Computational cost is only incurred after full verification begins

**Practical Feasibility:**
- An adversarial validator can execute this attack each time they become proposer
- The cost to the attacker is minimal (offline aggregation overhead)
- The cost to all other validators is substantial (synchronous verification overhead)
- Attack can be sustained across multiple epochs

## Recommendation

Implement an upper bound check on the number of dealers before performing expensive cryptographic verification operations. The check should be added in the VM verification path to reject transcripts that significantly exceed quorum requirements.

**Suggested Fix:**

In `types/src/dkg/real_dkg/mod.rs`, add a bounds check in the `verify_transcript` function after validating dealer indices:

```rust
// After line 347, add:
let quorum_dealer_count = (num_validators * 2 / 3) + 1;
let max_allowed_dealers = quorum_dealer_count + (num_validators / 10); // Allow 10% buffer
ensure!(
    dealers.len() <= max_allowed_dealers,
    "real_dkg::verify_transcript failed: too many dealers ({}) exceeds maximum allowed ({})",
    dealers.len(),
    max_allowed_dealers
);
```

Alternatively, add the check in `verify_transcript_extra` to enforce it at both consensus and VM layers:

```rust
// In verify_transcript_extra, after line 311:
let quorum_size = verifier.quorum_voting_power();
if checks_voting_power {
    let aggregated_power = verifier.check_voting_power(dealer_set.iter(), true)
        .context("not enough power")?;
    
    // Reject transcripts with excessive voting power (e.g., > 90% of total)
    let max_reasonable_power = verifier.total_voting_power() * 9 / 10;
    ensure!(
        aggregated_power <= max_reasonable_power,
        "excessive dealer voting power: {} exceeds reasonable maximum {}",
        aggregated_power,
        max_reasonable_power
    );
}
```

This ensures that transcripts cannot contain an unreasonable number of dealers that would cause excessive computational overhead during verification.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Setting up a DKG test environment with multiple validators
2. Having one validator collect and aggregate ALL transcripts instead of stopping at quorum
3. Submitting this maximally-aggregated transcript
4. Observing that verification succeeds but requires significantly more computation
5. Measuring the increased time spent in `pok_batch_verify` proportional to dealer count

A complete PoC would require access to a test network with sufficient validators to demonstrate the ~50% computational overhead, but the code path is clear from the citations provided.

## Notes

- This is a protocol-level resource exhaustion vulnerability, not a network-layer DoS attack
- The validator transaction pool only keeps one DKG transaction per topic, so the attack is limited to blocks proposed by the malicious validator [10](#0-9) 
- The attack requires the malicious validator to become a block proposer, which happens periodically through the leader election mechanism
- The impact is temporary (per-block) but can be repeated across multiple epochs
- No mechanism currently exists to penalize validators who submit oversized transcripts, as they are cryptographically valid

### Citations

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L302-309)
```rust
        batch_verify_soks::<G1Projective, A>(
            self.soks.as_slice(),
            g_1,
            &self.V[W],
            spks,
            auxs,
            sok_vrfy_challenge,
        )?;
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L405-407)
```rust
        for sok in &other.soks {
            self.soks.push(sok.clone());
        }
```

**File:** dkg/src/dkg_manager/mod.rs (L397-409)
```rust
                let txn = ValidatorTransaction::DKGResult(DKGTranscript {
                    metadata: DKGTranscriptMetadata {
                        epoch: self.epoch_state.epoch,
                        author: self.my_addr,
                    },
                    transcript_bytes: bcs::to_bytes(&agg_trx)
                        .map_err(|e| anyhow!("transcript serialization error: {e}"))?,
                });
                let vtxn_guard = self.vtxn_pool.put(
                    Topic::DKG,
                    Arc::new(txn),
                    Some(self.pull_notification_tx.clone()),
                );
```

**File:** consensus/src/round_manager.rs (L1134-1135)
```rust
                vtxn.verify(self.epoch_state.verifier.as_ref())
                    .context(format!("{} verify failed", vtxn_type_name))?;
```

**File:** types/src/validator_verifier.rs (L467-479)
```rust
        let target = if check_super_majority {
            self.quorum_voting_power
        } else {
            self.total_voting_power - self.quorum_voting_power + 1
        };

        if aggregated_voting_power < target {
            return Err(VerifyError::TooLittleVotingPower {
                voting_power: aggregated_voting_power,
                expected_voting_power: target,
            });
        }
        Ok(aggregated_voting_power)
```

**File:** aptos-move/aptos-vm/src/validator_txns/dkg.rs (L111-112)
```rust
        DefaultDKG::verify_transcript(&pub_params, &transcript)
            .map_err(|_| Expected(TranscriptVerificationFailed))?;
```

**File:** types/src/dkg/real_dkg/mod.rs (L336-347)
```rust
        // Verify dealer indices are valid.
        let dealers = trx
            .main
            .get_dealers()
            .iter()
            .map(|player| player.id)
            .collect::<Vec<usize>>();
        let num_validators = params.session_metadata.dealer_validator_set.len();
        ensure!(
            dealers.iter().all(|id| *id < num_validators),
            "real_dkg::verify_transcript failed with invalid dealer index."
        );
```

**File:** crates/aptos-dkg/src/pvss/contribution.rs (L76-76)
```rust
    schnorr::pok_batch_verify::<Gr>(&poks, pk_base, &tau)?;
```

**File:** crates/aptos-dkg/src/pvss/schnorr.rs (L78-104)
```rust
    let mut exps = Vec::with_capacity(2 * n + 1);
    let mut bases = Vec::with_capacity(2 * n + 1);

    // Compute \gamma_i = \gamma^i, for all i \in [0, n]
    let mut gammas = Vec::with_capacity(n);
    gammas.push(Scalar::ONE);
    for _ in 0..(n - 1) {
        gammas.push(gammas.last().unwrap().mul(gamma));
    }

    let mut last_exp = Scalar::ZERO;
    for i in 0..n {
        let (pk, (R, s)) = poks[i];

        bases.push(R);
        exps.push(gammas[i]);

        bases.push(pk);
        exps.push(schnorr_hash(Challenge::<Gr> { R, pk, g: *g }) * gammas[i]);

        last_exp += s * gammas[i];
    }

    bases.push(*g);
    exps.push(last_exp.neg());

    if Gr::multi_exp_iter(bases.iter(), exps.iter()) != Gr::identity() {
```

**File:** crates/validator-transaction-pool/src/lib.rs (L74-76)
```rust
        if let Some(old_seq_num) = pool.seq_nums_by_topic.insert(topic.clone(), seq_num) {
            pool.txn_queue.remove(&old_seq_num);
        }
```
