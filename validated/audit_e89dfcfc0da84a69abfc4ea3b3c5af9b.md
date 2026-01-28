# Audit Report

## Title
Computational DoS via Unbounded ProofOfStore Verification in Proposal Payloads

## Summary
A Byzantine validator can craft proposals containing thousands of ProofOfStore objects (up to ~20,000 in 6MB payload) that force all validators to perform expensive BLS aggregate signature verification before the proposer validity check occurs. This causes validator CPU saturation and potential consensus delays.

## Finding Description

**Broken Invariant**: Resource Limits - "All operations must respect gas, storage, and computational limits"

The vulnerability exists in the proposal verification flow where expensive payload verification occurs before proposer validity checks. When a validator receives a proposal, the verification proceeds as follows:

1. The proposal enters `UnverifiedEvent::verify()` which calls `ProposalMsg::verify()` for non-self messages [1](#0-0) 

2. `ProposalMsg::verify()` first checks that the sender matches the proposal author (which passes for a Byzantine validator proposing for themselves) [2](#0-1) 

3. The function then uses `rayon::join()` to parallelize payload and signature verification, triggering payload verification at line 100 without any prior check on the number of proofs [3](#0-2) 

4. `Payload::verify()` calls `verify_with_cache()` for InQuorumStore and other payload types [4](#0-3) 

5. The `verify_with_cache()` function filters cached proofs and verifies all remaining proofs in parallel **with no limit on the number of proofs** [5](#0-4) 

6. Each `ProofOfStore::verify()` performs expensive BLS aggregate signature verification via `validator.verify_multi_signatures()` [6](#0-5) 

7. Size and transaction count limits are only checked **AFTER** verification completes in `process_proposal()` [7](#0-6) 

8. Proposer validity is also checked **AFTER** verification [8](#0-7) 

**Key Difference**: `ProofOfStoreMsg::verify()` enforces `receiver_max_num_batches` limit (default 20) [9](#0-8)  and the configuration shows this default [10](#0-9) . However, proposal payload verification has no such protection as evidenced by the unbounded loop in `verify_with_cache()`.

**Attack Scenario**:
A Byzantine validator (single malicious validator within the <1/3 Byzantine tolerance) crafts proposals with maximum payload size of 6MB [11](#0-10) . Each ProofOfStore is ~300 bytes, allowing ~20,000 proofs per proposal. The Byzantine validator sends these proposals for rounds where they are NOT the valid proposer. Each proof with unique BatchInfo requires full BLS verification before the proposer check fails, causing CPU saturation.

## Impact Explanation

**Severity: High** per Aptos Bug Bounty category "Validator node slowdowns"

- **Validator Node Slowdowns**: Affected validators spend excessive CPU time (several seconds for 10,000+ BLS verifications) on malicious proposals, causing them to process legitimate proposals slowly and potentially miss voting deadlines
- **Consensus Delays**: If multiple validators are targeted, consensus rounds are significantly delayed
- **Cascading Effects**: Validators falling behind may trigger state sync, further degrading performance
- **Sustained Attack**: Can be repeated in every consensus round for continuous degradation

This aligns with the High severity category because it causes significant performance degradation affecting consensus participation without causing permanent network partition or fund loss. This is a computational DoS through protocol exploitation, not a network-level DoS attack.

## Likelihood Explanation

**Likelihood: Medium to High**

**Attacker Requirements**:
- Must be a validator in the current validator set (authenticated via consensus network protocol)
- This represents a single Byzantine validator scenario, which is within the BFT threat model (<1/3 Byzantine tolerance)
- Must construct valid BCS-serialized proposals with many ProofOfStore objects

**Attack Complexity**: Low to Medium
- Creating proposals with many ProofOfStore objects is straightforward once validator access is obtained
- No cryptographic breaks required
- Can be automated and sustained
- Each round provides a new opportunity to attack

**Detection**: Malicious proposals appear similar to legitimate ones in size, evident only through CPU metrics and verification duration.

## Recommendation

Add a proof count limit check in `Payload::verify_with_cache()` before performing expensive verification, similar to how `ProofOfStoreMsg::verify()` enforces `max_num_batches`:

```rust
fn verify_with_cache<T>(
    proofs: &[ProofOfStore<T>],
    validator: &ValidatorVerifier,
    proof_cache: &ProofCache,
) -> anyhow::Result<()>
where
    T: TBatchInfo + Send + Sync + 'static,
    BatchInfoExt: From<T>,
{
    // Add proof count limit check
    ensure!(
        proofs.len() <= MAX_PROOFS_IN_PROPOSAL,
        "Too many proofs in proposal: {} > {}",
        proofs.len(),
        MAX_PROOFS_IN_PROPOSAL
    );
    
    let unverified: Vec<_> = proofs
        .iter()
        .filter(|proof| {
            proof_cache
                .get(&BatchInfoExt::from(proof.info().clone()))
                .is_none_or(|cached_proof| cached_proof != *proof.multi_signature())
        })
        .collect();
    unverified
        .par_iter()
        .with_min_len(2)
        .try_for_each(|proof| proof.verify(validator, proof_cache))?;
    Ok(())
}
```

Additionally, consider moving the proposer validity check earlier in the verification flow, before expensive cryptographic operations.

## Proof of Concept

A malicious validator can craft a proposal with ~20,000 ProofOfStore objects by:
1. Creating 20,000 unique BatchInfo objects (varying batch_id or digest)
2. Generating corresponding AggregateSignature objects
3. Constructing a ProofWithData containing all 20,000 proofs
4. Wrapping in a Payload::InQuorumStore variant
5. Creating a Block and ProposalMsg with this payload
6. Broadcasting to all validators

Each receiving validator will call `verify_with_cache()` which iterates through all proofs without bound checking, performing expensive BLS verification for each uncached proof. This occurs before the proposer validity check at line 1196 of round_manager.rs, allowing a non-proposer to force this computation on all validators.

## Notes

This vulnerability exploits an ordering flaw in the verification pipeline where expensive cryptographic operations occur before cheap authorization checks. The bounded executor (default 16 concurrent tasks) provides some rate limiting but does not prevent the attack since each task can still verify thousands of proofs. This is a computational DoS through protocol exploitation, distinct from network-level DoS attacks which are out of scope.

### Citations

**File:** consensus/src/round_manager.rs (L120-127)
```rust
            UnverifiedEvent::ProposalMsg(p) => {
                if !self_message {
                    p.verify(peer_id, validator, proof_cache, quorum_store_enabled)?;
                    counters::VERIFY_MSG
                        .with_label_values(&["proposal"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::ProposalMsg(p)
```

**File:** consensus/src/round_manager.rs (L1178-1193)
```rust
        let payload_len = proposal.payload().map_or(0, |payload| payload.len());
        let payload_size = proposal.payload().map_or(0, |payload| payload.size());
        ensure!(
            num_validator_txns + payload_len as u64 <= self.local_config.max_receiving_block_txns,
            "Payload len {} exceeds the limit {}",
            payload_len,
            self.local_config.max_receiving_block_txns,
        );

        ensure!(
            validator_txns_total_bytes + payload_size as u64
                <= self.local_config.max_receiving_block_bytes,
            "Payload size {} exceeds the limit {}",
            payload_size,
            self.local_config.max_receiving_block_bytes,
        );
```

**File:** consensus/src/round_manager.rs (L1196-1200)
```rust
            self.proposer_election.is_valid_proposal(&proposal),
            "[RoundManager] Proposer {} for block {} is not a valid proposer for this round or created duplicate proposal",
            author,
            proposal,
        );
```

**File:** consensus/consensus-types/src/proposal_msg.rs (L89-96)
```rust
        if let Some(proposal_author) = self.proposal.author() {
            ensure!(
                proposal_author == sender,
                "Proposal author {:?} doesn't match sender {:?}",
                proposal_author,
                sender
            );
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

**File:** consensus/consensus-types/src/common.rs (L517-539)
```rust
    fn verify_with_cache<T>(
        proofs: &[ProofOfStore<T>],
        validator: &ValidatorVerifier,
        proof_cache: &ProofCache,
    ) -> anyhow::Result<()>
    where
        T: TBatchInfo + Send + Sync + 'static,
        BatchInfoExt: From<T>,
    {
        let unverified: Vec<_> = proofs
            .iter()
            .filter(|proof| {
                proof_cache
                    .get(&BatchInfoExt::from(proof.info().clone()))
                    .is_none_or(|cached_proof| cached_proof != *proof.multi_signature())
            })
            .collect();
        unverified
            .par_iter()
            .with_min_len(2)
            .try_for_each(|proof| proof.verify(validator, proof_cache))?;
        Ok(())
    }
```

**File:** consensus/consensus-types/src/common.rs (L574-596)
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
```

**File:** consensus/consensus-types/src/proof_of_store.rs (L573-578)
```rust
        ensure!(
            self.proofs.len() <= max_num_proofs,
            "Too many proofs: {} > {}",
            self.proofs.len(),
            max_num_proofs
        );
```

**File:** consensus/consensus-types/src/proof_of_store.rs (L635-652)
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
        result
    }
```

**File:** config/src/config/quorum_store_config.rs (L122-122)
```rust
            receiver_max_num_batches: 20,
```

**File:** config/src/config/consensus_config.rs (L231-231)
```rust
            max_receiving_block_bytes: 6 * 1024 * 1024, // 6MB
```
