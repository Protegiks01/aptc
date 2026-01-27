# Audit Report

## Title
Byzantine Proposer Can Falsely Exclude Honest Validators from OptQS Through Unauthenticated Batch Attribution

## Summary
A Byzantine validator acting as proposer can craft OptQuorumStore payloads with fake batch entries attributed to honest validators, causing all receiving validators to incorrectly report those honest validators as having missing payloads. This triggers automatic exclusion from OptQS, systematically degrading network efficiency and potentially impacting liveness.

## Finding Description

The vulnerability exists in the OptQuorumStore (OptQS) payload verification and timeout handling mechanism. The attack exploits the lack of cryptographic authentication on `BatchInfo` entries in `opt_batches`.

**Attack Flow:**

1. **Malicious Payload Creation**: When a Byzantine validator is the proposer, they create an `OptQuorumStorePayload` with fake `BatchInfo` entries in the `opt_batches` field. These entries have:
   - `author` field set to target honest validator V
   - `digest` field set to a non-existent/random hash
   - Valid `epoch`, `expiration`, and other metadata

2. **Weak Verification**: The payload passes validation because `verify_opt_batches()` only checks that the author is in the validator set, with no signature verification: [1](#0-0) 

3. **False Missing Detection**: When honest validators receive this block, they call `check_payload_availability()` to verify they have all referenced batches locally: [2](#0-1) 

Since the fake batches don't exist (wrong digest), validators mark the falsely-attributed author as missing in the `missing_authors` BitVec.

4. **Timeout Propagation**: When validators timeout due to unavailable payload, they create `RoundTimeoutReason::PayloadUnavailable` with the manipulated `missing_authors`: [3](#0-2) 

5. **Byzantine Aggregation**: The `aggregated_timeout_reason()` function aggregates timeout reasons from multiple validators. If f+1 validators report an author as missing (which happens because all honest validators see the same fake batch), that author gets marked in the aggregated BitVec: [4](#0-3) 

6. **Exclusion from OptQS**: The `get_exclude_authors()` function reads the aggregated `missing_authors` BitVec and excludes those validators from future OptQS payload pulls: [5](#0-4) 

7. **Network Degradation**: When pulling batches for OptQS, excluded authors are filtered out, preventing their legitimate batches from being included: [6](#0-5) 

**Root Cause**: Unlike `ProofOfStore` which has cryptographic signatures: [7](#0-6) 

The `BatchInfo` structure in OptBatches has no signature field and no authentication mechanism: [8](#0-7) 

This allows arbitrary batch attribution without proof of authorship.

## Impact Explanation

**Severity: High** (up to $50,000 per Aptos Bug Bounty criteria)

This vulnerability causes **significant protocol violations** through:

1. **Network Efficiency Degradation**: Byzantine proposers can systematically exclude honest validators from OptQS, forcing the network to use less efficient payload mechanisms or smaller block sizes.

2. **Unfair Validator Treatment**: Honest validators are penalized for malicious actions they didn't commit, violating fairness guarantees.

3. **Potential Liveness Impact**: If enough validators are excluded, block production efficiency could degrade to the point of impacting network liveness, especially under high transaction load.

4. **Byzantine Amplification**: A single Byzantine proposer can affect the entire validator set's behavior by manipulating exclusion lists, exceeding the expected impact of f Byzantine validators.

While this doesn't directly cause fund loss or consensus safety violations, it represents a **significant protocol violation** that degrades network performance and violates Byzantine fault tolerance assumptions.

## Likelihood Explanation

**Likelihood: High**

- **Attack Complexity**: Low - Byzantine proposer only needs to construct malicious `BatchInfo` entries when they are the leader
- **Detection Difficulty**: High - The attack appears as legitimate payload unavailability to observers
- **Frequency**: Occurs every time a Byzantine validator is the proposer
- **Prerequisites**: Only requires being selected as proposer (happens with 1/n probability per round for n validators)
- **Persistence**: Exclusion persists across the configured window size, allowing sustained impact

With f Byzantine validators rotating as proposers, this attack can be executed repeatedly to maintain continuous degradation of network efficiency.

## Recommendation

Add cryptographic authentication to OptBatches by either:

**Option 1: Add Signature Verification** (Recommended)
Extend `BatchInfo` in OptBatches to include signatures from the batch author, similar to `SignedBatchInfo`:

```rust
// In verify_opt_batches()
pub fn verify_opt_batches<T: TBatchInfo>(
    verifier: &ValidatorVerifier,
    opt_batches: &OptBatches<T>,
) -> anyhow::Result<()> {
    let authors = verifier.address_to_validator_index();
    for batch in &opt_batches.batch_summary {
        ensure!(
            authors.contains_key(&batch.author()),
            "Invalid author {} for batch {}",
            batch.author(),
            batch.digest()
        );
        
        // ADD SIGNATURE VERIFICATION HERE
        ensure!(
            batch.verify_signature(verifier).is_ok(),
            "Invalid signature for batch {} from author {}",
            batch.digest(),
            batch.author()
        );
    }
    Ok(())
}
```

**Option 2: Use Batch Hash Binding**
Require that batch digests in OptBatches must correspond to previously committed ProofOfStore entries, which are already signed.

**Option 3: Proposer Attestation**
Have the block proposer sign an attestation over the entire `opt_batches` list, making them accountable for false attributions.

## Proof of Concept

```rust
// PoC demonstrating the attack (pseudo-code for clarity)
#[test]
fn test_byzantine_optqs_exclusion_attack() {
    // Setup: 4 validators, 1 Byzantine (proposer)
    let (signers, verifier) = random_validator_verifier(4, None, false);
    let byzantine_proposer = signers[0].author();
    let honest_target = signers[1].author();
    
    // Byzantine proposer creates malicious OptQS payload
    let fake_batch = BatchInfo::new(
        honest_target,  // Falsely attribute to honest validator
        BatchId::new(123),
        epoch,
        expiration,
        HashValue::random(),  // Non-existent digest
        100,  // num_txns
        1000, // num_bytes
        0,    // gas_bucket_start
    );
    
    let malicious_payload = OptQuorumStorePayloadV1::new(
        vec![],  // inline_batches
        OptBatches::new(vec![fake_batch]),  // malicious opt_batches
        ProofBatches::empty(),
        PayloadExecutionLimit::default(),
    );
    
    let block = create_block_with_payload(
        byzantine_proposer,
        Payload::OptQuorumStore(OptQuorumStorePayload::V1(malicious_payload))
    );
    
    // Block passes verification (no signature check!)
    assert!(block.verify(&verifier).is_ok());
    
    // Honest validators receive block and check payload availability
    let mut honest_validator_1 = setup_validator(&signers[1]);
    let missing_authors = honest_validator_1
        .check_payload_availability(&block)
        .unwrap_err();  // Returns Err with missing_authors BitVec
    
    // Verify that honest_target is incorrectly marked as missing
    let target_index = verifier.address_to_validator_index()
        .get(&honest_target).unwrap();
    assert!(missing_authors.is_set(*target_index as u16));
    
    // After timeout aggregation with 2f+1 validators reporting
    // honest_target gets excluded from OptQS
    let excluded = get_excluded_authors_after_timeout(&verifier, &missing_authors);
    assert!(excluded.contains(&honest_target));
    
    // Future OptQS pulls will exclude honest_target's batches
    let optqs_params = get_optqs_params(&excluded);
    assert!(optqs_params.exclude_authors.contains(&honest_target));
}
```

**Notes:**
- This attack requires the Byzantine validator to be the proposer, which happens probabilistically
- The impact is amplified when multiple Byzantine validators collude to sustain the attack across rounds
- The excluded validator continues to be excluded across the configured window size (potentially 100+ rounds)
- Detection requires comparing local batch availability against reported missing authors, which is not currently implemented

### Citations

**File:** consensus/consensus-types/src/common.rs (L558-572)
```rust
    pub fn verify_opt_batches<T: TBatchInfo>(
        verifier: &ValidatorVerifier,
        opt_batches: &OptBatches<T>,
    ) -> anyhow::Result<()> {
        let authors = verifier.address_to_validator_index();
        for batch in &opt_batches.batch_summary {
            ensure!(
                authors.contains_key(&batch.author()),
                "Invalid author {} for batch {}",
                batch.author(),
                batch.digest()
            );
        }
        Ok(())
    }
```

**File:** consensus/src/payload_manager/quorum_store_payload_manager.rs (L409-424)
```rust
            Payload::OptQuorumStore(OptQuorumStorePayload::V1(p)) => {
                let mut missing_authors = BitVec::with_num_bits(self.ordered_authors.len() as u16);
                for batch in p.opt_batches().deref() {
                    if self.batch_reader.exists(batch.digest()).is_none() {
                        let index = *self
                            .address_to_validator_index
                            .get(&batch.author())
                            .expect("Payload author should have been verified");
                        missing_authors.set(index as u16);
                    }
                }
                if missing_authors.all_zeros() {
                    Ok(())
                } else {
                    Err(missing_authors)
                }
```

**File:** consensus/src/round_manager.rs (L968-983)
```rust
    fn compute_timeout_reason(&self, round: Round) -> RoundTimeoutReason {
        if self.round_state().vote_sent().is_some() {
            return RoundTimeoutReason::NoQC;
        }

        match self.block_store.get_block_for_round(round) {
            None => RoundTimeoutReason::ProposalNotReceived,
            Some(block) => {
                if let Err(missing_authors) = self.block_store.check_payload(block.block()) {
                    RoundTimeoutReason::PayloadUnavailable { missing_authors }
                } else {
                    RoundTimeoutReason::Unknown
                }
            },
        }
    }
```

**File:** consensus/src/pending_votes.rs (L93-153)
```rust
    fn aggregated_timeout_reason(&self, verifier: &ValidatorVerifier) -> RoundTimeoutReason {
        let mut reason_voting_power: HashMap<RoundTimeoutReason, u128> = HashMap::new();
        let mut missing_batch_authors: HashMap<usize, u128> = HashMap::new();
        // let ordered_authors = verifier.get_ordered_account_addresses();
        for (author, reason) in &self.timeout_reason {
            // To aggregate the reason, we only care about the variant type itself and
            // exclude any data within the variants.
            let reason_key = match reason {
                reason @ RoundTimeoutReason::Unknown
                | reason @ RoundTimeoutReason::ProposalNotReceived
                | reason @ RoundTimeoutReason::NoQC => reason.clone(),
                RoundTimeoutReason::PayloadUnavailable { missing_authors } => {
                    for missing_idx in missing_authors.iter_ones() {
                        *missing_batch_authors.entry(missing_idx).or_default() +=
                            verifier.get_voting_power(author).unwrap_or_default() as u128;
                    }
                    RoundTimeoutReason::PayloadUnavailable {
                        // Since we care only about the variant type, we replace the bitvec
                        // with a placeholder.
                        missing_authors: BitVec::with_num_bits(verifier.len() as u16),
                    }
                },
            };
            *reason_voting_power.entry(reason_key).or_default() +=
                verifier.get_voting_power(author).unwrap_or_default() as u128;
        }
        // The aggregated timeout reason is the reason with the most voting power received from
        // at least f+1 peers by voting power. If such voting power does not exist, then the
        // reason is unknown.

        reason_voting_power
            .into_iter()
            .max_by_key(|(_, voting_power)| *voting_power)
            .filter(|(_, voting_power)| {
                verifier
                    .check_aggregated_voting_power(*voting_power, false)
                    .is_ok()
            })
            .map(|(reason, _)| {
                // If the aggregated reason is due to unavailable payload, we will compute the
                // aggregated missing authors bitvec counting batch authors that have been reported
                // missing by minority peers.
                if matches!(reason, RoundTimeoutReason::PayloadUnavailable { .. }) {
                    let mut aggregated_bitvec = BitVec::with_num_bits(verifier.len() as u16);
                    for (author_idx, voting_power) in missing_batch_authors {
                        if verifier
                            .check_aggregated_voting_power(voting_power, false)
                            .is_ok()
                        {
                            aggregated_bitvec.set(author_idx as u16);
                        }
                    }
                    RoundTimeoutReason::PayloadUnavailable {
                        missing_authors: aggregated_bitvec,
                    }
                } else {
                    reason
                }
            })
            .unwrap_or(RoundTimeoutReason::Unknown)
    }
```

**File:** consensus/src/liveness/proposal_status_tracker.rs (L80-98)
```rust
    fn get_exclude_authors(&self) -> HashSet<Author> {
        let mut exclude_authors = HashSet::new();

        let limit = self.window;
        for round_reason in self.past_round_statuses.iter().rev().take(limit) {
            if let NewRoundReason::Timeout(RoundTimeoutReason::PayloadUnavailable {
                missing_authors,
            }) = round_reason
            {
                for author_idx in missing_authors.iter_ones() {
                    if let Some(author) = self.ordered_authors.get(author_idx) {
                        exclude_authors.insert(*author);
                    }
                }
            }
        }

        exclude_authors
    }
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L596-600)
```rust
        for (_, batches) in self
            .author_to_batches
            .iter()
            .filter(|(author, _)| !exclude_authors.contains(author))
        {
```

**File:** consensus/consensus-types/src/proof_of_store.rs (L49-118)
```rust
pub struct BatchInfo {
    author: PeerId,
    batch_id: BatchId,
    epoch: u64,
    expiration: u64,
    digest: HashValue,
    num_txns: u64,
    num_bytes: u64,
    gas_bucket_start: u64,
}

impl BatchInfo {
    pub fn new(
        author: PeerId,
        batch_id: BatchId,
        epoch: u64,
        expiration: u64,
        digest: HashValue,
        num_txns: u64,
        num_bytes: u64,
        gas_bucket_start: u64,
    ) -> Self {
        Self {
            author,
            batch_id,
            epoch,
            expiration,
            digest,
            num_txns,
            num_bytes,
            gas_bucket_start,
        }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn author(&self) -> PeerId {
        self.author
    }

    pub fn batch_id(&self) -> BatchId {
        self.batch_id
    }

    pub fn expiration(&self) -> u64 {
        self.expiration
    }

    pub fn digest(&self) -> &HashValue {
        &self.digest
    }

    pub fn num_txns(&self) -> u64 {
        self.num_txns
    }

    pub fn num_bytes(&self) -> u64 {
        self.num_bytes
    }

    pub fn size(&self) -> PayloadTxnsSize {
        PayloadTxnsSize::new(self.num_txns, self.num_bytes)
    }

    pub fn gas_bucket_start(&self) -> u64 {
        self.gas_bucket_start
    }
}
```

**File:** consensus/consensus-types/src/proof_of_store.rs (L459-482)
```rust
    pub fn verify(
        &self,
        sender: PeerId,
        max_batch_expiry_gap_usecs: u64,
        validator: &ValidatorVerifier,
    ) -> anyhow::Result<()> {
        if sender != self.signer {
            bail!("Sender {} mismatch signer {}", sender, self.signer);
        }

        if self.expiration()
            > aptos_infallible::duration_since_epoch().as_micros() as u64
                + max_batch_expiry_gap_usecs
        {
            bail!(
                "Batch expiration too far in future: {} > {}",
                self.expiration(),
                aptos_infallible::duration_since_epoch().as_micros() as u64
                    + max_batch_expiry_gap_usecs
            );
        }

        Ok(validator.optimistic_verify(self.signer, &self.info, &self.signature)?)
    }
```
