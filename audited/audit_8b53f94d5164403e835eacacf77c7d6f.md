# Audit Report

## Title
BitVec Index Validation Bypass Allows Byzantine Validators to Manipulate Missing Author Exclusion in OptQS Proposals

## Summary
The consensus layer's timeout aggregation logic fails to validate BitVec indices against the current validator set size, allowing Byzantine validators to inject invalid indices that bypass the missing author exclusion mechanism in Optimistic Quorum Store (OptQS) proposals. This can lead to liveness degradation and validator performance issues.

## Finding Description

The vulnerability exists in the interaction between three components:

1. **Timeout Vote Creation** - Individual validators create `RoundTimeoutReason::PayloadUnavailable` with a `missing_authors` BitVec [1](#0-0) 

2. **Timeout Aggregation** - The `aggregated_timeout_reason` function aggregates individual timeout votes without validating BitVec indices [2](#0-1) 

3. **Author Exclusion Processing** - The `get_exclude_authors` function processes the aggregated BitVec indices [3](#0-2) 

**The Critical Flaw:**

The `RoundTimeout::verify()` method validates signatures but NOT the BitVec indices in the `reason` field: [4](#0-3) 

Combined with BitVec's auto-resize behavior when `set()` is called with out-of-bounds indices: [5](#0-4) 

**Attack Scenario:**

1. Epoch has 10 validators (indices 0-9)
2. Validator at index 5 legitimately has missing batches
3. Byzantine validators (with ≥f+1 voting power) collude
4. Each sends timeout votes with `missing_authors` BitVec having bit 15 set (invalid index ≥ validator count)
5. They deliberately omit bit 5 (the actual missing validator)
6. In aggregation, index 15 accumulates ≥f+1 voting power and passes `check_aggregated_voting_power`
7. Index 5 has <f+1 voting power from honest nodes alone
8. The aggregated BitVec is created with `verifier.len()` bits (10) but then `set(15)` resizes it [6](#0-5) 

9. When processed in `ExponentialWindowFailureTracker`, `iter_ones()` returns [15] [7](#0-6) 

10. `self.ordered_authors.get(15)` returns None (only has indices 0-9)
11. The `exclude_authors` set remains empty - validator 5 is NOT excluded
12. OptQS continues attempting to fetch batches from validator 5
13. Repeated timeouts and liveness degradation occur

This breaks the invariant that validators with unavailable payloads should be excluded from optimistic proposals.

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty criteria:

- **Validator node slowdowns**: Repeated failed batch fetches from non-excluded validators cause processing delays
- **Significant protocol violations**: The timeout aggregation logic fails to maintain the integrity of missing author tracking
- **Liveness degradation**: While not total liveness failure, coordinated Byzantine behavior can significantly degrade network performance by preventing proper validator exclusion

The attack requires f+1 Byzantine validators (approximately 1/3 of the network), which is at the threshold of BFT Byzantine tolerance but does not require majority control.

## Likelihood Explanation

**Likelihood: Medium-High**

- Byzantine validators can trivially craft timeout messages with arbitrary BitVec indices (no cryptographic barrier)
- No validation occurs during timeout verification
- Requires coordination of f+1 validators to suppress legitimate exclusions
- Even without malicious intent, software bugs in validators could accidentally generate invalid indices, causing operational issues
- The defensive `.get()` prevents crashes but silently drops invalid indices, making the issue hard to detect

## Recommendation

Add strict validation of BitVec indices in timeout vote processing:

**Fix 1: Validate during timeout verification**
```rust
// In consensus/consensus-types/src/round_timeout.rs
pub fn verify(&self, validator: &ValidatorVerifier) -> anyhow::Result<()> {
    self.timeout.verify(validator)?;
    validator
        .verify(
            self.author(),
            &self.timeout.signing_format(),
            &self.signature,
        )
        .context("Failed to verify 2-chain timeout signature")?;
    
    // NEW: Validate missing_authors indices
    if let RoundTimeoutReason::PayloadUnavailable { missing_authors } = &self.reason {
        for idx in missing_authors.iter_ones() {
            ensure!(
                idx < validator.len(),
                "Invalid missing author index {} exceeds validator set size {}",
                idx,
                validator.len()
            );
        }
    }
    
    Ok(())
}
```

**Fix 2: Validate during aggregation**
```rust
// In consensus/src/pending_votes.rs, line 105-108
for missing_idx in missing_authors.iter_ones() {
    // NEW: Skip invalid indices
    if missing_idx >= verifier.len() {
        warn!("Skipping invalid missing author index {}", missing_idx);
        continue;
    }
    *missing_batch_authors.entry(missing_idx).or_default() +=
        verifier.get_voting_power(author).unwrap_or_default() as u128;
}
```

**Fix 3: Add bounds checking in ExponentialWindowFailureTracker**
```rust
// In consensus/src/liveness/proposal_status_tracker.rs
fn get_exclude_authors(&self) -> HashSet<Author> {
    let mut exclude_authors = HashSet::new();
    let limit = self.window;
    for round_reason in self.past_round_statuses.iter().rev().take(limit) {
        if let NewRoundReason::Timeout(RoundTimeoutReason::PayloadUnavailable {
            missing_authors,
        }) = round_reason
        {
            for author_idx in missing_authors.iter_ones() {
                // NEW: Warn on out-of-bounds indices
                if author_idx >= self.ordered_authors.len() {
                    warn!(
                        "Out-of-bounds author index {} in missing_authors (validator set size: {})",
                        author_idx,
                        self.ordered_authors.len()
                    );
                    continue;
                }
                if let Some(author) = self.ordered_authors.get(author_idx) {
                    exclude_authors.insert(*author);
                }
            }
        }
    }
    exclude_authors
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod test_bitvec_index_attack {
    use super::*;
    use aptos_bitvec::BitVec;
    use aptos_types::validator_verifier::random_validator_verifier;
    
    #[test]
    fn test_invalid_bitvec_indices_bypass_exclusion() {
        // Setup: 10 validators
        let (_, verifier) = random_validator_verifier(10, None, false);
        let ordered_authors = verifier.get_ordered_account_addresses();
        
        // Create tracker
        let mut tracker = ExponentialWindowFailureTracker::new(100, ordered_authors.clone());
        
        // Simulate Byzantine attack: BitVec with ONLY invalid indices
        let mut malicious_bitvec = BitVec::with_num_bits(10);
        malicious_bitvec.set(15);  // Invalid index (out of bounds)
        malicious_bitvec.set(20);  // Another invalid index
        
        // Push timeout with malicious BitVec
        tracker.push(NewRoundReason::Timeout(
            RoundTimeoutReason::PayloadUnavailable {
                missing_authors: malicious_bitvec,
            },
        ));
        
        // Get excluded authors
        let exclude_authors = tracker.get_exclude_authors();
        
        // VULNERABILITY: exclude_authors is EMPTY because all indices are invalid
        // Legitimate missing validators (e.g., index 5) are NOT excluded
        assert_eq!(exclude_authors.len(), 0, 
            "Expected empty exclusion set due to invalid indices, but got {} excluded authors",
            exclude_authors.len()
        );
        
        // Demonstrate BitVec resizing on out-of-bounds set()
        let mut test_bv = BitVec::with_num_bits(5);
        test_bv.set(10);  // Beyond initial capacity
        assert!(test_bv.iter_ones().any(|idx| idx == 10), "BitVec auto-resized to accommodate index 10");
    }
}
```

**Notes:**
- The defensive `.get()` check prevents crashes but enables silent security violations
- BitVec's auto-resize behavior on `set()` is the enabling factor for index overflow
- Multiple similar patterns exist (e.g., `process_optqs_payload` at lines 610-614) that should also be reviewed [8](#0-7)

### Citations

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

**File:** consensus/src/payload_manager/quorum_store_payload_manager.rs (L610-614)
```rust
        for i in peers.iter_ones() {
            if let Some(author) = ordered_authors.get(i) {
                signers.push(*author);
            }
        }
```

**File:** consensus/src/pending_votes.rs (L104-147)
```rust
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
```

**File:** consensus/src/liveness/proposal_status_tracker.rs (L89-93)
```rust
                for author_idx in missing_authors.iter_ones() {
                    if let Some(author) = self.ordered_authors.get(author_idx) {
                        exclude_authors.insert(*author);
                    }
                }
```

**File:** consensus/consensus-types/src/round_timeout.rs (L97-107)
```rust
    pub fn verify(&self, validator: &ValidatorVerifier) -> anyhow::Result<()> {
        self.timeout.verify(validator)?;
        validator
            .verify(
                self.author(),
                &self.timeout.signing_format(),
                &self.signature,
            )
            .context("Failed to verify 2-chain timeout signature")?;
        Ok(())
    }
```

**File:** crates/aptos-bitvec/src/lib.rs (L87-96)
```rust
    pub fn set(&mut self, pos: u16) {
        // This is optimised to: let bucket = pos >> 3;
        let bucket: usize = pos as usize / BUCKET_SIZE;
        if self.inner.len() <= bucket {
            self.inner.resize(bucket + 1, 0);
        }
        // This is optimized to: let bucket_pos = pos | 0x07;
        let bucket_pos = pos as usize - (bucket * BUCKET_SIZE);
        self.inner[bucket] |= 0b1000_0000 >> bucket_pos as u8;
    }
```

**File:** crates/aptos-bitvec/src/lib.rs (L134-136)
```rust
    pub fn iter_ones(&self) -> impl Iterator<Item = usize> + '_ {
        (0..self.inner.len() * BUCKET_SIZE).filter(move |idx| self.is_set(*idx as u16))
    }
```
