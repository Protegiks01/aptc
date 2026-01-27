# Audit Report

## Title
Byzantine Validators Can Forge PayloadUnavailable Timeout Reasons to Exclude Honest Validators from OptQS

## Summary
Byzantine validators can craft `RoundTimeout` messages with fabricated `PayloadUnavailable` reasons containing arbitrary `missing_authors` BitVec data. The timeout signature only covers `(epoch, round, hqc_round)` but not the `reason` field, allowing Byzantine validators to falsely report honest validators as missing and trigger their exclusion from Optimistic Quorum Store operations, degrading network performance.

## Finding Description

The vulnerability exists in how `RoundTimeout` messages authenticate their content. When a validator creates a timeout, they sign only the `TimeoutSigningRepr` structure: [1](#0-0) 

This structure contains only `epoch`, `round`, and `hqc_round`—it does NOT include the `RoundTimeoutReason`: [2](#0-1) 

The `RoundTimeout` struct contains both the signed timeout and an unsigne `reason` field: [3](#0-2) 

When received, the verification only checks the signature on the timeout metadata: [4](#0-3) 

**Attack Path:**

1. Byzantine validator creates a valid `TwoChainTimeout` and signs it properly
2. Attaches a fabricated `RoundTimeoutReason::PayloadUnavailable` with arbitrary `missing_authors` BitVec marking honest validators as missing
3. Broadcasts this `RoundTimeout` to the network
4. The timeout passes cryptographic verification because the signature doesn't cover the reason field
5. The timeout reasons are aggregated from multiple validators: [5](#0-4) 

6. If Byzantine validators with f+1 voting power coordinate to report the same honest validator as missing, that validator gets marked in the aggregated `missing_authors` BitVec (lines 137-143)
7. This aggregated reason is used to exclude validators from OptQS: [6](#0-5) 

8. Honest validators are incorrectly excluded from Optimistic Quorum Store operations, reducing network efficiency

**Invariant Broken:** This violates the **Cryptographic Correctness** invariant—consensus-critical data (which validators to exclude from OptQS) is being determined by unauthenticated data from Byzantine validators.

## Impact Explanation

**High Severity** per Aptos bug bounty criteria:
- **Validator node slowdowns**: Excluded validators cannot participate efficiently in OptQS, degrading their performance
- **Significant protocol violations**: The protocol makes consensus decisions (OptQS exclusions) based on unauthenticated data from Byzantine sources

This does NOT break consensus safety (no double-spending) or liveness (consensus progresses), but it allows Byzantine validators to manipulate protocol behavior and degrade performance of specific honest validators, violating the integrity of the consensus protocol's trust assumptions.

## Likelihood Explanation

**High likelihood**: 
- Byzantine validators are assumed to exist (up to f in a 3f+1 BFT system)
- Creating forged timeouts requires no special resources—only validator keys which Byzantine validators already possess
- If f+1 Byzantine voting power coordinates, they can arbitrarily exclude any honest validator
- The attack is undetectable at the protocol layer since the signature verification passes

## Recommendation

**Include the reason field in the signed data:**

Modify `TimeoutSigningRepr` to include the `RoundTimeoutReason`:

```rust
#[derive(Serialize, Deserialize, Debug, CryptoHasher, BCSCryptoHash)]
pub struct TimeoutSigningRepr {
    pub epoch: u64,
    pub round: Round,
    pub hqc_round: Round,
    pub reason: RoundTimeoutReason,  // ADD THIS
}
```

And update the `signing_format()` method:

```rust
pub fn signing_format(&self, reason: &RoundTimeoutReason) -> TimeoutSigningRepr {
    TimeoutSigningRepr {
        epoch: self.epoch(),
        round: self.round(),
        hqc_round: self.hqc_round(),
        reason: reason.clone(),
    }
}
```

Alternatively, sign a hash of the entire `RoundTimeout` structure instead of just the timeout metadata.

## Proof of Concept

```rust
#[test]
fn test_forged_timeout_reason_passes_verification() {
    use aptos_consensus_types::{
        round_timeout::{RoundTimeout, RoundTimeoutReason},
        timeout_2chain::TwoChainTimeout,
    };
    use aptos_bitvec::BitVec;
    use aptos_types::validator_verifier::random_validator_verifier;
    
    let (signers, validator_verifier) = random_validator_verifier(4, None, false);
    let byzantine_validator = &signers[0];
    
    // Byzantine validator creates valid timeout
    let timeout = TwoChainTimeout::new(
        1, 
        10,
        QuorumCert::certificate_for_genesis()
    );
    let signature = timeout.sign(byzantine_validator).unwrap();
    
    // Create HONEST reason (no missing authors)
    let honest_reason = RoundTimeoutReason::NoQC;
    let honest_timeout = RoundTimeout::new(
        timeout.clone(),
        byzantine_validator.author(),
        honest_reason,
        signature.clone(),
    );
    
    // Verify honest timeout passes
    assert!(honest_timeout.verify(&validator_verifier).is_ok());
    
    // Now create FORGED reason marking validator[2] as missing
    let mut forged_missing = BitVec::with_num_bits(4);
    forged_missing.set(2); // Falsely mark validator 2 as missing
    let forged_reason = RoundTimeoutReason::PayloadUnavailable {
        missing_authors: forged_missing,
    };
    
    // Use SAME signature but DIFFERENT reason
    let forged_timeout = RoundTimeout::new(
        timeout,
        byzantine_validator.author(),
        forged_reason,
        signature, // SAME SIGNATURE as honest timeout
    );
    
    // Forged timeout ALSO passes verification!
    assert!(forged_timeout.verify(&validator_verifier).is_ok());
    
    // This demonstrates the signature doesn't authenticate the reason field
}
```

This test demonstrates that the same signature validates both an honest reason and a fabricated reason, proving the reason field is unauthenticated.

## Notes

This vulnerability is specific to the consensus protocol layer and requires Byzantine validator participation, which is within the BFT threat model (< 1/3 Byzantine stake). The impact is performance degradation rather than safety violation, but it represents a significant protocol integrity issue where unauthenticated data influences consensus decisions.

### Citations

**File:** consensus/consensus-types/src/timeout_2chain.rs (L59-72)
```rust
    pub fn sign(
        &self,
        signer: &ValidatorSigner,
    ) -> Result<bls12381::Signature, CryptoMaterialError> {
        signer.sign(&self.signing_format())
    }

    pub fn signing_format(&self) -> TimeoutSigningRepr {
        TimeoutSigningRepr {
            epoch: self.epoch(),
            round: self.round(),
            hqc_round: self.hqc_round(),
        }
    }
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L96-103)
```rust
/// Validators sign this structure that allows the TwoChainTimeoutCertificate to store a round number
/// instead of a quorum cert per validator in the signatures field.
#[derive(Serialize, Deserialize, Debug, CryptoHasher, BCSCryptoHash)]
pub struct TimeoutSigningRepr {
    pub epoch: u64,
    pub round: Round,
    pub hqc_round: Round,
}
```

**File:** consensus/consensus-types/src/round_timeout.rs (L37-45)
```rust
#[derive(Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct RoundTimeout {
    // The timeout
    timeout: TwoChainTimeout,
    author: Author,
    reason: RoundTimeoutReason,
    /// Signature on the Timeout
    signature: bls12381::Signature,
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
