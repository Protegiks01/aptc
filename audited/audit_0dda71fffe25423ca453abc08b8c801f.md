# Audit Report

## Title
Pessimistic Verify Set DoS Attack via Intentional Bad Signature Triggering

## Summary
A Byzantine validator can intentionally submit one invalid commit vote signature to trigger inclusion in the `pessimistic_verify_set`, then exploit this state by flooding the node with invalid commit votes. Each invalid vote forces expensive individual BLS signature verification through a bounded executor (capacity 16), potentially causing consensus slowdown and delayed processing of legitimate votes from honest validators.

## Finding Description

The Aptos consensus implements an optimistic signature verification mechanism where commit votes are aggregated before verification. When aggregate verification fails, the system identifies bad validators and adds them to `pessimistic_verify_set` for individual verification on all future votes. [1](#0-0) 

The vulnerability arises in the asymmetric verification flow:

**Normal Flow (validator NOT in pessimistic_verify_set):**
1. Commit vote received and passes through `optimistic_verify()` without individual signature verification
2. Vote added to signature aggregator
3. Aggregate signature verified once for all votes (efficient)

**Exploitable Flow (validator IN pessimistic_verify_set):**
1. Each commit vote triggers individual BLS signature verification immediately
2. Verification happens in bounded executor with limited capacity (16 concurrent tasks) [2](#0-1) 

**Attack Execution:**

A Byzantine validator executes a two-phase attack:

**Phase 1: Trigger Inclusion**
- Send ONE commit vote with invalid signature
- During aggregation, `filter_invalid_signatures()` is called
- Validator is added to `pessimistic_verify_set` [3](#0-2) 

**Phase 2: Exploit via Flooding**
- Flood node with many invalid commit votes
- Each vote goes through verification task spawning in buffer manager [4](#0-3) 

- Each verification task acquires a permit from the bounded executor (blocking if at capacity)
- Expensive BLS signature verification is performed for each invalid vote
- Permits are slowly released as verifications complete and fail [5](#0-4) 

The bounded executor blocks new verification tasks when all 16 permits are in use. This delays processing of legitimate commit votes from honest validators, degrading consensus performance.

## Impact Explanation

**High Severity** - Validator node slowdowns and consensus degradation.

The attack impacts consensus liveness without requiring collusion or 1/3+ Byzantine stake:
- Bounded executor saturated with verification tasks for invalid votes
- Legitimate commit votes delayed waiting for executor capacity
- Consensus rounds take longer to collect quorum of valid signatures
- Network-wide consensus throughput reduced

This qualifies as "Validator node slowdowns" under High Severity per the Aptos bug bounty program. While not causing total liveness failure, it creates measurable consensus degradation exploitable by a single Byzantine validator.

## Likelihood Explanation

**High Likelihood** - Attack is trivial to execute and requires only validator credentials (which Byzantine validators possess by definition).

Requirements:
- Byzantine validator access (assumed under BFT threat model up to 1/3 stake)
- Ability to send consensus messages (standard validator capability)
- No special timing or state conditions required

The attack is deterministic and repeatable. Once in `pessimistic_verify_set`, the validator can maintain the DoS by continuous flooding. The mechanism provides no automatic removal from the pessimistic set, so the attack persists across rounds.

## Recommendation

Implement per-validator rate limiting at the verification layer before expensive cryptographic operations:

```rust
// Add to ValidatorVerifier struct
pessimistic_verify_rate_limiters: DashMap<AccountAddress, RateLimiter>,

// In optimistic_verify(), before expensive verification:
pub fn optimistic_verify<T: Serialize + CryptoHash>(
    &self,
    author: AccountAddress,
    message: &T,
    signature_with_status: &SignatureWithStatus,
) -> std::result::Result<(), VerifyError> {
    if self.get_public_key(&author).is_none() {
        return Err(VerifyError::UnknownAuthor);
    }
    
    // NEW: Rate limit pessimistic verifications
    if self.pessimistic_verify_set.contains(&author) {
        if let Some(limiter) = self.pessimistic_verify_rate_limiters.get(&author) {
            if !limiter.check_rate_limit() {
                return Err(VerifyError::RateLimitExceeded);
            }
        }
    }
    
    if (!self.optimistic_sig_verification || self.pessimistic_verify_set.contains(&author))
        && !signature_with_status.is_verified()
    {
        self.verify(author, message, signature_with_status.signature())?;
        signature_with_status.set_verified();
    }
    Ok(())
}
```

Additionally, implement automatic removal from `pessimistic_verify_set` after a period of valid signatures, or limit the duration of pessimistic verification status.

## Proof of Concept

```rust
#[cfg(test)]
mod pessimistic_dos_test {
    use super::*;
    use aptos_types::validator_verifier::{ValidatorVerifier, ValidatorConsensusInfo};
    use aptos_consensus_types::pipeline::commit_vote::CommitVote;
    use aptos_crypto::bls12381::Signature;
    use std::time::Instant;
    
    #[test]
    fn test_pessimistic_verify_set_dos() {
        // Setup: Create validator set with one Byzantine validator
        let (validator_signers, mut verifier) = create_test_validators(4);
        verifier.set_optimistic_sig_verification_flag(true);
        
        let byzantine_validator = &validator_signers[0];
        let ledger_info = create_test_ledger_info();
        
        // Phase 1: Send one bad vote to trigger pessimistic verification
        let bad_vote = CommitVote::new_with_signature(
            byzantine_validator.author(),
            ledger_info.clone(),
            Signature::dummy_signature(), // Invalid signature
        );
        
        // Simulate aggregation failure and filter_invalid_signatures
        // This would add byzantine_validator to pessimistic_verify_set
        verifier.add_pessimistic_verify_set(byzantine_validator.author());
        
        assert!(verifier.pessimistic_verify_set().contains(&byzantine_validator.author()));
        
        // Phase 2: Measure performance impact of flooding with invalid votes
        let num_invalid_votes = 100;
        let start = Instant::now();
        
        for _ in 0..num_invalid_votes {
            let invalid_vote = CommitVote::new_with_signature(
                byzantine_validator.author(),
                ledger_info.clone(),
                Signature::dummy_signature(),
            );
            
            // Each vote now requires expensive individual verification
            let result = verifier.optimistic_verify(
                byzantine_validator.author(),
                &ledger_info,
                invalid_vote.signature_with_status(),
            );
            
            assert!(result.is_err()); // Verification fails but after expensive BLS check
        }
        
        let duration = start.elapsed();
        println!("Time to process {} invalid votes with pessimistic verification: {:?}", 
                 num_invalid_votes, duration);
        
        // Compare with honest validator (not in pessimistic set)
        let honest_validator = &validator_signers[1];
        let start = Instant::now();
        
        for _ in 0..num_invalid_votes {
            let vote = CommitVote::new(
                honest_validator.author(),
                ledger_info.clone(),
                honest_validator,
            ).unwrap();
            
            // Optimistic path: no individual verification
            let result = verifier.optimistic_verify(
                honest_validator.author(),
                &ledger_info,
                vote.signature_with_status(),
            );
            
            assert!(result.is_ok()); // Passes without verification
        }
        
        let honest_duration = start.elapsed();
        println!("Time to process {} valid votes with optimistic verification: {:?}",
                 num_invalid_votes, honest_duration);
        
        // Demonstrate the asymmetry: pessimistic verification is significantly slower
        assert!(duration > honest_duration * 10);
    }
}
```

## Notes

The vulnerability is particularly concerning because:

1. **Self-Inflicted Entry**: A validator can deliberately enter `pessimistic_verify_set` with minimal cost (one bad signature)

2. **No Automatic Exit**: Once in the pessimistic set, there's no mechanism for removal even if subsequent signatures are valid

3. **Bounded Executor Saturation**: Default capacity of 16 concurrent tasks is insufficient to handle high-rate invalid vote floods without impacting legitimate vote processing

4. **No Per-Validator Rate Limiting**: The verification layer lacks rate limiting, relying only on bounded executor backpressure which affects all validators equally

The attack is distinct from generic network-level DoS because it exploits a protocol-level optimization mechanism (`pessimistic_verify_set`) to force asymmetric computational costs.

### Citations

**File:** types/src/validator_verifier.rs (L269-285)
```rust
    pub fn optimistic_verify<T: Serialize + CryptoHash>(
        &self,
        author: AccountAddress,
        message: &T,
        signature_with_status: &SignatureWithStatus,
    ) -> std::result::Result<(), VerifyError> {
        if self.get_public_key(&author).is_none() {
            return Err(VerifyError::UnknownAuthor);
        }
        if (!self.optimistic_sig_verification || self.pessimistic_verify_set.contains(&author))
            && !signature_with_status.is_verified()
        {
            self.verify(author, message, signature_with_status.signature())?;
            signature_with_status.set_verified();
        }
        Ok(())
    }
```

**File:** types/src/validator_verifier.rs (L287-311)
```rust
    pub fn filter_invalid_signatures<T: Send + Sync + Serialize + CryptoHash>(
        &self,
        message: &T,
        signatures: BTreeMap<AccountAddress, SignatureWithStatus>,
    ) -> BTreeMap<AccountAddress, SignatureWithStatus> {
        signatures
            .into_iter()
            .collect_vec()
            .into_par_iter()
            .with_min_len(4) // At least 4 signatures are verified in each task
            .filter_map(|(account_address, signature)| {
                if signature.is_verified()
                    || self
                        .verify(account_address, message, signature.signature())
                        .is_ok()
                {
                    signature.set_verified();
                    Some((account_address, signature))
                } else {
                    self.add_pessimistic_verify_set(account_address);
                    None
                }
            })
            .collect()
    }
```

**File:** config/src/config/consensus_config.rs (L379-379)
```rust
            num_bounded_executor_tasks: 16,
```

**File:** consensus/src/pipeline/buffer_manager.rs (L919-934)
```rust
        spawn_named!("buffer manager verification", async move {
            while let Some((sender, commit_msg)) = commit_msg_rx.next().await {
                let tx = verified_commit_msg_tx.clone();
                let epoch_state_clone = epoch_state.clone();
                bounded_executor
                    .spawn(async move {
                        match commit_msg.req.verify(sender, &epoch_state_clone.verifier) {
                            Ok(_) => {
                                let _ = tx.unbounded_send(commit_msg);
                            },
                            Err(e) => warn!("Invalid commit message: {}", e),
                        }
                    })
                    .await;
            }
        });
```

**File:** crates/bounded-executor/src/executor.rs (L45-52)
```rust
    pub async fn spawn<F>(&self, future: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let permit = self.acquire_permit().await;
        self.executor.spawn(future_with_permit(future, permit))
    }
```
