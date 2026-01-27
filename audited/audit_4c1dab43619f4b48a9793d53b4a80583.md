# Audit Report

## Title
Validator Decryption Key Share Equivocation Enables Consensus Disruption Without Detection

## Summary
The `SecretShareAggregator` in the consensus layer fails to detect when validators submit multiple conflicting decryption key shares for the same digest. A malicious validator can equivocate by broadcasting different shares to different peers, causing honest nodes to reconstruct different decryption keys and potentially breaking consensus determinism. No equivocation detection, logging, or penalty mechanism exists, despite similar protection being implemented for augmented data.

## Finding Description

The vulnerability exists in the secret share aggregation logic used by Aptos consensus for batch threshold encryption. When validators derive and broadcast decryption key shares, the `SecretShareAggregator::add_share()` method silently replaces any existing share from the same validator without detecting equivocation: [1](#0-0) 

The `HashMap::insert()` operation returns `Some(old_value)` if a key already existed, but the code only checks `is_none()` to decide whether to increment the weight counter. Critically, it **never compares** the new share with the existing share to detect equivocation. The new share always replaces the old one.

**Attack Path:**

1. A malicious validator derives a legitimate decryption key share for a given digest using their master secret key share
2. The validator broadcasts this share to a subset of peers
3. The validator derives a **different** decryption key share for the **same digest** (both shares are cryptographically valid since they're signed with the validator's legitimate key)
4. The validator broadcasts the second share to different peers or the same peers at a later time
5. Different honest nodes receive different shares from the equivocating validator
6. When nodes aggregate shares to reconstruct the decryption key, they use whichever share they received last from that validator
7. Nodes with different shares reconstruct **different decryption keys**
8. These different keys lead to different decryption results for the same ciphertext, breaking consensus determinism

The vulnerability is confirmed by contrasting it with the **correct** equivocation detection implemented for augmented data in the same codebase: [2](#0-1) 

The `AugDataStore` explicitly checks if incoming data matches existing data from the same author and raises an error for equivocation, proving the developers are aware of this attack vector but failed to implement the same protection for secret shares.

**Security Invariants Broken:**

1. **Consensus Safety**: Different validators see different decryption keys, leading to different block execution results
2. **Deterministic Execution**: Nodes decrypt the same ciphertext to different plaintexts, violating state determinism
3. **Byzantine Fault Tolerance**: A single malicious validator can cause inconsistencies without being detected, undermining the < 1/3 Byzantine assumption

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program criteria:

- **Significant Protocol Violation**: The batch threshold encryption protocol assumes validators provide consistent, non-equivocating shares. This assumption is violated without detection.

- **Consensus Disruption**: Different nodes reconstructing different decryption keys will produce different execution results when processing encrypted transaction batches, potentially causing:
  - Block execution divergence requiring manual intervention
  - State inconsistencies across validator nodes
  - Liveness failures if nodes cannot agree on decrypted content

- **No Accountability**: The malicious validator faces no penalty, detection, or slashing because equivocation is neither logged nor reported. Other validators cannot prove misbehavior.

- **Byzantine Amplification**: A validator below the 1/3 Byzantine threshold can cause disproportionate damage by selectively sending different shares to partition the validator set.

While this doesn't directly cause fund theft, it represents a fundamental violation of consensus safety guarantees that could lead to network partition requiring coordinated recovery.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

**Attacker Requirements:**
- Must be a validator with valid secret key shares (privileged position)
- No additional infrastructure or collusion required
- Attack is undetectable, so no risk of being caught

**Execution Complexity:**
- Low technical barrier: validator simply broadcasts different valid shares at different times
- No cryptographic breaking required - both shares are legitimately signed
- Can be triggered selectively to target specific blocks or peers

**Detection Difficulty:**
- No logging of share replacement
- No comparison with previous shares
- Network-level message deduplication does not exist
- Honest validators cannot prove equivocation without keeping all historical shares

The attack is realistic because:
1. The code path is actively used in consensus for every block requiring decryption
2. Network message ordering is non-deterministic, making the attack subtle
3. The absence of equivocation detection in related randomness code (`AugDataStore`) suggests awareness but incomplete implementation

## Recommendation

Implement equivocation detection matching the pattern already used in `AugDataStore`. Modify `SecretShareAggregator::add_share()` to check if an existing share differs from the new share:

```rust
pub fn add_share(&mut self, share: SecretShare, weight: u64) -> anyhow::Result<()> {
    if let Some(existing_share) = self.shares.get(&share.author) {
        ensure!(
            existing_share == &share,
            "[SecretShareAggregator] equivocate share from {}",
            share.author
        );
        return Ok(()); // Share already exists and matches
    }
    
    self.shares.insert(share.author, share);
    self.total_weight += weight;
    Ok(())
}
```

Additional hardening:
1. Change the return type to `Result<()>` to propagate equivocation errors
2. Update callers to handle and log equivocation attempts
3. Consider slashing or reputation penalties for detected equivocation
4. Add metrics to monitor equivocation attempts across the network [3](#0-2) 

Update the caller to handle equivocation errors appropriately.

## Proof of Concept

```rust
#[cfg(test)]
mod test_equivocation {
    use super::*;
    use aptos_types::secret_sharing::{SecretShare, SecretShareMetadata};
    use aptos_crypto::HashValue;

    #[test]
    fn test_validator_can_equivocate_without_detection() {
        // Setup: Create two different shares from the same validator
        let validator = Author::random();
        let metadata = SecretShareMetadata::new(
            1, // epoch
            10, // round  
            100, // timestamp
            HashValue::random(),
            Digest::new_for_testing(),
        );
        
        // Validator creates first share
        let share1 = SecretShare::new(
            validator,
            metadata.clone(),
            SecretKeyShare::new_for_testing(1),
        );
        
        // Validator creates DIFFERENT second share for SAME metadata
        let share2 = SecretShare::new(
            validator,
            metadata.clone(),
            SecretKeyShare::new_for_testing(2), // Different share value!
        );
        
        // Add shares to aggregator
        let mut aggregator = SecretShareAggregator::new(Author::random());
        
        // First share added successfully
        aggregator.add_share(share1.clone(), 1);
        assert_eq!(aggregator.shares.len(), 1);
        assert_eq!(aggregator.total_weight, 1);
        
        // VULNERABILITY: Second conflicting share replaces first WITHOUT ERROR
        aggregator.add_share(share2.clone(), 1);
        assert_eq!(aggregator.shares.len(), 1); // Still only 1 entry
        assert_eq!(aggregator.total_weight, 1); // Weight not double-counted (correct)
        
        // CRITICAL: The stored share is now share2, not share1!
        let stored = aggregator.shares.get(&validator).unwrap();
        assert_eq!(stored.share(), share2.share()); // share2 replaced share1
        assert_ne!(stored.share(), share1.share()); // share1 is lost
        
        // No error was raised, no logging occurred - equivocation is silent!
    }
}
```

**Notes:**

This vulnerability specifically affects the secret sharing protocol used in Aptos consensus for batch threshold encryption. The `DecryptionKeyShareVerifyError` mentioned in the security question only validates that a share is cryptographically correct (properly signed), but does **not** prevent a validator from creating multiple valid yet different shares for the same digest. The aggregation logic lacks the consistency check needed to detect this Byzantine behavior, unlike the parallel implementation for augmented data which correctly detects equivocation.

### Citations

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L32-36)
```rust
    pub fn add_share(&mut self, share: SecretShare, weight: u64) {
        if self.shares.insert(share.author, share).is_none() {
            self.total_weight += weight;
        }
    }
```

**File:** consensus/src/rand/rand_gen/aug_data_store.rs (L102-108)
```rust
    pub fn add_aug_data(&mut self, data: AugData<D>) -> anyhow::Result<AugDataSignature> {
        if let Some(existing_data) = self.data.get(data.author()) {
            ensure!(
                existing_data == &data,
                "[AugDataStore] equivocate data from {}",
                data.author()
            );
```

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L310-320)
```rust
            SecretShareMessage::Share(share) => {
                info!(LogSchema::new(LogEvent::ReceiveSecretShare)
                    .author(self.author)
                    .epoch(share.epoch())
                    .round(share.metadata().round)
                    .remote_peer(*share.author()));

                if let Err(e) = self.secret_share_store.lock().add_share(share) {
                    warn!("[SecretShareManager] Failed to add share: {}", e);
                }
            },
```
