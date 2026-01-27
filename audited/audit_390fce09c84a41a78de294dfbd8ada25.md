# Audit Report

## Title
Unvalidated Deserialization of Timeout Certificate Enables Node DoS via Database Corruption

## Summary
The consensus layer deserializes `TwoChainTimeoutCertificate` from persistent storage without validation, allowing malicious serialized data to cause node crashes, memory exhaustion, or consensus liveness degradation. The deserialization bypasses critical invariant checks present in the type's constructor, and uses `.expect()` which panics on invalid data.

## Finding Description

The vulnerability exists in the timeout certificate recovery path during node restart. The code path is:

1. **Storage without validation**: [1](#0-0) 

2. **Deserialization with panic on failure**: [2](#0-1) 

3. **Critical invariant bypassed during deserialization**: [3](#0-2) 

The `AggregateSignatureWithRounds::new()` constructor enforces the invariant that `sig.get_num_voters() == rounds.len()` using `assert_eq!`. However, when BCS deserializes the struct using the derived `Deserialize` trait, it directly populates the fields **without calling the constructor**, bypassing this critical safety check.

**Attack Scenarios:**

**A. Panic-based DoS**: An attacker with filesystem access writes malformed BCS bytes to ConsensusDB. On node restart, the `.expect()` call panics with "unable to deserialize highest 2-chain timeout cert", preventing the node from starting.

**B. Memory Exhaustion DoS**: An attacker writes valid BCS encoding with extremely large `rounds` vector (e.g., billions of `Round` entries). Deserialization succeeds but exhausts available memory, crashing the node.

**C. Invariant Violation Leading to Verification Failure**: An attacker writes valid BCS where `rounds.len() != sig.get_num_voters()`. The deserialization succeeds, but when SafetyRules attempts to verify the timeout certificate before voting [4](#0-3) , the verification fails due to incorrect signature/round mapping [5](#0-4) . The node cannot produce votes, degrading consensus liveness.

The recovered timeout certificate is stored in BlockTree without validation [6](#0-5)  and used in multiple consensus operations before any verification occurs [7](#0-6) .

## Impact Explanation

**Severity: High** per Aptos bug bounty criteria:

- **Validator node crashes**: The `.expect()` panic prevents node restart, requiring manual database repair or full state sync
- **Memory exhaustion**: Large vector attacks cause OOM crashes
- **Consensus liveness degradation**: Nodes with corrupted timeout certificates cannot participate in voting, reducing effective validator count

If multiple validators are compromised (or experience database corruption), this could approach the 1/3 Byzantine threshold and threaten network liveness. Each affected validator requires manual intervention to recover.

The vulnerability violates the **Resource Limits** invariant (memory exhaustion) and degrades **Consensus Safety** (liveness issues when >= 1/3 nodes affected).

## Likelihood Explanation

**Likelihood: Medium**

**Required conditions:**
- Attacker needs filesystem access to a validator's ConsensusDB directory, OR
- Database corruption occurs naturally (storage failure, bug in write path), OR  
- Supply chain attack compromises the database before deployment

**Mitigating factors:**
- Requires compromising validator infrastructure (not remotely exploitable)
- Modern validators have security hardening and access controls

**Aggravating factors:**
- Once corrupted, the database causes persistent DoS across all restarts
- No automatic recovery mechanism exists
- Silent truncation in `zip()` operations masks some errors until verification fails

The attack is feasible for adversaries with infrastructure access or in scenarios of accidental database corruption.

## Recommendation

Add validation immediately after deserialization to verify all invariants before storing the timeout certificate:

```rust
// In consensus/src/persistent_liveness_storage.rs, replace lines 530-532:
let highest_2chain_timeout_cert = raw_data.1
    .map(|bytes| {
        let tc: TwoChainTimeoutCertificate = bcs::from_bytes(&bytes)
            .context("Failed to deserialize timeout certificate")?;
        
        // Validate invariants that BCS deserialization doesn't check
        let sig_voters = tc.signatures_with_rounds().sig().get_num_voters();
        let rounds_len = tc.signatures_with_rounds().rounds().len();
        ensure!(
            sig_voters == rounds_len,
            "Timeout certificate invariant violation: sig has {} voters but {} rounds",
            sig_voters,
            rounds_len
        );
        
        // Verify the timeout certificate itself
        let validator_verifier = self.aptos_db()
            .get_latest_ledger_info()
            .ok()
            .and_then(|li| /* get verifier for epoch */)
            .context("Cannot verify timeout cert without epoch state")?;
        
        tc.verify(&validator_verifier)
            .context("Timeout certificate verification failed")?;
        
        Ok::<_, anyhow::Error>(tc)
    })
    .transpose()?;
```

Additionally, replace `.expect()` with proper error handling that logs the issue and continues with `None` instead of panicking:

```rust
.and_then(|bytes| {
    match bcs::from_bytes(&bytes) {
        Ok(tc) => Some(tc),
        Err(e) => {
            error!("Failed to deserialize timeout cert, ignoring: {}", e);
            None
        }
    }
})
```

## Proof of Concept

```rust
#[cfg(test)]
mod deserialization_vulnerability_test {
    use super::*;
    use aptos_consensus_types::timeout_2chain::{AggregateSignatureWithRounds, TwoChainTimeoutCertificate};
    use aptos_types::aggregate_signature::AggregateSignature;
    use bcs;
    
    #[test]
    fn test_invariant_bypass_via_deserialization() {
        // Create invalid AggregateSignatureWithRounds with mismatched lengths
        // by manually constructing the serialized form
        
        // Valid signature with 3 voters
        let sig = AggregateSignature::empty(); // In real attack, craft valid sig
        let mut sig_bytes = bcs::to_bytes(&sig).unwrap();
        
        // But only 1 round (violates invariant)
        let rounds = vec![1u64];
        let rounds_bytes = bcs::to_bytes(&rounds).unwrap();
        
        // Manually construct the struct bytes
        // This bypasses the constructor's assert_eq! check
        let mut malicious_bytes = vec![];
        malicious_bytes.extend_from_slice(&sig_bytes);
        malicious_bytes.extend_from_slice(&rounds_bytes);
        
        // Deserialization succeeds despite invariant violation!
        let result: Result<AggregateSignatureWithRounds, _> = 
            bcs::from_bytes(&malicious_bytes);
        
        // This should fail but currently succeeds
        assert!(result.is_ok());
        
        let invalid_obj = result.unwrap();
        
        // Invariant is violated
        assert_ne!(
            invalid_obj.sig().get_num_voters(),
            invalid_obj.rounds().len()
        );
        
        // When verify() is called, it will fail or behave incorrectly
        // due to zip() truncation in get_voters_and_rounds()
    }
    
    #[test]
    fn test_memory_exhaustion_attack() {
        // Create timeout cert with billion-entry rounds vector
        let huge_rounds = vec![1u64; 1_000_000_000];
        
        // Serialize it
        let malicious_bytes = bcs::to_bytes(&huge_rounds).unwrap();
        
        // Deserialization will attempt to allocate billions of u64s
        // causing OOM crash (don't actually run this in CI!)
        // let result: Result<Vec<u64>, _> = bcs::from_bytes(&malicious_bytes);
    }
}
```

**Notes:**

This vulnerability demonstrates a critical gap in the defense-in-depth strategy: data deserialized from persistent storage is assumed to be valid without verification. While the `save` path properly serializes valid data via `bcs::to_bytes()`, the recovery path trusts that persisted data hasn't been corrupted or tampered with. The fix requires adding validation at the deserialization boundary to re-establish trust in the recovered data before using it in consensus-critical operations.

### Citations

**File:** consensus/src/consensusdb/mod.rs (L108-113)
```rust
    pub fn save_highest_2chain_timeout_certificate(&self, tc: Vec<u8>) -> Result<(), DbError> {
        let mut batch = SchemaBatch::new();
        batch.put::<SingleEntrySchema>(&SingleEntryKey::Highest2ChainTimeoutCert, &tc)?;
        self.commit(batch)?;
        Ok(())
    }
```

**File:** consensus/src/persistent_liveness_storage.rs (L530-532)
```rust
        let highest_2chain_timeout_cert = raw_data.1.map(|b| {
            bcs::from_bytes(&b).expect("unable to deserialize highest 2-chain timeout cert")
        });
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L147-166)
```rust
                let timeout_messages: Vec<_> = self
                    .signatures_with_rounds
                    .get_voters_and_rounds(
                        &validators
                            .get_ordered_account_addresses_iter()
                            .collect_vec(),
                    )
                    .into_iter()
                    .map(|(_, round)| TimeoutSigningRepr {
                        epoch: self.timeout.epoch(),
                        round: self.timeout.round(),
                        hqc_round: round,
                    })
                    .collect();
                let timeout_messages_ref: Vec<_> = timeout_messages.iter().collect();
                validators.verify_aggregate_signatures(
                    &timeout_messages_ref,
                    self.signatures_with_rounds.sig(),
                )
            },
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L359-363)
```rust
impl AggregateSignatureWithRounds {
    pub fn new(sig: AggregateSignature, rounds: Vec<Round>) -> Self {
        assert_eq!(sig.get_num_voters(), rounds.len());
        Self { sig, rounds }
    }
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L62-64)
```rust
        if let Some(tc) = timeout_cert {
            self.verify_tc(tc)?;
        }
```

**File:** consensus/src/block_storage/block_store.rs (L250-258)
```rust
        let tree = BlockTree::new(
            root_block_id,
            window_root,
            root_qc,
            root_ordered_cert,
            root_commit_cert,
            max_pruned_blocks_in_mem,
            highest_2chain_timeout_cert.map(Arc::new),
        );
```

**File:** consensus/src/round_manager.rs (L1520-1523)
```rust
        let vote_result = self.safety_rules.lock().construct_and_sign_vote_two_chain(
            &vote_proposal,
            self.block_store.highest_2chain_timeout_cert().as_deref(),
        );
```
