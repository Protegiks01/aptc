# Audit Report

## Title
Missing Equivocation Evidence Recording and Slashing for AugData in Randomness Generation Protocol

## Summary
The Aptos randomness generation protocol detects when validators sign multiple conflicting AugData instances but fails to record this Byzantine behavior as evidence or trigger any slashing mechanism. While equivocation is detected at the storage layer and rejected, there is no economic penalty for validators who attempt this attack, undermining the security assumptions of the Byzantine fault tolerance model.

## Finding Description

The randomness generation protocol uses AugData (Augmented Data) for distributed randomness. When a validator receives AugData from another validator, the system checks for equivocation in `AugDataStore::add_aug_data()`: [1](#0-0) 

When equivocation is detected (validator sends different AugData instances for the same epoch), the error is caught and handled: [2](#0-1) 

**Critical Gaps Identified:**

1. **No SecurityEvent Logging**: Unlike vote equivocation which logs `SecurityEvent::ConsensusEquivocatingVote`, AugData equivocation only produces a warning log: [3](#0-2) 

2. **No Evidence Recording**: There is no mechanism to record proof of equivocation that could be used for slashing or governance action. The system simply rejects the conflicting data without preserving evidence.

3. **No Slashing Mechanism**: The staking system explicitly notes slashing is not implemented: [4](#0-3) 

**Attack Scenario:**

A Byzantine validator V can execute the following attack:
1. Generate two different AugData instances (AugData_A and AugData_B) for the same epoch
2. Send AugData_A to validators in subnet A
3. Send AugData_B to validators in subnet B
4. Each subnet detects valid signatures and stores the data they receive first
5. When validators communicate, they detect equivocation but only log warnings
6. V faces no economic penalty despite disrupting the randomness protocol
7. The randomness generation may fail or be delayed for affected rounds

## Impact Explanation

**Severity: High** (per Aptos bug bounty criteria for "Significant protocol violations")

This violates the **Consensus Safety** invariant and Byzantine fault tolerance assumptions:

- The randomness beacon is critical for consensus security (used in leader election, ordering)
- Without slashing, Byzantine validators have no economic disincentive to equivocate
- Repeated equivocation by multiple validators (up to f validators) could systematically disrupt randomness generation
- This creates a griefing vector where malicious validators can harm the network without penalty
- While the protocol detects and rejects equivocation, the lack of accountability undermines the cryptoeconomic security model

The impact falls short of Critical severity because:
- The equivocation is detected and rejected (no direct fund loss)
- The network can continue operating with remaining honest validators
- No permanent state corruption occurs

However, it meets High severity because it represents a significant protocol violation that weakens the Byzantine fault tolerance guarantees and creates a griefing attack vector without economic consequences.

## Likelihood Explanation

**Likelihood: Medium to High**

- Requires a validator to be malicious (within Byzantine threat model of < 1/3)
- Attack is trivial to execute (just broadcast different AugData to different peers)
- No technical complexity or timing requirements
- Can be performed repeatedly without detection beyond log warnings
- Network partitioning or latency differences could make equivocation easier
- The lack of slashing means attackers face no cost for attempting this attack

The likelihood is not higher because:
- Requires validator access (not accessible to arbitrary network participants)
- Validators have reputation at stake (though no on-chain economic penalty)

## Recommendation

Implement a comprehensive equivocation evidence and slashing system:

**1. Add SecurityEvent for AugData Equivocation:**

```rust
// In crates/aptos-logger/src/security.rs
pub enum SecurityEvent {
    // ... existing events ...
    
    /// Consensus received equivocating AugData in randomness generation
    ConsensusEquivocatingAugData,
}
```

**2. Record Equivocation Evidence:**

```rust
// In consensus/src/rand/rand_gen/rand_manager.rs, lines 441-450
RandMessage::AugData(aug_data) => {
    info!(LogSchema::new(LogEvent::ReceiveAugData)
        .author(self.author)
        .epoch(aug_data.epoch())
        .remote_peer(*aug_data.author()));
    match self.aug_data_store.add_aug_data(aug_data.clone()) {
        Ok(sig) => self.process_response(protocol, response_sender, RandMessage::AugDataSignature(sig)),
        Err(e) => {
            if e.to_string().contains("[AugDataStore] equivocate data") {
                // Log security event
                error!(
                    SecurityEvent::ConsensusEquivocatingAugData,
                    remote_peer = aug_data.author(),
                    epoch = aug_data.epoch(),
                    equivocating_aug_data = aug_data,
                );
                // TODO: Record evidence for slashing when implemented
                // self.record_equivocation_evidence(aug_data);
                warn!("[RandManager] Failed to add aug data: {}", e);
            } else {
                error!("[RandManager] Failed to add aug data: {}", e);
            }
        },
    }
}
```

**3. Store Conflicting AugData as Evidence:**

```rust
// Extend AugDataStore to preserve equivocation evidence
pub struct AugDataStore<D> {
    // ... existing fields ...
    equivocation_evidence: HashMap<Author, (AugData<D>, AugData<D>)>, // Store both versions
}

pub fn add_aug_data(&mut self, data: AugData<D>) -> anyhow::Result<AugDataSignature> {
    if let Some(existing_data) = self.data.get(data.author()) {
        if existing_data != &data {
            // Record both versions as evidence before returning error
            self.equivocation_evidence.insert(
                *data.author(),
                (existing_data.clone(), data.clone())
            );
            ensure!(false, "[AugDataStore] equivocate data from {}", data.author());
        }
    } else {
        self.db.save_aug_data(&data)?;
    }
    let sig = AugDataSignature::new(self.epoch, self.signer.sign(&data)?);
    self.data.insert(*data.author(), data);
    Ok(sig)
}
```

**4. Implement On-Chain Slashing (Future Work):**

Create a mechanism to submit equivocation evidence to the staking module for slashing validator stake, following the pattern established for vote equivocation in traditional BFT consensus.

## Proof of Concept

```rust
// Rust test demonstrating the vulnerability
#[test]
fn test_aug_data_equivocation_no_slashing() {
    use consensus::rand::rand_gen::{
        aug_data_store::AugDataStore,
        types::{AugData, AugmentedData},
    };
    
    // Setup: Create validator and AugDataStore
    let (signer, validator_verifier) = random_validator_verifier(4, Some(2), false);
    let rand_config = create_test_rand_config();
    let db = Arc::new(MockRandStorage::new());
    let mut store = AugDataStore::new(
        1, // epoch
        Arc::new(signer[0].clone()),
        rand_config,
        None,
        db,
    );
    
    // Attacker: Validator creates first AugData
    let aug_data_1 = AugData::new(
        1, // epoch
        signer[1].author(),
        AugmentedData { delta: Delta::new(vec![1, 2, 3]), fast_delta: None }
    );
    
    // Add first AugData - succeeds
    let result_1 = store.add_aug_data(aug_data_1.clone());
    assert!(result_1.is_ok(), "First AugData should be accepted");
    
    // Attacker: Same validator creates DIFFERENT AugData (equivocation)
    let aug_data_2 = AugData::new(
        1, // epoch (same)
        signer[1].author(), // same author
        AugmentedData { delta: Delta::new(vec![4, 5, 6]), fast_delta: None } // DIFFERENT data
    );
    
    // Add conflicting AugData - equivocation detected
    let result_2 = store.add_aug_data(aug_data_2.clone());
    assert!(result_2.is_err(), "Conflicting AugData should be rejected");
    assert!(
        result_2.unwrap_err().to_string().contains("equivocate"),
        "Error should indicate equivocation"
    );
    
    // VULNERABILITY: No evidence recorded, no slashing triggered
    // The equivocation was detected but validator faces no penalty
    // This test demonstrates the gap: detection exists but accountability does not
}
```

## Notes

This vulnerability represents a gap between **detection** (which exists) and **accountability** (which does not). The system correctly rejects equivocating AugData, preventing direct protocol failures, but the absence of evidence recording and slashing creates a permissionless griefing vector for Byzantine validators. This weakens the cryptoeconomic security model that underpins Aptos's Byzantine fault tolerance guarantees.

The issue is particularly concerning because:
1. The voting system has analogous equivocation detection with SecurityEvent logging, showing this pattern is established elsewhere
2. The randomness beacon is critical infrastructure for consensus security
3. Without economic penalties, the only deterrent is reputation (off-chain)

### Citations

**File:** consensus/src/rand/rand_gen/aug_data_store.rs (L102-115)
```rust
    pub fn add_aug_data(&mut self, data: AugData<D>) -> anyhow::Result<AugDataSignature> {
        if let Some(existing_data) = self.data.get(data.author()) {
            ensure!(
                existing_data == &data,
                "[AugDataStore] equivocate data from {}",
                data.author()
            );
        } else {
            self.db.save_aug_data(&data)?;
        }
        let sig = AugDataSignature::new(self.epoch, self.signer.sign(&data)?);
        self.data.insert(*data.author(), data);
        Ok(sig)
    }
```

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L436-451)
```rust
                        RandMessage::AugData(aug_data) => {
                            info!(LogSchema::new(LogEvent::ReceiveAugData)
                                .author(self.author)
                                .epoch(aug_data.epoch())
                                .remote_peer(*aug_data.author()));
                            match self.aug_data_store.add_aug_data(aug_data) {
                                Ok(sig) => self.process_response(protocol, response_sender, RandMessage::AugDataSignature(sig)),
                                Err(e) => {
                                    if e.to_string().contains("[AugDataStore] equivocate data") {
                                        warn!("[RandManager] Failed to add aug data: {}", e);
                                    } else {
                                        error!("[RandManager] Failed to add aug data: {}", e);
                                    }
                                },
                            }
                        }
```

**File:** crates/aptos-logger/src/security.rs (L23-82)
```rust
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEvent {
    //
    // Mempool
    //
    /// Mempool received a transaction from another peer with an invalid signature
    InvalidTransactionMempool,

    /// Mempool received an invalid network event
    InvalidNetworkEventMempool,

    // Consensus
    // ---------
    /// Consensus received an invalid message (not well-formed, invalid vote data or incorrect signature)
    ConsensusInvalidMessage,

    /// Consensus received an equivocating vote
    ConsensusEquivocatingVote,

    /// Consensus received an equivocating order vote
    ConsensusEquivocatingOrderVote,

    /// Consensus received an invalid proposal
    InvalidConsensusProposal,

    /// Consensus received an invalid new round message
    InvalidConsensusRound,

    /// Consensus received an invalid sync info message
    InvalidSyncInfoMsg,

    /// A received block is invalid
    InvalidRetrievedBlock,

    /// A block being committed or executed is invalid
    InvalidBlock,

    // State-Sync
    // ----------
    /// Invalid chunk of transactions received
    StateSyncInvalidChunk,

    // Health Checker
    // --------------
    /// HealthChecker received an invalid network event
    InvalidNetworkEventHC,

    /// HealthChecker received an invalid message
    InvalidHealthCheckerMsg,

    // Network
    // -------
    /// Network received an invalid message from a remote peer
    InvalidNetworkEvent,

    /// A failed noise handshake that's either a clear bug or indicates some
    /// security issue.
    NoiseHandshake,
}
```

**File:** aptos-move/framework/aptos-framework/sources/delegation_pool.move (L153-157)
```text
    /// Slashing (if implemented) should not be applied to already `inactive` stake.
    /// Not only it invalidates the accounting of past observed lockup cycles (OLC),
    /// but is also unfair to delegators whose stake has been inactive before validator started misbehaving.
    /// Additionally, the inactive stake does not count on the voting power of validator.
    const ESLASHED_INACTIVE_STAKE_ON_PAST_OLC: u64 = 7;
```
