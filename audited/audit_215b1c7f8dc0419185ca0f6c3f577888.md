# Audit Report

## Title
Epoch Boundary Confusion: Inflated Secret Share Acceptance Window at Epoch Transitions

## Summary
At epoch transitions, the `SecretShareStore` initializes `highest_known_round` with the last committed round from the previous epoch, while round numbers reset to 0 in the new epoch. This creates a semantic mismatch where the acceptance window for secret shares becomes up to 6x larger than intended (rounds 0-1200 instead of 0-200), violating the `FUTURE_ROUNDS_TO_ACCEPT` invariant and creating an attack surface for resource exhaustion.

## Finding Description

The vulnerability occurs in the secret sharing subsystem's epoch transition logic. When a new epoch begins:

1. **Round Reset**: Rounds reset to 0 at epoch boundaries as confirmed by the genesis block creation logic [1](#0-0) 

2. **Improper Initialization**: The new `SecretShareStore` is created with `highest_known_round = 0` [2](#0-1) , but is immediately updated with the previous epoch's final round via `update_highest_known_round(highest_known_round)` where `highest_known_round` comes from the old epoch's committed round [3](#0-2) 

3. **Validation Check Uses Stale Value**: When validating incoming shares, the code checks: `metadata.round <= self.highest_known_round + FUTURE_ROUNDS_TO_ACCEPT` [4](#0-3) 

4. **Inflated Window**: If the previous epoch ended at round 1000, the acceptance window becomes `round <= 1000 + 200 = 1200` for the new epoch, instead of the intended `round <= 0 + 200 = 200` (or `1 + 200 = 201` after the first block).

5. **Persistence of Issue**: The `update_highest_known_round` uses `std::cmp::max` [5](#0-4) , so even after processing the first block of the new epoch (round 1), `highest_known_round` remains at 1000, not 1.

The epoch check at line 244/262 prevents shares from the *old* epoch from being accepted, but does not prevent the inflated acceptance window for shares from the *new* epoch.

## Impact Explanation

**Severity: Medium to High**

This vulnerability creates several security concerns:

1. **Resource Exhaustion**: An attacker could flood the system with shares for rounds 0-1200 at epoch start, consuming 6x more memory and processing resources than intended. Each share requires storage in `secret_share_map` and verification processing.

2. **Invariant Violation**: The `FUTURE_ROUNDS_TO_ACCEPT = 200` constant [6](#0-5)  exists to limit the window of acceptable future shares. This protection is bypassed for up to 1000 rounds at each epoch transition.

3. **Consensus Disruption**: Accepting shares far into the future could interfere with normal consensus operation, particularly if malicious validators pre-commit to shares before seeing actual block proposals.

4. **Validator Node Slowdowns**: The additional memory pressure and processing overhead could degrade validator performance during critical epoch transitions, qualifying as **High Severity** per the bug bounty criteria.

## Likelihood Explanation

**Likelihood: High**

This vulnerability triggers automatically at every epoch transition without requiring special attacker actions:

1. **Guaranteed Occurrence**: Every epoch transition creates this condition
2. **Long-Duration Epochs**: In production, epochs can last thousands of rounds, amplifying the window size
3. **No Special Privileges Required**: Any validator can send shares for future rounds
4. **No Detection**: The inflated window is transparent to normal operation until exploited

The attack complexity is low - an attacker simply needs to send shares for high round numbers (up to old_epoch_last_round + 200) immediately after epoch transition.

## Recommendation

Reset `highest_known_round` to match the new epoch's round numbering when initializing the `SecretShareStore` for a new epoch. Modify the initialization logic:

**In `consensus/src/rand/secret_sharing/secret_share_manager.rs`:**

```rust
pub async fn start(
    mut self,
    mut incoming_blocks: Receiver<OrderedBlocks>,
    incoming_rpc_request: aptos_channel::Receiver<Author, IncomingSecretShareRequest>,
    mut reset_rx: Receiver<ResetRequest>,
    bounded_executor: BoundedExecutor,
    highest_known_round: Round,
) {
    info!("SecretShareManager started");
    let (verified_msg_tx, mut verified_msg_rx) = unbounded();
    let epoch_state = self.epoch_state.clone();
    let dec_config = self.config.clone();
    {
        // FIX: Reset to 0 for new epoch instead of using old epoch's round
        self.secret_share_store
            .lock()
            .update_highest_known_round(0);  // Changed from highest_known_round
    }
    // ... rest of the function
}
```

**Alternative**: Pass an explicit epoch transition flag and only use `highest_known_round` from the old epoch if rounds are continuous across epochs (which they are not).

## Proof of Concept

```rust
// Reproduction scenario (pseudocode demonstrating the vulnerability)
// This would be implemented as a Rust test in consensus/src/rand/secret_sharing/

#[test]
fn test_epoch_boundary_acceptance_window_inflation() {
    // Setup: Epoch 1 ending at round 1000
    let old_epoch = 1;
    let old_epoch_last_round = 1000;
    
    // Create new SecretShareStore for epoch 2
    let new_epoch = 2;
    let (tx, _rx) = unbounded();
    let mut store = SecretShareStore::new(
        new_epoch,
        test_author(),
        test_config(),
        tx,
    );
    
    // Initialize as done in SecretShareManager::start()
    store.update_highest_known_round(old_epoch_last_round);  // BUG: Uses old epoch's round
    
    // Verify the vulnerability: shares for round 1200 are accepted
    let share_round_1200 = create_test_share(new_epoch, 1200);
    
    // This should FAIL but PASSES due to: 1200 <= 1000 + 200
    assert!(store.add_share(share_round_1200).is_ok());  // ❌ VULNERABILITY
    
    // Expected behavior: only rounds 0-200 should be accepted
    let share_round_250 = create_test_share(new_epoch, 250);
    assert!(store.add_share(share_round_250).is_ok());  // Should fail, but passes
    
    // What SHOULD happen with the fix:
    // store.update_highest_known_round(0);  // Reset to 0 for new epoch
    // assert!(store.add_share(share_round_250).is_err());  // ✓ Correctly rejected
}
```

**Notes**

The vulnerability is structural and affects the secret sharing subsystem's invariant enforcement at epoch boundaries. While the epoch check prevents cross-epoch share acceptance [7](#0-6) , the inflated acceptance window within the new epoch creates an unnecessary attack surface that violates the intended 200-round limit specified by `FUTURE_ROUNDS_TO_ACCEPT`.

### Citations

**File:** consensus/consensus-types/src/block_data.rs (L292-301)
```rust
    pub fn new_genesis(timestamp_usecs: u64, quorum_cert: QuorumCert) -> Self {
        assume!(quorum_cert.certified_block().epoch() < u64::MAX); // unlikely to be false in this universe
        Self {
            epoch: quorum_cert.certified_block().epoch() + 1,
            round: 0,
            timestamp_usecs,
            quorum_cert,
            block_type: BlockType::Genesis,
        }
    }
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L217-231)
```rust
    pub fn new(
        epoch: u64,
        author: Author,
        dec_config: SecretShareConfig,
        decision_tx: Sender<SecretSharedKey>,
    ) -> Self {
        Self {
            epoch,
            self_author: author,
            secret_share_config: dec_config,
            secret_share_map: HashMap::new(),
            highest_known_round: 0,
            decision_tx,
        }
    }
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L233-235)
```rust
    pub fn update_highest_known_round(&mut self, round: u64) {
        self.highest_known_round = std::cmp::max(self.highest_known_round, round);
    }
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L244-248)
```rust
        ensure!(metadata.epoch == self.epoch, "Share from different epoch");
        ensure!(
            metadata.round <= self.highest_known_round + FUTURE_ROUNDS_TO_ACCEPT,
            "Share from future round"
        );
```

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L336-340)
```rust
        {
            self.secret_share_store
                .lock()
                .update_highest_known_round(highest_known_round);
        }
```

**File:** consensus/src/rand/secret_sharing/types.rs (L16-16)
```rust
pub const FUTURE_ROUNDS_TO_ACCEPT: u64 = 200;
```
