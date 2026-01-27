# Audit Report

## Title
Inconsistent Round Validation in RandStore Prevents Legitimate Share Requests During Rapid Round Progression

## Summary
The `RandStore::get_self_share()` function enforces a stricter round validation check than `RandStore::add_share()`, creating an asymmetry that can prevent legitimate share retrieval during rapid consensus round progression. This can cause temporary delays in randomness generation when nodes lag behind by even one round.

## Finding Description

The randomness generation subsystem in Aptos consensus has an inconsistency in round validation between share storage and retrieval operations.

The `add_share()` method accepts shares for future rounds with a buffer of 200 rounds: [1](#0-0) [2](#0-1) 

However, the `get_self_share()` method only retrieves shares for rounds up to and including `highest_known_round`, with no buffer: [3](#0-2) 

The `highest_known_round` is only updated when processing block metadata: [4](#0-3) 

**Attack Scenario:**

1. During high-throughput consensus operation, Node A advances to round R+1 faster than Node B
2. Node B is at round R (`highest_known_round = R`) but receives proactive share broadcasts for round R+1 from other nodes
3. Node B successfully stores these shares via `add_share()` because `R+1 <= R + 200` passes validation
4. Node A sends a `RequestShare` message to Node B asking for B's share for round R+1
5. Node B's `get_self_share()` is invoked, but the check fails: `R+1 <= R` is false
6. The function returns an error instead of the share
7. The request handler logs a warning and does NOT respond with any share: [5](#0-4) 

8. Node A's reliable broadcast mechanism retries, but if Node B hasn't processed its block for round R+1, the same failure repeats
9. If multiple nodes are in this lagging state, share aggregation can be delayed or fail to reach the threshold

The system eventually recovers when Node B processes its block for round R+1 and updates `highest_known_round`, but this creates unnecessary delays and potential failures during rapid round progression.

## Impact Explanation

This issue falls under **Low Severity** per the Aptos bug bounty criteria as a "non-critical implementation bug." The impact is:

- **Temporary liveness degradation** in randomness generation during periods of rapid round progression or network latency
- Does NOT violate consensus safety invariants
- Does NOT enable fund theft, minting, or state corruption
- Does NOT cause permanent network partition or require hard fork
- Self-healing as lagging nodes catch up and process their blocks
- In worst case, could prevent randomness generation for specific rounds if too many nodes lag simultaneously, but this is temporary

This does not meet the threshold for Critical, High, or Medium severity as it doesn't cause permanent damage, consensus safety violations, or exploitable fund loss.

## Likelihood Explanation

**Moderate likelihood** during normal operations:

- Occurs naturally during high-throughput consensus when validators have slight performance differences or network delays
- Does not require malicious behavior or active exploitation
- More likely during network congestion or validator infrastructure variance
- Validators with slower hardware or network connections more susceptible
- Cannot be directly triggered by external attackers, but natural network conditions can create the scenario
- The 300ms delay before broadcasting share requests provides some natural buffer, but may not be sufficient during rapid round progression

## Recommendation

Make the round validation in `get_self_share()` consistent with `add_share()` by adding the same future rounds buffer:

```rust
pub fn get_self_share(
    &mut self,
    metadata: &RandMetadata,
) -> anyhow::Result<Option<RandShare<S>>> {
    ensure!(
        metadata.round <= self.highest_known_round + FUTURE_ROUNDS_TO_ACCEPT,
        "Request share from future round {}, highest known round {}",
        metadata.round,
        self.highest_known_round
    );
    Ok(self
        .rand_map
        .get(&metadata.round)
        .and_then(|item| item.get_self_share())
        .filter(|share| share.metadata() == metadata))
}
```

Alternatively, update `highest_known_round` when receiving shares via `add_share()` to reflect awareness of future rounds, though this may have broader implications for the round management logic.

## Proof of Concept

```rust
#[tokio::test]
async fn test_get_self_share_rejects_valid_future_round() {
    use crate::rand::rand_gen::{
        test_utils::{create_share_for_round},
        types::{MockShare, PathType, RandConfig},
    };
    use futures_channel::mpsc::unbounded;
    
    let ctxt = TestContext::new(vec![100; 4], 0);
    let (decision_tx, _decision_rx) = unbounded();
    let mut rand_store = RandStore::<MockShare>::new(
        ctxt.target_epoch,
        ctxt.authors[0],
        ctxt.rand_config.clone(),
        None,
        decision_tx,
    );
    
    // Set highest_known_round to 10
    rand_store.update_highest_known_round(10);
    
    // Add a share for round 11 - this succeeds because 11 <= 10 + 200
    let share_r11 = create_share_for_round(ctxt.target_epoch, 11, ctxt.authors[0]);
    let metadata_r11 = share_r11.metadata().clone();
    assert!(rand_store.add_share(share_r11, PathType::Slow).is_ok());
    
    // Try to retrieve the share for round 11 - this FAILS because 11 <= 10 is false
    let result = rand_store.get_self_share(&metadata_r11);
    assert!(result.is_err(), "get_self_share should reject round 11 when highest_known_round is 10");
    assert!(result.unwrap_err().to_string().contains("Request share from future round"));
    
    // The share exists in storage but cannot be retrieved
    // This demonstrates the inconsistency between add and get validation
}
```

## Notes

This finding demonstrates a liveness issue in the randomness generation subsystem where validation logic inconsistency can cause temporary operational degradation. While classified as Low severity due to its self-healing nature and lack of safety violations, it represents a real implementation bug that could impact network performance during high-throughput scenarios. The fix is straightforward and would improve the robustness of share request handling during rapid round progression.

### Citations

**File:** consensus/src/rand/rand_gen/rand_store.rs (L286-288)
```rust
            share.metadata().round <= self.highest_known_round + FUTURE_ROUNDS_TO_ACCEPT,
            "Share from future round"
        );
```

**File:** consensus/src/rand/rand_gen/rand_store.rs (L327-332)
```rust
        ensure!(
            metadata.round <= self.highest_known_round,
            "Request share from future round {}, highest known round {}",
            metadata.round,
            self.highest_known_round
        );
```

**File:** consensus/src/rand/rand_gen/types.rs (L26-26)
```rust
pub const FUTURE_ROUNDS_TO_ACCEPT: u64 = 200;
```

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L152-152)
```rust
        rand_store.update_highest_known_round(metadata.round());
```

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L398-412)
```rust
                            let result = self.rand_store.lock().get_self_share(request.rand_metadata());
                            match result {
                                Ok(maybe_share) => {
                                    let share = maybe_share.unwrap_or_else(|| {
                                        // reproduce previous share if not found
                                        let share = S::generate(&self.config, request.rand_metadata().clone());
                                        self.rand_store.lock().add_share(share.clone(), PathType::Slow).expect("Add self share should succeed");
                                        share
                                    });
                                    self.process_response(protocol, response_sender, RandMessage::Share(share));
                                },
                                Err(e) => {
                                    warn!("[RandManager] Failed to get share: {}", e);
                                }
                            }
```
