# Audit Report

## Title
Time-Based Denial of Service via Future Timestamp Blocks in Consensus Block Storage

## Summary
A malicious validator can cause other validators to waste significant time (up to 5 minutes per block) by proposing blocks with timestamps far in the future. The `insert_block_inner()` function unconditionally waits until the block's timestamp is reached, creating a denial-of-service vector that degrades consensus performance and throughput.

## Finding Description

The vulnerability exists in the consensus block insertion mechanism where validators synchronously wait for future-timestamped blocks before processing them.

**Attack Flow:**

1. A Byzantine validator becomes the proposer for a round
2. They create a valid block but set its timestamp up to 5 minutes in the future (within the allowed TIMEBOUND limit)
3. The block passes all validation checks:
   - [1](#0-0) 
   - The timestamp validation allows blocks up to 300 seconds (5 minutes) in the future
   - [2](#0-1) 
   - The proposer validation confirms the block is from a valid proposer
4. The block is inserted via:
   - [3](#0-2) 
5. In `insert_block_inner()`, validators unconditionally wait:
   - [4](#0-3) 
6. The wait is implemented as an async sleep that blocks consensus processing:
   - [5](#0-4) 

**Why Existing Safeguards Fail:**

The round deadline check was intended to prevent excessive waiting: [6](#0-5) 

However, this check only prevents timestamps that exceed the round deadline, not timestamps that are significantly in the future. If the round duration is long (e.g., due to exponential backoff), attackers can exploit the full gap between current time and the deadline.

**Repeated Attack:**
The malicious validator can repeat this attack in every round where they are the proposer, causing sustained performance degradation across the validator network.

## Impact Explanation

This vulnerability falls under **High Severity** per the Aptos bug bounty program: "Validator node slowdowns."

**Quantified Impact:**
- Each malicious block can cause validators to waste up to 5 minutes (or up to the round deadline, whichever is lower)
- With typical round times and a validator that is proposer ~1/N of rounds (where N = validator count), sustained attacks can significantly degrade network throughput
- Multiple validators affected simultaneously reduces network capacity
- Does not compromise safety (no double-spending) but severely impacts liveness

**Broken Invariants:**
- **Resource Limits**: Validators waste computational resources (time) waiting unnecessarily
- **Consensus Liveness**: Unnecessary delays slow consensus progress and reduce throughput

## Likelihood Explanation

**Likelihood: HIGH**

**Attacker Requirements:**
- Must be a validator in the active set (or compromise a validator's signing key)
- No collusion with other validators needed
- Can execute attack whenever they are the valid proposer for a round

**Feasibility:**
- Attack is trivial to execute - requires only setting a timestamp field
- No complex timing or race conditions required
- Guaranteed to succeed if attacker is the proposer
- Repeatable in every round where attacker is proposer

**Frequency:**
- In a validator set of N validators, each validator proposes approximately every N rounds
- Attack can be sustained over many rounds

## Recommendation

**Fix 1: Reject blocks with future timestamps relative to local time**

Modify the timestamp validation to reject blocks with timestamps more than a small delta (e.g., 2 seconds) ahead of the validator's local clock: [6](#0-5) 

Add an additional check before the round deadline check:

```rust
let current_time = self.time_service.get_current_timestamp();
const MAX_FUTURE_TIMESTAMP_DELTA: Duration = Duration::from_secs(2);

ensure!(
    block_time_since_epoch <= current_time + MAX_FUTURE_TIMESTAMP_DELTA,
    "[RoundManager] Block timestamp {:?} is too far in the future (current time: {:?})",
    block_time_since_epoch,
    current_time,
);
```

**Fix 2: Remove the wait mechanism**

Alternatively, remove the unconditional wait in `insert_block_inner()`: [4](#0-3) 

The wait mechanism serves to ensure "local time past the block time," but this can be enforced through validation rather than waiting. If blocks with future timestamps are rejected during validation (Fix 1), the wait becomes unnecessary.

**Recommended Approach:**
Implement both fixes:
1. Reject future-timestamped blocks at validation time
2. Remove or significantly limit the wait duration in `insert_block_inner()` as defense in depth

## Proof of Concept

```rust
// Test demonstrating the vulnerability
// Add to consensus/src/block_storage/block_store_test.rs

#[tokio::test]
async fn test_future_timestamp_causes_wait() {
    use std::time::{Duration, Instant};
    
    // Setup block store with standard test configuration
    let (mut playground, block_store) = prepare_storage();
    
    // Create a block with timestamp 10 seconds in the future
    let future_time = playground.time_service.get_current_timestamp() 
        + Duration::from_secs(10);
    let future_timestamp_usecs = future_time.as_micros() as u64;
    
    let block = Block::new_proposal(
        vec![],  // empty payload
        1,       // round
        future_timestamp_usecs,
        playground.genesis_qc.clone(),
        &playground.signer,
        vec![],
    ).unwrap();
    
    // Measure time taken to insert the block
    let start = Instant::now();
    block_store.insert_block(block).await.unwrap();
    let elapsed = start.elapsed();
    
    // Verify that we waited approximately 10 seconds
    assert!(
        elapsed >= Duration::from_secs(9),
        "Expected wait of ~10 seconds, but only waited {:?}",
        elapsed
    );
    
    println!("Block with future timestamp caused validator to wait: {:?}", elapsed);
}

#[tokio::test]
async fn test_repeated_future_timestamps() {
    // Demonstrate repeated attack scenario
    let (mut playground, block_store) = prepare_storage();
    
    let mut total_wait = Duration::ZERO;
    
    // Simulate 5 rounds where malicious validator is proposer
    for round in 1..=5 {
        let future_time = playground.time_service.get_current_timestamp() 
            + Duration::from_secs(30); // 30 seconds in future
        let future_timestamp_usecs = future_time.as_micros() as u64;
        
        let block = Block::new_proposal(
            vec![],
            round,
            future_timestamp_usecs,
            playground.genesis_qc.clone(),
            &playground.signer,
            vec![],
        ).unwrap();
        
        let start = Instant::now();
        block_store.insert_block(block).await.unwrap();
        let elapsed = start.elapsed();
        
        total_wait += elapsed;
        
        // Update time to simulate round progression
        playground.time_service.advance(Duration::from_secs(35));
    }
    
    println!("Total time wasted across 5 rounds: {:?}", total_wait);
    assert!(
        total_wait >= Duration::from_secs(145),
        "Expected cumulative wait of ~150 seconds"
    );
}
```

## Notes

This vulnerability requires the attacker to be a validator in the active set, which aligns with the Byzantine Fault Tolerance threat model where up to 1/3 of validators can be malicious. The attack exploits a gap between timestamp validation (which allows up to 5 minutes in the future) and the block insertion logic (which waits for future timestamps), creating a denial-of-service vector against honest validators.

The comment in the code suggests awareness of the wait duration: "Long wait time" warnings are logged for waits exceeding 1 second [7](#0-6) , but the system still proceeds with the wait rather than rejecting such blocks.

### Citations

**File:** consensus/consensus-types/src/block.rs (L526-540)
```rust
        } else {
            ensure!(
                self.timestamp_usecs() > parent.timestamp_usecs(),
                "Blocks must have strictly increasing timestamps"
            );

            let current_ts = duration_since_epoch();

            // we can say that too far is 5 minutes in the future
            const TIMEBOUND: u64 = 300_000_000;
            ensure!(
                self.timestamp_usecs() <= (current_ts.as_micros() as u64).saturating_add(TIMEBOUND),
                "Blocks must not be too far in the future"
            );
        }
```

**File:** consensus/src/round_manager.rs (L1195-1200)
```rust
        ensure!(
            self.proposer_election.is_valid_proposal(&proposal),
            "[RoundManager] Proposer {} for block {} is not a valid proposer for this round or created duplicate proposal",
            author,
            proposal,
        );
```

**File:** consensus/src/round_manager.rs (L1233-1241)
```rust
        let block_time_since_epoch = Duration::from_micros(proposal.timestamp_usecs());

        ensure!(
            block_time_since_epoch < self.round_state.current_round_deadline(),
            "[RoundManager] Waiting until proposal block timestamp usecs {:?} \
            would exceed the round duration {:?}, hence will not vote for this round",
            block_time_since_epoch,
            self.round_state.current_round_deadline(),
        );
```

**File:** consensus/src/round_manager.rs (L1256-1259)
```rust
        self.block_store
            .insert_block(proposal.clone())
            .await
            .context("[RoundManager] Failed to insert the block into BlockStore")?;
```

**File:** consensus/src/block_storage/block_store.rs (L499-511)
```rust
        // ensure local time past the block time
        let block_time = Duration::from_micros(pipelined_block.timestamp_usecs());
        let current_timestamp = self.time_service.get_current_timestamp();
        if let Some(t) = block_time.checked_sub(current_timestamp) {
            if t > Duration::from_secs(1) {
                warn!(
                    "Long wait time {}ms for block {}",
                    t.as_millis(),
                    pipelined_block
                );
            }
            self.time_service.wait_until(block_time).await;
        }
```

**File:** consensus/src/util/time_service.rs (L39-45)
```rust
    async fn wait_until(&self, t: Duration) {
        while let Some(mut wait_duration) = t.checked_sub(self.get_current_timestamp()) {
            wait_duration += Duration::from_millis(1);
            counters::WAIT_DURATION_S.observe_duration(wait_duration);
            self.sleep(wait_duration).await;
        }
    }
```
