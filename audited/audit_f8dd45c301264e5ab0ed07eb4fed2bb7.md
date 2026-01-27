# Audit Report

## Title
Validator Liveness Failure Due to Unsynchronized `highest_known_round` in Secret Share Validation

## Summary
Validators maintain independent `highest_known_round` values that are updated locally when processing blocks. When a validator falls more than 200 rounds behind (FUTURE_ROUNDS_TO_ACCEPT), it systematically rejects secret shares from validators ahead of it, preventing share aggregation needed to decrypt encrypted transactions. This creates a permanent liveness failure where the lagging validator cannot process blocks with encrypted transactions, entering a deadlock state requiring manual intervention.

## Finding Description

The `SecretShareStore` maintains a local `highest_known_round` field that tracks the highest round this validator has processed. [1](#0-0)  This value is updated when blocks are processed locally in `process_incoming_block`. [2](#0-1) 

When validators receive secret shares from peers, these shares are validated against a forward-looking window: `metadata.round <= self.highest_known_round + FUTURE_ROUNDS_TO_ACCEPT`. [3](#0-2)  The constant `FUTURE_ROUNDS_TO_ACCEPT` is set to 200 rounds. [4](#0-3) 

**The Vulnerability:**
Different validators can have significantly different `highest_known_round` values due to:
- Network delays or partitions
- Validator restarts or syncing from behind
- Processing speed variations under load
- Temporary downtime

**Attack Scenario:**
1. Validator A processes blocks up to round 300 → `highest_known_round = 300`
2. Validator B is syncing from behind and only at round 100 → `highest_known_round = 100`
3. Block at round 301 requires encrypted transaction decryption
4. All validators generate and broadcast secret shares for round 301
5. **Validator A receives share for round 301:** `301 <= 300 + 200` → **ACCEPTS**
6. **Validator B receives share for round 301:** `301 <= 100 + 200 = 300` → **REJECTS** (301 > 300)

Validator B systematically rejects all shares for round 301 from other validators. With only its own share, it cannot reach the aggregation threshold needed to reconstruct the `SecretSharedKey`. [5](#0-4) 

**The Deadlock:**
Without the aggregated key, the decryption pipeline expects the key to be available and will panic when it's not. [6](#0-5)  The TODO comment at line 118 acknowledges this unhandled case. [7](#0-6) 

Blocks cannot be dequeued from the `BlockQueue` until they have their secret shared keys. [8](#0-7)  This creates a circular dependency:
- Validator needs to process blocks to update `highest_known_round`
- Validator needs current `highest_known_round` to accept shares
- Validator needs shares to decrypt transactions and process blocks
- **Validator is permanently stuck**

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program category "Validator node slowdowns" and "Significant protocol violations."

**Specific Impacts:**
- **Validator Liveness Failure:** Affected validators cannot process any blocks containing encrypted transactions until manually reset via `process_reset`. [9](#0-8) 
- **Network Degradation:** If multiple validators fall behind simultaneously (e.g., during network partition), a significant portion of the validator set could become non-functional
- **Cascading Effect:** As validators fall further behind while stuck, the gap increases, making recovery without intervention impossible
- **Deterministic Execution Violation:** Validators in different states (ahead vs. behind) make different decisions about which shares to accept, breaking the deterministic execution invariant

The vulnerability does not require attacker access to validator keys and can occur naturally through network conditions, making it a protocol-level flaw rather than an operational issue.

## Likelihood Explanation

**Likelihood: Medium-High**

This vulnerability is likely to occur in production because:

1. **Natural Occurrence:** Validators regularly experience:
   - Network delays during geographic distribution
   - Temporary downtime for maintenance
   - Syncing periods after restarts
   - Performance variations under different loads

2. **200-Round Window:** While 200 rounds provides a buffer, validators syncing from checkpoints or recovering from extended downtime can easily exceed this gap. At typical Aptos block rates, 200 rounds could represent 3-5 minutes of blocks.

3. **No Recovery Mechanism:** Once a validator enters this state, there is no automatic recovery. The codebase explicitly notes this gap with a TODO comment about handling unavailable decryption keys. [7](#0-6) 

4. **Encrypted Transactions:** The vulnerability only triggers when blocks contain encrypted transactions, but as this feature is used for privacy-preserving applications, affected blocks will become increasingly common.

## Recommendation

**Immediate Fix:** Implement graceful handling when `SecretSharedKey` is unavailable:

```rust
// In consensus/src/pipeline/decryption_pipeline_builder.rs, line 115-119
let maybe_decryption_key = secret_shared_key_rx
    .await
    .expect("decryption key should be available");

// REPLACE WITH:
let maybe_decryption_key = match secret_shared_key_rx.await {
    Ok(Some(key)) => key,
    Ok(None) | Err(_) => {
        // If decryption key unavailable, attempt to fast-forward highest_known_round
        // by processing the block metadata without decryption, or request sync from peers
        warn!("Decryption key unavailable for round {}, validator may be behind", block.round());
        // Return error to trigger block re-processing after sync
        return Err(TaskError::from(anyhow!("Decryption key unavailable - validator syncing")));
    }
};
```

**Long-term Solutions:**

1. **Synchronize `highest_known_round` globally:** Include round information in consensus messages so validators can update their view based on the current network state, not just locally processed blocks.

2. **Adaptive Window:** Make `FUTURE_ROUNDS_TO_ACCEPT` adaptive based on validator sync state. Validators that are syncing should temporarily accept a wider window.

3. **Share Request Fallback:** When a validator detects it's behind (receiving rejected shares), it should request shares for its current round rather than the broadcasted round, allowing it to catch up incrementally.

4. **Automatic Reset:** Implement automatic `highest_known_round` advancement when a validator detects it's significantly behind based on received block headers, before attempting share validation.

## Proof of Concept

```rust
// Reproduction steps (pseudo-code for clarity):

// Setup: Two validators in different sync states
let validator_a_store = SecretShareStore::new(epoch, author_a, config.clone(), tx_a);
let validator_b_store = SecretShareStore::new(epoch, author_b, config.clone(), tx_b);

// Validator A processes blocks 1-300
for round in 1..=300 {
    validator_a_store.update_highest_known_round(round);
}
// validator_a highest_known_round = 300

// Validator B only processes blocks 1-100 (simulating lag)
for round in 1..=100 {
    validator_b_store.update_highest_known_round(round);
}
// validator_b highest_known_round = 100

// Generate share for round 301
let metadata_301 = SecretShareMetadata::new(epoch, 301, timestamp, block_id, digest);
let share_301 = SecretShare::new(author_a, metadata_301.clone(), key_share);

// Validator A accepts the share
let result_a = validator_a_store.add_share(share_301.clone());
assert!(result_a.is_ok()); // 301 <= 300 + 200 = 500 ✓

// Validator B rejects the same share
let result_b = validator_b_store.add_share(share_301);
assert!(result_b.is_err()); // 301 <= 100 + 200 = 300 ✗ (301 > 300)
// Error: "Share from future round"

// Validator B cannot aggregate shares (has only its own share)
// Threshold requires 2/3 validators
// Validator B has 1/4 shares → Cannot aggregate
// DecryptionKey unavailable → Pipeline panics
// Blocks stuck in queue → Permanent liveness failure
```

**Notes**

This vulnerability represents a critical gap between the local state consistency maintained by individual validators and the global state consistency required for the secret sharing protocol to function correctly. The same validation logic exists in the randomness generation system (`rand_store.rs`), indicating this is a systemic issue affecting multiple consensus subsystems. [10](#0-9) 

The vulnerability breaks the **Deterministic Execution** and **State Consistency** invariants: validators in identical network positions should make identical decisions about protocol messages, but validators with different `highest_known_round` values make different accept/reject decisions for the same shares, leading to divergent execution paths and potential permanent validator exclusion from consensus participation.

### Citations

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L38-46)
```rust
    pub fn try_aggregate(
        self,
        secret_share_config: &SecretShareConfig,
        metadata: SecretShareMetadata,
        decision_tx: Sender<SecretSharedKey>,
    ) -> Either<Self, SecretShare> {
        if self.total_weight < secret_share_config.threshold() {
            return Either::Left(self);
        }
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L212-212)
```rust
    highest_known_round: u64,
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L245-248)
```rust
        ensure!(
            metadata.round <= self.highest_known_round + FUTURE_ROUNDS_TO_ACCEPT,
            "Share from future round"
        );
```

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L144-144)
```rust
            secret_share_store.update_highest_known_round(block.round());
```

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L172-184)
```rust
    fn process_reset(&mut self, request: ResetRequest) {
        let ResetRequest { tx, signal } = request;
        let target_round = match signal {
            ResetSignal::Stop => 0,
            ResetSignal::TargetRound(round) => round,
        };
        self.block_queue = BlockQueue::new();
        self.secret_share_store
            .lock()
            .update_highest_known_round(target_round);
        self.stop = matches!(signal, ResetSignal::Stop);
        let _ = tx.send(ResetAck::default());
    }
```

**File:** consensus/src/rand/rand_gen/types.rs (L26-26)
```rust
pub const FUTURE_ROUNDS_TO_ACCEPT: u64 = 200;
```

**File:** consensus/src/pipeline/decryption_pipeline_builder.rs (L115-119)
```rust
        let maybe_decryption_key = secret_shared_key_rx
            .await
            .expect("decryption key should be available");
        // TODO(ibalajiarun): account for the case where decryption key is not available
        let decryption_key = maybe_decryption_key.expect("decryption key should be available");
```

**File:** consensus/src/rand/secret_sharing/block_queue.rs (L112-126)
```rust
    pub fn dequeue_ready_prefix(&mut self) -> Vec<OrderedBlocks> {
        let mut ready_prefix = vec![];
        while let Some((_starting_round, item)) = self.queue.first_key_value() {
            if item.is_fully_secret_shared() {
                let (_, item) = self.queue.pop_first().expect("First key must exist");
                for block in item.blocks() {
                    observe_block(block.timestamp_usecs(), BlockStage::SECRET_SHARING_READY);
                }
                let QueueItem { ordered_blocks, .. } = item;
                ready_prefix.push(ordered_blocks);
            } else {
                break;
            }
        }
        ready_prefix
```

**File:** consensus/src/rand/rand_gen/rand_store.rs (L285-288)
```rust
        ensure!(
            share.metadata().round <= self.highest_known_round + FUTURE_ROUNDS_TO_ACCEPT,
            "Share from future round"
        );
```
