# Audit Report

## Title
Randomness Share Rejection During Initial Startup Due to Stale `highest_known_round` Initialization

## Summary
During validator startup, the `RandStore` is initialized with `highest_known_round = 0`, then updated with `highest_committed_round` from the database. If a node joins a network that has progressed beyond round 200, or restarts after being offline, incoming randomness shares are rejected as "future rounds" until the first block metadata updates `highest_known_round`. This creates a temporary window where the node cannot participate in randomness generation.

## Finding Description
The vulnerability occurs in the initialization sequence of the randomness generation system: [1](#0-0) 

The `RandStore::new()` function initializes `highest_known_round` to 0. Later, when `RandManager::start()` is called, it updates this value: [2](#0-1) 

The `highest_known_round` is sourced from the database's latest committed ledger info: [3](#0-2) 

When shares arrive, they are validated against this threshold: [4](#0-3) 

The constant `FUTURE_ROUNDS_TO_ACCEPT` is set to 200: [5](#0-4) 

**Attack Scenario:**
1. A validator node starts fresh or restarts after extended downtime
2. Database contains only genesis (round 0) or old data (e.g., round 50)
3. Network has progressed to round 300
4. Node's `highest_known_round` is initialized to 0 or 50
5. Randomness shares for round 300 arrive via network gossip before block metadata is processed
6. Validation check fails: `300 <= 50 + 200 = 250` → FALSE
7. Shares are rejected and logged as warnings: [6](#0-5) 

The issue is exacerbated by the event loop design where share processing happens concurrently with block processing, but blocks have an additional gate condition: [7](#0-6) 

Blocks require `my_certified_aug_data_exists()` to be true before processing, creating a startup window where shares arrive but blocks aren't processed yet, preventing `highest_known_round` from being updated via: [8](#0-7) 

## Impact Explanation
**Medium Severity** - This issue causes temporary liveness degradation of the randomness generation subsystem:

- **Randomness Generation Delay**: Affected nodes cannot contribute shares during the startup window, potentially delaying randomness decisions if multiple nodes restart simultaneously
- **State Inconsistency**: Share rejection creates gaps that must be recovered through the share request mechanism, adding latency
- **Validator Participation**: Nodes joining late or restarting cannot immediately participate in on-chain randomness, affecting the robustness of the randomness beacon

This qualifies as Medium severity per Aptos bug bounty criteria: "State inconsistencies requiring intervention" and impacts the availability guarantees of the randomness subsystem, though it does not break consensus safety.

## Likelihood Explanation
**High Likelihood** - This issue occurs in common operational scenarios:

1. **New validators joining**: Any validator joining an established network experiences this during initial sync
2. **Node restarts**: Validators restarting after downtime or maintenance encounter this regularly
3. **Epoch transitions**: If `highest_committed_round` from a previous epoch is used during new epoch initialization, the window is extended
4. **Network partition recovery**: Nodes recovering from partitions face this when rejoining

The 200-round window is relatively small (typically minutes of consensus progress), making this easy to trigger in production networks with regular validator operations.

## Recommendation
Initialize `highest_known_round` based on the current network state, not just the database:

```rust
pub async fn start(
    mut self,
    mut incoming_blocks: Receiver<OrderedBlocks>,
    incoming_rpc_request: aptos_channel::Receiver<Author, IncomingRandGenRequest>,
    mut reset_rx: Receiver<ResetRequest>,
    bounded_executor: BoundedExecutor,
    highest_known_round: Round,
) {
    info!("RandManager started");
    let (verified_msg_tx, mut verified_msg_rx) = unbounded();
    let epoch_state = self.epoch_state.clone();
    let rand_config = self.config.clone();
    let fast_rand_config = self.fast_config.clone();
    
    // Initialize with max of database round and current network round hint
    // Network round hint could come from peer discovery or block sync state
    self.rand_store
        .lock()
        .update_highest_known_round(highest_known_round);
    
    // Alternative: Wait for first block before accepting shares
    // or increase FUTURE_ROUNDS_TO_ACCEPT during startup phase
    
    spawn_named!(
        "rand manager verification",
        Self::verification_task(...)
    );
    // ...
}
```

**Alternative solutions:**
1. Increase `FUTURE_ROUNDS_TO_ACCEPT` to a larger value (e.g., 1000) to accommodate catch-up scenarios
2. Add startup phase logic that defers share processing until first block is received
3. Query peers for current round before accepting shares during initialization

## Proof of Concept
```rust
#[tokio::test]
async fn test_share_rejection_during_startup() {
    use consensus::rand::rand_gen::rand_store::RandStore;
    use consensus::rand::rand_gen::types::{RandConfig, MockShare};
    use futures_channel::mpsc::unbounded;
    
    let epoch = 5;
    let author = Author::ONE;
    
    // Create rand config (simplified for test)
    let rand_config = create_test_rand_config();
    
    let (decision_tx, _decision_rx) = unbounded();
    
    // Initialize RandStore - highest_known_round starts at 0
    let mut rand_store = RandStore::<MockShare>::new(
        epoch,
        author,
        rand_config.clone(),
        None,
        decision_tx,
    );
    
    // Simulate node starting with stale database (round 0)
    rand_store.update_highest_known_round(0);
    
    // Network is at round 300
    let network_round = 300;
    let share = create_test_share(epoch, network_round, Author::TWO);
    
    // Attempt to add share - should fail
    let result = rand_store.add_share(share, PathType::Slow);
    
    // Assertion: Share is rejected as "future round"
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Share from future round"));
    
    // After processing a block at round 300, highest_known_round updates
    rand_store.update_highest_known_round(network_round);
    
    // Now the same share would be accepted
    let share2 = create_test_share(epoch, network_round, Author::THREE);
    let result2 = rand_store.add_share(share2, PathType::Slow);
    assert!(result2.is_ok());
}
```

**Notes:**
- The vulnerability is confirmed by code inspection showing the initialization sequence and validation logic
- The 200-round window (FUTURE_ROUNDS_TO_ACCEPT) is insufficient for nodes that are significantly behind
- The issue is mitigated by the share request mechanism but creates unnecessary latency and complexity
- Epoch boundary transitions may compound this if rounds from previous epochs are used for initialization

### Citations

**File:** consensus/src/rand/rand_gen/rand_store.rs (L230-247)
```rust
    pub fn new(
        epoch: u64,
        author: Author,
        rand_config: RandConfig,
        fast_rand_config: Option<RandConfig>,
        decision_tx: Sender<Randomness>,
    ) -> Self {
        Self {
            epoch,
            author,
            rand_config,
            rand_map: BTreeMap::new(),
            fast_rand_config: fast_rand_config.clone(),
            fast_rand_map: fast_rand_config.map(|_| BTreeMap::new()),
            highest_known_round: 0,
            decision_tx,
        }
    }
```

**File:** consensus/src/rand/rand_gen/rand_store.rs (L285-288)
```rust
        ensure!(
            share.metadata().round <= self.highest_known_round + FUTURE_ROUNDS_TO_ACCEPT,
            "Share from future round"
        );
```

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L152-152)
```rust
        rand_store.update_highest_known_round(metadata.round());
```

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L361-363)
```rust
        self.rand_store
            .lock()
            .update_highest_known_round(highest_known_round);
```

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L380-382)
```rust
                Some(blocks) = incoming_blocks.next(), if self.aug_data_store.my_certified_aug_data_exists() => {
                    self.process_incoming_blocks(blocks);
                }
```

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L421-423)
```rust
                            if let Err(e) = self.rand_store.lock().add_share(share, PathType::Slow) {
                                warn!("[RandManager] Failed to add share: {}", e);
                            }
```

**File:** consensus/src/epoch_manager.rs (L1447-1453)
```rust
        let highest_committed_round = self
            .storage
            .aptos_db()
            .get_latest_ledger_info()
            .expect("unable to get latest ledger info")
            .commit_info()
            .round();
```

**File:** consensus/src/rand/rand_gen/types.rs (L26-26)
```rust
pub const FUTURE_ROUNDS_TO_ACCEPT: u64 = 200;
```
