# Audit Report

## Title
Critical Panic in Secret Share Aggregation Due to Uninitialized Weights HashMap

## Summary
The `SecretShareAggregator::retain()` function and `add_share_with_metadata()` function contain `.expect()` calls that attempt to look up validator weights from a HashMap that is always empty. This causes guaranteed panics when secret shares from other validators arrive before a node processes its own self-share, leading to validator node crashes and consensus liveness failures.

## Finding Description

The vulnerability exists in the secret sharing subsystem used for randomness generation in Aptos consensus. The issue stems from an incomplete implementation where:

1. **Empty Weights HashMap**: The `SecretShareConfig` struct initializes a `weights` field as an empty HashMap that is never populated. [1](#0-0) 

2. **Inconsistent Weight Retrieval**: Two methods exist for retrieving weights with contradictory implementations:
   - `get_peer_weight()` returns a hardcoded value of `1` for any peer [2](#0-1) 
   - `get_peer_weights()` returns the empty `weights` HashMap [3](#0-2) 

3. **Panic in add_share_with_metadata**: When adding the self share, the code attempts to look up the author's weight from the empty HashMap with an `.expect()` that will always panic. [4](#0-3) 

4. **Panic in retain()**: The `retain()` function recalculates total weight by looking up each existing share author's weight in the empty HashMap, which panics on any existing shares. [5](#0-4) 

**Attack Scenario:**

The panic occurs naturally due to network timing, without requiring any malicious action:

1. Validator A processes block B at round R, derives self-share, and broadcasts it [6](#0-5) 

2. Validator B is slower and hasn't processed block B yet

3. Validator B receives A's share via the network through `handle_incoming_msg()` [7](#0-6) 

4. The share gets added via `add_share()` which uses `get_peer_weight()` returning hardcoded weight=1 [8](#0-7) 

5. The share is stored in the `PendingMetadata` aggregator [9](#0-8) 

6. Validator B finally processes block B and calls `add_self_share()` [10](#0-9) 

7. `add_self_share()` retrieves the empty weights HashMap via `get_peer_weights()` [11](#0-10) 

8. Calls `add_share_with_metadata()` which attempts to get the self author's weight from the empty HashMap → **PANIC at line 164** [12](#0-11) 

9. OR if line 164 somehow didn't execute, `retain()` is called at line 168, which attempts to recalculate weights for existing shares (like A's share) from the empty HashMap → **PANIC at line 79** [13](#0-12) 

## Impact Explanation

**Severity: High** (up to $50,000 per Aptos Bug Bounty)

This vulnerability causes:

- **Validator Node Crashes**: Any validator that receives shares from faster peers before processing its own block will panic and crash at the `.expect()` call, immediately terminating the validator process
- **Consensus Liveness Degradation**: Multiple validators crashing simultaneously reduces the active validator set, potentially approaching the 2/3 threshold needed for liveness
- **Deterministic Failure**: The panic is guaranteed whenever the timing conditions are met, making it reproducible and exploitable through natural network conditions
- **Network-Wide Impact**: In a network with variable processing speeds (different hardware, network latency, load), many validators could crash when processing the same round

This qualifies as **High Severity** under the "Validator node slowdowns" and "Significant protocol violations" categories. While it doesn't directly cause consensus safety violations or permanent fund loss, it severely impacts network availability and validator operations. The feature is actively deployed as evidenced by [14](#0-13) .

## Likelihood Explanation

**Likelihood: High**

The vulnerability is highly likely to occur because:

1. **Normal Operation Trigger**: It requires only network timing differences, which are inherent in any distributed system
2. **No Malicious Action Required**: Any validator can inadvertently trigger this on other validators simply by processing blocks faster due to better hardware or lower network latency
3. **Guaranteed Crash**: Once the timing condition is met (receiving peer share before processing self block), the panic is deterministic due to the `.expect()` calls
4. **Common Scenario**: In any heterogeneous network, validators WILL have different processing speeds due to hardware variations, network latency differences, or varying load

The code comment at [15](#0-14)  indicates this is "temporary and meant to change in future PRs," suggesting the implementation is incomplete but already deployed.

## Recommendation

The issue should be fixed by properly populating the `weights` HashMap in `SecretShareConfig`:

1. Populate the `weights` HashMap during `SecretShareConfig::new()` by querying the validator verifier for each validator's voting power
2. Alternatively, modify `add_share_with_metadata()` and `retain()` to use `get_peer_weight()` (which returns 1) instead of looking up from the HashMap, ensuring consistency with how `add_share()` works
3. Add validation to ensure `weights` HashMap is populated before use, or remove it entirely if weighted secret sharing is not yet implemented

The preferred fix is option 1, as it would properly implement weighted secret sharing as intended by the infrastructure already in place.

## Proof of Concept

The vulnerability can be reproduced through a timing-based scenario:

1. Deploy two validator nodes (A and B) on a test network with the secret sharing feature enabled
2. Introduce artificial network delay for validator B or processing delay
3. Have validator A process a block and broadcast its secret share
4. Validator B receives the share via network before processing the block locally
5. The share is added to B's store via `add_share()` with weight=1
6. When validator B processes the block and calls `add_self_share()`, it will panic at the `.expect()` call attempting to lookup from the empty `weights` HashMap

The panic is deterministic and will occur every time shares arrive before self-share processing, which is a natural occurrence in networks with heterogeneous validator performance.

### Citations

**File:** types/src/secret_sharing.rs (L134-134)
```rust
/// This is temporary and meant to change in future PRs
```

**File:** types/src/secret_sharing.rs (L168-168)
```rust
            weights: HashMap::new(),
```

**File:** types/src/secret_sharing.rs (L196-198)
```rust
    pub fn get_peer_weight(&self, _peer: &Author) -> u64 {
        1
    }
```

**File:** types/src/secret_sharing.rs (L200-202)
```rust
    pub fn get_peer_weights(&self) -> &HashMap<Author, u64> {
        &self.weights
    }
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L74-81)
```rust
    fn retain(&mut self, metadata: &SecretShareMetadata, weights: &HashMap<Author, u64>) {
        self.shares.retain(|_, share| share.metadata == *metadata);
        self.total_weight = self
            .shares
            .keys()
            .map(|author| weights.get(author).expect("Author must exist for weight"))
            .sum();
    }
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L108-113)
```rust
    fn add_share(&mut self, share: SecretShare, share_weight: u64) -> anyhow::Result<()> {
        match self {
            SecretShareItem::PendingMetadata(aggr) => {
                aggr.add_share(share, share_weight);
                Ok(())
            },
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L162-164)
```rust
        let share_weight = *share_weights
            .get(share.author())
            .expect("Author must exist in weights");
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L168-168)
```rust
                share_aggregator.retain(share.metadata(), share_weights);
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L242-242)
```rust
        let peer_weights = self.secret_share_config.get_peer_weights();
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L254-254)
```rust
        item.add_share_with_metadata(share, peer_weights)?;
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L259-260)
```rust
    pub fn add_share(&mut self, share: SecretShare) -> anyhow::Result<bool> {
        let weight = self.secret_share_config.get_peer_weight(share.author());
```

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L145-147)
```rust
            secret_share_store
                .add_self_share(self_secret_share.clone())
                .expect("Add self dec share should succeed");
```

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L154-156)
```rust
        self.network_sender.broadcast_without_self(
            SecretShareMessage::Share(self_secret_share).into_network_message(),
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

**File:** consensus/src/pipeline/execution_client.rs (L286-302)
```rust
        let secret_share_manager = SecretShareManager::new(
            self.author,
            epoch_state.clone(),
            config,
            secret_ready_block_tx,
            network_sender.clone(),
            self.bounded_executor.clone(),
            &self.consensus_config.rand_rb_config,
        );

        tokio::spawn(secret_share_manager.start(
            ordered_block_rx,
            secret_sharing_msg_rx,
            reset_secret_share_manager_rx,
            self.bounded_executor.clone(),
            highest_committed_round,
        ));
```
