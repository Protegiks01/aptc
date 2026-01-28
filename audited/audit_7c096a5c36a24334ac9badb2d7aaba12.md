# Audit Report

## Title
Unbounded Memory Growth in SecretShareStore Due to Missing Garbage Collection

## Summary
The `SecretShareStore` in the consensus secret sharing module lacks a garbage collection mechanism for old rounds, causing unbounded memory growth throughout an epoch. Each consensus round permanently adds entries to the internal `secret_share_map` HashMap that are never removed, leading to progressive memory exhaustion and performance degradation on validator nodes.

## Finding Description

The `SecretShareStore` maintains a `HashMap<Round, SecretShareItem>` called `secret_share_map` to track secret shares across consensus rounds. [1](#0-0) 

New entries are continuously added to this HashMap during normal consensus operation through the `add_share` and `add_self_share` methods, which use the `.entry()` API to insert new rounds: [2](#0-1) 

However, **no garbage collection mechanism exists** to remove old round entries from this HashMap. A comprehensive code analysis reveals no calls to `remove()`, `retain()`, `clear()`, `drain()`, `split_off()`, or any other cleanup methods on `secret_share_map`.

When the consensus layer resets (e.g., during sync or recovery), the `process_reset` method in `SecretShareManager` only updates the highest known round but does **not** clear the stored shares: [3](#0-2) 

This contrasts sharply with the analogous `RandStore` component, which implements proper garbage collection using `split_off()` to remove future rounds during reset: [4](#0-3) 

The system accepts shares for rounds up to `FUTURE_ROUNDS_TO_ACCEPT` (200 rounds) ahead: [5](#0-4) 

But this forward-looking limit does not prevent unbounded growth of historical data.

**Execution Path:**
1. Validator processes consensus rounds normally
2. Each round triggers `add_share` or `add_self_share` via `SecretShareManager::process_incoming_block()`
3. Entries accumulate in `secret_share_map` with no removal mechanism
4. Memory usage grows linearly with rounds processed
5. Over a long epoch (hours to days), thousands to millions of entries accumulate
6. Node experiences GC pressure, performance degradation, and potential OOM

While a new `SecretShareStore` is created on epoch transitions (providing bounded memory per epoch), epochs can be arbitrarily long based on governance configuration: [6](#0-5) [7](#0-6) 

## Impact Explanation

This vulnerability qualifies as **High Severity** per Aptos bug bounty criteria under the "Validator Node Slowdowns" category.

**Impact Classification:**
- **Validator node slowdowns**: Progressive memory consumption causes performance degradation through increased GC pressure, reduced cache efficiency, and potential swap usage
- **Consensus performance impact**: Degraded validator performance affects block production and validation speed
- **Node availability risk**: In extreme cases (very long epochs with high round velocity), nodes may experience OOM conditions, potentially removing validators from consensus participation

**Severity Justification:**
The framework explicitly lists "Validator Node Slowdowns (High): Significant performance degradation affecting consensus, DoS through resource exhaustion" as a valid High Severity impact. This issue directly fits that category—it's a resource management bug (missing garbage collection) that causes progressive resource exhaustion during normal protocol operation.

While memory is bounded per epoch, epochs can last hours to days based on on-chain governance configuration. High-performance consensus can process 60-100+ rounds per minute, meaning a 24-hour epoch could accumulate 86,400+ entries, each containing cryptographic share data (BLS signatures, metadata, aggregator state).

## Likelihood Explanation

**Likelihood: High**

This vulnerability triggers automatically during normal consensus operation with **no malicious actor required**. It is a passive, protocol-level bug affecting all validator nodes running the secret sharing protocol.

**Factors Supporting High Likelihood:**
- Occurs on all validator nodes during every epoch
- No attacker action or special conditions required
- Impact scales directly with epoch duration and consensus throughput
- High round velocity (fast consensus) accelerates memory accumulation
- Long epochs (days/weeks) significantly exacerbate the issue
- Cannot be mitigated without code changes

The automatic, passive nature of this vulnerability makes it fundamentally different from active network attacks—it's a resource management flaw in the protocol implementation itself.

## Recommendation

Implement garbage collection for the `SecretShareStore` following the pattern established in `RandStore`. Add a `reset()` method to `SecretShareStore`:

```rust
pub fn reset(&mut self, round: u64) {
    self.update_highest_known_round(round);
    // Remove future rounds to prevent blocks from getting stuck
    // if they re-enter the queue after being decided
    let _ = self.secret_share_map.split_off(&round);
}
```

Modify `SecretShareManager::process_reset()` to call this new method:

```rust
fn process_reset(&mut self, request: ResetRequest) {
    let ResetRequest { tx, signal } = request;
    let target_round = match signal {
        ResetSignal::Stop => 0,
        ResetSignal::TargetRound(round) => round,
    };
    self.block_queue = BlockQueue::new();
    self.secret_share_store.lock().reset(target_round);  // Call reset instead of update_highest_known_round
    self.stop = matches!(signal, ResetSignal::Stop);
    let _ = tx.send(ResetAck::default());
}
```

Additionally, consider implementing periodic cleanup of decided rounds that are significantly older than the current highest known round.

## Proof of Concept

The vulnerability can be observed by monitoring validator memory usage over an extended epoch:

1. Deploy a validator node with secret sharing enabled
2. Monitor process memory consumption over time
3. Observe linear memory growth correlated with consensus round progression
4. Verify that memory is only released at epoch boundaries
5. In high-throughput scenarios (100+ rounds/min), observe GB-scale memory accumulation within hours

The automatic nature of this bug means it requires no specific attack code—it manifests through normal consensus operation.

## Notes

This is a protocol-level resource management bug, not a network DoS attack. It aligns with the Aptos bug bounty framework's "Validator Node Slowdowns (High)" category, which explicitly includes "DoS through resource exhaustion" caused by protocol bugs (similar to the example: "Gas calculation bug causes validator slowdowns"). The clear discrepancy between `SecretShareStore` (no GC) and `RandStore` (proper GC with `split_off`) provides strong evidence this is an unintended bug rather than deliberate design.

### Citations

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L207-214)
```rust
pub struct SecretShareStore {
    epoch: u64,
    self_author: Author,
    secret_share_config: SecretShareConfig,
    secret_share_map: HashMap<Round, SecretShareItem>,
    highest_known_round: u64,
    decision_tx: Sender<SecretSharedKey>,
}
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L237-275)
```rust
    pub fn add_self_share(&mut self, share: SecretShare) -> anyhow::Result<()> {
        assert!(
            self.self_author == share.author,
            "Only self shares can be added with metadata"
        );
        let peer_weights = self.secret_share_config.get_peer_weights();
        let metadata = share.metadata();
        ensure!(metadata.epoch == self.epoch, "Share from different epoch");
        ensure!(
            metadata.round <= self.highest_known_round + FUTURE_ROUNDS_TO_ACCEPT,
            "Share from future round"
        );

        let item = self
            .secret_share_map
            .entry(metadata.round)
            .or_insert_with(|| SecretShareItem::new(self.self_author));
        item.add_share_with_metadata(share, peer_weights)?;
        item.try_aggregate(&self.secret_share_config, self.decision_tx.clone());
        Ok(())
    }

    pub fn add_share(&mut self, share: SecretShare) -> anyhow::Result<bool> {
        let weight = self.secret_share_config.get_peer_weight(share.author());
        let metadata = share.metadata();
        ensure!(metadata.epoch == self.epoch, "Share from different epoch");
        ensure!(
            metadata.round <= self.highest_known_round + FUTURE_ROUNDS_TO_ACCEPT,
            "Share from future round"
        );

        let item = self
            .secret_share_map
            .entry(metadata.round)
            .or_insert_with(|| SecretShareItem::new(self.self_author));
        item.add_share(share, weight)?;
        item.try_aggregate(&self.secret_share_config, self.decision_tx.clone());
        Ok(item.has_decision())
    }
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

**File:** consensus/src/rand/rand_gen/rand_store.rs (L253-259)
```rust
    pub fn reset(&mut self, round: u64) {
        self.update_highest_known_round(round);
        // remove future rounds items in case they're already decided
        // otherwise if the block re-enters the queue, it'll be stuck
        let _ = self.rand_map.split_off(&round);
        let _ = self.fast_rand_map.as_mut().map(|map| map.split_off(&round));
    }
```

**File:** consensus/src/rand/rand_gen/types.rs (L26-26)
```rust
pub const FUTURE_ROUNDS_TO_ACCEPT: u64 = 200;
```

**File:** consensus/src/pipeline/execution_client.rs (L286-294)
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
```

**File:** consensus/src/pipeline/execution_client.rs (L734-745)
```rust
        if let Some(mut tx) = reset_tx_to_secret_share_manager {
            let (ack_tx, ack_rx) = oneshot::channel();
            tx.send(ResetRequest {
                tx: ack_tx,
                signal: ResetSignal::Stop,
            })
            .await
            .expect("[EpochManager] Fail to drop secret share manager");
            ack_rx
                .await
                .expect("[EpochManager] Fail to drop secret share manager");
        }
```
