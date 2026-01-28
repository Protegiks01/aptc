# Audit Report

## Title
Validator Node Crash Due to Empty Weight HashMap Lookup in SecretShareAggregator::retain()

## Summary
A data source inconsistency in `SecretShareConfig` causes validator nodes to panic when processing secret shares during normal consensus operation. The `retain()` method attempts to recalculate weights using an empty HashMap, causing a deterministic crash when peer shares arrive before the validator's own share.

## Finding Description

The vulnerability exists in the secret sharing consensus mechanism where two different methods provide validator weights with inconsistent data sources.

The `SecretShareConfig` struct initializes its `weights` field as an empty HashMap that is never populated: [1](#0-0) 

Two methods provide weight information with fundamentally different behaviors:

1. `get_peer_weight()` returns a hardcoded value of 1: [2](#0-1) 

2. `get_peer_weights()` returns a reference to the empty HashMap: [3](#0-2) 

The crash occurs in `SecretShareAggregator::retain()` which attempts to look up weights in the HashMap: [4](#0-3) 

**Exploitation Flow:**

1. When peer secret shares arrive via network messages, `add_share()` is called, which uses `get_peer_weight()` to assign weight=1 to each share: [5](#0-4) 

2. These shares accumulate in the `SecretShareAggregator` in `PendingMetadata` state with correct `total_weight` tracking.

3. When the validator computes its own share, `add_self_share()` retrieves the empty `peer_weights` HashMap: [6](#0-5) 

4. This empty HashMap is passed to `add_share_with_metadata()`: [7](#0-6) 

5. The `retain()` method filters shares by metadata (line 168), and if peer shares with matching metadata remain, attempts to look up each author's weight in the empty HashMap, causing panic with "Author must exist for weight".

This is verified by the network message handling flow where incoming shares are processed: [8](#0-7) 

And self shares are added after block processing: [9](#0-8) 

## Impact Explanation

**Severity: High** - This meets the Aptos bug bounty criteria for "Validator node slowdowns / API crashes" (up to $50,000).

**Impact:**
- Immediate validator node crash via panic during secret share processing
- Loss of validator availability during consensus rounds requiring secret sharing
- If multiple validators crash simultaneously (highly likely as all follow the same code path), network liveness degradation occurs
- Consensus round delays or failures if insufficient validators remain operational

The vulnerability directly affects consensus availability. While it does not cause fund loss, consensus safety violations, or permanent network partition (which would be Critical severity), it does cause deterministic validator crashes affecting network operation (High severity).

## Likelihood Explanation

**Likelihood: High**

This vulnerability triggers under normal protocol operation without requiring any malicious behavior:

1. Secret sharing is a standard consensus mechanism in Aptos used for randomness generation
2. Network latency naturally causes validators to receive shares at different times
3. It is common for a validator to receive peer shares via network before computing its own share
4. The bug triggers deterministically whenever shares exist in the aggregator when `add_self_share()` is called
5. Shares with matching metadata (the normal case for the same block/round) will not be filtered out, causing the panic

The crash occurs repeatedly during epochs where secret sharing is active and network timing causes the vulnerable execution order. This is not an edge case but a regular occurrence in distributed consensus protocols with asynchronous message delivery.

## Recommendation

Populate the `weights` HashMap in `SecretShareConfig` with actual validator weights, or modify `get_peer_weights()` to construct and return a HashMap with weights from the same source as `get_peer_weight()`.

**Option 1:** Populate weights in constructor:
```rust
pub fn new(
    author: Author,
    epoch: u64,
    validator: Arc<ValidatorVerifier>,
    // ... other params
) -> Self {
    let mut weights = HashMap::new();
    for addr in validator.get_ordered_account_addresses() {
        weights.insert(addr, 1); // or actual weight
    }
    Self {
        // ... other fields
        weights,
    }
}
```

**Option 2:** Construct weights on-the-fly in `get_peer_weights()`:
```rust
pub fn get_peer_weights(&self) -> HashMap<Author, u64> {
    self.validator
        .get_ordered_account_addresses_iter()
        .map(|addr| (addr, 1)) // or actual weight
        .collect()
}
```

## Proof of Concept

The vulnerability can be triggered by:
1. Starting a validator node with secret sharing enabled
2. Allowing peer shares to arrive via network before the local share computation completes
3. The `add_self_share()` call will trigger the panic in `retain()` when peer shares exist

This occurs naturally during normal consensus operation and does not require specially crafted inputs or malicious behavior.

### Citations

**File:** types/src/secret_sharing.rs (L145-169)
```rust
    weights: HashMap<Author, u64>,
}

impl SecretShareConfig {
    pub fn new(
        author: Author,
        epoch: u64,
        validator: Arc<ValidatorVerifier>,
        digest_key: DigestKey,
        msk_share: MasterSecretKeyShare,
        verification_keys: Vec<VerificationKey>,
        config: <FPTXWeighted as BatchThresholdEncryption>::ThresholdConfig,
        encryption_key: EncryptionKey,
    ) -> Self {
        Self {
            _author: author,
            _epoch: epoch,
            validator,
            digest_key,
            msk_share,
            verification_keys,
            config,
            encryption_key,
            weights: HashMap::new(),
        }
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

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L156-182)
```rust
    fn add_share_with_metadata(
        &mut self,
        share: SecretShare,
        share_weights: &HashMap<Author, u64>,
    ) -> anyhow::Result<()> {
        let item = std::mem::replace(self, Self::new(Author::ONE));
        let share_weight = *share_weights
            .get(share.author())
            .expect("Author must exist in weights");
        let new_item = match item {
            SecretShareItem::PendingMetadata(mut share_aggregator) => {
                let metadata = share.metadata.clone();
                share_aggregator.retain(share.metadata(), share_weights);
                share_aggregator.add_share(share, share_weight);
                SecretShareItem::PendingDecision {
                    metadata,
                    share_aggregator,
                }
            },
            SecretShareItem::PendingDecision { .. } => {
                bail!("Cannot add self share in PendingDecision state");
            },
            SecretShareItem::Decided { .. } => return Ok(()),
        };
        let _ = std::mem::replace(self, new_item);
        Ok(())
    }
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L237-256)
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
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L259-275)
```rust
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

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L132-158)
```rust
    async fn process_incoming_block(&self, block: &PipelinedBlock) -> DropGuard {
        let futures = block.pipeline_futs().expect("pipeline must exist");
        let self_secret_share = futures
            .secret_sharing_derive_self_fut
            .await
            .expect("Decryption share computation is expected to succeed")
            .expect("Must not be None");
        let metadata = self_secret_share.metadata().clone();

        // Now acquire lock and update store
        {
            let mut secret_share_store = self.secret_share_store.lock();
            secret_share_store.update_highest_known_round(block.round());
            secret_share_store
                .add_self_share(self_secret_share.clone())
                .expect("Add self dec share should succeed");
        }

        info!(LogSchema::new(LogEvent::BroadcastSecretShare)
            .epoch(self.epoch_state.epoch)
            .author(self.author)
            .round(block.round()));
        self.network_sender.broadcast_without_self(
            SecretShareMessage::Share(self_secret_share).into_network_message(),
        );
        self.spawn_share_requester_task(metadata)
    }
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
