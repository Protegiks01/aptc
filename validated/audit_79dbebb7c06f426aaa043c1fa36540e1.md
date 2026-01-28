# Audit Report

## Title
Critical Validator Crash Due to Empty Weight HashMap in Secret Share State Machine

## Summary
A validator node will panic and crash when processing secret shares if peer shares arrive before the node's own self-share computation completes. This occurs due to an inconsistency between `get_peer_weight()` (returns hardcoded 1) and `get_peer_weights()` (returns empty HashMap) in `SecretShareConfig`, causing a `.expect()` panic in the `retain()` function during state transition from `PendingMetadata` to `PendingDecision`.

## Finding Description

The vulnerability exists in the secret sharing subsystem of the Aptos consensus layer. The `SecretShareItem` state machine manages three states: `PendingMetadata`, `PendingDecision`, and `Decided`. [1](#0-0) 

The root cause is an inconsistency in `SecretShareConfig`. The struct initializes an empty `weights` HashMap [2](#0-1)  but provides two inconsistent methods to access weights:
- `get_peer_weight()` returns a hardcoded value of 1 [3](#0-2) 
- `get_peer_weights()` returns the empty HashMap [4](#0-3) 

**The Race Condition:**

When incoming secret shares from peer validators arrive via network messages, they are processed through `add_share()` which uses `get_peer_weight()` to obtain a weight of 1. [5](#0-4)  These peer shares are successfully added to the aggregator while in `PendingMetadata` state. [6](#0-5) 

Later, when the validator's own self-share computation completes, `add_self_share()` is called. [7](#0-6)  This method retrieves the weights using `get_peer_weights()`, obtaining the empty HashMap. [8](#0-7) 

The empty HashMap is then passed to `add_share_with_metadata()` [9](#0-8)  which triggers a state transition and calls `retain()` to filter shares by metadata. [10](#0-9) 

**The Panic Point:**

Inside `retain()`, the function attempts to recalculate the total weight by iterating over all remaining shares (including the peer shares that arrived earlier) and looking up each author in the weights HashMap. [11](#0-10) 

When it encounters a peer share, the lookup in the empty HashMap fails, triggering the `.expect("Author must exist for weight")` panic at line 79, causing the validator to crash.

**Execution Flow in Production:**

The secret sharing manager is instantiated as part of the consensus pipeline [12](#0-11)  and processes incoming blocks. When a block arrives, it triggers self-share computation (involving cryptographic operations) [13](#0-12)  while simultaneously peer shares can arrive through the network message handler. [14](#0-13) 

## Impact Explanation

**Severity: Critical** (aligns with "Total Loss of Liveness/Network Availability")

This vulnerability causes validator nodes to panic and crash, directly impacting consensus availability:

- **Single Validator Impact**: Loss of one validator reduces network redundancy and increases risk of liveness failures. This alone constitutes HIGH severity per the "Validator Node Crashes" category.

- **Multiple Validator Impact**: If enough validators crash simultaneously (>1/3 of voting power), the network loses liveness and cannot make progress. Since all validators process blocks at approximately the same time, they are all subject to the same race condition, making simultaneous crashes highly likely. This escalates to CRITICAL severity under "Total Loss of Liveness/Network Availability."

- **Non-recoverable without intervention**: Crashed validators must be manually restarted, and without a code fix, the race condition will recur upon restart.

The vulnerability directly breaks the consensus layer's availability guarantees, a core security property of the Aptos blockchain.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability will trigger frequently in production environments because:

1. **Natural Network Conditions**: Validators have different hardware capabilities, network latencies, and computational loads. Some validators will naturally compute shares faster than others, creating the timing window for the race condition.

2. **No Special Privileges Required**: This is not an attack scenario requiring malicious actors—normal network operation triggers it. All validators are susceptible during normal consensus operations.

3. **Significant Timing Window**: The window between receiving peer shares and computing the self-share involves cryptographic operations (PVSS decryption key share derivation), which takes measurable time. Network message propagation can easily occur within this window.

4. **Guaranteed Trigger Condition**: In any scenario where peer shares arrive before self-share computation completes, the validator will crash. This is not a probabilistic edge case but a deterministic outcome.

5. **Network-Wide Impact**: Since all validators process blocks for the same rounds at approximately the same time, if one validator experiences the race condition, multiple validators are likely to experience it simultaneously, compounding the impact on network liveness.

The vulnerability is particularly severe because it doesn't require any Byzantine behavior or attack—it can occur purely from natural network timing variations that are expected in any distributed system.

## Recommendation

The fix requires populating the `weights` HashMap in `SecretShareConfig` with actual validator weights from the `ValidatorVerifier`. The constructor should be modified to extract weights from the validator verifier:

```rust
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
    // Extract weights from validator verifier
    let weights: HashMap<Author, u64> = validator
        .get_ordered_account_addresses_iter()
        .map(|addr| (*addr, validator.get_voting_power(addr).unwrap_or(0)))
        .collect();
    
    Self {
        _author: author,
        _epoch: epoch,
        validator,
        digest_key,
        msk_share,
        verification_keys,
        config,
        encryption_key,
        weights,
    }
}
```

Additionally, `get_peer_weight()` should be updated to use the weights HashMap instead of returning a hardcoded value:

```rust
pub fn get_peer_weight(&self, peer: &Author) -> u64 {
    *self.weights.get(peer).unwrap_or(&0)
}
```

## Proof of Concept

The vulnerability can be demonstrated by creating a scenario where peer shares arrive before self-share computation:

1. Set up a test validator network with secret sharing enabled
2. Introduce artificial delay in self-share computation (simulating cryptographic operation latency)
3. Send peer shares from other validators during this delay
4. Complete self-share computation
5. Observer validator panic at `retain()` line 79 when recalculating weights

The panic will occur with the message: "Author must exist for weight" when the empty weights HashMap is queried for peer authors.

**Notes:**

This is a critical implementation bug in the secret sharing subsystem that affects consensus availability. The comment at line 134 in `types/src/secret_sharing.rs` indicates this is "temporary and meant to change in future PRs," suggesting the developers are aware the implementation is incomplete. However, if this code is deployed in production, it represents a genuine vulnerability that can crash validators and potentially halt the network.

### Citations

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

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L88-97)
```rust
enum SecretShareItem {
    PendingMetadata(SecretShareAggregator),
    PendingDecision {
        metadata: SecretShareMetadata,
        share_aggregator: SecretShareAggregator,
    },
    Decided {
        self_share: SecretShare,
    },
}
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L108-128)
```rust
    fn add_share(&mut self, share: SecretShare, share_weight: u64) -> anyhow::Result<()> {
        match self {
            SecretShareItem::PendingMetadata(aggr) => {
                aggr.add_share(share, share_weight);
                Ok(())
            },
            SecretShareItem::PendingDecision {
                metadata,
                share_aggregator,
            } => {
                ensure!(
                    metadata == &share.metadata,
                    "[SecretShareItem] SecretShare metadata from {} mismatch with block metadata!",
                    share.author,
                );
                share_aggregator.add_share(share, share_weight);
                Ok(())
            },
            SecretShareItem::Decided { .. } => Ok(()),
        }
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

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L65-110)
```rust
impl SecretShareManager {
    pub fn new(
        author: Author,
        epoch_state: Arc<EpochState>,
        config: SecretShareConfig,
        outgoing_blocks: Sender<OrderedBlocks>,
        network_sender: Arc<NetworkSender>,
        bounded_executor: BoundedExecutor,
        rb_config: &ReliableBroadcastConfig,
    ) -> Self {
        let rb_backoff_policy = ExponentialBackoff::from_millis(rb_config.backoff_policy_base_ms)
            .factor(rb_config.backoff_policy_factor)
            .max_delay(Duration::from_millis(rb_config.backoff_policy_max_delay_ms));
        let reliable_broadcast = Arc::new(ReliableBroadcast::new(
            author,
            epoch_state.verifier.get_ordered_account_addresses(),
            network_sender.clone(),
            rb_backoff_policy,
            TimeService::real(),
            Duration::from_millis(rb_config.rpc_timeout_ms),
            bounded_executor,
        ));
        let (decision_tx, decision_rx) = unbounded();

        let dec_store = Arc::new(Mutex::new(SecretShareStore::new(
            epoch_state.epoch,
            author,
            config.clone(),
            decision_tx,
        )));

        Self {
            author,
            epoch_state,
            stop: false,
            config,
            reliable_broadcast,
            network_sender,

            decision_rx,
            outgoing_blocks,

            secret_share_store: dec_store,
            block_queue: BlockQueue::new(),
        }
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

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L279-322)
```rust
    fn handle_incoming_msg(&self, rpc: SecretShareRpc) {
        let SecretShareRpc {
            msg,
            protocol,
            response_sender,
        } = rpc;
        match msg {
            SecretShareMessage::RequestShare(request) => {
                let result = self
                    .secret_share_store
                    .lock()
                    .get_self_share(request.metadata());
                match result {
                    Ok(Some(share)) => {
                        self.process_response(
                            protocol,
                            response_sender,
                            SecretShareMessage::Share(share),
                        );
                    },
                    Ok(None) => {
                        warn!(
                            "Self secret share could not be found for RPC request {}",
                            request.metadata().round
                        );
                    },
                    Err(e) => {
                        warn!("[SecretShareManager] Failed to get share: {}", e);
                    },
                }
            },
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
        }
    }
```
