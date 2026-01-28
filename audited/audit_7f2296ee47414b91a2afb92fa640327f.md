# Audit Report

## Title
Consensus Observer Bypasses Signature Verification for Future-Epoch CommitDecisions Enabling Critical State Corruption

## Summary
The consensus observer component accepts `CommitDecision` messages from subscribed peers and skips cryptographic signature verification when the epoch doesn't match the current epoch. These unverified commit decisions are then used to corrupt critical node state including the execution client's logical time and buffer manager's committed round tracking, leading to permanent node dysfunction and API service disruption.

## Finding Description

The vulnerability exists in the consensus observer's `process_commit_decision_message` function. When a `CommitDecision` message is received, signature verification is conditionally performed only for the current epoch: [1](#0-0) 

At line 468, verification only occurs when `commit_epoch == epoch_state.epoch`. For future-epoch commit decisions, the code bypasses signature verification at line 470 and falls through to line 526 where `sync_to_commit()` is called with the completely unverified commit decision.

This unverified commit decision then propagates through multiple state corruption paths:

**Path 1: Buffer Manager State Corruption**

The execution client's `sync_to_target` method calls `reset` with the unverified target BEFORE initiating state sync: [2](#0-1) 

The `reset` method extracts the round from the unverified target and sends it to the buffer manager: [3](#0-2) 

The buffer manager then directly updates its critical state fields with these unverified values: [4](#0-3) 

At lines 586-587, `highest_committed_round` and `latest_round` are set to attacker-controlled values without any cryptographic verification.

**Path 2: Logical Time Corruption**

The execution proxy's `sync_to_target` method constructs a logical time from the unverified target and updates the node's latest logical time: [5](#0-4) 

Lines 180-181 construct `target_logical_time` from the unverified epoch and round, and line 222 updates the node's `latest_logical_time` to this malicious value.

**Path 3: Root Ledger Info Corruption**

Before initiating state sync, the observer updates its block data with the unverified commit decision: [6](#0-5) 

At line 282, `update_root` is called with the unverified commit proof: [7](#0-6) 

**No Verification in State Sync Layer**

The state sync component's `initialize_sync_target_request` function performs NO cryptographic signature verification: [8](#0-7) 

It only validates version ordering, not signature authenticity.

**Attack Vector Feasibility**

The consensus observer subscription system allows public network peers to become publishers based solely on distance and latency metrics: [9](#0-8) 

The publisher's subscription handler has no authorization checks: [10](#0-9) 

Any connected peer can advertise support for the consensus observer protocol and potentially be selected as a subscription peer, enabling the attack.

## Impact Explanation

This vulnerability has **HIGH SEVERITY** impact meeting the Aptos bug bounty criteria for "API crashes":

1. **VFN Observer Node Dysfunction**: The corrupted logical time (set to future epoch with maximum round values) prevents the node from processing any legitimate consensus messages, as they would all have lower logical time values than the corrupted state. The node becomes permanently stuck.

2. **API Service Disruption**: VFN observers serve REST API requests for applications and users. When corrupted, they cannot process blocks or provide accurate blockchain state, causing complete API service failure. This directly meets the HIGH severity "API crashes" criterion.

3. **Buffer Manager State Corruption**: Setting `highest_committed_round` to `u64::MAX - 100` corrupts the buffer manager's tracking of committed rounds. All legitimate commit decisions with normal round values will be rejected as "already committed," preventing the node from making any forward progress.

4. **State Sync to Unreachable Target**: The state sync process will attempt to sync to a non-existent version (based on the malicious commit decision), which will fail indefinitely, keeping the node in a permanent failure state.

The impact is permanent node dysfunction requiring manual intervention to recover, qualifying as HIGH severity under "API crashes" that affect network infrastructure.

## Likelihood Explanation

**Likelihood: Medium**

The attack requires:
- Attacker to operate a node that can connect to target VFN observers on public networks
- Attacker's node to be selected as a subscription peer by the observer
- Knowledge of the current epoch to craft future-epoch messages (publicly available information)

The attack is **feasible** because:

1. **Public Network Access**: VFN observers accept connections from public network peers, as evidenced by the peer selection algorithm that includes public peers.

2. **No Authorization Requirement**: The subscription mechanism has no cryptographic authorization. Any peer advertising support for the consensus observer protocol can potentially be selected.

3. **Peer Selection Based on Metrics**: Selection is based on distance from validators and latency, not trust relationships. An attacker node with good network positioning can be selected.

4. **Default Configuration**: VFN observers commonly enable both observer and publisher features in default configurations.

However, the likelihood is not "High" because:
- The attacker must successfully get selected among competing peers
- The attacker needs to maintain the network connection during the attack
- Some network configurations may restrict public peer connections

## Recommendation

Implement mandatory signature verification for ALL commit decisions regardless of epoch:

1. **Verify Future-Epoch Commit Decisions**: When receiving a commit decision for a future epoch, either:
   - Reject it entirely (safest approach)
   - Store it temporarily and verify signatures once the new epoch state is available
   - Obtain the epoch state for the future epoch from trusted sources and verify against it

2. **Add Signature Verification in State Sync**: The state sync layer should verify signatures on target ledger infos before accepting them as sync targets.

3. **Strengthen Subscription Authorization**: Implement cryptographic authorization for consensus observer subscriptions, requiring peers to prove they are trusted VFNs or validators before being accepted as publishers.

Recommended code fix for immediate mitigation:

```rust
// In process_commit_decision_message, lines 466-495
let epoch_state = self.get_epoch_state();
if commit_epoch == epoch_state.epoch {
    // Verify the commit decision
    if let Err(error) = commit_decision.verify_commit_proof(&epoch_state) {
        // ... existing error handling ...
        return;
    }
    // ... process for current epoch ...
} else {
    // NEW: Reject future-epoch commit decisions instead of using them unverified
    warn!(
        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
            "Rejecting commit decision for different epoch! Commit epoch: {}, Current epoch: {}",
            commit_epoch, epoch_state.epoch
        ))
    );
    return; // Do not proceed with unverified future-epoch commits
}
```

## Proof of Concept

A proof of concept would involve:

1. Setting up a malicious node that implements the consensus observer protocol
2. Connecting to a VFN observer on the public network
3. Waiting to be selected as a subscription peer
4. Sending a `CommitDecision` message with:
   - `epoch = current_epoch + 1`
   - `round = u64::MAX - 100`
   - `version = u64::MAX - 100`
   - Empty or invalid signature aggregate
5. Observing the VFN observer's state become corrupted as evidenced by:
   - Rejection of all legitimate commit decisions
   - Buffer manager state showing `highest_committed_round = u64::MAX - 100`
   - Node unable to process any further consensus messages
   - API endpoints becoming unresponsive or returning stale data

The vulnerability can be reproduced by examining the code paths documented above, which show that no validation prevents this attack flow.

### Citations

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L466-495)
```rust
        // If the commit decision is for the current epoch, verify and process it
        let epoch_state = self.get_epoch_state();
        if commit_epoch == epoch_state.epoch {
            // Verify the commit decision
            if let Err(error) = commit_decision.verify_commit_proof(&epoch_state) {
                // Log the error and update the invalid message counter
                error!(
                    LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                        "Failed to verify commit decision! Ignoring: {:?}, from peer: {:?}. Error: {:?}",
                        commit_decision.proof_block_info(),
                        peer_network_id,
                        error
                    ))
                );
                increment_invalid_message_counter(&peer_network_id, metrics::COMMIT_DECISION_LABEL);
                return;
            }

            // Update the latency metrics for commit processing
            update_message_processing_latency_metrics(
                message_received_time,
                &peer_network_id,
                metrics::COMMIT_DECISION_LABEL,
            );

            // Update the pending blocks with the commit decision
            if self.process_commit_decision_for_pending_block(&commit_decision) {
                return; // The commit decision was successfully processed
            }
        }
```

**File:** consensus/src/pipeline/execution_client.rs (L661-672)
```rust
    async fn sync_to_target(&self, target: LedgerInfoWithSignatures) -> Result<(), StateSyncError> {
        fail_point!("consensus::sync_to_target", |_| {
            Err(anyhow::anyhow!("Injected error in sync_to_target").into())
        });

        // Reset the rand and buffer managers to the target round
        self.reset(&target).await?;

        // TODO: handle the state sync error (e.g., re-push the ordered
        // blocks to the buffer manager when it's reset but sync fails).
        self.execution_proxy.sync_to_target(target).await
    }
```

**File:** consensus/src/pipeline/execution_client.rs (L695-706)
```rust
        if let Some(mut reset_tx) = reset_tx_to_buffer_manager {
            // reset execution phase and commit phase
            let (tx, rx) = oneshot::channel::<ResetAck>();
            reset_tx
                .send(ResetRequest {
                    tx,
                    signal: ResetSignal::TargetRound(target.commit_info().round()),
                })
                .await
                .map_err(|_| Error::ResetDropped)?;
            rx.await.map_err(|_| Error::ResetDropped)?;
        }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L579-596)
```rust
    async fn process_reset_request(&mut self, request: ResetRequest) {
        let ResetRequest { tx, signal } = request;
        info!("Receive reset");

        match signal {
            ResetSignal::Stop => self.stop = true,
            ResetSignal::TargetRound(round) => {
                self.highest_committed_round = round;
                self.latest_round = round;

                let _ = self.drain_pending_commit_proof_till(round);
            },
        }

        self.reset().await;
        let _ = tx.send(ResetAck::default());
        info!("Reset finishes");
    }
```

**File:** consensus/src/state_computer.rs (L177-223)
```rust
    async fn sync_to_target(&self, target: LedgerInfoWithSignatures) -> Result<(), StateSyncError> {
        // Grab the logical time lock and calculate the target logical time
        let mut latest_logical_time = self.write_mutex.lock().await;
        let target_logical_time =
            LogicalTime::new(target.ledger_info().epoch(), target.ledger_info().round());

        // Before state synchronization, we have to call finish() to free the
        // in-memory SMT held by BlockExecutor to prevent a memory leak.
        self.executor.finish();

        // The pipeline phase already committed beyond the target block timestamp, just return.
        if *latest_logical_time >= target_logical_time {
            warn!(
                "State sync target {:?} is lower than already committed logical time {:?}",
                target_logical_time, *latest_logical_time
            );
            return Ok(());
        }

        // This is to update QuorumStore with the latest known commit in the system,
        // so it can set batches expiration accordingly.
        // Might be none if called in the recovery path, or between epoch stop and start.
        if let Some(inner) = self.state.read().as_ref() {
            let block_timestamp = target.commit_info().timestamp_usecs();
            inner
                .payload_manager
                .notify_commit(block_timestamp, Vec::new());
        }

        // Inject an error for fail point testing
        fail_point!("consensus::sync_to_target", |_| {
            Err(anyhow::anyhow!("Injected error in sync_to_target").into())
        });

        // Invoke state sync to synchronize to the specified target. Here, the
        // ChunkExecutor will process chunks and commit to storage. However, after
        // block execution and commits, the internal state of the ChunkExecutor may
        // not be up to date. So, it is required to reset the cache of the
        // ChunkExecutor in state sync when requested to sync.
        let result = monitor!(
            "sync_to_target",
            self.state_sync_notifier.sync_to_target(target).await
        );

        // Update the latest logical time
        *latest_logical_time = target_logical_time;

```

**File:** consensus/src/consensus_observer/observer/block_data.rs (L275-291)
```rust
    pub fn update_blocks_for_state_sync_commit(&mut self, commit_decision: &CommitDecision) {
        // Get the commit proof, epoch and round
        let commit_proof = commit_decision.commit_proof();
        let commit_epoch = commit_decision.epoch();
        let commit_round = commit_decision.round();

        // Update the root
        self.update_root(commit_proof.clone());

        // Update the block payload store
        self.block_payload_store
            .remove_blocks_for_epoch_round(commit_epoch, commit_round);

        // Update the ordered block store
        self.ordered_block_store
            .remove_blocks_for_commit(commit_proof);
    }
```

**File:** consensus/src/consensus_observer/observer/block_data.rs (L299-302)
```rust
    /// Updates the root ledger info
    pub fn update_root(&mut self, new_root: LedgerInfoWithSignatures) {
        self.root = new_root;
    }
```

**File:** state-sync/state-sync-driver/src/notification_handlers.rs (L262-318)
```rust
    pub async fn initialize_sync_target_request(
        &mut self,
        sync_target_notification: ConsensusSyncTargetNotification,
        latest_pre_committed_version: Version,
        latest_synced_ledger_info: LedgerInfoWithSignatures,
    ) -> Result<(), Error> {
        // Get the target sync version and latest committed version
        let sync_target_version = sync_target_notification
            .get_target()
            .ledger_info()
            .version();
        let latest_committed_version = latest_synced_ledger_info.ledger_info().version();

        // If the target version is old, return an error to consensus (something is wrong!)
        if sync_target_version < latest_committed_version
            || sync_target_version < latest_pre_committed_version
        {
            let error = Err(Error::OldSyncRequest(
                sync_target_version,
                latest_pre_committed_version,
                latest_committed_version,
            ));
            self.respond_to_sync_target_notification(sync_target_notification, error.clone())?;
            return error;
        }

        // If the committed version is at the target, return successfully
        if sync_target_version == latest_committed_version {
            info!(
                LogSchema::new(LogEntry::NotificationHandler).message(&format!(
                    "We're already at the requested sync target version: {} \
                (pre-committed version: {}, committed version: {})!",
                    sync_target_version, latest_pre_committed_version, latest_committed_version
                ))
            );
            let result = Ok(());
            self.respond_to_sync_target_notification(sync_target_notification, result.clone())?;
            return result;
        }

        // If the pre-committed version is already at the target, something has else gone wrong
        if sync_target_version == latest_pre_committed_version {
            let error = Err(Error::InvalidSyncRequest(
                sync_target_version,
                latest_pre_committed_version,
            ));
            self.respond_to_sync_target_notification(sync_target_notification, error.clone())?;
            return error;
        }

        // Save the request so we can notify consensus once we've hit the target
        let consensus_sync_request =
            ConsensusSyncRequest::new_with_target(sync_target_notification);
        self.consensus_sync_request = Arc::new(Mutex::new(Some(consensus_sync_request)));

        Ok(())
    }
```

**File:** consensus/src/consensus_observer/observer/subscription_utils.rs (L275-350)
```rust
/// Sorts the peers by subscription optimality (in descending order of
/// optimality). This requires: (i) sorting the peers by distance from the
/// validator set and ping latency (lower values are more optimal); and (ii)
/// filtering out peers that don't support consensus observer.
///
/// Note: we prioritize distance over latency as we want to avoid close
/// but not up-to-date peers. If peers don't have sufficient metadata
/// for sorting, they are given a lower priority.
pub fn sort_peers_by_subscription_optimality(
    peers_and_metadata: &HashMap<PeerNetworkId, PeerMetadata>,
) -> Vec<PeerNetworkId> {
    // Group peers and latencies by validator distance, i.e., distance -> [(peer, latency)]
    let mut unsupported_peers = Vec::new();
    let mut peers_and_latencies_by_distance = BTreeMap::new();
    for (peer_network_id, peer_metadata) in peers_and_metadata {
        // Verify that the peer supports consensus observer
        if !supports_consensus_observer(peer_metadata) {
            unsupported_peers.push(*peer_network_id);
            continue; // Skip the peer
        }

        // Get the distance and latency for the peer
        let distance = get_distance_for_peer(peer_network_id, peer_metadata);
        let latency = get_latency_for_peer(peer_network_id, peer_metadata);

        // If the distance is not found, use the maximum distance
        let distance =
            distance.unwrap_or(aptos_peer_monitoring_service_types::MAX_DISTANCE_FROM_VALIDATORS);

        // If the latency is not found, use a large latency
        let latency = latency.unwrap_or(MAX_PING_LATENCY_SECS);

        // Add the peer and latency to the distance group
        peers_and_latencies_by_distance
            .entry(distance)
            .or_insert_with(Vec::new)
            .push((*peer_network_id, OrderedFloat(latency)));
    }

    // If there are peers that don't support consensus observer, log them
    if !unsupported_peers.is_empty() {
        info!(
            LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                "Found {} peers that don't support consensus observer! Peers: {:?}",
                unsupported_peers.len(),
                unsupported_peers
            ))
        );
    }

    // Sort the peers by distance and latency. Note: BTreeMaps are
    // sorted by key, so the entries will be sorted by distance in ascending order.
    let mut sorted_peers_and_latencies = Vec::new();
    for (_, mut peers_and_latencies) in peers_and_latencies_by_distance {
        // Sort the peers by latency
        peers_and_latencies.sort_by_key(|(_, latency)| *latency);

        // Add the peers to the sorted list (in sorted order)
        sorted_peers_and_latencies.extend(peers_and_latencies);
    }

    // Log the sorted peers and latencies
    info!(
        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
            "Sorted {} peers by subscription optimality! Peers and latencies: {:?}",
            sorted_peers_and_latencies.len(),
            sorted_peers_and_latencies
        ))
    );

    // Only return the sorted peers (without the latencies)
    sorted_peers_and_latencies
        .into_iter()
        .map(|(peer, _)| peer)
        .collect()
}
```

**File:** consensus/src/consensus_observer/publisher/consensus_publisher.rs (L180-193)
```rust
        match message {
            ConsensusObserverRequest::Subscribe => {
                // Add the peer to the set of active subscribers
                self.add_active_subscriber(peer_network_id);
                info!(LogSchema::new(LogEntry::ConsensusPublisher)
                    .event(LogEvent::Subscription)
                    .message(&format!(
                        "New peer subscribed to consensus updates! Peer: {:?}",
                        peer_network_id
                    )));

                // Send a simple subscription ACK
                response_sender.send(ConsensusObserverResponse::SubscribeAck);
            },
```
