# Audit Report

## Title
Reliable Broadcast Panic on Empty Receiver List in Randomness Consensus

## Summary
The `multicast()` function in the reliable broadcast library panics when called with an empty receivers list, triggering an `unreachable!()` macro. While JWK consensus is protected by validation guards, the randomness consensus subsystems (rand_gen and secret_sharing) have exploitable code paths where filtered validator lists can become empty during normal operation, causing validator node crashes.

## Finding Description

When the reliable broadcast `multicast()` function receives an empty `receivers` list, it creates empty future streams. The `tokio::select!` loop immediately hits the `else` branch containing `unreachable!("Should aggregate with all responses")`, causing a panic and node crash. [1](#0-0) 

The randomness consensus has two vulnerable code paths that call `multicast()` with dynamically filtered validator lists:

**Vulnerable Path 1 - RandManager**: The `spawn_aggregate_shares_task()` method sleeps for 300ms, then filters validators to exclude those who have already submitted shares. If all validators submit shares during this delay, the `targets` list becomes empty, and `multicast()` is called with zero receivers. [2](#0-1) 

**Vulnerable Path 2 - SecretShareManager**: The `spawn_share_requester_task()` follows the identical pattern - 300ms sleep followed by filtered targets that can become empty. [3](#0-2) 

The underlying network layer's `to_bytes_by_protocol()` returns an empty HashMap when no peers match protocol requirements, which flows through without error checking: [4](#0-3) 

**JWK Consensus Protection**: JWK consensus is protected by a guard that prevents starting the manager unless the validator is in the active set, and it only uses `broadcast()` (not `multicast()` directly): [5](#0-4) 

The NetworkSender implementation delegates to the network client's `to_bytes_by_protocol()`: [6](#0-5) 

## Impact Explanation

**Severity: Medium (up to $10,000)**

This vulnerability causes validator node crashes, violating availability guarantees:
- **Availability Impact**: Validator nodes panic and require manual restart
- **Scope**: Affects randomness consensus subsystem used for validator selection and protocol fairness
- **Not Safety-Critical**: Does not cause consensus safety violations, double-spending, or fund loss
- **Temporary**: Recoverable through node restart
- **Potential for Multiple Failures**: If network conditions align, multiple validators could crash simultaneously

Per Aptos bug bounty criteria, this qualifies as **Medium severity** as it causes temporary liveness issues affecting validator availability but does not compromise consensus safety or lead to fund loss.

## Likelihood Explanation

**Likelihood: Medium**

The race condition occurs naturally during normal consensus operation:

1. Share request task spawns with 300ms delay
2. Fast validators broadcast shares proactively during this window
3. All validators complete share submission before delayed task executes
4. Filtered validator list becomes empty
5. `multicast()` called with empty list → panic

Factors increasing likelihood:
- **Small validator sets**: Fewer shares needed for quorum
- **Fast network propagation**: Shares arrive quickly during 300ms window
- **High validator responsiveness**: All validators submit promptly
- **Task scheduling delays**: The hardcoded 300ms sleep creates race window

No malicious attacker action required - this is a timing-dependent race condition that can occur in production under normal load with responsive validators and low-latency networks.

## Recommendation

Add validation before calling `multicast()` to handle empty receiver lists gracefully:

```rust
// In rand_manager.rs spawn_aggregate_shares_task()
let targets = epoch_state
    .verifier
    .get_ordered_account_addresses_iter()
    .filter(|author| !existing_shares.contains(author))
    .collect::<Vec<_>>();

if targets.is_empty() {
    info!(
        epoch = epoch,
        round = round,
        "[RandManager] All validators already submitted shares, skipping broadcast"
    );
    return;
}

rb.multicast(request, aggregate_state, targets)
    .await
    .expect("Broadcast cannot fail");
```

Apply the same fix to `secret_share_manager.rs:spawn_share_requester_task()`.

Alternatively, fix at the library level by handling empty receivers in `multicast()`:

```rust
// In reliable-broadcast/src/lib.rs multicast()
if receivers.is_empty() {
    return async { Err(anyhow::anyhow!("Cannot multicast to empty receiver list")) }.boxed();
}
```

## Proof of Concept

The vulnerability can be demonstrated by:
1. Setting up a test validator set with fast share propagation
2. Triggering randomness generation with all validators responding within 300ms
3. Observing the panic when the delayed broadcast task finds all shares already submitted

A complete PoC would require integration testing with the consensus layer, but the code paths are clearly vulnerable based on static analysis of the filtering logic and empty list handling.

## Notes

This vulnerability demonstrates a gap between the reliable broadcast library's assumptions (non-empty receiver lists) and the consensus layer's dynamic filtering logic. The 300ms hardcoded delay in both randomness subsystems creates a consistent race window where this condition can manifest in production networks with responsive validators.

### Citations

**File:** crates/reliable-broadcast/src/lib.rs (L164-203)
```rust
            for receiver in receivers {
                rpc_futures.push(send_message(receiver, None));
            }
            loop {
                tokio::select! {
                    Some((receiver, result)) = rpc_futures.next() => {
                        let aggregating = aggregating.clone();
                        let future = executor.spawn(async move {
                            (
                                    receiver,
                                    result
                                        .and_then(|msg| {
                                            msg.try_into().map_err(|e| anyhow::anyhow!("{:?}", e))
                                        })
                                        .and_then(|ack| aggregating.add(receiver, ack)),
                            )
                        }).await;
                        aggregate_futures.push(future);
                    },
                    Some(result) = aggregate_futures.next() => {
                        let (receiver, result) = result.expect("spawned task must succeed");
                        match result {
                            Ok(may_be_aggragated) => {
                                if let Some(aggregated) = may_be_aggragated {
                                    return Ok(aggregated);
                                }
                            },
                            Err(e) => {
                                log_rpc_failure(e, receiver);

                                let backoff_strategy = backoff_policies
                                    .get_mut(&receiver)
                                    .expect("should be present");
                                let duration = backoff_strategy.next().expect("should produce value");
                                rpc_futures
                                    .push(send_message(receiver, Some(duration)));
                            },
                        }
                    },
                    else => unreachable!("Should aggregate with all responses")
```

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L273-290)
```rust
        let task = async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            let maybe_existing_shares = rand_store.lock().get_all_shares_authors(round);
            if let Some(existing_shares) = maybe_existing_shares {
                let epoch = epoch_state.epoch;
                let request = RequestShare::new(metadata.clone());
                let targets = epoch_state
                    .verifier
                    .get_ordered_account_addresses_iter()
                    .filter(|author| !existing_shares.contains(author))
                    .collect::<Vec<_>>();
                info!(
                    epoch = epoch,
                    round = round,
                    "[RandManager] Start broadcasting share request for {}",
                    targets.len(),
                );
                rb.multicast(request, aggregate_state, targets)
```

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L246-264)
```rust
        let task = async move {
            // TODO(ibalajiarun): Make this configurable
            tokio::time::sleep(Duration::from_millis(300)).await;
            let maybe_existing_shares = secret_share_store.lock().get_all_shares_authors(&metadata);
            if let Some(existing_shares) = maybe_existing_shares {
                let epoch = epoch_state.epoch;
                let request = RequestSecretShare::new(metadata.clone());
                let targets = epoch_state
                    .verifier
                    .get_ordered_account_addresses_iter()
                    .filter(|author| !existing_shares.contains(author))
                    .collect::<Vec<_>>();
                info!(
                    epoch = epoch,
                    round = metadata.round,
                    "[SecretShareManager] Start broadcasting share request for {}",
                    targets.len(),
                );
                rb.multicast(request, aggregate_state, targets)
```

**File:** network/framework/src/application/interface.rs (L288-303)
```rust
    fn to_bytes_by_protocol(
        &self,
        peers: Vec<PeerNetworkId>,
        message: Message,
    ) -> anyhow::Result<HashMap<PeerNetworkId, Bytes>> {
        let peers_per_protocol = self.group_peers_by_protocol(peers);
        // Convert to bytes per protocol
        let mut bytes_per_peer = HashMap::new();
        for (protocol_id, peers) in peers_per_protocol {
            let bytes: Bytes = protocol_id.to_bytes(&message)?.into();
            for peer in peers {
                bytes_per_peer.insert(peer, bytes.clone());
            }
        }

        Ok(bytes_per_peer)
```

**File:** crates/aptos-jwk-consensus/src/epoch_manager.rs (L197-212)
```rust
        if jwk_manager_should_run && my_index.is_some() {
            info!(epoch = epoch_state.epoch, "JWKManager starting.");
            let network_sender = NetworkSender::new(
                self.my_addr,
                self.network_sender.clone(),
                self.self_sender.clone(),
            );
            let rb = ReliableBroadcast::new(
                self.my_addr,
                epoch_state.verifier.get_ordered_account_addresses(),
                Arc::new(network_sender),
                ExponentialBackoff::from_millis(5),
                aptos_time_service::TimeService::real(),
                Duration::from_millis(1000),
                BoundedExecutor::new(8, tokio::runtime::Handle::current()),
            );
```

**File:** consensus/src/network.rs (L709-717)
```rust
    fn to_bytes_by_protocol(
        &self,
        peers: Vec<Author>,
        message: Req,
    ) -> anyhow::Result<HashMap<Author, Bytes>> {
        let consensus_msg = message.into_network_message();
        self.consensus_network_client
            .to_bytes_by_protocol(peers, consensus_msg)
    }
```
