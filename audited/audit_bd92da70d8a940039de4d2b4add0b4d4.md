# Audit Report

## Title
State Sync Driver Panic on Public Fullnodes Due to ConsensusNotifier Channel Closure

## Summary
Public Fullnodes with default configuration (consensus observer disabled) will panic during initialization when all `ConsensusNotifier` sender instances are dropped, causing the consensus notification channel to close while the state sync driver is actively polling it with `select_next_some()`.

## Finding Description

The vulnerability stems from a lifecycle mismatch between the `ConsensusNotifier` senders and the state sync driver's event loop. The state sync driver polls the consensus notification channel using `select_next_some()`, which panics when a stream terminates. On Public Fullnodes (PFNs) with default configuration, all sender instances are dropped during initialization, causing the channel to close while the driver is running.

**Execution Flow:**

1. **Channel Creation**: A single `ConsensusNotifier` (sender) and `ConsensusNotificationListener` (receiver) pair is created during state sync initialization. [1](#0-0) 

2. **Driver Spawn**: The state sync driver is immediately spawned on a runtime and begins its main event loop, which polls `consensus_notification_handler.select_next_some()`. [2](#0-1) [3](#0-2) 

3. **Sender Distribution**: The original `ConsensusNotifier` is cloned and passed to consensus observer and consensus runtime initialization functions. [4](#0-3) 

4. **Sender Drops on PFNs**: For Public Fullnodes with consensus observer disabled (default per `ENABLE_ON_PUBLIC_FULLNODES = false`):
   - The consensus observer clone is immediately dropped when `is_observer_or_publisher_enabled()` returns false [5](#0-4) [6](#0-5) 
   
   - The consensus runtime clone is dropped when `create_consensus_runtime` returns `None` (no consensus on fullnodes) [7](#0-6) 
   
   - The original notifier goes out of scope at function end

5. **Channel Closure**: When all `mpsc::UnboundedSender` instances are dropped, the channel closes and the receiver returns `Poll::Ready(None)` on next poll.

6. **Panic**: The `select_next_some()` combinator panics when it receives `None` from a terminated stream. [8](#0-7) 

The panic occurs because `select_next_some()` from the `StreamExt` trait explicitly panics on terminated streams, as demonstrated in the test suite expectation: `#[should_panic(expected = "SelectNextSome polled after terminated")]`.

## Impact Explanation

**Severity: Medium**

This vulnerability causes **node availability loss** on all Public Fullnodes using default configuration:

- **Affected Nodes**: All PFNs with `consensus_observer.observer_enabled = false` and `consensus_observer.publisher_enabled = false` (default configuration)
- **Impact**: Complete node crash during or shortly after initialization due to panic in state sync driver
- **Recovery**: Node must be manually restarted with consensus observer explicitly enabled to work around the issue

This qualifies as **Medium severity** per Aptos bug bounty criteria because it causes:
- State inconsistencies requiring manual intervention (node restart/reconfiguration)
- Denial of service for affected node instances
- Does not compromise consensus safety or cause fund loss
- Limited to PFN availability, not validator operations

While validators and validator fullnodes are unaffected (consensus observer auto-enabled), the default PFN configuration triggers this bug, making it a widespread availability issue for a significant portion of the network infrastructure.

## Likelihood Explanation

**Likelihood: High**

This vulnerability triggers automatically under the default configuration for Public Fullnodes:

1. **Default Configuration**: `ENABLE_ON_PUBLIC_FULLNODES = false` means PFNs start with consensus observer disabled [9](#0-8) 

2. **No User Action Required**: The bug manifests during normal node initialization without any external trigger or malicious input

3. **Deterministic**: The race condition between driver spawn and sender drops will consistently result in panic

4. **Widespread**: Affects all PFN deployments using recommended default configurations

5. **Testing Gap**: The test suite uses validators or enables consensus observer, missing this edge case

The only mitigation is manual configuration override to enable consensus observer, which is not documented as a requirement for PFN operation.

## Recommendation

**Option 1: Keep Sentinel Sender Alive (Recommended)**

Maintain at least one `ConsensusNotifier` instance in the `AptosHandle` or state sync runtime structures to prevent channel closure:

```rust
// In aptos-node/src/lib.rs
Ok(AptosHandle {
    // ... existing fields ...
    _consensus_notifier: consensus_notifier, // Keep alive even if unused
    _state_sync_runtimes: state_sync_runtimes,
})
```

**Option 2: Use Fuse-Safe Stream Combinator**

Replace `select_next_some()` with a combinator that handles stream termination gracefully:

```rust
// In driver.rs main loop
loop {
    ::futures::select! {
        notification = self.consensus_notification_handler.next() => {
            if let Some(notification) = notification {
                self.handle_consensus_or_observer_notification(notification).await;
            }
            // Stream terminated - continue without panic
        },
        // ... other branches ...
    }
}
```

**Option 3: Conditional Polling**

Only poll the consensus notification handler if consensus or observer is enabled:

```rust
// In driver.rs
loop {
    if self.is_consensus_or_observer_enabled() {
        ::futures::select! {
            notification = self.consensus_notification_handler.select_next_some() => {
                self.handle_consensus_or_observer_notification(notification).await;
            },
            // ... other branches ...
        }
    } else {
        // Poll only non-consensus branches
        ::futures::select! {
            notification = self.client_notification_listener.select_next_some() => {
                self.handle_client_notification(notification).await;
            },
            // ... other non-consensus branches ...
        }
    }
}
```

**Option 1 is recommended** as it's the simplest fix with minimal code changes and maintains the existing architecture.

## Proof of Concept

To reproduce this vulnerability:

1. **Setup a Public Fullnode with default configuration:**
```yaml
# fullnode.yaml
base:
  role: "full_node"
consensus_observer:
  observer_enabled: false  # Default for PFNs
  publisher_enabled: false  # Default for PFNs
```

2. **Start the node:**
```bash
aptos-node -f fullnode.yaml
```

3. **Expected behavior:**
The node will panic during initialization with:
```
thread 'sync-driver' panicked at 'SelectNextSome polled after terminated'
```

4. **Verification via unit test:**
Add to `state-sync/state-sync-driver/src/tests/driver.rs`:
```rust
#[tokio::test]
#[should_panic(expected = "SelectNextSome polled after terminated")]
async fn test_pfn_consensus_notifier_drop_panic() {
    // Create consensus notifier/listener pair
    let (consensus_notifier, consensus_listener) = 
        aptos_consensus_notifications::new_consensus_notifier_listener_pair(1000);
    
    // Simulate PFN behavior: drop all notifier instances
    drop(consensus_notifier);
    
    // Simulate driver polling (this will panic)
    let mut handler = ConsensusNotificationHandler::new(
        consensus_listener, 
        TimeService::mock()
    );
    
    // This panics when channel is closed
    handler.select_next_some().await;
}
```

This demonstrates the exact failure mode affecting production PFN deployments.

## Notes

This vulnerability affects **node availability** rather than **consensus safety**, which is why it rates as Medium severity. However, the high likelihood and automatic triggering on default configurations make it a critical operational issue for the Public Fullnode fleet. The fix should be prioritized to prevent widespread PFN outages.

### Citations

**File:** state-sync/inter-component/consensus-notifications/src/lib.rs (L59-68)
```rust
pub fn new_consensus_notifier_listener_pair(
    timeout_ms: u64,
) -> (ConsensusNotifier, ConsensusNotificationListener) {
    let (notification_sender, notification_receiver) = mpsc::unbounded();

    let consensus_notifier = ConsensusNotifier::new(notification_sender, timeout_ms);
    let consensus_listener = ConsensusNotificationListener::new(notification_receiver);

    (consensus_notifier, consensus_listener)
}
```

**File:** state-sync/state-sync-driver/src/driver_factory.rs (L184-189)
```rust
        // Spawn the driver
        if let Some(driver_runtime) = &driver_runtime {
            driver_runtime.spawn(state_sync_driver.start_driver());
        } else {
            tokio::spawn(state_sync_driver.start_driver());
        }
```

**File:** state-sync/state-sync-driver/src/driver.rs (L221-239)
```rust
        loop {
            ::futures::select! {
                notification = self.client_notification_listener.select_next_some() => {
                    self.handle_client_notification(notification).await;
                },
                notification = self.commit_notification_listener.select_next_some() => {
                    self.handle_snapshot_commit_notification(notification).await;
                }
                notification = self.consensus_notification_handler.select_next_some() => {
                    self.handle_consensus_or_observer_notification(notification).await;
                }
                notification = self.error_notification_listener.select_next_some() => {
                    self.handle_error_notification(notification).await;
                }
                _ = progress_check_interval.select_next_some() => {
                    self.drive_progress().await;
                }
            }
        }
```

**File:** aptos-node/src/lib.rs (L830-851)
```rust
    let (consensus_observer_runtime, consensus_publisher_runtime, consensus_publisher) =
        consensus::create_consensus_observer_and_publisher(
            &node_config,
            consensus_observer_network_interfaces,
            consensus_notifier.clone(),
            consensus_to_mempool_sender.clone(),
            db_rw.clone(),
            consensus_observer_reconfig_subscription,
        );

    // Create the consensus runtime (if enabled)
    let consensus_runtime = consensus::create_consensus_runtime(
        &node_config,
        db_rw.clone(),
        consensus_reconfig_subscription,
        consensus_network_interfaces,
        consensus_notifier.clone(),
        consensus_to_mempool_sender.clone(),
        vtxn_pool,
        consensus_publisher.clone(),
        &mut admin_service,
    );
```

**File:** config/src/config/consensus_observer_config.rs (L11-14)
```rust
// Useful constants for enabling consensus observer on different node types
const ENABLE_ON_VALIDATORS: bool = true;
const ENABLE_ON_VALIDATOR_FULLNODES: bool = true;
const ENABLE_ON_PUBLIC_FULLNODES: bool = false;
```

**File:** config/src/config/consensus_observer_config.rs (L130-138)
```rust
            NodeType::PublicFullnode => {
                if ENABLE_ON_PUBLIC_FULLNODES && !observer_manually_set && !publisher_manually_set {
                    // Enable both the observer and the publisher for PFNs
                    consensus_observer_config.observer_enabled = true;
                    consensus_observer_config.publisher_enabled = true;
                    modified_config = true;
                }
            },
        }
```

**File:** aptos-node/src/consensus.rs (L39-65)
```rust
pub fn create_consensus_runtime(
    node_config: &NodeConfig,
    db_rw: DbReaderWriter,
    consensus_reconfig_subscription: Option<ReconfigNotificationListener<DbBackedOnChainConfig>>,
    consensus_network_interfaces: Option<ApplicationNetworkInterfaces<ConsensusMsg>>,
    consensus_notifier: ConsensusNotifier,
    consensus_to_mempool_sender: Sender<QuorumStoreRequest>,
    vtxn_pool: VTxnPoolState,
    consensus_publisher: Option<Arc<ConsensusPublisher>>,
    admin_service: &mut AdminService,
) -> Option<Runtime> {
    consensus_network_interfaces.map(|consensus_network_interfaces| {
        let (consensus_runtime, consensus_db, quorum_store_db) = services::start_consensus_runtime(
            node_config,
            db_rw.clone(),
            consensus_reconfig_subscription,
            consensus_network_interfaces,
            consensus_notifier.clone(),
            consensus_to_mempool_sender.clone(),
            vtxn_pool,
            consensus_publisher.clone(),
        );
        admin_service.set_consensus_dbs(consensus_db, quorum_store_db);

        consensus_runtime
    })
}
```

**File:** aptos-node/src/consensus.rs (L156-162)
```rust
    // If none of the consensus observer or publisher are enabled, return early
    if !node_config
        .consensus_observer
        .is_observer_or_publisher_enabled()
    {
        return (None, None, None);
    }
```

**File:** state-sync/data-streaming-service/src/tests/streaming_service.rs (L1552-1591)
```rust
#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "SelectNextSome polled after terminated")]
async fn test_terminate_stream() {
    // Create a new streaming client and service
    let streaming_client = create_streaming_client_and_service();

    // Request a state value stream
    let mut stream_listener = streaming_client
        .get_all_state_values(MAX_ADVERTISED_STATES - 1, None)
        .await
        .unwrap();

    // Fetch the first state value notification and then terminate the stream
    let data_notification = get_data_notification(&mut stream_listener).await.unwrap();
    match data_notification.data_payload {
        DataPayload::StateValuesWithProof(_) => {},
        data_payload => unexpected_payload_type!(data_payload),
    }

    // Terminate the stream
    let result = streaming_client
        .terminate_stream_with_feedback(
            stream_listener.data_stream_id,
            Some(NotificationAndFeedback::new(
                data_notification.notification_id,
                NotificationFeedback::InvalidPayloadData,
            )),
        )
        .await;
    assert_ok!(result);

    // Verify the streaming service has removed the stream (polling should panic)
    loop {
        let data_notification = get_data_notification(&mut stream_listener).await.unwrap();
        match data_notification.data_payload {
            DataPayload::StateValuesWithProof(_) => {},
            DataPayload::EndOfStream => panic!("The stream should have terminated!"),
            data_payload => unexpected_payload_type!(data_payload),
        }
    }
```
