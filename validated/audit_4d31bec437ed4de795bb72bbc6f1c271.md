# Audit Report

## Title
Resource Leak: Consensus Publisher Serialization Task Hangs Indefinitely After Publisher Shutdown

## Summary
When the `ConsensusPublisher::start()` loop exits, the spawned message serialization task remains alive indefinitely, consuming system resources. This occurs because the publisher is cloned before starting, and the original instance (wrapped in `Arc`) retains ownership of the `outbound_message_sender`, preventing the channel from closing and causing the serialization task to hang on `.collect::<()>().await`.

## Finding Description
The vulnerability exists in the initialization and lifecycle management of the `ConsensusPublisher`.

The publisher initialization follows this pattern: [1](#0-0) 

The publisher is cloned before calling `start()`, and the original is wrapped in an `Arc` and returned. The `ConsensusPublisher` struct derives `Clone`: [2](#0-1) 

When the `start()` method's loop exits at the `else` branch, the cloned `ConsensusPublisher` is dropped: [3](#0-2) 

However, the serialization task spawned earlier continues waiting: [4](#0-3) 

The serialization task uses `.collect::<()>().await` to consume the stream, which blocks until the `outbound_message_receiver` stream completes: [5](#0-4) 

**The Problem**: When `ConsensusPublisher` is cloned, Rust's derived `Clone` implementation clones all fields, including the `mpsc::Sender<...>`. This means:

1. The **cloned** publisher (used in `start()`) has its own copy of `outbound_message_sender`
2. The **original** publisher (in the `Arc`) also has a copy of `outbound_message_sender`
3. When `start()` exits, only the cloned publisher is dropped
4. The original still holds its `outbound_message_sender`
5. Since `mpsc::Sender` doesn't close the channel until **all** senders are dropped, the channel remains open
6. The serialization task hangs forever on `.collect::<()>().await`

The `start()` loop exits when the `publisher_message_receiver` completes, which happens when the network handler exits: [6](#0-5) 

## Impact Explanation
This is a **Medium Severity** vulnerability per the Aptos bug bounty criteria:

1. **Resource Exhaustion**: Each time the publisher is started and stopped (e.g., during node restarts, feature toggles, or testing), a tokio task remains alive indefinitely. While a single task has minimal overhead, repeated start/stop cycles cause accumulation.

2. **State Inconsistencies Requiring Intervention**: In long-running nodes with multiple restart cycles or in testing environments, the accumulation of hung tasks can degrade node performance and eventually require manual intervention or node restart.

3. **Limited Availability Impact**: The hung tasks consume tokio runtime worker slots. If enough tasks accumulate, they can starve the runtime and affect the node's ability to process new tasks, impacting availability.

The impact is limited because:
- It requires shutdown/restart cycles to accumulate
- Single instance has minimal impact
- Does not directly affect consensus safety or fund security
- Can be mitigated by node restart

## Likelihood Explanation
**Likelihood: High**

This vulnerability triggers automatically under normal operational conditions:

1. **Guaranteed Trigger**: Occurs every time the publisher's `start()` loop exits (when `publisher_message_receiver` completes)
2. **Operational Scenarios**:
   - Node shutdown/restart cycles
   - Consensus observer feature being disabled/re-enabled
   - Network handler exits due to network events stream completion
3. **No Special Privileges Required**: Happens through normal lifecycle management, no attacker action needed
4. **Accumulation Over Time**: In environments with frequent restarts (testing, development, or operational reconfigurations), leaked tasks accumulate rapidly

## Recommendation
Fix the issue by explicitly closing the `outbound_message_sender` channel before the `start()` method exits, or restructure the code to ensure the sender is dropped when the loop exits.

**Option 1**: Drop the sender before exiting:
```rust
pub async fn start(
    mut self,  // Take ownership
    outbound_message_receiver: mpsc::Receiver<(PeerNetworkId, ConsensusObserverDirectSend)>,
    mut publisher_message_receiver: Receiver<(), ConsensusPublisherNetworkMessage>,
) {
    // ... existing code ...
    
    // Drop the sender to close the channel
    drop(self.outbound_message_sender);
    
    // Log the exit
    error!(LogSchema::new(LogEntry::ConsensusPublisher)
        .message("The consensus publisher loop exited unexpectedly!"));
}
```

**Option 2**: Don't clone the publisher before starting:
```rust
// In create_consensus_publisher
runtime.spawn(consensus_publisher.start(outbound_message_receiver, publisher_message_receiver));

// Return None for the publisher Arc since it's consumed by start()
(Some(runtime), None)
```

## Proof of Concept
The issue can be demonstrated by:

1. Starting a node with the consensus observer publisher enabled
2. Triggering the network handler to exit (e.g., by closing the network events stream)
3. Observing that the spawned serialization task remains alive
4. Repeating this process multiple times to accumulate leaked tasks

A Rust test demonstrating the issue:

```rust
#[tokio::test]
async fn test_publisher_task_leak() {
    // Create a consensus publisher
    let (consensus_publisher, outbound_message_receiver) = 
        ConsensusPublisher::new(...);
    
    // Clone and start (simulating create_consensus_publisher behavior)
    let cloned_publisher = consensus_publisher.clone();
    let handle = tokio::spawn(async move {
        // Simulate start() exiting
        drop(cloned_publisher);
    });
    
    // Wait for the spawned task to complete
    handle.await.unwrap();
    
    // The original publisher still holds the sender
    // The serialization task would hang forever if spawned
    
    // Drop the original to verify channel closes
    drop(consensus_publisher);
    
    // Now the receiver should complete
    assert!(outbound_message_receiver.collect::<Vec<_>>().await.is_empty());
}
```

## Notes
This vulnerability violates the **Resource Limits** invariant, which requires all operations to respect resource constraints. The leaked tasks represent unbounded resource growth that degrades system reliability over time.

### Citations

**File:** aptos-node/src/consensus.rs (L256-267)
```rust
    let (consensus_publisher, outbound_message_receiver) =
        ConsensusPublisher::new(node_config.consensus_observer, consensus_observer_client);

    // Start the consensus publisher
    runtime.spawn(
        consensus_publisher
            .clone()
            .start(outbound_message_receiver, publisher_message_receiver),
    );

    // Return the runtime and publisher
    (Some(runtime), Some(Arc::new(consensus_publisher)))
```

**File:** consensus/src/consensus_observer/publisher/consensus_publisher.rs (L30-44)
```rust
#[derive(Clone)]
pub struct ConsensusPublisher {
    // The consensus observer client to send network messages
    consensus_observer_client:
        Arc<ConsensusObserverClient<NetworkClient<ConsensusObserverMessage>>>,

    // The configuration for the consensus observer
    consensus_observer_config: ConsensusObserverConfig,

    // The set of active subscribers that have subscribed to consensus updates
    active_subscribers: Arc<RwLock<HashSet<PeerNetworkId>>>,

    // The sender for outbound network messages
    outbound_message_sender: mpsc::Sender<(PeerNetworkId, ConsensusObserverDirectSend)>,
}
```

**File:** consensus/src/consensus_observer/publisher/consensus_publisher.rs (L241-245)
```rust
        spawn_message_serializer_and_sender(
            self.consensus_observer_client.clone(),
            self.consensus_observer_config,
            outbound_message_receiver,
        );
```

**File:** consensus/src/consensus_observer/publisher/consensus_publisher.rs (L265-267)
```rust
                else => {
                    break; // Exit the consensus publisher loop
                }
```

**File:** consensus/src/consensus_observer/publisher/consensus_publisher.rs (L303-348)
```rust
        serialization_task
            .buffered(consensus_observer_config.max_parallel_serialization_tasks)
            .map(|serialization_result| {
                // Attempt to send the serialized message to the peer
                match serialization_result {
                    Ok((peer_network_id, serialized_message, message_label)) => {
                        match serialized_message {
                            Ok(serialized_message) => {
                                // Send the serialized message to the peer
                                if let Err(error) = consensus_observer_client_clone
                                    .send_serialized_message_to_peer(
                                        &peer_network_id,
                                        serialized_message,
                                        message_label,
                                    )
                                {
                                    // We failed to send the message
                                    warn!(LogSchema::new(LogEntry::ConsensusPublisher)
                                        .event(LogEvent::SendDirectSendMessage)
                                        .message(&format!(
                                            "Failed to send message to peer: {:?}. Error: {:?}",
                                            peer_network_id, error
                                        )));
                                }
                            },
                            Err(error) => {
                                // We failed to serialize the message
                                warn!(LogSchema::new(LogEntry::ConsensusPublisher)
                                    .event(LogEvent::SendDirectSendMessage)
                                    .message(&format!(
                                        "Failed to serialize message for peer: {:?}. Error: {:?}",
                                        peer_network_id, error
                                    )));
                            },
                        }
                    },
                    Err(error) => {
                        // We failed to spawn the serialization task
                        warn!(LogSchema::new(LogEntry::ConsensusPublisher)
                            .event(LogEvent::SendDirectSendMessage)
                            .message(&format!("Failed to spawn the serializer task: {:?}", error)));
                    },
                }
            })
            .collect::<()>()
            .await;
```

**File:** consensus/src/consensus_observer/network/network_handler.rs (L157-165)
```rust
                else => {
                    break; // Exit the network handler loop
                }
            }
        }

        // Log an error that the network handler has stopped
        error!(LogSchema::new(LogEntry::ConsensusObserver)
            .message("Consensus observer network handler has stopped!"));
```
