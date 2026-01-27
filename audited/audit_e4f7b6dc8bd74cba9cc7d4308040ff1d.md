# Audit Report

## Title
Memory Leak and Denial of Service through Dropped Event Notification Listeners

## Summary
The `EventSubscriptionService` in the state-sync event notification system lacks a cleanup mechanism for dropped listeners. When an `EventNotificationListener` is dropped without consuming messages, the sender-side resources remain permanently allocated in the service, causing memory leaks and potential denial of service for all event subscribers.

## Finding Description

The vulnerability exists in the event notification subscription architecture where the service maintains sender-side state that persists indefinitely after listeners are dropped. [1](#0-0) 

When `subscribe_to_events()` is called, it creates a channel and stores the sender in `EventSubscription` within the `subscription_id_to_event_subscription` HashMap, while returning only the receiver to the caller. The subscription mappings are also stored in `event_key_subscriptions` and `event_v2_tag_subscriptions` HashMaps. [2](#0-1) 

When the listener is dropped, only the `Receiver` portion is dropped, which sets the `receiver_dropped` flag in the underlying channel: [3](#0-2) 

However, the `Sender` remains in the service's HashMap. The underlying `SharedState` (containing the channel's internal queue with accumulated messages) is held by an `Arc` reference from the sender and will not be freed until the sender is dropped: [4](#0-3) 

**Memory Leak Components:**
1. `EventSubscription` struct remains in `subscription_id_to_event_subscription` HashMap
2. The `Sender` maintains an Arc reference to `SharedState`
3. `SharedState` contains the `PerKeyQueue` with up to 100 buffered messages (per `EVENT_NOTIFICATION_CHANNEL_SIZE`)
4. The `event_buffer` in `EventSubscription` continues to accumulate events
5. Subscription mappings remain in `event_key_subscriptions` and `event_v2_tag_subscriptions`

**Denial of Service Impact:**
After the receiver is dropped, subsequent attempts to notify events will fail: [5](#0-4) 

The push operation checks if `receiver_dropped` is true and returns an error. This error propagates through the notification chain: [6](#0-5) [7](#0-6) 

The error propagation causes the entire `notify_events` call to fail, affecting transaction commit notifications: [8](#0-7) 

## Impact Explanation

This qualifies as **Medium Severity** based on Aptos bug bounty criteria:

1. **Memory Leak**: Each dropped listener permanently leaks memory including:
   - EventSubscription struct and buffers
   - Channel infrastructure (Sender, SharedState, PerKeyQueue)
   - Up to 100 event messages per subscription (at ~1-2 KB per event = ~100-200 KB)
   - HashMap entries and subscription mappings

2. **Denial of Service**: After a listener is dropped, every subsequent `notify_events` call fails when attempting to send to that subscription. While errors are logged rather than crashing the node, this causes:
   - Failed transaction commit notifications
   - Degraded state sync functionality
   - Accumulated error logs

3. **State Inconsistency**: The failure in event notification during transaction commits could lead to inconsistent notification state across system components.

While network-level DoS is out of scope, this represents a resource exhaustion vulnerability within the node that affects availability and requires manual intervention to resolve.

## Likelihood Explanation

**Current Production Code**: Low immediate likelihood as listeners are created at node startup and held for the node's lifetime. [9](#0-8) 

**Trigger Conditions**:
1. Component crashes during initialization after listener creation but before listener storage
2. Error conditions causing early returns that drop listeners
3. Future code changes introducing dynamic subscription patterns
4. Test code that creates and drops listeners (though tests are out of scope for exploitation)

The vulnerability represents a **design flaw** - the API lacks defensive cleanup mechanisms. While not currently exploitable by external attackers, it poses a risk during operational failures and future development.

## Recommendation

Implement a cleanup mechanism to remove stale subscriptions when receivers are dropped. This can be achieved through:

**Option 1: Add explicit unsubscribe method**
```rust
pub fn unsubscribe_from_events(&mut self, subscription_id: SubscriptionId) -> Result<(), Error> {
    // Remove from event_key_subscriptions
    self.event_key_subscriptions.retain(|_, ids| {
        ids.remove(&subscription_id);
        !ids.is_empty()
    });
    
    // Remove from event_v2_tag_subscriptions
    self.event_v2_tag_subscriptions.retain(|_, ids| {
        ids.remove(&subscription_id);
        !ids.is_empty()
    });
    
    // Remove the subscription itself
    self.subscription_id_to_event_subscription.remove(&subscription_id)
        .ok_or(Error::MissingEventSubscription(subscription_id))?;
    
    Ok(())
}
```

**Option 2: Return subscription handles with Drop implementation**
Wrap `EventNotificationListener` in a handle that calls unsubscribe on drop:
```rust
pub struct EventSubscriptionHandle {
    subscription_id: SubscriptionId,
    listener: EventNotificationListener,
    cleanup_tx: mpsc::Sender<SubscriptionId>,
}

impl Drop for EventSubscriptionHandle {
    fn drop(&mut self) {
        let _ = self.cleanup_tx.try_send(self.subscription_id);
    }
}
```

**Option 3: Detect closed channels during notification**
Modify `notify_subscriber_of_events` to return a special error when the channel is closed, then remove that subscription from the service.

## Proof of Concept

```rust
#[test]
fn test_dropped_listener_memory_leak() {
    use aptos_event_notifications::{EventSubscriptionService, EventNotificationSender};
    use aptos_types::{event::EventKey, contract_event::ContractEvent};
    use aptos_db::AptosDB;
    use aptos_executor_test_helpers::bootstrap_genesis;
    use aptos_infallible::RwLock;
    use std::sync::Arc;

    // Setup database
    let (genesis, validators) = aptos_vm_genesis::test_genesis_change_set_and_validators(Some(1));
    let genesis_txn = Transaction::GenesisTransaction(WriteSetPayload::Direct(genesis));
    let db = DbReaderWriter::new(AptosDB::new_for_test(&aptos_temppath::TempPath::new()));
    let executor = AptosVMBlockExecutor::new();
    executor.execute_genesis_block(db.writer.clone(), &genesis_txn, vec![]);

    // Create event subscription service
    let mut event_service = EventSubscriptionService::new(Arc::new(RwLock::new(db)));
    
    // Create test event key
    let event_key = EventKey::random();
    
    // Subscribe and immediately drop listener
    {
        let _listener = event_service.subscribe_to_events(vec![event_key], vec![])
            .expect("Failed to subscribe");
        // listener is dropped here
    }
    
    // Verify subscription still exists in service
    assert_eq!(event_service.event_key_subscriptions.get(&event_key).unwrap().len(), 1);
    assert_eq!(event_service.subscription_id_to_event_subscription.len(), 1);
    
    // Try to notify events - this will fail
    let test_event = create_test_event(event_key);
    let result = event_service.notify_events(0, vec![test_event]);
    
    // Verify error occurs
    assert!(result.is_err());
    
    // Subscription data still remains (memory leak)
    assert_eq!(event_service.subscription_id_to_event_subscription.len(), 1);
    
    // Multiple dropped listeners accumulate
    for _ in 0..10 {
        let _listener = event_service.subscribe_to_events(vec![event_key], vec![])
            .expect("Failed to subscribe");
        // Each listener dropped without cleanup
    }
    
    // All 11 subscriptions remain in memory
    assert_eq!(event_service.subscription_id_to_event_subscription.len(), 11);
}
```

## Notes

This vulnerability exists due to the asymmetric ownership model where the service retains sender-side resources while clients hold only the receiver. The KLAST (Keep Last) queue style with a capacity of 100 messages exacerbates the memory leak by retaining up to 100 events per dropped subscription. [10](#0-9) 

While not currently exploited in production code paths, this represents a critical design flaw that should be addressed to prevent future operational issues and enable safe dynamic subscription patterns.

### Citations

**File:** state-sync/inter-component/event-notifications/src/lib.rs (L36-40)
```rust
// Maximum channel sizes for each notification subscriber. If messages are not
// consumed, they will be dropped (oldest messages first). The remaining messages
// will be retrieved using FIFO ordering.
const EVENT_NOTIFICATION_CHANNEL_SIZE: usize = 100;
const RECONFIG_NOTIFICATION_CHANNEL_SIZE: usize = 1; // Note: this should be 1 to ensure only the latest reconfig is consumed
```

**File:** state-sync/inter-component/event-notifications/src/lib.rs (L110-163)
```rust
    pub fn subscribe_to_events(
        &mut self,
        event_keys: Vec<EventKey>,
        event_v2_tags: Vec<String>,
    ) -> Result<EventNotificationListener, Error> {
        if event_keys.is_empty() && event_v2_tags.is_empty() {
            return Err(Error::CannotSubscribeToZeroEventKeys);
        }

        let (notification_sender, notification_receiver) =
            aptos_channel::new(QueueStyle::KLAST, EVENT_NOTIFICATION_CHANNEL_SIZE, None);

        // Create a new event subscription
        let subscription_id = self.get_new_subscription_id();
        let event_subscription = EventSubscription {
            notification_sender,
            event_buffer: vec![],
        };

        // Store the new subscription
        if let Some(old_subscription) = self
            .subscription_id_to_event_subscription
            .insert(subscription_id, event_subscription)
        {
            return Err(Error::UnexpectedErrorEncountered(format!(
                "Duplicate event subscription found! This should not occur! ID: {}, subscription: {:?}",
                subscription_id, old_subscription
            )));
        }

        // Update the event key subscriptions to include the new subscription
        for event_key in event_keys {
            self.event_key_subscriptions
                .entry(event_key)
                .and_modify(|subscriptions| {
                    subscriptions.insert(subscription_id);
                })
                .or_insert_with(|| HashSet::from_iter([subscription_id].iter().cloned()));
        }

        // Update the event v2 tag subscriptions to include the new subscription
        for event_tag in event_v2_tags {
            self.event_v2_tag_subscriptions
                .entry(event_tag)
                .and_modify(|subscriptions| {
                    subscriptions.insert(subscription_id);
                })
                .or_insert_with(|| HashSet::from_iter([subscription_id].iter().cloned()));
        }

        Ok(EventNotificationListener {
            notification_receiver,
        })
    }
```

**File:** state-sync/inter-component/event-notifications/src/lib.rs (L207-260)
```rust
    fn notify_event_subscribers(
        &mut self,
        version: Version,
        events: Vec<ContractEvent>,
    ) -> Result<bool, Error> {
        let mut reconfig_event_found = false;
        let mut event_subscription_ids_to_notify = HashSet::new();

        for event in events.iter() {
            // Process all subscriptions for the current event
            let maybe_subscription_ids = match event {
                ContractEvent::V1(evt) => self.event_key_subscriptions.get(evt.key()),
                ContractEvent::V2(evt) => {
                    let tag = evt.type_tag().to_canonical_string();
                    self.event_v2_tag_subscriptions.get(&tag)
                },
            };
            if let Some(subscription_ids) = maybe_subscription_ids {
                // Add the event to the subscription's pending event buffer
                // and store the subscriptions that will need to notified once all
                // events have been processed.
                for subscription_id in subscription_ids.iter() {
                    if let Some(event_subscription) = self
                        .subscription_id_to_event_subscription
                        .get_mut(subscription_id)
                    {
                        event_subscription.buffer_event(event.clone());
                        event_subscription_ids_to_notify.insert(*subscription_id);
                    } else {
                        return Err(Error::MissingEventSubscription(*subscription_id));
                    }
                }
            }

            // Take note if a reconfiguration (new epoch) has occurred
            if event.is_new_epoch_event() {
                reconfig_event_found = true;
            }
        }

        // Notify event subscribers of the new events
        for event_subscription_id in event_subscription_ids_to_notify {
            if let Some(event_subscription) = self
                .subscription_id_to_event_subscription
                .get_mut(&event_subscription_id)
            {
                event_subscription.notify_subscriber_of_events(version)?;
            } else {
                return Err(Error::MissingEventSubscription(event_subscription_id));
            }
        }

        Ok(reconfig_event_found)
    }
```

**File:** state-sync/inter-component/event-notifications/src/lib.rs (L310-326)
```rust
impl EventNotificationSender for EventSubscriptionService {
    fn notify_events(&mut self, version: Version, events: Vec<ContractEvent>) -> Result<(), Error> {
        if events.is_empty() {
            return Ok(()); // No events!
        }

        // Notify event subscribers and check if a reconfiguration event was processed
        let reconfig_event_processed = self.notify_event_subscribers(version, events)?;

        // If a reconfiguration event was found, also notify the reconfig subscribers
        // of the new configuration values.
        if reconfig_event_processed {
            self.notify_reconfiguration_subscribers(version)
        } else {
            Ok(())
        }
    }
```

**File:** state-sync/inter-component/event-notifications/src/lib.rs (L338-359)
```rust
#[derive(Debug)]
struct EventSubscription {
    pub event_buffer: Vec<ContractEvent>,
    pub notification_sender: aptos_channels::aptos_channel::Sender<(), EventNotification>,
}

impl EventSubscription {
    fn buffer_event(&mut self, event: ContractEvent) {
        self.event_buffer.push(event)
    }

    fn notify_subscriber_of_events(&mut self, version: Version) -> Result<(), Error> {
        let event_notification = EventNotification {
            subscribed_events: self.event_buffer.drain(..).collect(),
            version,
        };

        self.notification_sender
            .push((), event_notification)
            .map_err(|error| Error::UnexpectedErrorEncountered(format!("{:?}", error)))
    }
}
```

**File:** crates/channel/src/aptos_channel.rs (L26-47)
```rust
/// SharedState is a data structure private to this module which is
/// shared by the `Receiver` and any `Sender`s.
#[derive(Debug)]
struct SharedState<K: Eq + Hash + Clone, M> {
    /// The internal queue of messages in this channel.
    internal_queue: PerKeyQueue<K, (M, Option<oneshot::Sender<ElementStatus<M>>>)>,
    /// The `Receiver` registers its `Waker` in this slot when the queue is empty.
    /// `Sender`s will try to wake the `Receiver` (if any) when they push a new
    /// item onto the queue. The last live `Sender` will also wake the `Receiver`
    /// as it's tearing down so the `Receiver` can gracefully drain and shutdown
    /// the channel.
    waker: Option<Waker>,
    /// The number of active senders. When this value reaches 0, all senders have
    /// been dropped.
    num_senders: usize,
    /// A boolean which tracks whether the receiver has dropped.
    receiver_dropped: bool,
    /// A boolean which tracks whether the stream has terminated. A stream is
    /// considered terminated when sender has dropped and we have drained everything
    /// inside our internal queue.
    stream_terminated: bool,
}
```

**File:** crates/channel/src/aptos_channel.rs (L85-112)
```rust
    pub fn push(&self, key: K, message: M) -> Result<()> {
        self.push_with_feedback(key, message, None)
    }

    /// Same as `push`, but this function also accepts a oneshot::Sender over which the sender can
    /// be notified when the message eventually gets delivered or dropped.
    pub fn push_with_feedback(
        &self,
        key: K,
        message: M,
        status_ch: Option<oneshot::Sender<ElementStatus<M>>>,
    ) -> Result<()> {
        let mut shared_state = self.shared_state.lock();
        ensure!(!shared_state.receiver_dropped, "Channel is closed");
        debug_assert!(shared_state.num_senders > 0);

        let dropped = shared_state.internal_queue.push(key, (message, status_ch));
        // If this or an existing message had to be dropped because of the queue being full, we
        // notify the corresponding status channel if it was registered.
        if let Some((dropped_val, Some(dropped_status_ch))) = dropped {
            // Ignore errors.
            let _err = dropped_status_ch.send(ElementStatus::Dropped(dropped_val));
        }
        if let Some(w) = shared_state.waker.take() {
            w.wake();
        }
        Ok(())
    }
```

**File:** crates/channel/src/aptos_channel.rs (L157-163)
```rust
impl<K: Eq + Hash + Clone, M> Drop for Receiver<K, M> {
    fn drop(&mut self) {
        let mut shared_state = self.shared_state.lock();
        debug_assert!(!shared_state.receiver_dropped);
        shared_state.receiver_dropped = true;
    }
}
```

**File:** state-sync/state-sync-driver/src/notification_handlers.rs (L106-112)
```rust
        // Notify the event subscription service of the events
        event_subscription_service
            .lock()
            .notify_events(latest_synced_version, events)?;

        Ok(())
    }
```

**File:** aptos-node/src/state_sync.rs (L91-115)
```rust
    // Create reconfiguration subscriptions for DKG
    let dkg_subscriptions = if node_config.base.role.is_validator() {
        let reconfig_events = event_subscription_service
            .subscribe_to_reconfigurations()
            .expect("DKG must subscribe to reconfigurations");
        let dkg_start_events = event_subscription_service
            .subscribe_to_events(vec![], vec!["0x1::dkg::DKGStartEvent".to_string()])
            .expect("Consensus must subscribe to DKG events");
        Some((reconfig_events, dkg_start_events))
    } else {
        None
    };

    // Create reconfiguration subscriptions for JWK consensus
    let jwk_consensus_subscriptions = if node_config.base.role.is_validator() {
        let reconfig_events = event_subscription_service
            .subscribe_to_reconfigurations()
            .expect("JWK consensus must subscribe to reconfigurations");
        let jwk_updated_events = event_subscription_service
            .subscribe_to_events(vec![], vec!["0x1::jwks::ObservedJWKsUpdated".to_string()])
            .expect("JWK consensus must subscribe to DKG events");
        Some((reconfig_events, jwk_updated_events))
    } else {
        None
    };
```
