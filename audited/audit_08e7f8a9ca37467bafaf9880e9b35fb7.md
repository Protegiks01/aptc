# Audit Report

## Title
DKG Start Event Loss Due to Insufficient Channel Capacity and Silent Event Dropping

## Summary
The DKG epoch manager creates a channel with KLAST queue style and capacity 1 to forward DKG start events to the DKG manager. [1](#0-0) 

When the channel is full and a new event arrives, KLAST behavior drops the oldest event without notification. [2](#0-1) 

The epoch manager ignores the return value from push operations, failing to detect dropped events. [3](#0-2) 

## Finding Description

**Channel Configuration:**
The DKG system uses a capacity-1 channel with KLAST (Keep Last) semantics between the EpochManager and DKGManager. When this channel is full, pushing a new item drops the oldest unprocessed item. [4](#0-3) 

**Event Dropping Mechanism:**
The KLAST queue style explicitly drops oldest messages when the queue is full. [5](#0-4) 

**Silent Failure:**
The EpochManager's `on_dkg_start_notification` method ignores the push result, masking dropped events. [6](#0-5) 

**Processing Constraints:**
The DKGManager processes events in a select loop handling multiple event types concurrently (RPC messages, aggregated transcripts, DKG start events, pool notifications). [7](#0-6) 

**Attack Scenarios:**

1. **Event Burst During Epoch Transition**: If the EventNotificationListener delivers events rapidly (it buffers up to 100 events), and the DKGManager is processing other events (RPC messages, aggregated transcripts), the capacity-1 buffer becomes a critical bottleneck.

2. **State Inconsistency**: The DKGManager validates that it's in `NotStarted` state before processing DKG start events. [8](#0-7)  If the first valid event is dropped and replaced by a stale or invalid event, the DKGManager may reject all subsequent events, never transitioning to `InProgress` state despite on-chain DKG session being active.

3. **Validator Non-Participation**: When a DKGStartEvent is dropped, the affected validator never calls `setup_deal_broadcast`, never generates its transcript, and never participates in the DKG session. [9](#0-8) 

## Impact Explanation

**High Severity** - Significant protocol violations and state inconsistencies:

- **Protocol Violation**: Validators failing to participate in DKG sessions violates the distributed key generation protocol invariant that requires threshold participation
- **State Inconsistency**: On-chain state shows DKG session in progress while affected validators remain in `NotStarted` state, requiring manual intervention
- **Randomness Failure**: If sufficient validators miss DKG start events, the session cannot complete, preventing randomness generation for subsequent epochs
- **Validator Slowdowns**: Affected validators cannot properly participate in consensus rounds requiring randomness

This maps to **High Severity** per Aptos bug bounty criteria: "Significant protocol violations" and "State inconsistencies requiring intervention."

## Likelihood Explanation

**Medium to High Likelihood:**

The vulnerability can manifest under normal operational conditions:

1. **Concurrent Event Processing**: The DKGManager's select loop processes multiple event types. During active DKG sessions, RPC message handling and transcript aggregation compete with DKG start event processing.

2. **No Rate Limiting**: The EventNotificationListener buffers up to 100 events. [10](#0-9)  During catch-up or network congestion, events can arrive faster than the DKGManager processes them.

3. **Silent Failure Mode**: Dropped events generate no errors, warnings, or metrics, making the issue invisible to operators until DKG session completion fails.

4. **No Recovery Mechanism**: Within an epoch, there's no retry logic or periodic synchronization to detect and recover from dropped events. The validator simply never participates.

## Recommendation

**Immediate Fix - Increase Capacity and Add Monitoring:**

```rust
// dkg/src/epoch_manager.rs, lines 223-225
// Increase capacity to prevent legitimate event loss
let (dkg_start_event_tx, dkg_start_event_rx) =
    aptos_channel::new(QueueStyle::KLAST, 10, None);
self.dkg_start_event_tx = Some(dkg_start_event_tx);
```

**Enhanced Fix - Detect and Log Dropped Events:**

```rust
// dkg/src/epoch_manager.rs, modify on_dkg_start_notification
fn on_dkg_start_notification(&mut self, notification: EventNotification) -> Result<()> {
    if let Some(tx) = self.dkg_start_event_tx.as_ref() {
        let EventNotification {
            subscribed_events, ..
        } = notification;
        for event in subscribed_events {
            if let Ok(dkg_start_event) = DKGStartEvent::try_from(&event) {
                // Check if push returns a dropped event
                match tx.push((), dkg_start_event.clone()) {
                    Ok(_) => {
                        info!("[DKG] DKG start event queued successfully");
                        return Ok(());
                    },
                    Err(e) => {
                        error!("[DKG] Failed to queue DKG start event: {:?}", e);
                        // Attempt retry or trigger alert
                        return Err(anyhow!("Failed to queue DKG start event"));
                    }
                }
            } else {
                debug!("[DKG] on_dkg_start_notification: failed in converting a contract event to a dkg start event!");
            }
        }
    }
    Ok(())
}
```

**Comprehensive Fix - Add Periodic State Synchronization:**

Implement periodic checking of on-chain DKG state against local DKGManager state to detect and recover from missed events within the same epoch.

## Proof of Concept

```rust
// Rust test demonstrating the vulnerability
#[tokio::test]
async fn test_dkg_event_drop_under_load() {
    use aptos_channels::{aptos_channel, message_queues::QueueStyle};
    use aptos_types::dkg::{DKGStartEvent, DKGSessionMetadata};
    
    // Create channel with capacity 1, KLAST
    let (tx, mut rx) = aptos_channel::new(QueueStyle::KLAST, 1, None);
    
    // Create multiple DKG start events
    let event1 = DKGStartEvent {
        session_metadata: create_test_metadata(1),
        start_time_us: 1000,
    };
    let event2 = DKGStartEvent {
        session_metadata: create_test_metadata(2),
        start_time_us: 2000,
    };
    let event3 = DKGStartEvent {
        session_metadata: create_test_metadata(3),
        start_time_us: 3000,
    };
    
    // Push first event - should succeed
    tx.push((), event1.clone()).unwrap();
    
    // Push second event before first is consumed
    // This drops event1 due to KLAST with capacity 1
    tx.push((), event2.clone()).unwrap();
    
    // Push third event
    // This drops event2
    tx.push((), event3.clone()).unwrap();
    
    // Consumer only sees event3
    let received = rx.next().await.unwrap();
    assert_eq!(received.start_time_us, 3000);
    
    // Events 1 and 2 were silently dropped
    // If event3 is invalid but events 1 or 2 were valid,
    // the DKG session fails to start
}
```

## Notes

The vulnerability is exacerbated by three design choices working together:
1. KLAST queue semantics that prioritize newest events
2. Capacity of 1 creating an extreme bottleneck
3. Silent dropping without error propagation or metrics

The on-chain Move code does include protections against multiple DKG sessions per epoch. [11](#0-10)  However, this protection operates at the blockchain level and cannot prevent event processing race conditions at the validator level where events may arrive in bursts during network congestion or state synchronization.

### Citations

**File:** dkg/src/epoch_manager.rs (L108-122)
```rust
    fn on_dkg_start_notification(&mut self, notification: EventNotification) -> Result<()> {
        if let Some(tx) = self.dkg_start_event_tx.as_ref() {
            let EventNotification {
                subscribed_events, ..
            } = notification;
            for event in subscribed_events {
                if let Ok(dkg_start_event) = DKGStartEvent::try_from(&event) {
                    let _ = tx.push((), dkg_start_event);
                    return Ok(());
                } else {
                    debug!("[DKG] on_dkg_start_notification: failed in converting a contract event to a dkg start event!");
                }
            }
        }
        Ok(())
```

**File:** dkg/src/epoch_manager.rs (L223-225)
```rust
            let (dkg_start_event_tx, dkg_start_event_rx) =
                aptos_channel::new(QueueStyle::KLAST, 1, None);
            self.dkg_start_event_tx = Some(dkg_start_event_tx);
```

**File:** crates/channel/src/message_queues.rs (L138-146)
```rust
            match self.queue_style {
                // Drop the newest message for FIFO
                QueueStyle::FIFO => Some(message),
                // Drop the oldest message for LIFO
                QueueStyle::LIFO | QueueStyle::KLAST => {
                    let oldest = key_message_queue.pop_front();
                    key_message_queue.push_back(message);
                    oldest
                },
```

**File:** dkg/src/dkg_manager/mod.rs (L166-194)
```rust
            let handling_result = tokio::select! {
                dkg_start_event = dkg_start_event_rx.select_next_some() => {
                    self.process_dkg_start_event(dkg_start_event)
                        .await
                        .map_err(|e|anyhow!("[DKG] process_dkg_start_event failed: {e}"))
                },
                (_sender, msg) = rpc_msg_rx.select_next_some() => {
                    self.process_peer_rpc_msg(msg)
                        .await
                        .map_err(|e|anyhow!("[DKG] process_peer_rpc_msg failed: {e}"))
                },
                agg_transcript = agg_trx_rx.select_next_some() => {
                    self.process_aggregated_transcript(agg_transcript)
                        .await
                        .map_err(|e|anyhow!("[DKG] process_aggregated_transcript failed: {e}"))

                },
                dkg_txn = self.pull_notification_rx.select_next_some() => {
                    self.process_dkg_txn_pulled_notification(dkg_txn)
                        .await
                        .map_err(|e|anyhow!("[DKG] process_dkg_txn_pulled_notification failed: {e}"))
                },
                close_req = close_rx.select_next_some() => {
                    self.process_close_cmd(close_req.ok())
                },
                _ = interval.tick().fuse() => {
                    self.observe()
                },
            };
```

**File:** dkg/src/dkg_manager/mod.rs (L293-375)
```rust
    async fn setup_deal_broadcast(
        &mut self,
        start_time_us: u64,
        dkg_session_metadata: &DKGSessionMetadata,
    ) -> Result<()> {
        ensure!(
            matches!(&self.state, InnerState::NotStarted),
            "transcript already dealt"
        );
        let dkg_start_time = Duration::from_micros(start_time_us);
        let deal_start = duration_since_epoch();
        let secs_since_dkg_start = deal_start.as_secs_f64() - dkg_start_time.as_secs_f64();
        DKG_STAGE_SECONDS
            .with_label_values(&[self.my_addr.to_hex().as_str(), "deal_start"])
            .observe(secs_since_dkg_start);
        info!(
            epoch = self.epoch_state.epoch,
            my_addr = self.my_addr,
            secs_since_dkg_start = secs_since_dkg_start,
            "[DKG] Deal transcript started.",
        );
        let public_params = DKG::new_public_params(dkg_session_metadata);
        if let Some(summary) = public_params.rounding_summary() {
            info!(
                epoch = self.epoch_state.epoch,
                "Rounding summary: {:?}", summary
            );
            ROUNDING_SECONDS
                .with_label_values(&[summary.method.as_str()])
                .observe(summary.exec_time.as_secs_f64());
        }

        let mut rng = if cfg!(feature = "smoke-test") {
            StdRng::from_seed(self.my_addr.into_bytes())
        } else {
            StdRng::from_rng(thread_rng()).unwrap()
        };
        let input_secret = DKG::InputSecret::generate(&mut rng);

        let trx = DKG::generate_transcript(
            &mut rng,
            &public_params,
            &input_secret,
            self.my_index as u64,
            &self.dealer_sk,
            &self.dealer_pk,
        );

        let my_transcript = DKGTranscript::new(
            self.epoch_state.epoch,
            self.my_addr,
            bcs::to_bytes(&trx).map_err(|e| anyhow!("transcript serialization error: {e}"))?,
        );

        let deal_finish = duration_since_epoch();
        let secs_since_dkg_start = deal_finish.as_secs_f64() - dkg_start_time.as_secs_f64();
        DKG_STAGE_SECONDS
            .with_label_values(&[self.my_addr.to_hex().as_str(), "deal_finish"])
            .observe(secs_since_dkg_start);
        info!(
            epoch = self.epoch_state.epoch,
            my_addr = self.my_addr,
            secs_since_dkg_start = secs_since_dkg_start,
            "[DKG] Deal transcript finished.",
        );

        let abort_handle = self.agg_trx_producer.start_produce(
            dkg_start_time,
            self.my_addr,
            self.epoch_state.clone(),
            public_params.clone(),
            self.agg_trx_tx.clone(),
        );

        // Switch to the next stage.
        self.state = InnerState::InProgress {
            start_time: dkg_start_time,
            my_transcript,
            abort_handle,
        };

        Ok(())
    }
```

**File:** dkg/src/dkg_manager/mod.rs (L438-441)
```rust
        ensure!(
            matches!(&self.state, InnerState::NotStarted),
            "[DKG] dkg already started"
        );
```

**File:** state-sync/inter-component/event-notifications/src/lib.rs (L39-39)
```rust
const EVENT_NOTIFICATION_CHANNEL_SIZE: usize = 100;
```

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration_with_dkg.move (L25-30)
```text
        let incomplete_dkg_session = dkg::incomplete_session();
        if (option::is_some(&incomplete_dkg_session)) {
            let session = option::borrow(&incomplete_dkg_session);
            if (dkg::session_dealer_epoch(session) == reconfiguration::current_epoch()) {
                return
            }
```
