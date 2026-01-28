# Audit Report

## Title
Memory Leak in Batch Store Subscribe Mechanism Leading to Unbounded Memory Growth

## Summary
The `subscribe()` function in the quorum store's batch store creates oneshot channels for batch persistence notifications but fails to clean up channel senders when batch requests fail. This causes unbounded memory accumulation in the `persist_subscribers` map that persists until epoch boundaries, leading to validator node performance degradation.

## Finding Description

The vulnerability exists in the batch subscription mechanism within the consensus quorum store implementation. When a validator node needs to fetch a batch that doesn't exist locally, the subscription mechanism creates a memory leak under failure conditions.

**The Vulnerable Flow:**

When `get_or_fetch_batch()` needs to fetch a batch from network peers, it calls `subscribe()` to create a oneshot channel for receiving the batch once persisted. [1](#0-0) 

The `subscribe()` function creates a oneshot channel pair and adds the sender to the `persist_subscribers` DashMap: [2](#0-1) 

**Cleanup Mechanisms (Incomplete):**

Subscribers are only cleaned up in two scenarios:

1. **Successful notification**: When a batch is successfully persisted, `notify_subscribers()` removes the entry from the map [3](#0-2) 

2. **Batch expiration**: When `clear_expired_payload()` processes expired batches that exist in cache [4](#0-3) 

**The Leak:**

When `request_batch()` fails (due to timeouts, network errors, or expired batches), the error propagates via the `await?` operator: [5](#0-4) 

This causes the subsequent `persist()` call to be skipped: [6](#0-5) 

Without the persist call, `notify_subscribers()` is never invoked (called at line 622 after successful persist), leaving the subscriber permanently in the map.

**Why clear_expired_payload() Doesn't Help:**

The expiration cleanup only processes batches that were added to cache via `insert_to_cache()`, which adds entries to the `expirations` structure. [7](#0-6) 

Failed batch fetches never reach cache insertion, so their subscribers are never cleaned up by this mechanism.

**Failure Scenarios in request_batch():**

The `request_batch()` function can fail in multiple ways:
- Timeout after exhausting retry limit [8](#0-7) 
- Expired batch responses [9](#0-8) 
- Network errors that eventually timeout [10](#0-9) 

All these paths return errors without any subscriber cleanup.

**Leak Persistence:**

The leak persists until epoch boundaries when new `BatchStore` instances are created with fresh `persist_subscribers` maps. [11](#0-10) 

This breaks the **Resource Limits** security invariant - consensus nodes should respect memory constraints, but leaked subscribers accumulate without bound within an epoch.

## Impact Explanation

**HIGH SEVERITY** - This qualifies as "Validator node slowdowns" per the Aptos bug bounty program.

The memory leak has cascading effects on validator node stability:

- Each leaked subscriber contains a `oneshot::Sender<PersistedValue<BatchInfoExt>>` stored in the DashMap [12](#0-11) 

- In high-throughput networks with frequent batch request failures (network issues, malicious peers), leaks accumulate for each unique batch digest that fails to fetch

- Memory pressure causes garbage collection overhead, increased memory consumption, and eventual validator performance degradation

- Severe cases can lead to out-of-memory conditions requiring validator restarts, impacting consensus liveness

- When multiple validators experience degraded performance simultaneously, it can affect overall network health

While epochs can last hours in production, allowing significant leak accumulation before the automatic cleanup at epoch boundaries.

## Likelihood Explanation

**HIGH LIKELIHOOD** - This vulnerability is triggered during normal consensus operation without requiring sophisticated attacks:

**Natural Triggers:**
- Network partitions or transient connectivity issues between validators cause batch request timeouts
- Slow or temporarily unavailable peers cause requests to exhaust retry limits
- Batch expiration scenarios when requesting older batches
- Normal Byzantine fault tolerance scenarios where some validators provide invalid responses

**Attack Amplification:**
- Malicious peers can deliberately send invalid batch responses or delay responses to maximize timeouts
- Attackers can propose blocks referencing non-existent batches to trigger fetch failures
- Network disruption techniques can increase the rate of batch fetch failures

The vulnerability occurs automatically whenever batch fetching fails, making it highly likely even in well-functioning networks. In degraded network conditions or under attack, the leak rate increases substantially.

## Recommendation

Add subscriber cleanup in the error path of `get_or_fetch_batch()`:

```rust
let fut = async move {
    let batch_digest = *batch_info.digest();
    defer!({
        inflight_requests_clone.lock().remove(&batch_digest);
    });
    
    if let Ok(mut value) = batch_store.get_batch_from_local(&batch_digest) {
        Ok(value.take_payload().expect("Must have payload"))
    } else {
        counters::MISSED_BATCHES_COUNT.inc();
        let subscriber_rx = batch_store.subscribe(*batch_info.digest());
        
        // FIX: Clean up subscriber on error
        let result = requester
            .request_batch(
                batch_digest,
                batch_info.expiration(),
                responders,
                subscriber_rx,
            )
            .await;
            
        match result {
            Ok(payload) => {
                batch_store.persist(vec![PersistedValue::new(
                    batch_info.into(),
                    Some(payload.clone()),
                )]);
                Ok(payload)
            },
            Err(e) => {
                // Clean up leaked subscriber
                batch_store.remove_subscriber(&batch_digest);
                Err(e)
            }
        }
    }
}
```

Add a public cleanup method to `BatchStore`:

```rust
pub(crate) fn remove_subscriber(&self, digest: &HashValue) {
    self.persist_subscribers.remove(digest);
}
```

## Proof of Concept

The following scenario demonstrates the leak:

1. Deploy a validator node and monitor its memory usage
2. Trigger batch fetch requests for non-existent or expired batches
3. Simulate network timeouts by blocking connections to peer validators
4. Observe that each failed fetch adds an entry to `persist_subscribers`
5. Monitor memory growth over time as failures accumulate
6. Verify that memory is only freed at epoch boundaries

The leak can be observed by:
- Adding logging to track `persist_subscribers.len()` 
- Monitoring validator process memory consumption
- Verifying cleanup only occurs at epoch transitions

This is reproducible in any network environment with intermittent connectivity issues or when requesting batches that peers don't have.

### Citations

**File:** consensus/src/quorum_store/batch_store.rs (L124-124)
```rust
    persist_subscribers: DashMap<HashValue, Vec<oneshot::Sender<PersistedValue<BatchInfoExt>>>>,
```

**File:** consensus/src/quorum_store/batch_store.rs (L129-154)
```rust
    pub(crate) fn new(
        epoch: u64,
        is_new_epoch: bool,
        last_certified_time: u64,
        db: Arc<dyn QuorumStoreStorage>,
        memory_quota: usize,
        db_quota: usize,
        batch_quota: usize,
        validator_signer: ValidatorSigner,
        expiration_buffer_usecs: u64,
    ) -> Self {
        let db_clone = db.clone();
        let batch_store = Self {
            epoch: OnceCell::with_value(epoch),
            last_certified_time: AtomicU64::new(last_certified_time),
            db_cache: DashMap::new(),
            peer_quota: DashMap::new(),
            expirations: Mutex::new(TimeExpirations::new()),
            db,
            memory_quota,
            db_quota,
            batch_quota,
            validator_signer,
            persist_subscribers: DashMap::new(),
            expiration_buffer_usecs,
        };
```

**File:** consensus/src/quorum_store/batch_store.rs (L448-448)
```rust
        let expired_digests = self.expirations.lock().expire(expiration_time);
```

**File:** consensus/src/quorum_store/batch_store.rs (L457-457)
```rust
                        self.persist_subscribers.remove(entry.get().digest());
```

**File:** consensus/src/quorum_store/batch_store.rs (L591-593)
```rust
    fn subscribe(&self, digest: HashValue) -> oneshot::Receiver<PersistedValue<BatchInfoExt>> {
        let (tx, rx) = oneshot::channel();
        self.persist_subscribers.entry(digest).or_default().push(tx);
```

**File:** consensus/src/quorum_store/batch_store.rs (L604-609)
```rust
    fn notify_subscribers(&self, value: PersistedValue<BatchInfoExt>) {
        if let Some((_, subscribers)) = self.persist_subscribers.remove(value.digest()) {
            for subscriber in subscribers {
                subscriber.send(value.clone()).ok();
            }
        }
```

**File:** consensus/src/quorum_store/batch_store.rs (L695-695)
```rust
                        let subscriber_rx = batch_store.subscribe(*batch_info.digest());
```

**File:** consensus/src/quorum_store/batch_store.rs (L696-703)
```rust
                        let payload = requester
                            .request_batch(
                                batch_digest,
                                batch_info.expiration(),
                                responders,
                                subscriber_rx,
                            )
                            .await?;
```

**File:** consensus/src/quorum_store/batch_store.rs (L704-707)
```rust
                        batch_store.persist(vec![PersistedValue::new(
                            batch_info.into(),
                            Some(payload.clone()),
                        )]);
```

**File:** consensus/src/quorum_store/batch_requester.rs (L148-150)
```rust
                                    counters::RECEIVED_BATCH_EXPIRED_COUNT.inc();
                                    debug!("QS: batch request expired, digest:{}", digest);
                                    return Err(ExecutorError::CouldNotGetData);
```

**File:** consensus/src/quorum_store/batch_requester.rs (L156-159)
```rust
                            Err(e) => {
                                counters::RECEIVED_BATCH_RESPONSE_ERROR_COUNT.inc();
                                debug!("QS: batch request error, digest:{}, error:{:?}", digest, e);
                            }
```

**File:** consensus/src/quorum_store/batch_requester.rs (L176-178)
```rust
            counters::RECEIVED_BATCH_REQUEST_TIMEOUT_COUNT.inc();
            debug!("QS: batch request timed out, digest:{}", digest);
            Err(ExecutorError::CouldNotGetData)
```
