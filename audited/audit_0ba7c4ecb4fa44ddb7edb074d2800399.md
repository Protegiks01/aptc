# Audit Report

## Title
Division by Zero Panic Leading to Indefinite Node Hang When Batch Responders Vector is Empty

## Summary
The `BatchRequester::next_request_peers()` function performs modulo operations without checking if the `signers` collection is empty, causing a division by zero panic when a batch has an empty responders vector. This panic aborts the spawned tokio task, causing the shared future to never complete and the consensus node to hang indefinitely while waiting for the batch.

## Finding Description

When `request_transactions()` is called with a batch that has an empty responders vector, it triggers a critical code path vulnerability in the batch fetching mechanism: [1](#0-0) 

The function calls `batch_reader.get_batch()` without validating that responders is non-empty. This call flows through: [2](#0-1) 

The batch fetcher spawns a tokio task (line 714) that calls `request_batch()`: [3](#0-2) 

Inside the request loop, `next_request_peers()` is called, which contains the vulnerable code: [4](#0-3) 

**The Critical Bug**: Lines 45 and 59 perform modulo operations with `signers.len()` as the divisor. When `signers` is empty, these operations cause a **division by zero panic** in Rust, aborting the tokio task.

When the spawned task panics:
1. The shared future returned by `get_or_fetch_batch()` never completes
2. The caller waiting on this future hangs indefinitely
3. Specifically, `request_and_wait_transactions()` uses `join_all()` to wait for all batch futures: [5](#0-4) 

Since `join_all()` waits for ALL futures to complete, a single non-completing future caused by the panic will cause the entire consensus node to hang indefinitely on that block.

**Invariant Broken**: This violates the **Consensus Liveness** invariant - the node cannot make forward progress and becomes unavailable for consensus participation.

## Impact Explanation

This vulnerability meets **Medium Severity** criteria under the Aptos bug bounty program:

- **Liveness Failure**: The consensus node hangs indefinitely when attempting to process a block containing a batch with empty responders, unable to participate in consensus or process subsequent blocks
- **Node Unavailability**: The affected node becomes unresponsive and requires manual intervention (restart) to recover
- **State Inconsistency Risk**: While hung, the node cannot process state updates, creating potential synchronization issues upon recovery

The impact is limited to Medium (rather than Critical) because:
- It affects individual nodes rather than the entire network
- It requires a specific condition (empty responders) which should be prevented by ProofOfStore verification under normal operation
- Recovery is possible via node restart

## Likelihood Explanation

**Likelihood: Low to Medium**

Under normal operation, this should not occur because:
- ProofOfStore verification requires quorum signatures (2f+1) before accepting blocks
- Empty signature bitmasks would fail verification: [6](#0-5) 

However, the likelihood increases due to:

1. **Lack of Defensive Programming**: The code assumes responders will never be empty but doesn't validate this assumption
2. **Potential Edge Cases**: Race conditions, verification bugs, or unusual network conditions could potentially trigger this
3. **Prefetch Timing**: Batch prefetching occurs during block insertion, creating potential race windows
4. **Code Complexity**: Multiple code paths construct responders vectors, increasing risk of edge cases

The question itself suggests this scenario is considered possible by the development team, warranting defensive measures.

## Recommendation

Add defensive checks to prevent division by zero when responders is empty:

```rust
fn next_request_peers(&mut self, num_peers: usize) -> Option<Vec<PeerId>> {
    let signers = self.signers.lock();
    
    // Defensive check: if no signers available, cannot request from anyone
    if signers.is_empty() {
        return None;
    }
    
    if self.num_retries == 0 {
        let mut rng = rand::thread_rng();
        self.next_index = rng.r#gen::<usize>() % signers.len();
        counters::SENT_BATCH_REQUEST_COUNT.inc_by(num_peers as u64);
    } else {
        counters::SENT_BATCH_REQUEST_RETRY_COUNT.inc_by(num_peers as u64);
    }
    
    if self.num_retries < self.retry_limit {
        self.num_retries += 1;
        let ret = signers
            .iter()
            .cycle()
            .skip(self.next_index)
            .take(num_peers)
            .cloned()
            .collect();
        self.next_index = (self.next_index + num_peers) % signers.len();
        Some(ret)
    } else {
        None
    }
}
```

Additionally, consider adding validation in `request_transactions()`:

```rust
fn request_transactions(
    batches: Vec<(BatchInfo, Vec<PeerId>)>,
    block_timestamp: u64,
    batch_reader: Arc<dyn BatchReader>,
) -> Vec<Shared<Pin<Box<dyn Future<Output = ExecutorResult<Vec<SignedTransaction>>> + Send>>>> {
    let mut futures = Vec::new();
    for (batch_info, responders) in batches {
        if responders.is_empty() {
            warn!("Empty responders for batch {:?}, skipping", batch_info);
            continue;
        }
        // ... rest of the logic
    }
    futures
}
```

## Proof of Concept

```rust
// Unit test demonstrating the panic
#[tokio::test]
#[should_panic(expected = "divide by zero")]
async fn test_empty_responders_causes_panic() {
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use aptos_infallible::Mutex;
    
    // Create empty responders set
    let empty_responders = Arc::new(Mutex::new(BTreeSet::new()));
    
    // Create BatchRequesterState with empty signers
    let mut state = BatchRequesterState::new(empty_responders, 3);
    
    // This will panic with division by zero
    state.next_request_peers(1);
}
```

The actual exploitation would require:
1. Constructing or receiving a block with a batch that has an empty responders vector
2. The block passing initial validation checks
3. `prefetch_payload_data()` or `get_transactions()` being called on the payload
4. The node attempting to fetch the batch with empty responders

When these conditions are met, the node will panic and hang indefinitely.

**Notes**

While ProofOfStore signature verification should prevent empty bitmasks under normal operation, the lack of defensive programming creates a fragile invariant assumption. The code should explicitly guard against this edge case rather than relying on upstream validation, especially given the severe impact (indefinite node hang) if the assumption is violated.

### Citations

**File:** consensus/src/payload_manager/quorum_store_payload_manager.rs (L89-109)
```rust
    fn request_transactions(
        batches: Vec<(BatchInfo, Vec<PeerId>)>,
        block_timestamp: u64,
        batch_reader: Arc<dyn BatchReader>,
    ) -> Vec<Shared<Pin<Box<dyn Future<Output = ExecutorResult<Vec<SignedTransaction>>> + Send>>>>
    {
        let mut futures = Vec::new();
        for (batch_info, responders) in batches {
            trace!(
                "QSE: requesting batch {:?}, time = {}",
                batch_info,
                block_timestamp
            );
            if block_timestamp <= batch_info.expiration() {
                futures.push(batch_reader.get_batch(batch_info, responders.clone()));
            } else {
                debug!("QSE: skipped expired batch {}", batch_info.digest());
            }
        }
        futures
    }
```

**File:** consensus/src/payload_manager/quorum_store_payload_manager.rs (L111-123)
```rust
    async fn request_and_wait_transactions(
        batches: Vec<(BatchInfo, Vec<PeerId>)>,
        block_timestamp: u64,
        batch_reader: Arc<dyn BatchReader>,
    ) -> ExecutorResult<Vec<SignedTransaction>> {
        let futures = Self::request_transactions(batches, block_timestamp, batch_reader);
        let mut all_txns = Vec::new();
        for result in futures::future::join_all(futures).await {
            all_txns.append(&mut result?);
        }
        Ok(all_txns)
    }
}
```

**File:** consensus/src/quorum_store/batch_store.rs (L663-723)
```rust
    fn get_or_fetch_batch(
        &self,
        batch_info: BatchInfo,
        responders: Vec<PeerId>,
    ) -> Shared<Pin<Box<dyn Future<Output = ExecutorResult<Vec<SignedTransaction>>> + Send>>> {
        let mut responders = responders.into_iter().collect();

        self.inflight_fetch_requests
            .lock()
            .entry(*batch_info.digest())
            .and_modify(|fetch_unit| {
                fetch_unit.responders.lock().append(&mut responders);
            })
            .or_insert_with(|| {
                let responders = Arc::new(Mutex::new(responders));
                let responders_clone = responders.clone();

                let inflight_requests_clone = self.inflight_fetch_requests.clone();
                let batch_store = self.batch_store.clone();
                let requester = self.batch_requester.clone();

                let fut = async move {
                    let batch_digest = *batch_info.digest();
                    defer!({
                        inflight_requests_clone.lock().remove(&batch_digest);
                    });
                    // TODO(ibalajiarun): Support V2 batch
                    if let Ok(mut value) = batch_store.get_batch_from_local(&batch_digest) {
                        Ok(value.take_payload().expect("Must have payload"))
                    } else {
                        // Quorum store metrics
                        counters::MISSED_BATCHES_COUNT.inc();
                        let subscriber_rx = batch_store.subscribe(*batch_info.digest());
                        let payload = requester
                            .request_batch(
                                batch_digest,
                                batch_info.expiration(),
                                responders,
                                subscriber_rx,
                            )
                            .await?;
                        batch_store.persist(vec![PersistedValue::new(
                            batch_info.into(),
                            Some(payload.clone()),
                        )]);
                        Ok(payload)
                    }
                }
                .boxed()
                .shared();

                tokio::spawn(fut.clone());

                BatchFetchUnit {
                    responders: responders_clone,
                    fut,
                }
            })
            .fut
            .clone()
    }
```

**File:** consensus/src/quorum_store/batch_requester.rs (L40-64)
```rust
    fn next_request_peers(&mut self, num_peers: usize) -> Option<Vec<PeerId>> {
        let signers = self.signers.lock();
        if self.num_retries == 0 {
            let mut rng = rand::thread_rng();
            // make sure nodes request from the different set of nodes
            self.next_index = rng.r#gen::<usize>() % signers.len();
            counters::SENT_BATCH_REQUEST_COUNT.inc_by(num_peers as u64);
        } else {
            counters::SENT_BATCH_REQUEST_RETRY_COUNT.inc_by(num_peers as u64);
        }
        if self.num_retries < self.retry_limit {
            self.num_retries += 1;
            let ret = signers
                .iter()
                .cycle()
                .skip(self.next_index)
                .take(num_peers)
                .cloned()
                .collect();
            self.next_index = (self.next_index + num_peers) % signers.len();
            Some(ret)
        } else {
            None
        }
    }
```

**File:** consensus/src/quorum_store/batch_requester.rs (L101-180)
```rust
    pub(crate) async fn request_batch(
        &self,
        digest: HashValue,
        expiration: u64,
        responders: Arc<Mutex<BTreeSet<PeerId>>>,
        mut subscriber_rx: oneshot::Receiver<PersistedValue<BatchInfoExt>>,
    ) -> ExecutorResult<Vec<SignedTransaction>> {
        let validator_verifier = self.validator_verifier.clone();
        let mut request_state = BatchRequesterState::new(responders, self.retry_limit);
        let network_sender = self.network_sender.clone();
        let request_num_peers = self.request_num_peers;
        let my_peer_id = self.my_peer_id;
        let epoch = self.epoch;
        let retry_interval = Duration::from_millis(self.retry_interval_ms as u64);
        let rpc_timeout = Duration::from_millis(self.rpc_timeout_ms as u64);

        monitor!("batch_request", {
            let mut interval = time::interval(retry_interval);
            let mut futures = FuturesUnordered::new();
            let request = BatchRequest::new(my_peer_id, epoch, digest);
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // send batch request to a set of peers of size request_num_peers
                        if let Some(request_peers) = request_state.next_request_peers(request_num_peers) {
                            for peer in request_peers {
                                futures.push(network_sender.request_batch(request.clone(), peer, rpc_timeout));
                            }
                        } else if futures.is_empty() {
                            // end the loop when the futures are drained
                            break;
                        }
                    },
                    Some(response) = futures.next() => {
                        match response {
                            Ok(BatchResponse::Batch(batch)) => {
                                counters::RECEIVED_BATCH_RESPONSE_COUNT.inc();
                                let payload = batch.into_transactions();
                                return Ok(payload);
                            }
                            // Short-circuit if the chain has moved beyond expiration
                            Ok(BatchResponse::NotFound(ledger_info)) => {
                                counters::RECEIVED_BATCH_NOT_FOUND_COUNT.inc();
                                if ledger_info.commit_info().epoch() == epoch
                                    && ledger_info.commit_info().timestamp_usecs() > expiration
                                    && ledger_info.verify_signatures(&validator_verifier).is_ok()
                                {
                                    counters::RECEIVED_BATCH_EXPIRED_COUNT.inc();
                                    debug!("QS: batch request expired, digest:{}", digest);
                                    return Err(ExecutorError::CouldNotGetData);
                                }
                            }
                            Ok(BatchResponse::BatchV2(_)) => {
                                error!("Batch V2 response is not supported");
                            }
                            Err(e) => {
                                counters::RECEIVED_BATCH_RESPONSE_ERROR_COUNT.inc();
                                debug!("QS: batch request error, digest:{}, error:{:?}", digest, e);
                            }
                        }
                    },
                    result = &mut subscriber_rx => {
                        match result {
                            Ok(persisted_value) => {
                                counters::RECEIVED_BATCH_FROM_SUBSCRIPTION_COUNT.inc();
                                let (_, maybe_payload) = persisted_value.unpack();
                                return Ok(maybe_payload.expect("persisted value must exist"));
                            }
                            Err(err) => {
                                debug!("channel closed: {}", err);
                            }
                        };
                    },
                }
            }
            counters::RECEIVED_BATCH_REQUEST_TIMEOUT_COUNT.inc();
            debug!("QS: batch request timed out, digest:{}", digest);
            Err(ExecutorError::CouldNotGetData)
        })
    }
```

**File:** types/src/validator_verifier.rs (L405-416)
```rust
        // Verify the quorum voting power of the authors
        self.check_voting_power(authors.iter(), true)?;
        // Verify empty aggregated signature
        let aggregated_sig = aggregated_signature
            .sig()
            .as_ref()
            .ok_or(VerifyError::EmptySignature)?;

        aggregated_sig
            .verify_aggregate(messages, &pub_keys)
            .map_err(|_| VerifyError::InvalidAggregatedSignature)?;
        Ok(())
```
