# Audit Report

## Title
Batch Payload Validation Bypass Allows Consensus Safety Violation Through Malicious Batch Injection

## Summary
The Quorum Store batch retrieval mechanism fails to validate that fetched batch payloads match their certified digests before persistence. A malicious peer can respond to batch requests with arbitrary transaction payloads that differ from the digest certified by the quorum, leading to different nodes executing different transactions for the same batch digest and causing consensus safety violations.

## Finding Description

The vulnerability exists in the batch fetching and persistence flow in the Quorum Store consensus component. When a validator needs to fetch a batch it doesn't have locally, the `get_or_fetch_batch()` function calls `request_batch()` to retrieve it from peers. [1](#0-0) 

The critical flaw occurs in the batch response processing. When a `BatchResponse::Batch` is received, the code immediately extracts the payload without any validation: [2](#0-1) 

This unvalidated payload is then persisted with the original `batch_info` (containing the certified digest from the block proposal): [3](#0-2) 

The `Batch` struct includes validation methods specifically designed to prevent this attack - `verify()` and `verify_with_digest()` that check if the payload hash matches the digest: [4](#0-3) 

However, these validation methods are **never called** in the batch fetching path. The test suite confirms these methods should be used to validate batches against requested digests: [5](#0-4) 

**Attack Flow:**

1. A block proposal contains a certified `BatchInfo` with digest X (already signed by quorum)
2. An honest validator needs to fetch the batch but doesn't have it locally
3. A malicious peer responds with `BatchResponse::Batch(malicious_batch)` where the payload hash ≠ X
4. The honest validator accepts the malicious payload without checking if `hash(payload) == X`
5. The malicious payload is persisted and associated with digest X
6. The honest validator executes the malicious payload instead of the legitimate batch
7. Different validators may execute different payloads for the same digest, causing consensus divergence

The vulnerability breaks deterministic execution - the core invariant that all validators produce identical state roots for identical blocks is violated, resulting in consensus safety violations.

## Impact Explanation

**Severity: CRITICAL** (up to $1,000,000)

This vulnerability directly causes **Consensus/Safety violations**, a critical severity issue per the Aptos bug bounty program. Specifically:

1. **Consensus Split**: Different validators will execute different transactions for blocks containing the compromised batch, leading to different state roots and chain splits
2. **Non-Deterministic Execution**: The certified digest in the block no longer corresponds to the actual executed transactions
3. **State Divergence**: Once validators have different states, the network cannot proceed without manual intervention or a hard fork
4. **Ledger Integrity Compromise**: The blockchain's fundamental guarantee of deterministic execution is violated

The impact is catastrophic because:
- Only a single malicious peer is needed (not a validator majority)
- The certified digest provides false security - nodes believe they're executing the correct batch
- The malicious payload propagates to other nodes through the batch store persistence
- Recovery requires identifying all affected nodes and potentially rolling back state

## Likelihood Explanation

**Likelihood: HIGH**

The attack is highly likely to succeed because:

1. **Common Scenario**: Batch fetching occurs regularly when nodes are catching up, experiencing network delays, or during state synchronization
2. **Low Attacker Requirements**: Any malicious peer can respond to batch requests - doesn't require validator keys or stake
3. **No Defense Mechanisms**: No validation exists in the current code path
4. **Race Condition Favorable**: If the malicious peer responds before honest peers, it wins
5. **Silent Failure**: The attack succeeds silently without triggering errors or alerts

The attack complexity is LOW - the malicious peer simply needs to:
- Monitor or respond to `BatchRequest` messages
- Return a `BatchResponse::Batch` with modified payload
- The digest validation that should prevent this is completely absent

## Recommendation

Add digest validation immediately after receiving batch responses. The fix should call `verify_with_digest()` before accepting the payload:

```rust
// In consensus/src/quorum_store/batch_requester.rs
Ok(BatchResponse::Batch(batch)) => {
    counters::RECEIVED_BATCH_RESPONSE_COUNT.inc();
    // Add validation before accepting the batch
    batch.verify_with_digest(digest)?;
    let payload = batch.into_transactions();
    return Ok(payload);
}
```

This ensures that fetched batch payloads always match the requested digest before persistence and execution.

## Proof of Concept

A malicious peer can construct a `Batch` object with:
- A `batch_info` containing the requested digest
- A `payload` containing different transactions

When the honest node calls `batch.into_transactions()`, it receives the wrong transactions without validation. The `verify_with_digest()` method that should prevent this is never invoked in the critical path shown at: [6](#0-5) 

The unvalidated payload propagates through the system as shown in the persistence flow: [7](#0-6) 

This allows different validators to execute different transaction sets for the same certified batch digest, violating consensus safety.

### Citations

**File:** consensus/src/quorum_store/batch_store.rs (L684-710)
```rust
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
```

**File:** consensus/src/quorum_store/batch_requester.rs (L134-160)
```rust
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
```

**File:** consensus/src/quorum_store/types.rs (L262-300)
```rust
    pub fn verify(&self) -> anyhow::Result<()> {
        ensure!(
            self.payload.author() == self.author(),
            "Payload author doesn't match the info"
        );
        ensure!(
            self.payload.hash() == *self.digest(),
            "Payload hash doesn't match the digest"
        );
        ensure!(
            self.payload.num_txns() as u64 == self.num_txns(),
            "Payload num txns doesn't match batch info"
        );
        ensure!(
            self.payload.num_bytes() as u64 == self.num_bytes(),
            "Payload num bytes doesn't match batch info"
        );
        for txn in self.payload.txns() {
            ensure!(
                txn.gas_unit_price() >= self.gas_bucket_start(),
                "Payload gas unit price doesn't match batch info"
            );
            ensure!(
                !txn.payload().is_encrypted_variant(),
                "Encrypted transaction is not supported yet"
            );
        }
        Ok(())
    }

    /// Verify the batch, and that it matches the requested digest
    pub fn verify_with_digest(&self, requested_digest: HashValue) -> anyhow::Result<()> {
        ensure!(
            requested_digest == *self.digest(),
            "Response digest doesn't match the request"
        );
        self.verify()?;
        Ok(())
    }
```

**File:** consensus/src/quorum_store/tests/types_test.rs (L36-39)
```rust
    assert_ok!(batch.verify());
    assert_ok!(batch.verify_with_digest(digest));
    // verify should fail if the digest does not match.
    assert_err!(batch.verify_with_digest(HashValue::random()));
```
