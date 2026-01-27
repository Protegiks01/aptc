# Audit Report

## Title
Selective Batch Withholding Attack Causes Consensus Delays Without Byzantine Detection

## Summary
Malicious validators can selectively withhold signed batches, causing consensus delays by forcing batch retrieval timeouts and indefinite retry loops in block materialization, without triggering any Byzantine detection mechanisms.

## Finding Description

The Aptos quorum store consensus mechanism allows validators to sign batches (via `SignedBatchInfo`) indicating they possess and can serve batch data. However, after signing, validators can delete batches or selectively refuse to serve them when requested. When batch retrieval fails, the block materialization pipeline enters an infinite retry loop, causing significant consensus delays.

**Attack Flow:**

1. A malicious validator receives a batch from another validator and processes it through the batch coordinator [1](#0-0) 

2. The batch is persisted to the local store and signed [2](#0-1) 

3. The signature is sent back to the batch author, who includes it in the `ProofOfStore` aggregate signature [3](#0-2) 

4. The malicious validator then deletes the batch or modifies their node to return `NotFound` responses

5. When other validators need to execute a block containing this batch, they extract the signer list and request the batch [4](#0-3) 

6. The batch requester queries signers, receives `NotFound` responses from malicious validators [5](#0-4) 

7. The system only increments `RECEIVED_BATCH_NOT_FOUND_COUNT` counter with no Byzantine detection or penalties [6](#0-5) 

8. After exhausting retries (10 attempts × 500ms intervals with 5 peers per attempt), the request times out [7](#0-6) 

9. The `materialize_block` function fails and enters an infinite retry loop with 100ms delays [8](#0-7) 

**Critical Gap:** The system treats `NotFound` responses as legitimate when accompanied by valid `LedgerInfoWithSignatures`, assuming honest storage failures rather than malicious withholding. There is no mechanism to distinguish between honest node failures and deliberate batch withholding.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program as it causes "Validator node slowdowns."

**Quantified Impact:**
- Each batch retrieval attempt takes ~5+ seconds (10 retries × 500ms + RPC timeouts of 5000ms) [9](#0-8) 
- Failed retrievals trigger indefinite retry loops with 100ms delays between attempts
- Multiple concurrent blocks requiring missing batches compound the delays
- Validators cannot make consensus progress on affected blocks
- No Byzantine detection or reputation tracking exists to identify or penalize malicious validators

The attack breaks the **Consensus Liveness** invariant: while safety is preserved (no chain splits), the system experiences significant degradation in block production rate and transaction throughput.

## Likelihood Explanation

**Likelihood: Medium to High**

The attack is practical because:
- Validators have complete control over their node software and can modify batch serving logic
- After signing batches, validators can delete them without detection
- The `request_num_peers` parameter (default: 5) means attackers don't need to control all signers
- Selective withholding can appear as intermittent storage failures, avoiding suspicion
- No reputation system exists to identify validators with high `NotFound` response rates

**Attack Requirements:**
- Control of validator node(s) that participate in batch signing
- Less than 1/3 of total validator stake (to stay within Byzantine tolerance)
- Ability to modify node code to selectively withhold batches

## Recommendation

Implement Byzantine detection and mitigation for batch withholding:

1. **Reputation Tracking**: Track per-validator `NotFound` response rates
```rust
struct ValidatorReputation {
    not_found_responses: u64,
    total_requests: u64,
    last_reset: Instant,
}
```

2. **Penalties**: When a validator's `NotFound` rate exceeds a threshold, deprioritize them in signer shuffling and consider excluding them from batch request peers

3. **Verification**: Before including a validator's signature in `ProofOfStore`, optionally verify they can serve the batch with a challenge-response

4. **Timeout Limits**: Add a maximum retry duration to the `materialize` loop to prevent indefinite blocking:
```rust
let start = Instant::now();
let max_retry_duration = Duration::from_secs(30);
let result = loop {
    if start.elapsed() > max_retry_duration {
        return Err(TaskError::InternalError("Batch retrieval timeout exceeded".into()));
    }
    // ... existing retry logic
};
```

5. **Alert Mechanisms**: Emit warnings when `RECEIVED_BATCH_NOT_FOUND_COUNT` exceeds thresholds for specific validators

## Proof of Concept

**Simulation Steps:**

1. Deploy a modified validator node that signs batches normally but:
```rust
// In quorum_store_builder.rs batch serving logic
let response = if malicious_mode && should_withhold(digest) {
    // Pretend batch doesn't exist
    match aptos_db_clone.get_latest_ledger_info() {
        Ok(ledger_info) => BatchResponse::NotFound(ledger_info),
        Err(e) => continue,
    }
} else if let Ok(value) = batch_store.get_batch_from_local(&rpc_request.req.digest()) {
    // Normal serving logic
    BatchResponse::Batch(value.try_into().unwrap())
} else {
    // Legitimately not found
    match aptos_db_clone.get_latest_ledger_info() {
        Ok(ledger_info) => BatchResponse::NotFound(ledger_info),
        Err(e) => continue,
    }
};
```

2. Configure the malicious validator to withhold 30% of batches randomly

3. Monitor consensus metrics:
   - `RECEIVED_BATCH_NOT_FOUND_COUNT` increases significantly
   - `RECEIVED_BATCH_REQUEST_TIMEOUT_COUNT` increases
   - Block production time increases measurably
   - Log warnings show repeated "failed to prepare block, retrying" messages

4. Verify no Byzantine detection triggers or penalties are applied to the malicious validator

5. Measure average block latency increase (expected: 5-10+ seconds per affected block)

## Notes

This vulnerability exploits the trust assumption that validators who sign batches will honestly serve them. The system lacks defense-in-depth against Byzantine behavior that manifests as storage failures rather than cryptographic violations (equivocation, invalid signatures). While the attack requires validator-level access, it represents a gap in Byzantine fault tolerance that should be addressed, as BFT consensus systems are designed to handle < 1/3 malicious validators through detection and mitigation mechanisms, not just cryptographic proofs.

### Citations

**File:** consensus/src/quorum_store/batch_coordinator.rs (L173-244)
```rust
    pub(crate) async fn handle_batches_msg(
        &mut self,
        author: PeerId,
        batches: Vec<Batch<BatchInfoExt>>,
    ) {
        if let Err(e) = self.ensure_max_limits(&batches) {
            error!("Batch from {}: {}", author, e);
            counters::RECEIVED_BATCH_MAX_LIMIT_FAILED.inc();
            return;
        }

        let Some(batch) = batches.first() else {
            error!("Empty batch received from {}", author.short_str().as_str());
            return;
        };

        // Filter the transactions in the batches. If any transaction is rejected,
        // the message will be dropped, and all batches will be rejected.
        if self.transaction_filter_config.is_enabled() {
            let transaction_filter = &self.transaction_filter_config.batch_transaction_filter();
            for batch in batches.iter() {
                for transaction in batch.txns() {
                    if !transaction_filter.allows_transaction(
                        batch.batch_info().batch_id(),
                        batch.author(),
                        batch.digest(),
                        transaction,
                    ) {
                        error!(
                            "Transaction {}, in batch {}, from {}, was rejected by the filter. Dropping {} batches!",
                            transaction.committed_hash(),
                            batch.batch_info().batch_id(),
                            author.short_str().as_str(),
                            batches.len()
                        );
                        counters::RECEIVED_BATCH_REJECTED_BY_FILTER.inc();
                        return;
                    }
                }
            }
        }

        let approx_created_ts_usecs = batch
            .info()
            .expiration()
            .saturating_sub(self.batch_expiry_gap_when_init_usecs);

        if approx_created_ts_usecs > 0 {
            observe_batch(
                approx_created_ts_usecs,
                batch.author(),
                BatchStage::RECEIVED,
            );
        }

        let mut persist_requests = vec![];
        for batch in batches.into_iter() {
            // TODO: maybe don't message batch generator if the persist is unsuccessful?
            if let Err(e) = self
                .sender_to_batch_generator
                .send(BatchGeneratorCommand::RemoteBatch(batch.clone()))
                .await
            {
                warn!("Failed to send batch to batch generator: {}", e);
            }
            persist_requests.push(batch.into());
        }
        counters::RECEIVED_BATCH_COUNT.inc_by(persist_requests.len() as u64);
        if author != self.my_peer_id {
            counters::RECEIVED_REMOTE_BATCH_COUNT.inc_by(persist_requests.len() as u64);
        }
        self.persist_and_send_digests(persist_requests, approx_created_ts_usecs);
```

**File:** consensus/src/quorum_store/batch_store.rs (L488-528)
```rust
    fn persist_inner(
        &self,
        batch_info: BatchInfoExt,
        persist_request: PersistedValue<BatchInfoExt>,
    ) -> Option<SignedBatchInfo<BatchInfoExt>> {
        assert!(
            &batch_info == persist_request.batch_info(),
            "Provided batch info doesn't match persist request batch info"
        );
        match self.save(&persist_request) {
            Ok(needs_db) => {
                trace!("QS: sign digest {}", persist_request.digest());
                if needs_db {
                    if !batch_info.is_v2() {
                        let persist_request =
                            persist_request.try_into().expect("Must be a V1 batch");
                        #[allow(clippy::unwrap_in_result)]
                        self.db
                            .save_batch(persist_request)
                            .expect("Could not write to DB");
                    } else {
                        #[allow(clippy::unwrap_in_result)]
                        self.db
                            .save_batch_v2(persist_request)
                            .expect("Could not write to DB")
                    }
                }
                if !batch_info.is_v2() {
                    self.generate_signed_batch_info(batch_info.info().clone())
                        .ok()
                        .map(|inner| inner.into())
                } else {
                    self.generate_signed_batch_info(batch_info).ok()
                }
            },
            Err(e) => {
                debug!("QS: failed to store to cache {:?}", e);
                None
            },
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

**File:** consensus/src/quorum_store/proof_coordinator.rs (L145-178)
```rust
    fn add_signature(
        &mut self,
        signed_batch_info: &SignedBatchInfo<BatchInfoExt>,
        validator_verifier: &ValidatorVerifier,
    ) -> Result<(), SignedBatchInfoError> {
        if signed_batch_info.batch_info() != &self.signature_aggregator.data() {
            return Err(SignedBatchInfoError::WrongInfo((
                signed_batch_info.batch_info().batch_id().id,
                self.signature_aggregator.data().batch_id().id,
            )));
        }

        match validator_verifier.get_voting_power(&signed_batch_info.signer()) {
            Some(voting_power) => {
                self.signature_aggregator.add_signature(
                    signed_batch_info.signer(),
                    signed_batch_info.signature_with_status(),
                );
                self.aggregated_voting_power += voting_power as u128;
                if signed_batch_info.signer() == self.signature_aggregator.data().author() {
                    self.self_voted = true;
                }
            },
            None => {
                error!(
                    "Received signature from author not in validator set: {}",
                    signed_batch_info.signer()
                );
                return Err(SignedBatchInfoError::InvalidAuthor);
            },
        }

        Ok(())
    }
```

**File:** consensus/src/quorum_store/batch_requester.rs (L142-152)
```rust
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
```

**File:** consensus/src/quorum_store/batch_requester.rs (L176-179)
```rust
            counters::RECEIVED_BATCH_REQUEST_TIMEOUT_COUNT.inc();
            debug!("QS: batch request timed out, digest:{}", digest);
            Err(ExecutorError::CouldNotGetData)
        })
```

**File:** consensus/src/quorum_store/counters.rs (L826-832)
```rust
pub static RECEIVED_BATCH_NOT_FOUND_COUNT: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "quorum_store_received_batch_not_found_count",
        "Count of the number of batch not found responses received from other nodes."
    )
    .unwrap()
});
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L634-646)
```rust
        let result = loop {
            match preparer.materialize_block(&block, qc_rx.clone()).await {
                Ok(input_txns) => break input_txns,
                Err(e) => {
                    warn!(
                        "[BlockPreparer] failed to prepare block {}, retrying: {}",
                        block.id(),
                        e
                    );
                    tokio::time::sleep(Duration::from_millis(100)).await;
                },
            }
        };
```

**File:** config/src/config/quorum_store_config.rs (L127-130)
```rust
            batch_request_num_peers: 5,
            batch_request_retry_limit: 10,
            batch_request_retry_interval_ms: 500,
            batch_request_rpc_timeout_ms: 5000,
```
