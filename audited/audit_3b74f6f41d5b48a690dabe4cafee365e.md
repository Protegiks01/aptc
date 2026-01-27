# Audit Report

## Title
Selective Batch Censorship via NetworkListener Manipulation Without Offline Detection

## Summary
Byzantine validators can selectively drop or delay `BatchMsg` forwarding in their `NetworkListener` based on transaction content, achieving targeted censorship when they become block leaders. This attack is undetectable as the validators continue participating normally in consensus for non-targeted batches, avoiding any "offline" status flags.

## Finding Description

The Quorum Store protocol relies on batch dissemination where validators broadcast transaction batches to all other validators for signature collection. When a validator receives a `BatchMsg`, the `NetworkListener.start()` function forwards it to `BatchCoordinator` for processing. [1](#0-0) 

A Byzantine validator controlling their own node can modify this forwarding logic to:

1. **Inspect batch contents**: Access transaction data via `batch.txns()` [2](#0-1) 

2. **Selectively drop batches**: Skip forwarding `BatchCoordinatorCommand::NewBatches` for batches containing specific transactions (e.g., from targeted addresses)

3. **Avoid local storage**: Dropped batches never reach `BatchCoordinator.handle_batches_msg()` and are never persisted locally [3](#0-2) 

4. **Skip signature generation**: Without processing the batch, the validator doesn't send `SignedBatchInfo` back to the batch author

When this Byzantine validator becomes the block leader and `ProofManager.handle_proposal_request()` is invoked, the leader pulls available proofs via `BatchProofQueue.pull_proofs()`. This method only returns proofs for batches that exist in the local `items` HashMap: [4](#0-3) 

Since dropped batches were never stored locally, their proofs (even if formed by other validators) cannot be selected for inclusion. The leader thus proposes blocks that exclude these batches, achieving **selective transaction censorship**.

**Attack Flow:**
1. Validator A broadcasts batch containing transaction T from targeted address
2. Byzantine validator B's modified `NetworkListener` inspects batch, detects T, and drops the message
3. Honest validators receive, process, and sign the batch  
4. If ≥2f+1 signatures collected, `ProofOfStore` forms and broadcasts [5](#0-4) 

5. Byzantine validator B receives the proof but lacks underlying batch data
6. When B becomes leader, `pull_proofs()` excludes this batch (not in local storage)
7. B proposes a block without the targeted transaction - **censorship achieved**

**No Detection Mechanism:**
The batch author sees timeout if insufficient signatures arrive, but cannot identify which specific validators dropped the batch. The Byzantine validator appears online for all other consensus activities (voting, signing other batches, proposing blocks with non-targeted transactions). [6](#0-5) 

## Impact Explanation

**Severity: High**

This vulnerability enables **targeted transaction censorship** without detection:

- **Selective censorship**: Byzantine validators can censor specific users, addresses, or transaction types while appearing to function normally
- **No attribution**: The protocol provides no mechanism to identify which validators dropped specific batches
- **No penalties**: Byzantine validators face no consequences for selective non-participation
- **Frequency**: Censorship occurs whenever a Byzantine validator is the block leader (~1/n rounds where n = validator count)
- **Collusion amplification**: Multiple colluding Byzantine validators (up to <1/3 voting power) can increase censorship frequency

This qualifies as **High severity** per Aptos bug bounty criteria as it constitutes a "significant protocol violation" that undermines transaction inclusion fairness—a core blockchain guarantee.

While Byzantine fault tolerance expects arbitrary behavior from <1/3 validators, the inability to detect and attribute selective censorship amplifies the attack's effectiveness beyond typical BFT assumptions.

## Likelihood Explanation

**Likelihood: High** given the prerequisites:

**Prerequisites:**
- Attacker controls a validator node (insider threat)
- Attacker can modify consensus code on their node
- Attacker becomes block leader (probability 1/n per round)

**Feasibility:**
- Code modification is trivial (single conditional in `NetworkListener.start()`)
- Transaction inspection is straightforward via `batch.txns()`
- No cryptographic operations required
- Completely undetectable within the protocol
- No risk of punishment or slashing

**Realistic Scenario:**
A malicious validator operator (or compromised validator) could deploy this attack to:
- Censor competitors' transactions in DeFi applications
- Target specific user addresses
- Perform economic attacks by delaying time-sensitive transactions
- Achieve coordinated censorship across multiple colluding validators

## Recommendation

Implement **batch signature accountability** and **censorship detection**:

1. **Track signature participation**: Maintain metrics for which validators sign which batch digests
   ```rust
   // In ProofCoordinator
   struct SignatureTracking {
       batch_digest: HashValue,
       signers: HashSet<PeerId>,
       non_signers: HashSet<PeerId>,
       timestamp: Instant,
   }
   ```

2. **Expose non-signing validators**: When a batch times out, log which validators in the current epoch did not contribute signatures
   ```rust
   fn log_non_signers(&self, batch_info: &BatchInfoExt, validator_verifier: &ValidatorVerifier) {
       let all_validators: HashSet<_> = validator_verifier
           .get_ordered_account_addresses_iter()
           .collect();
       let signers = self.signature_aggregator.all_voters();
       let non_signers: Vec<_> = all_validators
           .difference(&signers.collect())
           .collect();
       warn!("Batch {:?} timeout: non-signers: {:?}", batch_info.batch_id(), non_signers);
   }
   ```

3. **Reputation system**: Track validator participation rates and expose via metrics/APIs for monitoring

4. **Proof fetching requirement**: When a leader's `BatchProofQueue` lacks a batch with a valid proof, require fetching via `BatchRequester` before excluding from proposal

5. **Consider slashing conditions**: For validators with consistently low batch signing rates (across multiple epochs), introduce slashing or validator set ejection

## Proof of Concept

```rust
// Malicious NetworkListener modification demonstrating the attack

// File: consensus/src/quorum_store/network_listener.rs
// Modified start() method:

pub async fn start(mut self) {
    info!("QS: starting networking");
    let mut next_batch_coordinator_idx = 0;
    
    // MALICIOUS: Define targeted address to censor
    let censored_address = AccountAddress::from_hex_literal("0xBADF00D").unwrap();
    
    while let Some((sender, msg)) = self.network_msg_rx.next().await {
        monitor!("qs_network_listener_main_loop", {
            match msg {
                VerifiedEvent::BatchMsg(batch_msg) => {
                    counters::QUORUM_STORE_MSG_COUNT
                        .with_label_values(&["NetworkListener::batchmsg"])
                        .inc();
                    
                    let author = batch_msg.author().expect("Empty batch message");
                    let batches = batch_msg.take();
                    
                    // MALICIOUS: Inspect transactions and selectively drop
                    let mut should_censor = false;
                    for batch in &batches {
                        for txn in batch.txns() {
                            if txn.sender() == censored_address {
                                warn!("CENSORING batch from {} containing txn from {}",
                                      author, censored_address);
                                should_censor = true;
                                break;
                            }
                        }
                        if should_censor { break; }
                    }
                    
                    if should_censor {
                        // Drop the message - don't forward to BatchCoordinator
                        counters::RECEIVED_BATCH_MSG_COUNT.inc(); // Maintain normal metrics
                        continue; // SKIP FORWARDING
                    }
                    
                    // Normal forwarding for non-targeted batches
                    counters::RECEIVED_BATCH_MSG_COUNT.inc();
                    let idx = next_batch_coordinator_idx;
                    next_batch_coordinator_idx = (next_batch_coordinator_idx + 1)
                        % self.remote_batch_coordinator_tx.len();
                    
                    self.remote_batch_coordinator_tx[idx]
                        .send(BatchCoordinatorCommand::NewBatches(author, batches))
                        .await
                        .expect("Could not send remote batch");
                },
                // ... other cases unchanged
            }
        });
    }
}
```

**Demonstration Steps:**
1. Deploy modified validator node with censorship logic
2. Target specific address (e.g., 0xBADF00D)
3. Monitor validator becoming block leader
4. Observe proposed blocks exclude batches containing targeted transactions
5. Verify validator maintains normal metrics and appears online for other batches
6. Confirm no detection or penalty mechanisms are triggered

## Notes

This vulnerability represents a fundamental **accountability gap** in the Quorum Store protocol. While BFT consensus tolerates <1/3 Byzantine validators, the inability to attribute selective censorship behavior enables stealthy attacks that undermine transaction inclusion fairness.

The attack requires validator-level access (insider threat), which places it at the boundary of the typical threat model. However, given:
- The security question explicitly targets Byzantine validator behavior  
- Validator node compromise or malicious operators are realistic threats
- The complete lack of detection/attribution mechanisms
- The high impact on protocol guarantees

This constitutes a valid High severity finding requiring protocol-level mitigation through accountability and reputation mechanisms.

### Citations

**File:** consensus/src/quorum_store/network_listener.rs (L68-94)
```rust
                    VerifiedEvent::BatchMsg(batch_msg) => {
                        counters::QUORUM_STORE_MSG_COUNT
                            .with_label_values(&["NetworkListener::batchmsg"])
                            .inc();
                        // Batch msg verify function alreay ensures that the batch_msg is not empty.
                        let author = batch_msg.author().expect("Empty batch message");
                        let batches = batch_msg.take();
                        counters::RECEIVED_BATCH_MSG_COUNT.inc();

                        // Round-robin assignment to batch coordinator.
                        let idx = next_batch_coordinator_idx;
                        next_batch_coordinator_idx = (next_batch_coordinator_idx + 1)
                            % self.remote_batch_coordinator_tx.len();
                        trace!(
                            "QS: peer_id {:?},  # network_worker {}, hashed to idx {}",
                            author,
                            self.remote_batch_coordinator_tx.len(),
                            idx
                        );
                        counters::BATCH_COORDINATOR_NUM_BATCH_REQS
                            .with_label_values(&[&idx.to_string()])
                            .inc();
                        self.remote_batch_coordinator_tx[idx]
                            .send(BatchCoordinatorCommand::NewBatches(author, batches))
                            .await
                            .expect("Could not send remote batch");
                    },
```

**File:** consensus/src/quorum_store/types.rs (L306-308)
```rust
    pub fn txns(&self) -> &[SignedTransaction] {
        self.payload.txns()
    }
```

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

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L601-622)
```rust
            let batch_iter = batches.iter().rev().filter_map(|(sort_key, info)| {
                if let Some(item) = self.items.get(&sort_key.batch_key) {
                    let batch_create_ts_usecs =
                        item.info.expiration() - self.batch_expiry_gap_when_init_usecs;

                    // Ensure that the batch was created at least `min_batch_age_usecs` ago to
                    // reduce the chance of inline fetches.
                    if max_batch_creation_ts_usecs
                        .is_some_and(|max_create_ts| batch_create_ts_usecs > max_create_ts)
                    {
                        return None;
                    }

                    if item.is_committed() {
                        return None;
                    }
                    if !(batches_without_proofs ^ item.proof.is_none()) {
                        return Some((info, item));
                    }
                }
                None
            });
```

**File:** consensus/src/quorum_store/proof_coordinator.rs (L329-347)
```rust
            if !value.completed && value.check_voting_power(validator_verifier, true) {
                let proof = {
                    let _timer = counters::SIGNED_BATCH_INFO_VERIFY_DURATION.start_timer();
                    value.aggregate_and_verify(validator_verifier)?
                };
                // proof validated locally, so adding to cache
                self.proof_cache
                    .insert(proof.info().clone(), proof.multi_signature().clone());
                // quorum store measurements
                let duration = self
                    .batch_info_to_time
                    .remove(signed_batch_info.batch_info())
                    .ok_or(
                        // Batch created without recording the time!
                        SignedBatchInfoError::NoTimeStamps,
                    )?
                    .elapsed();
                counters::BATCH_TO_POS_DURATION.observe_duration(duration);
                return Ok(Some(proof));
```

**File:** consensus/src/quorum_store/proof_coordinator.rs (L369-391)
```rust
    async fn expire(&mut self) {
        let mut batch_ids = vec![];
        for signed_batch_info_info in self.timeouts.expire() {
            if let Some(state) = self.batch_info_to_proof.remove(&signed_batch_info_info) {
                if !state.completed {
                    batch_ids.push(signed_batch_info_info.batch_id());
                }
                Self::update_counters_on_expire(&state);

                // We skip metrics if the proof did not complete and did not get a self vote, as it
                // is considered a proof that was re-inited due to a very late vote.
                if !state.completed && !state.self_voted {
                    continue;
                }

                if !state.completed {
                    counters::TIMEOUT_BATCHES_COUNT.inc();
                    info!(
                        LogSchema::new(LogEvent::IncrementalProofExpired),
                        digest = signed_batch_info_info.digest(),
                        self_voted = state.self_voted,
                    );
                }
```
