# Audit Report

## Title
Non-Exhaustive Pattern Matching Causes Silent Drop of Quorum Store V2 Messages Leading to Transaction Processing Failure

## Summary
The `NetworkTask::start()` method in `consensus/src/network.rs` uses a non-exhaustive match statement when processing direct-send consensus messages. Three critical quorum store message variants (`BatchMsgV2`, `SignedBatchInfoMsgV2`, `ProofOfStoreMsgV2`) are not handled in the match statement, causing them to be silently dropped when received. This breaks the quorum store protocol and prevents transaction processing when V2 batching is enabled.

## Finding Description
The `ConsensusMsg` enum defines V2 quorum store message variants including `BatchMsgV2`, `SignedBatchInfoMsgV2`, and `ProofOfStoreMsgV2`. [1](#0-0) 

These V2 messages are actively used when the `enable_batch_v2` configuration flag is enabled. The batch generator broadcasts V2 batch messages: [2](#0-1) 

The batch coordinator sends V2 signed batch info messages: [3](#0-2) 

The proof coordinator broadcasts V2 proof of store messages: [4](#0-3) 

These messages are sent via `broadcast()` and `send()` methods which deliver through the `Event::Message` path (direct-send): [5](#0-4) [6](#0-5) [7](#0-6) 

However, the `NetworkTask::start()` method's match statement for `Event::Message` only handles V1 versions of these messages: [8](#0-7) 

The V2 variants are not included in any match arm and fall through to the wildcard pattern which only logs a warning and drops the message: [9](#0-8) 

Meanwhile, the round manager expects to receive and convert these V2 messages: [10](#0-9) [11](#0-10) 

The verification logic is implemented for V2 messages: [12](#0-11) [13](#0-12) [14](#0-13) 

But these messages never reach the round manager because they're dropped at the network layer.

**Attack Path:**
1. Network operators enable `enable_batch_v2` flag in consensus configuration
2. Quorum store components begin broadcasting V2 messages
3. Receiving validators' `NetworkTask` processes messages via `Event::Message`
4. Match statement fails to find patterns for V2 variants
5. Messages hit wildcard branch and are silently dropped
6. Validators cannot exchange batch information or form proofs of store
7. Block proposals contain empty payloads, network cannot process transactions [15](#0-14) 

## Impact Explanation
This vulnerability has **Critical Severity** impact under the "Total Loss of Liveness/Network Availability" category.

When V2 batching is enabled, all validators are unable to exchange quorum store messages. This completely breaks the transaction batching protocol. While consensus can technically continue creating blocks with empty payloads, the network becomes unable to process any user transactions, effectively making it unavailable for its intended purpose.

The quorum store protocol requires validators to:
1. Exchange batch messages to distribute transaction data
2. Collect signatures via SignedBatchInfo messages 
3. Broadcast ProofOfStore messages with 2f+1 signatures
4. Include these proofs in block proposals [16](#0-15) 

Without this message flow, no transaction batches can be certified and included in blocks. All validators are affected simultaneously when V2 is enabled, and the issue persists until code is patched or the flag is disabled.

This meets the Critical Severity criteria: "Network halts due to protocol bug" and "All validators unable to progress" (in terms of transaction processing).

## Likelihood Explanation
**Likelihood: HIGH**

This vulnerability triggers automatically whenever the `enable_batch_v2` configuration flag is enabled: [17](#0-16) 

No attacker action is required - this is a protocol-level bug affecting all honest validators. The vulnerability was likely introduced when V2 message types were added to support extended batch information, but the network message handler was not updated accordingly.

The code explicitly checks whether to use V2 batching and actively sends these messages in production paths, making this a guaranteed trigger condition rather than an edge case.

## Recommendation
Update the `NetworkTask::start()` method to handle V2 message variants in the `Event::Message` match statement:

```rust
match msg {
    quorum_store_msg @ (ConsensusMsg::SignedBatchInfo(_)
    | ConsensusMsg::SignedBatchInfoMsgV2(_)  // Add V2 variant
    | ConsensusMsg::BatchMsg(_)
    | ConsensusMsg::BatchMsgV2(_)  // Add V2 variant
    | ConsensusMsg::ProofOfStoreMsg(_)
    | ConsensusMsg::ProofOfStoreMsgV2(_)) => {  // Add V2 variant
        Self::push_msg(
            peer_id,
            quorum_store_msg,
            &self.quorum_store_messages_tx,
        );
    },
    // ... rest of match arms
}
```

## Proof of Concept
A PoC would require deploying a test network with `enable_batch_v2=true` and observing that:
1. V2 messages are broadcast (visible in logs with "BatchMsgV2", "SignedBatchInfoMsgV2", "ProofOfStoreMsgV2")
2. Warning logs appear: "Unexpected direct send msg"
3. Quorum store metrics show no batch processing
4. Block proposals contain empty payloads
5. No transactions are processed despite mempool having pending transactions

The vulnerability is confirmed through direct code inspection showing the missing match arms and the active usage of V2 messages in the codebase.

### Citations

**File:** consensus/src/network_interface.rs (L97-102)
```rust
    BatchMsgV2(Box<BatchMsg<BatchInfoExt>>),
    /// Quorum Store: Send a signed batch digest with BatchInfoExt. This is a vote for the batch and a promise that
    /// the batch of transactions was received and will be persisted until batch expiration.
    SignedBatchInfoMsgV2(Box<SignedBatchInfoMsg<BatchInfoExt>>),
    /// Quorum Store: Broadcast a certified proof of store (a digest that received 2f+1 votes) with BatchInfoExt.
    ProofOfStoreMsgV2(Box<ProofOfStoreMsg<BatchInfoExt>>),
```

**File:** consensus/src/quorum_store/batch_generator.rs (L190-211)
```rust
        if self.config.enable_batch_v2 {
            // TODO(ibalajiarun): Specify accurate batch kind
            let batch_kind = BatchKind::Normal;
            Batch::new_v2(
                batch_id,
                txns,
                self.epoch,
                expiry_time,
                self.my_peer_id,
                bucket_start,
                batch_kind,
            )
        } else {
            Batch::new_v1(
                batch_id,
                txns,
                self.epoch,
                expiry_time,
                self.my_peer_id,
                bucket_start,
            )
        }
```

**File:** consensus/src/quorum_store/batch_generator.rs (L494-495)
```rust
                            if self.config.enable_batch_v2 {
                                network_sender.broadcast_batch_msg_v2(batches).await;
```

**File:** consensus/src/quorum_store/batch_coordinator.rs (L102-110)
```rust
            if persist_requests[0].batch_info().is_v2() {
                let signed_batch_infos = batch_store.persist(persist_requests);
                if !signed_batch_infos.is_empty() {
                    if approx_created_ts_usecs > 0 {
                        observe_batch(approx_created_ts_usecs, peer_id, BatchStage::SIGNED);
                    }
                    network_sender
                        .send_signed_batch_info_msg_v2(signed_batch_infos, vec![peer_id])
                        .await;
```

**File:** consensus/src/quorum_store/proof_coordinator.rs (L485-487)
```rust
                                    if proofs_iter.peek().is_some_and(|p| p.info().is_v2()) {
                                        let proofs: Vec<_> = proofs_iter.collect();
                                        network_sender.broadcast_proof_of_store_msg_v2(proofs).await;
```

**File:** consensus/src/network.rs (L599-609)
```rust
    async fn send_signed_batch_info_msg_v2(
        &self,
        signed_batch_infos: Vec<SignedBatchInfo<BatchInfoExt>>,
        recipients: Vec<Author>,
    ) {
        fail_point!("consensus::send::signed_batch_info", |_| ());
        let msg = ConsensusMsg::SignedBatchInfoMsgV2(Box::new(SignedBatchInfoMsg::new(
            signed_batch_infos,
        )));
        self.send(msg, recipients).await
    }
```

**File:** consensus/src/network.rs (L617-621)
```rust
    async fn broadcast_batch_msg_v2(&mut self, batches: Vec<Batch<BatchInfoExt>>) {
        fail_point!("consensus::send::broadcast_batch", |_| ());
        let msg = ConsensusMsg::BatchMsgV2(Box::new(BatchMsg::new(batches)));
        self.broadcast(msg).await
    }
```

**File:** consensus/src/network.rs (L629-633)
```rust
    async fn broadcast_proof_of_store_msg_v2(&mut self, proofs: Vec<ProofOfStore<BatchInfoExt>>) {
        fail_point!("consensus::send::proof_of_store", |_| ());
        let msg = ConsensusMsg::ProofOfStoreMsgV2(Box::new(ProofOfStoreMsg::new(proofs)));
        self.broadcast(msg).await
    }
```

**File:** consensus/src/network.rs (L823-831)
```rust
                        quorum_store_msg @ (ConsensusMsg::SignedBatchInfo(_)
                        | ConsensusMsg::BatchMsg(_)
                        | ConsensusMsg::ProofOfStoreMsg(_)) => {
                            Self::push_msg(
                                peer_id,
                                quorum_store_msg,
                                &self.quorum_store_messages_tx,
                            );
                        },
```

**File:** consensus/src/network.rs (L937-940)
```rust
                        _ => {
                            warn!(remote_peer = peer_id, "Unexpected direct send msg");
                            continue;
                        },
```

**File:** consensus/src/round_manager.rs (L97-101)
```rust
    BatchMsgV2(Box<BatchMsg<BatchInfoExt>>),
    SignedBatchInfo(Box<SignedBatchInfoMsg<BatchInfo>>),
    SignedBatchInfoMsgV2(Box<SignedBatchInfoMsg<BatchInfoExt>>),
    ProofOfStoreMsg(Box<ProofOfStoreMsg<BatchInfo>>),
    ProofOfStoreMsgV2(Box<ProofOfStoreMsg<BatchInfoExt>>),
```

**File:** consensus/src/round_manager.rs (L175-182)
```rust
            UnverifiedEvent::BatchMsgV2(b) => {
                if !self_message {
                    b.verify(peer_id, max_num_batches, validator)?;
                    counters::VERIFY_MSG
                        .with_label_values(&["batch_v2"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::BatchMsg(b)
```

**File:** consensus/src/round_manager.rs (L198-210)
```rust
            UnverifiedEvent::SignedBatchInfoMsgV2(sd) => {
                if !self_message {
                    sd.verify(
                        peer_id,
                        max_num_batches,
                        max_batch_expiry_gap_usecs,
                        validator,
                    )?;
                    counters::VERIFY_MSG
                        .with_label_values(&["signed_batch_v2"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::SignedBatchInfo(sd)
```

**File:** consensus/src/round_manager.rs (L221-228)
```rust
            UnverifiedEvent::ProofOfStoreMsgV2(p) => {
                if !self_message {
                    p.verify(max_num_batches, validator, proof_cache)?;
                    counters::VERIFY_MSG
                        .with_label_values(&["proof_of_store_v2"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::ProofOfStoreMsg(p)
```

**File:** consensus/src/round_manager.rs (L263-265)
```rust
            ConsensusMsg::BatchMsgV2(m) => UnverifiedEvent::BatchMsgV2(m),
            ConsensusMsg::SignedBatchInfoMsgV2(m) => UnverifiedEvent::SignedBatchInfoMsgV2(m),
            ConsensusMsg::ProofOfStoreMsgV2(m) => UnverifiedEvent::ProofOfStoreMsgV2(m),
```

**File:** consensus/src/quorum_store/proof_manager.rs (L213-214)
```rust
        } else if proof_block.is_empty() && inline_block.is_empty() {
            Payload::empty(true, self.allow_batches_without_pos_in_proposal)
```

**File:** consensus/src/quorum_store/network_listener.rs (L57-100)
```rust
                    VerifiedEvent::SignedBatchInfo(signed_batch_infos) => {
                        counters::QUORUM_STORE_MSG_COUNT
                            .with_label_values(&["NetworkListener::signedbatchinfo"])
                            .inc();
                        let cmd =
                            ProofCoordinatorCommand::AppendSignature(sender, *signed_batch_infos);
                        self.proof_coordinator_tx
                            .send(cmd)
                            .await
                            .expect("Could not send signed_batch_info to proof_coordinator");
                    },
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
                    VerifiedEvent::ProofOfStoreMsg(proofs) => {
                        counters::QUORUM_STORE_MSG_COUNT
                            .with_label_values(&["NetworkListener::proofofstore"])
                            .inc();
                        let cmd = ProofManagerCommand::ReceiveProofs(*proofs);
                        self.proof_manager_tx
```
