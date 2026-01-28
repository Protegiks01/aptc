# Audit Report

## Title
Missing Payload Verification in DAG Consensus Enables Byzantine Validator DoS Attack

## Summary
The DAG consensus implementation fails to verify payload cryptographic signatures when processing incoming Node messages, allowing Byzantine validators to inject nodes with malicious payloads that cause execution failures and validator resource exhaustion.

## Finding Description

In the Aptos DAG consensus protocol, the `NodeBroadcastHandler::validate()` method performs validation before voting on nodes, but critically **omits payload cryptographic verification**. [1](#0-0) 

The validation checks epoch, validator transactions, payload size limits, round validity, and parent availability, but **never calls `payload.verify()`**. In contrast, regular AptosBFT consensus explicitly verifies payloads: [2](#0-1) 

The `Payload::verify()` method performs critical validation including ProofOfStore signature verification (2f+1 validators), inline batch digest validation, and batch author validity checks: [3](#0-2) 

**Attack Path:**

1. A Byzantine validator creates a DAG Node with malicious `Payload` containing forged ProofOfStore signatures or non-existent batch digests
2. The Node passes `NodeBroadcastHandler::validate()` since it only checks structural properties, not cryptographic validity
3. Honest validators vote for the node, and it becomes certified with valid aggregate signatures
4. The certified node is added to the DAG and ordered for execution
5. During execution, `OrderedNotifierAdapter::send_ordered_nodes()` extracts the payload: [4](#0-3) 

6. `QuorumStorePayloadManager::get_transactions()` attempts to fetch batches using the invalid ProofOfStore: [5](#0-4) 

7. `BatchRequester::request_batch()` fails after timeout when batches don't exist, returning `ExecutorError::CouldNotGetData`: [6](#0-5) 

8. The execution pipeline handles the error by logging and returning without advancing, blocking subsequent blocks: [7](#0-6) 

## Impact Explanation

This vulnerability qualifies as **High Severity** under Aptos bug bounty criteria for "Validator Node Slowdowns (up to $50,000)":

- Byzantine validators can continuously inject invalid nodes forcing honest validators to waste resources attempting to fetch non-existent batches
- Network bandwidth exhausted sending requests to fake responder lists  
- Execution pipeline blocks waiting for batches that will never arrive, preventing new blocks from being processed
- CPU cycles wasted on retry attempts with exponential backoff
- Violates the fundamental protocol assumption that certified nodes contain valid, executable payloads

The attack does not break consensus safety (all honest validators agree on the same DAG structure), but causes severe availability degradation and resource exhaustion.

## Likelihood Explanation

**High Likelihood:**

1. **Low Attack Complexity**: A Byzantine validator only needs to create a `Payload` with fake `ProofOfStore` objects (trivial to forge invalid signatures) and broadcast through normal DAG protocol
2. **No Detection Mechanism**: The missing verification is systematic - every invalid payload is accepted without challenge
3. **Amplification Effect**: A single Byzantine validator can spam multiple rounds with invalid nodes
4. **Byzantine Validators Expected**: BFT protocols assume up to 1/3 Byzantine validators by design
5. **No Additional Prerequisites**: Attack works under normal network operation without requiring specific timing or state conditions

## Recommendation

Add payload verification to `NodeBroadcastHandler::validate()` method:

```rust
fn validate(&self, node: Node) -> anyhow::Result<Node> {
    // ... existing validation checks ...
    
    // Add payload verification before accepting the node
    if let Some(proof_cache) = &self.proof_cache {
        node.payload().verify(
            &self.epoch_state.verifier,
            proof_cache,
            true // quorum_store_enabled
        )?;
    }
    
    Ok(node)
}
```

This ensures DAG consensus applies the same cryptographic payload validation as regular AptosBFT consensus, preventing Byzantine validators from injecting nodes with invalid ProofOfStore signatures or fake batch digests.

## Proof of Concept

A Byzantine validator can exploit this by:

1. Creating a `Node` with a `Payload::InQuorumStore` containing `ProofOfStore` objects with forged signatures
2. Broadcasting the node via the DAG reliable broadcast protocol
3. Honest validators accept and vote for the node (passes `validate()`)
4. Node becomes certified and enters the execution pipeline
5. Execution fails with `ExecutorError::CouldNotGetData` when attempting to fetch non-existent batches
6. Execution pipeline blocks, preventing progress on subsequent blocks

The attack is reproducible by modifying any validator to broadcast nodes with invalid payloads - no sophisticated cryptographic attacks required.

## Notes

The vulnerability specifically affects DAG consensus nodes. Regular AptosBFT block proposals are protected by `ProposalMsg::verify()` which does call `payload.verify()`. The discrepancy suggests DAG consensus validation was implemented without considering payload cryptographic integrity, creating a security gap that Byzantine validators can exploit for denial-of-service attacks.

### Citations

**File:** consensus/src/dag/rb_handler.rs (L112-185)
```rust
    fn validate(&self, node: Node) -> anyhow::Result<Node> {
        ensure!(
            node.epoch() == self.epoch_state.epoch,
            "different epoch {}, current {}",
            node.epoch(),
            self.epoch_state.epoch
        );

        let num_vtxns = node.validator_txns().len() as u64;
        ensure!(num_vtxns <= self.vtxn_config.per_block_limit_txn_count());
        for vtxn in node.validator_txns() {
            let vtxn_type_name = vtxn.type_name();
            ensure!(
                is_vtxn_expected(&self.randomness_config, &self.jwk_consensus_config, vtxn),
                "unexpected validator transaction: {:?}",
                vtxn_type_name
            );
            vtxn.verify(self.epoch_state.verifier.as_ref())
                .context(format!("{} verification failed", vtxn_type_name))?;
        }
        let vtxn_total_bytes = node
            .validator_txns()
            .iter()
            .map(ValidatorTransaction::size_in_bytes)
            .sum::<usize>() as u64;
        ensure!(vtxn_total_bytes <= self.vtxn_config.per_block_limit_total_bytes());

        let num_txns = num_vtxns + node.payload().len() as u64;
        let txn_bytes = vtxn_total_bytes + node.payload().size() as u64;
        ensure!(num_txns <= self.payload_config.max_receiving_txns_per_round);
        ensure!(txn_bytes <= self.payload_config.max_receiving_size_per_round_bytes);

        let current_round = node.metadata().round();

        let dag_reader = self.dag.read();
        let lowest_round = dag_reader.lowest_round();

        ensure!(
            current_round >= lowest_round,
            NodeBroadcastHandleError::StaleRound(current_round)
        );

        // check which parents are missing in the DAG
        let missing_parents: Vec<NodeCertificate> = node
            .parents()
            .iter()
            .filter(|parent| !dag_reader.exists(parent.metadata()))
            .cloned()
            .collect();
        drop(dag_reader); // Drop the DAG store early as it is no longer required

        if !missing_parents.is_empty() {
            // For each missing parent, verify their signatures and voting power.
            // Otherwise, a malicious node can send bad nodes with fake parents
            // and cause this peer to issue unnecessary fetch requests.
            ensure!(
                missing_parents
                    .iter()
                    .all(|parent| { parent.verify(&self.epoch_state.verifier).is_ok() }),
                NodeBroadcastHandleError::InvalidParent
            );

            // Don't issue fetch requests for parents of the lowest round in the DAG
            // because they are already GC'ed
            if current_round > lowest_round {
                if let Err(err) = self.fetch_requester.request_for_node(node) {
                    error!("request to fetch failed: {}", err);
                }
                bail!(NodeBroadcastHandleError::MissingParents);
            }
        }

        Ok(node)
    }
```

**File:** consensus/consensus-types/src/proposal_msg.rs (L97-101)
```rust
        let (payload_result, sig_result) = rayon::join(
            || {
                self.proposal().payload().map_or(Ok(()), |p| {
                    p.verify(validator, proof_cache, quorum_store_enabled)
                })
```

**File:** consensus/consensus-types/src/common.rs (L574-632)
```rust
    pub fn verify(
        &self,
        verifier: &ValidatorVerifier,
        proof_cache: &ProofCache,
        quorum_store_enabled: bool,
    ) -> anyhow::Result<()> {
        match (quorum_store_enabled, self) {
            (false, Payload::DirectMempool(_)) => Ok(()),
            (true, Payload::InQuorumStore(proof_with_status)) => {
                Self::verify_with_cache(&proof_with_status.proofs, verifier, proof_cache)
            },
            (true, Payload::InQuorumStoreWithLimit(proof_with_status)) => Self::verify_with_cache(
                &proof_with_status.proof_with_data.proofs,
                verifier,
                proof_cache,
            ),
            (true, Payload::QuorumStoreInlineHybrid(inline_batches, proof_with_data, _))
            | (true, Payload::QuorumStoreInlineHybridV2(inline_batches, proof_with_data, _)) => {
                Self::verify_with_cache(&proof_with_data.proofs, verifier, proof_cache)?;
                Self::verify_inline_batches(
                    inline_batches.iter().map(|(info, txns)| (info, txns)),
                )?;
                Ok(())
            },
            (true, Payload::OptQuorumStore(OptQuorumStorePayload::V1(p))) => {
                let proof_with_data = p.proof_with_data();
                Self::verify_with_cache(&proof_with_data.batch_summary, verifier, proof_cache)?;
                Self::verify_inline_batches(
                    p.inline_batches()
                        .iter()
                        .map(|batch| (batch.info(), batch.transactions())),
                )?;
                Self::verify_opt_batches(verifier, p.opt_batches())?;
                Ok(())
            },
            (true, Payload::OptQuorumStore(OptQuorumStorePayload::V2(p))) => {
                if true {
                    bail!("OptQuorumStorePayload::V2 cannot be accepted yet");
                }
                #[allow(unreachable_code)]
                {
                    let proof_with_data = p.proof_with_data();
                    Self::verify_with_cache(&proof_with_data.batch_summary, verifier, proof_cache)?;
                    Self::verify_inline_batches(
                        p.inline_batches()
                            .iter()
                            .map(|batch| (batch.info(), batch.transactions())),
                    )?;
                    Self::verify_opt_batches(verifier, p.opt_batches())?;
                    Ok(())
                }
            },
            (_, _) => Err(anyhow::anyhow!(
                "Wrong payload type. Expected Payload::InQuorumStore {} got {} ",
                quorum_store_enabled,
                self
            )),
        }
    }
```

**File:** consensus/src/dag/adapter.rs (L138-199)
```rust
    fn send_ordered_nodes(
        &self,
        ordered_nodes: Vec<Arc<CertifiedNode>>,
        failed_author: Vec<(Round, Author)>,
    ) {
        let anchor = ordered_nodes
            .last()
            .expect("ordered_nodes shuld not be empty");
        let epoch = anchor.epoch();
        let round = anchor.round();
        let timestamp = anchor.metadata().timestamp();
        let author = *anchor.author();
        let mut validator_txns = vec![];
        let mut payload = Payload::empty(
            !anchor.payload().is_direct(),
            self.allow_batches_without_pos_in_proposal,
        );
        let mut node_digests = vec![];
        for node in &ordered_nodes {
            validator_txns.extend(node.validator_txns().clone());
            payload = payload.extend(node.payload().clone());
            node_digests.push(node.digest());
        }
        let parent_block_id = self.parent_block_info.read().id();
        // construct the bitvec that indicates which nodes present in the previous round in CommitEvent
        let mut parents_bitvec = BitVec::with_num_bits(self.epoch_state.verifier.len() as u16);
        for parent in anchor.parents().iter() {
            if let Some(idx) = self
                .epoch_state
                .verifier
                .address_to_validator_index()
                .get(parent.metadata().author())
            {
                parents_bitvec.set(*idx as u16);
            }
        }
        let parent_timestamp = self.parent_block_info.read().timestamp_usecs();
        let block_timestamp = timestamp.max(parent_timestamp.checked_add(1).expect("must add"));

        NUM_NODES_PER_BLOCK.observe(ordered_nodes.len() as f64);
        let rounds_between = {
            let lowest_round_node = ordered_nodes.first().map_or(0, |node| node.round());
            round.saturating_sub(lowest_round_node)
        };
        NUM_ROUNDS_PER_BLOCK.observe((rounds_between + 1) as f64);

        let block = Arc::new(PipelinedBlock::new(
            Block::new_for_dag(
                epoch,
                round,
                block_timestamp,
                validator_txns,
                payload,
                author,
                failed_author,
                parent_block_id,
                parents_bitvec,
                node_digests,
            ),
            vec![],
            StateComputeResult::new_dummy(),
        ));
```

**File:** consensus/src/payload_manager/quorum_store_payload_manager.rs (L446-564)
```rust
    async fn get_transactions(
        &self,
        block: &Block,
        block_signers: Option<BitVec>,
    ) -> ExecutorResult<(Vec<SignedTransaction>, Option<u64>, Option<u64>)> {
        let Some(payload) = block.payload() else {
            return Ok((Vec::new(), None, None));
        };

        let transaction_payload = match payload {
            Payload::InQuorumStore(proof_with_data) => {
                let transactions = process_qs_payload(
                    proof_with_data,
                    self.batch_reader.clone(),
                    block,
                    &self.ordered_authors,
                )
                .await?;
                BlockTransactionPayload::new_in_quorum_store(
                    transactions,
                    proof_with_data.proofs.clone(),
                )
            },
            Payload::InQuorumStoreWithLimit(proof_with_data) => {
                let transactions = process_qs_payload(
                    &proof_with_data.proof_with_data,
                    self.batch_reader.clone(),
                    block,
                    &self.ordered_authors,
                )
                .await?;
                BlockTransactionPayload::new_in_quorum_store_with_limit(
                    transactions,
                    proof_with_data.proof_with_data.proofs.clone(),
                    proof_with_data.max_txns_to_execute,
                )
            },
            Payload::QuorumStoreInlineHybrid(
                inline_batches,
                proof_with_data,
                max_txns_to_execute,
            ) => {
                self.get_transactions_quorum_store_inline_hybrid(
                    block,
                    inline_batches,
                    proof_with_data,
                    max_txns_to_execute,
                    &None,
                )
                .await?
            },
            Payload::QuorumStoreInlineHybridV2(
                inline_batches,
                proof_with_data,
                execution_limits,
            ) => {
                self.get_transactions_quorum_store_inline_hybrid(
                    block,
                    inline_batches,
                    proof_with_data,
                    &execution_limits.max_txns_to_execute(),
                    &execution_limits.block_gas_limit(),
                )
                .await?
            },
            Payload::OptQuorumStore(OptQuorumStorePayload::V1(opt_qs_payload)) => {
                let opt_batch_txns = process_optqs_payload(
                    opt_qs_payload.opt_batches(),
                    self.batch_reader.clone(),
                    block,
                    &self.ordered_authors,
                    block_signers.as_ref(),
                )
                .await?;
                let proof_batch_txns = process_optqs_payload(
                    opt_qs_payload.proof_with_data(),
                    self.batch_reader.clone(),
                    block,
                    &self.ordered_authors,
                    None,
                )
                .await?;
                let inline_batch_txns = opt_qs_payload.inline_batches().transactions();
                let all_txns = [proof_batch_txns, opt_batch_txns, inline_batch_txns].concat();
                BlockTransactionPayload::new_opt_quorum_store(
                    all_txns,
                    opt_qs_payload.proof_with_data().deref().clone(),
                    opt_qs_payload.max_txns_to_execute(),
                    opt_qs_payload.block_gas_limit(),
                    [
                        opt_qs_payload.opt_batches().deref().clone(),
                        opt_qs_payload.inline_batches().batch_infos(),
                    ]
                    .concat(),
                )
            },
            _ => unreachable!(
                "Wrong payload {} epoch {}, round {}, id {}",
                payload,
                block.block_data().epoch(),
                block.block_data().round(),
                block.id()
            ),
        };

        if let Some(consensus_publisher) = &self.maybe_consensus_publisher {
            let message = ConsensusObserverMessage::new_block_payload_message(
                block.gen_block_info(HashValue::zero(), 0, None),
                transaction_payload.clone(),
            );
            consensus_publisher.publish_message(message);
        }

        Ok((
            transaction_payload.transactions(),
            transaction_payload.transaction_limit(),
            transaction_payload.gas_limit(),
        ))
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

**File:** consensus/src/pipeline/buffer_manager.rs (L609-627)
```rust
    async fn process_execution_response(&mut self, response: ExecutionResponse) {
        let ExecutionResponse { block_id, inner } = response;
        // find the corresponding item, may not exist if a reset or aggregated happened
        let current_cursor = self.buffer.find_elem_by_key(self.execution_root, block_id);
        if current_cursor.is_none() {
            return;
        }

        let executed_blocks = match inner {
            Ok(result) => result,
            Err(e) => {
                log_executor_error_occurred(
                    e,
                    &counters::BUFFER_MANAGER_RECEIVED_EXECUTOR_ERROR_COUNT,
                    block_id,
                );
                return;
            },
        };
```
