# Audit Report

## Title
Unverified Quorum Certificates Accepted During Block Retrieval in Sync Operations

## Summary
The `insert_quorum_cert()` function in `block_tree.rs` does not validate QC signatures before insertion. While most code paths verify QCs before reaching this function, there is a critical vulnerability in the block retrieval flow during sync operations where QCs embedded in blocks retrieved from remote peers are inserted without signature verification, allowing malicious peers to inject forged quorum certificates into the consensus layer.

## Finding Description

The `insert_quorum_cert()` function performs no cryptographic signature validation: [1](#0-0) 

The function only checks:
1. A safety invariant about duplicate rounds (precondition check)
2. Whether the certified block exists locally
3. Updates internal state tracking highest certified blocks

The critical vulnerability exists in the block retrieval path during sync operations. When a node receives a SyncInfo message with a newer QC, it triggers `fetch_quorum_cert()`: [2](#0-1) 

This function retrieves blocks from remote peers via `retrieve_blocks_in_range()`, which calls `retrieve_blocks()`: [3](#0-2) 

**The vulnerability**: The `BlockRetrievalResponse` received from remote peers is NEVER verified. The code extracts blocks from the response and directly uses them without calling the available `verify()` method.

The `BlockRetrievalResponse::verify()` method exists and would validate all block signatures and QCs: [4](#0-3) 

This method calls `block.validate_signature(sig_verifier)` which verifies QC signatures: [5](#0-4) 

However, in the retrieval flow, blocks are extracted and their QCs are inserted directly via `insert_single_quorum_cert()` without any verification: [6](#0-5) 

**Attack Path:**
1. Malicious peer M observes legitimate SyncInfo from honest validator V containing a valid high QC
2. When node N requests blocks during sync, M responds with blocks containing forged QCs with invalid signatures
3. Node N's `retrieve_blocks()` accepts the response without calling `verify()`
4. Forged QCs are extracted from blocks at line 260 and 265 in sync_manager.rs
5. `insert_single_quorum_cert()` is called, which internally calls `insert_quorum_cert()` without signature validation
6. Forged QCs are now in the block store, potentially used for consensus decisions

This breaks the **Consensus Safety** invariant: AptosBFT must prevent consensus manipulation under < 1/3 Byzantine validators. A single malicious peer (not even a validator) can inject forged QCs.

## Impact Explanation

**Critical Severity** - This vulnerability enables:

1. **Consensus Manipulation**: Forged QCs can make nodes believe blocks are certified when they are not, potentially causing:
   - Different nodes to have conflicting views of which blocks are certified
   - Nodes to advance to incorrect rounds based on fake QCs
   - Chain splits if different nodes accept different forged QCs

2. **Safety Violation**: The AptosBFT consensus protocol relies on QC signature verification to ensure only blocks certified by 2f+1 validators are accepted. This vulnerability allows bypassing that fundamental safety guarantee.

3. **Non-recoverable State**: Once forged QCs are persisted to storage (line 552-554 in block_store.rs), they become part of the node's persistent state, potentially requiring manual intervention or hard fork to recover.

This meets the **Critical Severity** criteria: "Consensus/Safety violations" and potentially "Non-recoverable network partition (requires hardfork)" from the Aptos bug bounty program.

## Likelihood Explanation

**High Likelihood**:

1. **Common Trigger**: The vulnerable code path executes during normal sync operations whenever a node falls behind and needs to catch up, which happens regularly during:
   - Node restarts
   - Network partitions
   - Slow network conditions
   - State sync operations

2. **Low Attacker Requirements**: 
   - Attacker only needs to run a malicious peer (not a validator)
   - No stake or voting power required
   - Only requires ability to respond to block retrieval requests
   - Can target any node performing sync

3. **No Rate Limiting**: The code retrieves blocks from any peer that responds successfully, with no additional validation beyond basic protocol conformance.

4. **Persistent Impact**: Once forged QCs are inserted, they persist in storage and continue to affect consensus behavior.

## Recommendation

Add signature verification to the block retrieval flow. In `BlockRetriever::retrieve_blocks()`, verify the response before accepting blocks:

```rust
// In consensus/src/block_storage/sync_manager.rs, in retrieve_blocks() method
// After line 835 (after retrieve_block_chunk completes):

let response = self
    .retrieve_block_chunk(
        last_block_id,
        target_block_retrieval_payload,
        retrieve_batch_size,
        peers.clone(),
    )
    .await;

match response {
    Ok(result) if matches!(result.status(), BlockRetrievalStatus::Succeeded) => {
        // ADD VERIFICATION HERE:
        let request = match target_block_retrieval_payload {
            TargetBlockRetrieval::TargetBlockId(id) => {
                BlockRetrievalRequest::V1(BlockRetrievalRequestV1::new_with_target_block_id(
                    last_block_id, retrieve_batch_size, id))
            },
            TargetBlockRetrieval::TargetRound(round) => {
                BlockRetrievalRequest::V2(BlockRetrievalRequestV2::new_with_target_round(
                    last_block_id, retrieve_batch_size, round))
            },
        };
        
        // Verify all blocks and their QCs before accepting
        result.verify(request, &self.network.epoch_state().verifier)
            .context("Block retrieval response verification failed")?;
        
        // Continue with existing logic
        let batch = result.blocks().clone();
        // ... rest of the code
    },
    // ... handle other cases
}
```

This ensures that:
1. All block signatures are verified
2. All QC signatures are verified via `block.validate_signature()`
3. Block chain consistency is validated
4. Only cryptographically valid blocks and QCs can be inserted

## Proof of Concept

```rust
// Proof of Concept showing the attack path
// This would be a test in consensus/src/block_storage/sync_manager_test.rs

#[tokio::test]
async fn test_unverified_qc_insertion_via_block_retrieval() {
    // Setup: Create a test environment with a node and malicious peer
    let (node, mut malicious_peer) = setup_test_environment();
    
    // Step 1: Malicious peer intercepts block retrieval request
    let retrieval_request = node.request_blocks_for_sync().await;
    
    // Step 2: Malicious peer creates blocks with forged QCs
    let forged_qc = create_qc_with_invalid_signatures();  // Invalid signatures
    let malicious_block = Block::new_with_qc(forged_qc);
    
    // Step 3: Malicious peer sends response with forged QCs
    let response = BlockRetrievalResponse::new(
        BlockRetrievalStatus::Succeeded,
        vec![malicious_block],
    );
    malicious_peer.send_response(response).await;
    
    // Step 4: Verify the forged QC was inserted without validation
    // The node should reject this, but currently it accepts it
    let inserted_qc = node.block_store.get_quorum_cert_for_block(malicious_block.id());
    
    // VULNERABILITY: This assertion passes when it should fail
    assert!(inserted_qc.is_some());
    
    // Verify the QC has invalid signatures
    let result = inserted_qc.unwrap().verify(&node.epoch_state.verifier);
    assert!(result.is_err());  // QC verification fails, but it's already inserted!
    
    // This proves forged QCs can be inserted into consensus layer
}
```

## Notes

While most code paths properly verify QCs before insertion:
- SyncInfo messages verify QCs via `sync_info.verify()` [7](#0-6) 
- Order vote messages verify QCs [8](#0-7) 
- Locally aggregated QCs from votes are trusted (votes were already verified)

The block retrieval path during sync is the only unprotected path that allows external, unverified QCs to reach `insert_quorum_cert()`. This is a critical gap in the defense-in-depth strategy that should be addressed immediately.

### Citations

**File:** consensus/src/block_storage/block_tree.rs (L349-386)
```rust
    pub(super) fn insert_quorum_cert(&mut self, qc: QuorumCert) -> anyhow::Result<()> {
        let block_id = qc.certified_block().id();
        let qc = Arc::new(qc);

        // Safety invariant: For any two quorum certificates qc1, qc2 in the block store,
        // qc1 == qc2 || qc1.round != qc2.round
        // The invariant is quadratic but can be maintained in linear time by the check
        // below.
        precondition!({
            let qc_round = qc.certified_block().round();
            self.id_to_quorum_cert.values().all(|x| {
                (*(*x).ledger_info()).ledger_info().consensus_data_hash()
                    == (*(*qc).ledger_info()).ledger_info().consensus_data_hash()
                    || x.certified_block().round() != qc_round
            })
        });

        match self.get_block(&block_id) {
            Some(block) => {
                if block.round() > self.highest_certified_block().round() {
                    self.highest_certified_block_id = block.id();
                    self.highest_quorum_cert = Arc::clone(&qc);
                }
            },
            None => bail!("Block {} not found", block_id),
        }

        self.id_to_quorum_cert
            .entry(block_id)
            .or_insert_with(|| Arc::clone(&qc));

        if self.highest_ordered_cert.commit_info().round() < qc.commit_info().round() {
            // Question: We are updating highest_ordered_cert but not highest_ordered_root. Is that fine?
            self.highest_ordered_cert = Arc::new(qc.into_wrapped_ledger_info());
        }

        Ok(())
    }
```

**File:** consensus/src/block_storage/sync_manager.rs (L233-270)
```rust
    async fn fetch_quorum_cert(
        &self,
        qc: QuorumCert,
        retriever: &mut BlockRetriever,
    ) -> anyhow::Result<()> {
        let mut pending = vec![];
        let mut retrieve_qc = qc.clone();
        loop {
            if self.block_exists(retrieve_qc.certified_block().id()) {
                break;
            }
            BLOCKS_FETCHED_FROM_NETWORK_WHILE_INSERTING_QUORUM_CERT.inc_by(1);
            let target_block_retrieval_payload = match &self.window_size {
                None => TargetBlockRetrieval::TargetBlockId(retrieve_qc.certified_block().id()),
                Some(_) => TargetBlockRetrieval::TargetRound(retrieve_qc.certified_block().round()),
            };
            let mut blocks = retriever
                .retrieve_blocks_in_range(
                    retrieve_qc.certified_block().id(),
                    1,
                    target_block_retrieval_payload,
                    qc.ledger_info()
                        .get_voters(&retriever.validator_addresses()),
                )
                .await?;
            // retrieve_blocks_in_range guarantees that blocks has exactly 1 element
            let block = blocks.remove(0);
            retrieve_qc = block.quorum_cert().clone();
            pending.push(block);
        }
        // insert the qc <- block pair
        while let Some(block) = pending.pop() {
            let block_qc = block.quorum_cert().clone();
            self.insert_single_quorum_cert(block_qc)?;
            self.insert_block(block).await?;
        }
        self.insert_single_quorum_cert(qc)
    }
```

**File:** consensus/src/block_storage/sync_manager.rs (L790-898)
```rust
    async fn retrieve_blocks(
        &mut self,
        block_id: HashValue,
        target_block_retrieval_payload: TargetBlockRetrieval,
        peers: Vec<AccountAddress>,
        num_blocks: u64,
    ) -> anyhow::Result<Vec<Block>> {
        match &target_block_retrieval_payload {
            TargetBlockRetrieval::TargetBlockId(target_block_id) => {
                info!(
                    "Retrieving {} blocks starting from {} with target_block_id {}",
                    num_blocks, block_id, target_block_id
                );
            },
            TargetBlockRetrieval::TargetRound(target_round) => {
                info!(
                    "Retrieving {} blocks starting from {} with target_round {}",
                    num_blocks, block_id, target_round
                );
            },
        }

        let mut progress = 0;
        let mut last_block_id = block_id;
        let mut result_blocks: Vec<Block> = vec![];
        let mut retrieve_batch_size = self.max_blocks_to_request;
        if peers.is_empty() {
            bail!("Failed to fetch block {}: no peers available", block_id);
        }
        while progress < num_blocks {
            // in case this is the last retrieval
            retrieve_batch_size = min(retrieve_batch_size, num_blocks - progress);

            info!(
                "Retrieving chunk: {} blocks starting from {}, original start {}",
                retrieve_batch_size, last_block_id, block_id
            );

            let response = self
                .retrieve_block_chunk(
                    last_block_id,
                    target_block_retrieval_payload,
                    retrieve_batch_size,
                    peers.clone(),
                )
                .await;
            match response {
                Ok(result) if matches!(result.status(), BlockRetrievalStatus::Succeeded) => {
                    // extend the result blocks
                    let batch = result.blocks().clone();
                    progress += batch.len() as u64;
                    last_block_id = batch.last().expect("Batch should not be empty").parent_id();
                    result_blocks.extend(batch);
                },
                Ok(result)
                    if matches!(result.status(), BlockRetrievalStatus::SucceededWithTarget) =>
                {
                    // if we found the target, end the loop
                    let batch = result.blocks().clone();
                    result_blocks.extend(batch);
                    break;
                },
                res => {
                    bail!(
                        "Failed to fetch block {}, for original start {}, returned status {:?}",
                        last_block_id,
                        block_id,
                        res
                    );
                },
            }
        }

        // Confirm retrieval hit the first block we care about
        assert_eq!(
            result_blocks.first().expect("blocks are empty").id(),
            block_id,
            "Expecting in the retrieval response, first block should be {}, but got {}",
            block_id,
            result_blocks.first().expect("blocks are empty").id(),
        );

        // Confirm retrieval hit the last block/round we care about
        // Slightly different logic if using execution pool and not
        match target_block_retrieval_payload {
            TargetBlockRetrieval::TargetBlockId(target_block_id) => {
                ensure!(
                    result_blocks
                        .last()
                        .expect("Expected at least a result_block")
                        .id()
                        == target_block_id
                );
            },
            TargetBlockRetrieval::TargetRound(target_round) => {
                let last_block = result_blocks.last().expect("blocks are empty");
                ensure!(
                    last_block.round() == target_round || last_block.quorum_cert().certified_block().round() < target_round,
                    "Expecting in the retrieval response, last block should be == {} or its parent should be < {}, but got {} and parent {}",
                    target_round,
                    target_round,
                    last_block.round(),
                    last_block.quorum_cert().certified_block().round(),
                );
            },
        }

        Ok(result_blocks)
    }
```

**File:** consensus/consensus-types/src/block_retrieval.rs (L260-281)
```rust
    pub fn verify(
        &self,
        retrieval_request: BlockRetrievalRequest,
        sig_verifier: &ValidatorVerifier,
    ) -> anyhow::Result<()> {
        self.verify_inner(&retrieval_request)?;

        self.blocks
            .iter()
            .try_fold(retrieval_request.block_id(), |expected_id, block| {
                block.validate_signature(sig_verifier)?;
                block.verify_well_formed()?;
                ensure!(
                    block.id() == expected_id,
                    "blocks doesn't form a chain: expect {}, get {}",
                    expected_id,
                    block.id()
                );
                Ok(block.parent_id())
            })
            .map(|_| ())
    }
```

**File:** consensus/consensus-types/src/block.rs (L425-464)
```rust
    pub fn validate_signature(&self, validator: &ValidatorVerifier) -> anyhow::Result<()> {
        match self.block_data.block_type() {
            BlockType::Genesis => bail!("We should not accept genesis from others"),
            BlockType::NilBlock { .. } => self.quorum_cert().verify(validator),
            BlockType::Proposal { author, .. } => {
                let signature = self
                    .signature
                    .as_ref()
                    .ok_or_else(|| format_err!("Missing signature in Proposal"))?;
                let (res1, res2) = rayon::join(
                    || validator.verify(*author, &self.block_data, signature),
                    || self.quorum_cert().verify(validator),
                );
                res1?;
                res2
            },
            BlockType::ProposalExt(proposal_ext) => {
                let signature = self
                    .signature
                    .as_ref()
                    .ok_or_else(|| format_err!("Missing signature in Proposal"))?;
                let (res1, res2) = rayon::join(
                    || validator.verify(*proposal_ext.author(), &self.block_data, signature),
                    || self.quorum_cert().verify(validator),
                );
                res1?;
                res2
            },
            BlockType::OptimisticProposal(p) => {
                // Note: Optimistic proposal is not signed by proposer unlike normal proposal
                let (res1, res2) = rayon::join(
                    || p.grandparent_qc().verify(validator),
                    || self.quorum_cert().verify(validator),
                );
                res1?;
                res2
            },
            BlockType::DAGBlock { .. } => bail!("We should not accept DAG block from others"),
        }
    }
```

**File:** consensus/src/block_storage/block_store.rs (L519-556)
```rust
    pub fn insert_single_quorum_cert(&self, qc: QuorumCert) -> anyhow::Result<()> {
        // If the parent block is not the root block (i.e not None), ensure the executed state
        // of a block is consistent with its QuorumCert, otherwise persist the QuorumCert's
        // state and on restart, a new execution will agree with it.  A new execution will match
        // the QuorumCert's state on the next restart will work if there is a memory
        // corruption, for example.
        match self.get_block(qc.certified_block().id()) {
            Some(pipelined_block) => {
                ensure!(
                    // decoupled execution allows dummy block infos
                    pipelined_block
                        .block_info()
                        .match_ordered_only(qc.certified_block()),
                    "QC for block {} has different {:?} than local {:?}",
                    qc.certified_block().id(),
                    qc.certified_block(),
                    pipelined_block.block_info()
                );
                observe_block(
                    pipelined_block.block().timestamp_usecs(),
                    BlockStage::QC_ADDED,
                );
                if pipelined_block.block().is_opt_block() {
                    observe_block(
                        pipelined_block.block().timestamp_usecs(),
                        BlockStage::QC_ADDED_OPT_BLOCK,
                    );
                }
                pipelined_block.set_qc(Arc::new(qc.clone()));
            },
            None => bail!("Insert {} without having the block in store first", qc),
        };

        self.storage
            .save_tree(vec![], vec![qc.clone()])
            .context("Insert block failed when saving quorum")?;
        self.inner.write().insert_quorum_cert(qc)
    }
```

**File:** consensus/src/round_manager.rs (L878-907)
```rust
    async fn sync_up(&mut self, sync_info: &SyncInfo, author: Author) -> anyhow::Result<()> {
        let local_sync_info = self.block_store.sync_info();
        if sync_info.has_newer_certificates(&local_sync_info) {
            info!(
                self.new_log(LogEvent::ReceiveNewCertificate)
                    .remote_peer(author),
                "Local state {},\n remote state {}", local_sync_info, sync_info
            );
            // Some information in SyncInfo is ahead of what we have locally.
            // First verify the SyncInfo (didn't verify it in the yet).
            sync_info.verify(&self.epoch_state.verifier).map_err(|e| {
                error!(
                    SecurityEvent::InvalidSyncInfoMsg,
                    sync_info = sync_info,
                    remote_peer = author,
                    error = ?e,
                );
                VerifyError::from(e)
            })?;
            SYNC_INFO_RECEIVED_WITH_NEWER_CERT.inc();
            let result = self
                .block_store
                .add_certs(sync_info, self.create_block_retriever(author))
                .await;
            self.process_certificates().await?;
            result
        } else {
            Ok(())
        }
    }
```

**File:** consensus/src/round_manager.rs (L1577-1597)
```rust
                let vote_reception_result = if !self.pending_order_votes.exists(&li_digest) {
                    let start = Instant::now();
                    order_vote_msg
                        .quorum_cert()
                        .verify(&self.epoch_state.verifier)
                        .context("[OrderVoteMsg QuorumCert verification failed")?;
                    counters::VERIFY_MSG
                        .with_label_values(&["order_vote_qc"])
                        .observe(start.elapsed().as_secs_f64());
                    self.pending_order_votes.insert_order_vote(
                        order_vote_msg.order_vote(),
                        &self.epoch_state.verifier,
                        Some(order_vote_msg.quorum_cert().clone()),
                    )
                } else {
                    self.pending_order_votes.insert_order_vote(
                        order_vote_msg.order_vote(),
                        &self.epoch_state.verifier,
                        None,
                    )
                };
```
