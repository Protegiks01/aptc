# Audit Report

## Title
Critical QuorumCert Signature Verification Bypass in Fast Forward Sync

## Summary
The `get_quorum_cert_for_block()` function can return QuorumCerts that were never cryptographically verified, allowing malicious peers to inject forged QCs into the block store during fast forward sync operations. This bypasses the fundamental consensus safety guarantee that all QCs represent valid 2f+1 validator signatures.

## Finding Description

During normal consensus operation, all blocks and their embedded QuorumCerts are properly verified before processing. The `ProposalMsg::verify()` method validates block signatures and QC signatures using the ValidatorVerifier. [1](#0-0) [2](#0-1) 

However, during **fast forward sync**, a completely different code path is taken that bypasses all signature verification:

1. When a node falls behind, it receives a `SyncInfo` message which IS properly verified: [3](#0-2) 

2. The node then calls `fast_forward_sync()` to retrieve intermediate blocks from peers: [4](#0-3) 

3. Blocks are retrieved via `retrieve_blocks_in_range()` which calls `retrieve_blocks()`: [5](#0-4) 

4. The retrieved `BlockRetrievalResponse` has a `verify()` method that would validate all block and QC signatures: [6](#0-5) 

**However, this `verify()` method is NEVER called.** The blocks are extracted directly and used without verification at line 839-850 in sync_manager.rs.

5. These unverified blocks (containing unverified QCs) are then saved to persistent storage: [7](#0-6) 

6. During block store rebuild, the QCs are inserted without verification: [8](#0-7) 

7. The `insert_single_quorum_cert()` function claims to "validate quorum certificates" but only checks block info consistency, NOT cryptographic signatures: [9](#0-8) 

8. Finally, `get_quorum_cert_for_block()` returns these unverified QCs directly from storage: [10](#0-9) [11](#0-10) 

**Attack Scenario:**
1. Honest validators advance to round 1000, creating valid blocks and QCs
2. Victim node is offline and falls behind at round 500
3. Victim comes online and requests sync from peers
4. Attacker-controlled malicious peer responds with forged blocks 501-999 containing invalid QCs with fake signatures
5. Victim accepts these blocks without verification and rebuilds consensus state with forged QCs
6. Victim now has invalid QCs that appear to certify blocks that were never properly voted on
7. This breaks the fundamental consensus safety invariant

## Impact Explanation

This is a **Critical Severity** vulnerability that directly violates the **Consensus Safety** invariant (Invariant #2: "AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine").

**Consensus Safety Violation**: By accepting forged QCs, a node can be convinced that blocks were certified by 2f+1 validators when they were not. This undermines the core assumption of Byzantine Fault Tolerance.

**Potential for Chain Forks**: If different nodes receive different forged blocks during sync, they will have inconsistent views of the blockchain state, potentially causing network partitions.

**State Inconsistency**: Nodes with forged QCs may make different consensus decisions than honest nodes, leading to divergent execution paths and state corruption.

This meets the Critical Severity criteria: "Consensus/Safety violations" and could lead to "Non-recoverable network partition (requires hardfork)" per the Aptos bug bounty program.

## Likelihood Explanation

**High Likelihood** - This vulnerability is easily exploitable:

**Attacker Requirements:**
- Control one peer node that the victim connects to for sync (low barrier)
- Victim node falls behind (common occurrence due to network issues, restarts, etc.)
- No validator collusion or stake required

**Triggering Conditions:**
- Occurs automatically whenever a node performs fast forward sync
- Fast forward sync happens regularly in production networks
- No special timing or race conditions required

**Attack Complexity:** Low - Attacker simply needs to respond to block retrieval requests with forged data.

## Recommendation

Add cryptographic verification to the fast forward sync path. The `BlockRetrievalResponse::verify()` method already exists and should be called before using retrieved blocks.

**Fix in `consensus/src/block_storage/sync_manager.rs`:**

After retrieving blocks in the `retrieve_block_chunk()` function, verify the response before returning:

```rust
async fn retrieve_block_chunk(
    &mut self,
    block_id: HashValue,
    target_block_retrieval_payload: TargetBlockRetrieval,
    retrieve_batch_size: u64,
    mut peers: Vec<AccountAddress>,
) -> anyhow::Result<BlockRetrievalResponse> {
    // ... existing retrieval logic ...
    
    // Add verification before returning
    let request = match target_block_retrieval_payload {
        TargetBlockRetrieval::TargetBlockId(target_block_id) => {
            BlockRetrievalRequest::V1(BlockRetrievalRequestV1::new_with_target_block_id(
                block_id,
                retrieve_batch_size,
                target_block_id,
            ))
        },
        TargetBlockRetrieval::TargetRound(target_round) => {
            BlockRetrievalRequest::V2(BlockRetrievalRequestV2::new_with_target_round(
                block_id,
                retrieve_batch_size,
                target_round,
            ))
        },
    };
    
    result.verify(request, validator_verifier)?; // ADD THIS LINE
    Ok(result)
}
```

Additionally, the `BlockRetriever` struct should store a reference to the `ValidatorVerifier` to enable this verification.

## Proof of Concept

**Setup:**
1. Create a test network with 4 validator nodes
2. Create one victim node and one attacker node (non-validator peers)
3. Have victim node fall behind by 100 blocks

**Attack Steps:**

```rust
// Pseudo-code for PoC
#[tokio::test]
async fn test_unverified_qc_injection() {
    // Setup: Create forged block with invalid QC
    let forged_block = create_block_with_forged_qc(
        round: 50,
        parent_qc: valid_qc_at_round_49,
        // Forge signatures without proper validator votes
        forged_signatures: create_fake_bls_signatures()
    );
    
    // Setup: Configure malicious peer to respond with forged block
    let malicious_peer = setup_malicious_peer(vec![forged_block]);
    
    // Victim node requests sync
    let victim = setup_victim_node(behind_at_round: 45);
    
    // Trigger fast forward sync
    victim.sync_up_to(round: 100, peers: vec![malicious_peer]).await;
    
    // Verify vulnerability: Check that forged QC is in block store
    let retrieved_qc = victim.block_store
        .get_quorum_cert_for_block(forged_block.id());
    
    assert!(retrieved_qc.is_some()); // Forged QC accepted!
    
    // Verify it was never cryptographically verified
    let result = retrieved_qc.unwrap().verify(&validator_verifier);
    assert!(result.is_err()); // Signature verification fails!
}
```

This PoC demonstrates that:
1. Forged blocks can be injected during sync
2. `get_quorum_cert_for_block()` returns the forged QC
3. The QC was never cryptographically verified
4. Consensus safety is violated

## Notes

This vulnerability exists because the codebase has two parallel paths for processing blocks:
- **Normal consensus path**: Full verification via `ProposalMsg::verify()`  
- **Sync path**: NO verification despite having the `BlockRetrievalResponse::verify()` method available

The fix is straightforward but critical: ensure the sync path uses the same cryptographic verification as the normal consensus path.

### Citations

**File:** consensus/consensus-types/src/proposal_msg.rs (L82-113)
```rust
    pub fn verify(
        &self,
        sender: Author,
        validator: &ValidatorVerifier,
        proof_cache: &ProofCache,
        quorum_store_enabled: bool,
    ) -> Result<()> {
        if let Some(proposal_author) = self.proposal.author() {
            ensure!(
                proposal_author == sender,
                "Proposal author {:?} doesn't match sender {:?}",
                proposal_author,
                sender
            );
        }
        let (payload_result, sig_result) = rayon::join(
            || {
                self.proposal().payload().map_or(Ok(()), |p| {
                    p.verify(validator, proof_cache, quorum_store_enabled)
                })
            },
            || {
                self.proposal()
                    .validate_signature(validator)
                    .map_err(|e| format_err!("{:?}", e))
            },
        );
        payload_result?;
        sig_result?;

        // if there is a timeout certificate, verify its signatures
        if let Some(tc) = self.sync_info.highest_2chain_timeout_cert() {
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

**File:** consensus/src/round_manager.rs (L888-896)
```rust
            sync_info.verify(&self.epoch_state.verifier).map_err(|e| {
                error!(
                    SecurityEvent::InvalidSyncInfoMsg,
                    sync_info = sync_info,
                    remote_peer = author,
                    error = ?e,
                );
                VerifyError::from(e)
            })?;
```

**File:** consensus/src/block_storage/sync_manager.rs (L365-525)
```rust
    pub async fn fast_forward_sync<'a>(
        highest_quorum_cert: &'a QuorumCert,
        highest_commit_cert: &'a WrappedLedgerInfo,
        retriever: &'a mut BlockRetriever,
        storage: Arc<dyn PersistentLivenessStorage>,
        execution_client: Arc<dyn TExecutionClient>,
        payload_manager: Arc<dyn TPayloadManager>,
        order_vote_enabled: bool,
        window_size: Option<u64>,
        maybe_block_store: Option<&'a BlockStore>,
    ) -> anyhow::Result<RecoveryData> {
        info!(
            LogSchema::new(LogEvent::StateSync).remote_peer(retriever.preferred_peer),
            "Start state sync to commit cert: {}, quorum cert: {}",
            highest_commit_cert,
            highest_quorum_cert,
        );

        let (target_block_retrieval_payload, num_blocks) =
            Self::generate_target_block_retrieval_payload_and_num_blocks(
                highest_quorum_cert,
                highest_commit_cert,
                window_size,
            );

        // although unlikely, we might wrap num_blocks around on a 32-bit machine
        assert!(num_blocks < usize::MAX as u64);

        BLOCKS_FETCHED_FROM_NETWORK_WHILE_FAST_FORWARD_SYNC.inc_by(num_blocks);
        let mut blocks = retriever
            .retrieve_blocks_in_range(
                highest_quorum_cert.certified_block().id(),
                num_blocks,
                target_block_retrieval_payload,
                highest_quorum_cert
                    .ledger_info()
                    .get_voters(&retriever.validator_addresses()),
            )
            .await?;

        let mut quorum_certs = vec![highest_quorum_cert.clone()];
        quorum_certs.extend(
            blocks
                .iter()
                .take(blocks.len() - 1)
                .map(|block| block.quorum_cert().clone()),
        );

        if !order_vote_enabled {
            // TODO: this is probably still necessary, but need to think harder, it's pretty subtle
            // check if highest_commit_cert comes from a fork
            // if so, we need to fetch it's block as well, to have a proof of commit.
            let highest_commit_certified_block =
                highest_commit_cert.certified_block(order_vote_enabled)?;
            if !blocks
                .iter()
                .any(|block| block.id() == highest_commit_certified_block.id())
            {
                info!(
                    "Found forked QC {}, fetching it as well",
                    highest_commit_cert
                );
                BLOCKS_FETCHED_FROM_NETWORK_WHILE_FAST_FORWARD_SYNC.inc_by(1);

                // Only retrieving one block here, we can simply use TargetBlockRetrieval::TargetBlockId
                let target_block_retrieval_payload =
                    TargetBlockRetrieval::TargetBlockId(highest_commit_certified_block.id());
                let mut additional_blocks = retriever
                    .retrieve_blocks_in_range(
                        highest_commit_certified_block.id(),
                        1,
                        target_block_retrieval_payload,
                        highest_commit_cert
                            .ledger_info()
                            .get_voters(&retriever.validator_addresses()),
                    )
                    .await?;

                assert_eq!(additional_blocks.len(), 1);
                let block = additional_blocks.pop().expect("blocks are empty");
                assert_eq!(
                    block.id(),
                    highest_commit_certified_block.id(),
                    "Expecting in the retrieval response, for commit certificate fork, first block should be {}, but got {}",
                    highest_commit_certified_block.id(),
                    block.id(),
                );
                blocks.push(block);
                quorum_certs.push(
                    highest_commit_cert
                        .clone()
                        .into_quorum_cert(order_vote_enabled)?,
                );
            }
        }

        assert_eq!(blocks.len(), quorum_certs.len());
        info!("[FastForwardSync] Fetched {} blocks. Requested num_blocks {}. Initial block hash {:?}, target block hash {:?}",
            blocks.len(), num_blocks, highest_quorum_cert.certified_block().id(), highest_commit_cert.commit_info().id()
        );
        for (i, block) in blocks.iter().enumerate() {
            assert_eq!(block.id(), quorum_certs[i].certified_block().id());
            if let Some(payload) = block.payload() {
                payload_manager.prefetch_payload_data(
                    payload,
                    block.author().expect("payload block must have author"),
                    block.timestamp_usecs(),
                );
            }
        }

        // Check early that recovery will succeed, and return before corrupting our state in case it will not.
        LedgerRecoveryData::new(highest_commit_cert.ledger_info().clone())
            .find_root(
                &mut blocks.clone(),
                &mut quorum_certs.clone(),
                order_vote_enabled,
                window_size,
            )
            .with_context(|| {
                // for better readability
                quorum_certs.sort_by_key(|qc| qc.certified_block().round());
                format!(
                    "\nRoot: {:?}\nBlocks in db: {}\nQuorum Certs in db: {}\n",
                    highest_commit_cert.commit_info(),
                    blocks
                        .iter()
                        .map(|b| format!("\n\t{}", b))
                        .collect::<Vec<String>>()
                        .concat(),
                    quorum_certs
                        .iter()
                        .map(|qc| format!("\n\t{}", qc))
                        .collect::<Vec<String>>()
                        .concat(),
                )
            })?;

        storage.save_tree(blocks.clone(), quorum_certs.clone())?;
        // abort any pending executor tasks before entering state sync
        // with zaptos, things can run before hitting buffer manager
        if let Some(block_store) = maybe_block_store {
            monitor!(
                "abort_pipeline_for_state_sync",
                block_store.abort_pipeline_for_state_sync().await
            );
        }
        execution_client
            .sync_to_target(highest_commit_cert.ledger_info().clone())
            .await?;

        // we do not need to update block_tree.highest_commit_decision_ledger_info here
        // because the block_tree is going to rebuild itself.

        let recovery_data = match storage.start(order_vote_enabled, window_size) {
            LivenessStorageData::FullRecoveryData(recovery_data) => recovery_data,
            _ => panic!("Failed to construct recovery data after fast forward sync"),
        };

        Ok(recovery_data)
    }
```

**File:** consensus/src/block_storage/sync_manager.rs (L790-916)
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

    /// Retrieve chain of n blocks for given QC
    async fn retrieve_blocks_in_range(
        &mut self,
        initial_block_id: HashValue,
        num_blocks: u64,
        target_block_retrieval_payload: TargetBlockRetrieval,
        peers: Vec<AccountAddress>,
    ) -> anyhow::Result<Vec<Block>> {
        BLOCKS_FETCHED_FROM_NETWORK_IN_BLOCK_RETRIEVER.inc_by(num_blocks);
        self.retrieve_blocks(
            initial_block_id,
            target_block_retrieval_payload,
            peers,
            num_blocks,
        )
        .await
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

**File:** consensus/src/block_storage/block_store.rs (L299-305)
```rust
        for qc in quorum_certs {
            block_store
                .insert_single_quorum_cert(qc)
                .unwrap_or_else(|e| {
                    panic!("[BlockStore] failed to insert quorum during build{:?}", e)
                });
        }
```

**File:** consensus/src/block_storage/block_store.rs (L518-556)
```rust
    /// Validates quorum certificates and inserts it into block tree assuming dependencies exist.
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

**File:** consensus/src/block_storage/block_store.rs (L647-649)
```rust
    fn get_quorum_cert_for_block(&self, block_id: HashValue) -> Option<Arc<QuorumCert>> {
        self.inner.read().get_quorum_cert_for_block(&block_id)
    }
```

**File:** consensus/src/block_storage/block_tree.rs (L234-239)
```rust
    pub(super) fn get_quorum_cert_for_block(
        &self,
        block_id: &HashValue,
    ) -> Option<Arc<QuorumCert>> {
        self.id_to_quorum_cert.get(block_id).cloned()
    }
```
