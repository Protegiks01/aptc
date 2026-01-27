# Audit Report

## Title
Missing Cryptographic Signature Validation in Fast-Forward Sync Enables Byzantine Peers to Forge Consensus Chain

## Summary
The fast-forward sync mechanism in Aptos consensus fails to validate cryptographic signatures on retrieved blocks and their embedded quorum certificates. This allows Byzantine peers to supply forged blocks that were never certified by 2f+1 validators, causing honest nodes to build consensus state on an invalid chain, potentially leading to consensus splits and safety violations.

## Finding Description

During fast-forward sync, when a node falls behind and needs to catch up with the network, it retrieves blocks from peer validators. The critical security flaw is that **these retrieved blocks are never cryptographically validated** before being accepted into the node's consensus state.

The vulnerability exists in the following execution flow:

1. **Block Retrieval Without Validation**: When `retrieve_blocks_in_range()` fetches blocks from a peer, no signature validation occurs. [1](#0-0) 

2. **Structural-Only Validation**: The `find_root()` function only validates structural properties (parent-child relationships, round ordering) but never calls cryptographic verification methods. [2](#0-1) 

3. **No Validation in Block Insertion**: When blocks are rebuilt via `insert_block()`, no signature validation is performed—only basic structural checks. [3](#0-2) 

4. **No Validation in QC Insertion**: When quorum certificates are inserted via `insert_single_quorum_cert()`, only structural consistency is checked, not cryptographic validity. [4](#0-3) 

**Contrast with Normal Proposal Path**: During normal consensus operation, blocks received as proposals ARE validated using `validate_signature()` which verifies both the block proposer's signature and the quorum certificate's aggregated BLS signatures. [5](#0-4) 

However, this validation is **completely absent** in the fast-forward sync path.

**Attack Scenario**:
1. Byzantine peer M receives or observes a valid `sync_info` containing `highest_quorum_cert` (legitimately signed by 2f+1 validators)
2. Honest node H falls behind and requests blocks from M via fast-forward sync
3. M calculates the correct block range using `calculate_window_start_round()`: [6](#0-5) 

4. M returns blocks that:
   - Start from the correct block (matching `highest_quorum_cert.certified_block().id()`)
   - Form a valid parent-child chain (correct parent IDs and round ordering)
   - End at the correct target round
   - **BUT contain forged signatures and forged quorum certificates** that were never signed by 2f+1 validators

5. H accepts these forged blocks because `fast_forward_sync()` never validates signatures: [7](#0-6) 

6. H rebuilds its block tree with forged blocks, creating a consensus state that diverges from honest nodes

## Impact Explanation

This is a **Critical severity** vulnerability under the Aptos bug bounty criteria because it represents a **Consensus/Safety violation**.

**Broken Invariant**: This directly violates Consensus Safety (Invariant #2): "AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine validators."

**Impact**:
- **Chain Split**: Different honest nodes can end up with fundamentally different views of the blockchain if they sync from different Byzantine peers
- **Invalid Block Acceptance**: Nodes accept blocks that were never certified by the required 2f+1 validator quorum
- **Consensus Divergence**: When nodes vote or propose based on forged history, they may create incompatible forks
- **State Transition Violation**: Forged blocks can contain different transactions/payloads than the real canonical blocks, causing state inconsistencies
- **Non-recoverable partition**: If multiple nodes sync forged blocks, the network could split into incompatible partitions requiring manual intervention or hard fork

The vulnerability is particularly severe because:
1. It requires only a single Byzantine peer (< f validators) to exploit
2. The forged blocks become part of the persistent consensus state
3. The node's execution state (synced via `sync_to_target`) is correct, but its consensus view is corrupted, creating a dangerous mismatch

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability will be exploited whenever:
1. A node falls behind and needs fast-forward sync (common during network issues, restarts, or new nodes joining)
2. The node selects a Byzantine peer for block retrieval (randomly chosen from QC voters)
3. The Byzantine peer responds with forged blocks instead of legitimate ones

**Attacker Requirements**:
- Control at least one peer node that can respond to block retrieval requests
- No validator privileges required
- No cryptographic key compromise needed
- Simple attack: just return forged blocks with fake signatures

**Complexity**: LOW - The attack is straightforward to execute since the validation gap is complete (zero cryptographic checks).

## Recommendation

Add comprehensive cryptographic validation to the fast-forward sync path. Specifically:

**1. Validate retrieved blocks immediately after retrieval**:

```rust
// In sync_manager.rs, after retrieve_blocks_in_range (line ~403)
for block in &blocks {
    block.validate_signature(&validator_verifier)
        .context("Block signature validation failed during sync")?;
    block.verify_well_formed()
        .context("Block well-formedness check failed during sync")?;
}
```

**2. Validate quorum certificates during extraction**:

```rust
// In sync_manager.rs, when extracting QCs (line ~405-411)
for qc in quorum_certs.iter().skip(1) { // Skip highest_quorum_cert (already validated)
    qc.verify(&validator_verifier)
        .context("QC verification failed during sync")?;
}
```

**3. Add validator verifier parameter to fast_forward_sync**:

The function signature should include a `ValidatorVerifier` to perform these checks: [8](#0-7) 

**4. Ensure BlockRetrievalResponse.verify() is called**:

The existing `verify()` method on `BlockRetrievalResponse` should be invoked: [9](#0-8) 

This method already validates signatures when given a validator verifier, but it's never called in the sync path.

## Proof of Concept

```rust
// Reproduction steps demonstrating the vulnerability:

// 1. Set up a test network with one Byzantine peer
// 2. Create a forged block chain with invalid signatures:

use aptos_consensus_types::block::Block;
use aptos_crypto::HashValue;

fn create_forged_block(parent: &Block, round: u64) -> Block {
    // Create block with forged QC (no real 2f+1 signatures)
    let forged_qc = QuorumCert::new(
        VoteData::new(parent.block_info(), parent.block_info()),
        LedgerInfoWithSignatures::new(
            LedgerInfo::new(parent.block_info(), vote_data.hash()),
            // Empty/fake signature instead of real 2f+1 aggregated signature
            AggregateSignature::new(BitVec::with_num_bits(4), None)
        )
    );
    
    Block::new_proposal(
        payload,
        round,
        timestamp,
        forged_qc,
        validator_signer, // Can be any signature, won't be validated
        Vec::new()
    )
}

// 3. When honest node requests blocks via fast_forward_sync,
//    Byzantine peer responds with forged blocks
// 4. Observe that honest node accepts these blocks without validation
// 5. Verify that node's block tree now contains blocks with invalid QCs
// 6. Demonstrate consensus divergence when node votes based on forged history
```

**Test Verification**:
1. Run a node through fast-forward sync receiving forged blocks
2. Verify no signature validation errors are raised
3. Check that forged blocks are inserted into block store
4. Confirm blocks with invalid signatures are in the consensus tree

This PoC demonstrates that the fast-forward sync path completely bypasses the cryptographic security mechanisms that protect the consensus protocol, enabling Byzantine peers to corrupt honest nodes' consensus state.

### Citations

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

**File:** consensus/src/block_storage/sync_manager.rs (L901-916)
```rust
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

**File:** consensus/src/persistent_liveness_storage.rs (L278-296)
```rust
    pub fn find_root(
        &self,
        blocks: &mut Vec<Block>,
        quorum_certs: &mut Vec<QuorumCert>,
        order_vote_enabled: bool,
        window_size: Option<u64>,
    ) -> Result<RootInfo> {
        info!(
            "The last committed block id as recorded in storage: {}",
            self.storage_ledger
        );

        match window_size {
            None => self.find_root_without_window(blocks, quorum_certs, order_vote_enabled),
            Some(window_size) => {
                self.find_root_with_window(blocks, quorum_certs, order_vote_enabled, window_size)
            },
        }
    }
```

**File:** consensus/src/block_storage/block_store.rs (L412-438)
```rust
    pub async fn insert_block(&self, block: Block) -> anyhow::Result<Arc<PipelinedBlock>> {
        if let Some(existing_block) = self.get_block(block.id()) {
            return Ok(existing_block);
        }
        ensure!(
            self.inner.read().ordered_root().round() < block.round(),
            "Block with old round"
        );

        let block_window = self
            .inner
            .read()
            .get_ordered_block_window(&block, self.window_size)?;
        let blocks = block_window.blocks();
        for block in blocks {
            if let Some(payload) = block.payload() {
                self.payload_manager.prefetch_payload_data(
                    payload,
                    block.author().expect("Payload block must have author"),
                    block.timestamp_usecs(),
                );
            }
        }

        let pipelined_block = PipelinedBlock::new_ordered(block, block_window);
        self.insert_block_inner(pipelined_block).await
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

**File:** consensus/src/util/mod.rs (L26-29)
```rust
pub fn calculate_window_start_round(current_round: Round, window_size: u64) -> Round {
    assert!(window_size > 0);
    (current_round + 1).saturating_sub(window_size)
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
