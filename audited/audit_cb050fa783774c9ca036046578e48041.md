# Audit Report

## Title
Validator Consensus Participation with Corrupted Blocks Due to Missing Validation During Recovery

## Summary
When a validator restarts and recovers state from ConsensusDB, blocks loaded from persistent storage are not validated for signature correctness or data integrity. The `find_root()` method only performs structural checks (block IDs, QC existence, parent relationships) without cryptographic verification. If blocks with corrupted signatures are loaded, the validator starts in normal mode and participates in consensus with unvalidated blocks, potentially causing consensus divergence if multiple validators experience different corruption patterns.

## Finding Description

During consensus recovery, blocks are retrieved from ConsensusDB and processed to reconstruct consensus state. The recovery flow in `StorageWriteProxy::start()` loads blocks and quorum certificates from the database, then attempts to construct `RecoveryData` by calling `RecoveryData::new()`. [1](#0-0) 

If `RecoveryData::new()` succeeds, it returns `LivenessStorageData::FullRecoveryData`, causing the validator to start `RoundManager` in normal mode. If it fails, the system falls back to `PartialRecoveryData` and enters recovery mode. [2](#0-1) 

The critical security gap exists in the `find_root()` method called by `RecoveryData::new()`. This method only validates structural consistency: [3](#0-2) 

Examining `find_root_without_window()` reveals it only checks:
1. A block with the expected ID exists in the blocks vector (line 233-236)
2. A QC exists for that block (line 238-242)
3. Parent relationships during window traversal [4](#0-3) 

**No signature validation, timestamp verification, or cryptographic integrity checks are performed.**

When blocks are deserialized from the database, the custom `Deserialize` implementation only recomputes the block ID from block_data without any validation: [5](#0-4) 

The recovered blocks are then inserted into BlockStore during the `build()` process without validation: [6](#0-5) 

Neither `insert_block()` nor `insert_committed_block()` perform signature or data integrity validation: [7](#0-6) 

**This contrasts sharply with network-received blocks**, which undergo rigorous validation. When a proposal is received from the network, `ProposalMsg::verify()` explicitly calls `validate_signature()`: [8](#0-7) 

The `Block::validate_signature()` method performs comprehensive cryptographic verification: [9](#0-8) 

Similarly, `QuorumCert::verify()` validates QC signatures: [10](#0-9) 

**The Vulnerability:** If ConsensusDB becomes corrupted through disk failure, power loss, or software bugs such that:
- Block signature bytes are corrupted (signature is stored separately from block_data)
- OR QuorumCert signature bytes are corrupted
- BUT block IDs and structural integrity remain intact

Then:
1. `find_root()` succeeds because it only checks IDs and structure
2. `RecoveryData::new()` succeeds and returns `FullRecoveryData`
3. Validator starts in normal consensus mode (not recovery mode)
4. Corrupted blocks with invalid signatures are inserted into BlockStore
5. Validator participates in consensus with cryptographically unverified blocks

This violates the fundamental consensus security invariant that all blocks must be cryptographically verified before being trusted.

## Impact Explanation

**Critical Severity** - This vulnerability can cause consensus safety violations and network partitions under the following scenarios:

**Consensus Safety Violations**: If multiple validators independently experience database corruption affecting different blocks' signatures, they will have divergent views of which blocks are valid. When these validators participate in consensus, they may vote on or propose blocks that other validators reject due to signature mismatches. This breaks the AptosBFT safety guarantee that all honest validators agree on the committed chain.

**Byzantine Behavior by Honest Nodes**: A validator with corrupted block signatures becomes effectively Byzantine despite being operated honestly. It will reference blocks with invalid signatures in its consensus messages, causing other validators to reject its proposals and votes. If multiple validators experience this, the network may fail to achieve quorum.

**Non-recoverable Network Partition**: If a significant portion of validators (but less than 1/3) recover with different signature corruptions, the network may enter a state where different subsets of validators cannot agree on block validity. While the >2/3 honest threshold provides safety, systematic corruption across validators (e.g., from a common software bug in the storage layer) could create an unrecoverable partition requiring manual intervention or a hard fork.

**QC Signature Corruption Impact**: If QuorumCert signatures are corrupted during recovery, the validator will have QCs that fail verification. This is particularly severe because QCs are the consensus mechanism's proof of agreement. Invalid QCs prevent proper chain extension and commit decisions.

This aligns with the Aptos Bug Bounty Critical severity criteria for "Consensus/Safety Violations" and "Non-recoverable Network Partition (requires hardfork)".

## Likelihood Explanation

**Likelihood: Medium**

This vulnerability can be triggered through several realistic scenarios:

1. **Disk Corruption**: Hardware failures, bad sectors, or filesystem corruption can selectively corrupt database files. RocksDB (used by ConsensusDB) stores data in SST files that could experience partial corruption affecting signature bytes while preserving block_data integrity.

2. **Power Loss During Write**: If a validator loses power while persisting blocks, partially written data may result in corrupted signatures. The block_data might be intact (correct ID) but signature bytes corrupted.

3. **Software Bugs**: Bugs in the consensus DB write path, BCS serialization, or RocksDB integration could write malformed signature data that passes deserialization but fails cryptographic verification.

4. **Database Version Mismatch**: Upgrades or downgrades of RocksDB or serialization formats could cause signature field corruption while preserving structural data.

The vulnerability requires corruption patterns that preserve block IDs (which are hashes of block_data) while corrupting separate signature fields. This is more likely than complete database corruption because:
- Signatures are stored as separate fields from block_data
- Partial corruption often affects byte ranges rather than entire structures
- Modern storage systems have error correction that may preserve some fields while corrupting others

However, this is not a "high" likelihood because it requires specific corruption patterns rather than general database failure.

## Recommendation

Add comprehensive cryptographic validation during consensus recovery. The `RecoveryData::new()` method should validate all blocks and quorum certificates before accepting them:

```rust
pub fn new(
    last_vote: Option<Vote>,
    ledger_recovery_data: LedgerRecoveryData,
    mut blocks: Vec<Block>,
    root_metadata: RootMetadata,
    mut quorum_certs: Vec<QuorumCert>,
    highest_2chain_timeout_cert: Option<TwoChainTimeoutCertificate>,
    order_vote_enabled: bool,
    window_size: Option<u64>,
    validator_verifier: &ValidatorVerifier, // Add validator verifier parameter
) -> Result<Self> {
    // Validate all blocks BEFORE calling find_root
    for block in &blocks {
        block.validate_signature(validator_verifier)
            .with_context(|| format!("Failed to validate block {} during recovery", block.id()))?;
        block.verify_well_formed()
            .with_context(|| format!("Block {} is not well-formed during recovery", block.id()))?;
    }
    
    // Validate all QCs
    for qc in &quorum_certs {
        qc.verify(validator_verifier)
            .with_context(|| format!("Failed to verify QC for block {} during recovery", qc.certified_block().id()))?;
    }
    
    // Validate timeout certificate if present
    if let Some(tc) = &highest_2chain_timeout_cert {
        tc.verify(validator_verifier)
            .with_context(|| "Failed to verify timeout certificate during recovery")?;
    }
    
    // Now proceed with find_root knowing all blocks are cryptographically valid
    let root = ledger_recovery_data.find_root(
        &mut blocks,
        &mut quorum_certs,
        order_vote_enabled,
        window_size,
    )?;
    
    // ... rest of the method
}
```

The `StorageWriteProxy::start()` method should be updated to pass the validator verifier and handle validation failures by entering recovery mode:

```rust
fn start(&self, order_vote_enabled: bool, window_size: Option<u64>) -> LivenessStorageData {
    // ... existing code to load blocks and QCs ...
    
    let validator_verifier = /* obtain from epoch state */;
    
    match RecoveryData::new(
        last_vote,
        ledger_recovery_data.clone(),
        blocks,
        accumulator_summary.into(),
        quorum_certs,
        highest_2chain_timeout_cert,
        order_vote_enabled,
        window_size,
        &validator_verifier,
    ) {
        Ok(mut initial_data) => {
            // ... existing code ...
            LivenessStorageData::FullRecoveryData(initial_data)
        },
        Err(e) => {
            error!(error = ?e, "Failed to construct recovery data, entering recovery mode");
            LivenessStorageData::PartialRecoveryData(ledger_recovery_data)
        },
    }
}
```

This ensures that if any blocks have invalid signatures due to corruption, the validator will enter recovery mode and re-sync from the network rather than participating in consensus with unvalidated data.

## Proof of Concept

A proof of concept would require:

1. Setting up a validator node with ConsensusDB
2. Persisting valid blocks with correct signatures
3. Manually corrupting the signature bytes in the RocksDB files (e.g., using a hex editor to modify signature field bytes)
4. Restarting the validator and observing that it starts in normal mode despite corrupted signatures
5. Demonstrating that the validator participates in consensus with these unvalidated blocks

The core issue can be demonstrated by code inspection showing that `find_root()` and the recovery insertion path never call `Block::validate_signature()` or `QuorumCert::verify()`, while the network path always does.

## Notes

**Technical Clarification**: The vulnerability specifically affects the **signature field** corruption, not block_data corruption. If timestamps, epochs, or payload within block_data are corrupted, the block ID (which is the hash of block_data) would change, causing `find_root()` to fail. The vulnerability exists because signatures are stored separately from the data they sign, allowing selective corruption.

**BFT Resilience**: Single validator corruption is handled by Aptos BFT's >2/3 honest threshold. The critical threat is systematic corruption affecting multiple validators (e.g., from a common storage bug) or coordinated corruption patterns that could cause consensus divergence.

**Threat Model Note**: While the report mentions "malicious file modification," validator operators are trusted roles per the Aptos threat model. However, the non-malicious scenarios (disk corruption, power loss, software bugs) are sufficient to demonstrate exploitability without trusted role compromise.

### Citations

**File:** consensus/src/persistent_liveness_storage.rs (L203-272)
```rust
    pub fn find_root_without_window(
        &self,
        blocks: &mut Vec<Block>,
        quorum_certs: &mut Vec<QuorumCert>,
        order_vote_enabled: bool,
    ) -> Result<RootInfo> {
        // We start from the block that storage's latest ledger info, if storage has end-epoch
        // LedgerInfo, we generate the virtual genesis block
        let (root_id, latest_ledger_info_sig) = if self.storage_ledger.ledger_info().ends_epoch() {
            let genesis =
                Block::make_genesis_block_from_ledger_info(self.storage_ledger.ledger_info());
            let genesis_qc = QuorumCert::certificate_for_genesis_from_ledger_info(
                self.storage_ledger.ledger_info(),
                genesis.id(),
            );
            let genesis_ledger_info = genesis_qc.ledger_info().clone();
            let genesis_id = genesis.id();
            blocks.push(genesis);
            quorum_certs.push(genesis_qc);
            (genesis_id, genesis_ledger_info)
        } else {
            (
                self.storage_ledger.ledger_info().consensus_block_id(),
                self.storage_ledger.clone(),
            )
        };

        // sort by (epoch, round) to guarantee the topological order of parent <- child
        blocks.sort_by_key(|b| (b.epoch(), b.round()));

        let root_idx = blocks
            .iter()
            .position(|block| block.id() == root_id)
            .ok_or_else(|| format_err!("unable to find root: {}", root_id))?;
        let root_block = blocks.remove(root_idx);
        let root_quorum_cert = quorum_certs
            .iter()
            .find(|qc| qc.certified_block().id() == root_block.id())
            .ok_or_else(|| format_err!("No QC found for root: {}", root_id))?
            .clone();

        let (root_ordered_cert, root_commit_cert) = if order_vote_enabled {
            // We are setting ordered_root same as commit_root. As every committed block is also ordered, this is fine.
            // As the block store inserts all the fetched blocks and quorum certs and execute the blocks, the block store
            // updates highest_ordered_cert accordingly.
            let root_ordered_cert =
                WrappedLedgerInfo::new(VoteData::dummy(), latest_ledger_info_sig.clone());
            (root_ordered_cert.clone(), root_ordered_cert)
        } else {
            let root_ordered_cert = quorum_certs
                .iter()
                .find(|qc| qc.commit_info().id() == root_block.id())
                .ok_or_else(|| format_err!("No LI found for root: {}", root_id))?
                .clone()
                .into_wrapped_ledger_info();
            let root_commit_cert = root_ordered_cert
                .create_merged_with_executed_state(latest_ledger_info_sig)
                .expect("Inconsistent commit proof and evaluation decision, cannot commit block");
            (root_ordered_cert, root_commit_cert)
        };
        info!("Consensus root block is {}", root_block);

        Ok(RootInfo {
            commit_root_block: Box::new(root_block),
            window_root_block: None,
            quorum_cert: root_quorum_cert,
            ordered_cert: root_ordered_cert,
            commit_cert: root_commit_cert,
        })
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

**File:** consensus/src/persistent_liveness_storage.rs (L519-595)
```rust
    fn start(&self, order_vote_enabled: bool, window_size: Option<u64>) -> LivenessStorageData {
        info!("Start consensus recovery.");
        let raw_data = self
            .db
            .get_data()
            .expect("unable to recover consensus data");

        let last_vote = raw_data
            .0
            .map(|bytes| bcs::from_bytes(&bytes[..]).expect("unable to deserialize last vote"));

        let highest_2chain_timeout_cert = raw_data.1.map(|b| {
            bcs::from_bytes(&b).expect("unable to deserialize highest 2-chain timeout cert")
        });
        let blocks = raw_data.2;
        let quorum_certs: Vec<_> = raw_data.3;
        let blocks_repr: Vec<String> = blocks.iter().map(|b| format!("\n\t{}", b)).collect();
        info!(
            "The following blocks were restored from ConsensusDB : {}",
            blocks_repr.concat()
        );
        let qc_repr: Vec<String> = quorum_certs
            .iter()
            .map(|qc| format!("\n\t{}", qc))
            .collect();
        info!(
            "The following quorum certs were restored from ConsensusDB: {}",
            qc_repr.concat()
        );
        // find the block corresponding to storage latest ledger info
        let latest_ledger_info = self
            .aptos_db
            .get_latest_ledger_info()
            .expect("Failed to get latest ledger info.");
        let accumulator_summary = self
            .aptos_db
            .get_accumulator_summary(latest_ledger_info.ledger_info().version())
            .expect("Failed to get accumulator summary.");
        let ledger_recovery_data = LedgerRecoveryData::new(latest_ledger_info);

        match RecoveryData::new(
            last_vote,
            ledger_recovery_data.clone(),
            blocks,
            accumulator_summary.into(),
            quorum_certs,
            highest_2chain_timeout_cert,
            order_vote_enabled,
            window_size,
        ) {
            Ok(mut initial_data) => {
                (self as &dyn PersistentLivenessStorage)
                    .prune_tree(initial_data.take_blocks_to_prune())
                    .expect("unable to prune dangling blocks during restart");
                if initial_data.last_vote.is_none() {
                    self.db
                        .delete_last_vote_msg()
                        .expect("unable to cleanup last vote");
                }
                if initial_data.highest_2chain_timeout_certificate.is_none() {
                    self.db
                        .delete_highest_2chain_timeout_certificate()
                        .expect("unable to cleanup highest 2-chain timeout cert");
                }
                info!(
                    "Starting up the consensus state machine with recovery data - [last_vote {}], [highest timeout certificate: {}]",
                    initial_data.last_vote.as_ref().map_or_else(|| "None".to_string(), |v| v.to_string()),
                    initial_data.highest_2chain_timeout_certificate().as_ref().map_or_else(|| "None".to_string(), |v| v.to_string()),
                );

                LivenessStorageData::FullRecoveryData(initial_data)
            },
            Err(e) => {
                error!(error = ?e, "Failed to construct recovery data");
                LivenessStorageData::PartialRecoveryData(ledger_recovery_data)
            },
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

**File:** consensus/consensus-types/src/block.rs (L641-663)
```rust
impl<'de> Deserialize<'de> for Block {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename = "Block")]
        struct BlockWithoutId {
            block_data: BlockData,
            signature: Option<bls12381::Signature>,
        }

        let BlockWithoutId {
            block_data,
            signature,
        } = BlockWithoutId::deserialize(deserializer)?;

        Ok(Block {
            id: block_data.hash(),
            block_data,
            signature,
        })
    }
```

**File:** consensus/src/block_storage/block_store.rs (L282-298)
```rust
        for block in blocks {
            if block.round() <= root_block_round {
                block_store
                    .insert_committed_block(block)
                    .await
                    .unwrap_or_else(|e| {
                        panic!(
                            "[BlockStore] failed to insert committed block during build {:?}",
                            e
                        )
                    });
            } else {
                block_store.insert_block(block).await.unwrap_or_else(|e| {
                    panic!("[BlockStore] failed to insert block during build {:?}", e)
                });
            }
        }
```

**File:** consensus/src/block_storage/block_store.rs (L397-438)
```rust
    pub async fn insert_committed_block(
        &self,
        block: Block,
    ) -> anyhow::Result<Arc<PipelinedBlock>> {
        ensure!(
            self.get_block(block.id()).is_none(),
            "Recovered block already exists"
        );

        // We don't know if the blocks in the window for a committed block will
        // be available in memory so we set the OrderedBlockWindow to empty
        let pipelined_block = PipelinedBlock::new_ordered(block, OrderedBlockWindow::empty());
        self.insert_block_inner(pipelined_block).await
    }

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

**File:** consensus/consensus-types/src/proposal_msg.rs (L82-118)
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
            tc.verify(validator).map_err(|e| format_err!("{:?}", e))?;
        }
        // Note that we postpone the verification of SyncInfo until it's being used.
        self.verify_well_formed()
    }
```

**File:** consensus/consensus-types/src/quorum_cert.rs (L119-148)
```rust
    pub fn verify(&self, validator: &ValidatorVerifier) -> anyhow::Result<()> {
        let vote_hash = self.vote_data.hash();
        ensure!(
            self.ledger_info().ledger_info().consensus_data_hash() == vote_hash,
            "Quorum Cert's hash mismatch LedgerInfo"
        );
        // Genesis's QC is implicitly agreed upon, it doesn't have real signatures.
        // If someone sends us a QC on a fake genesis, it'll fail to insert into BlockStore
        // because of the round constraint.
        if self.certified_block().round() == 0 {
            ensure!(
                self.parent_block() == self.certified_block(),
                "Genesis QC has inconsistent parent block with certified block"
            );
            ensure!(
                self.certified_block() == self.ledger_info().ledger_info().commit_info(),
                "Genesis QC has inconsistent commit block with certified block"
            );
            ensure!(
                self.ledger_info().get_num_voters() == 0,
                "Genesis QC should not carry signatures"
            );
            return Ok(());
        }
        self.ledger_info()
            .verify_signatures(validator)
            .context("Fail to verify QuorumCert")?;
        self.vote_data.verify()?;
        Ok(())
    }
```
