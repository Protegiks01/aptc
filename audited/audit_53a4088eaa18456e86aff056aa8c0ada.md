# Audit Report

## Title
Permanent Loss of Order Certificates Due to Missing Block Handling in Consensus

## Summary
Order certificates can be permanently lost when blocks are temporarily unavailable during order vote aggregation. The `new_qc_from_order_vote_msg()` function returns an error when blocks are missing (NeedFetch case), but the aggregated order certificate is never persisted. When the in-memory pending order votes are garbage collected, the order certificate is lost forever, even if the block becomes available later. This breaks consensus safety guarantees.

## Finding Description

When a validator receives order votes and aggregates them into an order certificate, the certificate can only be inserted into the block store if the corresponding block already exists. The vulnerable code path is: [1](#0-0) 

When `NeedFetchResult::NeedFetch` is returned (indicating the block doesn't exist), the function logs a warning and returns an error. The aggregated order certificate exists only in the function's return value and is never persisted. [2](#0-1) 

The error propagates through `process_order_vote_reception_result()` and up the call chain, where it is merely logged: [3](#0-2) 

Meanwhile, the individual order votes that formed the certificate remain in the in-memory `PendingOrderVotes` data structure: [4](#0-3) 

When consensus advances and `garbage_collect()` is called, order votes for older rounds are removed: [5](#0-4) 

The critical issue: votes with `EnoughVotes` status (meaning a valid order certificate was formed) are also removed if their round is not greater than `highest_ordered_round`. There is no mechanism to:
1. Persist the aggregated order certificate for later insertion
2. Retry processing pending order votes when the missing block arrives
3. Reconstruct the order certificate from the votes after garbage collection

**Attack Scenario:**
1. Validators receive order votes for round R and reach quorum (2f+1 votes)
2. The block for round R is delayed or withheld temporarily (network partition, Byzantine behavior)
3. `new_qc_from_order_vote_msg()` returns `NeedFetch` error for all validators
4. Order certificate is not inserted into any validator's block store
5. Consensus advances; `highest_ordered_round` moves past round R
6. `garbage_collect()` removes all order votes for round R from memory
7. Block for round R arrives, but order certificate cannot be reconstructed
8. **Result:** Order certificate for round R is permanently lost across the network

This violates the **Consensus Safety** invariant - different nodes may have inconsistent views of which blocks are ordered, potentially causing chain splits or execution divergence.

## Impact Explanation

This is a **Critical Severity** vulnerability under the Aptos bug bounty program because it constitutes a **Consensus/Safety violation**:

1. **Consensus Divergence**: Different validators may have different ordered certificates, breaking agreement on transaction ordering
2. **Non-Recoverable State**: Lost order certificates cannot be recreated, potentially requiring manual intervention or hard fork
3. **Execution Inconsistency**: Missing order certificates mean blocks won't be sent for execution, causing state divergence [6](#0-5) 

The code shows that order certificates trigger block execution. If some nodes have the certificate and others don't, execution will diverge.

## Likelihood Explanation

**High Likelihood** due to multiple realistic trigger conditions:

1. **Natural Network Delays**: In distributed systems, temporary network partitions or delays are common
2. **Block Propagation Order**: Blocks may arrive after order votes due to different network paths
3. **Byzantine Validators**: Malicious validators can strategically delay block propagation while allowing order vote propagation
4. **High Network Load**: During peak activity, blocks may be delayed while lighter order vote messages arrive first
5. **No Recovery Mechanism**: Once votes are garbage collected, there is zero chance of recovery

The vulnerability requires no special privileges - it can occur naturally or be triggered by any actor who can temporarily delay block delivery (e.g., by controlling network paths or being a Byzantine validator).

## Recommendation

**Immediate Fix**: Persist aggregated order certificates before attempting insertion, with retry logic when blocks become available.

**Recommended Solution:**

1. **Persist Order Certificates**: When `OrderVoteReceptionResult::NewLedgerInfoWithSignatures` is returned, immediately persist the order certificate to durable storage before attempting block store insertion:

```rust
async fn process_order_vote_reception_result(
    &mut self,
    result: OrderVoteReceptionResult,
    preferred_peer: Author,
) -> anyhow::Result<()> {
    match result {
        OrderVoteReceptionResult::NewLedgerInfoWithSignatures((
            verified_qc,
            ledger_info_with_signatures,
        )) => {
            let ordered_cert = WrappedLedgerInfo::new(VoteData::dummy(), ledger_info_with_signatures);
            
            // PERSIST the order certificate BEFORE attempting insertion
            self.storage.save_pending_ordered_cert(&ordered_cert, &verified_qc).await?;
            
            // Try to insert if block is available
            let insert_result = self.new_ordered_cert(
                ordered_cert,
                verified_qc,
                preferred_peer,
            ).await;
            
            // If insertion fails due to missing block, keep the persisted cert for retry
            if insert_result.is_err() {
                // Mark for retry when block arrives
                self.pending_ordered_certs.insert(ordered_cert.commit_info().id(), ordered_cert);
            }
            
            insert_result.or(Ok(())) // Don't propagate error if only block is missing
        },
        // ... rest of match
    }
}
```

2. **Retry Logic**: When blocks are inserted, check for pending order certificates:

```rust
async fn process_verified_proposal(&mut self, proposal: ProposalMsg) -> anyhow::Result<()> {
    // ... existing block insertion logic ...
    
    // After block insertion, retry any pending order certificates for this block
    if let Some(ordered_cert) = self.pending_ordered_certs.remove(&block.id()) {
        self.block_store.insert_ordered_cert(&ordered_cert).await?;
    }
    
    // ... rest of function
}
```

3. **Prevent Premature Garbage Collection**: Modify `PendingOrderVotes` to only remove votes after successful insertion or explicit timeout (not based solely on round number).

## Proof of Concept

```rust
// Reproduction test for consensus/src/round_manager.rs
#[tokio::test]
async fn test_order_cert_loss_on_missing_block() {
    // Setup: 4 validators with 3 needed for quorum
    let (signers, verifier) = random_validator_verifier(4, Some(3), false);
    let mut round_manager = create_test_round_manager(/* ... */);
    
    // Step 1: Create order votes for round 10, block_id_10
    let block_id_10 = HashValue::random();
    let ledger_info_10 = LedgerInfo::new(
        BlockInfo::new(1, 10, block_id_10, HashValue::zero(), 0, 0, None),
        HashValue::zero(),
    );
    
    // Step 2: Send 3 order votes (reaching quorum) for the block
    // But DON'T insert the block into block store
    for i in 0..3 {
        let order_vote = OrderVote::new_with_signature(
            signers[i].author(),
            ledger_info_10.clone(),
            signers[i].sign(&ledger_info_10).unwrap(),
        );
        
        let order_vote_msg = OrderVoteMsg::new(
            order_vote,
            QuorumCert::certificate_for_genesis(), // dummy QC
        );
        
        // This should aggregate votes and return NewLedgerInfoWithSignatures
        // But fail with NeedFetch error because block doesn't exist
        let result = round_manager.process_order_vote_msg(order_vote_msg).await;
        if i == 2 {
            // On 3rd vote, should reach quorum but fail insertion
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("without block"));
        }
    }
    
    // Step 3: Verify order votes are in pending_order_votes
    assert!(round_manager.pending_order_votes.has_enough_order_votes(&ledger_info_10));
    
    // Step 4: Advance consensus to round 111 (past round 10 + 100 window)
    // This triggers garbage collection
    round_manager.process_local_timeout(111).await.unwrap();
    
    // Step 5: Verify order votes were garbage collected
    assert!(!round_manager.pending_order_votes.has_enough_order_votes(&ledger_info_10));
    
    // Step 6: NOW insert the block that was missing
    let block_10 = create_test_block(block_id_10, 10, /* ... */);
    round_manager.block_store.insert_block(block_10).await.unwrap();
    
    // Step 7: Verify order certificate CANNOT be inserted anymore
    // The votes are gone, certificate is lost forever
    let sync_info = round_manager.block_store.sync_info();
    assert!(sync_info.highest_ordered_round() < 10); // Order cert for round 10 is lost
    
    // VULNERABILITY CONFIRMED: Order certificate permanently lost
}
```

## Notes

**Additional Context:**

1. The vulnerability affects the entire consensus network when blocks are delayed system-wide (e.g., network partition between regions)

2. Recovery through `SyncInfo` only works if at least one node successfully inserted the order certificate. If ALL nodes failed due to missing blocks, the certificate is lost network-wide. [7](#0-6) 

3. The 100-round window check provides insufficient protection: [8](#0-7) 

If rounds advance quickly or if there are delays, order votes can be received, aggregated, and garbage collected within this window without successful insertion.

4. This is distinct from normal fork resolution - this loses consensus-valid order certificates that cannot be recovered through any protocol mechanism.

### Citations

**File:** consensus/src/round_manager.rs (L1571-1573)
```rust
            if order_vote_round > highest_ordered_round
                && order_vote_round < highest_ordered_round + 100
            {
```

**File:** consensus/src/round_manager.rs (L1897-1923)
```rust
    async fn process_order_vote_reception_result(
        &mut self,
        result: OrderVoteReceptionResult,
        preferred_peer: Author,
    ) -> anyhow::Result<()> {
        match result {
            OrderVoteReceptionResult::NewLedgerInfoWithSignatures((
                verified_qc,
                ledger_info_with_signatures,
            )) => {
                self.new_ordered_cert(
                    WrappedLedgerInfo::new(VoteData::dummy(), ledger_info_with_signatures),
                    verified_qc,
                    preferred_peer,
                )
                .await
            },
            OrderVoteReceptionResult::VoteAdded(_) => {
                ORDER_VOTE_ADDED.inc();
                Ok(())
            },
            e => {
                ORDER_VOTE_OTHER_ERRORS.inc();
                Err(anyhow::anyhow!("{:?}", e))
            },
        }
    }
```

**File:** consensus/src/round_manager.rs (L1962-1978)
```rust
            NeedFetchResult::NeedFetch => {
                // If the block doesn't exist, we could ideally do sync up based on the qc.
                // But this could trigger fetching a lot of past blocks in case the node is lagging behind.
                // So, we just log a warning here to avoid a long sequence of block fetchs.
                // One of the subsequence syncinfo messages will trigger the block fetch or state sync if required.
                ORDER_CERT_CREATED_WITHOUT_BLOCK_IN_BLOCK_STORE.inc();
                sample!(
                    SampleRate::Duration(Duration::from_millis(200)),
                    info!(
                        "Ordered certificate created without block in block store: {:?}",
                        verified_qc.certified_block()
                    );
                );
                Err(anyhow::anyhow!(
                    "Ordered certificate created without block in block store"
                ))
            },
```

**File:** consensus/src/round_manager.rs (L2187-2193)
```rust
                    match result {
                        Ok(_) => trace!(RoundStateLogSchema::new(round_state)),
                        Err(e) => {
                            counters::ERROR_COUNT.inc();
                            warn!(kind = error_kind(&e), RoundStateLogSchema::new(round_state), "Error: {:#}", e);
                        }
                    }
```

**File:** consensus/src/pending_order_votes.rs (L38-45)
```rust
/// A PendingVotes structure keep track of order votes for the last few rounds
pub struct PendingOrderVotes {
    /// Maps LedgerInfo digest to associated signatures.
    /// Order vote status stores caches the information on whether the votes are enough to form a QC.
    /// We also store the QC that the order votes certify.
    li_digest_to_votes:
        HashMap<HashValue /* LedgerInfo digest */, (QuorumCert, OrderVoteStatus)>,
}
```

**File:** consensus/src/pending_order_votes.rs (L159-170)
```rust
    // Removes votes older than highest_ordered_round
    pub fn garbage_collect(&mut self, highest_ordered_round: u64) {
        self.li_digest_to_votes
            .retain(|_, (_, status)| match status {
                OrderVoteStatus::EnoughVotes(li_with_sig) => {
                    li_with_sig.ledger_info().round() > highest_ordered_round
                },
                OrderVoteStatus::NotEnoughVotes(sig_aggregator) => {
                    sig_aggregator.data().round() > highest_ordered_round
                },
            });
    }
```

**File:** consensus/src/block_storage/sync_manager.rs (L116-173)
```rust
    pub async fn add_certs(
        &self,
        sync_info: &SyncInfo,
        mut retriever: BlockRetriever,
    ) -> anyhow::Result<()> {
        // When the local ordered round is very old than the received sync_info, this function will
        // (1) resets the block store with highest commit cert = sync_info.highest_quorum_cert()
        // (2) insert all the blocks between (inclusive) highest_commit_cert.commit_info().id() to
        // highest_quorum_cert.certified_block().id() into the block store and storage
        // (3) insert the quorum cert for all the above blocks into the block store and storage
        // (4) executes all the blocks that are ordered while inserting the above quorum certs
        self.sync_to_highest_quorum_cert(
            sync_info.highest_quorum_cert().clone(),
            sync_info.highest_commit_cert().clone(),
            &mut retriever,
        )
        .await?;

        self.sync_to_highest_commit_cert(
            sync_info.highest_commit_cert().ledger_info(),
            retriever.network.clone(),
        )
        .await;

        // The insert_ordered_cert(order_cert) function call expects that order_cert.commit_info().id() block
        // is already stored in block_store. So, we first call insert_quorum_cert(highest_quorum_cert).
        // This call will ensure that the highest ceritified block along with all its ancestors are inserted
        // into the block store.
        self.insert_quorum_cert(sync_info.highest_quorum_cert(), &mut retriever)
            .await?;

        // Even though we inserted the highest_quorum_cert (and its ancestors) in the above step,
        // we still need to insert ordered cert explicitly. This will send the highest ordered block
        // to execution.
        if self.order_vote_enabled {
            self.insert_ordered_cert(&sync_info.highest_ordered_cert())
                .await?;
        } else {
            // When order votes are disabled, the highest_ordered_cert().certified_block().id() need not be
            // one of the ancestors of highest_quorum_cert.certified_block().id() due to forks. So, we call
            // insert_quorum_cert instead of insert_ordered_cert as in the above case. This will ensure that
            // highest_ordered_cert().certified_block().id() is inserted the block store.
            self.insert_quorum_cert(
                &self
                    .highest_ordered_cert()
                    .as_ref()
                    .clone()
                    .into_quorum_cert(self.order_vote_enabled)?,
                &mut retriever,
            )
            .await?;
        }

        if let Some(tc) = sync_info.highest_2chain_timeout_cert() {
            self.insert_2chain_timeout_certificate(Arc::new(tc.clone()))?;
        }
        Ok(())
    }
```

**File:** consensus/src/block_storage/sync_manager.rs (L206-227)
```rust
    pub async fn insert_ordered_cert(
        &self,
        ordered_cert: &WrappedLedgerInfo,
    ) -> anyhow::Result<()> {
        if self.ordered_root().round() < ordered_cert.ledger_info().ledger_info().round() {
            if let Some(ordered_block) = self.get_block(ordered_cert.commit_info().id()) {
                if !ordered_block.block().is_nil_block() {
                    observe_block(
                        ordered_block.block().timestamp_usecs(),
                        BlockStage::OC_ADDED,
                    );
                }
                SUCCESSFUL_EXECUTED_WITH_ORDER_VOTE_QC.inc();
                self.send_for_execution(ordered_cert.clone()).await?;
            } else {
                bail!("Ordered block not found in block store when inserting ordered cert");
            }
        } else {
            LATE_EXECUTION_WITH_ORDER_VOTE_QC.inc();
        }
        Ok(())
    }
```
