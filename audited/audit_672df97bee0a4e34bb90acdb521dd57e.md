# Audit Report

## Title
Race Condition in ConsensusDB Recovery Causes Non-Atomic Block/QC Retrieval Leading to Recovery Failures

## Summary
The `get_data()` function in `consensus/src/consensusdb/mod.rs` retrieves blocks and quorum certificates through two separate, non-atomic database reads. This creates a race condition window where concurrent pruning operations can delete blocks/QCs between the two reads, causing validators to receive inconsistent recovery data and fall back to degraded recovery mode.

## Finding Description

The vulnerability exists in the `get_data()` function which retrieves consensus recovery data through two separate iterator creations: [1](#0-0) 

The function creates two independent RocksDB iterators at different points in time—one for blocks (lines 90-94) and one for quorum certificates (lines 95-99). While each individual iterator operates on a consistent snapshot of the database, the two snapshots are created at different times, allowing concurrent deletions to create inconsistency.

**Race Condition Scenario:**

1. **T1**: `get_all::<BlockSchema>()` creates Iterator 1, capturing snapshot containing blocks A, B, C
2. **T1-T2**: Iterator 1 collects all blocks [A, B, C]
3. **T2**: Concurrent thread calls `delete_blocks_and_quorum_certificates([B])`, atomically deleting Block B and its QC
4. **T3**: `get_all::<QCSchema>()` creates Iterator 2, capturing snapshot **after** deletion, containing only QCs for A and C
5. **Result**: Recovery data contains Block B but no corresponding QC for Block B

This occurs because the deletion is atomic (both block and QC deleted together), but the **reads are not atomic** across the two schemas. [2](#0-1) 

During recovery, the system expects matching blocks and QCs. When mismatches occur, recovery fails: [3](#0-2) [4](#0-3) 

When `RecoveryData::new()` fails due to missing QCs for blocks, the node falls back to `PartialRecoveryData` and enters recovery mode: [5](#0-4) 

**Trigger Points:**

1. **Epoch Transitions**: During `start_new_epoch`, the storage is accessed while old epoch data may still be pruned [6](#0-5) 

2. **Admin API Calls**: The admin diagnostic endpoint calls `get_data()` while consensus is running [7](#0-6) 

## Impact Explanation

**Severity: High** (up to $50,000 per bug bounty criteria)

This vulnerability causes **validator node slowdowns** through forced degraded recovery mode:

- Affected validators cannot start consensus normally and must sync state from peers
- During epoch transitions, multiple validators may hit this race simultaneously, degrading network liveness
- Recovery mode requires additional network communication and state synchronization overhead
- Repeated failures could prevent validators from participating in consensus for extended periods

The impact aligns with the High Severity category: "Validator node slowdowns" and "Significant protocol violations" (inconsistent recovery data violates the State Consistency invariant).

## Likelihood Explanation

**Likelihood: Medium**

The race window exists whenever:
- `get_data()` is called (epoch transitions, admin dumps, node restarts)
- Concurrent `prune_tree()` operations are executing
- Block/QC deletion occurs between the two `get_all()` calls

The window is small (microseconds to milliseconds), but:
- Epoch transitions occur regularly in production networks
- Pruning is triggered by block commits, which happen continuously
- Admin diagnostic endpoints can be called at any time during operation
- No synchronization prevents concurrent access to ConsensusDB

## Recommendation

**Solution**: Implement atomic snapshot-based reads for blocks and QCs together.

```rust
pub fn get_data(
    &self,
) -> Result<(
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Vec<Block>,
    Vec<QuorumCert>,
)> {
    let last_vote = self.get_last_vote()?;
    let highest_2chain_timeout_certificate = self.get_highest_2chain_timeout_certificate()?;
    
    // Create a single snapshot for consistent reads
    let mut read_opts = ReadOptions::default();
    // Note: Would need to create and manage explicit RocksDB snapshot
    // let snapshot = self.db.get_snapshot();
    // read_opts.set_snapshot(&snapshot);
    
    let consensus_blocks = self
        .get_all_with_opts::<BlockSchema>(read_opts.clone())?
        .into_iter()
        .map(|(_, block)| block)
        .collect();
    let consensus_qcs = self
        .get_all_with_opts::<QCSchema>(read_opts)?
        .into_iter()
        .map(|(_, qc)| qc)
        .collect();
    
    Ok((
        last_vote,
        highest_2chain_timeout_certificate,
        consensus_blocks,
        consensus_qcs,
    ))
}
```

**Alternative**: Add a read-write lock around `get_data()` and pruning operations to ensure mutual exclusion.

## Proof of Concept

```rust
// Conceptual reproduction (requires multi-threaded test setup)
#[test]
fn test_concurrent_deletion_race() {
    let db = ConsensusDB::new(temp_dir());
    
    // Setup: Insert blocks A, B, C with their QCs
    let blocks = vec![block_a, block_b, block_c];
    let qcs = vec![qc_a, qc_b, qc_c];
    db.save_blocks_and_quorum_certificates(blocks.clone(), qcs.clone()).unwrap();
    
    // Thread 1: Call get_data() slowly to expose race window
    let db_clone = db.clone();
    let handle1 = thread::spawn(move || {
        // This will call get_all for blocks, then get_all for QCs
        // with a delay between them
        db_clone.get_data()
    });
    
    // Thread 2: Delete block B and its QC in the middle
    thread::sleep(Duration::from_micros(10)); // Let Thread 1 read blocks first
    let handle2 = thread::spawn(move || {
        db.delete_blocks_and_quorum_certificates(vec![block_b.id()]).unwrap();
    });
    
    handle2.join().unwrap();
    let (_, _, recovered_blocks, recovered_qcs) = handle1.join().unwrap().unwrap();
    
    // Assert: We have block_b but no qc_b - inconsistent state
    assert!(recovered_blocks.iter().any(|b| b.id() == block_b.id()));
    assert!(!recovered_qcs.iter().any(|qc| qc.certified_block().id() == block_b.id()));
    // This inconsistency will cause RecoveryData::new() to fail
}
```

## Notes

The underlying issue is that RocksDB iterators provide snapshot isolation **per iterator**, but `get_data()` creates two separate iterators with independent snapshots. The fix requires either explicit snapshot management to ensure both reads use the same snapshot, or synchronization to prevent concurrent modifications during the read sequence.

This vulnerability does not require malicious actor involvement—it's a reliability bug that occurs naturally during normal validator operations, particularly during epoch transitions when recovery and pruning operations overlap.

### Citations

**File:** consensus/src/consensusdb/mod.rs (L80-106)
```rust
    pub fn get_data(
        &self,
    ) -> Result<(
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Vec<Block>,
        Vec<QuorumCert>,
    )> {
        let last_vote = self.get_last_vote()?;
        let highest_2chain_timeout_certificate = self.get_highest_2chain_timeout_certificate()?;
        let consensus_blocks = self
            .get_all::<BlockSchema>()?
            .into_iter()
            .map(|(_, block)| block)
            .collect();
        let consensus_qcs = self
            .get_all::<QCSchema>()?
            .into_iter()
            .map(|(_, qc)| qc)
            .collect();
        Ok((
            last_vote,
            highest_2chain_timeout_certificate,
            consensus_blocks,
            consensus_qcs,
        ))
    }
```

**File:** consensus/src/consensusdb/mod.rs (L139-152)
```rust
    pub fn delete_blocks_and_quorum_certificates(
        &self,
        block_ids: Vec<HashValue>,
    ) -> Result<(), DbError> {
        if block_ids.is_empty() {
            return Err(anyhow::anyhow!("Consensus block ids is empty!").into());
        }
        let mut batch = SchemaBatch::new();
        block_ids.iter().try_for_each(|hash| {
            batch.delete::<BlockSchema>(hash)?;
            batch.delete::<QCSchema>(hash)
        })?;
        self.commit(batch)
    }
```

**File:** consensus/src/persistent_liveness_storage.rs (L139-143)
```rust
        let commit_block_quorum_cert = quorum_certs
            .iter()
            .find(|qc| qc.certified_block().id() == commit_block.id())
            .ok_or_else(|| format_err!("No QC found for root: {}", commit_block.id()))?
            .clone();
```

**File:** consensus/src/persistent_liveness_storage.rs (L153-157)
```rust
            let root_ordered_cert = quorum_certs
                .iter()
                .find(|qc| qc.commit_info().id() == commit_block.id())
                .ok_or_else(|| format_err!("No LI found for root: {}", latest_commit_id))?
                .clone()
```

**File:** consensus/src/persistent_liveness_storage.rs (L559-596)
```rust
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
    }
```

**File:** consensus/src/epoch_manager.rs (L1383-1416)
```rust
        match self.storage.start(
            consensus_config.order_vote_enabled(),
            consensus_config.window_size(),
        ) {
            LivenessStorageData::FullRecoveryData(initial_data) => {
                self.recovery_mode = false;
                self.start_round_manager(
                    consensus_key,
                    initial_data,
                    epoch_state,
                    consensus_config,
                    execution_config,
                    onchain_randomness_config,
                    jwk_consensus_config,
                    Arc::new(network_sender),
                    payload_client,
                    payload_manager,
                    rand_config,
                    fast_rand_config,
                    rand_msg_rx,
                    secret_share_msg_rx,
                )
                .await
            },
            LivenessStorageData::PartialRecoveryData(ledger_data) => {
                self.recovery_mode = true;
                self.start_recovery_manager(
                    ledger_data,
                    consensus_config,
                    epoch_state,
                    Arc::new(network_sender),
                )
                .await
            },
```

**File:** crates/aptos-admin-service/src/server/consensus/mod.rs (L130-156)
```rust
fn dump_consensus_db(consensus_db: &dyn PersistentLivenessStorage) -> anyhow::Result<String> {
    let mut body = String::new();

    let (last_vote, highest_tc, consensus_blocks, consensus_qcs) =
        consensus_db.consensus_db().get_data()?;

    body.push_str(&format!("Last vote: \n{last_vote:?}\n\n"));
    body.push_str(&format!("Highest tc: \n{highest_tc:?}\n\n"));
    body.push_str("Blocks: \n");
    for block in consensus_blocks {
        body.push_str(&format!(
            "[id: {:?}, author: {:?}, epoch: {}, round: {:02}, parent_id: {:?}, timestamp: {}, payload: {:?}]\n\n",
            block.id(),
            block.author(),
            block.epoch(),
            block.round(),
            block.parent_id(),
            block.timestamp_usecs(),
            block.payload(),
        ));
    }
    body.push_str("QCs: \n");
    for qc in consensus_qcs {
        body.push_str(&format!("{qc:?}\n\n"));
    }
    Ok(body)
}
```
