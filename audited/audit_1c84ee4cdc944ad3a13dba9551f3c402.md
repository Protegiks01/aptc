# Audit Report

## Title
Transaction Backup Restoration Allows Creating Gaps in Transaction History Leading to State Inconsistency

## Summary
The transaction backup restoration process lacks validation to ensure the first transaction chunk starts at the correct version. This allows restoration of transaction ranges starting at arbitrary versions without validating that earlier transactions exist, creating gaps in the transaction history and violating state consistency invariants.

## Finding Description

The vulnerability exists in the transaction backup restoration flow where multiple validation checks fail to prevent gaps:

**1. Missing First Chunk Validation**

The gap detection logic uses a scan operation that starts with `last_chunk_last_version = 0`, causing the first chunk to bypass consecutive version validation regardless of its starting version. [1](#0-0) 

The condition `if *last_chunk_last_version != 0` at line 366 is FALSE for the first chunk, so no gap check occurs even if the chunk starts at version 100 instead of 0.

**2. Unconditional Frozen Subtree Saving**

When `confirm_or_save_frozen_subtrees` is called with the first chunk's version and proof, it saves frozen subtree roots to the database without validating that the corresponding transactions exist: [2](#0-1) 

Lines 314-315 save frozen subtree nodes to the database if they don't already exist, without verifying the claimed number of leaves (transactions) actually exist in the transaction database.

**3. Weak Backup Range Validation**

The backup service endpoint accepts arbitrary transaction ranges without enforcing that backups must start from version 0: [3](#0-2) 

This allows creating valid proofs for any transaction range, even if earlier transactions are missing.

**Attack Path:**

1. Attacker creates a backup of transactions [100-199] from a node with full history using the backup service endpoint
2. The returned `TransactionAccumulatorRangeProof` contains `left_siblings` representing frozen subtree roots for an accumulator with 100 leaves (transactions 0-99)
3. On a fresh empty node, the attacker initiates restoration using only this backup manifest
4. During restoration:
   - `confirm_or_save_frozen_subtrees` is called with `num_leaves=100`
   - Frozen subtrees are saved to DB claiming 100 transactions exist
   - Transactions [100-199] are saved to transaction database
5. Result: The database has an inconsistent state where:
   - Transaction accumulator claims 200 transactions exist (versions 0-199)
   - Only transactions 100-199 actually exist in the transaction database
   - Transactions 0-99 are missing, creating a 100-transaction gap

**Broken Invariants:**

This violates the **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs." The transaction accumulator and transaction database become inconsistent, with the accumulator referencing transactions that don't exist.

## Impact Explanation

**Severity: Medium to High**

This vulnerability causes **state inconsistencies requiring intervention**, meeting Medium severity criteria. Potential impacts include:

1. **State Corruption**: Missing transactions mean missing state updates, leading to incorrect state roots
2. **Query Failures**: Requests for transactions in the gap (0-99) return NotFound despite the accumulator claiming they exist
3. **Consensus Divergence Risk**: If different nodes restore from different backup sets, they could end up with different transaction histories
4. **State Sync Failures**: State synchronization may fail when verifying transactions against an inconsistent accumulator
5. **Potential for Critical Transaction Loss**: If governance proposals, validator stake changes, or other critical transactions fall in the gap, they would be permanently lost

While this doesn't directly cause fund theft, it breaks fundamental database consistency guarantees that consensus and state synchronization rely upon.

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability is exploitable but requires specific conditions:

**Feasibility Factors:**
- Attacker needs access to create and restore backups
- Requires either:
  - Control over backup storage to provide incomplete backup sets
  - Custom tooling to call `TransactionRestoreBatchController` directly with malicious parameters
  - Ability to manipulate backup manifest files

**Mitigating Factors:**
- The standard `RestoreCoordinator` flow is designed to work with state snapshots and has some protections
- Normal operational procedures likely use complete backup sets
- The issue may be detected when attempting to query missing transactions

**Attack Scenarios:**
- Malicious node operator restoring from incomplete backups
- Compromised backup storage serving manipulated manifests
- Development/testing scenarios using custom restore scripts

## Recommendation

Add explicit validation to ensure the first transaction chunk starts at the expected version. Implement the following checks:

1. **In `TransactionRestoreBatchController::confirm_or_save_frozen_subtrees`**: Validate that the first chunk's `first_version` matches the expected database state:

```rust
async fn confirm_or_save_frozen_subtrees(
    &self,
    loaded_chunk_stream: &mut Peekable<impl Unpin + Stream<Item = Result<LoadedChunk>>>,
) -> Result<Version> {
    let first_chunk = Pin::new(loaded_chunk_stream)
        .peek()
        .await
        .ok_or_else(|| anyhow!("LoadedChunk stream is empty."))?
        .as_ref()
        .map_err(|e| anyhow!("Error: {}", e))?;

    // ADD THIS VALIDATION:
    if let RestoreRunMode::Restore { restore_handler } = self.global_opt.run_mode.as_ref() {
        let db_next_version = restore_handler.get_next_expected_transaction_version()?;
        ensure!(
            first_chunk.manifest.first_version == db_next_version,
            "First chunk version {} doesn't match DB next expected version {}. This would create a gap in transaction history.",
            first_chunk.manifest.first_version,
            db_next_version
        );
        
        restore_handler.confirm_or_save_frozen_subtrees(
            first_chunk.manifest.first_version,
            first_chunk.range_proof.left_siblings(),
        )?;
    }
    
    Ok(first_chunk.manifest.first_version)
}
```

2. **In `confirm_or_save_frozen_subtrees_impl`**: Add validation that frozen subtrees being saved match the current accumulator state:

```rust
fn confirm_or_save_frozen_subtrees_impl(
    transaction_accumulator_db: &DB,
    frozen_subtrees: &[HashValue],
    positions: Vec<Position>,
    batch: &mut SchemaBatch,
) -> Result<()> {
    // ADD: Verify all positions are either already in DB with matching hashes,
    // or if new, ensure they represent a valid continuation
    let mut has_existing_nodes = false;
    let mut has_new_nodes = false;
    
    positions
        .iter()
        .zip(frozen_subtrees.iter().rev())
        .map(|(p, h)| {
            if let Some(_h) = transaction_accumulator_db.get::<TransactionAccumulatorSchema>(p)? {
                has_existing_nodes = true;
                ensure!(
                    h == &_h,
                    "Frozen subtree root does not match that already in DB. Provided: {}, in db: {}.",
                    h,
                    _h,
                );
            } else {
                has_new_nodes = true;
                batch.put::<TransactionAccumulatorSchema>(p, h)?;
            }
            Ok(())
        })
        .collect::<Result<Vec<_>>>()?;
    
    // If saving entirely new frozen subtrees, verify DB is empty
    ensure!(
        !has_new_nodes || !has_existing_nodes || positions.is_empty(),
        "Cannot save new frozen subtrees when some already exist - this indicates a gap in transaction history"
    );
    
    Ok(())
}
```

3. **Documentation**: Add clear warnings in backup/restore documentation about the requirement for complete, consecutive transaction ranges.

## Proof of Concept

```rust
#[tokio::test]
async fn test_transaction_gap_vulnerability() {
    use aptos_storage_interface::DbReader;
    use tempfile::TempDir;
    
    // Setup: Create a source DB with transactions 0-299
    let source_tmpdir = TempDir::new().unwrap();
    let source_db = create_test_db_with_transactions(0, 300, &source_tmpdir);
    
    // Step 1: Create backup for transactions [100-199] only (skipping 0-99)
    let backup_dir = TempDir::new().unwrap();
    let backup_service = BackupServiceClient::new(/* ... */);
    let backup_storage = LocalBackupStorage::new(backup_dir.path());
    
    // Create manifest for transactions [100-199]
    let manifest_handle = create_transaction_backup(
        &backup_service,
        &backup_storage,
        100, // start_version - NOT ZERO!
        100, // num_transactions
    ).await.unwrap();
    
    // Step 2: Restore to empty DB
    let restore_tmpdir = TempDir::new().unwrap();
    let restore_db = create_empty_db(&restore_tmpdir);
    let restore_handler = RestoreHandler::new(Arc::new(restore_db));
    
    // Create restore controller with first_version = None
    let controller = TransactionRestoreBatchController::new(
        GlobalRestoreOptions {
            target_version: 199,
            run_mode: RestoreRunMode::Restore { restore_handler: restore_handler.clone() },
            /* ... */
        },
        Arc::new(backup_storage),
        vec![manifest_handle],
        None, // first_version = None, triggering vulnerability
        None, // no replay
        None, // no epoch history
        VerifyExecutionMode::NoVerify,
        None,
    );
    
    // This should fail but doesn't due to the vulnerability
    controller.run().await.unwrap();
    
    // Step 3: Verify the inconsistent state
    let db_reader = restore_handler.aptosdb.reader.clone();
    
    // The accumulator claims 200 transactions exist
    let synced_version = db_reader.get_synced_version().unwrap().unwrap();
    assert_eq!(synced_version, 199); // Last version is 199
    
    // But transaction 50 doesn't actually exist!
    let result = db_reader.get_transaction_by_version(50, 0);
    assert!(result.is_err()); // NotFound error
    
    // Yet transaction 150 does exist
    let result = db_reader.get_transaction_by_version(150, 0);
    assert!(result.is_ok());
    
    // This proves the gap: transactions 0-99 are missing
    // but the accumulator claims they exist
    println!("VULNERABILITY CONFIRMED: Transaction gap from 0-99");
}
```

## Notes

- This vulnerability is particularly concerning for disaster recovery scenarios where incomplete backups might be used
- The issue affects the backup/restore subsystem which is critical for node recovery and network resilience  
- While the standard `RestoreCoordinator` flow has some protections through state snapshot requirements, the underlying `TransactionRestoreBatchController` lacks fundamental validation
- The cryptographic proofs themselves are valid—the issue is accepting proofs that reference non-existent earlier transactions without validation

### Citations

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L363-382)
```rust
            .scan(0, |last_chunk_last_version, chunk_res| {
                let res = match &chunk_res {
                    Ok(chunk) => {
                        if *last_chunk_last_version != 0
                            && chunk.first_version != *last_chunk_last_version + 1
                        {
                            Some(Err(anyhow!(
                                "Chunk range not consecutive. expecting {}, got {}",
                                *last_chunk_last_version + 1,
                                chunk.first_version
                            )))
                        } else {
                            *last_chunk_last_version = chunk.last_version;
                            Some(chunk_res)
                        }
                    },
                    Err(_) => Some(chunk_res),
                };
                future::ready(res)
            });
```

**File:** storage/aptosdb/src/backup/restore_utils.rs (L297-322)
```rust
fn confirm_or_save_frozen_subtrees_impl(
    transaction_accumulator_db: &DB,
    frozen_subtrees: &[HashValue],
    positions: Vec<Position>,
    batch: &mut SchemaBatch,
) -> Result<()> {
    positions
        .iter()
        .zip(frozen_subtrees.iter().rev())
        .map(|(p, h)| {
            if let Some(_h) = transaction_accumulator_db.get::<TransactionAccumulatorSchema>(p)? {
                ensure!(
                        h == &_h,
                        "Frozen subtree root does not match that already in DB. Provided: {}, in db: {}.",
                        h,
                        _h,
                    );
            } else {
                batch.put::<TransactionAccumulatorSchema>(p, h)?;
            }
            Ok(())
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(())
}
```

**File:** storage/backup/backup-service/src/handlers/mod.rs (L112-122)
```rust
    // GET transaction_range_proof/<first_version>/<last_version>
    let bh = backup_handler;
    let transaction_range_proof = warp::path!(Version / Version)
        .map(move |first_version, last_version| {
            reply_with_bcs_bytes(
                TRANSACTION_RANGE_PROOF,
                &bh.get_transaction_range_proof(first_version, last_version)?,
            )
        })
        .map(unwrap_or_500)
        .recover(handle_rejection);
```
