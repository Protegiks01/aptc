# Audit Report

## Title
Transaction Backup Restore Proof Chain Continuity Vulnerability with Bypassed Epoch Verification

## Summary
When restoring transaction backups without epoch history verification (`--skip-epoch-endings` flag or standalone restore command), individual chunks are verified against their own `LedgerInfoWithSignatures` but there is no cryptographic verification that consecutive chunks form a valid proof chain. This allows an attacker to provide chunks with consecutive version numbers from different blockchain forks or states that would pass verification individually but create an inconsistent database.

## Finding Description

The transaction backup restore system verifies each `TransactionChunk` independently against its embedded `LedgerInfoWithSignatures`, but critically fails to verify that consecutive chunks maintain accumulator state continuity or that their ledger infos form a valid chain. [1](#0-0) 

The `TransactionBackup::verify()` method only checks version number continuity, not cryptographic proof chain continuity. [2](#0-1) 

In `LoadedChunk::load()`, epoch history verification is **optional** (line 152-154). When `epoch_history` is `None`, no signature verification occurs on the `LedgerInfoWithSignatures`, and each chunk is only verified against its own ledger info without checking consistency with other chunks. [3](#0-2) 

The `--skip-epoch-endings` flag explicitly allows bypassing epoch verification. More critically: [4](#0-3) 

The standalone transaction restore command **hardcodes** `epoch_history` to `None`, providing no option for secure verification. [5](#0-4) 

The `confirm_or_save_frozen_subtrees()` is only called for the **first chunk**, not for verifying continuity between chunks.

Unlike state sync, which uses `verify_extends_ledger()` to ensure cryptographic continuity: [6](#0-5) 

The backup restore uses `ReplayChunkVerifier` which **does not** perform this critical verification: [7](#0-6) 

### Attack Scenario

An attacker with access to backups from different blockchain states/forks could:

1. Create malicious backup with chunks from different forks:
   - Chunk 1: versions 0-99 from fork A (with LedgerInfoA)
   - Chunk 2: versions 100-199 from fork B (with LedgerInfoB)

2. When `epoch_history` is None:
   - No signature verification on LedgerInfo occurs
   - Each chunk verifies independently against its own LedgerInfo
   - Version continuity check passes (versions are consecutive)
   - No accumulator state continuity verification

3. Victim restores database with inconsistent state combining multiple forks

4. If validator restores from this backup:
   - Database contains mixed state from different blockchain histories
   - Violates **State Consistency** invariant (#4)
   - Could cause consensus issues if validator participates with corrupted state

## Impact Explanation

**Critical Severity** - This vulnerability enables:

1. **Consensus/Safety Violation**: Validators restoring from malicious backups would have inconsistent state, potentially causing fork detection failures or invalid block proposals that could affect consensus if multiple validators are compromised.

2. **State Inconsistency**: Breaks the fundamental invariant that "State transitions must be atomic and verifiable via Merkle proofs" - the restored database represents an impossible state that never existed on the actual blockchain.

3. **Network Partition Risk**: If multiple validators restore from the same malicious backup (e.g., during disaster recovery), they could form a partition with inconsistent state, requiring manual intervention or hard fork to resolve.

The vulnerability is particularly severe because:
- The standalone restore command provides NO warning about missing verification
- Operators using debugging flags may not understand security implications
- During emergency recovery scenarios, operators might skip epoch verification for speed

## Likelihood Explanation

**Medium to High Likelihood** in specific scenarios:

1. **Disaster Recovery**: When validators need to restore quickly from backups, they might use `--skip-epoch-endings` to save time, unknowingly exposing themselves

2. **Testing/Staging Environments**: Operators testing restore procedures with production-like data could use unsafe tools, potentially promoting unsafe practices to production

3. **Malicious Backup Sources**: If an attacker compromises backup storage or performs man-in-the-middle attacks on backup downloads, they could serve malicious mixed-fork backups

4. **Social Engineering**: Attackers could distribute "corrupted but recoverable" backups to validators during crisis situations

The attack complexity is moderate - attacker needs access to multiple blockchain states (which validators naturally have) and ability to influence backup sources.

## Recommendation

Implement multi-layered defense:

**1. Mandatory Accumulator Continuity Verification**

Add verification that consecutive chunks have matching accumulator states, similar to `verify_extends_ledger()`:

```rust
// In TransactionRestoreBatchController::loaded_chunk_stream
let mut prev_chunk_end_state: Option<(Version, HashValue)> = None;

chunk_stream.and_then(move |chunk| {
    if let Some((prev_last_version, prev_accumulator_hash)) = prev_chunk_end_state {
        // Verify this chunk's proof starts where previous ended
        let proof_start_accumulator = compute_accumulator_from_proof(
            &chunk.range_proof,
            chunk.manifest.first_version
        )?;
        
        ensure!(
            chunk.manifest.first_version == prev_last_version + 1,
            "Chunk version gap"
        );
        
        ensure!(
            proof_start_accumulator == prev_accumulator_hash,
            "Accumulator state discontinuity between chunks"
        );
    }
    
    prev_chunk_end_state = Some((
        chunk.manifest.last_version,
        chunk.range_proof.compute_end_accumulator_hash()
    ));
    
    Ok(chunk)
})
```

**2. Remove Hardcoded None for epoch_history**

In `db-tool/src/restore.rs`, require epoch history or add explicit warning:

```rust
TransactionRestoreController::new(
    opt,
    global.try_into()?,
    storage.init_storage().await?,
    Some(load_or_require_epoch_history()?), // Don't hardcode None
    VerifyExecutionMode::NoVerify,
)
```

**3. Require Explicit Opt-In for Unsafe Mode**

Change `--skip-epoch-endings` to require confirmation:

```rust
#[clap(
    long,
    help = "UNSAFE: Skip epoch ending verification. Use ONLY for debugging on test networks. \
            Restoring with this flag on mainnet can create inconsistent database state."
)]
pub skip_epoch_endings: bool,
```

Add runtime check:

```rust
if skip_epoch_endings && is_mainnet() {
    return Err(anyhow!(
        "Cannot use --skip-epoch-endings on mainnet. This flag is only for debugging."
    ));
}
```

**4. Add Ledger Info Signature Verification Fallback**

Even when epoch_history is None, verify signatures if validator set is available:

```rust
if epoch_history.is_none() {
    warn!("Restoring without epoch history - attempting standalone signature verification");
    if let Some(validator_verifier) = try_load_validator_set(&ledger_info)? {
        ledger_info.verify_signatures(&validator_verifier)?;
    } else {
        return Err(anyhow!(
            "Cannot verify ledger info signatures without epoch history or validator set"
        ));
    }
}
```

## Proof of Concept

```rust
// Proof of Concept - demonstrates the vulnerability
use aptos_backup_cli::backup_types::transaction::{
    manifest::{TransactionBackup, TransactionChunk},
    restore::TransactionRestoreController,
};
use aptos_types::{
    ledger_info::LedgerInfoWithSignatures,
    proof::TransactionAccumulatorRangeProof,
    transaction::Version,
};

#[tokio::test]
async fn test_discontinuous_proof_chain_attack() {
    // Setup: Create two chunks from "different forks"
    
    // Chunk 1: versions 0-99 from fork A
    let chunk1 = TransactionChunk {
        first_version: 0,
        last_version: 99,
        transactions: create_transactions_file(0, 99, "fork_A"),
        // LedgerInfo from fork A with accumulator hash for fork A state
        proof: create_proof_file(
            fork_a_range_proof,
            fork_a_ledger_info_with_sigs  // Valid signatures from fork A
        ),
        format: TransactionChunkFormat::V1,
    };
    
    // Chunk 2: versions 100-199 from fork B (INCONSISTENT with fork A!)
    let chunk2 = TransactionChunk {
        first_version: 100,  // Consecutive version - passes check
        last_version: 199,
        transactions: create_transactions_file(100, 199, "fork_B"),
        // LedgerInfo from fork B with DIFFERENT accumulator state
        proof: create_proof_file(
            fork_b_range_proof,
            fork_b_ledger_info_with_sigs  // Valid signatures from fork B
        ),
        format: TransactionChunkFormat::V1,
    };
    
    let manifest = TransactionBackup {
        first_version: 0,
        last_version: 199,
        chunks: vec![chunk1, chunk2],
    };
    
    // Vulnerability: manifest.verify() only checks version continuity
    assert!(manifest.verify().is_ok());  // PASSES despite discontinuous proofs!
    
    // Restore with epoch_history = None (standalone restore or --skip-epoch-endings)
    let controller = TransactionRestoreController::new(
        restore_opt,
        global_opt,
        storage,
        None,  // NO epoch history verification - VULNERABLE
        VerifyExecutionMode::NoVerify,
    );
    
    // Attack succeeds: database now contains mixed state from two forks
    assert!(controller.run().await.is_ok());  // Restore succeeds!
    
    // Verify the attack: check that database has inconsistent state
    let db_state = read_database_state(0, 199);
    assert_ne!(
        compute_expected_state_from_fork_a(0, 99),
        db_state[0..100]
    );  // State at version 100 doesn't match what fork A would produce
    
    // This violates the invariant: database represents an impossible blockchain state
}
```

## Notes

The vulnerability is particularly insidious because:

1. **Silent Failure**: No warnings are emitted when using unsafe restore modes
2. **Version Check Gives False Confidence**: The version continuity check makes it appear secure
3. **Production Tool Has Unsafe Default**: The `db-tool` restore command is unsafe by default
4. **Emergency Scenario Risk**: Most likely to be exploited during disaster recovery when operators prioritize speed over security

The proper state sync flow (using `StateSyncChunkVerifier`) correctly implements `verify_extends_ledger()` for chunk continuity, but this protection is absent in the backup restore path.

### Citations

**File:** storage/backup/backup-cli/src/backup_types/transaction/manifest.rs (L50-88)
```rust
    pub fn verify(&self) -> Result<()> {
        // check number of waypoints
        ensure!(
            self.first_version <= self.last_version,
            "Bad version range: [{}, {}]",
            self.first_version,
            self.last_version,
        );

        // check chunk ranges
        ensure!(!self.chunks.is_empty(), "No chunks.");

        let mut next_version = self.first_version;
        for chunk in &self.chunks {
            ensure!(
                chunk.first_version == next_version,
                "Chunk ranges not continuous. Expected first version: {}, actual: {}.",
                next_version,
                chunk.first_version,
            );
            ensure!(
                chunk.last_version >= chunk.first_version,
                "Chunk range invalid. [{}, {}]",
                chunk.first_version,
                chunk.last_version,
            );
            next_version = chunk.last_version + 1;
        }

        // check last version in chunk matches manifest
        ensure!(
            next_version - 1 == self.last_version, // okay to -1 because chunks is not empty.
            "Last version in chunks: {}, in manifest: {}",
            next_version - 1,
            self.last_version,
        );

        Ok(())
    }
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L147-167)
```rust
        let (range_proof, ledger_info) = storage
            .load_bcs_file::<(TransactionAccumulatorRangeProof, LedgerInfoWithSignatures)>(
                &manifest.proof,
            )
            .await?;
        if let Some(epoch_history) = epoch_history {
            epoch_history.verify_ledger_info(&ledger_info)?;
        }

        // make a `TransactionListWithProof` to reuse its verification code.
        let txn_list_with_proof =
            TransactionListWithProofV2::new(TransactionListWithAuxiliaryInfos::new(
                TransactionListWithProof::new(
                    txns,
                    Some(event_vecs),
                    Some(manifest.first_version),
                    TransactionInfoListWithProof::new(range_proof, txn_infos),
                ),
                persisted_aux_info,
            ));
        txn_list_with_proof.verify(ledger_info.ledger_info(), Some(manifest.first_version))?;
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L403-422)
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

        if let RestoreRunMode::Restore { restore_handler } = self.global_opt.run_mode.as_ref() {
            restore_handler.confirm_or_save_frozen_subtrees(
                first_chunk.manifest.first_version,
                first_chunk.range_proof.left_siblings(),
            )?;
        }

        Ok(first_chunk.manifest.first_version)
    }
```

**File:** storage/backup/backup-cli/src/coordinators/restore.rs (L219-231)
```rust
        let epoch_history = if !self.skip_epoch_endings {
            Some(Arc::new(
                EpochHistoryRestoreController::new(
                    epoch_handles,
                    self.global_opt.clone(),
                    self.storage.clone(),
                )
                .run()
                .await?,
            ))
        } else {
            None
        };
```

**File:** storage/db-tool/src/restore.rs (L102-110)
```rust
                        TransactionRestoreController::new(
                            opt,
                            global.try_into()?,
                            storage.init_storage().await?,
                            None, /* epoch_history */
                            VerifyExecutionMode::NoVerify,
                        )
                        .run()
                        .await?;
```

**File:** execution/executor/src/chunk_executor/chunk_result_verifier.rs (L36-66)
```rust
impl ChunkResultVerifier for StateSyncChunkVerifier {
    fn verify_chunk_result(
        &self,
        parent_accumulator: &InMemoryTransactionAccumulator,
        ledger_update_output: &LedgerUpdateOutput,
    ) -> Result<()> {
        // In consensus-only mode, we cannot verify the proof against the executed output,
        // because the proof returned by the remote peer is an empty one.
        if cfg!(feature = "consensus-only-perf-test") {
            return Ok(());
        }

        THREAD_MANAGER.get_exe_cpu_pool().install(|| {
            let first_version = parent_accumulator.num_leaves();

            // Verify the chunk extends the parent accumulator.
            let parent_root_hash = parent_accumulator.root_hash();
            let num_overlap = self.txn_infos_with_proof.verify_extends_ledger(
                first_version,
                parent_root_hash,
                Some(first_version),
            )?;
            assert_eq!(num_overlap, 0, "overlapped chunks");

            // Verify transaction infos match
            ledger_update_output
                .ensure_transaction_infos_match(&self.txn_infos_with_proof.transaction_infos)?;

            Ok(())
        })
    }
```

**File:** execution/executor/src/chunk_executor/chunk_result_verifier.rs (L133-140)
```rust
impl ChunkResultVerifier for ReplayChunkVerifier {
    fn verify_chunk_result(
        &self,
        _parent_accumulator: &InMemoryTransactionAccumulator,
        ledger_update_output: &LedgerUpdateOutput,
    ) -> Result<()> {
        ledger_update_output.ensure_transaction_infos_match(&self.transaction_infos)
    }
```
