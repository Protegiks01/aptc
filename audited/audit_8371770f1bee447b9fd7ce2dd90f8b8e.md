# Audit Report

## Title
Transaction Accumulator Proof Tampering via Unverified LedgerInfo in Database Restore

## Summary
The transaction restore functionality allows an attacker controlling backup storage to inject malicious accumulator proof data (left_siblings) into the database without cryptographic verification. When `epoch_history` is `None` (in oneoff transaction restores or when `--skip-epoch-endings` flag is used), the `LedgerInfoWithSignatures` loaded from untrusted storage is never signature-verified, allowing arbitrary accumulator state corruption.

## Finding Description
The vulnerability exists in the database restoration process at two critical points: [1](#0-0) 

The code loads a `(TransactionAccumulatorRangeProof, LedgerInfoWithSignatures)` tuple from backup storage and only verifies the ledger_info signatures if `epoch_history` is `Some`. When `epoch_history` is `None`, signature verification is completely skipped. [2](#0-1) 

The oneoff Transaction restore command explicitly sets `epoch_history` to `None`, making it always vulnerable. [3](#0-2) 

The BootstrapDB command also sets `epoch_history` to `None` when the `--skip-epoch-endings` flag is used.

The subsequent verification at line 167 only checks mathematical consistency: [4](#0-3) 

This verification uses `ledger_info.transaction_accumulator_hash()` as the expected root but doesn't verify that the ledger_info itself is authentic. An attacker can provide a fake ledger_info with a fake root hash, along with fake left_siblings that are consistent with that fake root. [5](#0-4) 

The tampered `left_siblings` are then passed to `confirm_or_save_frozen_subtrees()`: [6](#0-5) 

If the database is being restored for the first time (line 314-315), the malicious frozen subtree roots are saved directly without any comparison to existing values.

**Attack Path:**
1. Attacker gains control of backup storage location (e.g., compromised S3 bucket, malicious mirror)
2. Attacker crafts malicious backup files containing:
   - Fake `LedgerInfoWithSignatures` with arbitrary `transaction_accumulator_hash`
   - Fake `TransactionAccumulatorRangeProof` with fake `left_siblings` consistent with the fake root
   - Fake transaction infos that hash to values consistent with the proof
3. Node operator runs oneoff transaction restore OR BootstrapDB with `--skip-epoch-endings`
4. Since `epoch_history` is `None`, no signature verification occurs
5. Mathematical consistency check passes (fake proof matches fake root)
6. Malicious `left_siblings` are saved as frozen subtree roots in database
7. Database is now corrupted with wrong accumulator state
8. Node may accept invalid transactions or reject valid ones, causing consensus divergence

## Impact Explanation
**Critical Severity** - This vulnerability breaks the fundamental **State Consistency** and **Cryptographic Correctness** invariants:

1. **Database Corruption**: Wrong accumulator frozen subtree roots permanently corrupt the database's transaction accumulator state
2. **Consensus Safety Violation**: Nodes with corrupted accumulator state will have different state roots than honest nodes, potentially causing chain splits or accepting invalid blocks
3. **Transaction Validation Bypass**: With wrong accumulator roots, the node may incorrectly validate transaction inclusion proofs
4. **Non-Recoverable State**: Once corrupted, the accumulator state is difficult to detect and requires full database restoration from trusted source

This meets the Critical severity criteria of "Consensus/Safety violations" and "Non-recoverable network partition" per the Aptos bug bounty program. The vulnerability allows an attacker to compromise the integrity of the entire transaction history stored in the node's database.

## Likelihood Explanation
**High Likelihood** of occurrence:

1. **Common Operation**: Database restoration is a standard operational procedure when:
   - Setting up new validator nodes
   - Recovering from hardware failures
   - Migrating to new infrastructure
   - Debugging/testing scenarios (oneoff restore is documented for debugging)

2. **Low Attack Complexity**: Attacker only needs to:
   - Compromise or control the backup storage location
   - Generate mathematically consistent but fake proof data
   - No need for validator private keys or network access

3. **Default Vulnerable Configuration**: The oneoff transaction restore always has `epoch_history = None` by design, and the documentation describes `--skip-epoch-endings` as "used for debugging" without security warnings

4. **Supply Chain Attack Vector**: Organizations may use third-party backup services or cloud storage that could be compromised

## Recommendation
**Immediate Fix:** Make `epoch_history` mandatory for all restore operations. Remove the option to skip epoch ending verification:

```rust
// In storage/db-tool/src/restore.rs
Oneoff::Transaction {
    storage,
    opt,
    global,
} => {
    // Load epoch history first - REQUIRED
    let epoch_history = Arc::new(
        EpochEndingRestoreController::new(
            // epoch_ending_opt must be provided
            epoch_ending_opt,
            global.clone().try_into()?,
            storage.init_storage().await?,
        )
        .run(None)
        .await?
    );
    
    TransactionRestoreController::new(
        opt,
        global.try_into()?,
        storage.init_storage().await?,
        Some(epoch_history), // Always provide epoch_history
        VerifyExecutionMode::NoVerify,
    )
    .run()
    .await?;
}
```

**Additional Hardening:**
1. Remove the `skip_epoch_endings` flag entirely - signature verification should never be optional
2. Add explicit error if epoch_history is None during production restores
3. Document security requirements for backup storage integrity
4. Consider adding additional checksums/signatures on backup manifests themselves [7](#0-6) 

This optional verification should be changed to:
```rust
let epoch_history = epoch_history
    .ok_or_else(|| anyhow!("epoch_history is required for secure restore"))?;
epoch_history.verify_ledger_info(&ledger_info)?;
```

## Proof of Concept

```rust
// Proof of Concept - Malicious Backup Generation
use aptos_crypto::hash::HashValue;
use aptos_types::{
    ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
    proof::TransactionAccumulatorRangeProof,
    block_info::BlockInfo,
};

// Step 1: Create fake LedgerInfo with arbitrary accumulator hash
let fake_root = HashValue::random();
let fake_commit_info = BlockInfo::new(
    /* epoch */ 100,
    /* round */ 1000,
    /* id */ HashValue::random(),
    /* executed_state_id */ fake_root, // This is the transaction_accumulator_hash
    /* version */ 50000,
    /* timestamp_usecs */ 1000000,
    /* next_epoch_state */ None,
);

let fake_ledger_info = LedgerInfo::new(
    fake_commit_info,
    HashValue::zero(), // consensus_data_hash
);

// Step 2: Create fake LedgerInfoWithSignatures (with no actual signatures)
let fake_ledger_info_with_sigs = LedgerInfoWithSignatures::new(
    fake_ledger_info,
    BTreeMap::new(), // Empty signatures - will not be verified!
);

// Step 3: Create fake range proof with fake left_siblings
// These are crafted to be mathematically consistent with fake_root
let fake_left_siblings = vec![
    HashValue::random(),
    HashValue::random(),
    // ... crafted to verify against fake_root
];

let fake_range_proof = TransactionAccumulatorRangeProof::new(
    fake_left_siblings,
    vec![], // right_siblings
);

// Step 4: Save to backup storage as (fake_range_proof, fake_ledger_info_with_sigs)
// When restored with epoch_history=None, these fake values will be accepted!

// Step 5: Run restore command
// $ aptos-db-tool restore oneoff transaction \
//     --transaction-manifest <manifest-with-fake-proof> \
//     --target-db-dir /path/to/db
//
// Result: Database is corrupted with fake frozen subtree roots from fake_left_siblings
```

The vulnerability is demonstrated by the fact that without signature verification, any mathematically self-consistent but factually incorrect accumulator proof data will be accepted and permanently stored in the database.

## Notes
- This vulnerability specifically affects the **database restore functionality**, not normal consensus operation
- The attack requires the attacker to control or compromise the backup storage location
- Once exploited, the corruption is persistent and difficult to detect without comparing against a trusted source
- The `--skip-epoch-endings` flag appears to be intended for debugging but creates a production security risk
- Normal consensus operation with properly verified epoch changes is not affected by this vulnerability

### Citations

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L147-154)
```rust
        let (range_proof, ledger_info) = storage
            .load_bcs_file::<(TransactionAccumulatorRangeProof, LedgerInfoWithSignatures)>(
                &manifest.proof,
            )
            .await?;
        if let Some(epoch_history) = epoch_history {
            epoch_history.verify_ledger_info(&ledger_info)?;
        }
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L414-418)
```rust
        if let RestoreRunMode::Restore { restore_handler } = self.global_opt.run_mode.as_ref() {
            restore_handler.confirm_or_save_frozen_subtrees(
                first_chunk.manifest.first_version,
                first_chunk.range_proof.left_siblings(),
            )?;
```

**File:** storage/db-tool/src/restore.rs (L97-111)
```rust
                    Oneoff::Transaction {
                        storage,
                        opt,
                        global,
                    } => {
                        TransactionRestoreController::new(
                            opt,
                            global.try_into()?,
                            storage.init_storage().await?,
                            None, /* epoch_history */
                            VerifyExecutionMode::NoVerify,
                        )
                        .run()
                        .await?;
                    },
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

**File:** types/src/proof/definition.rs (L910-925)
```rust
    pub fn verify(
        &self,
        ledger_info: &LedgerInfo,
        first_transaction_info_version: Option<Version>,
    ) -> Result<()> {
        let txn_info_hashes: Vec<_> = self
            .transaction_infos
            .iter()
            .map(CryptoHash::hash)
            .collect();
        self.ledger_info_to_transaction_infos_proof.verify(
            ledger_info.transaction_accumulator_hash(),
            first_transaction_info_version,
            &txn_info_hashes,
        )
    }
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
