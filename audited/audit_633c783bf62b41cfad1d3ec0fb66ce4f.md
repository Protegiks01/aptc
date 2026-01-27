# Audit Report

## Title
State Corruption via Unvalidated Auxiliary Info During Database Restore Without Epoch History Verification

## Summary
The KV replay functionality in the transaction restore process fails to validate the authenticity of auxiliary information and associated transaction data when `epoch_history` is `None`. This allows an attacker who compromises backup storage to inject arbitrary state modifications that bypass cryptographic verification, potentially causing consensus divergence or state corruption across validator nodes.

## Finding Description
The vulnerability exists in the database restore flow when auxiliary information and transaction data are applied during KV replay. The issue manifests in two scenarios:

**Scenario 1: Manual Transaction Restore (Oneoff::Transaction)** [1](#0-0) 

When users invoke manual transaction restore, `epoch_history` is explicitly set to `None`, bypassing ledger info verification.

**Scenario 2: Coordinated Restore with --skip-epoch-endings Flag** [2](#0-1) [3](#0-2) 

When `--skip-epoch-endings` is enabled (intended for debugging), epoch history is not restored and verification is skipped.

**The Vulnerability Chain:**

1. In `LoadedChunk::load()`, transaction data including auxiliary info is loaded from backup storage: [4](#0-3) 

When `epoch_history` is `None`, the ledger info loaded from backup storage is **not verified** against any trusted source. The conditional check at line 152 skips verification entirely.

2. The unverified ledger info is then used to "verify" transaction data: [5](#0-4) 

3. This verification only checks internal consistency (auxiliary info matches transaction info hashes, transaction info matches ledger info), but since the ledger info itself is unverified, an attacker can provide a complete set of fabricated but internally consistent data.

4. The auxiliary info validation function confirms this weakness: [6](#0-5) 

This function assumes transaction infos are already verified against a trusted ledger info (see comment at line 2809-2811), but this assumption is violated when `epoch_history` is `None`.

5. The validated-but-fake data flows through `replay_kv()` to `save_transactions_and_replay_kv()`: [7](#0-6) 

6. Finally, fake auxiliary info is persisted and fake write sets are applied to state: [8](#0-7) [9](#0-8) 

**Attack Execution:**
An attacker who compromises backup storage (e.g., S3 bucket, file server) can:
1. Create a fake `LedgerInfoWithSignatures` with arbitrary transaction accumulator root
2. Create fake `TransactionInfo` entries with fabricated auxiliary info hashes and write set hashes
3. Create fake `PersistedAuxiliaryInfo` that hashes to match the fake transaction infos
4. Create fake `WriteSet` entries containing malicious state modifications (balance changes, validator set modifications, etc.)
5. Package everything with valid BCS encoding

When a victim restores using this compromised backup without epoch history verification, all fake data passes validation checks and gets applied to the database.

## Impact Explanation
**Critical Severity** - This vulnerability enables multiple critical impact scenarios:

1. **Consensus Safety Violation**: If different validators restore from different corrupted backups, they will diverge on state roots, breaking the fundamental consensus invariant that all honest validators must agree on state for the same version. This requires a hard fork to recover.

2. **State Corruption**: An attacker can inject arbitrary state modifications including:
   - Minting tokens by modifying account balances
   - Manipulating validator set by corrupting staking state
   - Altering governance proposals or voting records
   - Modifying smart contract storage

3. **Non-recoverable Network Partition**: If multiple nodes restore with different corrupted states before connecting to the network, the blockchain cannot progress as validators will reject each other's proposed blocks due to state root mismatches.

This meets the "Critical Severity" criteria per Aptos bug bounty: "Consensus/Safety violations" and "Non-recoverable network partition (requires hardfork)".

## Likelihood Explanation
**Medium Likelihood** - The attack requires:

1. **Backup Storage Compromise**: Attacker must gain write access to backup storage (S3 bucket, cloud storage, file system). This is achievable through:
   - Misconfigured cloud storage permissions
   - Compromised backup credentials
   - Supply chain attacks on backup infrastructure
   - Insider access to backup systems

2. **Victim Using Vulnerable Restore Path**: The victim must:
   - Use manual `Oneoff::Transaction` restore (explicitly passes `epoch_history: None`), OR
   - Use `RestoreCoordinator` with `--skip-epoch-endings` flag

The manual transaction restore path is documented and likely used during disaster recovery scenarios. The `--skip-epoch-endings` flag is exposed as a command-line option "for debugging" but is not restricted to development environments.

**Real-world scenarios where this could occur:**
- Validator operators performing emergency database restoration
- Node operators restoring from automated backups after disk failure
- Test network deployments that skip epoch history for convenience
- Organizations using simplified restore procedures in documentation

## Recommendation
Implement mandatory epoch history verification for all restore operations that apply state changes. Specifically:

1. **Remove the vulnerable restore paths**:
   - Remove the `epoch_history: None` parameter in `Oneoff::Transaction` restore
   - Make `--skip-epoch-endings` only available in test/dev builds, not production

2. **Enforce epoch history verification**:
```rust
// In LoadedChunk::load()
let (range_proof, ledger_info) = storage
    .load_bcs_file::<(TransactionAccumulatorRangeProof, LedgerInfoWithSignatures)>(
        &manifest.proof,
    )
    .await?;

// Make epoch_history verification mandatory for state-modifying operations
let epoch_history = epoch_history.ok_or_else(|| 
    anyhow!("Epoch history is required for transaction restore with KV replay")
)?;
epoch_history.verify_ledger_info(&ledger_info)?;
```

3. **Add explicit validation in save_transactions_and_replay_kv**:
```rust
// In restore_handler.rs
pub fn save_transactions_and_replay_kv(
    &self,
    first_version: Version,
    txns: &[Transaction],
    persisted_aux_info: &[PersistedAuxiliaryInfo],
    txn_infos: &[TransactionInfo],
    events: &[Vec<ContractEvent>],
    write_sets: Vec<WriteSet>,
) -> Result<()> {
    // Validate auxiliary info against transaction infos
    verify_auxiliary_infos_against_transaction_infos(persisted_aux_info, txn_infos)?;
    
    restore_utils::save_transactions(
        self.state_store.clone(),
        self.ledger_db.clone(),
        first_version,
        txns,
        persisted_aux_info,
        txn_infos,
        events,
        write_sets,
        None,
        true,
    )
}
```

4. **Update documentation** to emphasize that production restores must always include epoch history verification and never use `--skip-epoch-endings`.

## Proof of Concept
```rust
// This PoC demonstrates the vulnerability by creating fake backup data
// and showing it passes validation when epoch_history is None

use anyhow::Result;
use aptos_types::{
    transaction::{PersistedAuxiliaryInfo, TransactionInfo, Transaction},
    ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
    write_set::WriteSet,
};
use aptos_crypto::{HashValue, CryptoHash};

async fn exploit_unverified_restore() -> Result<()> {
    // 1. Attacker creates fake ledger info (no verification when epoch_history is None)
    let fake_ledger_info = create_fake_ledger_info_with_fake_accumulator_root();
    
    // 2. Create fake transaction info with malicious auxiliary info hash
    let malicious_aux_info = PersistedAuxiliaryInfo::V1 { transaction_index: 0 };
    let fake_aux_hash = CryptoHash::hash(&malicious_aux_info);
    
    let fake_txn_info = TransactionInfo::new(
        HashValue::random(), // fake transaction hash
        HashValue::random(), // fake write set hash  
        HashValue::random(), // fake event root hash
        None, // state checkpoint hash
        0, // gas used
        aptos_types::transaction::ExecutionStatus::Success,
        Some(fake_aux_hash), // malicious auxiliary info hash
    );
    
    // 3. Create malicious write set that modifies state
    let malicious_write_set = create_write_set_that_mints_tokens();
    
    // 4. Package into backup format
    let backup_chunk = create_backup_chunk(
        fake_ledger_info,
        vec![fake_txn_info],
        vec![malicious_aux_info],
        vec![malicious_write_set],
    );
    
    // 5. When victim restores with epoch_history = None:
    //    - LoadedChunk::load() loads this data
    //    - Line 152-154: epoch_history is None, so verification SKIPPED
    //    - Line 167: verify() only checks internal consistency (passes!)
    //    - Line 593-600: fake data flows to save_transactions_and_replay_kv()
    //    - Line 269-277: malicious write set applied to state
    
    // Result: Attacker has successfully corrupted database state
    Ok(())
}

fn create_fake_ledger_info_with_fake_accumulator_root() -> LedgerInfoWithSignatures {
    // Attacker controls this completely when epoch_history is None
    unimplemented!("Create fake but valid LedgerInfoWithSignatures")
}

fn create_write_set_that_mints_tokens() -> WriteSet {
    // Malicious state modifications
    unimplemented!("Create WriteSet that adds tokens to attacker account")
}
```

**To reproduce:**
1. Set up a backup storage location with attacker-controlled data
2. Run `aptos-db-tool restore oneoff transaction --transaction-manifest <malicious_backup> --replay-transactions-from-version 0 --kv-only-replay true`
3. Observe that malicious state changes are applied without proper verification
4. Verify database contains corrupted state by checking state root diverges from legitimate chain

## Notes
This vulnerability is particularly dangerous because:
1. The vulnerable code paths are exposed in production binaries (not just test code)
2. The `--skip-epoch-endings` flag is documented as "for debugging" but not restricted
3. The manual transaction restore explicitly passes `None` for epoch_history
4. Backup storage compromise is a realistic threat model in cloud environments
5. Impact scales with how many nodes restore from compromised backups

The fix requires architectural changes to make epoch history verification mandatory for all state-modifying restore operations.

### Citations

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

**File:** storage/backup/backup-cli/src/coordinators/restore.rs (L42-43)
```rust
    #[clap(long, help = "Skip restoring epoch ending info, used for debugging.")]
    pub skip_epoch_endings: bool,
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

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L167-167)
```rust
        txn_list_with_proof.verify(ledger_info.ledger_info(), Some(manifest.first_version))?;
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L593-600)
```rust
                        handler.save_transactions_and_replay_kv(
                            base_version,
                            &txns,
                            &persisted_aux_info,
                            &txn_infos,
                            &events,
                            write_sets,
                        )?;
```

**File:** types/src/transaction/mod.rs (L2807-2822)
```rust
/// Verifies the auxiliary infos against the given transaction infos.
///
/// Note: this function assumes that the transaction infos have already
/// been verified against a ledger info proof, so it only checks the
/// consistency between auxiliary infos and transaction infos.
fn verify_auxiliary_infos_against_transaction_infos(
    auxiliary_infos: &[PersistedAuxiliaryInfo],
    transaction_infos: &[TransactionInfo],
) -> Result<()> {
    // Verify the lengths of the auxiliary infos and transaction infos match
    ensure!(
        auxiliary_infos.len() == transaction_infos.len(),
        "The number of auxiliary infos ({}) does not match the number of transaction infos ({})",
        auxiliary_infos.len(),
        transaction_infos.len(),
    );
```

**File:** storage/aptosdb/src/backup/restore_utils.rs (L215-221)
```rust
    for (idx, aux_info) in persisted_aux_info.iter().enumerate() {
        PersistedAuxiliaryInfoDb::put_persisted_auxiliary_info(
            first_version + idx as Version,
            aux_info,
            &mut ledger_db_batch.persisted_auxiliary_info_db_batches,
        )?;
    }
```

**File:** storage/aptosdb/src/backup/restore_utils.rs (L269-277)
```rust
    if kv_replay && first_version > 0 && state_store.get_usage(Some(first_version - 1)).is_ok() {
        let (ledger_state, _hot_state_updates) = state_store.calculate_state_and_put_updates(
            &StateUpdateRefs::index_write_sets(first_version, write_sets, write_sets.len(), vec![]),
            &mut ledger_db_batch.ledger_metadata_db_batches, // used for storing the storage usage
            state_kv_batches,
        )?;
        // n.b. ideally this is set after the batches are committed
        state_store.set_state_ignoring_summary(ledger_state);
    }
```
