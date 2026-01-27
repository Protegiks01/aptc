# Audit Report

## Title
Unverified Blockchain State Restoration via Hardcoded NoVerify Mode in db-tool restore

## Summary
The db-tool restore command hardcodes `VerifyExecutionMode::NoVerify` and sets `epoch_history` to None, allowing restoration of blockchain state without cryptographic verification of ledger info signatures or re-execution validation of transaction outputs. This breaks critical state consistency invariants.

## Finding Description

The vulnerability exists in the database restoration flow where two critical security parameters are hardcoded to insecure values: [1](#0-0) 

The `epoch_history` parameter is set to `None` and `verify_execution_mode` is hardcoded to `VerifyExecutionMode::NoVerify`. These settings have severe security implications:

**1. Missing Ledger Info Signature Verification**

When `epoch_history` is `None`, the ledger info signature verification is completely skipped: [2](#0-1) 

The `verify_ledger_info` method (when epoch_history is provided) validates that the ledger info is properly signed by validators: [3](#0-2) 

**2. Missing Transaction Execution Verification**

When `VerifyExecutionMode::NoVerify` is used, the system skips re-executing transactions to verify their outputs match the claimed results: [4](#0-3) 

The `verify_execution` function re-executes transactions and validates outputs against expected values: [5](#0-4) 

**Attack Scenario:**

1. Attacker provides malicious backup via compromised storage, misconfiguration, or MITM attack
2. Malicious backup contains:
   - Arbitrary transactions with fake outputs (incorrect balances, events, state changes)
   - Self-consistent but fake transaction_infos 
   - Unsigned or self-signed ledger_info committing to fake transaction_infos
   - Matching proofs that pass cryptographic consistency checks
3. Operator runs `db-tool restore` pointing to malicious backup
4. System restores fake state because:
   - Transaction hashes match transaction_infos (attacker ensures consistency) ✓
   - Transaction_infos proven by ledger_info (attacker creates matching proof) ✓
   - Ledger_info signature NOT verified (epoch_history is None) ✗
   - Transaction outputs NOT re-executed (NoVerify mode) ✗
5. Node database now contains completely fabricated blockchain state

## Impact Explanation

**High Severity** - Significant Protocol Violations:

- **State Consistency Violation**: Breaks invariant #4 "State transitions must be atomic and verifiable via Merkle proofs" - the restored state cannot be verified as legitimate
- **Consensus Divergence**: If restored node is a validator, it will produce blocks based on incorrect state, causing consensus failures
- **Data Integrity Violation**: Query results from the node will return fabricated data to users and dApps
- **Potential Fund Manipulation**: Fake state could show incorrect account balances, enabling theft if applications trust the node's data

This meets High Severity criteria per bug bounty: "Significant protocol violations" and "Validator node slowdowns" (from consensus divergence).

## Likelihood Explanation

**Medium Likelihood:**

The attack requires operator involvement through:
- Compromised backup storage system (realistic for cloud storage)
- MITM attack on backup downloads (possible without HTTPS verification)
- Social engineering to use malicious backup source
- Misconfiguration pointing to wrong backup location

However, this is a realistic operational scenario:
- Backup restoration is a routine disaster recovery operation
- Operators may not verify backup sources during emergencies
- Automated systems may restore from compromised storage
- No warnings or confirmations alert operators to the security risk

## Recommendation

**Immediate Fix:**

1. Never set `epoch_history` to None in production restore paths
2. Default to `VerifyExecutionMode::verify_all()` for untrusted sources
3. Add command-line flags requiring explicit opt-in to disable verification

**Code Fix:**

```rust
// In storage/db-tool/src/restore.rs
Oneoff::Transaction {
    storage,
    opt,
    global,
} => {
    // Load epoch history to verify ledger info signatures
    let epoch_history = load_epoch_history(&storage, &global).await?;
    
    TransactionRestoreController::new(
        opt,
        global.try_into()?,
        storage.init_storage().await?,
        Some(epoch_history), // Always provide epoch history
        VerifyExecutionMode::verify_all(), // Default to full verification
    )
    .run()
    .await?;
}
```

Add explicit flags for fast mode:
```rust
#[clap(long, help = "DANGEROUS: Skip ledger info verification. Only use with trusted backups.")]
skip_ledger_verification: bool,

#[clap(long, help = "DANGEROUS: Skip transaction re-execution. Only use with trusted backups.")]  
skip_execution_verification: bool,
```

## Proof of Concept

```rust
// Proof of Concept: Creating and restoring malicious backup

use aptos_types::{
    transaction::{Transaction, TransactionInfo, TransactionPayload},
    account_address::AccountAddress,
};

async fn create_malicious_backup() -> Result<()> {
    // 1. Create fake transactions with malicious payloads
    let fake_txn = Transaction::UserTransaction(
        // Transaction that transfers funds incorrectly
    );
    
    // 2. Create fake transaction_info with incorrect state_root
    let fake_txn_info = TransactionInfo::new(
        fake_txn.hash(),
        HashValue::zero(), // Fake state root
        HashValue::zero(), // Fake event root  
        None,
        0, // Zero gas
        ExecutionStatus::Success,
    );
    
    // 3. Create self-signed ledger_info (won't be verified)
    let fake_ledger_info = LedgerInfoWithSignatures::new(
        LedgerInfo::new(...),
        BTreeMap::new(), // No validator signatures
    );
    
    // 4. Create matching proof
    let fake_proof = create_accumulator_proof(&[fake_txn_info]);
    
    // 5. Save to backup storage
    save_backup(fake_txn, fake_txn_info, fake_ledger_info, fake_proof).await?;
    
    Ok(())
}

async fn demonstrate_vulnerability() -> Result<()> {
    // Operator runs: aptos-db-tool restore --local-fs-dir /malicious/backup
    // Result: Node restores completely fake blockchain state
    // No warnings, no verification failures
    // Database now contains fabricated account balances and state
    
    Ok(())
}
```

## Notes

The vulnerability exists because defensive verification is disabled by default. While RestoreCoordinator (the high-level coordinator) does load epoch_history for verification, the lower-level db-tool restore command bypasses this protection. This creates an operational security gap where administrators using the wrong tool or following outdated documentation could restore unverified state.

The existence of a separate `replay_verify` tool suggests the development team recognizes the need for verification but made the restore tool too permissive. A defense-in-depth approach would verify data during restoration rather than as a separate optional step.

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

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L147-155)
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

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L276-312)
```rust
    pub fn verify_ledger_info(&self, li_with_sigs: &LedgerInfoWithSignatures) -> Result<()> {
        let epoch = li_with_sigs.ledger_info().epoch();
        ensure!(!self.epoch_endings.is_empty(), "Empty epoch history.",);
        if epoch > self.epoch_endings.len() as u64 {
            // TODO(aldenhu): fix this from upper level
            warn!(
                epoch = epoch,
                epoch_history_until = self.epoch_endings.len(),
                "Epoch is too new and can't be verified. Previous chunks are verified and node \
                won't be able to start if this data is malicious."
            );
            return Ok(());
        }
        if epoch == 0 {
            ensure!(
                li_with_sigs.ledger_info() == &self.epoch_endings[0],
                "Genesis epoch LedgerInfo info doesn't match.",
            );
        } else if let Some(wp_trusted) = self
            .trusted_waypoints
            .get(&li_with_sigs.ledger_info().version())
        {
            let wp_li = Waypoint::new_any(li_with_sigs.ledger_info());
            ensure!(
                *wp_trusted == wp_li,
                "Waypoints don't match. In backup: {}, trusted: {}",
                wp_li,
                wp_trusted,
            );
        } else {
            self.epoch_endings[epoch as usize - 1]
                .next_epoch_state()
                .ok_or_else(|| anyhow!("Shouldn't contain non- epoch bumping LIs."))?
                .verify(li_with_sigs)?;
        };
        Ok(())
    }
```

**File:** execution/executor/src/chunk_executor/mod.rs (L562-575)
```rust
            let next_begin = if verify_execution_mode.should_verify() {
                self.verify_execution(
                    transactions,
                    persisted_aux_info,
                    transaction_infos,
                    write_sets,
                    event_vecs,
                    batch_begin,
                    batch_end,
                    verify_execution_mode,
                )?
            } else {
                batch_end
            };
```

**File:** execution/executor/src/chunk_executor/mod.rs (L592-650)
```rust
    fn verify_execution(
        &self,
        transactions: &[Transaction],
        persisted_aux_info: &[PersistedAuxiliaryInfo],
        transaction_infos: &[TransactionInfo],
        write_sets: &[WriteSet],
        event_vecs: &[Vec<ContractEvent>],
        begin_version: Version,
        end_version: Version,
        verify_execution_mode: &VerifyExecutionMode,
    ) -> Result<Version> {
        // Execute transactions.
        let parent_state = self.commit_queue.lock().latest_state().clone();
        let state_view = self.state_view(parent_state.latest())?;
        let txns = transactions
            .iter()
            .take((end_version - begin_version) as usize)
            .cloned()
            .map(|t| t.into())
            .collect::<Vec<SignatureVerifiedTransaction>>();

        let auxiliary_info = persisted_aux_info
            .iter()
            .take((end_version - begin_version) as usize)
            .map(|persisted_aux_info| AuxiliaryInfo::new(*persisted_aux_info, None))
            .collect::<Vec<_>>();
        // State sync executor shouldn't have block gas limit.
        let execution_output = DoGetExecutionOutput::by_transaction_execution::<V>(
            &V::new(),
            txns.into(),
            auxiliary_info,
            &parent_state,
            state_view,
            BlockExecutorConfigFromOnchain::new_no_block_limit(),
            TransactionSliceMetadata::chunk(begin_version, end_version),
        )?;
        // not `zip_eq`, deliberately
        for (version, txn_out, txn_info, write_set, events) in multizip((
            begin_version..end_version,
            &execution_output.to_commit.transaction_outputs,
            transaction_infos.iter(),
            write_sets.iter(),
            event_vecs.iter(),
        )) {
            if let Err(err) = txn_out.ensure_match_transaction_info(
                version,
                txn_info,
                Some(write_set),
                Some(events),
            ) {
                return if verify_execution_mode.is_lazy_quit() {
                    error!("(Not quitting right away.) {}", err);
                    verify_execution_mode.mark_seen_error();
                    Ok(version + 1)
                } else {
                    Err(err)
                };
            }
        }
```
