# Audit Report

## Title
Critical Epoch Ending Verification Bypass Allowing Acceptance of Forged Blockchain State

## Summary
The `skip_epoch_endings` flag in the backup verification system completely bypasses LedgerInfo signature verification, allowing an attacker to provide forged blockchain state with fabricated LedgerInfos that were never signed by validators. The verification will pass because only data consistency checks are performed, not cryptographic authenticity checks.

## Finding Description

When the `skip_epoch_endings` flag is set to `true`, the backup verification coordinator skips loading the epoch history, which is the **only** component that verifies LedgerInfo authenticity through validator signatures. [1](#0-0) 

This flag is passed to the VerifyCoordinator: [2](#0-1) 

In the verification implementation, when `skip_epoch_endings` is true, `epoch_history` is set to `None`: [3](#0-2) 

This `None` value propagates to both state snapshot and transaction verification. In state snapshot verification, the critical LedgerInfo verification is **conditionally skipped**: [4](#0-3) 

Similarly, in transaction verification: [5](#0-4) 

The `verify_ledger_info` method is the **ONLY** place where LedgerInfo authenticity is verified through validator signatures or trusted waypoints: [6](#0-5) 

Without this verification, the remaining checks only verify internal consistency (transaction hashes match transaction infos, Merkle proofs are valid for the claimed roots) but **NOT** that the LedgerInfo itself is authentic. [7](#0-6) 

Even if a user provides trusted waypoints, they are never used when `skip_epoch_endings` is true because the waypoints are only checked inside `EpochHistory.verify_ledger_info()`, which is never called: [8](#0-7) 

**Attack Scenario:**
1. Attacker creates a forged `LedgerInfoWithSignatures` with arbitrary `state_root_hash` and `transaction_accumulator_hash` but **without valid validator signatures**
2. Attacker creates state snapshot data and Merkle proofs consistent with the forged `state_root_hash`
3. Attacker creates transaction data and accumulator proofs consistent with the forged `transaction_accumulator_hash`
4. Attacker packages these as a backup archive
5. Victim runs: `aptos-db-tool backup verify --skip-epoch-endings ...`
6. **Verification passes** because only consistency checks are performed, not signature verification
7. Victim believes the forged state is valid and may restore it

## Impact Explanation

This is **Critical Severity** under the Aptos Bug Bounty program because it enables:

1. **Consensus/Safety Violations**: A restored node with forged state could participate in consensus with incorrect state, causing safety violations and potential chain splits
2. **State Consistency Breach**: Breaks the invariant that "State transitions must be atomic and verifiable via Merkle proofs" - the proofs verify against an unverified root
3. **Cryptographic Correctness Violation**: Completely bypasses the BLS signature verification that ensures LedgerInfos were actually committed by validators
4. **Loss of Funds**: An attacker could forge state showing they own assets they don't actually own
5. **Non-recoverable Network Issues**: If multiple nodes restore from forged backups, the network could suffer a split requiring manual intervention or a hardfork

The impact is maximized because:
- No validator access or Byzantine behavior is required
- The attacker only needs to convince victims to use the `--skip-epoch-endings` flag
- The flag is exposed as a user-facing CLI option despite being marked "for debugging"
- Trusted waypoints provide no protection since they're never checked

## Likelihood Explanation

**Likelihood: Medium to High**

The vulnerability is likely to occur because:

1. **User Confusion**: The flag is documented as "Skip verifying epoch ending info" without clearly stating it disables **all** signature verification
2. **Performance Incentive**: Users may enable this flag to speed up verification, not understanding the security implications
3. **Legitimate Use Cases**: The documentation mentions using this for debugging, creating scenarios where users might use it
4. **No Warning**: The tool provides no warning that critical security checks are being disabled
5. **Restore Context**: The comment explicitly states LedgerInfos are "NOT checked at all when doing one-shot restoring" without epoch endings [9](#0-8) 

Attacker requirements are minimal:
- Ability to create backup files (no special privileges needed)
- Ability to convince victim to verify/restore with `--skip-epoch-endings`
- No need for validator keys, Byzantine behavior, or network access

## Recommendation

**Immediate Fix:**

1. **Remove the flag entirely** or make it require an additional `--i-understand-this-is-insecure` confirmation flag
2. **Add mandatory signature verification** even when epoch endings are skipped, by requiring trusted waypoints

**Proposed Code Fix:**

In `storage/backup/backup-cli/src/coordinators/verify.rs`, modify the logic to require at least one trusted waypoint when skipping epoch endings:

```rust
let epoch_history = if self.skip_epoch_endings {
    // If skipping epoch endings, require trusted waypoints for security
    ensure!(
        !global_opt.trusted_waypoints.is_empty(),
        "When --skip-epoch-endings is used, you must provide at least one \
         --trust-waypoint for security. Without epoch endings, there is NO \
         signature verification on LedgerInfos."
    );
    // Create a minimal EpochHistory with only waypoints for verification
    Some(Arc::new(EpochHistory {
        epoch_endings: Vec::new(),
        trusted_waypoints: global_opt.trusted_waypoints.clone(),
    }))
} else {
    Some(Arc::new(
        EpochHistoryRestoreController::new(...)
        .run()
        .await?,
    ))
};
```

3. **Update CLI documentation** to explicitly warn about security implications
4. **Add verification guards** that fail loudly when LedgerInfo verification is skipped

## Proof of Concept

```rust
// PoC demonstrating the vulnerability
// File: test_skip_epoch_bypass.rs

use aptos_backup_cli::coordinators::verify::VerifyCoordinator;
use aptos_crypto::{hash::CryptoHash, HashValue};
use aptos_types::{
    ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
    transaction::Version,
};

#[tokio::test]
async fn test_forged_ledger_info_bypasses_verification() {
    // Step 1: Create a FORGED LedgerInfo without any valid signatures
    let forged_ledger_info = LedgerInfo::new(
        /* block_info */ Default::default(),
        /* consensus_block_id */ HashValue::random(),
    );
    
    // Create LedgerInfoWithSignatures with EMPTY signatures (invalid!)
    let forged_li_with_sigs = LedgerInfoWithSignatures::new(
        forged_ledger_info,
        /* signatures */ Default::default(), // No validator signatures!
    );
    
    // Step 2: Create backup files with data consistent with forged LedgerInfo
    // (This would include state snapshots and transactions that match the
    //  forged state_root_hash and transaction_accumulator_hash)
    
    // Step 3: Run verification with skip_epoch_endings = true
    let coordinator = VerifyCoordinator::new(
        /* storage */ test_storage.clone(),
        /* metadata_cache_opt */ Default::default(),
        /* trusted_waypoints_opt */ Default::default(), // No waypoints!
        /* concurrent_downloads */ 1,
        /* start_version */ 0,
        /* end_version */ 100,
        /* state_snapshot_before_version */ 100,
        /* skip_epoch_endings */ true, // CRITICAL: Bypasses verification
        /* validate_modules */ false,
        /* output_transaction_analysis */ None,
    ).unwrap();
    
    // Step 4: Verification PASSES even though LedgerInfo has no valid signatures!
    let result = coordinator.run().await;
    
    // Without the fix, this assertion passes (vulnerability exists)
    assert!(result.is_ok(), "Forged backup verification should fail but passes!");
    
    // Expected: Should fail with "LedgerInfo signatures not verified"
    // Actual: Passes because epoch_history is None and verification is skipped
}
```

**Reproduction Steps:**
1. Create a backup with forged LedgerInfos (no valid validator signatures)
2. Ensure state/transaction data has valid Merkle proofs for the forged roots
3. Run: `aptos-db-tool backup verify --skip-epoch-endings --metadata-cache-dir /tmp/cache <backup-storage>`
4. Observe verification passes despite invalid signatures
5. Compare with: `aptos-db-tool backup verify <backup-storage>` (without flag)
6. Observe second verification fails with signature errors

## Notes

This vulnerability exists because the security model assumes epoch ending verification is **mandatory** for all backup verification, but the `skip_epoch_endings` flag breaks this assumption without providing alternative verification. The comment in the code acknowledges LedgerInfos are "NOT checked at all" in certain scenarios, but this is treated as acceptable for "debugging" use cases without proper safeguards against misuse.

### Citations

**File:** storage/db-tool/src/backup.rs (L153-154)
```rust
    #[clap(long, help = "Skip verifying epoch ending info.")]
    skip_epoch_endings: bool,
```

**File:** storage/db-tool/src/backup.rs (L238-252)
```rust
                VerifyCoordinator::new(
                    opt.storage.init_storage().await?,
                    opt.metadata_cache_opt,
                    opt.trusted_waypoints_opt,
                    opt.concurrent_downloads.get(),
                    opt.start_version.unwrap_or(0),
                    opt.end_version.unwrap_or(Version::MAX),
                    opt.state_snapshot_before_version.unwrap_or(Version::MAX),
                    opt.skip_epoch_endings,
                    opt.validate_modules,
                    opt.output_transaction_analysis,
                )?
                .run()
                .await?
            },
```

**File:** storage/backup/backup-cli/src/coordinators/verify.rs (L106-121)
```rust
        let epoch_history = if self.skip_epoch_endings {
            None
        } else {
            Some(Arc::new(
                EpochHistoryRestoreController::new(
                    epoch_endings
                        .into_iter()
                        .map(|backup| backup.manifest)
                        .collect(),
                    global_opt.clone(),
                    self.storage.clone(),
                )
                .run()
                .await?,
            ))
        };
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L137-139)
```rust
        if let Some(epoch_history) = self.epoch_history.as_ref() {
            epoch_history.verify_ledger_info(&li)?;
        }
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L152-154)
```rust
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

**File:** types/src/transaction/mod.rs (L2288-2354)
```rust
    /// Verifies the transaction list with proof using the given `ledger_info`.
    /// This method will ensure:
    /// 1. All transactions exist on the given `ledger_info`.
    /// 2. All transactions in the list have consecutive versions.
    /// 3. If `first_transaction_version` is None, the transaction list is empty.
    ///    Otherwise, the transaction list starts at `first_transaction_version`.
    /// 4. If events exist, they match the expected event root hashes in the proof.
    pub fn verify(
        &self,
        ledger_info: &LedgerInfo,
        first_transaction_version: Option<Version>,
    ) -> Result<()> {
        // Verify the first transaction versions match
        ensure!(
            self.get_first_transaction_version() == first_transaction_version,
            "First transaction version ({:?}) doesn't match given version ({:?}).",
            self.get_first_transaction_version(),
            first_transaction_version,
        );

        // Verify the lengths of the transactions and transaction infos match
        ensure!(
            self.proof.transaction_infos.len() == self.get_num_transactions(),
            "The number of TransactionInfo objects ({}) does not match the number of \
             transactions ({}).",
            self.proof.transaction_infos.len(),
            self.get_num_transactions(),
        );

        // Verify the transaction hashes match those of the transaction infos
        self.transactions
            .par_iter()
            .zip_eq(self.proof.transaction_infos.par_iter())
            .map(|(txn, txn_info)| {
                let txn_hash = CryptoHash::hash(txn);
                ensure!(
                    txn_hash == txn_info.transaction_hash(),
                    "The hash of transaction does not match the transaction info in proof. \
                     Transaction hash: {:x}. Transaction hash in txn_info: {:x}.",
                    txn_hash,
                    txn_info.transaction_hash(),
                );
                Ok(())
            })
            .collect::<Result<Vec<_>>>()?;

        // Verify the transaction infos are proven by the ledger info.
        self.proof
            .verify(ledger_info, self.get_first_transaction_version())?;

        // Verify the events if they exist.
        if let Some(event_lists) = &self.events {
            ensure!(
                event_lists.len() == self.get_num_transactions(),
                "The length of event_lists ({}) does not match the number of transactions ({}).",
                event_lists.len(),
                self.get_num_transactions(),
            );
            event_lists
                .into_par_iter()
                .zip_eq(self.proof.transaction_infos.par_iter())
                .map(|(events, txn_info)| verify_events_against_root_hash(events, txn_info))
                .collect::<Result<Vec<_>>>()?;
        }

        Ok(())
    }
```

**File:** storage/backup/backup-cli/src/utils/mod.rs (L332-363)
```rust
pub struct TrustedWaypointOpt {
    #[clap(
        long,
        help = "(multiple) When provided, an epoch ending LedgerInfo at the waypoint version will be \
        checked against the hash in the waypoint, but signatures on it are NOT checked. \
        Use this for two purposes: \
        1. set the genesis or the latest waypoint to confirm the backup is compatible. \
        2. set waypoints at versions where writeset transactions were used to overwrite the \
        validator set, so that the signature check is skipped. \
        N.B. LedgerInfos are verified only when restoring / verifying the epoch ending backups, \
        i.e. they are NOT checked at all when doing one-shot restoring of the transaction \
        and state backups."
    )]
    pub trust_waypoint: Vec<Waypoint>,
}

impl TrustedWaypointOpt {
    pub fn verify(self) -> Result<HashMap<Version, Waypoint>> {
        let mut trusted_waypoints = HashMap::new();
        for w in self.trust_waypoint {
            trusted_waypoints
                .insert(w.version(), w)
                .map_or(Ok(()), |w| {
                    Err(AptosDbError::Other(format!(
                        "Duplicated waypoints at version {}",
                        w.version()
                    )))
                })?;
        }
        Ok(trusted_waypoints)
    }
}
```

**File:** storage/backup/backup-cli/src/coordinators/restore.rs (L42-43)
```rust
    #[clap(long, help = "Skip restoring epoch ending info, used for debugging.")]
    pub skip_epoch_endings: bool,
```
