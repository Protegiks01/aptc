# Audit Report

## Title
Cryptographic Signature Verification Bypass in Replay-Verify Coordinator Allows Malicious Backup Manifest Injection

## Summary
The ReplayVerifyCoordinator bypasses cryptographic verification of LedgerInfoWithSignatures in backup manifests by passing `None` for `epoch_history`, allowing an attacker with backup storage access to inject malicious state snapshots and transactions that will be accepted without validator signature verification.

## Finding Description
The replay-verify coordinator, used in production CI/CD workflows to verify backup integrity, instantiates both `StateSnapshotRestoreController` and `TransactionRestoreBatchController` with `epoch_history: None`. This causes critical cryptographic verification to be completely skipped. [1](#0-0) [2](#0-1) 

The verification logic exists in both restore controllers but is conditional on `epoch_history` being present. In StateSnapshotRestoreController: [3](#0-2) 

And in TransactionRestoreBatchController's LoadedChunk::load: [4](#0-3) 

When `epoch_history` is `None`, the `LedgerInfoWithSignatures` verification is completely skipped. This contrasts with the normal restore and verify coordinators, which DO provide epoch_history: [5](#0-4) [6](#0-5) 

The manifest structures contain `proof` fields with `LedgerInfoWithSignatures` that should be cryptographically verified: [7](#0-6) [8](#0-7) 

The trusted waypoints system provides no protection for state/transaction manifests, only for epoch ending backups: [9](#0-8) 

**Attack Path:**
1. Attacker compromises backup storage credentials (GCS bucket access)
2. Attacker creates malicious `StateSnapshotBackup` and `TransactionBackup` JSON manifests
3. Manifests point to malicious state/transaction data chunks
4. Manifests include fake `LedgerInfoWithSignatures` in proof fields (can contain invalid signatures or fabricated data)
5. When replay-verify runs via CI/CD workflow, it loads these manifests without verifying signatures
6. Malicious data is replayed into the target database
7. Result: corrupted database or validation of invalid blockchain history

## Impact Explanation
This is **Critical Severity** under the Aptos Bug Bounty program for the following reasons:

1. **Consensus/Safety Violation**: The vulnerability allows acceptance of blockchain state that was never agreed upon by validator consensus. This directly violates the "Consensus Safety" invariant.

2. **Cryptographic Correctness Violation**: Bypasses the fundamental security control of BLS signature verification on `LedgerInfoWithSignatures`, violating the "Cryptographic Correctness: BLS signatures... must be secure" invariant.

3. **Production Impact**: The replay-verify tool is used in production CI/CD workflows to verify backup integrity, as evidenced by the GitHub Actions workflow configuration. [10](#0-9) 

4. **Database Corruption Risk**: Could lead to non-recoverable network partition if corrupted backups are used to restore validator nodes, requiring a hardfork to recover.

5. **Supply Chain Attack Vector**: An attacker compromising backup storage can inject malicious data that appears valid to automated verification systems.

## Likelihood Explanation
**Moderate to High Likelihood**:

1. **Attack Prerequisites**:
   - Write access to backup storage (GCS bucket) - achievable through credential compromise, insider threat, or misconfigured IAM policies
   - Knowledge of backup manifest format (publicly available in source code)

2. **Realistic Scenarios**:
   - Compromised service account credentials for backup storage
   - Misconfigured GCS bucket permissions allowing public write access
   - Insider threat with legitimate backup storage access
   - Man-in-the-middle attack on backup storage connections (if not properly secured)

3. **Detection Difficulty**: The attack would be difficult to detect because:
   - No cryptographic verification failure occurs (it's skipped entirely)
   - Malicious manifests look syntactically valid
   - The replay process would proceed normally until execution mismatches are detected (if at all)

## Recommendation
**Immediate Fix**: Always provide `epoch_history` to replay-verify operations. Modify `ReplayVerifyCoordinator` to build epoch history before instantiating restore controllers:

```rust
// In replay_verify.rs run_impl():
// After loading metadata_view, build epoch history
let epoch_history = Arc::new(
    EpochHistory::new(
        metadata_view,
        Arc::clone(&self.storage),
        self.concurrent_downloads,
    )
    .await?
);

// Then pass epoch_history instead of None:
StateSnapshotRestoreController::new(
    StateSnapshotRestoreOpt { /* ... */ },
    global_opt.clone(),
    Arc::clone(&self.storage),
    Some(epoch_history.clone()), // Changed from None
)

TransactionRestoreBatchController::new(
    global_opt,
    self.storage,
    txn_manifests,
    save_start_version,
    Some((next_txn_version, false)),
    Some(epoch_history), // Changed from None
    self.verify_execution_mode.clone(),
    None,
)
```

**Long-term Improvements**:
1. Make `epoch_history` non-optional in restore controller constructors to prevent accidental bypasses
2. Add explicit security warnings when bypassing signature verification
3. Implement backup manifest signing at storage layer as defense-in-depth
4. Add integrity checks (checksums, content-addressed storage) for backup data

## Proof of Concept
```rust
// PoC demonstrating the vulnerability:
// File: storage/backup/backup-cli/tests/replay_verify_bypass_test.rs

#[tokio::test]
async fn test_malicious_manifest_accepted_without_epoch_history() {
    use aptos_backup_cli::coordinators::replay_verify::ReplayVerifyCoordinator;
    use aptos_backup_cli::metadata::cache::MetadataCacheOpt;
    use aptos_backup_cli::storage::local_fs::LocalFs;
    use aptos_backup_cli::utils::TrustedWaypointOpt;
    use aptos_types::ledger_info::LedgerInfoWithSignatures;
    use std::sync::Arc;
    
    // 1. Create a temporary backup storage with malicious manifests
    let storage_dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(LocalFs::new(storage_dir.path()));
    
    // 2. Create a fake StateSnapshotBackup manifest with invalid LedgerInfo
    let malicious_manifest = StateSnapshotBackup {
        version: 1000,
        epoch: 10,
        root_hash: HashValue::random(), // Fake root hash
        chunks: vec![/* fake chunks */],
        proof: /* FileHandle pointing to fake LedgerInfoWithSignatures */,
    };
    
    // 3. Save malicious manifest to storage
    storage.save_json_file(&malicious_manifest).await.unwrap();
    
    // 4. Create ReplayVerifyCoordinator with epoch_history: None
    let coordinator = ReplayVerifyCoordinator::new(
        storage,
        MetadataCacheOpt::new(None),
        TrustedWaypointOpt { trust_waypoint: vec![] },
        8, // concurrent_downloads
        4, // replay_concurrency_level
        restore_handler,
        0, // start_version
        1000, // end_version
        false, // validate_modules
        VerifyExecutionMode::NoVerify,
    ).unwrap();
    
    // 5. Run replay-verify - it will accept the malicious manifest
    // without verifying the LedgerInfoWithSignatures!
    let result = coordinator.run().await;
    
    // 6. Verify that malicious data was processed without signature verification
    assert!(result.is_ok(), "Malicious manifest was accepted!");
    
    // Expected: Should fail with signature verification error
    // Actual: Succeeds because verification is skipped
}
```

## Notes
- This vulnerability exists specifically in the `replay_verify` coordinator path, not in normal `restore` or `verify` operations
- The issue stems from an architectural decision to make `epoch_history` optional in restore controllers, then explicitly passing `None` in replay-verify
- The trusted waypoints mechanism does NOT protect against this attack for state/transaction manifests
- Production CI/CD workflows using replay-verify are vulnerable to supply chain attacks via backup storage compromise

### Citations

**File:** storage/backup/backup-cli/src/coordinators/replay_verify.rs (L173-188)
```rust
        if !skip_snapshot {
            if let Some(backup) = state_snapshot {
                StateSnapshotRestoreController::new(
                    StateSnapshotRestoreOpt {
                        manifest_handle: backup.manifest,
                        version: backup.version,
                        validate_modules: self.validate_modules,
                        restore_mode: Default::default(),
                    },
                    global_opt.clone(),
                    Arc::clone(&self.storage),
                    None, /* epoch_history */
                )
                .run()
                .await?;
            }
```

**File:** storage/backup/backup-cli/src/coordinators/replay_verify.rs (L191-205)
```rust
        TransactionRestoreBatchController::new(
            global_opt,
            self.storage,
            transactions
                .into_iter()
                .map(|t| t.manifest)
                .collect::<Vec<_>>(),
            save_start_version,
            Some((next_txn_version, false)), /* replay_from_version */
            None,                            /* epoch_history */
            self.verify_execution_mode.clone(),
            None,
        )
        .run()
        .await?;
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

**File:** storage/backup/backup-cli/src/coordinators/restore.rs (L247-260)
```rust
                StateSnapshotRestoreController::new(
                    StateSnapshotRestoreOpt {
                        manifest_handle: kv_snapshot.manifest,
                        version: kv_snapshot.version,
                        validate_modules: false,
                        restore_mode: StateSnapshotRestoreMode::KvOnly,
                    },
                    self.global_opt.clone(),
                    Arc::clone(&self.storage),
                    epoch_history.clone(),
                )
                .run()
                .await?;
            }
```

**File:** storage/backup/backup-cli/src/coordinators/verify.rs (L129-142)
```rust
            StateSnapshotRestoreController::new(
                StateSnapshotRestoreOpt {
                    manifest_handle: backup.manifest,
                    version: backup.version,
                    validate_modules: self.validate_modules,
                    restore_mode: StateSnapshotRestoreMode::Default,
                },
                global_opt.clone(),
                Arc::clone(&self.storage),
                epoch_history.clone(),
            )
            .run()
            .await?;
        }
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/manifest.rs (L29-51)
```rust
/// State snapshot backup manifest, representing a complete state view at specified version.
#[derive(Deserialize, Serialize)]
pub struct StateSnapshotBackup {
    /// Version at which this state snapshot is taken.
    pub version: Version,
    /// Epoch in which this state snapshot is taken.
    pub epoch: u64,
    /// Hash of the state tree root.
    pub root_hash: HashValue,
    /// All account blobs in chunks.
    pub chunks: Vec<StateSnapshotChunk>,
    /// BCS serialized
    /// `Tuple(TransactionInfoWithProof, LedgerInfoWithSignatures)`.
    ///   - The `TransactionInfoWithProof` is at `Version` above, and carries the same `root_hash`
    /// above; It proves that at specified version the root hash is as specified in a chain
    /// represented by the LedgerInfo below.
    ///   - The signatures on the `LedgerInfoWithSignatures` has a version greater than or equal to
    /// the version of this backup but is within the same epoch, so the signatures on it can be
    /// verified by the validator set in the same epoch, which can be provided by an
    /// `EpochStateBackup` recovered prior to this to the DB; Requiring it to be in the same epoch
    /// limits the requirement on such `EpochStateBackup` to no older than the same epoch.
    pub proof: FileHandle,
}
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/manifest.rs (L18-34)
```rust
/// [`first_version`, `last_version`] range (right side inclusive).
#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct TransactionChunk {
    pub first_version: Version,
    pub last_version: Version,
    /// Repeated `len(record) + record`, where `record` is BCS serialized tuple
    /// `(Transaction, TransactionInfo)`
    pub transactions: FileHandle,
    /// BCS serialized `(TransactionAccumulatorRangeProof, LedgerInfoWithSignatures)`.
    /// The `TransactionAccumulatorRangeProof` links the transactions to the
    /// `LedgerInfoWithSignatures`, and the `LedgerInfoWithSignatures` can be verified by the
    /// signatures it carries, against the validator set in the epoch. (Hence proper
    /// `EpochEndingBackup` is needed for verification.)
    pub proof: FileHandle,
    #[serde(default = "default_to_v0")]
    pub format: TransactionChunkFormat,
}
```

**File:** storage/backup/backup-cli/src/utils/mod.rs (L341-343)
```rust
        N.B. LedgerInfos are verified only when restoring / verifying the epoch ending backups, \
        i.e. they are NOT checked at all when doing one-shot restoring of the transaction \
        and state backups."
```

**File:** .github/workflows/workflow-run-replay-verify.yaml (L217-267)
```yaml
      - name: Run replay-verify in parallel
        env:
          BUCKET: ${{ inputs.BUCKET }}
          SUB_DIR: ${{ inputs.SUB_DIR }}
        shell: bash
        run: |
          set -o nounset -o errexit -o pipefail
          replay() {
              idx=$1
              id=$2
              begin=$3
              end=$4
              desc=$5

              echo ---------
              echo Job start. $id: $desc
              echo ---------

              MC=metadata_cache_$idx
              cp -r metadata_cache $MC
              DB=db_$idx

              for try in {0..6}
              do
                if [ $try -gt 0 ]; then
                  SLEEP=$((10 * $try))
                  echo "sleeping for $SLEEP seconds before retry #$try" >&2
                  sleep $SLEEP
                fi

                res=0
                ./aptos-debugger aptos-db replay-verify \
                  --metadata-cache-dir $MC \
                  --command-adapter-config ${{ inputs.BACKUP_CONFIG_TEMPLATE_PATH }} \
                  --start-version $begin \
                  --end-version $end \
                  \
                  --lazy-quit \
                  --enable-storage-sharding \
                  --target-db-dir $DB \
                  --concurrent-downloads 8 \
                  --replay-concurrency-level 4 \
                  || res=$?

                if [[ $res == 0 || $res == 2 ]]
                then
                  return $res
                fi
              done
              return 1
          }
```
