# Audit Report

## Title
Manifest Tampering Vulnerability in Transaction Backup Restore Process

## Summary
The transaction backup manifest is written as plain JSON without any cryptographic signature or MAC, allowing an attacker with storage access to modify the manifest and inject arbitrary transactions into a node's database when epoch history verification is disabled. [1](#0-0) 

## Finding Description

The backup system writes transaction manifests as unprotected JSON files that reference chunk files and proof files. [2](#0-1) 

During restore, the manifest verification only checks logical consistency (version ranges), not cryptographic integrity. [3](#0-2) 

The critical security flaw occurs in the `LoadedChunk::load` function during restore. When `epoch_history` is `None`, BLS signature verification on the `LedgerInfoWithSignatures` is completely skipped. [4](#0-3) 

The subsequent verification only checks that transactions match the `LedgerInfo` via Merkle proofs, but does NOT verify the `LedgerInfo` itself is legitimate. [5](#0-4) 

This vulnerability is exploitable in two scenarios:

1. **Oneoff::Transaction restore mode** - explicitly sets `epoch_history` to `None` [6](#0-5) 

2. **RestoreCoordinator with --skip-epoch-endings flag** - marks epoch_history as `None` when this debugging flag is set [7](#0-6) 

Notably, the TrustedWaypointOpt documentation explicitly states that LedgerInfos are NOT checked during one-shot transaction restore. [8](#0-7) 

**Attack Path:**
1. Attacker gains write access to backup storage (e.g., compromised S3 credentials, cloud storage breach)
2. Attacker creates malicious transaction data with arbitrary content
3. Attacker creates a fake `LedgerInfoWithSignatures` (without valid BLS signatures)
4. Attacker computes valid Merkle accumulator proofs linking transactions to the fake LedgerInfo
5. Attacker modifies the manifest JSON to point to the malicious chunk and proof files
6. Victim runs restore with `--skip-epoch-endings` or uses `Oneoff::Transaction` mode
7. The Merkle proof verification passes (line 167) because proofs are mathematically valid for the fake LedgerInfo
8. BLS signature verification is skipped (lines 152-154 check fails, no `epoch_history`)
9. Malicious transactions are saved directly to the database [9](#0-8) 

The restored node now has completely fabricated transaction history and divergent state from the legitimate network.

## Impact Explanation

This vulnerability represents a **High Severity** issue under Aptos bug bounty criteria for the following reasons:

1. **State Inconsistencies Requiring Intervention**: The restored node operates with false historical data, requiring manual intervention to detect and remediate

2. **Ecosystem Impact**: If the compromised node serves as an archive node, API endpoint, or data provider, it propagates false information to applications and users relying on that data

3. **Validator Node Impact**: A validator restoring from compromised backup would have incorrect state, causing participation issues and potential slowdowns, meeting the "Validator node slowdowns" criterion for High severity

4. **Storage Access Attack Vector**: The attack requires only storage access (not validator keys), making it realistic against nodes using cloud storage or shared backup infrastructure

While this does not achieve Critical severity (no network-wide consensus violation due to BFT safety, no direct fund loss), it does cause significant protocol violations through state corruption of individual nodes.

## Likelihood Explanation

**Likelihood: Medium**

**Attack Prerequisites:**
- Write access to backup storage location (cloud storage credentials, S3 bucket compromise, filesystem access)
- Victim must use restore modes with disabled epoch history verification

**Feasibility Factors:**

*Favorable to attacker:*
- Cloud storage compromises are realistic threat vectors
- The `Oneoff::Transaction` mode is a legitimate restore option, not just debugging
- No validator keys or cryptographic material required
- Manifest modification is straightforward (JSON editing)

*Limiting factors:*
- `--skip-epoch-endings` is documented as "for debugging", limiting production usage [10](#0-9) 
- Proper restore workflow via `RestoreCoordinator` includes epoch history verification
- Attack impact is node-specific, not network-wide

## Recommendation

**Implement manifest integrity protection through cryptographic signatures or HMAC:**

1. **Add manifest signing during backup:**
   - Generate a signing key pair specifically for backup integrity
   - Sign the manifest JSON with the private key before writing
   - Include the signature in the manifest metadata

2. **Verify manifest signature during restore:**
   - Load the public key from trusted configuration
   - Verify the manifest signature before processing
   - Reject manifests with invalid or missing signatures

3. **Alternative: Use HMAC with shared secret:**
   - Derive HMAC key from operator-controlled secret
   - Compute HMAC over manifest contents
   - Store HMAC in separate metadata file
   - Verify HMAC before trusting manifest content

**Code Fix Outline:**

In `backup.rs`, modify `write_manifest`:
```rust
async fn write_manifest(
    &self,
    backup_handle: &BackupHandleRef,
    first_version: Version,
    last_version: Version,
    chunks: Vec<TransactionChunk>,
) -> Result<FileHandle> {
    let manifest = TransactionBackup {
        first_version,
        last_version,
        chunks,
    };
    
    // NEW: Sign the manifest
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    let signature = self.signer.sign(&manifest_bytes)?;
    
    let signed_manifest = SignedManifest {
        manifest,
        signature,
    };
    
    // Write signed manifest instead of plain manifest
    manifest_file.write_all(&serde_json::to_vec(&signed_manifest)?).await?;
    // ... rest of function
}
```

In `restore.rs`, modify manifest loading to verify signature before use.

**Additional Hardening:**
- Make epoch history verification mandatory for production restores (remove `--skip-epoch-endings` from production tooling)
- Add warnings when restoring without epoch history verification
- Implement manifest hash verification at minimum, even if full signatures aren't deployed

## Proof of Concept

```rust
// PoC demonstrating manifest tampering attack
// This would be a Rust integration test in storage/backup/backup-cli/src/backup_types/transaction/

#[tokio::test]
async fn test_manifest_tampering_without_epoch_history() {
    // Setup: Create legitimate backup
    let (storage, temp_dir) = create_test_storage().await;
    let backup_handle = create_transaction_backup(&storage, 0, 100).await;
    
    // Attack Step 1: Read original manifest
    let manifest_handle = FileHandle::new(/* ... */);
    let mut original_manifest: TransactionBackup = 
        storage.load_json_file(&manifest_handle).await.unwrap();
    
    // Attack Step 2: Create fake chunk with malicious transactions
    let fake_txns = create_fake_transactions();
    let fake_txn_infos = compute_txn_infos(&fake_txns);
    let fake_ledger_info = create_fake_ledger_info(fake_txn_infos);
    let fake_proof = compute_merkle_proof(&fake_txn_infos);
    
    let fake_chunk_handle = write_fake_chunk(&storage, fake_txns).await;
    let fake_proof_handle = write_fake_proof(&storage, fake_proof, fake_ledger_info).await;
    
    // Attack Step 3: Modify manifest to point to fake chunks
    original_manifest.chunks[0].transactions = fake_chunk_handle;
    original_manifest.chunks[0].proof = fake_proof_handle;
    
    // Attack Step 4: Overwrite manifest with tampered version
    storage.save_json_file(&manifest_handle, &original_manifest).await.unwrap();
    
    // Attack Step 5: Restore without epoch_history (simulating --skip-epoch-endings)
    let restore_controller = TransactionRestoreController::new(
        TransactionRestoreOpt { manifest_handle, replay_from_version: None, kv_only_replay: None },
        global_opt,
        storage.clone(),
        None, // epoch_history = None, verification bypassed!
        VerifyExecutionMode::NoVerify,
    );
    
    // RESULT: Restore succeeds with fake transactions
    restore_controller.run().await.unwrap();
    
    // Verify: Database now contains fake transactions
    let db = open_restored_db();
    let restored_txn = db.get_transaction(0).unwrap();
    assert_eq!(restored_txn, fake_txns[0]); // Fake data successfully injected!
}
```

**Notes**

The vulnerability exists at the intersection of two design choices:
1. Manifests lack integrity protection (no signatures/MACs)
2. Restore modes exist that skip BLS signature verification

While some vulnerable modes are marked "for debugging", the `Oneoff::Transaction` restore is a legitimate operation mode. The manifest itself should have integrity protection regardless of whether full epoch history verification is performed, as it controls the routing of restore operations to specific chunk files.

The comment in the codebase explicitly acknowledges that LedgerInfo verification is skipped in one-shot restore scenarios, suggesting this may be a known limitation rather than an oversight. However, the lack of ANY integrity protection on the manifest file itself represents a security gap that enables storage-level attacks.

### Citations

**File:** storage/backup/backup-cli/src/backup_types/transaction/backup.rs (L205-208)
```rust
        manifest_file
            .write_all(&serde_json::to_vec(&manifest)?)
            .await?;
        manifest_file.shutdown().await?;
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/manifest.rs (L40-47)
```rust
/// Transaction backup manifest, representing transactions in the
/// [`first_version`, `last_version`] range (right side inclusive).
#[derive(Deserialize, Serialize)]
pub struct TransactionBackup {
    pub first_version: Version,
    pub last_version: Version,
    pub chunks: Vec<TransactionChunk>,
}
```

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

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L152-154)
```rust
        if let Some(epoch_history) = epoch_history {
            epoch_history.verify_ledger_info(&ledger_info)?;
        }
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L167-167)
```rust
        txn_list_with_proof.verify(ledger_info.ledger_info(), Some(manifest.first_version))?;
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L508-516)
```rust
                            restore_handler.save_transactions(
                                first_version,
                                &txns_to_save,
                                &persisted_aux_info_to_save,
                                &txn_infos_to_save,
                                &event_vecs_to_save,
                                write_sets_to_save,
                            )
                        })
```

**File:** storage/db-tool/src/restore.rs (L102-107)
```rust
                        TransactionRestoreController::new(
                            opt,
                            global.try_into()?,
                            storage.init_storage().await?,
                            None, /* epoch_history */
                            VerifyExecutionMode::NoVerify,
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

**File:** storage/backup/backup-cli/src/utils/mod.rs (L341-343)
```rust
        N.B. LedgerInfos are verified only when restoring / verifying the epoch ending backups, \
        i.e. they are NOT checked at all when doing one-shot restoring of the transaction \
        and state backups."
```
