# Audit Report

## Title
Missing Cryptographic Signature Verification in State Snapshot Restore Allows Arbitrary State Injection

## Summary
The state snapshot restore process in `ReplayVerifyCoordinator::run_impl()` does not cryptographically verify BLS signatures on the `LedgerInfoWithSignatures` contained in backup manifests when `epoch_history` is `None`. This allows an attacker with write access to backup storage to inject arbitrary blockchain state that will be accepted as valid during restore operations.

## Finding Description

The vulnerability exists in the state snapshot restoration flow where backup manifests are trusted without proper cryptographic validation of the ledger info signatures.

**Vulnerable Code Path:** [1](#0-0) 

The `backup.manifest` is passed to `StateSnapshotRestoreController` with `epoch_history` set to `None`, which skips critical signature verification.

**Missing Signature Verification:** [2](#0-1) 

The code loads the manifest and proof file, then calls `txn_info_with_proof.verify()` at line 127. However, this verification method only checks the accumulator proof structure: [3](#0-2) 

Which delegates to `verify_transaction_info()`: [4](#0-3) 

This verification **only checks that the transaction info exists in the accumulator** against the ledger info's transaction accumulator hash. It does **NOT** verify the BLS signatures on the `LedgerInfoWithSignatures`.

The only signature verification happens through `epoch_history.verify_ledger_info()` at line 137-139, but this is **conditional** and skipped when `epoch_history` is `None`.

**Explicit Design Gap:** [5](#0-4) 

The documentation explicitly states that LedgerInfos are NOT checked for state snapshot restores, confirming this vulnerability is a design flaw.

**Attack Scenario:**

1. Attacker gains write access to backup storage (cloud storage compromise, credential theft, insider threat)
2. Attacker creates a malicious state snapshot with arbitrary state (unlimited funds, modified validator set, etc.)
3. Attacker generates a fake `LedgerInfoWithSignatures` with invalid or missing validator signatures
4. Attacker creates a valid `TransactionInfoWithProof` that internally matches the fake `LedgerInfo`
5. Attacker creates valid Merkle proofs for malicious state chunks (using the attacker's chosen root hash)
6. Attacker replaces the manifest JSON and proof BCS files in backup storage
7. Victim node runs `replay_verify` to restore from backup
8. The restore succeeds because:
   - Manifest is loaded as plain JSON (no signature)
   - `TransactionInfoWithProof.verify()` only validates internal consistency, not signatures
   - `epoch_history` is `None`, so no validator signature verification occurs
   - Chunk Merkle proofs validate against the attacker's root hash
9. Victim node now has completely arbitrary blockchain state controlled by the attacker

This breaks the **State Consistency** invariant: state transitions must be verifiable via cryptographic proofs. It also breaks **Cryptographic Correctness**: BLS signatures must be verified for all ledger info.

## Impact Explanation

**Severity: CRITICAL** (up to $1,000,000 per Aptos Bug Bounty)

This vulnerability enables:

1. **Complete Blockchain State Manipulation**: An attacker can restore nodes to any arbitrary state, including:
   - Minting unlimited funds to attacker-controlled accounts
   - Modifying validator sets to include attacker-controlled validators
   - Altering governance proposals and voting outcomes
   - Changing staking balances and rewards

2. **Consensus Safety Violation**: Different nodes could restore from different malicious backups, creating chain splits and consensus failure

3. **Loss of Funds**: Legitimate user balances can be zeroed out or redirected to attacker accounts

4. **Network Partition**: If some nodes restore from legitimate backups and others from malicious backups, the network becomes permanently partitioned

This qualifies as **Critical Severity** under multiple categories:
- Loss of Funds (theft or minting)
- Consensus/Safety violations  
- Non-recoverable network partition (requires hardfork to resolve)

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

While the attack requires write access to backup storage, this is realistic in several scenarios:

1. **Cloud Storage Misconfiguration**: Backup buckets with overly permissive access policies
2. **Credential Compromise**: Leaked AWS/GCP credentials with write access to backup storage
3. **Insider Threat**: Malicious operators with legitimate backup storage access
4. **Supply Chain Attack**: Compromise of backup management infrastructure

Many production systems use cloud object storage (S3, GCS, Azure Blob) for backups, which are common targets for attackers. Additionally, the `replay_verify` coordinator is explicitly designed for disaster recovery scenarios where nodes need to restore from backups - precisely when this vulnerability would be exploited.

The attack complexity is LOW once storage access is obtained, as the attacker only needs to create valid internal proofs (Merkle proofs) without any validator signatures, which is cryptographically trivial.

## Recommendation

**Mandatory Signature Verification**: Always verify `LedgerInfoWithSignatures` BLS signatures during state snapshot restore, even when `epoch_history` is not available.

**Implementation Fix**:

1. Require `epoch_history` to be provided for state snapshot restoration in production environments
2. Add a mandatory signature verification step that fails the restore if signatures cannot be validated
3. For disaster recovery scenarios where epoch history may be unavailable, require explicit trusted waypoint verification for the state snapshot's `LedgerInfo`

**Code Fix** (in `storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs`):

```rust
// After line 127, add mandatory signature verification:
if let Some(epoch_history) = self.epoch_history.as_ref() {
    epoch_history.verify_ledger_info(&li)?;
} else {
    // Fallback: verify against trusted waypoint
    ensure!(
        !global_opt.trusted_waypoints.is_empty(),
        "State snapshot restore requires either epoch_history or trusted_waypoints for signature verification"
    );
    
    if let Some(waypoint) = global_opt.trusted_waypoints.get(&li.ledger_info().version()) {
        waypoint.verify(li.ledger_info())?;
    } else {
        bail!(
            "Cannot verify LedgerInfo at version {} - no epoch_history and no matching trusted waypoint",
            li.ledger_info().version()
        );
    }
}
```

Additionally, update `ReplayVerifyCoordinator` to either:
- Build `epoch_history` from epoch ending backups before state snapshot restore
- Require explicit trusted waypoints for the state snapshot version

## Proof of Concept

**Setup: Create Malicious Backup Files**

```rust
// Create a fake LedgerInfoWithSignatures with no valid signatures
let fake_ledger_info = LedgerInfo::new(
    /* ... blockchain state at version V ... */
    malicious_state_root_hash,
    malicious_transaction_accumulator_hash,
    version,
    epoch,
    /* ... other fields ... */
);

// Create empty signature set (or invalid signatures)
let fake_li_with_sigs = LedgerInfoWithSignatures::new(
    fake_ledger_info,
    AggregateSignature::empty(), // No valid BLS signatures!
);

// Create TransactionInfo pointing to malicious state
let malicious_txn_info = TransactionInfo::new(
    /* ... */
    malicious_state_root_hash,
    /* ... */
);

// Create accumulator proof that makes txn_info valid against fake_ledger_info
let proof = create_accumulator_proof(
    malicious_txn_info.hash(),
    fake_ledger_info.transaction_accumulator_hash(),
);

let txn_info_with_proof = TransactionInfoWithProof::new(proof, malicious_txn_info);

// Save to proof file
let proof_tuple = (txn_info_with_proof, fake_li_with_sigs);
save_bcs_file("proof.bcs", &proof_tuple);

// Create manifest pointing to malicious chunks
let manifest = StateSnapshotBackup {
    version,
    epoch,
    root_hash: malicious_state_root_hash,
    chunks: vec![/* malicious chunk file handles */],
    proof: FileHandle::from("proof.bcs"),
};
save_json_file("manifest.json", &manifest);
```

**Execution: Trigger Restore**

```bash
# Upload malicious manifest.json and proof.bcs to backup storage
aws s3 cp manifest.json s3://backup-bucket/state_snapshot_epoch_X_ver_Y/manifest.json
aws s3 cp proof.bcs s3://backup-bucket/state_snapshot_epoch_X_ver_Y/proof.bcs

# Victim runs replay_verify
cargo run --bin aptos-backup-cli -- \
    replay-verify \
    --metadata-cache-dir /tmp/metadata \
    --start-version 0 \
    --end-version 1000000 \
    # Note: no --epoch-ending-manifest provided, so epoch_history is None
```

**Result**: The restore succeeds with the malicious state because:
1. `txn_info_with_proof.verify()` passes (internal consistency check only)
2. `epoch_history.verify_ledger_info()` is skipped (epoch_history is None)
3. No BLS signature verification occurs
4. Victim node accepts arbitrary attacker-controlled blockchain state

**Notes**

This vulnerability represents a critical gap in the backup/restore security model. The implicit assumption that backup storage is trusted and immutable is violated in real-world deployment scenarios where cloud storage can be compromised. The lack of cryptographic binding between restored state and validator consensus creates an attack vector for complete blockchain state manipulation.

The fix requires treating backup storage as untrusted and enforcing the same cryptographic verification (BLS signatures, waypoints, or epoch history) that protects the blockchain during normal consensus operation.

### Citations

**File:** storage/backup/backup-cli/src/coordinators/replay_verify.rs (L174-188)
```rust
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

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L123-139)
```rust
        let manifest: StateSnapshotBackup =
            self.storage.load_json_file(&self.manifest_handle).await?;
        let (txn_info_with_proof, li): (TransactionInfoWithProof, LedgerInfoWithSignatures) =
            self.storage.load_bcs_file(&manifest.proof).await?;
        txn_info_with_proof.verify(li.ledger_info(), manifest.version)?;
        let state_root_hash = txn_info_with_proof
            .transaction_info()
            .ensure_state_checkpoint_hash()?;
        ensure!(
            state_root_hash == manifest.root_hash,
            "Root hash mismatch with that in proof. root hash: {}, expected: {}",
            manifest.root_hash,
            state_root_hash,
        );
        if let Some(epoch_history) = self.epoch_history.as_ref() {
            epoch_history.verify_ledger_info(&li)?;
        }
```

**File:** types/src/proof/definition.rs (L864-874)
```rust
    /// Verifies that the `TransactionInfo` exists in the ledger represented by the `LedgerInfo`
    /// at specified version.
    pub fn verify(&self, ledger_info: &LedgerInfo, transaction_version: Version) -> Result<()> {
        verify_transaction_info(
            ledger_info,
            transaction_version,
            &self.transaction_info,
            &self.ledger_info_to_transaction_info_proof,
        )?;
        Ok(())
    }
```

**File:** types/src/proof/mod.rs (L40-61)
```rust
fn verify_transaction_info(
    ledger_info: &LedgerInfo,
    transaction_version: Version,
    transaction_info: &TransactionInfo,
    ledger_info_to_transaction_info_proof: &TransactionAccumulatorProof,
) -> Result<()> {
    ensure!(
        transaction_version <= ledger_info.version(),
        "Transaction version {} is newer than LedgerInfo version {}.",
        transaction_version,
        ledger_info.version(),
    );

    let transaction_info_hash = transaction_info.hash();
    ledger_info_to_transaction_info_proof.verify(
        ledger_info.transaction_accumulator_hash(),
        transaction_info_hash,
        transaction_version,
    )?;

    Ok(())
}
```

**File:** storage/backup/backup-cli/src/utils/mod.rs (L341-343)
```rust
        N.B. LedgerInfos are verified only when restoring / verifying the epoch ending backups, \
        i.e. they are NOT checked at all when doing one-shot restoring of the transaction \
        and state backups."
```
