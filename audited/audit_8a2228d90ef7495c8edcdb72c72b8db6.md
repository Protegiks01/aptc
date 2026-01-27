# Audit Report

## Title
State Snapshot Restore Version Mismatch Enables Consensus Safety Violation Through State Root Inconsistency

## Summary
The `StateSnapshotRestoreController` does not verify that the user-specified restore version (`--state-into-version`) matches the actual version in the backup manifest, allowing validators to restore state data from one version while tagging it as a different version in the database. This breaks the fundamental consensus invariant that all validators must have identical state roots at the same version, enabling non-recoverable network partitions.

## Finding Description

The vulnerability exists in the state snapshot restoration flow where two critical versions are never validated against each other: [1](#0-0) 

The controller accepts a user-specified version via `--state-into-version` (stored as `self.version`) and a manifest file via `--state-manifest`. The manifest contains its own version field (`manifest.version`) representing the actual blockchain version at which the snapshot was taken: [2](#0-1) 

The restore process validates the manifest cryptographically against its embedded version: [3](#0-2) 

However, when creating the state restore receiver, the code uses `self.version` (user-provided) instead of `manifest.version`: [4](#0-3) 

This version directly tags all state data written to the database. The state value restore uses this version as the key component: [5](#0-4) 

Similarly, the Jellyfish Merkle tree nodes are tagged with this version: [6](#0-5) 

**Attack Scenario:**

1. Validator A restores state using: `--state-into-version 1000 --state-manifest manifest_v500.json`
2. The system validates that `manifest_v500.json` is cryptographically valid for version 500
3. But stores all state data tagged as version 1000
4. Validator A now has version 500's state root at version 1000's position
5. Other validators with correct state at version 1000 have a different state root
6. When consensus attempts to agree on blocks building from version 1000, validators disagree on state roots
7. Consensus safety is violated - the network experiences a non-recoverable partition

This breaks the **Deterministic Execution** invariant: "All validators must produce identical state roots for identical blocks."

## Impact Explanation

This is a **Critical Severity** vulnerability under the Aptos bug bounty program criteria for the following reasons:

**Consensus/Safety Violation:** The fundamental safety property of AptosBFT consensus requires all honest validators to maintain identical state at each version. This vulnerability allows state root divergence, which means validators computing block execution from the same version will produce different results, breaking consensus agreement.

**Non-recoverable Network Partition:** If multiple validators restore state with mismatched versions, the network can split into disjoint sets that cannot agree on block validity. This requires a coordinated hardfork to recover, as the state inconsistency is written to persistent storage and survives restarts.

**Chain Fork Potential:** Validators with incorrect state roots for the same version will disagree about which blocks are valid, potentially leading to multiple competing chains if the inconsistency affects enough stake weight.

The proof verification in `TransactionInfoWithProof::verify` only ensures the manifest is valid for its claimed version, but does not prevent storing that data under a different version label: [7](#0-6) [8](#0-7) 

## Likelihood Explanation

**Likelihood: High**

This vulnerability can be triggered through:

1. **Operator Error:** An honest validator operator accidentally provides mismatched command-line parameters during state snapshot restoration (e.g., using an old manifest with a new target version)

2. **Malicious Validator:** A Byzantine validator intentionally misconfigures their node to diverge from consensus, though this requires no special privileges beyond running the db-tool

3. **Automated Tooling Bugs:** Scripts or automation tools that manage backup/restore operations could have logic errors that pass incorrect version parameters

The attack requires no special privileges - only the ability to run the `db-tool` restore command with chosen parameters. The command-line interface accepts both parameters separately with no cross-validation: [9](#0-8) 

## Recommendation

Add explicit validation that the user-specified restore version matches the version in the manifest before proceeding with restoration:

```rust
async fn run_impl(self) -> Result<()> {
    if self.version > self.target_version {
        warn!(
            "Trying to restore state snapshot to version {}, which is newer than the target version {}, skipping.",
            self.version,
            self.target_version,
        );
        return Ok(());
    }

    let manifest: StateSnapshotBackup =
        self.storage.load_json_file(&self.manifest_handle).await?;
    
    // ADD THIS VALIDATION
    ensure!(
        self.version == manifest.version,
        "Version mismatch: attempting to restore manifest for version {} as version {}. \
         This would cause state root inconsistency. Use --state-into-version {} to match the manifest.",
        manifest.version,
        self.version,
        manifest.version,
    );
    
    let (txn_info_with_proof, li): (TransactionInfoWithProof, LedgerInfoWithSignatures) =
        self.storage.load_bcs_file(&manifest.proof).await?;
    // ... rest of the function
}
```

This ensures that:
1. The cryptographic proof validates state for version X
2. The state is stored in the database tagged as version X
3. No state root inconsistency can occur across validators

## Proof of Concept

**Prerequisites:**
- Two state snapshot manifests for different versions (e.g., version 500 and 1000)
- Access to the `db-tool` CLI

**Step 1:** Create a valid manifest for version 500:
```bash
# Assume we have manifest_v500.json with manifest.version = 500
# And manifest_v1000.json with manifest.version = 1000
```

**Step 2:** Attempt to restore version 500 manifest as version 1000:
```bash
cargo run --bin aptos-db-tool -- restore oneoff state-snapshot \
    --state-into-version 1000 \
    --state-manifest manifest_v500.json \
    --restore-mode default \
    --target-db-dir /tmp/aptos_test_db \
    --concurrent-downloads 4
```

**Expected Vulnerable Behavior:**
- The command succeeds
- Cryptographic verification passes (manifest is valid for version 500)
- State data from version 500 is written to database tagged as version 1000
- State root at version 1000 now differs from what other validators have

**Expected Secure Behavior (with fix):**
- The command fails with error: "Version mismatch: attempting to restore manifest for version 500 as version 1000"
- No state data is written to database
- Database remains consistent

**Verification:**
After restoration, query the state root at version 1000 and compare with a correctly-restored validator. They will differ, proving the vulnerability enables state root inconsistency.

### Citations

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L49-59)
```rust
#[derive(Parser)]
pub struct StateSnapshotRestoreOpt {
    #[clap(long = "state-manifest")]
    pub manifest_handle: FileHandle,
    #[clap(long = "state-into-version")]
    pub version: Version,
    #[clap(long)]
    pub validate_modules: bool,
    #[clap(long)]
    pub restore_mode: StateSnapshotRestoreMode,
}
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L83-96)
```rust
        Self {
            storage,
            run_mode: global_opt.run_mode,
            version: opt.version,
            manifest_handle: opt.manifest_handle,
            target_version: global_opt.target_version,
            epoch_history,
            concurrent_downloads: global_opt.concurrent_downloads,
            validate_modules: opt.validate_modules,
            restore_mode: opt.restore_mode,
        }
    }

    pub async fn run(self) -> Result<()> {
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L123-136)
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
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L141-145)
```rust
        let receiver = Arc::new(Mutex::new(Some(self.run_mode.get_state_restore_receiver(
            self.version,
            manifest.root_hash,
            self.restore_mode,
        )?)));
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

**File:** storage/aptosdb/src/state_restore/mod.rs (L117-120)
```rust
        let kv_batch: StateValueBatch<K, Option<V>> = chunk
            .into_iter()
            .map(|(k, v)| ((k, self.version), Some(v)))
            .collect();
```

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L456-461)
```rust
                        ChildInfo::Leaf(LeafNode::new(
                            new_hashed_key,
                            new_value_hash,
                            (new_key.clone(), self.version),
                        )),
                    );
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
