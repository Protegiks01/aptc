# Audit Report

## Title
State Snapshot Restore Allows Arbitrary State Injection When Epoch Verification is Skipped

## Summary
The state snapshot restore functionality in `restore.rs` fails to properly validate that `TransactionInfoWithProof` corresponds to the claimed `manifest.version` when the `--skip-epoch-endings` flag is used. This allows an attacker controlling the backup source to restore arbitrary blockchain state at any version, breaking consensus safety and state consistency invariants. [1](#0-0) 

## Finding Description

The vulnerability exists in the `run_impl()` function's verification logic. The `TransactionInfo` structure does not contain a version field, relying entirely on cryptographic proof verification to ensure the transaction info corresponds to the correct version. [2](#0-1) 

At line 127, the code verifies the transaction info proof: [3](#0-2) 

However, both the `TransactionInfoWithProof` and `LedgerInfoWithSignatures` come from the same untrusted proof file. The verification at line 127 uses the `LedgerInfo`'s transaction accumulator hash as the expected root. When `epoch_history` is `None` (set via `--skip-epoch-endings` flag), the critical signature verification is bypassed: [4](#0-3) 

The `--skip-epoch-endings` flag is a CLI option marked "for debugging": [5](#0-4) 

When this flag is set, `epoch_history` becomes `None`: [6](#0-5) 

**Attack Path:**

1. Attacker creates malicious backup with manifest claiming version V but containing arbitrary state
2. Attacker constructs a fake transaction accumulator with malicious `TransactionInfo` at position V
3. Attacker provides corresponding `LedgerInfoWithSignatures` with fake accumulator root
4. Attacker provides valid accumulator proof for position V in their fake accumulator
5. Node operator restores using `--skip-epoch-endings`
6. Line 127 verification PASSES (proof is valid for fake accumulator)
7. Lines 131-136 pass (state_root_hash matches attacker-controlled value)
8. Malicious state is restored to the database

Line 128 does NOT catch this - it merely extracts the hash: [7](#0-6) 

## Impact Explanation

**Severity: Critical**

This vulnerability enables:
- **Consensus Safety Violation**: Nodes restored with malicious state will produce different state roots than honest nodes, causing chain splits
- **State Consistency Break**: The fundamental invariant that state at version V represents the actual blockchain history is violated
- **Potential Fund Theft**: Arbitrary account balances and ownership can be injected
- **Validator Set Manipulation**: Staking state can be arbitrarily modified

Per Aptos bug bounty criteria, this qualifies as Critical severity due to:
- Consensus/Safety violations
- State inconsistencies that could lead to loss of funds
- Potential for non-recoverable network partition [8](#0-7) 

The manifest documentation explicitly expects signature verification, indicating this is not intended behavior.

## Likelihood Explanation

**Likelihood: Medium to High**

The vulnerability is exploitable when:
1. Node operator uses `--skip-epoch-endings` flag (explicitly available, not hidden)
2. Attacker controls or compromises the backup data source
3. No additional safeguards exist in the deployment environment

While the flag is marked "for debugging," it:
- Is not disabled in production builds
- Has no security warning in help text
- May be used by operators for performance reasons without understanding implications
- Could be accidentally enabled in automated restore scripts

When normal epoch verification is used, the `EpochHistory` provides protection: [9](#0-8) 

## Recommendation

**Immediate Fix:**

1. Remove `--skip-epoch-endings` flag from production builds or add explicit security warnings
2. Make epoch history verification mandatory for production restores
3. Add explicit version validation in `TransactionInfo` structure or add secondary verification

**Code Fix:**

```rust
async fn run_impl(self) -> Result<()> {
    // ... existing code ...
    
    let manifest: StateSnapshotBackup = 
        self.storage.load_json_file(&self.manifest_handle).await?;
    let (txn_info_with_proof, li): (TransactionInfoWithProof, LedgerInfoWithSignatures) =
        self.storage.load_bcs_file(&manifest.proof).await?;
    
    // MANDATORY: Verify LedgerInfo signatures
    let epoch_history = self.epoch_history.as_ref()
        .ok_or_else(|| anyhow!("Epoch history required for secure state restore. Do not use --skip-epoch-endings in production."))?;
    epoch_history.verify_ledger_info(&li)?;
    
    // Verify transaction info at claimed version
    txn_info_with_proof.verify(li.ledger_info(), manifest.version)?;
    
    // ... rest of verification ...
}
```

## Proof of Concept

**Setup:**
1. Create malicious backup manifest with `version=100`, `root_hash=AttackerChosenHash`
2. Generate fake `LedgerInfoWithSignatures` with fake accumulator root
3. Create `TransactionInfoWithProof` with malicious state checkpoint hash
4. Generate valid accumulator proof for the fake accumulator

**Execution:**
```bash
# Restore with vulnerability enabled
aptos-db-tool restore \
    --target-version 100 \
    --skip-epoch-endings \  # Disables signature verification
    --state-manifest malicious_manifest.json
```

**Expected Result:**
- Verification at line 127 passes (valid proof for fake accumulator)
- Malicious state restored to database
- Node diverges from consensus when it syncs/validates

**Verification:**
Query restored state shows attacker-injected values rather than actual blockchain state at version 100.

### Citations

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L125-127)
```rust
        let (txn_info_with_proof, li): (TransactionInfoWithProof, LedgerInfoWithSignatures) =
            self.storage.load_bcs_file(&manifest.proof).await?;
        txn_info_with_proof.verify(li.ledger_info(), manifest.version)?;
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L128-130)
```rust
        let state_root_hash = txn_info_with_proof
            .transaction_info()
            .ensure_state_checkpoint_hash()?;
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L137-139)
```rust
        if let Some(epoch_history) = self.epoch_history.as_ref() {
            epoch_history.verify_ledger_info(&li)?;
        }
```

**File:** types/src/transaction/mod.rs (L2025-2051)
```rust
pub struct TransactionInfoV0 {
    /// The amount of gas used.
    gas_used: u64,

    /// The vm status. If it is not `Executed`, this will provide the general error class. Execution
    /// failures and Move abort's receive more detailed information. But other errors are generally
    /// categorized with no status code or other information
    status: ExecutionStatus,

    /// The hash of this transaction.
    transaction_hash: HashValue,

    /// The root hash of Merkle Accumulator storing all events emitted during this transaction.
    event_root_hash: HashValue,

    /// The hash value summarizing all changes caused to the world state by this transaction.
    /// i.e. hash of the output write set.
    state_change_hash: HashValue,

    /// The root hash of the Sparse Merkle Tree describing the world state at the end of this
    /// transaction. Depending on the protocol configuration, this can be generated periodical
    /// only, like per block.
    state_checkpoint_hash: Option<HashValue>,

    /// The hash value summarizing PersistedAuxiliaryInfo.
    auxiliary_info_hash: Option<HashValue>,
}
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

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/manifest.rs (L40-50)
```rust
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
