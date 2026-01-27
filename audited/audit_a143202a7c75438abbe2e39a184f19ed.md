# Audit Report

## Title
Unauthenticated State Injection via Compromised Backup Storage When Epoch History Verification is Disabled

## Summary
The backup restore system allows complete bypass of cryptographic authentication when `epoch_history` is `None`, enabling attackers who compromise backup storage (S3/GCS) to inject arbitrary malicious blockchain state. The `ReadRecordBytes` trait reads data from untrusted storage, but the critical vulnerability occurs in the verification logic that optionally skips BLS signature validation of `LedgerInfoWithSignatures`.

## Finding Description
The backup restore system implements a multi-layer verification chain to authenticate restored data. However, this chain is broken when `epoch_history` parameter is `None`, which occurs in two documented scenarios:

1. **One-off restores via db-tool**: The state snapshot oneoff command always passes `None` for `epoch_history` [1](#0-0) 

2. **Coordinator with --skip-epoch-endings flag**: The RestoreCoordinator allows skipping epoch history restoration via CLI flag [2](#0-1) 

When `epoch_history` is `None`, the state snapshot restore verification flow becomes:

**Step 1**: Load manifest from storage (untrusted JSON) [3](#0-2) 

**Step 2**: Load proof file containing `TransactionInfoWithProof` and `LedgerInfoWithSignatures` [4](#0-3) 

**Step 3**: Verify TransactionInfo against LedgerInfo using accumulator proof [5](#0-4) 

**Step 4 (CRITICAL)**: Conditionally verify LedgerInfo signatures - **SKIPPED when epoch_history is None** [6](#0-5) 

The `TransactionInfoWithProof::verify()` method only validates that the TransactionInfo is consistent with the LedgerInfo via accumulator proof [7](#0-6) . It does **NOT** verify the authenticity of the LedgerInfo itself.

**Attack Execution Path**:

An attacker who compromises backup storage can:

1. Generate a completely fabricated state tree with arbitrary key-value pairs
2. Compute the Merkle root hash of this malicious tree
3. Create a fake `TransactionInfo` containing this fake root hash as `state_checkpoint_hash`
4. Build a fake transaction accumulator tree containing the fake TransactionInfo
5. Create a fake `LedgerInfo` with the accumulator root pointing to the fake accumulator
6. Create a fake `LedgerInfoWithSignatures` with **invalid or no BLS signatures** (verification will be skipped!)
7. Generate valid Merkle accumulator proofs connecting the fake TransactionInfo to fake LedgerInfo
8. Generate valid Sparse Merkle Range Proofs for all state chunks against the fake root hash
9. Replace backup files in S3/GCS with these fabricated files

When the victim runs restoration with `--skip-epoch-endings` or uses db-tool oneoff command:
- All Merkle proofs validate correctly (against the fake roots)
- LedgerInfo signature verification is **skipped**
- Malicious state is successfully written to the database
- Node restarts with compromised state as source of truth

**Broken Invariants**:
- **State Consistency**: State transitions must be atomic and verifiable - the root hash itself is not cryptographically authenticated
- **Cryptographic Correctness**: BLS signatures must secure the system - they are optionally skipped

## Impact Explanation
**Critical Severity** per Aptos Bug Bounty criteria:

1. **Loss of Funds**: Attacker can modify account balances, steal tokens by granting themselves arbitrary amounts
2. **Consensus/Safety Violations**: Restored nodes operate with different state than the canonical chain, causing network partition
3. **Governance Compromise**: Attacker can manipulate voting power, stake pool states, validator sets
4. **Non-recoverable Network Damage**: If multiple nodes restore from compromised backups, reaching consensus on canonical state may require hardfork

The vulnerability enables complete compromise of restored node state without any cryptographic barriers when epoch history verification is disabled. This is a fundamental authentication bypass, not a configuration issue.

## Likelihood Explanation
**High Likelihood**:

**Attacker Requirements**:
- Compromise of backup storage (S3/GCS) - realistic for sophisticated attackers
- Victim must run restore with `epoch_history = None` - two documented scenarios make this common

**Realistic Scenarios**:
1. Node operators using db-tool for quick state recovery after disk failure
2. Setting up new nodes with `--skip-epoch-endings` to speed up initial sync
3. Backup storage credentials leaked or misconfigured

**Complexity**: Medium - requires understanding of Merkle tree construction but no cryptographic breaks needed

The combination of realistic attacker capabilities and documented usage patterns that disable verification makes this highly exploitable.

## Recommendation
**Mandatory Fix**: Always require cryptographic verification of `LedgerInfoWithSignatures`. Remove the optional path that skips signature validation.

**Implementation**:

1. **Make epoch_history mandatory** for state snapshot restore:
```rust
// In StateSnapshotRestoreController::new()
pub fn new(
    opt: StateSnapshotRestoreOpt,
    global_opt: GlobalRestoreOptions,
    storage: Arc<dyn BackupStorage>,
    epoch_history: Arc<EpochHistory>, // Remove Option<>
) -> Self
```

2. **Require trusted waypoints** as fallback when epoch history unavailable:
```rust
// In run_impl(), remove optional check
let epoch_history = self.epoch_history.as_ref();
epoch_history.verify_ledger_info(&li)?; // Always verify

// Or if trusted waypoints exist in global_opt
if !global_opt.trusted_waypoints.is_empty() {
    // Verify against trusted waypoint
} else {
    bail!("Cannot restore without epoch history or trusted waypoints");
}
```

3. **Remove --skip-epoch-endings flag** or make it only skip writing epoch data, not verification

4. **Update db-tool** to require epoch history manifest handle or trusted waypoint for state restoration

## Proof of Concept

**Prerequisites**: S3/GCS bucket containing Aptos backups with write access

**Step 1 - Generate Fake State**:
```rust
// Create malicious state with arbitrary balances
let fake_state: Vec<(StateKey, StateValue)> = vec![
    (attacker_balance_key, StateValue::new(Vec::from(1000000000u64.to_le_bytes()))),
    // ... more malicious state
];

// Build Merkle tree
let fake_root_hash = compute_merkle_root(&fake_state);
```

**Step 2 - Create Fake Proof Chain**:
```rust
// Create fake TransactionInfo
let fake_txn_info = TransactionInfo::new(
    HashValue::zero(), // transaction hash
    HashValue::zero(), // write set hash  
    HashValue::zero(), // event root
    Some(fake_root_hash), // state_checkpoint_hash
    0, // gas_used
    ExecutionStatus::Success,
);

// Build fake accumulator
let fake_accumulator = InMemoryTransactionAccumulator::new_empty();
fake_accumulator.append(&[fake_txn_info.hash()]);

// Create fake LedgerInfo (NO VALID SIGNATURES!)
let fake_ledger_info = LedgerInfo::new(
    BlockInfo::new(/*..., txn_accumulator_hash = fake_accumulator.root_hash()*/),
    HashValue::zero(), // consensus_data_hash
);

let fake_li_with_sigs = LedgerInfoWithSignatures::new(
    fake_ledger_info,
    BTreeMap::new(), // EMPTY SIGNATURES!
);
```

**Step 3 - Replace Backup Files**:
```bash
# Upload to compromised S3 bucket
aws s3 cp fake_manifest.json s3://bucket/state_snapshot/manifest.json
aws s3 cp fake_proof.bcs s3://bucket/state_snapshot/proof.bcs
aws s3 cp fake_chunk_*.bcs s3://bucket/state_snapshot/chunks/
```

**Step 4 - Victim Restores**:
```bash
# Using db-tool (always passes None for epoch_history)
aptos-db-tool restore oneoff state-snapshot \
    --state-manifest s3://bucket/state_snapshot/manifest.json \
    --target-db-dir /data/db

# State with attacker's fake balances now written to database!
```

**Verification**: Check restored database contains malicious state values without any signature verification occurring.

---

## Notes
This vulnerability demonstrates that the `ReadRecordBytes` trait itself is not the issue - it correctly reads length-prefixed records. The security failure occurs in the **optional cryptographic verification** layer above it. The trait works with any `AsyncRead`, which is acceptable **if and only if** the data is always cryptographically authenticated after reading. When authentication is optionally skipped, storage compromise leads to complete state injection.

### Citations

**File:** storage/db-tool/src/restore.rs (L88-95)
```rust
                        StateSnapshotRestoreController::new(
                            opt,
                            global.try_into()?,
                            storage.init_storage().await?,
                            None, /* epoch_history */
                        )
                        .run()
                        .await?;
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

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L123-124)
```rust
        let manifest: StateSnapshotBackup =
            self.storage.load_json_file(&self.manifest_handle).await?;
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L125-126)
```rust
        let (txn_info_with_proof, li): (TransactionInfoWithProof, LedgerInfoWithSignatures) =
            self.storage.load_bcs_file(&manifest.proof).await?;
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L127-127)
```rust
        txn_info_with_proof.verify(li.ledger_info(), manifest.version)?;
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L137-139)
```rust
        if let Some(epoch_history) = self.epoch_history.as_ref() {
            epoch_history.verify_ledger_info(&li)?;
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
