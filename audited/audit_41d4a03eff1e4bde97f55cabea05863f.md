# Audit Report

## Title
Backup Restoration Process Accepts Untrusted Data Without Cryptographic Signature Verification

## Summary
The Aptos backup restoration process fails to validate cryptographic signatures on `LedgerInfoWithSignatures` objects when neither trusted waypoints nor epoch history are provided. This allows an attacker with write access to backup storage to inject completely fabricated blockchain state that will be accepted as valid during restoration, leading to loss of funds and consensus violations.

## Finding Description

The backup restoration system validates Merkle proofs of transactions and state data against a `LedgerInfoWithSignatures` object, but critically fails to verify the cryptographic signatures on that ledger info itself when certain optional parameters are not provided.

**The Attack Flow:**

1. The `ReplayVerifyCoordinator` explicitly passes `None` for `epoch_history` to both state snapshot and transaction restore controllers: [1](#0-0) [2](#0-1) 

2. The `TrustedWaypointOpt` parameter is optional and defaults to an empty vector: [3](#0-2) 

3. The `StateSnapshotRestoreController` loads the `LedgerInfoWithSignatures` directly from untrusted backup storage and only verifies signatures if `epoch_history` is provided: [4](#0-3) 

4. The verification only checks that the Merkle proof is internally consistent with the (unverified) ledger info, not that the ledger info itself is authentic: [5](#0-4) 

5. The underlying `verify()` method only validates Merkle accumulator proofs, NOT BLS signatures: [6](#0-5) 

6. The same vulnerability exists in `TransactionRestoreBatchController`: [7](#0-6) [8](#0-7) 

The documentation explicitly acknowledges that signatures are not checked in this path: [9](#0-8) 

**Exploitation Path:**

An attacker who compromises backup storage (e.g., misconfigured S3 bucket, malicious backup provider) can:
1. Create a fake blockchain state with arbitrary transactions (token minting, unauthorized transfers)
2. Generate valid internal Merkle tree structures for this fake state
3. Create a `LedgerInfoWithSignatures` with invalid/missing validator signatures
4. An operator running restore without `--trust-waypoint` flags will accept this fake data because:
   - The Merkle proofs are internally consistent
   - The validator signatures are never checked
   - No comparison to any trusted source occurs

## Impact Explanation

This vulnerability meets **Critical Severity** criteria under the Aptos bug bounty program:

1. **Loss of Funds**: An attacker can create fake transactions showing arbitrary token balances, enabling theft or minting of tokens. Restored nodes will accept this fake financial state as valid.

2. **Consensus/Safety Violations**: The restored node operates with a completely different blockchain history than the honest network, fundamentally breaking consensus safety guarantees. This violates the critical invariant that "All validators must produce identical state roots for identical blocks."

3. **Non-Recoverable Network Partition**: Nodes restored from malicious backups will diverge permanently from the honest network, potentially requiring a hard fork to remediate if the compromise goes undetected.

4. **Cryptographic Correctness Violation**: The system fails to enforce the invariant that "BLS signatures, VRF, and hash operations must be secure" by skipping signature verification entirely.

The vulnerability is particularly severe because operators may not realize they need to provide trusted waypoints - the parameter is optional and the security implications of omitting it are not enforced by the code.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploited because:

1. **Realistic Attack Surface**: Backup storage is a common attack target with documented compromises in production systems. Cloud storage misconfigurations, compromised credentials, and malicious backup providers are all realistic threat vectors.

2. **Low Attacker Requirements**: The attacker needs only write access to backup storage, not validator private keys or consensus participation. This is a significantly lower bar than most blockchain attacks.

3. **User Error Prone**: The `--trust-waypoint` flag is optional, and operators may not understand its security implications. The system provides no warning when running without this critical safeguard.

4. **Silent Failure**: The vulnerability allows malicious data to be silently accepted. There are no error messages or warnings that signature verification was skipped.

5. **Wide Applicability**: This affects all restore and replay-verify operations, which are commonly used during node recovery, testing, and verification workflows.

## Recommendation

**Immediate Fix**: Make trusted waypoints mandatory for restoration operations or implement automatic signature verification using built-in genesis state.

**Recommended Implementation:**

1. Modify `TrustedWaypointOpt` to require at least one waypoint:

```rust
impl TrustedWaypointOpt {
    pub fn verify(self) -> Result<HashMap<Version, Waypoint>> {
        ensure!(
            !self.trust_waypoint.is_empty(),
            "At least one trusted waypoint must be provided for secure backup restoration. \
            Use --trust-waypoint to specify known-good ledger versions."
        );
        // ... existing logic
    }
}
```

2. Alternative: Always verify LedgerInfo signatures against the genesis validator set when epoch_history is None:

```rust
// In StateSnapshotRestoreController::run_impl
if self.epoch_history.is_none() {
    // Load genesis epoch state and verify signatures
    let genesis_epoch_state = /* load from genesis */;
    li.verify_signatures(&genesis_epoch_state.verifier())?;
}
```

3. Add explicit warnings in documentation and CLI help text that restoration without trusted waypoints is insecure.

4. Consider making epoch history mandatory for all non-genesis restorations.

## Proof of Concept

**Setup Requirements:**
- Access to backup storage (local or cloud)
- Aptos db-tool with replay-verify functionality

**PoC Steps:**

```rust
// 1. Create malicious backup data with fake LedgerInfo (no valid signatures)
use aptos_types::ledger_info::{LedgerInfo, LedgerInfoWithSignatures};

// Create fake ledger info with arbitrary state
let fake_ledger_info = LedgerInfo::new(
    /* fake blockchain state with attacker's desired balances */
);

// Create LedgerInfoWithSignatures WITHOUT valid validator signatures
let fake_li_with_sigs = LedgerInfoWithSignatures::new(
    fake_ledger_info,
    AggregateSignature::empty(), // No valid signatures!
);

// 2. Package this with internally-consistent Merkle proofs
// (attacker controls entire tree, so can generate valid proofs)

// 3. Upload to backup storage

// 4. Run restore WITHOUT trusted waypoints
// Command: aptos-db-tool replay-verify --target-db-dir ./db --backup-dir ./malicious-backup
// Note: No --trust-waypoint flags provided

// Result: The fake data is accepted because signatures are never checked
// The restored node now has completely fabricated blockchain state
```

**Verification:**
After restoration, query the node's state - it will return the attacker's fabricated data (fake balances, fake transactions) as if it were legitimate blockchain history. The node will fail to sync with honest peers because its state root doesn't match the real network.

## Notes

This vulnerability specifically affects the replay-verify coordinator and general restore operations when used without security safeguards. The code explicitly documents that signature verification is skipped in certain paths, suggesting this may have been an intentional design decision for convenience. However, making signature verification optional without enforcing it through required parameters or clear warnings creates a critical security gap that violates defense-in-depth principles for blockchain systems.

The vulnerability is particularly concerning because it affects disaster recovery procedures - the exact scenarios where operators are under stress and may overlook security parameters.

### Citations

**File:** storage/backup/backup-cli/src/coordinators/replay_verify.rs (L184-184)
```rust
                    None, /* epoch_history */
```

**File:** storage/backup/backup-cli/src/coordinators/replay_verify.rs (L200-200)
```rust
            None,                            /* epoch_history */
```

**File:** storage/backup/backup-cli/src/utils/mod.rs (L332-346)
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
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L125-139)
```rust
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
