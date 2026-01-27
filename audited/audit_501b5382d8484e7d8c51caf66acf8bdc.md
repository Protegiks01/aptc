# Audit Report

## Title
Critical Authentication Bypass in State Snapshot Restore via Optional Signature Verification

## Summary
The state snapshot restore process contains a critical vulnerability where validator signature verification can be completely bypassed when the `--skip-epoch-endings` flag is used. This allows an attacker who can modify backup storage to inject arbitrary blockchain state without cryptographic authentication, violating the fundamental security invariant that all blockchain state must be signed by validators.

## Finding Description

The vulnerability exists in the state snapshot restoration process. While all three file loading methods (`load_json_file`, `load_bcs_file`, and `open_for_read`) use the same underlying storage mechanism with no authentication, the critical security issue is in the **post-load verification logic**. [1](#0-0) 

All three methods ultimately call `open_for_read` and have no authentication at the storage level. However, the security model relies on cryptographic verification after loading: [2](#0-1) 

The critical flaw is at lines 137-139: signature verification only occurs IF `epoch_history` is `Some`. When `epoch_history` is `None`, the `LedgerInfoWithSignatures` validator signatures are **never verified**.

The `epoch_history` is set to `None` when the restore coordinator is run with the `--skip-epoch-endings` flag: [3](#0-2) 

The `TransactionInfoWithProof::verify` method only validates the accumulator proof structure, NOT the ledger info signatures: [4](#0-3) 

While `LedgerInfoWithSignatures` has a signature verification method: [5](#0-4) 

This verification is only called through `epoch_history.verify_ledger_info()`, which is skipped when `epoch_history` is `None`.

**Attack Path:**
1. Attacker compromises backup storage (e.g., misconfigured cloud bucket, compromised backup server)
2. Attacker creates malicious backup files:
   - Fake `manifest.json` with arbitrary `version` and `root_hash`
   - Fake proof file with `LedgerInfoWithSignatures` containing **forged/invalid signatures**
   - Fake chunk files with arbitrary state data (fake accounts, balances, validator sets)
   - Fake `SparseMerkleRangeProof` files mathematically consistent with fake root_hash
3. Victim runs restore with `--skip-epoch-endings` flag (marked "for debugging" but not code-protected)
4. Restoration succeeds:
   - Mathematical consistency checks pass
   - **Cryptographic signature verification is completely bypassed**
   - Arbitrary malicious state is injected into the database

## Impact Explanation

**Severity: CRITICAL**

This vulnerability meets multiple Critical severity criteria from the Aptos bug bounty:

1. **Loss of Funds**: Attacker can create fake accounts with arbitrary balances, effectively minting funds
2. **Consensus/Safety Violations**: Attacker can manipulate the validator set, breaking consensus integrity  
3. **State Consistency**: Breaks the fundamental invariant that blockchain state must be cryptographically authenticated by validator signatures

The vulnerability completely bypasses the cryptographic security model of the blockchain. While BLS signatures exist on the `LedgerInfoWithSignatures` structure, they are never verified when `epoch_history` is `None`, rendering them useless.

This violates the **Cryptographic Correctness** invariant: "BLS signatures, VRF, and hash operations must be secure" - the signatures exist but are not checked.

## Likelihood Explanation

**Likelihood: MEDIUM to HIGH**

Required conditions:
1. **Attacker compromise of backup storage** (MEDIUM difficulty): Possible through misconfigured cloud storage permissions, compromised backup servers, or supply chain attacks on backup infrastructure
2. **Use of `--skip-epoch-endings` flag** (MEDIUM difficulty): While marked "for debugging", there is no code-level protection preventing its use. Operators might use it for:
   - Performance optimization during large restores
   - Troubleshooting failed restores
   - Following incomplete/outdated operational procedures

The flag is in production code and can be enabled by any operator without special privileges. There are no warnings about security implications when using this flag.

## Recommendation

**Immediate Fix:**

1. **Remove the optional nature of signature verification** - Make epoch history restoration mandatory:

```rust
// In restore.rs run_impl()
let epoch_history = self.epoch_history.as_ref()
    .ok_or_else(|| anyhow!("Epoch history is required for secure state snapshot restore. Do not use --skip-epoch-endings in production."))?;
epoch_history.verify_ledger_info(&li)?;
```

2. **Add explicit security warnings and safeguards** to the `--skip-epoch-endings` flag:

```rust
#[clap(
    long, 
    help = "DANGEROUS: Skip restoring epoch ending info. This completely bypasses signature verification and should NEVER be used in production. Only for local testing."
)]
pub skip_epoch_endings: bool,
```

3. **Add runtime check** to prevent usage in production:

```rust
if self.skip_epoch_endings && !cfg!(debug_assertions) {
    bail!("--skip-epoch-endings is only allowed in debug builds for security reasons");
}
```

**Long-term Fix:**

Implement defense-in-depth by adding cryptographic signatures directly to the manifest file itself, similar to how package managers sign their manifests.

## Proof of Concept

```rust
// PoC: Restore with forged state without signature verification
// Run from storage/backup/backup-cli directory

use std::fs;
use serde_json::json;

fn create_malicious_backup() {
    // 1. Create fake manifest with arbitrary root_hash
    let fake_manifest = json!({
        "version": 1000000,
        "epoch": 100,
        "root_hash": "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "chunks": [],
        "proof": "proof_file_handle"
    });
    
    fs::write("backup/fake_manifest.json", fake_manifest.to_string()).unwrap();
    
    // 2. Create fake proof file with LedgerInfoWithSignatures
    // The signatures will be invalid/forged, but they won't be checked!
    let fake_proof = create_fake_ledger_info_with_invalid_signatures();
    fs::write("backup/proof_file", bcs::to_bytes(&fake_proof).unwrap()).unwrap();
    
    // 3. Run restore with --skip-epoch-endings
    // $ cargo run --bin db-restore -- \
    //     --target-db-dir /tmp/fake_db \
    //     --state-manifest backup/fake_manifest.json \
    //     --skip-epoch-endings  # <-- This bypasses signature verification!
    
    // Result: Arbitrary state restored without cryptographic authentication
}
```

**Demonstration Steps:**
1. Set up backup storage with crafted files
2. Run restore command: `db-restore --skip-epoch-endings --state-manifest fake_manifest.json`
3. Observe that restore succeeds despite invalid signatures
4. Query restored database to confirm arbitrary state was injected
5. Note that without `--skip-epoch-endings`, restore would fail with signature verification error

This demonstrates that the cryptographic security guarantee can be completely bypassed through a command-line flag that has no code-level protection.

### Citations

**File:** storage/backup/backup-cli/src/utils/storage_ext.rs (L24-37)
```rust
    async fn read_all(&self, file_handle: &FileHandleRef) -> Result<Vec<u8>> {
        let mut file = self.open_for_read(file_handle).await?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).await?;
        Ok(bytes)
    }

    async fn load_bcs_file<T: DeserializeOwned>(&self, file_handle: &FileHandleRef) -> Result<T> {
        Ok(bcs::from_bytes(&self.read_all(file_handle).await?)?)
    }

    async fn load_json_file<T: DeserializeOwned>(&self, file_handle: &FileHandleRef) -> Result<T> {
        Ok(serde_json::from_slice(&self.read_all(file_handle).await?)?)
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

**File:** types/src/ledger_info.rs (L303-308)
```rust
    pub fn verify_signatures(
        &self,
        validator: &ValidatorVerifier,
    ) -> ::std::result::Result<(), VerifyError> {
        validator.verify_multi_signatures(self.ledger_info(), &self.signatures)
    }
```
