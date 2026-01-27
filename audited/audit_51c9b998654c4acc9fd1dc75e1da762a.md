# Audit Report

## Title
Integer Overflow Panic in Backup Manifest Validation Can DoS Backup Restoration and Verification Processes

## Summary
The `verify()` function in `TransactionBackup` performs arithmetic operations without overflow protection that will panic when processing maliciously crafted backup manifests. With `overflow-checks = true` enabled in release builds, an attacker can trigger a panic by providing a backup manifest with `chunk.last_version = u64::MAX`, causing denial of service to backup verification and node bootstrapping processes. [1](#0-0) 

## Finding Description

The vulnerability exists in the manifest verification logic that validates transaction backup integrity. The `verify()` method iterates through backup chunks and performs unchecked arithmetic:

**Line 76 - Addition Overflow:** [1](#0-0) 

When `chunk.last_version` equals `u64::MAX`, the operation `chunk.last_version + 1` overflows.

**Line 81 - Subtraction Underflow:** [2](#0-1) 

While less exploitable, if `next_version` could be 0, this would underflow.

**Overflow Checks Enabled:** [3](#0-2) 

The workspace configuration explicitly enables `overflow-checks = true` for release builds, meaning arithmetic overflows will panic rather than wrap.

**Verification Called in Critical Path:** [4](#0-3) 

The `verify()` function is invoked during backup manifest loading, before any cryptographic verification of the actual backup data.

**Attack Vector:**

1. Attacker creates a malicious JSON manifest file with structure:
```json
{
  "first_version": 0,
  "last_version": 18446744073709551615,
  "chunks": [{
    "first_version": 0,
    "last_version": 18446744073709551615,
    "transactions": "...",
    "proof": "..."
  }]
}
```

2. The manifest is deserialized without validation: [5](#0-4) 

3. When `verify()` processes the chunk, line 76 executes `u64::MAX + 1`, triggering a panic.

**Exploitation Scenarios:**

1. **Backup Verification DoS:** Automatic backup verification CronJobs crash when processing malicious manifests: [6](#0-5) 

2. **Node Bootstrap Prevention:** Operators attempting to bootstrap nodes from compromised backup sources experience crashes: [7](#0-6) 

## Impact Explanation

**Severity Assessment: Low to Medium**

While this is a real panic vulnerability, its impact is limited to **offline backup infrastructure**, not running validators:

**Limited Impact:**
- Affects backup verification CronJobs (separate Kubernetes pods)
- Affects node bootstrapping from untrusted backup sources  
- Does **NOT** affect running validators during consensus
- Does **NOT** impact blockchain state or transaction processing
- No funds at risk

**Medium Severity Justification (Borderline):**
Per Aptos bug bounty criteria, this could qualify as Medium ("State inconsistencies requiring intervention") because:
- Prevents detection of genuinely corrupted backups if verification crashes
- Blocks new validator nodes from bootstrapping, requiring manual intervention
- Disrupts operational backup infrastructure

However, this is a **borderline case** as the impact is confined to offline operational tooling rather than consensus-critical components.

## Likelihood Explanation

**Likelihood: Low to Medium**

**Requirements:**
- Attacker must compromise backup storage or social engineer operators to use malicious backup source
- Requires operators to restore/verify from untrusted sources
- Backup manifests are not cryptographically signed (only chunk data has proofs)

**Realistic Scenarios:**
1. Compromised cloud storage bucket hosting backups
2. Man-in-the-middle on backup downloads if not using HTTPS
3. Social engineering validator operators with "helpful" backup sources
4. Insider threat providing malicious backups

## Recommendation

Use checked arithmetic operations that return `Result` instead of panicking:

```rust
pub fn verify(&self) -> Result<()> {
    ensure!(
        self.first_version <= self.last_version,
        "Bad version range: [{}, {}]",
        self.first_version,
        self.last_version,
    );

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
        
        // Use checked_add to prevent overflow panic
        next_version = chunk.last_version.checked_add(1)
            .ok_or_else(|| anyhow::anyhow!(
                "Version overflow: chunk.last_version {} is too large",
                chunk.last_version
            ))?;
    }

    // Use checked_sub to prevent underflow panic  
    let last_chunk_version = next_version.checked_sub(1)
        .ok_or_else(|| anyhow::anyhow!("Version underflow in validation"))?;
    
    ensure!(
        last_chunk_version == self.last_version,
        "Last version in chunks: {}, in manifest: {}",
        last_chunk_version,
        self.last_version,
    );

    Ok(())
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::FileHandle;

    #[test]
    #[should_panic(expected = "attempt to add with overflow")]
    fn test_overflow_attack() {
        let malicious_manifest = TransactionBackup {
            first_version: 0,
            last_version: u64::MAX,
            chunks: vec![TransactionChunk {
                first_version: 0,
                last_version: u64::MAX, // Triggers overflow
                transactions: FileHandle::new("test"),
                proof: FileHandle::new("test"),
                format: TransactionChunkFormat::V0,
            }],
        };

        // This will panic with overflow-checks = true
        malicious_manifest.verify().unwrap();
    }
}
```

**Notes:**

This vulnerability represents a **real implementation flaw** where panic-inducing arithmetic operations can be triggered by untrusted input. However, its security impact is **limited to offline backup infrastructure** rather than consensus-critical validator operations. The backup verification process runs in separate infrastructure (Kubernetes CronJobs) and does not directly affect running validators. The primary risk is operational disruption to backup verification and node bootstrapping processes when using untrusted backup sources.

### Citations

**File:** storage/backup/backup-cli/src/backup_types/transaction/manifest.rs (L76-76)
```rust
            next_version = chunk.last_version + 1;
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/manifest.rs (L81-81)
```rust
            next_version - 1 == self.last_version, // okay to -1 because chunks is not empty.
```

**File:** Cargo.toml (L921-923)
```text
[profile.release]
debug = true
overflow-checks = true
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L353-353)
```rust
            .and_then(|m: TransactionBackup| future::ready(m.verify().map(|_| m)));
```

**File:** storage/backup/backup-cli/src/utils/storage_ext.rs (L35-36)
```rust
    async fn load_json_file<T: DeserializeOwned>(&self, file_handle: &FileHandleRef) -> Result<T> {
        Ok(serde_json::from_slice(&self.read_all(file_handle).await?)?)
```

**File:** terraform/helm/fullnode/templates/backup-verify.yaml (L38-41)
```yaml
            - /usr/local/bin/aptos-debugger
            - aptos-db
            - backup
            - verify
```

**File:** storage/backup/backup-cli/src/coordinators/verify.rs (L144-156)
```rust
        let txn_manifests = transactions.into_iter().map(|b| b.manifest).collect();
        TransactionRestoreBatchController::new(
            global_opt,
            self.storage,
            txn_manifests,
            None,
            None, /* replay_from_version */
            epoch_history,
            VerifyExecutionMode::NoVerify,
            self.output_transaction_analysis,
        )
        .run()
        .await?;
```
