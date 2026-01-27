# Audit Report

## Title
Unbounded Memory Allocation in Transaction Backup Restore Leading to Resource Exhaustion

## Summary
The `TransactionBackup::verify()` function fails to validate chunk size limits, allowing an attacker who controls backup storage to create malicious manifests with version ranges spanning billions of transactions. When a victim attempts restoration, the `LoadedChunk::load()` function tries to allocate memory for all transactions in a chunk simultaneously, causing memory exhaustion and potential disk exhaustion, resulting in denial of service.

## Finding Description

The vulnerability exists in the backup restoration system due to insufficient validation of chunk sizes in backup manifests.

**Location 1 - Inadequate Validation:**
The `TransactionBackup::verify()` function only validates version range continuity but does not check for reasonable size limits. [1](#0-0) 

The verification only ensures:
- `first_version <= last_version` (basic range validity)
- Chunks are continuous
- No validation of total transaction count per chunk

**Location 2 - Unbounded Memory Allocation:**
When loading chunks during restoration, all transaction records are read into memory simultaneously without size checks. [2](#0-1) 

The `LoadedChunk::load()` function allocates vectors and loads all transactions from a chunk into memory (lines 106-137). The only validation occurs afterward, checking that the number of transactions matches the manifest's claim, but by then memory has already been allocated.

**Attack Path:**

1. Attacker gains access to backup storage (compromised cloud storage, malicious backup provider, or insider threat)
2. Attacker creates a malicious `TransactionBackup` manifest with a chunk claiming an enormous version range (e.g., `first_version: 0, last_version: 10_000_000_000`)
3. Attacker provides a corresponding transaction file with matching number of minimal transaction records
4. The manifest passes `verify()` because it only checks continuity, not size
5. When a victim attempts restoration:
   - `LoadedChunk::load()` opens the transaction file
   - Reads all records into memory (lines 112-137)
   - For billions of transactions, this exhausts available memory
   - Node crashes or becomes unresponsive

**Broken Invariant:**
This violates the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." The restore operation performs unbounded memory allocation without validating input sizes.

**Contrast with Backup Creation:**
During backup creation, chunks are limited by `max_chunk_size` (default 128 MB) to prevent excessive sizes. [3](#0-2) [4](#0-3) 

However, this limit is not enforced during restoration, creating an asymmetry where well-behaved backups respect limits but malicious manifests can bypass them.

## Impact Explanation

**Severity: High** (per Aptos Bug Bounty criteria: "Validator node slowdowns" and "API crashes")

**Primary Impact:**
- **Memory Exhaustion**: Attempting to load billions of transactions into memory causes OOM (Out of Memory) conditions
- **Node Unavailability**: Restoration process crashes or hangs, preventing node operators from recovering their nodes
- **Disk Exhaustion**: If memory allocation somehow succeeds, writing billions of transactions to disk exhausts storage

**Secondary Impact:**
- **Operational DoS**: Prevents legitimate node recovery from backups
- **Infrastructure Cost**: Wasted compute resources attempting to process malicious manifests
- **Network Impact**: If multiple nodes attempt restoration from compromised backup storage, multiple nodes become unavailable

This qualifies as High severity because it causes validator node failures and prevents critical operational procedures (node restoration).

## Likelihood Explanation

**Likelihood: Medium-High**

**Prerequisites for Exploitation:**
1. Attacker must influence backup storage (compromised cloud storage, malicious backup provider, or shared backup infrastructure)
2. Victim must attempt restoration from the compromised source

**Realistic Scenarios:**
- **Compromised Cloud Storage**: If an organization's S3 bucket or cloud storage is compromised, attacker can modify manifests
- **Malicious Backup Provider**: Third-party backup services could be compromised or malicious
- **Shared Infrastructure**: Multiple organizations sharing backup infrastructure could be attacked if one is compromised
- **Supply Chain Attack**: Compromised backup automation tools could inject malicious manifests

The likelihood increases because:
- Backup storage is often less protected than production systems
- Organizations may use third-party or shared backup services
- The verification function exists but provides false security by not checking sizes
- No runtime protections prevent the resource exhaustion

## Recommendation

Implement chunk size validation in both the `verify()` function and during chunk loading:

**Fix 1 - Add Validation to verify():**
```rust
impl TransactionBackup {
    pub fn verify(&self) -> Result<()> {
        // Existing checks...
        ensure!(
            self.first_version <= self.last_version,
            "Bad version range: [{}, {}]",
            self.first_version,
            self.last_version,
        );
        
        // NEW: Validate reasonable version range size
        const MAX_TRANSACTIONS_PER_MANIFEST: u64 = 1_000_000_000; // 1 billion
        let total_versions = self.last_version
            .checked_sub(self.first_version)
            .and_then(|v| v.checked_add(1))
            .ok_or_else(|| anyhow!("Version range overflow"))?;
        
        ensure!(
            total_versions <= MAX_TRANSACTIONS_PER_MANIFEST,
            "Manifest version range too large: {} transactions (max: {})",
            total_versions,
            MAX_TRANSACTIONS_PER_MANIFEST
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
            
            // NEW: Validate individual chunk size
            const MAX_TRANSACTIONS_PER_CHUNK: u64 = 10_000_000; // 10 million
            let chunk_size = chunk.last_version
                .checked_sub(chunk.first_version)
                .and_then(|v| v.checked_add(1))
                .ok_or_else(|| anyhow!("Chunk version range overflow"))?;
            
            ensure!(
                chunk_size <= MAX_TRANSACTIONS_PER_CHUNK,
                "Chunk version range too large: {} transactions (max: {}). Chunk: [{}, {}]",
                chunk_size,
                MAX_TRANSACTIONS_PER_CHUNK,
                chunk.first_version,
                chunk.last_version
            );
            
            next_version = chunk.last_version + 1;
        }

        ensure!(
            next_version - 1 == self.last_version,
            "Last version in chunks: {}, in manifest: {}",
            next_version - 1,
            self.last_version,
        );

        Ok(())
    }
}
```

**Fix 2 - Add Early Size Check in LoadedChunk::load():**
```rust
impl LoadedChunk {
    async fn load(
        manifest: TransactionChunk,
        storage: &Arc<dyn BackupStorage>,
        epoch_history: Option<&Arc<EpochHistory>>,
    ) -> Result<Self> {
        // NEW: Early validation of expected transaction count
        const MAX_TRANSACTIONS_PER_CHUNK: u64 = 10_000_000;
        let expected_txn_count = manifest.last_version
            .checked_sub(manifest.first_version)
            .and_then(|v| v.checked_add(1))
            .ok_or_else(|| anyhow!("Chunk version range overflow"))?;
        
        ensure!(
            expected_txn_count <= MAX_TRANSACTIONS_PER_CHUNK,
            "Chunk claims too many transactions: {} (max: {})",
            expected_txn_count,
            MAX_TRANSACTIONS_PER_CHUNK
        );
        
        // Continue with existing load logic...
        let mut file = BufReader::new(storage.open_for_read(&manifest.transactions).await?);
        // ... rest of the function
    }
}
```

These fixes ensure that:
1. Manifests are validated before any processing begins
2. Chunk sizes have reasonable upper bounds aligned with backup creation limits
3. Early failures prevent resource exhaustion
4. The validation is defense-in-depth (checked in multiple places)

## Proof of Concept

```rust
// Add this test to storage/backup/backup-cli/src/backup_types/transaction/tests.rs

#[tokio::test]
async fn test_malicious_manifest_resource_exhaustion() {
    use crate::backup_types::transaction::manifest::{TransactionBackup, TransactionChunk, TransactionChunkFormat};
    use crate::storage::FileHandle;
    
    // Create a malicious manifest claiming billions of transactions
    let malicious_manifest = TransactionBackup {
        first_version: 0,
        last_version: 10_000_000_000, // 10 billion transactions
        chunks: vec![
            TransactionChunk {
                first_version: 0,
                last_version: 10_000_000_000,
                transactions: FileHandle::new("malicious_txns.chunk"),
                proof: FileHandle::new("malicious_proof.proof"),
                format: TransactionChunkFormat::V1,
            }
        ],
    };
    
    // This currently PASSES verify() - demonstrating the vulnerability
    let result = malicious_manifest.verify();
    assert!(result.is_ok(), "Malicious manifest should be rejected but currently passes: {:?}", result);
    
    // With the fix, this should FAIL
    // assert!(result.is_err(), "Malicious manifest should be rejected");
    // assert!(result.unwrap_err().to_string().contains("too large"));
}

#[tokio::test]
async fn test_reasonable_manifest_passes() {
    use crate::backup_types::transaction::manifest::{TransactionBackup, TransactionChunk, TransactionChunkFormat};
    use crate::storage::FileHandle;
    
    // Create a reasonable manifest
    let reasonable_manifest = TransactionBackup {
        first_version: 0,
        last_version: 999_999, // 1 million transactions (reasonable)
        chunks: vec![
            TransactionChunk {
                first_version: 0,
                last_version: 999_999,
                transactions: FileHandle::new("txns.chunk"),
                proof: FileHandle::new("proof.proof"),
                format: TransactionChunkFormat::V1,
            }
        ],
    };
    
    // This should pass both before and after the fix
    let result = reasonable_manifest.verify();
    assert!(result.is_ok(), "Reasonable manifest should pass: {:?}", result);
}
```

**To demonstrate the full impact:**
1. Create a malicious manifest as shown above
2. Generate a transaction file with 10 billion minimal records (script to generate file)
3. Attempt restoration using the backup-cli tool
4. Observe memory exhaustion as `LoadedChunk::load()` attempts to allocate vectors for billions of transactions
5. Node becomes unresponsive or crashes with OOM

**Notes**

This vulnerability is particularly insidious because:

1. **The verification function provides false security** - operators may assume validated manifests are safe
2. **Legitimate backup creation respects limits** - but restoration doesn't enforce them symmetrically
3. **Attack surface includes backup infrastructure** - which is often less hardened than production systems
4. **No runtime protections** - once loading begins, there's no circuit breaker to prevent resource exhaustion

The fix should align restoration validation with the limits used during backup creation (128 MB chunks, reasonable transaction counts), ensuring defense-in-depth against malicious backup manifests.

### Citations

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

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L100-186)
```rust
    async fn load(
        manifest: TransactionChunk,
        storage: &Arc<dyn BackupStorage>,
        epoch_history: Option<&Arc<EpochHistory>>,
    ) -> Result<Self> {
        let mut file = BufReader::new(storage.open_for_read(&manifest.transactions).await?);
        let mut txns = Vec::new();
        let mut persisted_aux_info = Vec::new();
        let mut txn_infos = Vec::new();
        let mut event_vecs = Vec::new();
        let mut write_sets = Vec::new();

        while let Some(record_bytes) = file.read_record_bytes().await? {
            let (txn, aux_info, txn_info, events, write_set): (
                _,
                PersistedAuxiliaryInfo,
                _,
                _,
                WriteSet,
            ) = match manifest.format {
                TransactionChunkFormat::V0 => {
                    let (txn, txn_info, events, write_set) = bcs::from_bytes(&record_bytes)?;
                    (
                        txn,
                        PersistedAuxiliaryInfo::None,
                        txn_info,
                        events,
                        write_set,
                    )
                },
                TransactionChunkFormat::V1 => bcs::from_bytes(&record_bytes)?,
            };
            txns.push(txn);
            persisted_aux_info.push(aux_info);
            txn_infos.push(txn_info);
            event_vecs.push(events);
            write_sets.push(write_set);
        }

        ensure!(
            manifest.first_version + (txns.len() as Version) == manifest.last_version + 1,
            "Number of items in chunks doesn't match that in manifest. first_version: {}, last_version: {}, items in chunk: {}",
            manifest.first_version,
            manifest.last_version,
            txns.len(),
        );

        let (range_proof, ledger_info) = storage
            .load_bcs_file::<(TransactionAccumulatorRangeProof, LedgerInfoWithSignatures)>(
                &manifest.proof,
            )
            .await?;
        if let Some(epoch_history) = epoch_history {
            epoch_history.verify_ledger_info(&ledger_info)?;
        }

        // make a `TransactionListWithProof` to reuse its verification code.
        let txn_list_with_proof =
            TransactionListWithProofV2::new(TransactionListWithAuxiliaryInfos::new(
                TransactionListWithProof::new(
                    txns,
                    Some(event_vecs),
                    Some(manifest.first_version),
                    TransactionInfoListWithProof::new(range_proof, txn_infos),
                ),
                persisted_aux_info,
            ));
        txn_list_with_proof.verify(ledger_info.ledger_info(), Some(manifest.first_version))?;
        // and disassemble it to get things back.
        let (txn_list_with_proof, persisted_aux_info) = txn_list_with_proof.into_parts();
        let txns = txn_list_with_proof.transactions;
        let range_proof = txn_list_with_proof
            .proof
            .ledger_info_to_transaction_infos_proof;
        let txn_infos = txn_list_with_proof.proof.transaction_infos;
        let event_vecs = txn_list_with_proof.events.expect("unknown to be Some.");

        Ok(Self {
            manifest,
            txns,
            persisted_aux_info,
            txn_infos,
            event_vecs,
            range_proof,
            write_sets,
        })
    }
```

**File:** storage/backup/backup-cli/src/utils/mod.rs (L50-57)
```rust
pub struct GlobalBackupOpt {
    // Defaults to 128MB, so concurrent chunk downloads won't take up too much memory.
    #[clap(
        long = "max-chunk-size",
        default_value_t = 134217728,
        help = "Maximum chunk file size in bytes."
    )]
    pub max_chunk_size: usize,
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/backup.rs (L35-50)
```rust
    max_chunk_size: usize,
    client: Arc<BackupServiceClient>,
    storage: Arc<dyn BackupStorage>,
}

impl TransactionBackupController {
    pub fn new(
        opt: TransactionBackupOpt,
        global_opt: GlobalBackupOpt,
        client: Arc<BackupServiceClient>,
        storage: Arc<dyn BackupStorage>,
    ) -> Self {
        Self {
            start_version: opt.start_version,
            num_transactions: opt.num_transactions,
            max_chunk_size: global_opt.max_chunk_size,
```
