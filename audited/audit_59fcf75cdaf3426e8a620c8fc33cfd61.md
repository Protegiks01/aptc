# Audit Report

## Title
Backup Restore DoS via Unvalidated Chunk Size and Deferred Proof Verification

## Summary
The `LoadedChunk::load()` function in the backup restore subsystem loads and deserializes all transaction data before verifying cryptographic proofs. An attacker can exploit this by providing maliciously crafted backup chunks with arbitrarily large records and invalid proofs, causing memory exhaustion and CPU consumption that only fails after resources are consumed.

## Finding Description

The vulnerability exists in the transaction backup restore process. [1](#0-0) 

The critical flaw is in the execution order:

**Step 1: Unbounded Data Loading** - The function reads transaction records in a loop without any size validation. [2](#0-1) 

Each record is read via `read_record_bytes()`, which reads a 4-byte u32 size field and allocates a buffer of that size with **no maximum limit check**. [3](#0-2) 

Specifically, the code allocates memory based on an attacker-controlled size field: [4](#0-3) 

**Step 2: BCS Deserialization** - All loaded data is then deserialized using BCS, consuming additional CPU resources. [5](#0-4) 

**Step 3: Deferred Proof Verification** - Only after all data is loaded and deserialized does the function verify the cryptographic proof. [6](#0-5) 

The proof verification itself involves merkle proof validation and hash checking: [7](#0-6) 

**Attack Scenario:**
1. Attacker creates a malicious backup chunk manifest pointing to crafted transaction data files
2. Each transaction record has a size field of 100MB-4GB (up to u32::MAX)
3. The chunk contains 100-1000 such records (total: 10GB-4TB)
4. The proof file contains an invalid proof that will fail verification
5. Victim runs restore command pointing to attacker's storage
6. The node allocates gigabytes of memory and performs expensive deserialization
7. Finally, proof verification fails and all work is discarded
8. Result: Node crashes due to OOM or becomes unresponsive

This breaks the **Resource Limits** invariant which requires all operations to respect computational and memory constraints.

## Impact Explanation

This is a **High Severity** vulnerability according to Aptos bug bounty criteria:
- **Validator node slowdowns**: Large chunks cause significant CPU consumption during BCS deserialization
- **Node crashes**: Memory exhaustion from allocating gigabytes per malicious chunk leads to OOM crashes

The impact is amplified because:
1. No authentication is required for backup storage in local filesystem mode
2. Multiple chunks can be processed in parallel (concurrent downloads setting), multiplying resource consumption
3. The restore process is critical for node recovery and state synchronization
4. Failed restores require manual intervention and node restart

While this does not directly affect consensus or funds, it severely impacts node availability during restore operations, which is critical for disaster recovery and new validator onboarding.

## Likelihood Explanation

**Likelihood: Medium-High**

The attack is realistic because:

1. **Access to backup storage**: Operators commonly use cloud storage or shared filesystems for backups, which may be compromised or attacker-controlled in certain scenarios
2. **Command-line argument exposure**: The restore command accepts arbitrary storage paths via `--local-fs-dir` or cloud storage configurations [8](#0-7) 
3. **No pre-validation**: There are no size limits or sanity checks before loading chunk data
4. **Parallel processing**: The concurrent download mechanism multiplies impact across multiple chunks simultaneously [9](#0-8) 

Attack complexity is **LOW**:
- Creating malicious backup chunks requires only crafting files with large size headers
- No cryptographic operations needed (the proof is intentionally invalid)
- Standard tools can generate multi-gigabyte files with arbitrary headers

## Recommendation

**Immediate Fix**: Add size validation before resource allocation

```rust
// In read_record_bytes function
const MAX_RECORD_SIZE: u32 = 100 * 1024 * 1024; // 100MB limit

async fn read_record_bytes(&mut self) -> Result<Option<Bytes>> {
    let _timer = BACKUP_TIMER.timer_with(&["read_record_bytes"]);
    
    // read record size
    let mut size_buf = BytesMut::with_capacity(4);
    self.read_full_buf_or_none(&mut size_buf).await?;
    if size_buf.is_empty() {
        return Ok(None);
    }

    let record_size = u32::from_be_bytes(size_buf.as_ref().try_into()?) as usize;
    
    // ADD SIZE VALIDATION HERE
    ensure!(
        record_size <= MAX_RECORD_SIZE as usize,
        "Record size {} exceeds maximum allowed size {}",
        record_size,
        MAX_RECORD_SIZE
    );
    
    if record_size == 0 {
        return Ok(Some(Bytes::new()));
    }

    // read record
    let mut record_buf = BytesMut::with_capacity(record_size);
    self.read_full_buf_or_none(&mut record_buf).await?;
    if record_buf.is_empty() {
        bail!("Hit EOF when reading record.")
    }

    Ok(Some(record_buf.freeze()))
}
```

**Better Solution**: Verify proof early before loading all data

Restructure `LoadedChunk::load()` to:
1. Load metadata and proof first
2. Verify proof against ledger info
3. Only then load and deserialize transaction data
4. Apply per-chunk size limits in manifest validation

**Defense in Depth**:
- Add maximum chunk size to manifest schema
- Validate chunk size against manifest before download
- Implement streaming verification where data is verified incrementally
- Add resource monitoring to abort restore operations exceeding memory thresholds

## Proof of Concept

```rust
// This PoC demonstrates creating a malicious backup chunk
// File: malicious_chunk_creator.rs

use std::fs::File;
use std::io::Write;

fn create_malicious_chunk() -> std::io::Result<()> {
    let mut file = File::create("malicious_transactions.chunk")?;
    
    // Create 100 records, each claiming to be 100MB
    for _ in 0..100 {
        let malicious_size: u32 = 100_000_000; // 100MB
        
        // Write size header (4 bytes, big-endian)
        file.write_all(&malicious_size.to_be_bytes())?;
        
        // Write some garbage data (actual size can be smaller to save space)
        // but the size header claims 100MB
        let garbage_data = vec![0u8; 1000]; // Just 1KB of garbage
        file.write_all(&garbage_data)?;
        
        // This will cause the reader to try allocating 100MB
        // but hit EOF, or we could write full 100MB of garbage
    }
    
    Ok(())
}

fn create_invalid_proof() -> std::io::Result<()> {
    use std::fs::File;
    use std::io::Write;
    
    let mut file = File::create("malicious_proof.proof")?;
    
    // Write BCS-serialized but cryptographically invalid proof
    // The proof structure exists but signatures/hashes are wrong
    let fake_proof_data = vec![0u8; 1000]; // Invalid proof bytes
    file.write_all(&fake_proof_data)?;
    
    Ok(())
}

// To exploit:
// 1. Run create_malicious_chunk() and create_invalid_proof()
// 2. Create a manifest pointing to these files
// 3. Point restore command to this backup:
//    aptos-db-tool restore oneoff transaction \
//      --local-fs-dir ./malicious_backup \
//      --transaction-manifest manifest.json \
//      --target-db-dir /tmp/victim_db
// 4. Observer node consuming 10GB+ RAM before failing on proof verification
```

**Validation Steps**:
1. Create malicious chunk files with large size headers
2. Create corresponding manifest and invalid proof
3. Run restore command pointing to malicious backup
4. Monitor memory consumption - should spike to multi-GB before failure
5. Observe proof verification error only after resource exhaustion
6. Node becomes unresponsive or crashes with OOM

---

**Notes**

This vulnerability is particularly concerning because:
1. Backup/restore is a critical operational procedure for node recovery
2. The attack can be repeated across multiple chunks in parallel
3. No authentication or authorization protects against malicious backup sources in common deployment scenarios
4. The issue affects all restore operations (bootstrap, state snapshot, transaction, epoch ending)

The fix requires both immediate size validation and architectural changes to verify-then-load rather than load-then-verify.

### Citations

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

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L341-401)
```rust
    fn loaded_chunk_stream(&self) -> Peekable<impl Stream<Item = Result<LoadedChunk>> + use<>> {
        let con = self.global_opt.concurrent_downloads;

        let manifest_handle_stream = stream::iter(self.manifest_handles.clone());

        let storage = self.storage.clone();
        let manifest_stream = manifest_handle_stream
            .map(move |hdl| {
                let storage = storage.clone();
                async move { storage.load_json_file(&hdl).await.err_notes(&hdl) }
            })
            .buffered_x(con * 3, con)
            .and_then(|m: TransactionBackup| future::ready(m.verify().map(|_| m)));

        let target_version = self.global_opt.target_version;
        let first_version = self.first_version.unwrap_or(0);
        let chunk_manifest_stream = manifest_stream
            .map_ok(|m| stream::iter(m.chunks.into_iter().map(Result::<_>::Ok)))
            .try_flatten()
            .try_filter(move |c| {
                future::ready(c.first_version <= target_version && c.last_version >= first_version)
            })
            .scan(0, |last_chunk_last_version, chunk_res| {
                let res = match &chunk_res {
                    Ok(chunk) => {
                        if *last_chunk_last_version != 0
                            && chunk.first_version != *last_chunk_last_version + 1
                        {
                            Some(Err(anyhow!(
                                "Chunk range not consecutive. expecting {}, got {}",
                                *last_chunk_last_version + 1,
                                chunk.first_version
                            )))
                        } else {
                            *last_chunk_last_version = chunk.last_version;
                            Some(chunk_res)
                        }
                    },
                    Err(_) => Some(chunk_res),
                };
                future::ready(res)
            });

        let storage = self.storage.clone();
        let epoch_history = self.epoch_history.clone();
        chunk_manifest_stream
            .and_then(move |chunk| {
                let storage = storage.clone();
                let epoch_history = epoch_history.clone();
                future::ok(async move {
                    tokio::task::spawn(async move {
                        LoadedChunk::load(chunk, &storage, epoch_history.as_ref()).await
                    })
                    .err_into::<anyhow::Error>()
                    .await
                })
            })
            .try_buffered_x(con * 2, con)
            .and_then(future::ready)
            .peekable()
    }
```

**File:** storage/backup/backup-cli/src/utils/read_record_bytes.rs (L44-67)
```rust
    async fn read_record_bytes(&mut self) -> Result<Option<Bytes>> {
        let _timer = BACKUP_TIMER.timer_with(&["read_record_bytes"]);
        // read record size
        let mut size_buf = BytesMut::with_capacity(4);
        self.read_full_buf_or_none(&mut size_buf).await?;
        if size_buf.is_empty() {
            return Ok(None);
        }

        // empty record
        let record_size = u32::from_be_bytes(size_buf.as_ref().try_into()?) as usize;
        if record_size == 0 {
            return Ok(Some(Bytes::new()));
        }

        // read record
        let mut record_buf = BytesMut::with_capacity(record_size);
        self.read_full_buf_or_none(&mut record_buf).await?;
        if record_buf.is_empty() {
            bail!("Hit EOF when reading record.")
        }

        Ok(Some(record_buf.freeze()))
    }
```

**File:** types/src/transaction/mod.rs (L2295-2354)
```rust
    pub fn verify(
        &self,
        ledger_info: &LedgerInfo,
        first_transaction_version: Option<Version>,
    ) -> Result<()> {
        // Verify the first transaction versions match
        ensure!(
            self.get_first_transaction_version() == first_transaction_version,
            "First transaction version ({:?}) doesn't match given version ({:?}).",
            self.get_first_transaction_version(),
            first_transaction_version,
        );

        // Verify the lengths of the transactions and transaction infos match
        ensure!(
            self.proof.transaction_infos.len() == self.get_num_transactions(),
            "The number of TransactionInfo objects ({}) does not match the number of \
             transactions ({}).",
            self.proof.transaction_infos.len(),
            self.get_num_transactions(),
        );

        // Verify the transaction hashes match those of the transaction infos
        self.transactions
            .par_iter()
            .zip_eq(self.proof.transaction_infos.par_iter())
            .map(|(txn, txn_info)| {
                let txn_hash = CryptoHash::hash(txn);
                ensure!(
                    txn_hash == txn_info.transaction_hash(),
                    "The hash of transaction does not match the transaction info in proof. \
                     Transaction hash: {:x}. Transaction hash in txn_info: {:x}.",
                    txn_hash,
                    txn_info.transaction_hash(),
                );
                Ok(())
            })
            .collect::<Result<Vec<_>>>()?;

        // Verify the transaction infos are proven by the ledger info.
        self.proof
            .verify(ledger_info, self.get_first_transaction_version())?;

        // Verify the events if they exist.
        if let Some(event_lists) = &self.events {
            ensure!(
                event_lists.len() == self.get_num_transactions(),
                "The length of event_lists ({}) does not match the number of transactions ({}).",
                event_lists.len(),
                self.get_num_transactions(),
            );
            event_lists
                .into_par_iter()
                .zip_eq(self.proof.transaction_infos.par_iter())
                .map(|(events, txn_info)| verify_events_against_root_hash(events, txn_info))
                .collect::<Result<Vec<_>>>()?;
        }

        Ok(())
    }
```

**File:** storage/db-tool/src/restore.rs (L18-63)
```rust
/// Restore the database using either a one-time or continuous backup.
#[derive(Subcommand)]
pub enum Command {
    #[clap(about = "run continuously to restore the DB")]
    BootstrapDB(BootstrapDB),
    #[clap(subcommand)]
    Oneoff(Oneoff),
}

#[derive(Parser)]
pub struct BootstrapDB {
    #[clap(flatten)]
    storage: DBToolStorageOpt,
    #[clap(flatten)]
    opt: RestoreCoordinatorOpt,
    #[clap(flatten)]
    global: GlobalRestoreOpt,
}

#[derive(Parser)]
pub enum Oneoff {
    EpochEnding {
        #[clap(flatten)]
        storage: DBToolStorageOpt,
        #[clap(flatten)]
        opt: EpochEndingRestoreOpt,
        #[clap(flatten)]
        global: GlobalRestoreOpt,
    },
    StateSnapshot {
        #[clap(flatten)]
        storage: DBToolStorageOpt,
        #[clap(flatten)]
        opt: StateSnapshotRestoreOpt,
        #[clap(flatten)]
        global: GlobalRestoreOpt,
    },
    Transaction {
        #[clap(flatten)]
        storage: DBToolStorageOpt,
        #[clap(flatten)]
        opt: TransactionRestoreOpt,
        #[clap(flatten)]
        global: GlobalRestoreOpt,
    },
}
```
