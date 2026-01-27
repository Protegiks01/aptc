# Audit Report

## Title
Unbounded Memory Allocation and Performance DoS in Backup Restoration via Malicious Record Size Prefixes

## Summary
The `read_record_bytes()` function in the backup restoration code path allocates memory based on an unchecked 4-byte size prefix read from backup files. An attacker who can compromise public backup storage sources can craft malicious backup files with arbitrarily large record size values (up to 4GB), causing memory exhaustion or extremely slow restoration operations that timeout, effectively preventing new validators from bootstrapping.

## Finding Description

The vulnerability exists in the backup restoration system where Aptos supports restoring from public, untrusted backup sources. The attack unfolds as follows:

**Vulnerable Code Flow:**

1. The `read_record_bytes()` function reads a 4-byte big-endian integer as the record size without validation [1](#0-0) 

2. It then allocates a buffer of exactly that size [2](#0-1) 

3. The `read_full_buf_or_none()` loop reads chunks until the entire buffer is filled, with no size limits or early exit conditions [3](#0-2) 

4. This reading happens **before** any cryptographic verification via trusted waypoints [4](#0-3) 

**Attack Vector:**

Aptos explicitly supports restoring from public backup sources hosted by AptosLabs on cloud storage (S3/GCS) [5](#0-4) . An attacker who compromises these backup sources can upload malicious backup files.

**Exploitation Steps:**

1. Attacker creates a malicious backup file with a record containing:
   - Size prefix: `0x40000000` (1GB in big-endian u32)
   - Actual data: 1GB of arbitrary bytes

2. Node operator initiates restore from the compromised public backup source

3. During restoration, `LoadedChunk::load()` opens the file and calls `read_record_bytes()` [6](#0-5) 

4. The code allocates a 1GB buffer and enters the read loop

5. With `BufReader`'s default 8KB buffering, filling 1GB requires ~131,072 read iterations

6. For network-based storage with typical 20ms latency per read: 131,072 × 20ms ≈ 44 minutes per record

7. A chunk with multiple such records causes restoration to take hours, exceeding any reasonable timeout

**Security Guarantees Broken:**

- **Resource Limits Invariant**: Operations must respect computational and memory constraints, but record sizes are unbounded (up to u32::MAX = 4GB)
- **Availability**: Backup restoration is a critical operation for validator bootstrapping and disaster recovery

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos Bug Bounty program for the following reasons:

1. **Denial of Service on Critical Operations**: Backup restoration is essential for:
   - New validators bootstrapping from genesis or snapshots
   - Existing validators recovering from data loss
   - Network upgrades requiring fresh state synchronization

2. **Limited but Realistic Attack Path**: Requires compromising public backup storage infrastructure, which is a realistic threat model given that:
   - Public backups are explicitly supported and documented [7](#0-6) 
   - Cloud storage compromises occur in practice
   - The impact affects all nodes restoring from that source

3. **Not Critical Because**: 
   - Doesn't directly affect consensus or running validators
   - Doesn't cause fund loss or permanent network damage
   - Requires external infrastructure compromise first
   - Can be mitigated by restoring from alternate sources

4. **Alignment with Bounty Categories**: Falls under "State inconsistencies requiring intervention" (Medium) as it prevents proper database restoration and requires manual intervention to identify and remove malicious backup files.

## Likelihood Explanation

**Likelihood: Medium**

**Factors Increasing Likelihood:**
- Public backup sources are actively used for validator bootstrapping (documented in deployment guides)
- Cloud storage security breaches occur regularly in the industry
- No authentication or integrity checks before reading record sizes
- Attack is straightforward: just upload a crafted file to compromised storage
- Silent failure mode: operators may not immediately recognize the cause of slow restoration

**Factors Decreasing Likelihood:**
- Requires initial compromise of backup storage infrastructure (S3/GCS)
- AptosLabs likely has robust security on official backup sources
- Trusted waypoints verification would eventually catch data corruption, though after the DoS
- Node operators may have local backup alternatives

**Overall Assessment**: While not trivial to execute, the attack is feasible for a determined attacker with cloud infrastructure access, and the impact on validator bootstrapping makes this a genuine concern.

## Recommendation

Implement multiple layers of defense against unbounded record sizes:

### 1. Add Maximum Record Size Validation

Define a reasonable maximum record size based on the largest legitimate backup records. Since the default chunk size is 128MB [8](#0-7) , individual records should be well below this threshold.

**Recommended Fix** (in `read_record_bytes.rs`):

```rust
const MAX_RECORD_SIZE: usize = 100 * 1024 * 1024; // 100MB, well below chunk limit

async fn read_record_bytes(&mut self) -> Result<Option<Bytes>> {
    let _timer = BACKUP_TIMER.timer_with(&["read_record_bytes"]);
    
    // read record size
    let mut size_buf = BytesMut::with_capacity(4);
    self.read_full_buf_or_none(&mut size_buf).await?;
    if size_buf.is_empty() {
        return Ok(None);
    }

    let record_size = u32::from_be_bytes(size_buf.as_ref().try_into()?) as usize;
    
    // SECURITY: Validate record size to prevent DoS
    if record_size > MAX_RECORD_SIZE {
        bail!(
            "Record size {} exceeds maximum allowed size {}. \
             Possible malicious backup file.",
            record_size,
            MAX_RECORD_SIZE
        );
    }
    
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

### 2. Add Timeout Protection

Implement per-record read timeouts to prevent indefinite blocking:

```rust
use tokio::time::{timeout, Duration};

const RECORD_READ_TIMEOUT_SECS: u64 = 300; // 5 minutes per record

async fn read_record_bytes(&mut self) -> Result<Option<Bytes>> {
    timeout(
        Duration::from_secs(RECORD_READ_TIMEOUT_SECS),
        self.read_record_bytes_impl()
    )
    .await
    .map_err(|_| anyhow!("Record read timeout exceeded"))?
}
```

### 3. Add Progressive Monitoring

Log warnings when record sizes exceed typical thresholds to aid in attack detection:

```rust
if record_size > 10 * 1024 * 1024 { // 10MB
    warn!(
        record_size = record_size,
        "Unusually large backup record detected. Size: {} bytes",
        record_size
    );
}
```

## Proof of Concept

```rust
// File: storage/backup/backup-cli/src/utils/read_record_bytes_dos_test.rs
#[cfg(test)]
mod dos_tests {
    use super::*;
    use tokio::runtime::Runtime;
    use std::io::Cursor;

    #[test]
    fn test_malicious_large_record_size() {
        Runtime::new().unwrap().block_on(async {
            // Create malicious backup file with 1GB size claim
            let malicious_size = 1u32 << 30; // 1GB
            let mut malicious_backup = malicious_size.to_be_bytes().to_vec();
            
            // Add some data (not 1GB, just enough to demonstrate)
            malicious_backup.extend_from_slice(&vec![0u8; 1024]);
            
            let mut reader = Cursor::new(malicious_backup);
            
            // This will attempt to allocate 1GB buffer
            let start = std::time::Instant::now();
            let result = reader.read_record_bytes().await;
            
            // Without the fix, this would:
            // 1. Allocate 1GB of memory (may cause OOM)
            // 2. Loop trying to read 1GB (would timeout/fail on EOF)
            assert!(result.is_err()); // Should fail due to EOF
            
            println!("Time taken: {:?}", start.elapsed());
            println!("Result: {:?}", result);
        });
    }

    #[test]
    fn test_max_u32_record_size() {
        Runtime::new().unwrap().block_on(async {
            // Attacker claims record is 4GB (u32::MAX)
            let malicious_size = u32::MAX;
            let malicious_backup = malicious_size.to_be_bytes().to_vec();
            
            let mut reader = Cursor::new(malicious_backup);
            
            // Without validation, this would attempt to allocate 4GB
            // With the recommended fix, this should fail immediately
            let result = reader.read_record_bytes().await;
            
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("exceeds maximum"));
        });
    }

    #[test]
    fn test_legitimate_record_passes() {
        Runtime::new().unwrap().block_on(async {
            // Legitimate record under 100MB limit
            let data = vec![1, 2, 3, 4, 5];
            let size = (data.len() as u32).to_be_bytes();
            
            let mut legitimate_backup = size.to_vec();
            legitimate_backup.extend_from_slice(&data);
            
            let mut reader = Cursor::new(legitimate_backup);
            let result = reader.read_record_bytes().await;
            
            assert!(result.is_ok());
            assert_eq!(result.unwrap().unwrap(), &data[..]);
        });
    }
}
```

**To demonstrate the real-world impact:**

1. Deploy a test S3 bucket with command adapter configuration
2. Upload a malicious backup file with 1GB record size prefix
3. Attempt restoration using `aptos-debugger aptos-db restore bootstrap-db`
4. Observe: memory spike to 1GB+ and restoration taking 40+ minutes per record
5. Apply the recommended fix and observe: immediate rejection with clear error message

---

## Notes

This vulnerability highlights the importance of validating all external inputs, even when using trusted waypoints for cryptographic verification. The verification happens **after** resource allocation and I/O operations, making the system vulnerable to resource exhaustion attacks that occur before verification can reject malicious data.

The recommended 100MB maximum is conservative and well above typical record sizes (most state values and transactions are under 1MB when BCS-serialized), while preventing the extreme cases that enable this DoS attack.

### Citations

**File:** storage/backup/backup-cli/src/utils/read_record_bytes.rs (L24-41)
```rust
        loop {
            let n_read = self.read_buf(buf).await.err_notes("")?;
            let n_read_total = buf.len();
            if n_read_total == n_expected {
                return Ok(());
            }
            if n_read == 0 {
                if n_read_total == 0 {
                    return Ok(());
                } else {
                    bail!(
                        "Hit EOF before filling the whole buffer, read {}, expected {}",
                        n_read_total,
                        n_expected
                    );
                }
            }
        }
```

**File:** storage/backup/backup-cli/src/utils/read_record_bytes.rs (L54-54)
```rust
        let record_size = u32::from_be_bytes(size_buf.as_ref().try_into()?) as usize;
```

**File:** storage/backup/backup-cli/src/utils/read_record_bytes.rs (L60-60)
```rust
        let mut record_buf = BytesMut::with_capacity(record_size);
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L105-167)
```rust
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
```

**File:** docker/compose/data-restore/docker-compose.yaml (L1-32)
```yaml
# This compose file can be used to restore data for a fullnode.
# You will need to provide the restore data source in the configuration.
version: "3.8"
services:
  restore:
    image: aptoslabs/tools:nightly
    volumes:
      - type: volume
        source: db
        target: /opt/aptos/data
      - type: volume
        source: tmp
        target: /tmp
      # Depends on which cloud backup data you use, replace this with either:
      # `s3.yaml` (AWS S3)
      # `gcs.yaml` (GCP GCS)
      # You can update the yaml file to specify where you want to download data from,
      # default data resource is hosted by AptosLabs.
      - type: bind
        source: ./s3.yaml
        target: /opt/aptos/etc/restore.yaml
        read_only: true
    environment:
      - HOME=/tmp
      - RUST_LOG=debug
    command: >
      sh -c "
      /usr/local/bin/aptos-debugger aptos-db restore bootstrap-db --concurrent-downloads 2 \
        --target-db-dir /opt/aptos/data/db
        --metadata-cache-dir /tmp/aptos-restore-metadata \
        --command-adapter-config /opt/aptos/etc/restore.yaml
      "
```

**File:** storage/backup/backup-cli/src/utils/mod.rs (L51-57)
```rust
    // Defaults to 128MB, so concurrent chunk downloads won't take up too much memory.
    #[clap(
        long = "max-chunk-size",
        default_value_t = 134217728,
        help = "Maximum chunk file size in bytes."
    )]
    pub max_chunk_size: usize,
```
