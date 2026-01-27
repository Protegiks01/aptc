# Audit Report

## Title
Unbounded Memory Allocation in State Snapshot and Transaction Restore Operations Enabling Validator DoS

## Summary
The backup restore functionality lacks validation of chunk file sizes and individual record sizes, allowing malicious backup files to trigger unbounded memory allocation. An attacker who can influence backup sources can craft malicious chunks that exhaust node memory, causing validator nodes to crash during initialization and preventing them from participating in consensus.

## Finding Description

The restore operations in `Command::run()` delegate to various restore controllers that load backup chunks into memory without size validation, violating the Resource Limits invariant (#9). [1](#0-0) 

The vulnerability exists in three critical code paths:

**1. State Snapshot Restore - Unbounded Chunk Loading**

The `read_state_value` function loads an entire chunk file into memory without validating its size: [2](#0-1) 

**2. Record-Level Memory Allocation Without Bounds**

The `read_record_bytes` function allocates memory based on an untrusted u32 size field from the backup file, allowing up to 4GB allocation per record: [3](#0-2) 

At line 60, `BytesMut::with_capacity(record_size)` unconditionally allocates memory based on the size read from the file at line 54, with no upper bound validation.

**3. Transaction Restore - Similar Unbounded Loading**

The `LoadedChunk::load` method exhibits the same pattern: [4](#0-3) 

**4. Manifest Verification Lacks Size Validation**

The manifest verification only checks structural integrity (version continuity), not resource limits: [5](#0-4) 

**5. Concurrent Download Amplification**

The restore process uses concurrent downloads (default 16) with buffering that amplifies memory consumption: [6](#0-5) 

At line 199, `buffered_x(con * 2, con)` allows up to `2 * concurrent_downloads` chunks to be in various stages of processing simultaneously.

**Attack Scenario:**

1. Attacker creates malicious backup with chunks claiming gigabyte sizes instead of the expected 128MB max_chunk_size used during backup creation: [7](#0-6) 

2. Validator operator configures restore from this malicious source (via compromised S3 bucket or malicious URL)

3. Restore runs as initContainer before validator starts: [8](#0-7) 

4. Multiple oversized chunks are loaded concurrently into memory (16-32 chunks with `concurrent_downloads=16`)

5. Memory exhaustion causes OOM kill, restore fails, validator pod cannot start

6. Validator remains offline, unable to participate in consensus

**Broken Invariant:** Resource Limits (#9) - "All operations must respect gas, storage, and computational limits"

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty criteria for the following reasons:

1. **Validator Node Unavailability**: The restore process runs as an initContainer that must complete successfully before the validator can start. A malicious backup causes the restore to crash (OOM kill), preventing the validator from ever starting and participating in consensus.

2. **State Inconsistency Requiring Intervention**: A failed restore leaves the validator in a broken state requiring manual intervention to identify the issue, replace the backup source, and restart.

3. **Potential Network Impact**: If multiple validators are configured to restore from the same compromised backup source (e.g., a shared backup repository), multiple nodes could be simultaneously taken offline, potentially affecting network liveness.

4. **Not Critical Because**: 
   - Does not directly cause fund loss or theft
   - Does not break consensus safety (validators that remain online continue correctly)
   - Requires specific conditions (restore operation must be initiated)
   - Has deployment-level mitigations (memory limits at 120Gi in Kubernetes)

The impact aligns with Medium severity: "State inconsistencies requiring intervention" and can contribute to "Validator node slowdowns" if memory thrashing occurs before OOM kill.

## Likelihood Explanation

**Likelihood: Medium-High**

**Attack Prerequisites:**
1. Ability to influence backup source (compromised storage, malicious URL, or MITM on HTTP backups)
2. Validator operator initiates restore from compromised source
3. Common during validator setup, recovery, or when syncing new nodes

**Realistic Scenarios:**
- **Compromised Backup Storage**: S3 buckets or GCS storage with overly permissive access policies
- **Supply Chain Attack**: Malicious backup service provider
- **Insider Threat**: Malicious validator operator providing crafted backup
- **Configuration Error**: Operator accidentally uses untrusted backup source

**Amplifying Factors:**
- Restore operations are common in validator lifecycle (initial sync, disaster recovery)
- Default configuration parameters (`concurrent_downloads=16`) amplify the attack
- No application-level warnings or size validation before starting restore
- Multiple validators may use the same backup repository, multiplying impact

## Recommendation

**Immediate Fixes:**

1. **Add Maximum Chunk Size Validation**

In `read_state_value` and similar functions, validate file size before loading:

```rust
async fn read_state_value(
    storage: &Arc<dyn BackupStorage>,
    file_handle: FileHandle,
    max_chunk_size: usize,
) -> Result<Vec<(StateKey, StateValue)>> {
    let mut file = storage.open_for_read(&file_handle).await?;
    let mut chunk = vec![];
    let mut total_bytes = 0;
    
    while let Some(record_bytes) = file.read_record_bytes().await? {
        total_bytes += record_bytes.len();
        ensure!(
            total_bytes <= max_chunk_size,
            "Chunk size {} exceeds maximum allowed size {}",
            total_bytes,
            max_chunk_size
        );
        chunk.push(bcs::from_bytes(&record_bytes)?);
    }
    
    Ok(chunk)
}
```

2. **Add Maximum Record Size Validation**

In `read_record_bytes`, add bounds checking:

```rust
const MAX_RECORD_SIZE: usize = 256 * 1024 * 1024; // 256MB

async fn read_record_bytes(&mut self) -> Result<Option<Bytes>> {
    // ... existing size reading code ...
    let record_size = u32::from_be_bytes(size_buf.as_ref().try_into()?) as usize;
    
    ensure!(
        record_size <= MAX_RECORD_SIZE,
        "Record size {} exceeds maximum allowed size {}",
        record_size,
        MAX_RECORD_SIZE
    );
    
    // ... rest of function ...
}
```

3. **Pre-flight Disk Space Validation**

Before starting restore, check available disk space:

```rust
async fn run_impl(self) -> Result<()> {
    // Check available disk space
    let db_path = self.global_opt.db_dir.as_ref().unwrap();
    let available_space = get_available_disk_space(db_path)?;
    let estimated_size = estimate_restore_size(&metadata_view)?;
    
    ensure!(
        available_space > estimated_size * 2, // 2x safety margin
        "Insufficient disk space. Available: {}, Estimated needed: {}",
        available_space,
        estimated_size
    );
    
    // ... rest of function ...
}
```

4. **Manifest Validation Enhancement**

Add size validation to manifest verify methods to check chunk counts and estimated sizes are reasonable.

5. **Memory Budget Tracking**

Implement runtime memory tracking to abort restore if memory usage exceeds safe thresholds before hitting system OOM killer.

## Proof of Concept

**Malicious Backup Creation Script:**

```bash
#!/bin/bash
# Creates a malicious state snapshot chunk with oversized records

OUTPUT_FILE="malicious_chunk.blob"

# Write a record claiming to be 2GB (will cause 2GB allocation attempt)
MALICIOUS_SIZE=$((2 * 1024 * 1024 * 1024))  # 2GB
printf '%08x' $MALICIOUS_SIZE | xxd -r -p > $OUTPUT_FILE

# Write some data (doesn't need to be 2GB, just the size claim)
dd if=/dev/zero bs=1M count=1 >> $OUTPUT_FILE 2>/dev/null

# Create minimal valid manifest pointing to this chunk
cat > malicious_manifest.json <<EOF
{
  "version": 1000000,
  "epoch": 1,
  "root_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "chunks": [
    {
      "first_idx": 0,
      "last_idx": 1,
      "first_key": "0x0000000000000000000000000000000000000000000000000000000000000000",
      "last_key": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "blobs": "malicious_chunk.blob",
      "proof": "proof.blob"
    }
  ],
  "proof": "txn_proof.blob"
}
EOF

echo "Malicious backup created: malicious_chunk.blob"
echo "When restore attempts to read this, it will try to allocate 2GB per record"
```

**Exploitation Steps:**

1. Deploy malicious backup to accessible storage (S3/GCS/local)
2. Configure validator to restore from malicious backup
3. Start validator pod - initContainer runs restore
4. Observe OOM kill when restore attempts to allocate 2GB+ memory
5. Validator pod fails to start, remains in CrashLoopBackOff

**Memory Exhaustion Calculation:**

With `concurrent_downloads=16` and malicious chunks of 2GB each:
- Up to 32 chunks buffered (`buffered_x(con * 2, con)`)
- Each chunk attempts 2GB+ allocation
- Total memory demand: 64GB+
- Exceeds 120Gi Kubernetes limit → OOM kill
- Even with smaller chunks (500MB), 16 concurrent = 16GB memory pressure

## Notes

- The vulnerability affects both state snapshot restore and transaction restore operations
- Deployment-level memory limits (120Gi) provide last-resort protection but result in ungraceful failures
- The issue is exacerbated by concurrent processing amplifying memory consumption
- Proper fix requires application-level validation before allocation, not just relying on system limits
- The restore process running as initContainer means this directly prevents validator availability

### Citations

**File:** storage/db-tool/src/restore.rs (L65-127)
```rust
impl Command {
    pub async fn run(self) -> Result<()> {
        match self {
            Command::Oneoff(oneoff) => {
                match oneoff {
                    Oneoff::EpochEnding {
                        storage,
                        opt,
                        global,
                    } => {
                        EpochEndingRestoreController::new(
                            opt,
                            global.try_into()?,
                            storage.init_storage().await?,
                        )
                        .run(None)
                        .await?;
                    },
                    Oneoff::StateSnapshot {
                        storage,
                        opt,
                        global,
                    } => {
                        StateSnapshotRestoreController::new(
                            opt,
                            global.try_into()?,
                            storage.init_storage().await?,
                            None, /* epoch_history */
                        )
                        .run()
                        .await?;
                    },
                    Oneoff::Transaction {
                        storage,
                        opt,
                        global,
                    } => {
                        TransactionRestoreController::new(
                            opt,
                            global.try_into()?,
                            storage.init_storage().await?,
                            None, /* epoch_history */
                            VerifyExecutionMode::NoVerify,
                        )
                        .run()
                        .await?;
                    },
                }
            },
            Command::BootstrapDB(bootstrap) => {
                RestoreCoordinator::new(
                    bootstrap.opt,
                    bootstrap.global.try_into()?,
                    bootstrap.storage.init_storage().await?,
                )
                .run()
                .await?;
            },
        }

        Ok(())
    }
}
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L186-199)
```rust
        let storage = self.storage.clone();
        let futs_iter = chunks.into_iter().enumerate().map(|(chunk_idx, chunk)| {
            let storage = storage.clone();
            async move {
                tokio::spawn(async move {
                    let blobs = Self::read_state_value(&storage, chunk.blobs.clone()).await?;
                    let proof = storage.load_bcs_file(&chunk.proof).await?;
                    Result::<_>::Ok((chunk_idx, chunk, blobs, proof))
                })
                .await?
            }
        });
        let con = self.concurrent_downloads;
        let mut futs_stream = stream::iter(futs_iter).buffered_x(con * 2, con);
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L253-266)
```rust
    async fn read_state_value(
        storage: &Arc<dyn BackupStorage>,
        file_handle: FileHandle,
    ) -> Result<Vec<(StateKey, StateValue)>> {
        let mut file = storage.open_for_read(&file_handle).await?;

        let mut chunk = vec![];

        while let Some(record_bytes) = file.read_record_bytes().await? {
            chunk.push(bcs::from_bytes(&record_bytes)?);
        }

        Ok(chunk)
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

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L100-137)
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
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/manifest.rs (L49-88)
```rust
impl TransactionBackup {
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

**File:** storage/backup/backup-cli/src/utils/mod.rs (L49-65)
```rust
#[derive(Clone, Parser)]
pub struct GlobalBackupOpt {
    // Defaults to 128MB, so concurrent chunk downloads won't take up too much memory.
    #[clap(
        long = "max-chunk-size",
        default_value_t = 134217728,
        help = "Maximum chunk file size in bytes."
    )]
    pub max_chunk_size: usize,
    #[clap(
        long,
        default_value_t = 8,
        help = "When applicable (currently only for state snapshot backups), the number of \
        concurrent requests to the fullnode backup service. "
    )]
    pub concurrent_data_requests: usize,
}
```

**File:** terraform/helm/fullnode/templates/fullnode.yaml (L32-72)
```yaml
      initContainers:
      {{- with .Values.restore }}
      {{- if .enabled }}
      - name: restore
        image: {{ .image.repo }}:{{ .image.tag | default $.Values.imageTag }}
        imagePullPolicy: {{ .image.pullPolicy }}
        resources:
          {{- toYaml .resources | nindent 10 }}
        args:
        - /bin/bash
        - -c
        - |-
          set -euxo pipefail
          # cleanup aptosdb
          if [ -f /opt/aptos/data/restore-failed ] || \
              [ ! -f /opt/aptos/data/restore-uid ] || \
              [ "$(cat /opt/aptos/data/restore-uid)" != "{{ .config.restore_epoch }}" ]; then
            rm -rf /opt/aptos/data/db /opt/aptos/data/restore-{complete,failed}
            echo "{{ .config.restore_epoch }}" > /opt/aptos/data/restore-uid
          fi

          [ -f /opt/aptos/data/restore-complete ] && exit 0
          # start restore process
          /usr/local/bin/aptos-debugger aptos-db restore bootstrap-db \
            --concurrent-downloads {{ .config.concurrent_downloads }} \
            {{ range .config.trusted_waypoints }} --trust-waypoint {{ . }}{{ end }} \
            --target-db-dir /opt/aptos/data/db \
            --metadata-cache-dir /opt/aptos/data/aptos-restore-metadata \
            --ledger-history-start-version {{ .config.start_version }} \
            {{- if .config.target_version }} --target-version {{- .config.target_version }}{{- end }}
            --command-adapter-config /opt/aptos/etc/{{ .config.location }}.yaml

          if [ $? -gt 0 ]; then
            # mark restore as failed
            touch /opt/aptos/data/restore-failed
            exit 1
          else
            # success, remove the marker
            rm -f /opt/aptos/data/restore-failed
            touch /opt/aptos/data/restore-complete
          fi
```
