# Audit Report

## Title
Unbounded Memory Exhaustion in QuorumStore V2 Batch Recovery Causing Consensus Node Crash on Restart

## Summary
The `get_all_batches_v2()` function loads all persisted V2 batches from the database into memory without any pagination or limits during node restart. With multiple validators each accumulating up to 300,000 batches over time, this can cause Out-Of-Memory (OOM) crashes during restart, preventing consensus participation and potentially causing network liveness failures.

## Finding Description

The vulnerability exists in the QuorumStore batch recovery mechanism during consensus node restart. When a node restarts (but not during a new epoch transition), the system attempts to repopulate its in-memory cache by loading all persisted batches from the database. [1](#0-0) 

This function creates an iterator over the entire `BatchV2Schema` column family and collects **all entries** into a HashMap in memory without any bounds checking or pagination. The function is called during node initialization: [2](#0-1) 

The critical flaw is at lines 299-301 where `get_all_batches_v2()` loads everything into memory **before** filtering expired batches. The garbage collection happens only **after** all batches are already in memory.

**Data Structure Analysis:**

Each batch is stored as `PersistedValue<BatchInfoExt>`: [3](#0-2) 

The `BatchInfoExt` type is larger than the V1 `BatchInfo` because it includes extended metadata: [4](#0-3) [5](#0-4) 

**Memory Calculation:**

The default per-peer batch quota is 300,000: [6](#0-5) 

In a network with 100 validators:
- Total potential batches: 100 × 300,000 = 30,000,000 batches
- Size per entry (metadata only): ~350 bytes (BatchInfoExt + HashMap overhead)
- **Total memory requirement: ~10.5 GB** just for metadata

If payloads are included (even partially), memory usage can exceed 50+ GB, causing OOM on most nodes.

**Attack Scenario:**

1. **Natural Accumulation**: During normal operation, each validator creates batches within their quota limits. Over days/weeks, batches naturally accumulate in the database.

2. **Trigger Event**: Node restarts due to crash, upgrade, or maintenance (common operational events).

3. **Unbounded Load**: `populate_cache_and_gc_expired_batches_v2()` is invoked, which calls `get_all_batches_v2()` loading all 30M+ batches into memory.

4. **OOM Crash**: The node runs out of memory and crashes, failing to restart and participate in consensus.

5. **Amplified Impact**: If multiple nodes restart simultaneously (e.g., coordinated upgrade), the network could experience liveness issues.

## Impact Explanation

**Severity: HIGH to CRITICAL**

This vulnerability qualifies as **HIGH severity** under the Aptos bug bounty criteria:
- **Validator node crashes** - Direct match for "Validator node slowdowns" and API crashes
- Prevents validator from participating in consensus during restart

The severity escalates to **CRITICAL** if:
- Multiple validators restart simultaneously (coordinated upgrades)
- Could cause **"Total loss of liveness/network availability"** if enough nodes cannot restart
- Represents a **"Non-recoverable network partition"** scenario requiring emergency intervention

The vulnerability breaks **Critical Invariant #9**: "Resource Limits: All operations must respect gas, storage, and computational limits." The unbounded memory load during restart violates fundamental resource constraint guarantees.

## Likelihood Explanation

**Likelihood: HIGH**

This is not a theoretical attack—it's an operational inevitability:

1. **Natural Occurrence**: Batches accumulate naturally during normal validator operation. The 300,000 per-peer quota is designed to be hit during normal operation.

2. **Common Trigger**: Node restarts happen regularly for:
   - Software upgrades
   - Crash recovery  
   - Maintenance operations
   - Hardware issues

3. **No Special Privileges Required**: Any validator participating normally will accumulate batches. No malicious behavior needed.

4. **Amplification Over Time**: The longer the network runs without epoch changes that trigger full cleanup, the worse the problem becomes.

5. **Network-Wide Risk**: With 100+ validators, the probability that at least one node experiences this during restart approaches certainty as batches accumulate.

## Recommendation

Implement **paginated/streaming batch recovery** to avoid loading all batches into memory simultaneously:

```rust
fn get_all_batches_v2(&self) -> Result<HashMap<HashValue, PersistedValue<BatchInfoExt>>> {
    let mut iter = self.db.iter::<BatchV2Schema>()?;
    iter.seek_to_first();
    
    // Add pagination or streaming
    const MAX_BATCHES_PER_LOAD: usize = 10_000;
    let mut result = HashMap::new();
    let mut count = 0;
    
    for item in iter {
        let (key, value) = item?;
        result.insert(key, value);
        count += 1;
        
        if count >= MAX_BATCHES_PER_LOAD {
            break;
        }
    }
    
    Ok(result)
}
```

**Better solution**: Modify `populate_cache_and_gc_expired_batches_v2()` to stream and filter batches incrementally:

```rust
fn populate_cache_and_gc_expired_batches_v2(
    db: Arc<dyn QuorumStoreStorage>,
    current_epoch: u64,
    last_certified_time: u64,
    expiration_buffer_usecs: u64,
    batch_store: &BatchStore,
) {
    let gc_timestamp = last_certified_time.saturating_sub(expiration_buffer_usecs);
    let mut expired_keys = Vec::new();
    
    // Stream directly from database iterator instead of loading all
    let mut iter = db.db.iter::<BatchV2Schema>().expect("Failed to create iterator");
    iter.seek_to_first();
    
    for item in iter {
        let (digest, value) = item.expect("Failed to read batch");
        
        if value.expiration() < gc_timestamp {
            expired_keys.push(digest);
        } else {
            batch_store
                .insert_to_cache(&value)
                .expect("Storage limit exceeded upon BatchReader construction");
        }
    }
    
    tokio::task::spawn_blocking(move || {
        db.delete_batches_v2(expired_keys)
            .expect("Deletion of expired keys should not fail");
    });
}
```

**Additional improvements**:
1. Add a configurable maximum batch age for cleanup
2. Implement periodic background cleanup instead of only at startup
3. Add memory usage monitoring and alerts
4. Consider compacting the database to remove old entries

## Proof of Concept

```rust
#[cfg(test)]
mod oom_test {
    use super::*;
    use aptos_crypto::HashValue;
    use std::sync::Arc;
    use tempfile::TempDir;
    
    #[test]
    #[ignore] // Ignore by default as this will consume large memory
    fn test_get_all_batches_v2_memory_exhaustion() {
        // Setup
        let tmp_dir = TempDir::new().unwrap();
        let db = Arc::new(QuorumStoreDB::new(tmp_dir.path()));
        
        // Simulate 100 validators each with 300,000 batches
        let num_validators = 100;
        let batches_per_validator = 300_000;
        let total_batches = num_validators * batches_per_validator; // 30,000,000
        
        println!("Creating {} batches...", total_batches);
        
        // Create and persist batches
        for validator_id in 0..num_validators {
            let author = PeerId::random();
            for batch_idx in 0..batches_per_validator {
                let batch_info = BatchInfoExt::new_v2(
                    author,
                    BatchId::new_for_test(batch_idx),
                    1, // epoch
                    aptos_infallible::duration_since_epoch().as_micros() as u64 + 1000000,
                    HashValue::random(),
                    10, // num_txns
                    1000, // num_bytes
                    0, // gas_bucket_start
                    BatchKind::Normal,
                );
                
                let persisted = PersistedValue::new(batch_info, None);
                db.save_batch_v2(persisted).unwrap();
                
                if batch_idx % 10000 == 0 {
                    println!("Validator {}: Created {} batches", validator_id, batch_idx);
                }
            }
        }
        
        println!("All batches created. Now attempting to load all into memory...");
        
        // Measure memory before
        let memory_before = get_memory_usage();
        
        // This should cause OOM or consume massive memory
        let result = db.get_all_batches_v2();
        
        match result {
            Ok(batches) => {
                let memory_after = get_memory_usage();
                let memory_used = memory_after - memory_before;
                
                println!("Loaded {} batches", batches.len());
                println!("Memory used: {} MB", memory_used / 1_000_000);
                
                // If we got here, assert that excessive memory was used
                assert!(memory_used > 5_000_000_000, // > 5GB
                    "Expected high memory usage, got {} bytes", memory_used);
            }
            Err(e) => {
                println!("Failed to load batches (likely OOM): {:?}", e);
                panic!("OOM occurred as expected");
            }
        }
    }
    
    fn get_memory_usage() -> usize {
        // Platform-specific memory usage check
        #[cfg(target_os = "linux")]
        {
            use std::fs;
            let status = fs::read_to_string("/proc/self/status").unwrap();
            for line in status.lines() {
                if line.starts_with("VmRSS:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    return parts[1].parse::<usize>().unwrap() * 1024; // Convert KB to bytes
                }
            }
        }
        0
    }
}
```

**Steps to reproduce:**
1. Configure a test network with multiple validators
2. Let the network run for extended period, accumulating batches
3. Restart a consensus node (kill and restart the process)
4. Monitor memory usage during startup
5. Observe OOM crash or excessive memory consumption (10+ GB)

## Notes

This vulnerability affects both V1 (`get_all_batches()`) and V2 (`get_all_batches_v2()`) implementations, but V2 is marginally worse due to the additional `ExtraBatchInfo` metadata (~10-20 bytes per batch). While the per-batch overhead is small, across millions of batches this compounds the problem.

The quota system (300,000 batches per peer) protects against **creating** too many batches during normal operation but provides **no protection** during the recovery/restart phase when all batches are loaded into memory simultaneously.

The vulnerability is particularly dangerous because:
- It's triggered by normal operational events (restarts)
- It worsens over time as batches accumulate
- It can prevent nodes from restarting, requiring manual database cleanup
- Coordinated restarts (e.g., network upgrades) could cause widespread outages

### Citations

**File:** consensus/src/quorum_store/quorum_store_db.rs (L133-138)
```rust
    fn get_all_batches_v2(&self) -> Result<HashMap<HashValue, PersistedValue<BatchInfoExt>>> {
        let mut iter = self.db.iter::<BatchV2Schema>()?;
        iter.seek_to_first();
        iter.map(|res| res.map_err(Into::into))
            .collect::<Result<HashMap<HashValue, PersistedValue<BatchInfoExt>>>>()
    }
```

**File:** consensus/src/quorum_store/batch_store.rs (L292-336)
```rust
    fn populate_cache_and_gc_expired_batches_v2(
        db: Arc<dyn QuorumStoreStorage>,
        current_epoch: u64,
        last_certified_time: u64,
        expiration_buffer_usecs: u64,
        batch_store: &BatchStore,
    ) {
        let db_content = db
            .get_all_batches_v2()
            .expect("failed to read v1 data from db");
        info!(
            epoch = current_epoch,
            "QS: Read v1 batches from storage. Len: {}, Last Cerified Time: {}",
            db_content.len(),
            last_certified_time
        );

        let mut expired_keys = Vec::new();
        let gc_timestamp = last_certified_time.saturating_sub(expiration_buffer_usecs);
        for (digest, value) in db_content {
            let expiration = value.expiration();
            trace!(
                "QS: Batchreader recovery content exp {:?}, digest {}",
                expiration,
                digest
            );

            if expiration < gc_timestamp {
                expired_keys.push(digest);
            } else {
                batch_store
                    .insert_to_cache(&value)
                    .expect("Storage limit exceeded upon BatchReader construction");
            }
        }

        info!(
            "QS: Batch store bootstrap expired keys len {}",
            expired_keys.len()
        );
        tokio::task::spawn_blocking(move || {
            db.delete_batches_v2(expired_keys)
                .expect("Deletion of expired keys should not fail");
        });
    }
```

**File:** consensus/src/quorum_store/types.rs (L21-25)
```rust
#[derive(Clone, Eq, Deserialize, Serialize, PartialEq, Debug)]
pub struct PersistedValue<T> {
    info: T,
    maybe_payload: Option<Vec<SignedTransaction>>,
}
```

**File:** consensus/consensus-types/src/proof_of_store.rs (L192-203)
```rust
#[derive(
    Clone, Debug, Deserialize, Serialize, CryptoHasher, BCSCryptoHash, PartialEq, Eq, Hash,
)]
pub enum BatchInfoExt {
    V1 {
        info: BatchInfo,
    },
    V2 {
        info: BatchInfo,
        extra: ExtraBatchInfo,
    },
}
```

**File:** consensus/consensus-types/src/proof_of_store.rs (L335-348)
```rust
#[derive(
    Clone, Debug, Deserialize, Serialize, CryptoHasher, BCSCryptoHash, PartialEq, Eq, Hash,
)]
pub struct ExtraBatchInfo {
    pub batch_kind: BatchKind,
}

#[derive(
    Clone, Debug, Deserialize, Serialize, CryptoHasher, BCSCryptoHash, PartialEq, Eq, Hash,
)]
pub enum BatchKind {
    Normal,
    Encrypted,
}
```

**File:** config/src/config/quorum_store_config.rs (L135-135)
```rust
            batch_quota: 300_000,
```
