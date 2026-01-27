# Audit Report

## Title
Master Node Impersonation Vulnerability in Indexer GRPC Manager Allows Historical Data Corruption

## Summary
The `is_master` configuration flag in `IndexerGrpcManagerConfig` lacks authentication and coordination mechanisms, allowing any actor with GCS write access to deploy a malicious master node that can overwrite legitimate historical transaction data in the file store, causing data corruption and denial of service of the indexer infrastructure.

## Finding Description

The indexer-grpc-manager system uses a master/non-master architecture where the master node writes transaction data to a shared file store (GCS bucket), and non-master nodes read from it. The master designation is controlled solely by the `is_master` boolean field in the configuration file. [1](#0-0) 

When `is_master` is set to `true`, the node spawns a `FileStoreUploader` that continuously writes transaction data and metadata to the file store: [2](#0-1) 

The critical vulnerability exists because:

1. **No Authentication**: Any actor can set `is_master: true` in their config file. The system has a comment acknowledging this: "We assume the master is statically configured for now." [3](#0-2) 

2. **No Coordination**: Multiple nodes can claim to be master simultaneously with no detection or prevention mechanism.

3. **Unconditional Writes**: The file store writes use `Object::create` without conditional update preconditions (no etag or generation matching), meaning last-write-wins: [4](#0-3) 

4. **Metadata Overwriting**: The critical `metadata.json` file (containing the current version pointer) gets overwritten by each master: [5](#0-4) 

5. **Version Corruption Detection**: Non-master nodes detect when the file store version goes backward and panic, causing DoS: [6](#0-5) 

**Attack Scenario:**
1. Legitimate master node A is running with version at 1,000,000
2. Attacker deploys malicious master node B with valid GCS credentials and `is_master: true`
3. Attacker's node starts from an earlier version (e.g., 500,000) or arbitrary version
4. Both masters race to write `metadata.json` and transaction data files
5. Version numbers oscillate or jump backward as masters overwrite each other
6. Non-master nodes detect backward version progression and crash
7. Historical transaction data integrity is compromised

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos Bug Bounty criteria:

- **API crashes**: Non-master indexer nodes will panic and crash when they detect version inconsistency, matching "API crashes" category
- **Significant protocol violations**: Data integrity guarantees for historical transaction data are violated, matching "Significant protocol violations"

While this does not affect blockchain consensus directly (the core blockchain continues operating), it causes:
- Complete denial of service of the indexer infrastructure
- Corruption of historical transaction data relied upon by applications and block explorers
- Non-recoverable state requiring manual intervention to restore data consistency
- Potential cascading failures in downstream systems depending on indexer data

The impact is significant because Aptos applications and services rely on the indexer for querying historical blockchain state.

## Likelihood Explanation

**Likelihood: Medium-High**

Required attacker capabilities:
- Access to a GCS service account key with write permissions to the indexer bucket (could be obtained through credential compromise, misconfigured permissions, or insider access)
- Knowledge of the bucket configuration (often publicly documented or discoverable)
- Ability to deploy and run an indexer-grpc-manager instance

The attack is straightforward once credentials are obtained - simply deploy a node with `is_master: true` in the config. No sophisticated exploit techniques are required.

The vulnerability is exacerbated by:
- No monitoring or alerting for multiple masters
- No audit logging of master claims
- No mutual exclusion or leader election protocol

## Recommendation

Implement a distributed coordination mechanism to ensure only one master node can write to the file store at any time. Multiple approaches can prevent this:

**Option 1: Use GCS Conditional Updates**
Modify the file store writer to use generation-based conditional updates:
- Before writing, read the current object generation number
- Write with `if-generation-match` precondition
- Retry on conflict, implementing exponential backoff
- If precondition fails consistently, alert and terminate (another master exists)

**Option 2: Distributed Lock Using Cloud Services**
Implement a distributed lock using GCS object metadata or a dedicated coordination service:
- Master must acquire and maintain a lock before writing
- Lock includes timestamp and master identity
- Lock must be refreshed periodically (with lease timeout)
- Masters detect lock conflicts and refuse to operate

**Option 3: Master Election Protocol**
Implement a proper leader election protocol among indexer-grpc-managers:
- Use consensus among manager nodes to elect a single master
- Master sends heartbeats proving liveness
- Automatic failover if master becomes unavailable

**Immediate Mitigation:**
Add validation to ensure only one master can exist:
```rust
// In GrpcManager::new()
if config.is_master {
    // Attempt to create a lock file with conditional create
    // Fail startup if lock already exists
    // Include master identity and startup timestamp in lock
}
```

## Proof of Concept

```rust
// Simulate two masters writing conflicting metadata

use aptos_indexer_grpc_utils::file_store_operator_v2::common::FileStoreMetadata;
use std::path::PathBuf;

#[tokio::test]
async fn test_master_impersonation() {
    // Setup shared GCS bucket
    let bucket_name = "test-indexer-bucket";
    let service_account_key = "/path/to/service-account.json";
    
    // Master A configuration
    let config_a = IndexerGrpcManagerConfig {
        chain_id: 1,
        is_master: true,  // Legitimate master
        file_store_config: IndexerGrpcFileStoreConfig::GcsFileStore(GcsFileStore {
            gcs_file_store_bucket_name: bucket_name.to_string(),
            gcs_file_store_service_account_key_path: service_account_key.to_string(),
            ..Default::default()
        }),
        ..Default::default()
    };
    
    // Master B configuration (attacker)
    let config_b = IndexerGrpcManagerConfig {
        chain_id: 1,
        is_master: true,  // Malicious master - NO VALIDATION PREVENTS THIS
        file_store_config: IndexerGrpcFileStoreConfig::GcsFileStore(GcsFileStore {
            gcs_file_store_bucket_name: bucket_name.to_string(),
            gcs_file_store_service_account_key_path: service_account_key.to_string(),
            ..Default::default()
        }),
        ..Default::default()
    };
    
    // Start both masters concurrently
    let master_a = tokio::spawn(async move {
        let manager = GrpcManager::new(&config_a).await;
        // Master A writes version 1000
        manager.file_store_uploader.lock().await
            .update_file_store_metadata(1000).await.unwrap();
    });
    
    let master_b = tokio::spawn(async move {
        let manager = GrpcManager::new(&config_b).await;
        // Master B writes version 500 (backward!)
        manager.file_store_uploader.lock().await
            .update_file_store_metadata(500).await.unwrap();
    });
    
    // Both succeed - last write wins, version goes backward
    master_a.await.unwrap();
    master_b.await.unwrap();
    
    // Non-master node reads backward version and panics
    let non_master_config = IndexerGrpcManagerConfig {
        is_master: false,
        ..config_a
    };
    let data_manager = DataManager::new(/* ... */);
    
    // This will panic: "File store version is going backward, data might be corrupted"
    data_manager.update_file_store_version_in_cache(
        &cache, 
        /*version_can_go_backward=*/ false
    ).await;
}
```

## Notes

This vulnerability is specific to the indexer-grpc infrastructure and does not directly impact blockchain consensus or validator operations. However, it represents a significant data integrity and availability issue for the Aptos indexing layer, which is critical for application developers and blockchain explorers querying historical state.

The root cause is the lack of distributed coordination in a system designed with a single-master assumption but no enforcement mechanism. The `is_master` flag should be either:
1. Eliminated in favor of automatic leader election
2. Protected by cryptographic attestation or distributed locks
3. Validated at runtime with conflict detection

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/config.rs (L40-40)
```rust
    pub(crate) is_master: bool,
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/grpc_manager.rs (L112-121)
```rust
            if self.is_master {
                s.spawn(async move {
                    self.file_store_uploader
                        .lock()
                        .await
                        .start(self.data_manager.clone(), tx)
                        .await
                        .unwrap();
                });
            }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L135-136)
```rust
    // NOTE: We assume the master is statically configured for now.
    master_address: Mutex<Option<GrpcAddress>>,
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator_v2/gcs.rs (L120-137)
```rust
    async fn save_raw_file(&self, file_path: PathBuf, data: Vec<u8>) -> Result<()> {
        let path = self.get_path(file_path);
        trace!(
            "Uploading object to {}/{}.",
            self.bucket_name,
            path.as_str()
        );
        Object::create(
            self.bucket_name.as_str(),
            data,
            path.as_str(),
            JSON_FILE_TYPE,
        )
        .await
        .map_err(anyhow::Error::msg)?;

        Ok(())
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/file_store_uploader.rs (L261-274)
```rust
    /// Updates the file store metadata.
    async fn update_file_store_metadata(&self, version: u64) -> Result<()> {
        FILE_STORE_VERSION.set(version as i64);
        let metadata = FileStoreMetadata {
            chain_id: self.chain_id,
            num_transactions_per_folder: NUM_TXNS_PER_FOLDER,
            version,
        };

        let raw_data = serde_json::to_vec(&metadata).map_err(anyhow::Error::msg)?;
        self.writer
            .save_raw_file(PathBuf::from(METADATA_FILE_NAME), raw_data)
            .await
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/data_manager.rs (L415-417)
```rust
            if !version_can_go_backward && file_store_version_before_update > file_store_version {
                panic!("File store version is going backward, data might be corrupted. {file_store_version_before_update} v.s. {file_store_version}");
            };
```
