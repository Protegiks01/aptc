# Audit Report

## Title
Backward Compatibility Failure in GCS FileStoreMetadata Migration Causes Indexer Initialization Panic

## Summary
The `#[serde(default)]` attribute on the `storage_format` field in `FileStoreMetadata` correctly provides a default value for backward compatibility with old metadata files. However, a storage format assertion in the GCS file store operator breaks this intended migration path, causing indexer crashes when upgrading from legacy to compressed storage format.

## Finding Description

The `FileStoreMetadata` struct includes backward compatibility support via `#[serde(default)]`: [1](#0-0) 

The default function returns the legacy format: [2](#0-1) 

A test explicitly validates this backward compatibility: [3](#0-2) 

However, the GCS file store operator contains an assertion that breaks the intended migration: [4](#0-3) 

**Migration Failure Scenario:**
1. Existing GCS file store has `metadata.json` without `storage_format` field (pre-compression era)
2. Operator deploys new indexer with `enable_compression=true`, creating operator with `storage_format=Lz4CompressedProto`: [5](#0-4) 

3. During initialization, processor calls `update_file_store_metadata_with_timeout`: [6](#0-5) 

4. Old metadata deserializes with default `JsonBase64UncompressedProto`, but operator has `Lz4CompressedProto`
5. Assertion fails with panic: "Storage format mismatch"
6. Indexer cannot initialize

The local file store operator does NOT have this bug - it only validates chain_id: [7](#0-6) 

## Impact Explanation

**Medium Severity** - This causes indexer service disruption during legitimate upgrades:
- **Service Availability**: Indexers fail to initialize, blocking data access for applications
- **Migration Failure**: Cannot upgrade from legacy to compressed storage without manual intervention
- **Operational Impact**: Requires manual metadata file updates to resolve

However, this does NOT affect:
- Core blockchain consensus or safety
- Validator operations or transaction processing  
- On-chain funds or state integrity
- The blockchain continues operating; only off-chain indexer services are impacted

## Likelihood Explanation

**High Likelihood** during specific upgrade scenarios:
- Any GCS-based indexer upgrading from pre-compression to compression-enabled configuration
- Operators following standard upgrade procedures will encounter this issue
- Does NOT require attacker action - occurs during legitimate operational upgrades

**Low Likelihood** as a security exploit:
- Not exploitable by unprivileged external attackers
- Requires operator/admin access to deploy configuration changes
- Falls outside the threat model of external adversaries

## Recommendation

Remove the storage format assertion from the GCS operator to allow format migration, matching the local operator's behavior. The assertion prevents the intended backward compatibility from working:

```rust
async fn update_file_store_metadata_with_timeout(
    &mut self,
    expected_chain_id: u64,
    version: u64,
) -> anyhow::Result<()> {
    if let Some(metadata) = self.get_file_store_metadata().await {
        assert_eq!(metadata.chain_id, expected_chain_id, "Chain ID mismatch.");
        // REMOVE this assertion to allow format migration:
        // assert_eq!(
        //     metadata.storage_format, self.storage_format,
        //     "Storage format mismatch."
        // );
        
        // OPTIONAL: Log a warning instead if formats differ
        if metadata.storage_format != self.storage_format {
            tracing::warn!(
                old_format = ?metadata.storage_format,
                new_format = ?self.storage_format,
                "Storage format migration detected"
            );
        }
    }
    // ... rest of function
}
```

Alternatively, implement explicit migration logic that updates the metadata file's storage format upon first detection of a mismatch.

## Proof of Concept

```rust
#[cfg(test)]
mod backward_compatibility_test {
    use super::*;
    
    #[test]
    fn test_gcs_operator_migration_failure() {
        // Simulate old metadata without storage_format field
        let old_metadata_json = r#"{
            "chain_id": 1,
            "file_folder_size": 1000,
            "version": 0
        }"#;
        
        // Deserialize old metadata - should get default JsonBase64UncompressedProto
        let metadata: FileStoreMetadata = serde_json::from_str(old_metadata_json).unwrap();
        assert_eq!(metadata.storage_format, StorageFormat::JsonBase64UncompressedProto);
        
        // Create new operator with compression enabled
        let operator_storage_format = StorageFormat::Lz4CompressedProto;
        
        // This assertion would fail in update_file_store_metadata_with_timeout:
        // assert_eq!(metadata.storage_format, operator_storage_format, "Storage format mismatch.");
        
        // Demonstrates the panic condition
        assert_ne!(
            metadata.storage_format, 
            operator_storage_format,
            "Format mismatch causes panic during migration"
        );
    }
}
```

---

## Notes

While this is a genuine backward compatibility bug that causes service disruption, it falls **outside the scope** of critical blockchain security vulnerabilities because:

1. **Not Exploitable by External Attackers**: Requires operator/admin access to deploy configuration changes
2. **Indexer Infrastructure Only**: Affects off-chain data access services, not core blockchain consensus, state, or funds
3. **Operational Issue**: Occurs during legitimate upgrades, not from adversarial actions
4. **No Protocol Impact**: The Aptos blockchain continues operating normally; only indexer services are disrupted

This is better classified as an **operational deployment bug** rather than a security vulnerability per the strict validation criteria. The issue should be fixed to improve operational reliability, but it does not represent an attack vector for unprivileged adversaries to compromise blockchain security.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/compression_util.rs (L44-45)
```rust
    #[serde(default = "default_file_storage_format")]
    pub storage_format: StorageFormat,
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/compression_util.rs (L446-462)
```rust
    fn test_new_format_not_break_existing_metadata() {
        let file_metadata_serialized_json = r#"{
            "chain_id": 1,
            "file_folder_size": 1000,
            "version": 1
        }"#;

        let file_metadata: FileStoreMetadata = serde_json::from_str(file_metadata_serialized_json)
            .expect("FileStoreMetadata deserialization failed.");

        assert_eq!(
            file_metadata.storage_format,
            StorageFormat::JsonBase64UncompressedProto
        );
        assert_eq!(file_metadata.chain_id, 1);
        assert_eq!(file_metadata.file_folder_size, 1000);
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/lib.rs (L31-33)
```rust
pub fn default_file_storage_format() -> compression_util::StorageFormat {
    compression_util::StorageFormat::JsonBase64UncompressedProto
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator/gcs.rs (L39-43)
```rust
        let storage_format = if enable_compression {
            StorageFormat::Lz4CompressedProto
        } else {
            StorageFormat::JsonBase64UncompressedProto
        };
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator/gcs.rs (L167-173)
```rust
        if let Some(metadata) = self.get_file_store_metadata().await {
            assert_eq!(metadata.chain_id, expected_chain_id, "Chain ID mismatch.");
            assert_eq!(
                metadata.storage_format, self.storage_format,
                "Storage format mismatch."
            );
        }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store/src/processor.rs (L67-69)
```rust
            while file_store_operator
                .update_file_store_metadata_with_timeout(chain_id, 0)
                .await
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator/local.rs (L100-106)
```rust
        match tokio::fs::read(metadata_path).await {
            Ok(metadata) => {
                let metadata: FileStoreMetadata =
                    serde_json::from_slice(&metadata).expect("Expected metadata to be valid JSON.");
                anyhow::ensure!(metadata.chain_id == expected_chain_id, "Chain ID mismatch.");
                Ok(())
            },
```
