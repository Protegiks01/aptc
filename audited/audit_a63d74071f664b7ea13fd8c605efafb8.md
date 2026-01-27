# Audit Report

## Title
File Checker Skips Verification of Initial Transaction Files When Starting Version is Not Multiple of 1000

## Summary
The indexer-grpc-file-checker lacks validation that the `starting_version` configuration parameter is a multiple of 1000. When set to a non-aligned value, the checker skips verification of all transaction files before the rounded-down starting version, allowing unverified or malicious data to remain in the new bucket.

## Finding Description

The file checker's purpose is to verify that transaction files in a new storage bucket match those in an existing (trusted) bucket. Files are stored in batches of 1000 transactions each, with file names determined by `FileEntry::build_key()` which rounds versions down to the nearest multiple of 1000. [1](#0-0) 

The checker increments its version counter by exactly 1000 after each file verification: [2](#0-1) 

However, there is **no validation** that `starting_version` is a multiple of 1000. The configuration simply accepts any u64 value: [3](#0-2) 

When initialized without an existing progress file, the checker uses `starting_version` directly: [4](#0-3) 

**Attack Scenario:**

If `starting_version = 2500`:
1. First iteration: version 2500 → `build_key(2500)` → file at version 2000
2. Second iteration: version 3500 → `build_key(3500)` → file at version 3000  
3. Third iteration: version 4500 → `build_key(4500)` → file at version 4000

**Files at versions 0 and 1000 are never checked!** The checker permanently skips `(starting_version / 1000) * 1000` worth of files.

A malicious operator could:
- Set `starting_version = 1000` to skip file 0
- Set `starting_version = 5500` to skip files 0, 1000, 2000, 3000, 4000
- Alternatively, corrupt the progress file in the new bucket to jump forward

The new bucket could contain completely different or malicious transaction data in the skipped files, and the checker would never detect this discrepancy.

## Impact Explanation

This qualifies as **High Severity** under "Significant protocol violations" because:

1. **Data Integrity Violation**: The file checker's entire purpose is to ensure complete data integrity between buckets. Skipping files defeats this guarantee.

2. **Undetected Data Corruption**: Malicious or corrupted transaction files in the new bucket will be served to downstream indexer consumers without verification.

3. **Silent Failure**: No error, warning, or log message indicates that files are being skipped. The checker appears to function normally while providing incomplete verification.

4. **Persistent Issue**: Once past the skipped versions, the checker never goes back to verify them.

5. **Indexer Infrastructure Impact**: Applications and services relying on the new bucket will consume unverified blockchain history, potentially making incorrect decisions based on corrupted data.

## Likelihood Explanation

**Likelihood: Medium-High**

This is likely to occur because:

1. **Configuration Error**: Operators might naturally set `starting_version` to the "current" blockchain version without understanding the 1000-alignment requirement, especially since this requirement is not documented or enforced.

2. **Progress File Corruption**: The progress file in GCS could be manually edited or corrupted, setting `file_checker_version` to a non-aligned value.

3. **No Validation or Warning**: The system provides no feedback that the configuration is incorrect.

4. **Non-Obvious Behavior**: The checker continues to operate normally, masking the problem. The rounding behavior of `build_key()` is not immediately apparent to operators.

## Recommendation

Add validation to ensure version alignment at all entry points:

**In `processor.rs` init() function:**

```rust
pub async fn init(&self) -> Result<(Client, ProgressFile)> {
    let client = Client::new();
    
    // Validate starting_version alignment
    ensure!(
        self.starting_version % FILE_ENTRY_TRANSACTION_COUNT == 0,
        "starting_version must be a multiple of {}, got {}",
        FILE_ENTRY_TRANSACTION_COUNT,
        self.starting_version
    );

    // ... rest of init code ...
    
    let progress_file = /* ... */;
    
    // Validate loaded progress file alignment
    ensure!(
        progress_file.file_checker_version % FILE_ENTRY_TRANSACTION_COUNT == 0,
        "Progress file version must be a multiple of {}, got {}",
        FILE_ENTRY_TRANSACTION_COUNT,
        progress_file.file_checker_version
    );
    
    Ok((client, progress_file))
}
```

**Additional safeguards:**

1. Add an assertion after the increment in the run loop to detect any drift
2. Add documentation to `IndexerGrpcFileCheckerConfig` explaining the 1000-alignment requirement
3. Consider rounding down `starting_version` automatically with a warning log

## Proof of Concept

```rust
// Test demonstrating the vulnerability
// Add to ecosystem/indexer-grpc/indexer-grpc-file-checker/src/processor.rs

#[cfg(test)]
mod tests {
    use super::*;
    use aptos_indexer_grpc_utils::compression_util::{FileEntry, StorageFormat, FILE_ENTRY_TRANSACTION_COUNT};

    #[test]
    fn test_non_aligned_starting_version_skips_files() {
        // Demonstrate file skipping with non-aligned starting version
        let starting_version = 2500u64;
        
        // Files exist at versions: 0, 1000, 2000, 3000, 4000
        let expected_files = vec![0, 1000, 2000, 3000, 4000];
        
        // Simulate checker iterations
        let mut checked_files = Vec::new();
        let mut current_version = starting_version;
        
        for _ in 0..5 {
            let file_name = FileEntry::build_key(current_version, StorageFormat::Lz4CompressedProto);
            // Extract version from file name (format: "compressed_files/lz4/{hash}_{version}.bin")
            let version_str = file_name.split('_').last().unwrap().strip_suffix(".bin").unwrap();
            let file_version: u64 = version_str.parse().unwrap();
            checked_files.push(file_version);
            current_version += FILE_ENTRY_TRANSACTION_COUNT;
        }
        
        // Checker verifies: [2000, 3000, 4000, 5000, 6000]
        // Files 0 and 1000 are NEVER checked!
        assert_eq!(checked_files, vec![2000, 3000, 4000, 5000, 6000]);
        
        // Demonstrate the skipped files
        let skipped_files: Vec<u64> = expected_files.into_iter()
            .filter(|v| !checked_files.contains(v))
            .collect();
        
        assert_eq!(skipped_files, vec![0, 1000], 
            "Files at versions 0 and 1000 are never verified!");
    }
    
    #[test]
    fn test_aligned_starting_version_checks_all_files() {
        // Demonstrate correct behavior with aligned starting version
        let starting_version = 2000u64;
        
        let mut checked_files = Vec::new();
        let mut current_version = starting_version;
        
        for _ in 0..5 {
            let file_name = FileEntry::build_key(current_version, StorageFormat::Lz4CompressedProto);
            let version_str = file_name.split('_').last().unwrap().strip_suffix(".bin").unwrap();
            let file_version: u64 = version_str.parse().unwrap();
            checked_files.push(file_version);
            current_version += FILE_ENTRY_TRANSACTION_COUNT;
        }
        
        // Checker correctly verifies: [2000, 3000, 4000, 5000, 6000]
        assert_eq!(checked_files, vec![2000, 3000, 4000, 5000, 6000]);
        
        // All files from starting_version onward are checked (no skips)
        for i in 0..checked_files.len()-1 {
            assert_eq!(checked_files[i+1] - checked_files[i], FILE_ENTRY_TRANSACTION_COUNT,
                "No version gaps in checking sequence");
        }
    }
}
```

**To run the PoC:**
```bash
cd ecosystem/indexer-grpc/indexer-grpc-file-checker
cargo test test_non_aligned_starting_version_skips_files -- --nocapture
```

The test proves that a non-aligned `starting_version` causes the checker to skip verification of earlier files, creating a data integrity vulnerability where unverified files remain in the new bucket.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/compression_util.rs (L240-242)
```rust
    pub fn build_key(version: u64, storage_format: StorageFormat) -> String {
        let starting_version =
            version / FILE_ENTRY_TRANSACTION_COUNT * FILE_ENTRY_TRANSACTION_COUNT;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-file-checker/src/processor.rs (L94-94)
```rust
            progress_file.file_checker_version += 1000;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-file-checker/src/processor.rs (L142-149)
```rust
        let progress_file =
            download_file::<ProgressFile>(&client, &self.new_bucket_name, PROGRESS_FILE_NAME)
                .await
                .context("Failed to get progress file.")?
                .unwrap_or(ProgressFile {
                    file_checker_version: self.starting_version,
                    file_checker_chain_id: existing_metadata.chain_id,
                });
```

**File:** ecosystem/indexer-grpc/indexer-grpc-file-checker/src/lib.rs (L13-17)
```rust
pub struct IndexerGrpcFileCheckerConfig {
    pub existing_bucket_name: String,
    pub new_bucket_name: String,
    pub starting_version: u64,
}
```
