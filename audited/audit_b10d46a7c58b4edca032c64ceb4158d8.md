# Audit Report

## Title
Temporary Directory Resource Leak in Indexer Backup Restore Leading to Permanent Service Failure

## Summary
The `unpack_tar_gz()` function in the indexer-grpc-table-info backup restore module fails to clean up temporary directories when archive unpacking fails, creating a permanent denial-of-service condition that prevents all future restore attempts until manual intervention.

## Finding Description

The vulnerability exists in the `unpack_tar_gz()` function where a temporary directory is created but not cleaned up on failure paths. [1](#0-0) 

The execution flow creates a critical resource leak:

1. Line 102: A temporary directory path is constructed using `target_db_path.with_extension("tmp")`
2. Line 103: The temporary directory is created with `fs::create_dir(&temp_dir_path)?`
3. Line 108: If `archive.unpack(&temp_dir_path)?` fails, the `?` operator causes immediate return
4. The cleanup code at lines 110-111 is never executed
5. The temporary directory remains on disk indefinitely

This creates a **denial-of-service condition** because:
- First failed restore attempt: Creates `.tmp` directory and leaves it behind
- Second restore attempt: Fails at line 103 with "directory already exists" error
- All subsequent attempts fail permanently until manual filesystem cleanup

The function is called during database snapshot restoration: [2](#0-1) 

**Attack Vectors:**
1. **Corrupted Backup Injection**: An attacker with GCS bucket write access uploads a malformed tar.gz file
2. **Transient Failure Exploitation**: Disk space exhaustion or IO errors during unpacking leave the temp directory
3. **Repeated Failures**: Any transient condition that causes unpacking to fail creates permanent service disruption

## Impact Explanation

**Severity: Medium** per Aptos bug bounty criteria - "State inconsistencies requiring intervention"

However, upon strict validation against the audit scope:

**This vulnerability affects indexer infrastructure, NOT core blockchain protocol components.** The indexer-grpc services are ecosystem tools for querying blockchain data and do NOT participate in:
- Consensus (AptosBFT)
- Transaction execution (AptosVM)
- State management (AptosDB)
- On-chain governance
- Validator staking

The impact is limited to:
- Indexer service availability (infrastructure concern)
- Operational disruption requiring manual intervention
- No effect on blockchain consensus safety
- No effect on fund security
- No effect on validator operations

## Likelihood Explanation

Likelihood is MODERATE for indexer deployments:
- Corrupted backups can occur from storage system failures
- Disk space issues are common operational concerns
- No retry mechanism exists to handle transient failures
- Manual intervention is required for recovery

However, this requires either:
- Legitimate operational failures (transient), OR
- Attacker access to GCS bucket (privileged)

## Recommendation

Implement proper cleanup using RAII pattern with the `tempfile` crate (already in use in tests): [3](#0-2) 

**Proposed Fix:**
```rust
pub fn unpack_tar_gz(temp_file_path: &PathBuf, target_db_path: &PathBuf) -> anyhow::Result<()> {
    use tempfile::TempDir;
    
    // Create temp directory that auto-cleans on drop
    let temp_dir = TempDir::new_in(target_db_path.parent().unwrap())?;
    let temp_dir_path = temp_dir.path();

    let file = File::open(temp_file_path)?;
    let gz_decoder = GzDecoder::new(file);
    let mut archive = Archive::new(gz_decoder);
    archive.unpack(temp_dir_path)?;

    fs::remove_dir_all(target_db_path).unwrap_or(());
    fs::rename(temp_dir_path, target_db_path)?;
    
    // Prevent auto-cleanup since we've moved the directory
    temp_dir.into_path();
    Ok(())
}
```

Alternatively, use explicit cleanup with proper error handling:
```rust
pub fn unpack_tar_gz(temp_file_path: &PathBuf, target_db_path: &PathBuf) -> anyhow::Result<()> {
    let temp_dir_path = target_db_path.with_extension("tmp");
    
    // Clean up any existing temp directory first
    let _ = fs::remove_dir_all(&temp_dir_path);
    
    fs::create_dir(&temp_dir_path)?;
    
    let result = (|| -> anyhow::Result<()> {
        let file = File::open(temp_file_path)?;
        let gz_decoder = GzDecoder::new(file);
        let mut archive = Archive::new(gz_decoder);
        archive.unpack(&temp_dir_path)?;
        Ok(())
    })();
    
    // Clean up temp dir on failure
    if result.is_err() {
        let _ = fs::remove_dir_all(&temp_dir_path);
        return result;
    }

    fs::remove_dir_all(target_db_path).unwrap_or(());
    fs::rename(&temp_dir_path, target_db_path)?;
    Ok(())
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod test_temp_dir_leak {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_temp_directory_leak_on_unpack_failure() {
        // Create a temporary directory for testing
        let test_dir = tempdir().unwrap();
        let target_db_path = test_dir.path().join("target_db");
        
        // Create a corrupted tar.gz file
        let corrupted_tar_path = test_dir.path().join("corrupted.tar.gz");
        let mut file = std::fs::File::create(&corrupted_tar_path).unwrap();
        file.write_all(b"This is not a valid tar.gz file").unwrap();
        drop(file);

        // First attempt - will fail and leave temp directory
        let result1 = unpack_tar_gz(&corrupted_tar_path, &target_db_path);
        assert!(result1.is_err(), "Should fail on corrupted tar.gz");

        // Verify temp directory exists after failure
        let temp_dir_path = target_db_path.with_extension("tmp");
        assert!(temp_dir_path.exists(), "Temp directory should exist after failure");

        // Second attempt - will fail at create_dir because temp directory exists
        let result2 = unpack_tar_gz(&corrupted_tar_path, &target_db_path);
        assert!(result2.is_err(), "Should fail because temp directory already exists");
        
        // Verify the error is about directory already existing
        let error_msg = format!("{:?}", result2.unwrap_err());
        assert!(
            error_msg.contains("File exists") || error_msg.contains("already exists"),
            "Error should indicate directory already exists"
        );

        println!("VULNERABILITY CONFIRMED: Temp directory leak causes permanent failure");
    }
}
```

## Notes

**CRITICAL SCOPE LIMITATION:** While this is a legitimate resource leak bug, it does NOT meet the security audit criteria because:

1. **Component Scope**: The indexer-grpc-table-info is ecosystem infrastructure, NOT a core protocol component. It does not participate in consensus, execution, state management, governance, or staking.

2. **No Invariant Violation**: This bug does not break any of the 10 critical blockchain invariants (deterministic execution, consensus safety, Move VM safety, state consistency, etc.)

3. **Limited Security Impact**: This affects indexer service availability (operational concern) but has:
   - No impact on consensus safety or blockchain operation
   - No impact on fund security
   - No impact on validator operations
   - No impact on core protocol security

4. **Attack Surface**: Requires either legitimate operational failures OR attacker access to GCS bucket (privileged access)

**Conclusion**: This is a **valid operational reliability bug** but NOT a security vulnerability in the core Aptos blockchain protocol as defined by the audit scope focusing on "consensus, execution, storage, governance, and staking components."

The bug should be fixed for operational reliability, but it does not constitute a security vulnerability under the strict validation criteria provided.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/backup_restore/fs_ops.rs (L101-113)
```rust
pub fn unpack_tar_gz(temp_file_path: &PathBuf, target_db_path: &PathBuf) -> anyhow::Result<()> {
    let temp_dir_path = target_db_path.with_extension("tmp");
    fs::create_dir(&temp_dir_path)?;

    let file = File::open(temp_file_path)?;
    let gz_decoder = GzDecoder::new(file);
    let mut archive = Archive::new(gz_decoder);
    archive.unpack(&temp_dir_path)?;

    fs::remove_dir_all(target_db_path).unwrap_or(());
    fs::rename(&temp_dir_path, target_db_path)?; // Atomically replace the directory
    Ok(())
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/backup_restore/fs_ops.rs (L125-125)
```rust
    use tempfile::tempdir;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/backup_restore/gcs.rs (L303-305)
```rust
                task::spawn_blocking(move || unpack_tar_gz(&temp_file_path_clone, &db_path))
                    .await?
                    .expect("Failed to unpack gzipped tar file");
```
