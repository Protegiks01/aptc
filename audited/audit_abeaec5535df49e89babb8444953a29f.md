# Audit Report

## Title
World-Readable Backup Directories Expose Sensitive Blockchain State Data to Local Users

## Summary
The `create_backup()` function in the local filesystem storage backend creates backup directories using `tokio::fs::create_dir_all()` without explicitly setting restrictive permissions. On Unix systems, this results in directories being created with default permissions (typically 0755), making them readable by all local users on the validator machine and exposing sensitive blockchain state data. [1](#0-0) 

## Finding Description

The vulnerability exists in the `LocalFs` storage backend implementation where three separate calls to `create_dir_all()` create directories without setting restrictive permissions:

1. **Primary backup directories** - Created when `create_backup()` is called [1](#0-0) 

2. **Metadata backup directories** - Created in `backup_metadata_file()` [2](#0-1) 

3. **Metadata directories** - Created in `save_metadata_lines()` [3](#0-2) 

The backup-cli stores sensitive blockchain data including:
- **Complete blockchain state** (StateKey/StateValue pairs containing all account resources and balances) [4](#0-3) 

- **Transaction history** with full transaction data [5](#0-4) 

- **Account balances** stored as Move resources (CoinStoreResource)

On Unix systems, `tokio::fs::create_dir_all()` (which wraps `std::fs::create_dir_all()`) creates directories with mode 0o777 modified by the current umask. With the typical umask of 0o022, directories are created with permissions 0o755 (rwxr-xr-x), making them readable and traversable by all local users.

The codebase demonstrates awareness of permission security in other contexts, where sensitive files are explicitly created with mode 0o600 (user-only access): [6](#0-5) 

However, this security practice was not applied to backup directory creation.

## Impact Explanation

This issue constitutes an **information disclosure vulnerability**. According to the Aptos bug bounty severity categories, this falls under **Low Severity** (up to $1,000) as it represents a "Minor information leak" that does not directly cause:
- Loss or theft of funds
- Consensus safety violations
- Network availability issues
- Validator node performance degradation
- State manipulation or corruption

The exposed data includes all blockchain state (account balances, smart contract resources, transaction history), which represents a privacy violation but does not enable direct attacks on consensus, execution integrity, or fund security.

## Likelihood Explanation

**Likelihood: MEDIUM to HIGH**

This vulnerability will manifest on any validator system where:
1. The backup-cli local filesystem storage is used (common for development/testing and some production deployments)
2. The system has multiple user accounts or has been partially compromised
3. The default umask is 0o022 (standard on most Linux distributions)

Attack prerequisites:
- Attacker needs local shell access (any user account) on the validator machine
- No special privileges required beyond basic filesystem read access
- No authentication or authorization checks bypass needed

The vulnerability is deterministic and will occur every time backups are created unless the administrator manually adjusts permissions post-creation.

## Recommendation

Implement explicit permission setting for backup directories using `DirBuilder` with mode 0o700 on Unix systems. This ensures only the owner (validator process user) can access backup data.

**Recommended fix:**

```rust
#[cfg(unix)]
use std::os::unix::fs::DirBuilderExt;
use tokio::fs::DirBuilder;

async fn create_backup(&self, name: &ShellSafeName) -> Result<BackupHandle> {
    let path = self.dir.join(name.as_ref());
    
    #[cfg(unix)]
    {
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        builder.recursive(true);
        builder.create(&path).await.err_notes(&path)?;
    }
    
    #[cfg(not(unix))]
    {
        create_dir_all(&path).await.err_notes(&path)?;
    }
    
    Ok(name.to_string())
}
```

Apply the same pattern to the other two `create_dir_all()` calls at lines 132 and 155.

## Proof of Concept

**Rust test demonstrating the vulnerability:**

```rust
#[cfg(unix)]
#[tokio::test]
async fn test_backup_directory_permissions() {
    use std::os::unix::fs::PermissionsExt;
    use tokio::fs::{create_dir_all, metadata};
    use tempfile::TempDir;
    
    let temp_dir = TempDir::new().unwrap();
    let backup_path = temp_dir.path().join("backup_test");
    
    // Simulate the current vulnerable code
    create_dir_all(&backup_path).await.unwrap();
    
    // Check permissions
    let perms = metadata(&backup_path).await.unwrap().permissions();
    let mode = perms.mode() & 0o777;
    
    // With default umask 0o022, directories are created as 0o755
    // This allows group and other users to read (not secure)
    assert_eq!(mode, 0o755, "Directory should be 0o755 with default umask");
    
    // Demonstrate that any user can list the directory
    println!("Directory permissions: {:o}", mode);
    println!("Group can read: {}", mode & 0o040 != 0);
    println!("Others can read: {}", mode & 0o004 != 0);
}
```

**Manual verification steps:**

```bash
# Run backup with local filesystem storage
./aptos-backup-cli backup --dir /tmp/aptos_backup

# Check directory permissions
ls -la /tmp/aptos_backup
# Expected output: drwxr-xr-x (755) - world-readable!

# Any local user can now read backup data
su - otheruser
cat /tmp/aptos_backup/*/state.manifest
# This exposes blockchain state to unauthorized users
```

## Notes

While this is a valid security issue representing a violation of the principle of least privilege and data confidentiality, it does not meet the **Critical, High, or Medium severity** thresholds defined in the Aptos bug bounty program. The impact is limited to **information disclosure** without direct exploitation paths for fund theft, consensus violations, or availability disruption. According to the strict validation checklist provided, this would be classified as **Low Severity** - a minor information leak rather than a critical blockchain security vulnerability.

### Citations

**File:** storage/backup/backup-cli/src/storage/local_fs/mod.rs (L73-78)
```rust
    async fn create_backup(&self, name: &ShellSafeName) -> Result<BackupHandle> {
        create_dir_all(self.dir.join(name.as_ref()))
            .await
            .err_notes(self.dir.join(name.as_ref()))?;
        Ok(name.to_string())
    }
```

**File:** storage/backup/backup-cli/src/storage/local_fs/mod.rs (L127-133)
```rust
    async fn backup_metadata_file(&self, file_handle: &FileHandleRef) -> Result<()> {
        let dir = self.metadata_backup_dir();

        // Check if the backup directory exists, create it if it doesn't
        if !dir.exists() {
            create_dir_all(&dir).await?;
        }
```

**File:** storage/backup/backup-cli/src/storage/local_fs/mod.rs (L149-155)
```rust
    async fn save_metadata_lines(
        &self,
        name: &ShellSafeName,
        lines: &[TextLine],
    ) -> Result<FileHandle> {
        let dir = self.metadata_dir();
        create_dir_all(&dir).await.err_notes(name)?; // in case not yet created
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/backup.rs (L165-169)
```rust

    fn parse_key(record: &[u8]) -> Result<HashValue> {
        let (key, _): (StateKey, StateValue) = bcs::from_bytes(record)?;
        Ok(key.hash())
    }
```

**File:** storage/backup/backup-cli/src/coordinators/backup.rs (L5-9)
```rust
    backup_types::{
        epoch_ending::backup::{EpochEndingBackupController, EpochEndingBackupOpt},
        state_snapshot::backup::{StateSnapshotBackupController, StateSnapshotBackupOpt},
        transaction::backup::{TransactionBackupController, TransactionBackupOpt},
    },
```

**File:** crates/aptos/src/common/utils.rs (L224-229)
```rust
pub fn write_to_user_only_file(path: &Path, name: &str, bytes: &[u8]) -> CliTypedResult<()> {
    let mut opts = OpenOptions::new();
    #[cfg(unix)]
    opts.mode(0o600);
    write_to_file_with_opts(path, name, bytes, &mut opts)
}
```
