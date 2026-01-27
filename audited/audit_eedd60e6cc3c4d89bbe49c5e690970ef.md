# Audit Report

## Title
Insufficient Entropy in Backup Handle Generation Enables Unauthorized Access to Validator Backups

## Summary
Backup handles are generated using only 16-bit random suffixes, creating only 65,536 possible values per backup name. Since backup names are based on predictable public blockchain data (epoch, version, etc.), attackers can trivially enumerate all possible backup handles to access unauthorized backups, especially when S3 buckets are configured as public-read or when attackers have valid storage credentials.

## Finding Description

The backup system generates handles by appending a 4-digit hexadecimal random suffix to predictable backup names. This occurs in the `create_backup_with_random_suffix` helper method: [1](#0-0) 

The function uses `random::<u16>()` which provides only 16 bits of entropy (0x0000 to 0xFFFF = 65,536 possibilities). Backup names themselves are deterministic and based on public blockchain data:

**State Snapshot Backups:** [2](#0-1) 

**Transaction Backups:** [3](#0-2) 

**Epoch Ending Backups:** [4](#0-3) 

The backup handle is then used directly to construct file paths in cloud storage without any additional authentication or authorization checks: [5](#0-4) 

Furthermore, the S3 bucket configuration allows public-read access when enabled: [6](#0-5) 

**Attack Scenario:**

1. Attacker queries the blockchain to obtain current epoch 100 and version 5,000,000 (public data)
2. Constructs base backup name: `state_epoch_100_ver_5000000`
3. Enumerates all possible handles: `state_epoch_100_ver_5000000.0000` through `state_epoch_100_ver_5000000.ffff`
4. For each handle, attempts to access: `s3://bucket/subdir/state_epoch_100_ver_5000000.XXXX/state.manifest`
5. Successfully retrieves backup metadata and data chunks from any matching backup
6. If write permissions exist, can inject malicious data into backups

This violates the **Access Control** invariant: backup handles should not be enumerable, and unauthorized parties should not be able to predict valid handles to access other validators' backups.

## Impact Explanation

This vulnerability qualifies as **HIGH severity** under the Aptos bug bounty program's "Significant protocol violations" category for the following reasons:

1. **Information Disclosure**: Attackers can access sensitive blockchain state snapshots, transaction histories, and epoch-ending data from other validators' backups
2. **Data Tampering**: With write access, attackers can inject malicious files into backups, potentially compromising restore operations
3. **Cross-Validator Access**: In shared S3 bucket deployments, one validator could access another validator's backup data
4. **Public Exposure Risk**: When `enable_public_backup` is true, anyone on the internet can enumerate and access backup files without any credentials

While this does not directly compromise consensus safety or cause immediate loss of funds, it represents a significant operational security failure that could:
- Expose proprietary validator configurations or sensitive state data
- Enable sophisticated attacks if malicious backups are restored
- Violate privacy expectations for backup data
- Facilitate reconnaissance for more complex attacks

## Likelihood Explanation

This vulnerability has **HIGH likelihood** of exploitation:

1. **Low Complexity**: Only 65,536 attempts needed to enumerate all handles for a given backup name
2. **Public Information**: Epoch and version numbers are publicly available on-chain
3. **No Rate Limiting**: No documented rate limiting on S3 access attempts
4. **Fast Enumeration**: Can enumerate all handles in seconds with parallel requests
5. **Common Deployment**: Public-read S3 buckets may be used for community access to backups

The attack requires minimal resources:
- For public buckets: No credentials needed
- For private buckets: Valid S3 read credentials (insider threat or compromised credentials)
- Computation: Trivial (65,536 iterations)
- Time: Seconds to minutes

## Recommendation

Replace the 16-bit random suffix with a cryptographically secure random identifier:

```rust
async fn create_backup_with_random_suffix(&self, name: &str) -> Result<BackupHandle> {
    // Generate 128-bit cryptographically secure random suffix (32 hex chars)
    let mut rng = rand::thread_rng();
    let random_bytes: [u8; 16] = rng.gen();
    let random_suffix = hex::encode(random_bytes);
    
    self.create_backup(&format!("{}.{}", name, random_suffix).try_into()?)
        .await
}
```

This provides 128 bits of entropy (2^128 ≈ 3.4×10^38 possibilities), making enumeration computationally infeasible.

**Additional Recommendations:**
1. Implement backup handle authentication/authorization at the storage layer
2. Disable public-read access by default (`enable_public_backup = false`)
3. Add monitoring for unusual backup access patterns
4. Consider using signed URLs with expiration for backup file access
5. Implement per-validator namespace isolation in shared storage

## Proof of Concept

```rust
// File: backup_handle_enumeration_poc.rs
use rand::random;
use std::collections::HashSet;

fn main() {
    // Simulate current implementation
    let backup_name = "state_epoch_100_ver_5000000";
    let mut possible_handles = HashSet::new();
    
    // Generate what the system would create
    let actual_suffix = random::<u16>();
    let actual_handle = format!("{}.{:04x}", backup_name, actual_suffix);
    println!("Actual backup handle: {}", actual_handle);
    
    // Attacker enumerates all possibilities
    println!("\nEnumerating all possible handles (showing first 10):");
    for i in 0..=0xFFFFu16 {
        let guessed_handle = format!("{}.{:04x}", backup_name, i);
        possible_handles.insert(guessed_handle.clone());
        
        if i < 10 {
            println!("  - {}", guessed_handle);
        }
        
        // Check if we found the actual handle
        if guessed_handle == actual_handle {
            println!("\n✓ Found actual handle at iteration {}: {}", i, guessed_handle);
        }
    }
    
    println!("\nTotal possible handles: {}", possible_handles.len());
    println!("Enumeration is trivial with only 2^16 = 65,536 possibilities");
    
    // Demonstrate S3 access pattern
    println!("\nExample S3 access URLs to try:");
    for i in 0..5 {
        let handle = format!("{}.{:04x}", backup_name, i);
        println!("  s3://bucket/subdir/{}/state.manifest", handle);
    }
}
```

**Expected Output:**
```
Actual backup handle: state_epoch_100_ver_5000000.a3f7

Enumerating all possible handles (showing first 10):
  - state_epoch_100_ver_5000000.0000
  - state_epoch_100_ver_5000000.0001
  - state_epoch_100_ver_5000000.0002
  ...

✓ Found actual handle at iteration 41975: state_epoch_100_ver_5000000.a3f7

Total possible handles: 65,536
Enumeration is trivial with only 2^16 = 65,536 possibilities
```

## Notes

This vulnerability affects all three backup types (state snapshots, transactions, and epoch endings). The issue is exacerbated when backup storage is configured with public-read access or when multiple validators share the same S3 bucket with different subdirectories. Even with proper IAM controls, this enables insider threats or credential compromise scenarios where attackers can access backups they should not have access to.

### Citations

**File:** storage/backup/backup-cli/src/utils/storage_ext.rs (L39-42)
```rust
    async fn create_backup_with_random_suffix(&self, name: &str) -> Result<BackupHandle> {
        self.create_backup(&format!("{}.{:04x}", name, random::<u16>()).try_into()?)
            .await
    }
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/backup.rs (L363-365)
```rust
    fn backup_name(&self) -> String {
        format!("state_epoch_{}_ver_{}", self.epoch, self.version())
    }
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/backup.rs (L129-131)
```rust
    fn backup_name(&self) -> String {
        format!("transaction_{}-", self.start_version)
    }
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/backup.rs (L126-128)
```rust
    fn backup_name(&self) -> String {
        format!("epoch_ending_{}-", self.start_epoch)
    }
```

**File:** storage/backup/backup-cli/src/storage/command_adapter/sample_configs/s3.sample.yaml (L7-21)
```yaml
  create_backup: |
    # backup handle is the same with input backup name, output to stdout
    echo "$BACKUP_NAME"
  create_for_write: |
    # file handle is the file name under the folder with the name of the backup handle
    FILE_HANDLE="$BACKUP_HANDLE/$FILE_NAME"
    # output file handle to stdout
    echo "$FILE_HANDLE"
    # close stdout
    exec 1>&-
    # route stdin to file handle
    gzip -c | aws s3 cp - "s3://$BUCKET/$SUB_DIR/$FILE_HANDLE"
  open_for_read: |
    # route file handle content to stdout
    aws s3 cp "s3://$BUCKET/$SUB_DIR/$FILE_HANDLE" - | gzip -cd
```

**File:** terraform/fullnode/aws/backup.tf (L9-21)
```terraform
resource "aws_s3_bucket_public_access_block" "backup" {
  bucket                  = aws_s3_bucket.backup.id
  block_public_acls       = !var.enable_public_backup
  block_public_policy     = !var.enable_public_backup
  ignore_public_acls      = !var.enable_public_backup
  restrict_public_buckets = !var.enable_public_backup
}

resource "aws_s3_bucket_acl" "public-backup" {
  count  = var.enable_public_backup ? 1 : 0
  bucket = aws_s3_bucket.backup.id
  acl    = "public-read"
}
```
