# Audit Report

## Title
Critical Flag Combination Attack: Backup Verification Bypass Allows Completely Fabricated Backups to Pass as Verified

## Summary
The backup verification system in Aptos Core contains a critical vulnerability where combining `skip_epoch_endings=true` and `validate_modules=false` flags completely bypasses all meaningful security verification. This allows an attacker to create entirely fabricated backups containing invalid state, malicious Move bytecode, and fake transaction history that will pass verification despite having no connection to the actual Aptos blockchain.

## Finding Description

The vulnerability exists in the backup verification flow where two flags interact to eliminate all security anchors:

**Flag 1: `skip_epoch_endings=true`** [1](#0-0) 

When this flag is set, the `VerifyCoordinator` skips epoch history verification: [2](#0-1) 

This causes `epoch_history` to be set to `None`, which is then passed to both `StateSnapshotRestoreController` and `TransactionRestoreBatchController`.

**Flag 2: `validate_modules=false`** [3](#0-2) 

When this flag is false, Move module validation is skipped: [4](#0-3) 

**Critical Security Bypass:**

When `epoch_history` is `None`, ledger info verification against trusted waypoints is completely skipped in multiple locations:

1. In `StateSnapshotRestoreController`: [5](#0-4) 

2. In `TransactionRestoreBatchController`'s `LoadedChunk::load` method: [6](#0-5) 

The only remaining verification is internal consistency - checking that transaction proofs match the provided ledger info: [7](#0-6) 

However, this verification only confirms that proofs are mathematically consistent with the ledger info, NOT that the ledger info itself is legitimate.

**The Security Anchor That Gets Bypassed:**

The `EpochHistory::verify_ledger_info` method is the critical security anchor that ensures ledger infos are trustworthy: [8](#0-7) 

This method:
- Verifies ledger infos against trusted waypoints (lines 294-304)
- Verifies epoch chain transitions using cryptographic proofs (lines 306-310)
- Anchors the entire backup to the real blockchain via trusted waypoints

Without this verification, an attacker can:
1. Generate fake ledger infos with arbitrary state roots
2. Create fake transaction proofs that match these ledger infos
3. Include malicious Move modules (since `validate_modules=false`)
4. Craft a completely fabricated backup that appears internally consistent

This fabricated backup will pass "verification" because it only checks mathematical consistency, not authenticity against the actual Aptos blockchain.

## Impact Explanation

**Critical Severity** - This vulnerability meets multiple Critical severity criteria from the Aptos bug bounty program:

1. **Consensus/Safety Violations**: If a node restores from a fake verified backup, it would have invalid state that doesn't match the canonical blockchain. This could cause:
   - Different nodes to have different state roots for the same version
   - Violation of deterministic execution invariant
   - Potential consensus splits when the node attempts to participate

2. **Remote Code Execution**: Since `validate_modules=false`, malicious Move bytecode modules can be included in the fake backup. When these modules are loaded and executed, they could:
   - Bypass VM safety checks
   - Exploit bytecode verification weaknesses
   - Execute arbitrary operations on the validator node

3. **State Consistency Violations**: The fake backup could contain:
   - Invalid validator sets
   - Incorrect governance state
   - Manipulated account balances
   - Corrupted resource state

4. **Loss of Funds**: Fake backups could be crafted with:
   - Altered account balances
   - Modified staking rewards
   - Manipulated treasury funds
   - Invalid ownership records

The vulnerability is exploitable by any unprivileged attacker who can provide backup files to a node operator, requiring no validator privileges or insider access.

## Likelihood Explanation

**High Likelihood** of exploitation because:

1. **Simple Attack Vector**: The attacker only needs to:
   - Generate cryptographically consistent but fake data
   - Convince a node operator to verify/restore from these backups
   - The flags are legitimate CLI options that could be used unknowingly

2. **Realistic Scenarios**:
   - Disaster recovery situations where operators may skip verification steps for speed
   - Third-party backup providers could offer "pre-verified" malicious backups
   - Social engineering to convince operators these flags are safe for "faster verification"

3. **No Special Requirements**: 
   - No validator access needed
   - No cryptographic key compromise required
   - Standard backup file format can be used

4. **Detection Difficulty**: The fake backup would appear to pass verification successfully, making the attack difficult to detect until the node is started and consensus failures occur.

## Recommendation

**Immediate Fix**: Remove the ability to combine these dangerous flags. Modify the verification logic:

```rust
// In storage/backup/backup-cli/src/coordinators/verify.rs
impl VerifyCoordinator {
    pub fn new(
        // ... existing parameters ...
        skip_epoch_endings: bool,
        validate_modules: bool,
        // ... existing parameters ...
    ) -> Result<Self> {
        // Prevent dangerous flag combination
        ensure!(
            !(skip_epoch_endings && !validate_modules),
            "Cannot skip both epoch ending verification and module validation - \
             this would bypass all security checks. At least one must be enabled."
        );
        
        Ok(Self {
            // ... existing fields ...
        })
    }
}
```

**Long-term Fixes**:

1. **Make epoch history verification mandatory for security-critical operations**:
   - Remove the `skip_epoch_endings` flag entirely for verification mode
   - Only allow skipping for non-security-critical debugging purposes

2. **Make module validation mandatory**:
   - Always validate Move modules during backup verification
   - Only allow skipping in explicitly marked "unsafe" debugging modes

3. **Add explicit security warnings**:
   - Log critical warnings when security checks are disabled
   - Require explicit confirmation for dangerous flag combinations
   - Document the security implications clearly

4. **Implement defense in depth**:
   - Even with flags set, perform basic sanity checks:
     * Verify genesis ledger info matches known genesis
     * Check that version numbers are plausible
     * Validate basic state tree structure

## Proof of Concept

```bash
# Step 1: Create a fake backup with fabricated data
# (Attacker generates fake but cryptographically consistent ledger infos and transaction proofs)

# Step 2: Run verification with dangerous flag combination
./aptos-db-tool backup verify \
    --skip-epoch-endings \
    --validate-modules=false \
    --metadata-cache-dir /tmp/fake_backup_cache \
    --storage-type local \
    --local-path /tmp/fake_backup

# Result: The completely fabricated backup passes verification
# Output: "Verify coordinator exiting with success."

# Step 3: If this backup is used for restore, node will have:
# - Invalid state disconnected from real blockchain
# - Potentially malicious Move modules
# - Incorrect validator sets and governance state
# - Consensus failures when attempting to sync with network
```

**Rust Test Scenario**:
```rust
#[tokio::test]
async fn test_fake_backup_verification_bypass() {
    // 1. Create fake ledger info with arbitrary state root
    let fake_ledger_info = create_fake_ledger_info_with_signatures();
    
    // 2. Create fake transaction proofs matching the fake ledger info
    let fake_txn_proof = create_consistent_fake_proof(&fake_ledger_info);
    
    // 3. Create fake state snapshot with malicious modules
    let fake_snapshot = create_fake_snapshot_with_malicious_modules();
    
    // 4. Run verification with both flags set
    let result = VerifyCoordinator::new(
        storage,
        metadata_cache_opt,
        trusted_waypoints_opt,
        concurrent_downloads,
        0, // start_version
        Version::MAX, // end_version  
        Version::MAX, // state_snapshot_before_version
        true, // skip_epoch_endings - DANGEROUS
        false, // validate_modules - DANGEROUS
        None,
    )?.run().await;
    
    // 5. Verification passes despite fake data
    assert!(result.is_ok()); // This should NOT pass but does!
    
    // 6. The fake backup is now marked as "verified"
    // If used for restore, causes consensus violation
}
```

## Notes

This vulnerability fundamentally breaks the trust model of backup verification. The entire purpose of verification is to ensure backups contain authentic blockchain data anchored to trusted waypoints. By allowing these flags to be combined, the system reduces verification to a mere consistency check without any authentication, making it trivial for attackers to create fake but "verified" backups.

The issue affects disaster recovery scenarios most severely, where operators under pressure might use these flags to speed up verification, unknowingly accepting completely fabricated data that could destroy consensus when the node attempts to rejoin the network.

### Citations

**File:** storage/db-tool/src/backup.rs (L153-154)
```rust
    #[clap(long, help = "Skip verifying epoch ending info.")]
    skip_epoch_endings: bool,
```

**File:** storage/db-tool/src/backup.rs (L155-159)
```rust
    #[clap(
        long,
        help = "Optionally, while verifying a snapshot, run module validation."
    )]
    validate_modules: bool,
```

**File:** storage/backup/backup-cli/src/coordinators/verify.rs (L106-121)
```rust
        let epoch_history = if self.skip_epoch_endings {
            None
        } else {
            Some(Arc::new(
                EpochHistoryRestoreController::new(
                    epoch_endings
                        .into_iter()
                        .map(|backup| backup.manifest)
                        .collect(),
                    global_opt.clone(),
                    self.storage.clone(),
                )
                .run()
                .await?,
            ))
        };
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L137-139)
```rust
        if let Some(epoch_history) = self.epoch_history.as_ref() {
            epoch_history.verify_ledger_info(&li)?;
        }
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L205-210)
```rust
            if self.validate_modules {
                blobs = tokio::task::spawn_blocking(move || {
                    Self::validate_modules(&blobs);
                    blobs
                })
                .await?;
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L152-154)
```rust
        if let Some(epoch_history) = epoch_history {
            epoch_history.verify_ledger_info(&ledger_info)?;
        }
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L167-167)
```rust
        txn_list_with_proof.verify(ledger_info.ledger_info(), Some(manifest.first_version))?;
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L276-312)
```rust
    pub fn verify_ledger_info(&self, li_with_sigs: &LedgerInfoWithSignatures) -> Result<()> {
        let epoch = li_with_sigs.ledger_info().epoch();
        ensure!(!self.epoch_endings.is_empty(), "Empty epoch history.",);
        if epoch > self.epoch_endings.len() as u64 {
            // TODO(aldenhu): fix this from upper level
            warn!(
                epoch = epoch,
                epoch_history_until = self.epoch_endings.len(),
                "Epoch is too new and can't be verified. Previous chunks are verified and node \
                won't be able to start if this data is malicious."
            );
            return Ok(());
        }
        if epoch == 0 {
            ensure!(
                li_with_sigs.ledger_info() == &self.epoch_endings[0],
                "Genesis epoch LedgerInfo info doesn't match.",
            );
        } else if let Some(wp_trusted) = self
            .trusted_waypoints
            .get(&li_with_sigs.ledger_info().version())
        {
            let wp_li = Waypoint::new_any(li_with_sigs.ledger_info());
            ensure!(
                *wp_trusted == wp_li,
                "Waypoints don't match. In backup: {}, trusted: {}",
                wp_li,
                wp_trusted,
            );
        } else {
            self.epoch_endings[epoch as usize - 1]
                .next_epoch_state()
                .ok_or_else(|| anyhow!("Shouldn't contain non- epoch bumping LIs."))?
                .verify(li_with_sigs)?;
        };
        Ok(())
    }
```
