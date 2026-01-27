# Audit Report

## Title
Database Truncation Leads to Consensus Safety Violation Through Forced SafetyRules Reset

## Summary
The database truncation tool (`db_debugger truncate`) can create an irrecoverable state mismatch between AptosDB and SafetyRules secure storage, forcing validator operators to reset SafetyRules state to restore operation. This reset eliminates the `last_voted_round` protection, enabling double-voting and violating AptosBFT consensus safety guarantees.

## Finding Description

The truncation tool operates on two independent storage systems with no synchronization:

1. **AptosDB** (ledger database) - stores blockchain data, truncated by the tool
2. **SafetyRules secure storage** - stores consensus safety state (`last_voted_round`, `epoch`, `waypoint`), NOT modified by the tool [1](#0-0) 

The truncate command only updates the database's `OverallCommitProgress`: [2](#0-1) 

SafetyRules stores its state separately in secure storage (e.g., `secure-data.json`), which is never checked or updated during truncation.

**The Attack Path:**

When database is truncated to `target_version` < `waypoint_version`:

1. **SafetyRules initialization fails** - the waypoint references a database version that no longer exists: [3](#0-2) 

2. The call to `retrieve_epoch_change_proof(waypoint_version)` fails because: [4](#0-3) 

The `get_epoch(known_version)` lookup fails for truncated versions.

3. **Operator forced to reset SafetyRules** - with initialization failing, the only practical recovery option is deleting the secure storage file.

4. **Consensus safety violation** - After reset, `last_voted_round` returns to 0, bypassing the first voting rule: [5](#0-4) 

The validator can now vote on rounds it previously voted on, enabling double-voting on the same round with different blocks. [6](#0-5) 

The `verify_and_update_last_vote_round` check that prevents double-voting is bypassed because `last_voted_round` was reset to 0.

## Impact Explanation

**Critical Severity** - This breaks Invariant #2 (Consensus Safety: AptosBFT must prevent double-spending and chain splits).

Double-voting allows:
- Two conflicting blocks at the same height to receive quorum certificates
- Potential chain split requiring hard fork to resolve
- Violation of BFT safety guarantees (safety holds only if <1/3 validators are Byzantine)

Even a single compromised validator can trigger this through legitimate database maintenance, effectively becoming Byzantine without detection.

## Likelihood Explanation

**High Likelihood** - This occurs during legitimate operational scenarios:
- Database corruption requiring rollback
- Restoring from backup checkpoint
- Testing/debugging database states
- Disaster recovery procedures

Operators commonly use the truncate tool without understanding the SafetyRules implications. The tool provides NO warnings about:
- SafetyRules state mismatch
- Waypoint version validation
- Consensus safety risks [7](#0-6) 

The tool only creates an optional backup but never validates against consensus state.

## Recommendation

**Immediate Fix:**
1. Add waypoint version validation before truncation:

```rust
pub fn run(self) -> Result<()> {
    // NEW: Check SafetyRules state
    if let Ok(secure_storage_path) = std::env::var("SECURE_STORAGE_PATH") {
        if let Ok(waypoint) = read_waypoint_from_secure_storage(&secure_storage_path) {
            ensure!(
                self.target_version >= waypoint.version(),
                "Cannot truncate to version {} - below SafetyRules waypoint version {}. \
                This would break consensus safety. Reset SafetyRules ONLY if you understand \
                the double-voting risks.",
                self.target_version,
                waypoint.version()
            );
        }
    }
    
    // Existing truncation logic...
}
```

2. Add explicit warning message about SafetyRules reset dangers
3. Require explicit `--force-unsafe-truncation` flag for truncation below waypoint
4. Document the SafetyRules reset procedure and its security implications

**Long-term Fix:**
Implement coordinated truncation that atomically resets both AptosDB and SafetyRules state together, or prohibit truncation below the waypoint entirely.

## Proof of Concept

**Reproduction Steps:**

1. **Setup validator with committed state:**
```bash
# Start validator, let it vote on rounds 1-100
# SafetyRules now has: last_voted_round=100, epoch=1, waypoint=(version=1000, hash)
# Database contains versions 0-1000
```

2. **Truncate database below waypoint:**
```bash
aptos-debugger aptos-db debug truncate \
    --db-dir /opt/aptos/data/db \
    --target-version 500 \
    --opt-out-backup-checkpoint
# Database now contains only versions 0-500
# SafetyRules STILL has: last_voted_round=100, waypoint=(version=1000, hash)
```

3. **Observe initialization failure:**
```bash
# Restart validator
# SafetyRules tries: retrieve_epoch_change_proof(1000)
# Database lookup FAILS - version 1000 doesn't exist
# Node cannot start consensus
```

4. **Operator forces reset:**
```bash
# Delete SafetyRules state
rm /opt/aptos/data/secure-data.json
# Restart validator
# SafetyRules now has: last_voted_round=0, epoch=1, waypoint=(genesis)
```

5. **Double-voting enabled:**
```rust
// Validator can now vote on round 50 (previously voted in step 1)
// SafetyRules check: round 50 > last_voted_round (0) ✓ PASSES
// Consensus safety VIOLATED - can vote on same round twice with different blocks
```

**Notes**

This vulnerability requires validator operator access to trigger, placing it in an operational security category rather than a direct network exploit. However, the consensus safety impact affects all network participants. The lack of safeguards in the truncate tool makes this a critical design flaw that can inadvertently compromise consensus safety during routine database maintenance operations.

### Citations

**File:** storage/aptosdb/src/db_debugger/truncate/mod.rs (L48-65)
```rust
    pub fn run(self) -> Result<()> {
        if !self.opt_out_backup_checkpoint {
            let backup_checkpoint_dir = self.backup_checkpoint_dir.unwrap();
            ensure!(
                !backup_checkpoint_dir.exists(),
                "Backup dir already exists."
            );
            println!("Creating backup at: {:?}", &backup_checkpoint_dir);
            fs::create_dir_all(&backup_checkpoint_dir)?;
            AptosDB::create_checkpoint(
                &self.db_dir,
                backup_checkpoint_dir,
                self.sharding_config.enable_storage_sharding,
            )?;
            println!("Done!");
        } else {
            println!("Opted out backup creation!.");
        }
```

**File:** storage/aptosdb/src/db_debugger/truncate/mod.rs (L130-135)
```rust
        let mut batch = SchemaBatch::new();
        batch.put::<DbMetadataSchema>(
            &DbMetadataKey::OverallCommitProgress,
            &DbMetadataValue::Version(target_version),
        )?;
        ledger_db.metadata_db().write_schemas(batch)?;
```

**File:** consensus/safety-rules/src/persistent_safety_storage.rs (L24-28)
```rust
pub struct PersistentSafetyStorage {
    enable_cached_safety_data: bool,
    cached_safety_data: Option<SafetyData>,
    internal_store: Storage,
}
```

**File:** consensus/src/metrics_safety_rules.rs (L44-52)
```rust
            let proofs = self
                .storage
                .retrieve_epoch_change_proof(waypoint_version)
                .map_err(|e| {
                    Error::InternalError(format!(
                        "Unable to retrieve Waypoint state from storage, encountered Error:{}",
                        e
                    ))
                })?;
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L604-610)
```rust
            ensure!(
                known_version <= ledger_info.version(),
                "Client known_version {} larger than ledger version {}.",
                known_version,
                ledger_info.version(),
            );
            let known_epoch = self.ledger_db.metadata_db().get_epoch(known_version)?;
```

**File:** consensus/safety-rules/src/safety_rules.rs (L213-225)
```rust
    pub(crate) fn verify_and_update_last_vote_round(
        &self,
        round: Round,
        safety_data: &mut SafetyData,
    ) -> Result<(), Error> {
        if round <= safety_data.last_voted_round {
            return Err(Error::IncorrectLastVotedRound(
                round,
                safety_data.last_voted_round,
            ));
        }

        safety_data.last_voted_round = round;
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L77-80)
```rust
        self.verify_and_update_last_vote_round(
            proposed_block.block_data().round(),
            &mut safety_data,
        )?;
```
