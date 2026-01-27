# Audit Report

## Title
ConsensusDB WAL Non-Durability Enables Double-Voting and Consensus Safety Violations

## Summary
The ConsensusDB uses `write_schemas_relaxed()` which does not sync the RocksDB Write-Ahead Log to disk. If a validator's machine crashes after voting but before the OS flushes the WAL, the vote is permanently lost. On recovery, the validator can vote again in the same round for a different block, violating AptosBFT consensus safety guarantees and potentially causing chain splits.

## Finding Description

The Aptos consensus system stores critical safety-critical state in ConsensusDB, including the validator's last vote. This vote is essential for preventing double-voting, which is a fundamental consensus safety violation.

**The vulnerability chain:**

1. **Non-durable writes in ConsensusDB**: When a validator votes, the vote is persisted via `ConsensusDB::save_vote()` which calls `commit()`: [1](#0-0) 

2. **The commit function uses relaxed writes without sync**: [2](#0-1) 

3. **write_schemas_relaxed explicitly does NOT sync to disk**: [3](#0-2) 

4. **The comment explicitly warns about data loss on machine crashes**:
The documentation states: "If this flag is false, and the machine crashes, some recent writes may be lost. Note that if it is just the process that crashes (i.e., the machine does not reboot), no writes will be lost even if sync==false."

5. **SafetyRules storage also lacks durability**: The SafetyData is persisted via `PersistentSafetyStorage` which can use `OnDiskStorage`. This implementation also fails to sync: [4](#0-3) 

Note that lines 66-68 write to a file and rename it, but never call `sync_all()` or `sync_data()` to ensure durability.

**Attack scenario:**

1. Validator votes at round R for block B1
2. SafetyRules updates `safety_data.last_voted_round = R` and `safety_data.last_vote = Vote(B1)`
3. ConsensusDB saves the vote via `save_vote()`
4. Both writes complete in memory but are not synced to disk
5. Machine crashes (power failure, hardware failure, kernel panic)
6. On recovery:
   - ConsensusDB: `last_vote = None` (lost from WAL)
   - SafetyRules: `safety_data.last_voted_round = 0` and `last_vote = None` (if using OnDiskStorage, lost from file buffer)
7. Recovery logic filters out None votes: [5](#0-4) 

8. Validator thinks it never voted at round R
9. Validator receives new proposal for round R with block B2 (B2 ≠ B1)
10. SafetyRules checks prevent double-voting by verifying `round > last_voted_round`: [6](#0-5) 

11. Since `last_voted_round = 0 < R`, the check passes
12. Validator votes for B2 at round R
13. **Result: Validator has now voted twice in round R for different blocks (B1 and B2)**

This violates the fundamental voting safety rule of AptosBFT and can lead to consensus divergence if enough validators experience simultaneous crashes.

## Impact Explanation

This is a **CRITICAL severity** vulnerability per the Aptos Bug Bounty program because it causes:

1. **Consensus Safety Violation**: The validator can vote twice in the same round for conflicting blocks, directly violating the "no double-voting" invariant that AptosBFT depends on for safety.

2. **Potential Chain Split**: If multiple validators crash and lose their votes, they can collectively vote for conflicting blocks, potentially forming two competing quorum certificates and causing a permanent chain split.

3. **Requires Hardfork to Resolve**: A consensus safety violation with diverged chains would require manual intervention or a hardfork to resolve, as the network cannot automatically recover.

4. **Breaks Fundamental Invariant**: Violates invariant #2: "Consensus Safety: AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine"

The vulnerability affects ALL validators in ALL deployment environments (mainnet, testnet, local) because ConsensusDB always uses `write_schemas_relaxed`.

## Likelihood Explanation

**Likelihood: Medium to High**

**Triggering conditions:**
- Requires machine crash (not just process crash) after voting but before OS page cache flush
- Typical page cache flush happens within 30 seconds by default on Linux
- Window of vulnerability: ~30 seconds per vote

**Realistic scenarios:**
1. **Power failures**: Data centers can experience power loss despite UPS systems
2. **Hardware failures**: Memory errors, disk controller failures can cause kernel panics
3. **Kernel bugs**: OS kernel crashes do occur in production
4. **Coordinated attack**: Attacker with physical or remote access could:
   - Trigger DoS causing kernel panic
   - Cut power to validator nodes
   - Exploit kernel vulnerabilities to force crash

**Amplification factors:**
- High vote frequency in AptosBFT (votes every few seconds)
- If multiple validators crash simultaneously (e.g., regional power outage), the impact multiplies
- Validators often run in cloud environments with shared infrastructure, increasing correlated failure probability

## Recommendation

**Immediate fix:** Change ConsensusDB to use synchronous writes for critical safety data.

**Code fix for `consensus/src/consensusdb/mod.rs`:**

```rust
fn commit(&self, batch: SchemaBatch) -> Result<(), DbError> {
    // Use write_schemas (with sync) instead of write_schemas_relaxed
    // for critical consensus safety data
    self.db.write_schemas(batch)?;
    Ok(())
}
```

**Additional recommendation for `secure/storage/src/on_disk.rs`:**

```rust
fn write(&self, data: &HashMap<String, Value>) -> Result<(), Error> {
    let contents = serde_json::to_vec(data)?;
    let mut file = File::create(self.temp_path.path())?;
    file.write_all(&contents)?;
    file.sync_all()?; // Add sync to ensure durability
    fs::rename(&self.temp_path, &self.file_path)?;
    Ok(())
}
```

**Performance consideration:** The sync operation adds latency (~1-10ms per vote depending on hardware). However, consensus safety is more critical than performance. Alternative optimizations could include:
- Using group commits to batch multiple votes
- Using battery-backed write cache on validators
- Accepting the latency trade-off for safety

## Proof of Concept

```rust
#[test]
fn test_vote_loss_on_crash() {
    use consensus::consensusdb::ConsensusDB;
    use consensus_types::vote::Vote;
    use tempfile::TempDir;
    use std::sync::Arc;
    
    // Setup
    let temp_dir = TempDir::new().unwrap();
    let db = Arc::new(ConsensusDB::new(temp_dir.path()));
    
    // Create a test vote
    let vote = create_test_vote(/* round */ 5, /* block_id */ HashValue::random());
    let vote_bytes = bcs::to_bytes(&vote).unwrap();
    
    // Save vote using ConsensusDB
    db.save_vote(vote_bytes.clone()).unwrap();
    
    // Verify vote is in memory cache
    let retrieved = db.get_data().unwrap();
    assert!(retrieved.0.is_some(), "Vote should be present in memory");
    
    // Simulate machine crash by dropping DB without sync
    // In real scenario, this would be OS page cache not flushed
    drop(db);
    
    // Simulate reboot: open DB again
    let db_after_crash = Arc::new(ConsensusDB::new(temp_dir.path()));
    
    // Check if vote survived
    let recovered = db_after_crash.get_data().unwrap();
    
    // BUG: Vote may be lost depending on timing of OS page cache flush
    // This demonstrates the non-deterministic data loss
    println!("Vote recovered: {:?}", recovered.0.is_some());
    
    // The test would need to force WAL corruption to reliably reproduce,
    // but in production this happens naturally with machine crashes
}

fn create_test_vote(round: u64, block_id: HashValue) -> Vote {
    // Helper to create a valid test vote
    // Implementation details omitted for brevity
    unimplemented!()
}
```

**Notes:**
- The actual PoC would require forcing the OS to not flush page cache, which is difficult to do deterministically in tests
- In production, this manifests as non-deterministic vote loss after power failures or kernel panics
- The vulnerability can be validated by adding instrumentation to track fsync calls and confirming none occur for ConsensusDB writes

### Citations

**File:** consensus/src/consensusdb/mod.rs (L115-119)
```rust
    pub fn save_vote(&self, last_vote: Vec<u8>) -> Result<(), DbError> {
        let mut batch = SchemaBatch::new();
        batch.put::<SingleEntrySchema>(&SingleEntryKey::LastVote, &last_vote)?;
        self.commit(batch)
    }
```

**File:** consensus/src/consensusdb/mod.rs (L156-159)
```rust
    fn commit(&self, batch: SchemaBatch) -> Result<(), DbError> {
        self.db.write_schemas_relaxed(batch)?;
        Ok(())
    }
```

**File:** storage/schemadb/src/lib.rs (L311-318)
```rust
    /// Writes without sync flag in write option.
    /// If this flag is false, and the machine crashes, some recent
    /// writes may be lost.  Note that if it is just the process that
    /// crashes (i.e., the machine does not reboot), no writes will be
    /// lost even if sync==false.
    pub fn write_schemas_relaxed(&self, batch: impl IntoRawBatch) -> DbResult<()> {
        self.write_schemas_inner(batch, &WriteOptions::default())
    }
```

**File:** secure/storage/src/on_disk.rs (L64-70)
```rust
    fn write(&self, data: &HashMap<String, Value>) -> Result<(), Error> {
        let contents = serde_json::to_vec(data)?;
        let mut file = File::create(self.temp_path.path())?;
        file.write_all(&contents)?;
        fs::rename(&self.temp_path, &self.file_path)?;
        Ok(())
    }
```

**File:** consensus/src/persistent_liveness_storage.rs (L405-408)
```rust
            last_vote: match last_vote {
                Some(v) if v.epoch() == epoch => Some(v),
                _ => None,
            },
```

**File:** consensus/safety-rules/src/safety_rules.rs (L213-232)
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
        trace!(
            SafetyLogSchema::new(LogEntry::LastVotedRound, LogEvent::Update)
                .last_voted_round(safety_data.last_voted_round)
        );

        Ok(())
    }
```
