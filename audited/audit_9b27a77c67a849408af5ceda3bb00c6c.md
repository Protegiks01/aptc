# Audit Report

## Title
Partial Replay Range Generation Creates Verification Coverage Gaps Allowing Undetected State Corruption

## Summary
The `gen_replay_verify_jobs.rs` implementation contains a critical flaw in its batching logic that creates permanent gaps in transaction verification coverage when snapshot ranges exceed `max_versions_per_range`. When large ranges are truncated into "partial" replays, the remaining transactions are permanently omitted from all verification jobs, allowing state corruption in those version ranges to persist undetected and breaking the fundamental state consistency invariant.

## Finding Description

The vulnerability exists in the job range generation logic that processes state snapshot pairs to create replay-verify jobs. [1](#0-0) 

When the version range between two consecutive snapshots (`end.version - begin.version`) is greater than or equal to `max_versions_per_range`, the code creates a "partial" replay job that only covers the first `max_versions_per_range` transactions starting from `begin.version`. The description explicitly acknowledges that `end.version - begin.version - max_versions_per_range` versions are "omitted" (line 113).

The critical issue is that after creating this partial range, the batching iterator immediately returns and moves to the **next** snapshot pair via `it.next()` on the subsequent iteration (line 94). The omitted transactions in the current range are never revisited or covered by any subsequent job.

**Attack Scenario:**
1. State snapshots exist at versions: [1000, 10000, 15000]
2. `max_versions_per_range` = 3000
3. Latest transaction version = 15000
4. A fake_end is created at version 15000 with potentially mismatched epoch metadata [2](#0-1) 

5. Snapshot pairs processed (reversed): [(fake_end@15000, snapshot@10000), (snapshot@10000, snapshot@1000)]

6. For pair (fake_end@15000, snapshot@10000):
   - Range size: 15000 - 10000 = 5000 versions
   - 5000 ≥ 3000, so partial range created: versions 10000-12999
   - **Gap created: versions 13000-14999 NEVER VERIFIED** (including chain tip!)

7. For pair (snapshot@10000, snapshot@1000):
   - Range size: 10000 - 1000 = 9000 versions  
   - 9000 ≥ 3000, so partial range created: versions 1000-3999
   - **Gap created: versions 4000-9999 NEVER VERIFIED**

8. If state corruption exists at any version in ranges [4000-9999] or [13000-14999], the replay-verify process will complete successfully without detecting it.

The replay-verify coordinator only processes the version ranges provided in the jobs JSON: [3](#0-2) 

Since the gaps are not in any job range, they are never replayed or verified, allowing corrupted state to persist undetected.

## Impact Explanation

**Critical Severity** - This vulnerability breaks the fundamental "State Consistency" invariant (#4): "State transitions must be atomic and verifiable via Merkle proofs."

The impact includes:
- **Undetected State Corruption**: Transaction execution results and state roots in gap ranges could be corrupted without any detection
- **Consensus Safety Risk**: If different validators have different corrupted states in unverified ranges, they may diverge without detection until it's too late
- **Chain Integrity Compromise**: The verification system is supposed to ensure the entire chain state is valid; gaps undermine this guarantee
- **Potential for Permanent Damage**: If corruption in gaps affects critical system state (governance, staking, framework code), it could require a hard fork to fix

This meets the Critical severity criteria for "State inconsistencies requiring intervention" and potentially "Consensus/Safety violations" if the undetected corruption leads to validator divergence.

## Likelihood Explanation

**High Likelihood** when the following conditions exist:
1. State snapshot frequency is low relative to transaction volume (common in production environments to reduce storage costs)
2. Large transaction bursts or load tests create snapshot gaps > `max_versions_per_range`  
3. The code even acknowledges this scenario with the warning "!!! Need more snapshots !!!" (line 99) [4](#0-3) 

The fake_end pattern exacerbates this by artificially creating a snapshot marker at the latest transaction version with potentially stale epoch information, which is more likely to create a large final gap between the last real snapshot and the chain tip. [5](#0-4) 

Any state corruption occurring in gap ranges (hardware failure, software bug, malicious validator action) will go undetected during replay-verify runs.

## Recommendation

Replace the partial range logic with a chunking approach that ensures complete coverage:

```rust
.batching(|it| {
    match it.next() {
        Some((end, mut begin)) => {
            let total_range = end.version - begin.version;
            
            if total_range >= self.max_versions_per_range {
                // Instead of creating one partial range and moving on,
                // create the FIRST chunk and mark that we need continuation
                let first_chunk_end = begin.version + self.max_versions_per_range - 1;
                
                // Store the remaining range for next iteration
                // This requires modifying the iterator to track partial state
                // OR: Return multiple ranges in a Vec for this single pair
                
                // Better approach: Don't use batching for this.
                // Pre-process pairs to split large ranges into chunks
            } else {
                // Existing merge logic for small ranges
                while let Some((_prev_end, prev_begin)) = it.peek() {
                    if end.version - prev_begin.version > self.max_versions_per_range {
                        break;
                    }
                    begin = prev_begin;
                    let _ = it.next();
                }
                Some((
                    false,
                    begin.version,
                    end.version - 1,
                    format!("...")
                ))
            }
        },
        None => None,
    }
})
```

**Better solution**: Pre-process large ranges before the batching step:

```rust
let expanded_job_ranges = metadata_view
    .all_state_snapshots()
    .iter()
    .dedup_by(|a, b| a.epoch == b.epoch)
    .filter(|s| s.epoch >= global_min_epoch && s.version <= global_end_version)
    .chain(once(&fake_end))
    .collect_vec()
    .iter()
    .rev()
    .tuple_windows()
    .take_while(|(_end, begin)| begin.version >= self.start_version.unwrap_or(0))
    .flat_map(|(end, begin)| {
        // Split large ranges into chunks
        let mut chunks = Vec::new();
        let mut current_start = begin.version;
        while current_start < end.version {
            let current_end = std::cmp::min(
                current_start + self.max_versions_per_range - 1,
                end.version - 1
            );
            chunks.push((begin.epoch, end.epoch, current_start, current_end));
            current_start = current_end + 1;
        }
        chunks
    })
    .peekable()
    .batching(/* existing merge logic for combining small adjacent chunks */);
```

This ensures every version from `start_version` to `end_version` is covered by at least one job range.

## Proof of Concept

```rust
// Create mock scenario demonstrating the gap
use aptos_backup_cli::metadata::StateSnapshotBackupMeta;

fn test_gap_creation() {
    let snapshots = vec![
        StateSnapshotBackupMeta {
            epoch: 10,
            version: 1000,
            manifest: "snapshot_1000".to_string(),
        },
        StateSnapshotBackupMeta {
            epoch: 50,
            version: 10000,
            manifest: "snapshot_10000".to_string(),
        },
    ];
    
    let fake_end = StateSnapshotBackupMeta {
        epoch: 50,  // From latest snapshot
        version: 15000,  // From latest transaction
        manifest: "".to_string(),
    };
    
    let max_versions_per_range = 3000;
    
    // Simulate the batching logic
    let pairs = vec![
        (fake_end.clone(), snapshots[1].clone()),  // (15000, 10000)
        (snapshots[1].clone(), snapshots[0].clone()),  // (10000, 1000)
    ];
    
    for (end, begin) in pairs {
        if end.version - begin.version >= max_versions_per_range {
            let partial_end = begin.version + max_versions_per_range - 1;
            let gap_start = partial_end + 1;
            let gap_end = end.version - 1;
            
            println!("Partial range: {} to {}", begin.version, partial_end);
            println!("GAP NOT VERIFIED: {} to {} ({} versions)", 
                     gap_start, gap_end, gap_end - gap_start + 1);
        }
    }
    
    // Output shows:
    // Partial range: 10000 to 12999
    // GAP NOT VERIFIED: 13000 to 14999 (2000 versions)
    // Partial range: 1000 to 3999  
    // GAP NOT VERIFIED: 4000 to 9999 (6000 versions)
    //
    // Total unverified: 8000 versions across 2 gaps
}
```

## Notes

The warning message "!!! Need more snapshots !!!" indicates the developers were aware that large epoch gaps are problematic, but the implementation does not actually solve the problem—it simply warns about it while still creating incomplete verification coverage. This is particularly dangerous because operators may believe verification is complete when it actually has significant gaps.

### Citations

**File:** storage/db-tool/src/gen_replay_verify_jobs.rs (L64-79)
```rust
        let storage_state = metadata_view.get_storage_state()?;
        let global_end_version = storage_state
            .latest_transaction_version
            .expect("No transaction backups.")
            + 1;
        let latest_epoch = storage_state
            .latest_state_snapshot_epoch
            .expect("No state snapshots.");
        let max_epochs = self.max_epochs.min(latest_epoch + 1);
        let global_min_epoch = latest_epoch + 1 - max_epochs;

        let fake_end = StateSnapshotBackupMeta {
            epoch: latest_epoch,
            version: global_end_version,
            manifest: "".to_string(),
        };
```

**File:** storage/db-tool/src/gen_replay_verify_jobs.rs (L93-117)
```rust
            .batching(|it| {
                match it.next() {
                    Some((end, mut begin)) => {
                        if end.version - begin.version >= self.max_versions_per_range {
                            // cut big range short, this hopefully automatically skips load tests
                            let msg = if end.epoch - begin.epoch > 15 {
                                "!!! Need more snapshots !!!"
                            } else {
                                ""
                            };
                            Some((
                                true,
                                begin.version,
                                begin.version + self.max_versions_per_range - 1,
                                format!(
                                    "Partial replay epoch {} - {}, {} txns starting from version {}, another {} versions omitted, until {}. {}",
                                    begin.epoch,
                                    end.epoch - 1,
                                    self.max_versions_per_range,
                                    begin.version,
                                    end.version - begin.version - self.max_versions_per_range,
                                    end.version,
                                    msg
                                )
                            ))
```

**File:** storage/backup/backup-cli/src/coordinators/replay_verify.rs (L159-164)
```rust
        let transactions = metadata_view.select_transaction_backups(
            // transaction info at the snapshot must be restored otherwise the db will be confused
            // about the latest version after snapshot is restored.
            next_txn_version.saturating_sub(1),
            self.end_version,
        )?;
```
