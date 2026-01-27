# Audit Report

## Title
Zero-Length Replay Verification Bypass Due to Insufficient Version Range Validation

## Summary
The `ReplayVerifyCoordinator` in the backup verification system fails to reject cases where `start_version` equals `end_version`, allowing zero-length replay operations to complete successfully without performing any actual transaction verification. This validation gap can be automatically triggered by the CI/CD job generator and results in backup integrity checks being silently skipped. [1](#0-0) 

## Finding Description

The version validation logic only checks if `start_version > end_version` but does not reject the equality case (`start_version == end_version`). When this condition occurs in conjunction with a state snapshot at exactly the `end_version`, the replay verification process skips all transaction replay due to the following execution flow:

1. **Validation passes**: The check at line 110-115 only rejects `start_version > end_version`, not `start_version == end_version`

2. **Snapshot selection**: When a state snapshot exists at exactly `start_version` (which equals `end_version`), it is selected and `next_txn_version` is set to `snapshot_version + 1` [2](#0-1) 

3. **Version calculation**: The system sets `next_txn_version = max(next_txn_version, snapshot_version + 1)`, which becomes `end_version + 1` when a snapshot exists at `end_version` [3](#0-2) 

4. **Transaction selection**: Backups are selected from `next_txn_version.saturating_sub(1)` to `end_version`, but the replay controller's `first_to_replay` parameter becomes `end_version + 1` [4](#0-3) 

5. **Zero replay**: In the `save_before_replay_version` method, since `first_to_replay` (end_version + 1) exceeds `target_version` (end_version), all transactions are saved but none are replayed for verification [5](#0-4) 

6. **Silent success**: The function returns `Ok(None)` when no transactions need replay, and the final error check passes because no verification errors occurred (since no verification was performed) [6](#0-5) 

**Automated Trigger**: The `gen-replay-verify-jobs` command used in CI/CD workflows can automatically generate jobs with `start_version == end_version` when:
- `max_versions_per_range` is set to 1, or
- Consecutive state snapshots differ by exactly 1 version [7](#0-6) 

The GitHub Actions workflow executes these generated jobs without additional validation: [8](#0-7) 

## Impact Explanation

This vulnerability affects the **integrity of the backup verification system**, which is critical for disaster recovery scenarios. According to Aptos bug bounty criteria, this falls under **Low Severity** as a "non-critical implementation bug" in tooling infrastructure.

While not directly exploitable by malicious actors, the impact includes:

1. **False verification confidence**: CI/CD pipelines report successful verification for version ranges that were never actually verified
2. **Corrupted backup risk**: If backups contain corrupted data in the skipped version ranges, they could pass verification and be deployed in disaster recovery
3. **Operational blind spots**: Teams may trust verified backups that have gaps in actual verification coverage

The impact is limited because:
- This is backup/restore tooling, not consensus-critical code
- It requires specific conditions (equal versions + snapshot at that version)
- Other version ranges in the same backup set are still properly verified
- It does not directly affect live validator operation or consensus

## Likelihood Explanation

**Likelihood: Medium** - This can occur in normal automated operation:

1. The CI/CD workflow automatically generates replay-verify jobs using `gen-replay-verify-jobs`
2. Job generation can legitimately produce `start_version == end_version` cases based on snapshot distribution
3. Each generated job uses a fresh database, making the snapshot-at-end-version condition common
4. The workflow runs regularly against mainnet/testnet backups

The issue is not exploitable by external attackers but represents a systematic gap in the verification infrastructure that affects operational reliability.

## Recommendation

Add explicit validation to reject zero-length version ranges:

```rust
if self.start_version >= self.end_version {
    return Err(ReplayError::OtherError(format!(
        "start_version {} must be strictly less than end_version {}. Zero-length ranges are not supported.",
        self.start_version, self.end_version
    )));
}
```

Additionally, update the job generator to skip ranges where `first >= last`:

```rust
.filter(|(_, first, last, _)| first < last)
```

## Proof of Concept

**Setup**: Create a backup with a state snapshot at version V, then run replay-verify with `--start-version V --end-version V`:

```bash
# Assuming backup exists with snapshot at version 1000
./aptos-debugger aptos-db replay-verify \
  --metadata-cache-dir ./cache \
  --command-adapter-config config.yaml \
  --start-version 1000 \
  --end-version 1000 \
  --target-db-dir ./db \
  --concurrent-downloads 4 \
  --replay-concurrency-level 4
```

**Expected behavior**: Command should fail with "start_version must be strictly less than end_version"

**Actual behavior**: Command succeeds with exit code 0, logging indicates no transactions were replayed:
- "Transactions saved" appears for version 1000
- No "Transaction replayed" messages
- "ReplayVerify coordinator exiting with success" appears

This demonstrates that verification was skipped entirely while reporting success.

---

## Notes

This is a **quality assurance vulnerability** in backup infrastructure rather than a direct security exploit. The validation gap allows operationally invalid ranges to be processed successfully, creating blind spots in backup verification coverage. While the immediate security impact is limited (Low severity), it undermines the integrity guarantees of the backup verification system, which is critical for disaster recovery scenarios in production blockchain networks.

### Citations

**File:** storage/backup/backup-cli/src/coordinators/replay_verify.rs (L110-115)
```rust
        if self.start_version > self.end_version {
            return Err(ReplayError::OtherError(format!(
                "start_version {} should precede end_version {}.",
                self.start_version, self.end_version
            )));
        }
```

**File:** storage/backup/backup-cli/src/coordinators/replay_verify.rs (L132-142)
```rust
        } else if let Some(snapshot) = metadata_view.select_state_snapshot(self.start_version)? {
            let snapshot_version = snapshot.version;
            info!(
                "Found state snapshot backup at epoch {}, will replay from version {}.",
                snapshot.epoch,
                snapshot_version + 1
            );
            (Some(snapshot), Some(snapshot_version))
        } else {
            (None, None)
        };
```

**File:** storage/backup/backup-cli/src/coordinators/replay_verify.rs (L157-157)
```rust
        next_txn_version = std::cmp::max(next_txn_version, snapshot_version.map_or(0, |v| v + 1));
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

**File:** storage/backup/backup-cli/src/coordinators/replay_verify.rs (L207-211)
```rust
        if self.verify_execution_mode.seen_error() {
            Err(ReplayError::TxnMismatch)
        } else {
            Ok(())
        }
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L453-458)
```rust
        let first_to_replay = max(
            self.replay_from_version
                .map_or(Version::MAX, |(version, _)| version),
            next_expected_version,
        );
        let target_version = self.global_opt.target_version;
```

**File:** storage/db-tool/src/gen_replay_verify_jobs.rs (L96-117)
```rust
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

**File:** .github/workflows/workflow-run-replay-verify.yaml (L248-259)
```yaml
                ./aptos-debugger aptos-db replay-verify \
                  --metadata-cache-dir $MC \
                  --command-adapter-config ${{ inputs.BACKUP_CONFIG_TEMPLATE_PATH }} \
                  --start-version $begin \
                  --end-version $end \
                  \
                  --lazy-quit \
                  --enable-storage-sharding \
                  --target-db-dir $DB \
                  --concurrent-downloads 8 \
                  --replay-concurrency-level 4 \
                  || res=$?
```
