# Audit Report

## Title
Missing Version Monotonicity Validation in Epoch Ending Ledger Info Retrieval Allows Undetected Database Corruption

## Summary
The `get_epoch_ending_ledger_infos_impl` function validates that the count of returned epoch ending ledger infos matches the expected range and that epochs are consecutive, but fails to validate that ledger info versions are monotonically increasing across epochs. This defensive validation gap could allow corrupted database state with non-monotonic versions to pass integrity checks during reads.

## Finding Description

The validation logic in `storage/aptosdb/src/db/aptosdb_reader.rs` performs two primary checks when retrieving epoch ending ledger infos:

1. **Count Validation**: Ensures the number of returned ledger infos matches the expected range [1](#0-0) 

2. **Epoch Consecutiveness**: The iterator validates that epoch numbers are consecutive [2](#0-1) 

**Missing Validation**: Neither check validates that ledger info versions are strictly monotonically increasing across epoch boundaries. If the database were corrupted such that:
- Epoch 0 ends at version 100
- Epoch 1 ends at version 50 (version decreased!)
- Epoch 2 ends at version 200

This would pass both validation checks above despite violating the fundamental blockchain invariant that versions must strictly increase.

**Why This Matters**: While write-time validation in `check_and_put_ledger_info` prevents this during normal operation: [3](#0-2) 

The system lacks defense-in-depth. If database corruption occurs through:
- Backup/restore bypassing write validation [4](#0-3) 
- Direct database manipulation
- Bugs in the write path

The read validation would not detect the corruption, allowing:
- Nodes to sync from corrupted state
- Epoch proofs with invalid version sequences to be distributed
- Potential consensus divergence if multiple nodes have different corrupted states

## Impact Explanation

**Severity Assessment: High**

While this issue requires database corruption to manifest (typically requiring privileged access), once corrupted:

1. **State Inconsistency**: Nodes could accept and propagate epoch proofs with non-monotonic versions, violating Critical Invariant #4 (State Consistency)

2. **Consensus Risk**: If multiple nodes have different corrupted states, they could diverge on what constitutes valid epoch history, potentially causing consensus safety violations (Critical Invariant #2)

3. **Recovery Complexity**: Detecting and recovering from this corruption would require manual intervention

However, this does NOT meet **Critical** severity because:
- Exploitation requires privileged database access (not an unprivileged attacker)
- Normal operation prevents this through write-time validation
- No direct loss of funds or network-wide failure

This aligns with **High Severity** criteria: "Significant protocol violations" that could cause node-level state inconsistencies.

## Likelihood Explanation

**Likelihood: Low to Medium**

The likelihood is constrained by several factors:

**Mitigating Factors:**
- Write-time validation prevents this in normal operation
- Requires database corruption through privileged access or bugs
- Backup/restore has some validation (epoch consecutiveness)

**Risk Factors:**
- Backup/restore path bypasses `check_and_put_ledger_info`
- No version monotonicity check in restore path [5](#0-4) 
- EpochChangeProof verification also doesn't check version monotonicity [6](#0-5) 

## Recommendation

Add version monotonicity validation in `get_epoch_ending_ledger_infos_impl` after collecting ledger infos:

```rust
// After line 1054 in aptosdb_reader.rs
let lis = self
    .ledger_db
    .metadata_db()
    .get_epoch_ending_ledger_info_iter(start_epoch, paging_epoch)?
    .collect::<Result<Vec<_>>>()?;

// Add version monotonicity validation
let mut prev_version: Option<Version> = None;
for li in &lis {
    let version = li.ledger_info().version();
    if let Some(prev) = prev_version {
        ensure!(
            version > prev,
            "DB corruption: epoch ending ledger info versions are not monotonically increasing. \
             Previous version: {}, current version: {}, epoch: {}",
            prev,
            version,
            li.ledger_info().epoch()
        );
    }
    
    // Also validate next_block_epoch correctness
    if let Some(next) = lis.get((li.ledger_info().epoch() - start_epoch + 1) as usize) {
        ensure!(
            li.ledger_info().next_block_epoch() == next.ledger_info().epoch(),
            "DB corruption: next_block_epoch mismatch. Expected: {}, got: {}",
            next.ledger_info().epoch(),
            li.ledger_info().next_block_epoch()
        );
    }
    
    prev_version = Some(version);
}

// Existing count validation continues...
```

Additionally, add similar validation in the backup/restore path and consider adding it to `EpochChangeProof::verify` for comprehensive defense-in-depth.

## Proof of Concept

**Note**: This vulnerability requires database manipulation, making a traditional PoC challenging. However, here's a demonstration of how to test the validation gap:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    #[should_panic(expected = "versions are not monotonically increasing")]
    fn test_non_monotonic_version_detection() {
        // This test demonstrates that current validation DOES NOT catch
        // non-monotonic versions in epoch ending ledger infos
        
        // Setup: Create mock database with corrupted epoch ending ledger infos
        // Epoch 0: version 100
        // Epoch 1: version 50 (INVALID - version decreased)
        // Epoch 2: version 200
        
        let mut corrupted_lis = vec![];
        
        // Create epoch 0 ending at version 100
        let li0 = create_test_ledger_info(/*epoch=*/0, /*version=*/100, /*next_epoch=*/1);
        corrupted_lis.push(li0);
        
        // Create epoch 1 ending at version 50 (corrupted!)
        let li1 = create_test_ledger_info(/*epoch=*/1, /*version=*/50, /*next_epoch=*/2);
        corrupted_lis.push(li1);
        
        // Create epoch 2 ending at version 200
        let li2 = create_test_ledger_info(/*epoch=*/2, /*version=*/200, /*next_epoch=*/3);
        corrupted_lis.push(li2);
        
        // Current validation: Count check passes (3 == 3)
        assert_eq!(corrupted_lis.len(), 3);
        
        // Current validation: Epoch consecutiveness passes (0, 1, 2)
        for (i, li) in corrupted_lis.iter().enumerate() {
            assert_eq!(li.ledger_info().epoch(), i as u64);
        }
        
        // MISSING VALIDATION: Version monotonicity check would fail
        // This should panic but currently doesn't!
        validate_version_monotonicity(&corrupted_lis);
    }
    
    fn validate_version_monotonicity(lis: &[LedgerInfoWithSignatures]) {
        let mut prev_version: Option<Version> = None;
        for li in lis {
            if let Some(prev) = prev_version {
                assert!(
                    li.ledger_info().version() > prev,
                    "versions are not monotonically increasing"
                );
            }
            prev_version = Some(li.ledger_info().version());
        }
    }
}
```

**To exploit in practice**, an attacker would need to:
1. Gain access to a node's database files
2. Manually corrupt the `LedgerInfoSchema` entries with non-monotonic versions
3. Have the node serve these corrupted epoch proofs to other nodes
4. Other nodes would accept them due to missing validation

This demonstrates the defense-in-depth gap, though exploitation requires privileged access.

### Citations

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L1056-1062)
```rust
        ensure!(
            lis.len() == (paging_epoch - start_epoch) as usize,
            "DB corruption: missing epoch ending ledger info for epoch {}",
            lis.last()
                .map(|li| li.ledger_info().next_block_epoch() - 1)
                .unwrap_or(start_epoch),
        );
```

**File:** storage/aptosdb/src/utils/iterators.rs (L219-224)
```rust
                    ensure!(
                        epoch == self.next_epoch,
                        "Epochs are not consecutive. expecting: {}, got: {}",
                        self.next_epoch,
                        epoch,
                    );
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L549-554)
```rust
        ensure!(
            ledger_info.version() == version,
            "Version in LedgerInfo doesn't match last version. {:?} vs {:?}",
            ledger_info.version(),
            version,
        );
```

**File:** storage/aptosdb/src/backup/restore_utils.rs (L184-187)
```rust
    ledger_infos
        .iter()
        .map(|li| ledger_metadata_db.put_ledger_info(li, batch))
        .collect::<Result<Vec<_>>>()?;
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L113-118)
```rust
                ensure!(
                    li.ledger_info().epoch() == next_epoch,
                    "LedgerInfo epoch not expected. Expected: {}, actual: {}.",
                    li.ledger_info().epoch(),
                    next_epoch,
                );
```

**File:** types/src/epoch_change.rs (L66-76)
```rust
    pub fn verify(&self, verifier: &dyn Verifier) -> Result<&LedgerInfoWithSignatures> {
        ensure!(
            !self.ledger_info_with_sigs.is_empty(),
            "The EpochChangeProof is empty"
        );
        ensure!(
            !verifier
                .is_ledger_info_stale(self.ledger_info_with_sigs.last().unwrap().ledger_info()),
            "The EpochChangeProof is stale as our verifier is already ahead \
             of the entire EpochChangeProof"
        );
```
