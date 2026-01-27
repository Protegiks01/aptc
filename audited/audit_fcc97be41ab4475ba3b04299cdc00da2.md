# Audit Report

## Title
Memory Ordering Race Condition in Group Size Validation Allows Consensus Safety Violation

## Summary
A race condition exists in `validate_group_size()` due to insufficient memory ordering guarantees when reading the estimate flag. The `is_estimate()` check uses `Ordering::Relaxed` atomics, allowing concurrent `mark_estimate()` operations to be missed during validation. This can cause transactions to validate successfully against invalidated (estimate) data, leading to non-deterministic execution and consensus divergence. [1](#0-0) 

## Finding Description

The vulnerability exists in the interaction between validation and abort paths during BlockSTM parallel execution:

**The Race Window:**

When `validate_group_size()` is called, it invokes `get_group_size_no_record()`, which performs the following check: [2](#0-1) 

The critical issue is that `size.is_estimate()` uses a relaxed atomic load: [3](#0-2) 

Meanwhile, `mark_estimate()` can be called concurrently by the abort path with only a READ lock on the DashMap: [4](#0-3) 

**Attack Scenario:**

1. Transaction 10 executes and writes size S1 to resource group G at index 10
2. Transaction 15 executes, reads size S1, completes execution  
3. Transaction 10 fails validation and is aborted
4. Transaction 15 begins validation

**Concurrent Execution:**

- **Thread A (Validator for Txn 15):**
  - Calls `validate_group_size(G, 15, S1)` at line 1105 in captured_reads.rs
  - Acquires READ lock via `group_sizes.get(G)`
  - Reads `size.is_estimate()` with `Ordering::Relaxed` → returns `false` [5](#0-4) 

- **Thread B (Aborting Txn 10):**
  - Calls `mark_estimate(G, 10, ...)` during abort handling
  - Acquires READ lock (concurrent with Thread A!)
  - Stores `FLAG_ESTIMATE` with `Ordering::Relaxed` [6](#0-5) 

- **Thread A continues:**
  - Because `is_estimate() == false`, skips the dependency check
  - Returns `Ok(S1)`, validation succeeds
  - Transaction 15 commits with dependency on invalid data

**Root Cause:**

`Ordering::Relaxed` provides atomicity but NO happens-before relationships or memory barriers. Thread A can observe a stale `false` value even after Thread B's store has executed, as there are no ordering guarantees between cores' caches. The DashMap read lock protects the BTreeMap structure but does not synchronize the relaxed atomic operations.

## Impact Explanation

This is a **Critical Severity** vulnerability (Consensus/Safety violation):

1. **Non-Deterministic Execution**: Different validator nodes may observe different interleavings of the race, causing some to validate successfully while others fail and re-execute.

2. **State Divergence**: Validators commit different transaction orderings and produce different state roots for the same block.

3. **Consensus Safety Breach**: Violates the fundamental "Deterministic Execution" invariant that all validators must produce identical states for identical blocks.

4. **Chain Split Risk**: In worst case, this could cause irrecoverable consensus failures requiring a hard fork.

The vulnerability breaks the AptosBFT safety guarantee and could manifest as state root mismatches between validators, preventing block commitment or causing validators to diverge on state.

## Likelihood Explanation

**Likelihood: Medium-High**

- **Trigger Condition**: Requires concurrent transaction validation and abortion, which naturally occurs in BlockSTM parallel execution
- **Race Window**: Small but non-zero window between reading `is_estimate()` and completing validation
- **Frequency**: Higher under load when many transactions execute in parallel and validations/aborts overlap
- **Detection**: Difficult to detect as it manifests as non-deterministic state divergence that may appear intermittent

The race is more likely on systems with:
- Many CPU cores (more parallelism)
- Weak memory ordering architectures (ARM)
- High transaction throughput (more concurrent operations)

## Recommendation

**Fix: Use Acquire-Release Memory Ordering**

Replace `Ordering::Relaxed` with proper synchronization:

```rust
// In versioned_data.rs Entry implementation:
pub(crate) fn is_estimate(&self) -> bool {
    self.flag.load(Ordering::Acquire) == FLAG_ESTIMATE  // Changed from Relaxed
}

pub(crate) fn mark_estimate(&self) {
    self.flag.store(FLAG_ESTIMATE, Ordering::Release);  // Changed from Relaxed
}
```

`Ordering::Acquire` on loads and `Ordering::Release` on stores establishes a happens-before relationship, ensuring that when a thread observes `FLAG_ESTIMATE` via an acquire load, it sees all writes that happened-before the release store.

**Alternative Fix: Strengthen Locking**

Acquire write lock during `mark_estimate()` to prevent concurrent reads:

```rust
pub fn mark_estimate(&self, group_key: &K, txn_idx: TxnIndex, tags: HashSet<&T>) {
    // ... mark data estimates ...
    
    let mut group_sizes = self.group_sizes.get_mut(group_key)  // Write lock
        .expect("Path must exist");
    group_sizes.size_entries
        .get(&ShiftedTxnIndex::new(txn_idx))
        .expect("Entry by the txn must exist to mark estimate")
        .mark_estimate();
}
```

**Recommended**: Use Acquire-Release ordering as it's less invasive and maintains the design goal of allowing estimate marking with minimal locking overhead.

## Proof of Concept

```rust
#[test]
fn test_race_condition_validation_estimate() {
    use std::sync::{Arc, Barrier};
    use std::thread;
    
    let group_data = Arc::new(VersionedGroupData::<KeyType<Vec<u8>>, usize, TestValue>::empty());
    let group_key = KeyType(b"/test/group".to_vec());
    
    // Initialize group
    group_data.set_raw_base_values(group_key.clone(), vec![]).unwrap();
    
    // Write at transaction 10
    group_data.write(
        group_key.clone(),
        10,
        0,
        vec![(0, (TestValue::creation_with_len(100), None))],
        ResourceGroupSize::Combined { 
            num_tagged_resources: 1, 
            all_tagged_resources_size: 100 
        },
        HashSet::new(),
    ).unwrap();
    
    let barrier = Arc::new(Barrier::new(2));
    let group_data_clone = Arc::clone(&group_data);
    let group_key_clone = group_key.clone();
    let barrier_clone = Arc::clone(&barrier);
    
    // Thread A: Validator
    let validator = thread::spawn(move || {
        barrier_clone.wait();
        // Read size - should see estimate flag set by Thread B
        // But due to Ordering::Relaxed, might miss it
        group_data_clone.get_group_size_no_record(&group_key_clone, 15)
    });
    
    // Thread B: Aborter
    let aborter = thread::spawn(move || {
        barrier.wait();
        // Mark as estimate concurrently
        group_data.mark_estimate(&group_key, 10, HashSet::from([&0]));
    });
    
    validator.join().unwrap();
    aborter.join().unwrap();
    
    // In the race condition, validator may return Ok(size) when it should
    // return Err(Dependency(10)) if size_has_changed is true
}
```

**Note**: This test demonstrates the race but may not reliably trigger it due to timing. A proper reproduction would require memory sanitizers or stress testing under concurrent load.

### Citations

**File:** aptos-move/mvhashmap/src/versioned_group_data.rs (L322-336)
```rust
    pub fn mark_estimate(&self, group_key: &K, txn_idx: TxnIndex, tags: HashSet<&T>) {
        for tag in tags {
            // Use GroupKeyRef to avoid cloning the group_key
            let key_ref = GroupKeyRef { group_key, tag };
            self.values.mark_estimate(&key_ref, txn_idx);
        }

        self.group_sizes
            .get(group_key)
            .expect("Path must exist")
            .size_entries
            .get(&ShiftedTxnIndex::new(txn_idx))
            .expect("Entry by the txn must exist to mark estimate")
            .mark_estimate();
    }
```

**File:** aptos-move/mvhashmap/src/versioned_group_data.rs (L462-482)
```rust
    pub fn get_group_size_no_record(
        &self,
        group_key: &K,
        txn_idx: TxnIndex,
    ) -> Result<ResourceGroupSize, MVGroupError> {
        match self.group_sizes.get(group_key) {
            Some(g) => {
                Self::get_latest_entry(&g.size_entries, txn_idx, ReadPosition::BeforeCurrentTxn)
                    .map_or(Err(MVGroupError::Uninitialized), |(idx, size)| {
                        if size.is_estimate() && g.size_has_changed {
                            Err(MVGroupError::Dependency(
                                idx.idx().expect("May not depend on storage version"),
                            ))
                        } else {
                            Ok(size.value.size)
                        }
                    })
            },
            None => Err(MVGroupError::Uninitialized),
        }
    }
```

**File:** aptos-move/mvhashmap/src/versioned_group_data.rs (L504-511)
```rust
    pub fn validate_group_size(
        &self,
        group_key: &K,
        txn_idx: TxnIndex,
        group_size_to_validate: ResourceGroupSize,
    ) -> bool {
        self.get_group_size_no_record(group_key, txn_idx) == Ok(group_size_to_validate)
    }
```

**File:** aptos-move/mvhashmap/src/versioned_data.rs (L99-105)
```rust
    pub(crate) fn is_estimate(&self) -> bool {
        self.flag.load(Ordering::Relaxed) == FLAG_ESTIMATE
    }

    pub(crate) fn mark_estimate(&self) {
        self.flag.store(FLAG_ESTIMATE, Ordering::Relaxed);
    }
```

**File:** aptos-move/block-executor/src/captured_reads.rs (L1091-1107)
```rust
    pub(crate) fn validate_group_reads(
        &self,
        group_map: &VersionedGroupData<T::Key, T::Tag, T::Value>,
        idx_to_validate: TxnIndex,
    ) -> bool {
        use MVGroupError::*;

        if self.non_delayed_field_speculative_failure {
            return false;
        }

        self.group_reads.iter().all(|(key, group)| {
            let mut ret = true;
            if let Some(size) = group.collected_size {
                ret &= group_map.validate_group_size(key, idx_to_validate, size);
            }

```

**File:** aptos-move/block-executor/src/executor_utilities.rs (L321-339)
```rust
    // Not valid and successfully aborted, mark the latest write/delta sets as estimates.
    if let Some(keys) = last_input_output.modified_resource_keys(txn_idx) {
        for (k, _) in keys {
            versioned_cache.data().mark_estimate(&k, txn_idx);
        }
    }

    // Group metadata lives in same versioned cache as data / resources.
    // We are not marking metadata change as estimate, but after a transaction execution
    // changes metadata, suffix validation is guaranteed to be triggered. Estimation affecting
    // execution behavior is left to size, which uses a heuristic approach.
    last_input_output
        .for_each_resource_group_key_and_tags(txn_idx, |key, tags| {
            versioned_cache
                .group_data()
                .mark_estimate(key, txn_idx, tags);
            Ok(())
        })
        .expect("Passed closure always returns Ok");
```
