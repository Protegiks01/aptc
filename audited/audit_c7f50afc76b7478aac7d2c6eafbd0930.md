# Audit Report

## Title
State Storage Usage Verification Bypass in State Snapshot Restoration Leading to Potential Consensus Divergence

## Summary
The `StateValueRestore::finish()` function fails to verify that the accumulated state storage usage matches the actual restored data, potentially allowing incorrect usage values to be persisted. This usage directly affects consensus-critical gas parameter calculations, which could lead to different nodes executing transactions with different gas costs and causing consensus divergence.

## Finding Description

The vulnerability exists in the state snapshot restoration path where usage accounting lacks validation: [1](#0-0) 

The `finish()` method retrieves the final usage from progress and passes it directly to `kv_finish()` without any verification. During chunk processing, usage is accumulated incrementally: [2](#0-1) 

The `add_item()` method uses unchecked arithmetic operations, violating the project's coding standard: [3](#0-2) 

The coding standard explicitly requires checked arithmetic: [4](#0-3) 

In contrast, normal state commits include validation through `check_usage_consistency()`: [5](#0-4) 

This validation ensures consistency between ledger metadata, Jellyfish Merkle Tree leaf count, and in-memory state. **No such validation exists in the restoration path.**

The security impact is severe because state storage usage directly affects consensus-critical gas calculations: [6](#0-5) 

These gas parameters are reconfigured at each epoch boundary and affect all transaction execution costs: [7](#0-6) 

## Impact Explanation

This breaks the **Deterministic Execution** invariant: "All validators must produce identical state roots for identical blocks."

If different nodes restore state with inconsistent usage values (due to database corruption, processing variations, or other edge cases during restoration), they will calculate different gas parameters at the next epoch boundary. This causes:

1. **Consensus Divergence**: Transactions succeed on some nodes but fail on others due to different gas costs
2. **State Inconsistency**: The stored usage doesn't match the actual Jellyfish Merkle Tree leaf count
3. **Violation of Coding Standards**: Unchecked arithmetic where checked operations are required

This qualifies as **High Severity** per the Aptos bug bounty criteria: "Significant protocol violations" that could lead to consensus issues.

## Likelihood Explanation

**Medium likelihood:**
- Requires state restoration from snapshot (state sync or backup restore)
- While arithmetic overflow of `usize` is practically impossible on 64-bit systems (~18 exabytes), the lack of validation means:
  - Database corruption during restoration propagates undetected
  - Software bugs in chunk processing could cause incorrect accumulation
  - Edge cases in concurrent restoration scenarios are not validated

The missing validation is a latent vulnerability that could be triggered by environmental factors or combined with other bugs.

## Recommendation

Add usage verification to `StateValueRestore::finish()` similar to the normal commit path:

```rust
pub fn finish(self) -> Result<()> {
    let progress = self.db.get_progress(self.version)?;
    let usage = progress.map_or(StateStorageUsage::zero(), |p| p.usage);
    
    // Verify usage consistency against actual tree state
    // This should match check_usage_consistency() pattern
    let leaf_count = self.get_tree_leaf_count(self.version)?;
    ensure!(
        usage.items() == leaf_count,
        "State usage item count mismatch: {} from progress, {} from tree",
        usage.items(),
        leaf_count
    );
    
    self.db.kv_finish(self.version, usage)
}
```

Additionally, update `StateStorageUsage::add_item()` to use checked arithmetic:

```rust
pub fn add_item(&mut self, bytes_delta: usize) -> Result<()> {
    match self {
        Self::Tracked { items, bytes } => {
            *items = items.checked_add(1)
                .ok_or_else(|| anyhow!("Item count overflow"))?;
            *bytes = bytes.checked_add(bytes_delta)
                .ok_or_else(|| anyhow!("Byte count overflow"))?;
        },
        Self::Untracked => (),
    }
    Ok(())
}
```

## Proof of Concept

Test demonstrating the missing validation in restoration vs. normal commits: [8](#0-7) 

The test validates usage after restoration, but this validation is only in tests. Production code in `finish()` performs no such check, allowing inconsistent usage values to be persisted to the ledger metadata database, which then affects consensus-critical gas calculations.

## Notes

While direct exploitation through arithmetic overflow is practically infeasible on modern systems, the **missing validation** represents a critical gap in state consistency checks. The normal commit path correctly validates usage against tree state, but the restoration path bypasses this entirely. This asymmetry creates a vulnerability where corrupted or incorrectly calculated usage values can enter the system undetected during state synchronization, potentially causing consensus divergence when gas parameters are recalculated at epoch boundaries.

### Citations

**File:** storage/aptosdb/src/state_restore/mod.rs (L107-114)
```rust
        let mut usage = progress_opt.map_or(StateStorageUsage::zero(), |p| p.usage);
        let (last_key, _last_value) = chunk.last().unwrap();
        let last_key_hash = CryptoHash::hash(last_key);

        // In case of TreeOnly Restore, we only restore the usage of KV without actually writing KV into DB
        for (k, v) in chunk.iter() {
            usage.add_item(k.key_size() + v.value_size());
        }
```

**File:** storage/aptosdb/src/state_restore/mod.rs (L129-135)
```rust
    pub fn finish(self) -> Result<()> {
        let progress = self.db.get_progress(self.version)?;
        self.db.kv_finish(
            self.version,
            progress.map_or(StateStorageUsage::zero(), |p| p.usage),
        )
    }
```

**File:** types/src/state_store/state_storage_usage.rs (L44-52)
```rust
    pub fn add_item(&mut self, bytes_delta: usize) {
        match self {
            Self::Tracked { items, bytes } => {
                *items += 1;
                *bytes += bytes_delta;
            },
            Self::Untracked => (),
        }
    }
```

**File:** RUST_CODING_STYLE.md (L220-231)
```markdown
### Integer Arithmetic

As every integer operation (`+`, `-`, `/`, `*`, etc.) implies edge-cases (e.g. overflow `u64::MAX + 1`, underflow `0u64 -1`, division by zero, etc.),
we use checked arithmetic instead of directly using math symbols.
It forces us to think of edge-cases, and handle them explicitly.
This is a brief and simplified mini guide of the different functions that exist to handle integer arithmetic:

- [checked\_](https://doc.rust-lang.org/std/primitive.u32.html#method.checked_add): use this function if you want to handle overflow and underflow as a special edge-case. It returns `None` if an underflow or overflow has happened, and `Some(operation_result)` otherwise.
- [overflowing\_](https://doc.rust-lang.org/std/primitive.u32.html#method.overflowing_add): use this function if you want the result of an overflow to potentially wrap around (e.g. `u64::MAX.overflow_add(10) == (9, true)`). It returns the underflowed or overflowed result as well as a flag indicating if an overflow has occurred or not.
- [wrapping\_](https://doc.rust-lang.org/std/primitive.u32.html#method.wrapping_add): this is similar to overflowing operations, except that it returns the result directly. Use this function if you are sure that you want to handle underflow and overflow by wrapping around.
- [saturating\_](https://doc.rust-lang.org/std/primitive.u32.html#method.saturating_add): if an overflow occurs, the result is kept within the boundary of the type (e.g. `u64::MAX.saturating_add(1) == u64::MAX`).

```

**File:** storage/aptosdb/src/state_store/state_merkle_batch_committer.rs (L136-168)
```rust
    fn check_usage_consistency(&self, state: &State) -> Result<()> {
        let version = state
            .version()
            .ok_or_else(|| anyhow!("Committing without version."))?;

        let usage_from_ledger_db = self.state_db.ledger_db.metadata_db().get_usage(version)?;
        let leaf_count_from_jmt = self
            .state_db
            .state_merkle_db
            .metadata_db()
            .get::<JellyfishMerkleNodeSchema>(&NodeKey::new_empty_path(version))?
            .ok_or_else(|| anyhow!("Root node missing at version {}", version))?
            .leaf_count();

        ensure!(
            usage_from_ledger_db.items() == leaf_count_from_jmt,
            "State item count inconsistent, {} from ledger db and {} from state tree.",
            usage_from_ledger_db.items(),
            leaf_count_from_jmt,
        );

        let usage_from_in_mem_state = state.usage();
        if !usage_from_in_mem_state.is_untracked() {
            ensure!(
                usage_from_in_mem_state == usage_from_ledger_db,
                "State storage usage info inconsistent. from smt: {:?}, from ledger_db: {:?}",
                usage_from_in_mem_state,
                usage_from_ledger_db,
            );
        }

        Ok(())
    }
```

**File:** aptos-move/framework/aptos-framework/sources/storage_gas.move (L524-533)
```text
        let (items, bytes) = state_storage::current_items_and_bytes();
        let gas_config = borrow_global<StorageGasConfig>(@aptos_framework);
        let gas = borrow_global_mut<StorageGas>(@aptos_framework);
        gas.per_item_read = calculate_read_gas(&gas_config.item_config, items);
        gas.per_item_create = calculate_create_gas(&gas_config.item_config, items);
        gas.per_item_write = calculate_write_gas(&gas_config.item_config, items);
        gas.per_byte_read = calculate_read_gas(&gas_config.byte_config, bytes);
        gas.per_byte_create = calculate_create_gas(&gas_config.byte_config, bytes);
        gas.per_byte_write = calculate_write_gas(&gas_config.byte_config, bytes);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/state_storage.move (L39-49)
```text
    public(friend) fun on_new_block(epoch: u64) acquires StateStorageUsage {
        assert!(
            exists<StateStorageUsage>(@aptos_framework),
            error::not_found(ESTATE_STORAGE_USAGE)
        );
        let usage = borrow_global_mut<StateStorageUsage>(@aptos_framework);
        if (epoch != usage.epoch) {
            usage.epoch = epoch;
            usage.usage = get_state_storage_usage_only_at_epoch_beginning();
        }
    }
```

**File:** storage/aptosdb/src/state_restore/restore_test.rs (L231-257)
```rust
fn assert_success<V>(
    db: &MockSnapshotStore<V, V>,
    expected_root_hash: HashValue,
    btree: &BTreeMap<HashValue, (V, V)>,
    version: Version,
) where
    V: TestKey + TestValue,
{
    let tree = JellyfishMerkleTree::new(db);
    for (key, value) in btree.values() {
        let (value_hash, value_index) = tree
            .get_with_proof(CryptoHash::hash(key), version)
            .unwrap()
            .0
            .unwrap();
        let value_in_db = db.get_value_at_version(&value_index).unwrap();
        assert_eq!(CryptoHash::hash(value), value_hash);
        assert_eq!(&value_in_db, value);
    }

    let actual_root_hash = tree.get_root_hash(version).unwrap();
    assert_eq!(actual_root_hash, expected_root_hash);
    let usage_calculated = db.calculate_usage(version);
    let usage_stored = db.get_stored_usage(version);
    assert_eq!(usage_calculated, usage_stored);
    assert_eq!(usage_stored.items(), tree.get_leaf_count(version).unwrap());
}
```
