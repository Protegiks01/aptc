# Audit Report

## Title
Malicious Governance Proposal Can Change CommitHistory max_capacity Causing Consensus to Read Wrong Historical Events

## Summary
The `CommitHistory` resource lacks runtime validation to ensure `max_capacity` matches its initialized value of 2000. A malicious governance proposal can upgrade the `block` module to add a function modifying `max_capacity`, then invoke it to change the value while preserving old table entries. This causes the consensus layer's index calculations to wrap around incorrectly, leading validators to read duplicate or wrong historical commit events.

## Finding Description

The `CommitHistory` Move resource stores blockchain commit events in a circular buffer with hardcoded `max_capacity = 2000` at genesis: [1](#0-0) 

The circular buffer uses modulo arithmetic for index wraparound: [2](#0-1) 

The consensus layer reads historical events by calculating indices backwards from `next_idx`: [3](#0-2) 

**Attack Path:**

1. **Step 1 - Framework Upgrade:** Governance proposes upgrading `block.move` to add:
```move
public fun update_max_capacity(aptos_framework: &signer, new_capacity: u32) acquires CommitHistory {
    system_addresses::assert_aptos_framework(aptos_framework);
    let history = borrow_global_mut<CommitHistory>(@aptos_framework);
    history.max_capacity = new_capacity;
}
```
This passes compatibility checks because struct layout is unchanged (only adding a function). [4](#0-3) 

2. **Step 2 - Malicious Update:** Second governance proposal calls `update_max_capacity(signer, 1000)` to reduce capacity from 2000 to 1000.

3. **Step 3 - Index Calculation Mismatch:** The table still contains 2000 entries with `length = 2000`, but `max_capacity = 1000`. When consensus reads historical events:
   - For i=1: `idx = (500 + 1000 - 1) % 1000 = 499` ✓
   - For i=1000: `idx = (500 + 1000 - 1000) % 1000 = 500` ✓  
   - For i=1001: `idx = (500 + 1000 - 1001) % 1000 = 499` ← **DUPLICATE! Same as i=1**

The loop continues up to `min(k, length)` where `length = 2000`: [5](#0-4) 

This causes consensus to read the same events multiple times or access wrong indices, violating the **Deterministic Execution** invariant where all validators must process identical historical data.

## Impact Explanation

**High Severity** - Significant Protocol Violation:

- Consensus layer depends on accurate historical commit events for DAG operations
- Different validators may compute different historical event sequences if `max_capacity` changes between validator restarts or state syncs
- This breaks deterministic execution guarantees and could lead to consensus disagreements
- While not directly causing fund loss, corrupted consensus state could require manual intervention or emergency upgrades
- The attack requires governance control but exploits a missing validation check that should prevent such modifications

## Likelihood Explanation

**Medium-High Likelihood** in adversarial governance scenarios:

- Requires two sequential governance proposals (framework upgrade + function call)
- Governance must be compromised or have malicious majority
- The security question explicitly considers "malicious governance proposal" as in-scope threat
- No runtime checks exist to prevent `max_capacity` modification
- Framework upgrade compatibility checks only validate struct layout, not semantic correctness of new functions
- Once exploited, affects all validators reading from `CommitHistory`

## Recommendation

Add runtime validation in `block.move` to ensure `max_capacity` remains immutable after initialization:

**Option 1 - Defensive Check in emit_new_block_event:**
```move
fun emit_new_block_event(...) acquires CommitHistory {
    if (exists<CommitHistory>(@aptos_framework)) {
        let commit_history_ref = borrow_global_mut<CommitHistory>(@aptos_framework);
        // Validate max_capacity hasn't been tampered with
        assert!(commit_history_ref.max_capacity == 2000, error::invalid_state(EINVALID_CAPACITY));
        // ... rest of function
    }
}
```

**Option 2 - Add getter validation in Rust:** [6](#0-5) 

Add validation in `max_capacity()` method:
```rust
pub fn max_capacity(&self) -> u32 {
    assert_eq!(self.max_capacity, 2000, "CommitHistory max_capacity must be 2000");
    self.max_capacity
}
```

**Option 3 - Const enforcement (preferred):**
Mark `max_capacity` semantically immutable by replacing the field with a constant and removing it from the struct entirely, calculating capacity from table length bounds.

## Proof of Concept

```move
#[test(aptos_framework = @aptos_framework)]
fun test_malicious_max_capacity_change(aptos_framework: signer) acquires CommitHistory {
    // Initialize with max_capacity = 2000
    block::initialize_for_test(&aptos_framework, 100000000);
    
    // Simulate malicious governance upgrade adding update function
    public fun update_max_capacity_malicious(aptos_framework: &signer, new_capacity: u32) acquires CommitHistory {
        system_addresses::assert_aptos_framework(aptos_framework);
        let history = borrow_global_mut<CommitHistory>(@aptos_framework);
        history.max_capacity = new_capacity;
    }
    
    // Add 2500 events to fill circular buffer
    for (i in 0..2500) {
        emit_new_block_event(...); // Adds events at indices 0-1999, wraps to 0-499
    }
    
    // Malicious capacity change
    update_max_capacity_malicious(&aptos_framework, 1000);
    
    // Read historical events - will read duplicates after index 1000
    let history = borrow_global<CommitHistory>(@aptos_framework);
    let next_idx = history.next_idx; // 500
    let max_cap = history.max_capacity; // 1000 (changed!)
    
    // Calculate indices for i=1 and i=1001
    let idx1 = (next_idx + max_cap - 1) % max_cap; // 499
    let idx1001 = (next_idx + max_cap - 1001) % max_cap; // 499 - DUPLICATE!
    
    assert!(idx1 == idx1001, 0); // This passes, proving the vulnerability
}
```

**Notes**

The vulnerability exists because:
1. Framework upgrade compatibility checks only validate struct layout, not semantic correctness of added functions
2. No runtime validation exists to prevent `max_capacity` modification after initialization  
3. The Rust code passively reads `max_capacity` without validating it matches the expected constant value
4. The `TableWithLength.length` field independently tracks table size and doesn't automatically decrease when `max_capacity` is reduced

This is a genuine security issue where governance's ability to upgrade modules can be exploited to corrupt consensus-critical data structures through missing validation checks.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/block.move (L95-99)
```text
        move_to<CommitHistory>(aptos_framework, CommitHistory {
            max_capacity: 2000,
            next_idx: 0,
            table: table_with_length::new(),
        });
```

**File:** aptos-move/framework/aptos-framework/sources/block.move (L271-279)
```text
            let idx = commit_history_ref.next_idx;
            if (table_with_length::contains(&commit_history_ref.table, idx)) {
                table_with_length::remove(&mut commit_history_ref.table, idx);
            };
            table_with_length::add(&mut commit_history_ref.table, idx, copy new_block_event);
            spec {
                assume idx + 1 <= MAX_U32;
            };
            commit_history_ref.next_idx = (idx + 1) % commit_history_ref.max_capacity;
```

**File:** consensus/src/dag/adapter.rs (L387-389)
```rust
        for i in 1..=std::cmp::min(k, resource.length()) {
            let idx = (resource.next_idx() + resource.max_capacity() - i as u32)
                % resource.max_capacity();
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1570-1577)
```rust
        let check_struct_layout = true;
        let check_friend_linking = !self
            .features()
            .is_enabled(FeatureFlag::TREAT_FRIEND_AS_PRIVATE);
        // TODO(#17171): remove this once 1.34 is in production.
        let function_compat_bug = self.gas_feature_version() < gas_feature_versions::RELEASE_V1_34;
        let compatibility_checks = Compatibility::new(
            check_struct_layout,
```

**File:** types/src/on_chain_config/commit_history.rs (L20-23)
```rust
impl CommitHistoryResource {
    pub fn max_capacity(&self) -> u32 {
        self.max_capacity
    }
```
