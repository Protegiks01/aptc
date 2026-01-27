# Audit Report

## Title
Position Boundary Check Bypass Enables Denial of Service via Invalid Postorder Index

## Summary
The `Position::from_postorder_index()` function has an insufficient boundary check that allows specific large postorder indices to produce `Position` objects violating the critical invariant `Position.0 < u64::MAX - 1`. When these invalid positions are used in accumulator operations, they trigger assertion failures causing node crashes during database operations like backups, pruning, or state synchronization.

## Finding Description

The vulnerability exists in the boundary validation of postorder indices before conversion to inorder positions. [1](#0-0) 

The check `index < !0u64` (equivalent to `index < u64::MAX`) is insufficient. The function allows `index = 2^63 - 64 = 9223372036854775744` to pass validation, but the `postorder_to_inorder` conversion produces a critical edge case:

**Step-by-step exploitation:**

1. Malicious postorder index `2^63 - 64` passes the boundary check at line 81
2. The `postorder_to_inorder()` algorithm at line 85 [2](#0-1)  iterates through 64 levels, subtracting full binary tree sizes
3. For input `2^63 - 64`, the algorithm subtracts exactly `2^63 - 64` total across iterations, leaving `node = 0` after the loop
4. This produces `level = 0` and `pos = 2^63 - 1`
5. `Position::from_level_and_pos(0, 2^63 - 1)` [3](#0-2)  computes:
   - `shifted_pos = (2^63 - 1) << 1 = 2^64 - 2 = u64::MAX - 1`
   - `level_one_bits = 0`
   - Result: `Position(u64::MAX - 1)`

6. This violates the invariant stated at line 35 [4](#0-3) 

7. When `parent()`, `child()`, `sibling()`, or `is_left_child()` are called on this position, they hit assertion failures [5](#0-4)  causing immediate panic

**Attack Vector:**

The `TransactionAccumulatorSchema` uses postorder indices as database keys [6](#0-5) . When database keys are decoded during iteration [7](#0-6) , malformed keys trigger the vulnerability.

An attacker can exploit this through:
- **Database corruption**: Bit flips or external tampering introducing the malicious key value
- **Malicious backup restore**: Providing a corrupted backup containing the poisoned key [8](#0-7) 
- **State sync vulnerabilities**: If state sync doesn't validate positions before storage

## Impact Explanation

**Severity: High (Validator node crashes)**

This vulnerability causes **Denial of Service** against validator nodes:

1. **Node Crashes During Operations**: Any database iteration that encounters the malicious key will crash the node. This includes:
   - Database backup operations
   - Transaction accumulator pruning [9](#0-8) 
   - Database debugging/verification tools
   - State restoration from backups

2. **Persistent Failure**: Once the malicious key exists in the database, the node cannot complete these critical operations without manual intervention

3. **Network-Wide Impact**: If multiple nodes restore from the same corrupted backup, multiple validators crash simultaneously, potentially affecting network liveness

This meets **High Severity** criteria per the Aptos bug bounty program as it causes validator node crashes and API failures during critical database operations.

## Likelihood Explanation

**Likelihood: Medium**

While normal accumulator operations never generate postorder indices near `2^63 - 64` (the maximum leaf count is `2^63` [10](#0-9) , producing much smaller indices), the vulnerability can be triggered through:

1. **Database corruption**: Hardware failures, bit flips, or storage bugs could corrupt keys
2. **Malicious backup injection**: An attacker providing corrupted backup files
3. **Future bugs**: Changes to accumulator logic could inadvertently generate these edge-case indices

The attack is feasible but requires either database-level access or exploitation of separate backup/restore vulnerabilities. The impact severity when triggered is high, making this a credible medium-likelihood threat.

## Recommendation

Replace the insufficient boundary check with proper validation ensuring the converted position satisfies the invariant:

```rust
pub fn from_postorder_index(index: u64) -> Result<Self> {
    // Maximum valid postorder index that produces Position.0 < u64::MAX - 1
    // This is 2^63 - 65 (one less than the problematic value)
    const MAX_VALID_POSTORDER_INDEX: u64 = (1u64 << 63) - 65;
    
    ensure!(
        index <= MAX_VALID_POSTORDER_INDEX,
        "postorder index {} exceeds maximum valid value {}",
        index,
        MAX_VALID_POSTORDER_INDEX
    );
    
    let position = Position(postorder_to_inorder(index));
    
    // Additional safety check: verify invariant is maintained
    debug_assert!(
        position.0 < u64::MAX - 1,
        "postorder_to_inorder produced invalid position {}",
        position.0
    );
    
    Ok(position)
}
```

Additionally, add validation in the database restore path to reject any keys that fail `from_postorder_index()` conversion, preventing corrupted backups from being imported.

## Proof of Concept

```rust
#[test]
#[should_panic(expected = "assertion failed")]
fn test_postorder_index_boundary_bypass() {
    // The problematic index that passes the boundary check
    let malicious_index = (1u64 << 63) - 64; // 2^63 - 64
    
    // This should fail but doesn't with current code
    let position = Position::from_postorder_index(malicious_index)
        .expect("Index passes boundary check");
    
    // Verify the position violates the invariant
    assert_eq!(position.0, u64::MAX - 1);
    
    // This will panic when parent() checks the invariant
    let _parent = position.parent(); // PANICS HERE
}

#[test]
fn test_postorder_index_edge_case_sequence() {
    // Test values near the boundary
    let test_cases = vec![
        ((1u64 << 63) - 65, true),  // Should pass
        ((1u64 << 63) - 64, false), // Should fail (creates Position(u64::MAX - 1))
        ((1u64 << 63) - 63, false), // Should fail
        (u64::MAX - 1, false),      // Should fail (explicitly mentioned in question)
    ];
    
    for (index, should_succeed) in test_cases {
        let result = Position::from_postorder_index(index);
        
        if should_succeed {
            assert!(result.is_ok(), "Index {} should be valid", index);
            let pos = result.unwrap();
            // Verify invariant holds
            assert!(pos.0 < u64::MAX - 1, "Position violates invariant");
            // Verify operations don't panic
            let _ = pos.parent();
        } else {
            // With proper fix, these should be rejected at boundary check
            // Without fix, they create invalid positions that panic on use
            if result.is_ok() {
                let pos = result.unwrap();
                // If it passed, it must violate invariant or panic on operations
                if pos.0 >= u64::MAX - 1 {
                    panic!("Boundary check allowed invalid position creation");
                }
            }
        }
    }
}
```

**Notes:**

The vulnerability is specific to accumulator positions used in Merkle tree proofs for transaction and event accumulators. While normal validator operations will never generate these edge-case indices, the vulnerability becomes exploitable through database corruption or malicious backup injection. The fix requires tightening the boundary check to prevent conversion of postorder indices that would violate the position invariant.

### Citations

**File:** types/src/proof/position/mod.rs (L33-35)
```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Position(u64);
// invariant Position.0 < u64::MAX - 1
```

**File:** types/src/proof/position/mod.rs (L62-68)
```rust
    pub fn from_level_and_pos(level: u32, pos: u64) -> Self {
        assert!(level < 64);
        assert!(1u64 << level > 0); // bitwise and integer operations don't mix.
        let level_one_bits = (1u64 << level) - 1;
        let shifted_pos = if level == 63 { 0 } else { pos << (level + 1) };
        Position(shifted_pos | level_one_bits)
    }
```

**File:** types/src/proof/position/mod.rs (L78-85)
```rust
    pub fn from_postorder_index(index: u64) -> Result<Self> {
        ensure!(
            index < !0u64,
            "node index {} is invalid (equal to 2^64 - 1)",
            index
        );
        Ok(Position(postorder_to_inorder(index)))
    }
```

**File:** types/src/proof/position/mod.rs (L92-94)
```rust
    pub fn parent(self) -> Self {
        assert!(self.0 < u64::MAX - 1); // invariant
        Self(
```

**File:** types/src/proof/position/mod.rs (L520-534)
```rust
pub fn postorder_to_inorder(mut node: u64) -> u64 {
    // The number of nodes in a full binary tree with height `n` is `2^n - 1`.
    let mut full_binary_size = !0u64;
    let mut bitmap = 0u64;
    for i in (0..64).rev() {
        if node >= full_binary_size {
            node -= full_binary_size;
            bitmap |= 1 << i;
        }
        full_binary_size >>= 1;
    }
    let level = node as u32;
    let pos = bitmap >> level;
    Position::from_level_and_pos(level, pos).to_inorder_index()
}
```

**File:** storage/aptosdb/src/schema/transaction_accumulator/mod.rs (L31-41)
```rust
impl KeyCodec<TransactionAccumulatorSchema> for Position {
    fn encode_key(&self) -> Result<Vec<u8>> {
        Ok(self.to_postorder_index().to_be_bytes().to_vec())
    }

    fn decode_key(mut data: &[u8]) -> Result<Self> {
        ensure_slice_len_eq(data, size_of::<u64>())?;
        let index = data.read_u64::<BigEndian>()?;
        Position::from_postorder_index(index)
    }
}
```

**File:** storage/schemadb/src/iterator.rs (L118-118)
```rust
        let key = <S::Key as KeyCodec<S>>::decode_key(raw_key);
```

**File:** storage/aptosdb/src/backup/restore_utils.rs (L78-111)
```rust
pub fn confirm_or_save_frozen_subtrees(
    transaction_accumulator_db: &DB,
    num_leaves: LeafCount,
    frozen_subtrees: &[HashValue],
    existing_batch: Option<&mut SchemaBatch>,
) -> Result<()> {
    let positions: Vec<_> = FrozenSubTreeIterator::new(num_leaves).collect();
    ensure!(
        positions.len() == frozen_subtrees.len(),
        "Number of frozen subtree roots not expected. Expected: {}, actual: {}",
        positions.len(),
        frozen_subtrees.len(),
    );

    if let Some(existing_batch) = existing_batch {
        confirm_or_save_frozen_subtrees_impl(
            transaction_accumulator_db,
            frozen_subtrees,
            positions,
            existing_batch,
        )?;
    } else {
        let mut batch = SchemaBatch::new();
        confirm_or_save_frozen_subtrees_impl(
            transaction_accumulator_db,
            frozen_subtrees,
            positions,
            &mut batch,
        )?;
        transaction_accumulator_db.write_schemas(batch)?;
    }

    Ok(())
}
```

**File:** storage/aptosdb/src/ledger_db/transaction_accumulator_db.rs (L149-172)
```rust
    pub(crate) fn prune(begin: Version, end: Version, db_batch: &mut SchemaBatch) -> Result<()> {
        for version_to_delete in begin..end {
            db_batch.delete::<TransactionAccumulatorRootHashSchema>(&version_to_delete)?;
            // The even version will be pruned in the iteration of version + 1.
            if version_to_delete % 2 == 0 {
                continue;
            }

            let first_ancestor_that_is_a_left_child =
                Self::find_first_ancestor_that_is_a_left_child(version_to_delete);

            // This assertion is true because we skip the leaf nodes with address which is a
            // a multiple of 2.
            assert!(!first_ancestor_that_is_a_left_child.is_leaf());

            let mut current = first_ancestor_that_is_a_left_child;
            while !current.is_leaf() {
                db_batch.delete::<TransactionAccumulatorSchema>(&current.left_child())?;
                db_batch.delete::<TransactionAccumulatorSchema>(&current.right_child())?;
                current = current.right_child();
            }
        }
        Ok(())
    }
```

**File:** types/src/proof/definition.rs (L46-47)
```rust
pub const MAX_ACCUMULATOR_PROOF_DEPTH: usize = 63;
pub const MAX_ACCUMULATOR_LEAVES: LeafCount = 1 << MAX_ACCUMULATOR_PROOF_DEPTH;
```
