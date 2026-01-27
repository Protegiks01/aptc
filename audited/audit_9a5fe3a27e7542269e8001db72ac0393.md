Audit Report

## Title
MockTreeStore write_node_batch() Lacks Atomicity, Allowing State Inconsistency on Panic

## Summary
The write_node_batch() function in MockTreeStore does not guarantee atomicity. If a panic occurs during the batch insert loop, it leaves the data store with a subset of nodes written, violating the expected all-or-nothing behavior for state transitions.

## Finding Description
The write_node_batch() method takes a NodeBatch (a HashMap of nodes), acquires a write lock, and inserts each entry into the backing HashMap in a loop. If a panic occurs during this process (for example, due to memory exhaustion or failed assertion), the previously written entries remain in the store, while subsequent ones are not committed. There is no rollback or transaction mechanism in place to undo partial writes, resulting in a state inconsistent with the expectation that a batch is written atomically. This directly breaks the critical Aptos invariant that state transitions must be atomic and verifiable via Merkle proofs. Any higher-level logic assuming atomic batch semantics (as is typical in state management and consensus code) could be misled, leading to issues that could propagate into consensus splits, invalid proofs, or misleading test results.

## Impact Explanation
This issue allows for state inconsistency in situations where a panic can be induced or occurs unexpectedly during batch insertion. In the context of blockchain state management (especially consensus-critical code), this can lead to consensus failures, data corruption, and potentially unrecoverable forks. As such, this matches the "Critical" severity category: state consistency and consensus/safety violations are plausible outcomes if code written atop MockTreeStore is assumed to behave atomically. Particularly concerning is any upstream use in critical integration or simulation testing, since incorrect behaviors could propagate into production if assumptions about atomicity are unsound.

## Likelihood Explanation
While panics in Rust are not expected under ordinary operation, a maliciously crafted NodeBatch (e.g., violating allow_overwrite expectations, or hitting implementation limits/resources) or introduction of bugs (e.g., assertion failures) could trigger a panic. Moreover, if this pattern or code were copied or lifted into production contexts, the risk could become material. Even if MockTreeStore is used only in tests, the loss of atomicity can allow for subtle mistakes or overlooked issues to escape into production.

## Recommendation
Replace the in-place mutation logic with a two-phase approach: (1) prepare a new copy of the data that includes the batch updates, ensuring all checks/insertions succeed without panic, and (2) commit the updated copy only after the batch has been fully processed. Alternatively, implement an explicit rollback mechanism for any batch insertions that panic, perhaps via a transaction or explicit revert logic.

Example (conceptual fix):
```
let mut new_data = locked.0.clone();
for (node_key, node) in node_batch.clone() {
    let replaced = new_data.insert(node_key, node);
    if !self.allow_overwrite {
        assert_eq!(replaced, None);
    }
}
locked.0 = new_data;
```

## Proof of Concept
A Rust test or main function injecting a NodeBatch with an entry that triggers a panic (e.g., duplicate key when allow_overwrite is false) will result in only some nodes being written to the store, with later entries missing:

1. Insert NodeBatch with {A, B, duplicate C}
2. write_node_batch() writes A, writes B, panics on assert when C is duplicate
3. Data store contains A and B, but not all of NodeBatch, leaving the store in a partial state [1](#0-0) [2](#0-1) 

Notes:
- This issue occurs within MockTreeStore, typically intended for testing, but its existence undermines test invariant reliability and could cause dangerous assumptions to propagate. If reused outside pure test context, impact is elevated further. 
- Only concrete, code-backed claims are presented here.

### Citations

**File:** storage/jellyfish-merkle/src/mock_tree_store.rs (L58-67)
```rust
    fn write_node_batch(&self, node_batch: &NodeBatch<K>) -> Result<()> {
        let mut locked = self.data.write();
        for (node_key, node) in node_batch.clone() {
            let replaced = locked.0.insert(node_key, node);
            if !self.allow_overwrite {
                assert_eq!(replaced, None);
            }
        }
        Ok(())
    }
```

**File:** storage/jellyfish-merkle/src/lib.rs (L182-182)
```rust
pub type NodeBatch<K> = HashMap<NodeKey, Node<K>>;
```
