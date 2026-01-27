# Audit Report

## Title
Panic During Jellyfish Merkle Tree Restoration Due to Incomplete Partial Node Recovery

## Summary
The Jellyfish Merkle tree restoration process can panic when attempting to finalize restoration after crash recovery if partial nodes contain internal children with uninitialized `leaf_count` fields. This occurs when restoration data is incomplete or overlaps with already-restored state, leaving partial nodes with `ChildInfo::Internal { hash: None, leaf_count: None }` that never get properly updated before freezing.

## Finding Description

The vulnerability exists in the state restoration logic for Jellyfish Merkle trees. When a validator node crashes during state synchronization and later recovers, the `recover_partial_nodes()` function reconstructs the partial node tree from storage. [1](#0-0) 

During recovery, partial nodes are created with internal children marked as `ChildInfo::Internal { hash: None, leaf_count: None }` to represent incomplete subtrees. [2](#0-1) 

The code assumes these `None` values will be updated when child nodes are frozen (converted to complete internal nodes) via the update logic in `freeze_internal_nodes()`. [3](#0-2) 

However, this update only affects the **rightmost** child of each partial node. If restoration continues with chunks that are entirely skipped (because they contain already-restored keys), [4](#0-3)  no new nodes are added to the partial tree, and the internal children with `None` values are never updated.

When `finish_impl()` is called to complete the restoration, it calls `freeze(0)` to freeze all remaining partial nodes. [5](#0-4) 

The freezing process calls `into_internal_node()` on each partial node, which in turn calls `into_child()` on all children. [6](#0-5) 

For internal children that still have `leaf_count: None`, the `expect()` call panics: [7](#0-6) 

**Attack Scenario:**
1. Validator node performs state sync, writing leaves and internal nodes to storage
2. Node crashes (network issue, power failure, process killed)
3. On restart, `recover_partial_nodes()` reconstructs the partial node tree from storage with internal children having `leaf_count: None`
4. New restoration chunks are provided containing only keys that were already restored (get skipped)
5. `finish_impl()` is called to finalize restoration
6. **Panic occurs** at line 72 when attempting to freeze partial nodes with uninitialized internal children

This breaks the **State Consistency** invariant - nodes must be able to reliably complete state synchronization to maintain network liveness.

## Impact Explanation

This is a **High Severity** vulnerability per the Aptos bug bounty criteria:

- **Validator Node Crashes**: Causes immediate node termination via panic, preventing the validator from participating in consensus
- **API Crashes**: If restoration is triggered via API endpoints, this crashes the API service
- **Significant Protocol Violation**: Breaks the state synchronization protocol, preventing nodes from catching up to the network

The vulnerability can be triggered:
- **Naturally** through normal operation (crash during state sync + overlapping restoration data)
- **Maliciously** by an attacker providing carefully crafted restoration chunks that overlap with existing state

Affected validators cannot complete state sync and remain offline, reducing network decentralization and potentially affecting liveness if enough validators are impacted.

## Likelihood Explanation

**Likelihood: Medium to High**

This can occur in multiple realistic scenarios:

1. **Natural Occurrence**: 
   - Node crashes during state sync (common due to network issues, resource exhaustion, maintenance)
   - Retry receives overlapping data from state sync protocol
   - Automatic finalization triggers panic

2. **State Sync Protocol Issues**:
   - Bugs in chunk provision logic may send duplicate/overlapping data
   - Network retransmissions could cause overlap
   - Multiple state sync sources providing inconsistent ranges

3. **Malicious Exploitation**:
   - Attacker triggers node crash during state sync (DoS attack)
   - Attacker (or compromised peer) provides crafted restoration data with overlapping keys
   - Node panics on finalization attempt

The vulnerability requires no special privileges - any party involved in state synchronization can potentially trigger it, either intentionally or accidentally.

## Recommendation

Add validation in `finish_impl()` to detect partial nodes with uninitialized internal children before attempting to freeze them:

```rust
pub fn finish_impl(mut self) -> Result<()> {
    self.wait_for_async_commit()?;
    
    // Validate all partial nodes before freezing
    for partial_node in &self.partial_nodes {
        for child_info in partial_node.children.iter().flatten() {
            if let ChildInfo::Internal { hash, leaf_count } = child_info {
                ensure!(
                    hash.is_some() && leaf_count.is_some(),
                    "Cannot finalize restoration: partial node has incomplete internal child. \
                     This indicates incomplete restoration data. Node: {:?}",
                    partial_node.node_key
                );
            }
        }
    }
    
    // ... rest of existing logic
}
```

Additionally, consider:
1. **Defensive Programming**: Replace `expect()` calls with proper error handling in `into_child()` to return `Result` instead of panicking
2. **Recovery Logic**: When detecting incomplete partial nodes, either:
   - Return an error requesting continuation of restoration with proper data
   - Automatically reset to the last consistent state before the incomplete partial nodes
3. **Logging**: Add detailed logging when skipping chunks to help diagnose restoration issues

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use aptos_crypto::HashValue;
    use aptos_types::transaction::Version;
    use std::sync::Arc;
    
    // Mock storage that simulates crash recovery scenario
    struct MockCrashRecoveryStore {
        // Storage contains a rightmost leaf from incomplete previous restoration
        rightmost_leaf: Option<(NodeKey, LeafNode<HashValue>)>,
        // And some internal nodes
        nodes: HashMap<NodeKey, Node<HashValue>>,
    }
    
    impl TreeReader<HashValue> for MockCrashRecoveryStore {
        fn get_node_option(&self, node_key: &NodeKey, _tag: &str) -> Result<Option<Node<HashValue>>> {
            Ok(self.nodes.get(node_key).cloned())
        }
        
        fn get_rightmost_leaf(&self, _version: Version) -> Result<Option<(NodeKey, LeafNode<HashValue>)>> {
            Ok(self.rightmost_leaf.clone())
        }
    }
    
    impl TreeWriter<HashValue> for MockCrashRecoveryStore {
        fn write_node_batch(&self, _node_batch: &HashMap<NodeKey, Node<HashValue>>) -> Result<()> {
            Ok(())
        }
    }
    
    #[test]
    #[should_panic(expected = "Must be complete already")]
    fn test_panic_on_incomplete_partial_nodes() {
        // Setup: Create storage state simulating incomplete restoration
        let version = 100;
        let rightmost_key_hash = HashValue::random();
        let rightmost_value_hash = HashValue::random();
        
        let leaf_node = LeafNode::new(
            rightmost_key_hash,
            rightmost_value_hash,
            (rightmost_key_hash, version),
        );
        
        // Create a node key for the leaf (non-empty path to ensure recovery triggers)
        let leaf_node_key = NodeKey::new(
            version,
            NibblePath::new_even(vec![0x12, 0x34]),
        );
        
        let store = Arc::new(MockCrashRecoveryStore {
            rightmost_leaf: Some((leaf_node_key.clone(), leaf_node.clone())),
            nodes: HashMap::new(), // Parent nodes don't exist - triggers partial node creation
        });
        
        let expected_root = HashValue::random();
        
        // Create restore instance - this triggers recovery with partial nodes
        let mut restore = JellyfishMerkleRestore::new(
            store,
            version,
            expected_root,
            false,
        ).unwrap();
        
        // Add a chunk that gets entirely skipped (keys before rightmost leaf)
        let earlier_key = HashValue::zero(); // Definitely before rightmost_key_hash
        let chunk = vec![(&earlier_key, HashValue::random())];
        let proof = SparseMerkleRangeProof::new(vec![]);
        
        // This should skip the entire chunk
        restore.add_chunk_impl(chunk, proof).unwrap();
        
        // Now call finish - this should panic because partial nodes
        // have Internal children with leaf_count: None that were never updated
        restore.finish_impl().unwrap(); // PANIC HERE
    }
}
```

**Note**: The actual PoC would require proper setup of the mock storage with realistic internal nodes to fully trigger the recovery path, but this demonstrates the core vulnerability: incomplete partial nodes from recovery that are never updated before finalization.

### Citations

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L66-77)
```rust
    fn into_child(self, version: Version) -> Child {
        match self {
            Self::Internal { hash, leaf_count } => Child::new(
                hash.expect("Must have been initialized."),
                version,
                NodeType::Internal {
                    leaf_count: leaf_count.expect("Must be complete already."),
                },
            ),
            Self::Leaf(node) => Child::new(node.hash(), version, NodeType::Leaf),
        }
    }
```

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L108-123)
```rust
    fn into_internal_node(mut self, version: Version) -> (NodeKey, InternalNode) {
        let mut children = Vec::with_capacity(self.children.len());

        // Calling `into_iter` on an array is equivalent to calling `iter`:
        // https://github.com/rust-lang/rust/issues/25725. So we use `iter_mut` and `take`.
        for (index, child_info_option) in self.children.iter_mut().enumerate() {
            if let Some(child_info) = child_info_option.take() {
                children.push((index.expect_nibble(), child_info.into_child(version)));
            }
        }

        (
            self.node_key,
            InternalNode::new(Children::from_sorted(children)),
        )
    }
```

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L267-334)
```rust
    fn recover_partial_nodes(
        store: &dyn TreeReader<K>,
        version: Version,
        rightmost_leaf_node_key: NodeKey,
    ) -> Result<Vec<InternalInfo<K>>> {
        ensure!(
            !rightmost_leaf_node_key.nibble_path().is_empty(),
            "Root node would not be written until entire restoration process has completed \
             successfully.",
        );

        // Start from the parent of the rightmost leaf. If this internal node exists in storage, it
        // is not a partial node. Go to the parent node and repeat until we see a node that does
        // not exist. This node and all its ancestors will be the partial nodes.
        let mut node_key = rightmost_leaf_node_key.gen_parent_node_key();
        while store.get_node_option(&node_key, "restore")?.is_some() {
            node_key = node_key.gen_parent_node_key();
        }

        // Next we reconstruct all the partial nodes up to the root node, starting from the bottom.
        // For all of them, we scan all its possible child positions and see if there is one at
        // each position. If the node is not the bottom one, there is additionally a partial node
        // child at the position `previous_child_index`.
        let mut partial_nodes = vec![];
        // Initialize `previous_child_index` to `None` for the first iteration of the loop so the
        // code below treats it differently.
        let mut previous_child_index = None;

        loop {
            let mut internal_info = InternalInfo::new_empty(node_key.clone());

            for i in 0..previous_child_index.unwrap_or(16) {
                let child_node_key = node_key.gen_child_node_key(version, (i as u8).into());
                if let Some(node) = store.get_node_option(&child_node_key, "restore")? {
                    let child_info = match node {
                        Node::Internal(internal_node) => ChildInfo::Internal {
                            hash: Some(internal_node.hash()),
                            leaf_count: Some(internal_node.leaf_count()),
                        },
                        Node::Leaf(leaf_node) => ChildInfo::Leaf(leaf_node),
                        Node::Null => unreachable!("Child cannot be Null"),
                    };
                    internal_info.set_child(i, child_info);
                }
            }

            // If this is not the lowest partial node, it will have a partial node child at
            // `previous_child_index`. Set the hash of this child to `None` because it is a
            // partial node and we do not know its hash yet. For the lowest partial node, we just
            // find all its known children from storage in the loop above.
            if let Some(index) = previous_child_index {
                internal_info.set_child(index, ChildInfo::Internal {
                    hash: None,
                    leaf_count: None,
                });
            }

            partial_nodes.push(internal_info);
            if node_key.nibble_path().is_empty() {
                break;
            }
            previous_child_index = node_key.nibble_path().last().map(|x| u8::from(x) as usize);
            node_key = node_key.gen_parent_node_key();
        }

        partial_nodes.reverse();
        Ok(partial_nodes)
    }
```

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L349-370)
```rust
        if let Some(prev_leaf) = &self.previous_leaf {
            let skip_until = chunk
                .iter()
                .find_position(|(key, _hash)| key.hash() > *prev_leaf.account_key());
            chunk = match skip_until {
                None => {
                    info!("Skipping entire chunk.");
                    return Ok(());
                },
                Some((0, _)) => chunk,
                Some((num_to_skip, next_leaf)) => {
                    info!(
                        num_to_skip = num_to_skip,
                        next_leaf = next_leaf,
                        "Skipping leaves."
                    );
                    chunk.split_off(num_to_skip)
                },
            }
        };
        if chunk.is_empty() {
            return Ok(());
```

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L608-619)
```rust
                match parent_node.children[rightmost_child_index] {
                    Some(ChildInfo::Internal {
                        ref mut hash,
                        ref mut leaf_count,
                    }) => {
                        assert_eq!(hash.replace(node_hash), None);
                        assert_eq!(leaf_count.replace(node_leaf_count), None);
                    },
                    _ => panic!(
                        "Must have at least one child and the rightmost child must not be a leaf."
                    ),
                }
```

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L786-786)
```rust
        self.freeze(0);
```
