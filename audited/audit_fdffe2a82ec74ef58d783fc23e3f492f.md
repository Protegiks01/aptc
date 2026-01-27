# Audit Report

## Title
Missing Input Validation on expected_root_hash Allows State Restore with Invalid Root Hash Values

## Summary
The `expected_root_hash` parameter passed to `get_state_restore_receiver()` is not validated for zero, null, or placeholder values (`SPARSE_MERKLE_PLACEHOLDER_HASH`), allowing operators to restore blockchain state using backups with semantically invalid root hashes. This breaks the State Consistency invariant and can lead to nodes having incorrect state for a given version.

## Finding Description

The state restore functionality in the backup-cli accepts an `expected_root_hash` parameter without validating whether this value is appropriate for the blockchain version being restored. [1](#0-0) 

The function directly passes this hash to the underlying restore handlers without any validation. The hash flows through multiple layers: [2](#0-1) [3](#0-2) [4](#0-3) 

At no point is there validation that `expected_root_hash` is not:
- `HashValue::zero()` (all zeros)
- `SPARSE_MERKLE_PLACEHOLDER_HASH` (empty tree marker) [5](#0-4) 

The `SPARSE_MERKLE_PLACEHOLDER_HASH` represents an empty tree and should not be a valid state root for any version beyond genesis: [6](#0-5) 

**Attack Scenario:**

1. An attacker who compromises backup storage or an operator who mistakenly uses an untrusted backup source provides a malicious manifest with `root_hash = SPARSE_MERKLE_PLACEHOLDER_HASH`
2. The manifest includes a matching `TransactionInfoWithProof` 
3. The operator uses the trusted waypoint feature (legitimate for bootstrapping) that matches this version
4. The validation at the restore entry point passes because the values match [7](#0-6) 

5. The node restores with an empty or invalid state tree for that version
6. Critical issue: Test code validates the final root hash matches expected, but production code does NOT perform this final validation [8](#0-7) 

The production `finish_impl()` method writes the final tree without verifying it matches `expected_root_hash`: [9](#0-8) 

This breaks **Critical Invariant #4: State Consistency** - "State transitions must be atomic and verifiable via Merkle proofs" and **Invariant #1: Deterministic Execution** - "All validators must produce identical state roots for identical blocks."

## Impact Explanation

This qualifies as **HIGH severity** per the Aptos Bug Bounty criteria:

- **Significant protocol violations**: A node with incorrect state for a version cannot properly participate in consensus or serve state queries correctly
- **State inconsistencies requiring intervention**: If multiple nodes restore from different (malicious) backup sources, they will have divergent states, requiring manual intervention to resolve
- **Validator node issues**: Validators restoring from compromised backups will have wrong state and fail validation checks

While not reaching Critical severity (no direct fund loss or unrecoverable network partition), this enables state inconsistency attacks that undermine network integrity.

## Likelihood Explanation

**Likelihood: Medium**

Exploitation requires:
1. **Compromised backup infrastructure** OR **operator error** (using untrusted backup source) - requires either infrastructure breach or operational mistake
2. **Trusted waypoint misconfiguration** - operators must either be tricked or make configuration errors
3. **Lack of post-restore validation** - the code doesn't detect the issue after completion

The trusted waypoint feature is legitimate for bootstrapping nodes but can be exploited. Operators following standard procedures from official sources are protected, but those using alternative backup sources or custom waypoints are vulnerable.

## Recommendation

Add validation in `get_state_restore_receiver()` to reject invalid root hash values:

```rust
pub fn get_state_restore_receiver(
    &self,
    version: Version,
    expected_root_hash: HashValue,
    restore_mode: StateSnapshotRestoreMode,
) -> Result<StateSnapshotRestore<StateKey, StateValue>> {
    // Validate expected_root_hash
    ensure!(
        expected_root_hash != HashValue::zero(),
        "Invalid expected_root_hash: cannot be zero"
    );
    
    // SPARSE_MERKLE_PLACEHOLDER_HASH is only valid for empty state (version 0)
    if expected_root_hash == *SPARSE_MERKLE_PLACEHOLDER_HASH {
        ensure!(
            version == 0,
            "Invalid expected_root_hash: SPARSE_MERKLE_PLACEHOLDER_HASH only valid at version 0"
        );
    }
    
    // Continue with existing logic...
    match self {
        Self::Restore { restore_handler } => restore_handler.get_state_restore_receiver(
            version,
            expected_root_hash,
            restore_mode,
        ),
        Self::Verify => {
            // ... existing code
        }
    }
}
```

Additionally, add final validation in `JellyfishMerkleRestore::finish_impl()` (similar to test code):

```rust
pub fn finish_impl(mut self) -> Result<()> {
    self.wait_for_async_commit()?;
    
    // ... existing finish logic ...
    
    self.freeze(0);
    self.store.write_node_batch(&self.frozen_nodes)?;
    
    // CRITICAL: Validate final root hash matches expected
    let root_key = NodeKey::new_empty_path(self.version);
    if let Some(root_node) = self.store.get_node_option(&root_key, "finish")? {
        ensure!(
            root_node.hash() == self.expected_root_hash,
            "Final root hash {} does not match expected {}",
            root_node.hash(),
            self.expected_root_hash
        );
    }
    
    Ok(())
}
```

## Proof of Concept

```rust
#[test]
fn test_invalid_expected_root_hash_rejected() {
    use aptos_crypto::{HashValue, hash::SPARSE_MERKLE_PLACEHOLDER_HASH};
    use aptos_types::transaction::Version;
    
    let mock_store = Arc::new(MockStore);
    let version: Version = 1000; // Non-genesis version
    
    // Attempt 1: Zero hash should be rejected
    let result = StateSnapshotRestore::new(
        &mock_store,
        &mock_store,
        version,
        HashValue::zero(),  // Invalid!
        true,
        StateSnapshotRestoreMode::Default,
    );
    assert!(result.is_err(), "Zero hash should be rejected");
    
    // Attempt 2: SPARSE_MERKLE_PLACEHOLDER_HASH at non-zero version should be rejected  
    let result = StateSnapshotRestore::new(
        &mock_store,
        &mock_store,
        version,
        *SPARSE_MERKLE_PLACEHOLDER_HASH,  // Invalid for version > 0!
        true,
        StateSnapshotRestoreMode::Default,
    );
    assert!(result.is_err(), "Empty tree hash should be rejected for non-genesis version");
    
    // Attempt 3: SPARSE_MERKLE_PLACEHOLDER_HASH at genesis should be accepted
    let result = StateSnapshotRestore::new(
        &mock_store,
        &mock_store,
        0,  // Genesis version
        *SPARSE_MERKLE_PLACEHOLDER_HASH,
        true,
        StateSnapshotRestoreMode::Default,
    );
    assert!(result.is_ok(), "Empty tree hash should be valid at genesis");
}
```

This PoC demonstrates that the current code accepts invalid hash values that should be rejected based on semantic constraints.

### Citations

**File:** storage/backup/backup-cli/src/utils/mod.rs (L216-239)
```rust
    pub fn get_state_restore_receiver(
        &self,
        version: Version,
        expected_root_hash: HashValue,
        restore_mode: StateSnapshotRestoreMode,
    ) -> Result<StateSnapshotRestore<StateKey, StateValue>> {
        match self {
            Self::Restore { restore_handler } => restore_handler.get_state_restore_receiver(
                version,
                expected_root_hash,
                restore_mode,
            ),
            Self::Verify => {
                let mock_store = Arc::new(MockStore);
                StateSnapshotRestore::new_overwrite(
                    &mock_store,
                    &mock_store,
                    version,
                    expected_root_hash,
                    restore_mode,
                )
            },
        }
    }
```

**File:** storage/aptosdb/src/backup/restore_handler.rs (L41-55)
```rust
    pub fn get_state_restore_receiver(
        &self,
        version: Version,
        expected_root_hash: HashValue,
        restore_mode: StateSnapshotRestoreMode,
    ) -> Result<StateSnapshotRestore<StateKey, StateValue>> {
        StateSnapshotRestore::new(
            &self.state_store.state_merkle_db,
            &self.state_store,
            version,
            expected_root_hash,
            true, /* async_commit */
            restore_mode,
        )
    }
```

**File:** storage/aptosdb/src/state_restore/mod.rs (L152-173)
```rust
    pub fn new<T: 'static + TreeReader<K> + TreeWriter<K>, S: 'static + StateValueWriter<K, V>>(
        tree_store: &Arc<T>,
        value_store: &Arc<S>,
        version: Version,
        expected_root_hash: HashValue,
        async_commit: bool,
        restore_mode: StateSnapshotRestoreMode,
    ) -> Result<Self> {
        Ok(Self {
            tree_restore: Arc::new(Mutex::new(Some(JellyfishMerkleRestore::new(
                Arc::clone(tree_store),
                version,
                expected_root_hash,
                async_commit,
            )?))),
            kv_restore: Arc::new(Mutex::new(Some(StateValueRestore::new(
                Arc::clone(value_store),
                version,
            )))),
            restore_mode,
        })
    }
```

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L189-235)
```rust
    pub fn new<D: 'static + TreeReader<K> + TreeWriter<K>>(
        store: Arc<D>,
        version: Version,
        expected_root_hash: HashValue,
        async_commit: bool,
    ) -> Result<Self> {
        let tree_reader = Arc::clone(&store);
        let (finished, partial_nodes, previous_leaf) = if let Some(root_node) =
            tree_reader.get_node_option(&NodeKey::new_empty_path(version), "restore")?
        {
            info!("Previous restore is complete, checking root hash.");
            ensure!(
                root_node.hash() == expected_root_hash,
                "Previous completed restore has root hash {}, expecting {}",
                root_node.hash(),
                expected_root_hash,
            );
            (true, vec![], None)
        } else if let Some((node_key, leaf_node)) = tree_reader.get_rightmost_leaf(version)? {
            // If the system crashed in the middle of the previous restoration attempt, we need
            // to recover the partial nodes to the state right before the crash.
            (
                false,
                Self::recover_partial_nodes(tree_reader.as_ref(), version, node_key)?,
                Some(leaf_node),
            )
        } else {
            (
                false,
                vec![InternalInfo::new_empty(NodeKey::new_empty_path(version))],
                None,
            )
        };

        Ok(Self {
            store,
            version,
            partial_nodes,
            frozen_nodes: HashMap::new(),
            previous_leaf,
            num_keys_received: 0,
            expected_root_hash,
            finished,
            async_commit,
            async_commit_result: None,
        })
    }
```

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L750-789)
```rust
    pub fn finish_impl(mut self) -> Result<()> {
        self.wait_for_async_commit()?;
        // Deal with the special case when the entire tree has a single leaf or null node.
        if self.partial_nodes.len() == 1 {
            let mut num_children = 0;
            let mut leaf = None;
            for i in 0..16 {
                if let Some(ref child_info) = self.partial_nodes[0].children[i] {
                    num_children += 1;
                    if let ChildInfo::Leaf(node) = child_info {
                        leaf = Some(node.clone());
                    }
                }
            }

            match num_children {
                0 => {
                    let node_key = NodeKey::new_empty_path(self.version);
                    assert!(self.frozen_nodes.is_empty());
                    self.frozen_nodes.insert(node_key, Node::Null);
                    self.store.write_node_batch(&self.frozen_nodes)?;
                    return Ok(());
                },
                1 => {
                    if let Some(node) = leaf {
                        let node_key = NodeKey::new_empty_path(self.version);
                        assert!(self.frozen_nodes.is_empty());
                        self.frozen_nodes.insert(node_key, node.into());
                        self.store.write_node_batch(&self.frozen_nodes)?;
                        return Ok(());
                    }
                },
                _ => (),
            }
        }

        self.freeze(0);
        self.store.write_node_batch(&self.frozen_nodes)?;
        Ok(())
    }
```

**File:** crates/aptos-crypto/src/hash.rs (L153-157)
```rust
    pub const fn zero() -> Self {
        HashValue {
            hash: [0; HashValue::LENGTH],
        }
    }
```

**File:** storage/jellyfish-merkle/src/node_type/mod.rs (L1-100)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

//! Node types of [`JellyfishMerkleTree`](crate::JellyfishMerkleTree)
//!
//! This module defines two types of Jellyfish Merkle tree nodes: [`InternalNode`]
//! and [`LeafNode`] as building blocks of a 256-bit
//! [`JellyfishMerkleTree`](crate::JellyfishMerkleTree). [`InternalNode`] represents a 4-level
//! binary tree to optimize for IOPS: it compresses a tree with 31 nodes into one node with 16
//! children at the lowest level. [`LeafNode`] stores the full key and the value associated.

#[cfg(test)]
mod node_type_test;

use crate::{
    get_hash,
    metrics::{APTOS_JELLYFISH_INTERNAL_ENCODED_BYTES, APTOS_JELLYFISH_LEAF_ENCODED_BYTES},
    Key, TreeReader,
};
use anyhow::{ensure, Context, Result};
use aptos_crypto::{
    hash::{CryptoHash, SPARSE_MERKLE_PLACEHOLDER_HASH},
    HashValue,
};
use aptos_types::{
    nibble::{nibble_path::NibblePath, Nibble, ROOT_NIBBLE_HEIGHT},
    proof::{definition::NodeInProof, SparseMerkleInternalNode, SparseMerkleLeafNode},
    transaction::Version,
};
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::cast::FromPrimitive;
#[cfg(any(test, feature = "fuzzing"))]
use proptest::{collection::btree_map, prelude::*};
#[cfg(any(test, feature = "fuzzing"))]
use proptest_derive::Arbitrary;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    io::{prelude::*, Cursor, Read, SeekFrom, Write},
    mem::size_of,
    sync::Arc,
};
use thiserror::Error;

/// The unique key of each node.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct NodeKey {
    // The version at which the node is created.
    version: Version,
    // The nibble path this node represents in the tree.
    nibble_path: NibblePath,
}

impl NodeKey {
    /// Creates a new `NodeKey`.
    pub fn new(version: Version, nibble_path: NibblePath) -> Self {
        Self {
            version,
            nibble_path,
        }
    }

    /// A shortcut to generate a node key consisting of a version and an empty nibble path.
    pub fn new_empty_path(version: Version) -> Self {
        Self::new(version, NibblePath::new_even(vec![]))
    }

    /// Gets the version.
    pub fn version(&self) -> Version {
        self.version
    }

    /// Gets the nibble path.
    pub fn nibble_path(&self) -> &NibblePath {
        &self.nibble_path
    }

    /// Generates a child node key based on this node key.
    pub fn gen_child_node_key(&self, version: Version, n: Nibble) -> Self {
        let mut node_nibble_path = self.nibble_path().clone();
        node_nibble_path.push(n);
        Self::new(version, node_nibble_path)
    }

    /// Generates parent node key at the same version based on this node key.
    pub fn gen_parent_node_key(&self) -> Self {
        let mut node_nibble_path = self.nibble_path().clone();
        assert!(
            node_nibble_path.pop().is_some(),
            "Current node key is root.",
        );
        Self::new(self.version, node_nibble_path)
    }

    /// Sets the version to the given version.
    pub fn set_version(&mut self, version: Version) {
        self.version = version;
    }
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L128-136)
```rust
        let state_root_hash = txn_info_with_proof
            .transaction_info()
            .ensure_state_checkpoint_hash()?;
        ensure!(
            state_root_hash == manifest.root_hash,
            "Root hash mismatch with that in proof. root hash: {}, expected: {}",
            manifest.root_hash,
            state_root_hash,
        );
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
