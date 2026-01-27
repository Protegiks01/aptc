# Audit Report

## Title
Missing Invariant Validation in StaleNodeIndex Schema Enables Incorrect Node Pruning via Data Corruption

## Summary
The `StaleNodeIndexSchema` does not validate that `node_key.version()` is less than `stale_since_version`, violating the critical invariant that nodes can only become stale after they are created. This lack of validation allows corrupted or malformed database entries to cause premature deletion of active Merkle tree nodes, leading to state inconsistencies and potential consensus disruption.

## Finding Description

The `StaleNodeIndex` structure tracks when Jellyfish Merkle tree nodes become obsolete and ready for pruning. It contains two key fields: [1](#0-0) 

The critical invariant is: **`node_key.version() < stale_since_version`** because a node created at version V can only become stale at some future version V' where V' > V.

However, the schema's encoding and decoding functions perform no validation of this relationship: [2](#0-1) 

The `decode_key` function simply deserializes both components without checking their relationship. Similarly, when writing to the database, the only validations performed are for shard_id matching: [3](#0-2) 

The pruner retrieves stale nodes based solely on `stale_since_version`: [4](#0-3) 

And then deletes nodes using the `node_key`: [5](#0-4) 

**Attack Scenario via Database Corruption:**

1. Blockchain reaches version 10,000
2. An active node N exists at version 9,000 (`node_key.version() = 9,000`)
3. Database corruption (bit flip, disk error, or restoration bug) creates an invalid entry:
   - `stale_since_version: 5,000`
   - `node_key: NodeKey { version: 10,000, ... }`
4. Pruner runs with `target_version = 7,000`
5. Since `stale_since_version (5,000) <= target_version (7,000)`, the entry is processed
6. Node at version 10,000 is deleted prematurely
7. Queries for state at version ≥ 10,000 fail with "node not found"
8. State synchronization breaks, consensus disrupted

## Impact Explanation

This violates **Critical Invariant #4: State Consistency** - "State transitions must be atomic and verifiable via Merkle proofs."

**Medium Severity** ($10,000 category): "State inconsistencies requiring intervention"

- Active Merkle tree nodes can be incorrectly deleted
- Historical state queries fail
- State proof generation becomes impossible
- New nodes cannot synchronize state
- Requires database restoration or full resync
- Does not directly steal funds but breaks state integrity

## Likelihood Explanation

**Likelihood: Medium-Low**

While normal code paths maintain the invariant correctly, the lack of validation creates risk: [6](#0-5) 

**Risk Factors:**
- Database corruption events (hardware failures, cosmic rays)
- Bugs in future code modifications to tree update logic
- Incorrect backup/restore operations
- Edge cases in cross-epoch node handling
- No defense-in-depth protection

**Mitigation Factor:**
- High-level version validation exists at commit time [7](#0-6) 

However, this doesn't protect against corruption or schema-level bugs.

## Recommendation

Add validation in the `decode_key` function to enforce the invariant:

```rust
fn decode_key(data: &[u8]) -> Result<Self> {
    const VERSION_SIZE: usize = size_of::<Version>();

    ensure_slice_len_gt(data, VERSION_SIZE)?;
    let stale_since_version = (&data[..VERSION_SIZE]).read_u64::<BigEndian>()?;
    let node_key = NodeKey::decode(&data[VERSION_SIZE..])?;

    // ADDED: Validate version relationship
    ensure!(
        node_key.version() < stale_since_version,
        "Invalid StaleNodeIndex: node cannot become stale (version {}) before it was created (version {})",
        stale_since_version,
        node_key.version()
    );

    Ok(Self {
        stale_since_version,
        node_key,
    })
}
```

Additionally, add validation during write operations in `create_jmt_commit_batch_for_shard`:

```rust
stale_node_index_batch.iter().try_for_each(|row| {
    ensure!(row.node_key.get_shard_id() == shard_id, "shard_id mismatch");
    
    // ADDED: Validate version invariant
    ensure!(
        row.node_key.version() < row.stale_since_version,
        "Invalid StaleNodeIndex: node_key.version() ({}) must be less than stale_since_version ({})",
        row.node_key.version(),
        row.stale_since_version
    );
    
    // ... rest of the logic
})?;
```

## Proof of Concept

```rust
#[cfg(test)]
mod invariant_violation_test {
    use super::*;
    use aptos_jellyfish_merkle::node_type::NodeKey;
    use aptos_types::nibble::nibble_path::NibblePath;

    #[test]
    #[should_panic(expected = "node cannot become stale")]
    fn test_invalid_version_relationship_detected() {
        // Create a StaleNodeIndex with invalid version relationship
        let node_key = NodeKey::new(10000, NibblePath::new_even(vec![]));
        let stale_index = StaleNodeIndex {
            stale_since_version: 5000,  // Invalid: less than node_key.version()
            node_key,
        };

        // This should panic with validation enabled
        let encoded = <StaleNodeIndex as KeyCodec<StaleNodeIndexSchema>>::encode_key(&stale_index).unwrap();
        let _decoded = <StaleNodeIndex as KeyCodec<StaleNodeIndexSchema>>::decode_key(&encoded).unwrap();
    }

    #[test]
    fn test_valid_version_relationship_accepted() {
        // Create a StaleNodeIndex with valid version relationship
        let node_key = NodeKey::new(5000, NibblePath::new_even(vec![]));
        let stale_index = StaleNodeIndex {
            stale_since_version: 10000,  // Valid: greater than node_key.version()
            node_key,
        };

        // This should succeed
        let encoded = <StaleNodeIndex as KeyCodec<StaleNodeIndexSchema>>::encode_key(&stale_index).unwrap();
        let decoded = <StaleNodeIndex as KeyCodec<StaleNodeIndexSchema>>::decode_key(&encoded).unwrap();
        
        assert_eq!(decoded.stale_since_version, 10000);
        assert_eq!(decoded.node_key.version(), 5000);
    }
}
```

**Notes:**

The vulnerability represents a violation of defense-in-depth principles. While normal operation maintains the invariant through higher-level version validation, the schema layer provides no protection against corruption or bugs. The lack of validation at the schema boundary means malformed entries can silently propagate through the system until they cause pruning of active nodes, resulting in irrecoverable state inconsistencies.

### Citations

**File:** storage/jellyfish-merkle/src/lib.rs (L195-201)
```rust
pub struct StaleNodeIndex {
    /// The version since when the node is overwritten and becomes stale.
    pub stale_since_version: Version,
    /// The [`NodeKey`](node_type/struct.NodeKey.html) identifying the node associated with this
    /// record.
    pub node_key: NodeKey,
}
```

**File:** storage/jellyfish-merkle/src/lib.rs (L243-248)
```rust
    pub fn put_stale_node(&mut self, node_key: NodeKey, stale_since_version: Version) {
        self.stale_node_index_batch[0].push(StaleNodeIndex {
            node_key,
            stale_since_version,
        });
    }
```

**File:** storage/aptosdb/src/schema/stale_node_index/mod.rs (L38-59)
```rust
impl KeyCodec<StaleNodeIndexSchema> for StaleNodeIndex {
    fn encode_key(&self) -> Result<Vec<u8>> {
        let mut encoded = vec![];
        encoded.write_u64::<BigEndian>(self.stale_since_version)?;
        encoded.write_all(&self.node_key.encode()?)?;

        Ok(encoded)
    }

    fn decode_key(data: &[u8]) -> Result<Self> {
        const VERSION_SIZE: usize = size_of::<Version>();

        ensure_slice_len_gt(data, VERSION_SIZE)?;
        let stale_since_version = (&data[..VERSION_SIZE]).read_u64::<BigEndian>()?;
        let node_key = NodeKey::decode(&data[VERSION_SIZE..])?;

        Ok(Self {
            stale_since_version,
            node_key,
        })
    }
}
```

**File:** storage/aptosdb/src/state_merkle_db.rs (L376-386)
```rust
        stale_node_index_batch.iter().try_for_each(|row| {
            ensure!(row.node_key.get_shard_id() == shard_id, "shard_id mismatch");
            if previous_epoch_ending_version.is_some()
                && row.node_key.version() <= previous_epoch_ending_version.unwrap()
            {
                batch.put::<StaleNodeIndexCrossEpochSchema>(row, &())
            } else {
                // These are processed by the state merkle pruner.
                batch.put::<StaleNodeIndexSchema>(row, &())
            }
        })?;
```

**File:** storage/aptosdb/src/pruner/state_merkle_pruner/mod.rs (L205-210)
```rust
        while indices.len() < limit {
            if let Some((index, _)) = iter.next().transpose()? {
                next_version = Some(index.stale_since_version);
                if index.stale_since_version <= target_version {
                    indices.push(index);
                    continue;
```

**File:** storage/aptosdb/src/pruner/state_merkle_pruner/state_merkle_shard_pruner.rs (L73-76)
```rust
            indices.into_iter().try_for_each(|index| {
                batch.delete::<JellyfishMerkleNodeSchema>(&index.node_key)?;
                batch.delete::<S>(&index)
            })?;
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L253-258)
```rust
        ensure!(
            chunk.first_version == next_version,
            "The first version passed in ({}), and the next version expected by db ({}) are inconsistent.",
            chunk.first_version,
            next_version,
        );
```
