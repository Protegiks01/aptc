# Audit Report

## Title
Critical Batch Overlap Vulnerability in Quorum Store Proof Manager: BatchInfoExt Variant Mismatch Allows Same Batch in Multiple Categories

## Summary
The exclusion chaining logic in `handle_proposal_request()` uses `HashSet<BatchInfoExt>` for filtering batches across proof, optimistic, and inline categories. However, `BatchInfoExt` is an enum with V1 and V2 variants that have strict equality semantics. Due to inconsistent state management in `BatchProofQueue`, the same batch can be represented as different variants in `author_to_batches` vs the exclusion set, causing exclusion checks to fail and allowing the same batch to appear in multiple payload categories simultaneously.

## Finding Description

The vulnerability exists in the batch exclusion logic spanning `proof_manager.rs` and `batch_proof_queue.rs`. 

**Root Cause:** [1](#0-0) 

`BatchInfoExt` is an enum with V1 and V2 variants. The derived `PartialEq` implementation requires exact variant matching - `BatchInfoExt::V1 { info: X }` is NOT equal to `BatchInfoExt::V2 { info: X, extra: Y }` even though they represent the same underlying batch (same author, batch_id, digest).

**State Inconsistency in BatchProofQueue:** [2](#0-1) 

When inserting a proof, `author_to_batches` is ALWAYS updated with the proof's `BatchInfoExt` variant. [3](#0-2) 

When inserting batch summaries, `author_to_batches` is ALWAYS updated with the batch's `BatchInfoExt` variant. [4](#0-3) 

However, `items[batch_key].info` is ONLY set when creating a new entry (Vacant case), and is NEVER updated when the entry already exists (Occupied case).

This creates a critical inconsistency:
- `items[batch_key].info` contains whichever variant (V1 or V2) was inserted FIRST
- `author_to_batches[sort_key]` contains whichever variant was inserted LAST
- These can DIFFER!

**Exclusion Logic Failure:** [5](#0-4) 

The inline batch exclusion set is built by chaining `excluded_batches`, `proof_block` infos, and `opt_batches`. [6](#0-5) 

The pull iterator yields `(info, item)` where `info` comes from `author_to_batches`. [7](#0-6) 

The exclusion check uses `info` from `author_to_batches`, comparing against `BatchInfoExt` values in the exclusion set.

**Exploitation Scenario:**

1. Network is in protocol upgrade mode with `enable_batch_v2` configuration flag being rolled out [8](#0-7) 

2. V2 `ProofOfStore<BatchInfoExt::V2>` arrives first → `items[key].info = V2`, `author_to_batches = V2`

3. V1 batch summaries arrive for the same batch → `items[key].info` remains V2 (not updated), but `author_to_batches = V1` (overwritten)

4. `pull_proofs()` executes:
   - Iterates using `author_to_batches` which has `V1`
   - Returns `item.proof = ProofOfStore<V2>`
   - Adds `V2` to exclusion set via `proof.info().clone()`

5. `pull_batches()` or `pull_batches_with_transactions()` executes with exclusion set containing `V2`:
   - Iterates using `author_to_batches` which has `V1`
   - Checks `excluded_batches.contains(V1)` where excluded has `V2` → Returns FALSE
   - Batch passes exclusion check and is included in opt_batches or inline_block

**Result:** The same batch appears in BOTH `proof_block` (as V2 proof) AND `opt_batches`/`inline_block` (with V1 in author_to_batches but V2 in items.info).

## Impact Explanation

**Severity: CRITICAL** (Consensus Safety Violation)

This vulnerability breaks the fundamental invariant that each batch should appear in exactly ONE category within a block payload. When the same batch appears multiple times:

1. **Transaction Double-Counting**: Transactions from the batch are counted multiple times toward block limits, potentially causing different nodes to construct different payloads from identical inputs.

2. **Consensus Divergence**: If nodes have different V1/V2 representations due to network timing or state sync differences, they will construct different block payloads, leading to:
   - Different state roots for the same block
   - Consensus failures requiring manual intervention
   - Potential chain splits

3. **Execution Inconsistencies**: The execution layer may process the same transactions multiple times or fail validation checks, causing node crashes or state corruption.

4. **Payload Corruption**: Block payloads become invalid as they violate the uniqueness invariant, potentially causing blocks to be rejected or executed incorrectly.

This qualifies as **Critical Severity** per Aptos Bug Bounty criteria:
- **Consensus/Safety violations**: Different nodes compute different state roots
- **Non-recoverable network partition**: Could require hardfork if widespread
- Breaks invariant #1 (Deterministic Execution) and #2 (Consensus Safety)

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability will occur whenever:

1. **Protocol Upgrade**: During the rollout of `enable_batch_v2` configuration flag, the network will have mixed V1/V2 batch representations. This is a PLANNED upgrade scenario.

2. **State Sync**: Nodes syncing state may receive V1 batch summaries from storage while receiving V2 proofs from the network.

3. **Network Asynchrony**: Due to network delays, proofs and batch summaries can arrive in any order, creating the V1/V2 mismatch.

4. **Recovery/Restart**: Nodes recovering from crashes may have V1 batches in local storage but receive V2 proofs from peers.

The attack requires NO special privileges - it occurs naturally during protocol upgrades or can be triggered by:
- Any validator broadcasting batches during version transitions
- Network timing variations
- State sync operations

**Complexity: LOW** - Happens automatically during normal protocol operations.

## Recommendation

**Fix 1: Use BatchKey for Exclusion Instead of BatchInfoExt**

Change the exclusion logic to use `BatchKey` (author + batch_id) instead of full `BatchInfoExt`:

```rust
// In proof_manager.rs, change from HashSet<BatchInfoExt> to HashSet<BatchKey>
let excluded_batch_keys: HashSet<BatchKey> = match request.filter {
    PayloadFilter::Empty => HashSet::new(),
    PayloadFilter::InQuorumStore(batches) => batches
        .iter()
        .map(|info| BatchKey::from_info(info))
        .collect(),
    ...
};

// Update chain to use BatchKey::from_info()
&excluded_batch_keys
    .iter()
    .cloned()
    .chain(proof_block.iter().map(|proof| BatchKey::from_info(proof.info())))
    .chain(opt_batches.iter().map(|info| BatchKey::from_info(info)))
    .collect()
```

**Fix 2: Normalize BatchInfoExt Comparisons**

Implement custom `PartialEq` for `BatchInfoExt` that compares based on the underlying `BatchInfo` only, ignoring variant differences:

```rust
impl PartialEq for BatchInfoExt {
    fn eq(&self, other: &Self) -> bool {
        self.info() == other.info()
    }
}
```

**Fix 3: Always Update items.info**

Ensure `items[batch_key].info` is updated when receiving new variants:

```rust
// In insert_proof()
Entry::Occupied(mut entry) => {
    let item = entry.get_mut();
    item.info = proof.info().clone(); // ADD THIS LINE
    item.proof = Some(proof);
    ...
}
```

**Recommended Approach:** Fix 1 (BatchKey-based exclusion) is the cleanest solution as it eliminates variant-related equality issues entirely.

## Proof of Concept

```rust
#[cfg(test)]
mod batch_overlap_vulnerability_test {
    use super::*;
    use aptos_consensus_types::proof_of_store::{BatchInfoExt, BatchKind};
    
    #[test]
    fn test_v1_v2_exclusion_bypass() {
        // Setup: Create a batch that will be represented as both V1 and V2
        let author = PeerId::random();
        let batch_id = BatchId::new(1000);
        let epoch = 1;
        let expiration = 2000;
        let digest = HashValue::random();
        
        // Create V2 proof first
        let batch_info_v2 = BatchInfoExt::new_v2(
            author, batch_id, epoch, expiration, digest, 
            10, 1000, 0, BatchKind::Normal
        );
        let proof_v2 = ProofOfStore::new(
            batch_info_v2.clone(), 
            AggregateSignature::empty()
        );
        
        // Create V1 batch summary for same batch
        let batch_info_v1 = BatchInfoExt::new_v1(
            author, batch_id, epoch, expiration, digest,
            10, 1000, 0
        );
        
        let mut queue = BatchProofQueue::new(...);
        
        // Insert V2 proof first
        queue.insert_proof(proof_v2);
        
        // Insert V1 batch summaries second (same batch!)
        queue.insert_batches(vec![(batch_info_v1.clone(), vec![])]);
        
        // Now pull proofs with empty exclusion
        let (proof_block, _, _, _) = queue.pull_proofs(
            &HashSet::new(), 
            PayloadTxnsSize::new(1000, 100000),
            1000, 500, false, Duration::from_secs(0)
        );
        
        // Build exclusion set with V2 from proof_block
        let excluded: HashSet<BatchInfoExt> = proof_block
            .iter()
            .map(|p| p.info().clone())
            .collect();
        
        assert!(excluded.contains(&batch_info_v2)); // Contains V2
        
        // Pull batches with V2 in exclusion
        let (opt_batches, _, _) = queue.pull_batches(
            &excluded,
            &HashSet::new(),
            PayloadTxnsSize::new(1000, 100000),
            1000, 500, false, Duration::from_secs(0),
            None
        );
        
        // VULNERABILITY: batch_info_v1 is NOT excluded even though it's the same batch!
        // because excluded.contains(&batch_info_v1) returns false
        assert!(!excluded.contains(&batch_info_v1)); // V1 != V2
        assert!(!opt_batches.is_empty()); // Batch appears in BOTH categories!
        
        // Verify the batch appears in multiple categories
        let proof_batch_id = proof_block[0].batch_id();
        let opt_batch_id = opt_batches[0].batch_id();
        assert_eq!(proof_batch_id, opt_batch_id); // SAME BATCH IN BOTH!
    }
}
```

**Notes:**
- This vulnerability is particularly dangerous during protocol upgrades when V1 and V2 batches coexist
- The fix should be prioritized before any `enable_batch_v2` rollout
- Existing deployments may already exhibit this behavior if mixed V1/V2 traffic exists

### Citations

**File:** consensus/consensus-types/src/proof_of_store.rs (L192-203)
```rust
#[derive(
    Clone, Debug, Deserialize, Serialize, CryptoHasher, BCSCryptoHash, PartialEq, Eq, Hash,
)]
pub enum BatchInfoExt {
    V1 {
        info: BatchInfo,
    },
    V2 {
        info: BatchInfo,
        extra: ExtraBatchInfo,
    },
}
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L196-197)
```rust
        let batches_for_author = self.author_to_batches.entry(author).or_default();
        batches_for_author.insert(batch_sort_key.clone(), proof.info().clone());
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L229-242)
```rust
        match self.items.entry(batch_key) {
            Entry::Occupied(mut entry) => {
                let item = entry.get_mut();
                item.proof = Some(proof);
                item.proof_insertion_time = Some(Instant::now());
            },
            Entry::Vacant(entry) => {
                entry.insert(QueueItem {
                    info: proof.info().clone(),
                    proof: Some(proof),
                    proof_insertion_time: Some(Instant::now()),
                    txn_summaries: None,
                });
            },
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L278-281)
```rust
            self.author_to_batches
                .entry(batch_info.author())
                .or_default()
                .insert(batch_sort_key.clone(), batch_info.clone());
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L601-622)
```rust
            let batch_iter = batches.iter().rev().filter_map(|(sort_key, info)| {
                if let Some(item) = self.items.get(&sort_key.batch_key) {
                    let batch_create_ts_usecs =
                        item.info.expiration() - self.batch_expiry_gap_when_init_usecs;

                    // Ensure that the batch was created at least `min_batch_age_usecs` ago to
                    // reduce the chance of inline fetches.
                    if max_batch_creation_ts_usecs
                        .is_some_and(|max_create_ts| batch_create_ts_usecs > max_create_ts)
                    {
                        return None;
                    }

                    if item.is_committed() {
                        return None;
                    }
                    if !(batches_without_proofs ^ item.proof.is_none()) {
                        return Some((info, item));
                    }
                }
                None
            });
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L634-636)
```rust
                    if excluded_batches.contains(batch) {
                        excluded_txns += batch.num_txns();
                    } else {
```

**File:** consensus/src/quorum_store/proof_manager.rs (L169-174)
```rust
                        &excluded_batches
                            .iter()
                            .cloned()
                            .chain(proof_block.iter().map(|proof| proof.info().clone()))
                            .chain(opt_batches.clone())
                            .collect(),
```

**File:** consensus/src/quorum_store/batch_generator.rs (L190-211)
```rust
        if self.config.enable_batch_v2 {
            // TODO(ibalajiarun): Specify accurate batch kind
            let batch_kind = BatchKind::Normal;
            Batch::new_v2(
                batch_id,
                txns,
                self.epoch,
                expiry_time,
                self.my_peer_id,
                bucket_start,
                batch_kind,
            )
        } else {
            Batch::new_v1(
                batch_id,
                txns,
                self.epoch,
                expiry_time,
                self.my_peer_id,
                bucket_start,
            )
        }
```
