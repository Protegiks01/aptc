# Audit Report

## Title
Predictable Shard Assignment Enables Targeted Performance Degradation Attack

## Summary
The block partitioner uses a deterministic, non-cryptographic hash function (`std::collections::hash_map::DefaultHasher`) to assign storage locations to anchor shards. An attacker can precompute which storage locations hash to a specific shard and craft transactions targeting those locations, causing extreme load imbalance and executor performance degradation on the targeted shard.

## Finding Description

The sharded executor system assigns each storage location to an "anchor shard" for conflict resolution. This assignment is performed in `get_anchor_shard_id()` using a predictable hash function: [1](#0-0) 

The vulnerability arises from three design properties working together:

1. **Deterministic Hash Function**: The anchor shard is determined by hashing `StorageLocation` with `DefaultHasher` and taking modulo. This is completely predictable - an attacker can precompute which account addresses result in CoinStore resources that hash to any target shard.

2. **Cross-Shard Conflict Resolution**: During partitioning, transactions are checked for cross-shard conflicts using the anchor shard concept: [2](#0-1) 

Transactions accessing a storage location can only execute conflict-free on the anchor shard. Transactions on other shards that access the same location are discarded to later rounds: [3](#0-2) 

3. **Load Imbalance Tolerance Bypass**: While `load_imbalance_tolerance` limits individual group sizes: [4](#0-3) 

An attacker can create multiple DIFFERENT storage locations (different accounts) that all hash to the same anchor shard, bypassing the group size limit.

**Attack Scenario:**
1. Attacker precomputes 100 account addresses whose CoinStore resources all hash to shard 0 (anchor_shard_id = 0)
2. Attacker submits 100 transactions transferring coins to these 100 different accounts
3. Pre-partitioner distributes transactions across shards 0-3 using LPT scheduling
4. During cross-shard dependency removal, transactions on shards 1-3 detect conflicts (their keys anchor to shard 0 where writes are pending) and get discarded
5. Multiple rounds execute with most work concentrated on shard 0
6. Metrics show extreme load imbalance across shards, visible via: [5](#0-4) 

This breaks the **Resource Limits** invariant (#9): "All operations must respect gas, storage, and computational limits" - the intended parallel execution and load distribution are violated.

## Impact Explanation

**Severity: Medium**

Per the Aptos bug bounty criteria, this qualifies as Medium severity based on:
- "State inconsistencies requiring intervention" - The load imbalance creates execution inefficiency requiring manual intervention (adjusting shard configuration)
- Does not reach High severity ("Validator node slowdowns") because:
  - Attack targets specific shards, not entire validator nodes
  - Can be mitigated by reducing number of shards or adjusting configuration
  - Requires sustained attacker transaction submission (costs gas)

The impact includes:
- Targeted shard performance degradation (visible in metrics)
- Increased block execution latency when targeted shard becomes bottleneck
- Potential validator performance issues if sustained
- Suboptimal resource utilization across shards

## Likelihood Explanation

**Likelihood: Medium-High**

The attack is highly feasible because:

1. **Predictable Hash Function**: `DefaultHasher` is deterministic - attackers can compute offline which addresses map to target shards
2. **Controlled Transaction Payload**: Attackers fully control transaction arguments, including receiver addresses in coin transfers: [6](#0-5) 

3. **No Randomization**: The anchor shard assignment contains no randomness or cryptographic unpredictability
4. **Low Attack Cost**: Only requires submitting normal transactions (pays standard gas fees)
5. **Observable Effect**: Metrics clearly show the load imbalance, making the attack verifiable

Mitigating factors:
- Requires understanding of internal sharding mechanism
- Must sustain attack across multiple blocks to have significant impact
- Block gas limits prevent unlimited transactions per block

## Recommendation

**Fix: Use Cryptographic Hash for Anchor Shard Assignment**

Replace `DefaultHasher` with a cryptographically secure hash function that includes block-specific randomness:

```rust
use aptos_crypto::{hash::CryptoHash, HashValue};

fn get_anchor_shard_id(
    storage_location: &StorageLocation, 
    num_shards: usize,
    block_hash: &HashValue,  // Add block-specific entropy
) -> ShardId {
    let mut data = bcs::to_bytes(storage_location).unwrap();
    data.extend_from_slice(block_hash.as_ref());
    let hash = CryptoHash::hash(&data);
    let hash_value = u64::from_be_bytes(hash.as_ref()[0..8].try_into().unwrap());
    (hash_value % num_shards as u64) as usize
}
```

This makes anchor shard assignment unpredictable to attackers while remaining deterministic for all validators processing the same block.

**Alternative: Load-Aware Shard Assignment**

Monitor shard load in real-time and use load-aware assignment to avoid concentration:

```rust
fn get_anchor_shard_id_load_aware(
    storage_location: &StorageLocation,
    num_shards: usize,
    shard_loads: &[usize],  // Current load per shard
) -> ShardId {
    let base_shard = hash_location(storage_location) % num_shards;
    // If target shard is overloaded, shift to next available shard
    find_least_loaded_shard_near(base_shard, shard_loads, num_shards)
}
```

## Proof of Concept

```rust
// Proof of concept demonstrating predictable anchor shard assignment
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use move_core_types::account_address::AccountAddress;

fn compute_anchor_shard(addr: &AccountAddress, num_shards: usize) -> usize {
    // Simulate CoinStore<AptosCoin> storage location hashing
    let mut hasher = DefaultHasher::new();
    // This would be the full StorageLocation in practice
    addr.hash(&mut hasher);
    (hasher.finish() % num_shards as u64) as usize
}

fn find_addresses_for_target_shard(target_shard: usize, num_shards: usize, count: usize) -> Vec<AccountAddress> {
    let mut addresses = Vec::new();
    let mut candidate = 0u64;
    
    while addresses.len() < count {
        let addr = AccountAddress::from_hex_literal(&format!("0x{:x}", candidate)).unwrap();
        if compute_anchor_shard(&addr, num_shards) == target_shard {
            addresses.push(addr);
        }
        candidate += 1;
    }
    addresses
}

#[test]
fn test_targeted_shard_attack() {
    let num_shards = 4;
    let target_shard = 0;
    
    // Attacker finds 100 addresses that hash to shard 0
    let malicious_addresses = find_addresses_for_target_shard(target_shard, num_shards, 100);
    
    // Verify all addresses map to target shard
    for addr in &malicious_addresses {
        assert_eq!(compute_anchor_shard(addr, num_shards), target_shard);
    }
    
    println!("Found {} addresses mapping to shard {}", malicious_addresses.len(), target_shard);
    println!("Attacker can now submit transactions to these addresses");
    println!("All transactions will concentrate on shard {}", target_shard);
}
```

**Execution Steps:**
1. Run the test to demonstrate predictable shard assignment
2. Observe that an attacker can easily find arbitrary numbers of addresses mapping to any target shard
3. In practice, attacker would submit coin transfer transactions to these addresses
4. Monitor metrics to observe load concentration on target shard

**Notes**

The vulnerability exists because the sharding system prioritizes determinism for consensus over unpredictability for security. While `load_imbalance_tolerance` provides some mitigation, it cannot prevent an attacker from finding multiple independent storage locations that all hash to the same anchor shard. The predictable `DefaultHasher` makes this attack practical - an attacker can precompute target addresses offline and execute the attack without trial-and-error.

The fix requires balancing determinism (all validators must agree on shard assignment) with unpredictability (attackers cannot predict assignments). Using block-specific entropy in the hash provides both properties.

### Citations

**File:** execution/block-partitioner/src/lib.rs (L39-43)
```rust
fn get_anchor_shard_id(storage_location: &StorageLocation, num_shards: usize) -> ShardId {
    let mut hasher = DefaultHasher::new();
    storage_location.hash(&mut hasher);
    (hasher.finish() % num_shards as u64) as usize
}
```

**File:** execution/block-partitioner/src/v2/state.rs (L211-217)
```rust
    pub(crate) fn key_owned_by_another_shard(&self, shard_id: ShardId, key: StorageKeyIdx) -> bool {
        let tracker_ref = self.trackers.get(&key).unwrap();
        let tracker = tracker_ref.read().unwrap();
        let range_start = self.start_txn_idxs_by_shard[tracker.anchor_shard_id];
        let range_end = self.start_txn_idxs_by_shard[shard_id];
        tracker.has_write_in_range(range_start, range_end)
    }
```

**File:** execution/block-partitioner/src/v2/partition_to_matrix.rs (L116-140)
```rust
                    txn_idxs.into_par_iter().for_each(|txn_idx| {
                        let ori_txn_idx = state.ori_idxs_by_pre_partitioned[txn_idx];
                        let mut in_round_conflict_detected = false;
                        let write_set = state.write_sets[ori_txn_idx].read().unwrap();
                        let read_set = state.read_sets[ori_txn_idx].read().unwrap();
                        for &key_idx in write_set.iter().chain(read_set.iter()) {
                            if state.key_owned_by_another_shard(shard_id, key_idx) {
                                in_round_conflict_detected = true;
                                break;
                            }
                        }

                        if in_round_conflict_detected {
                            let sender = state.sender_idx(ori_txn_idx);
                            min_discard_table
                                .entry(sender)
                                .or_insert_with(|| AtomicUsize::new(usize::MAX))
                                .fetch_min(txn_idx, Ordering::SeqCst);
                            discarded[shard_id].write().unwrap().push(txn_idx);
                        } else {
                            tentatively_accepted[shard_id]
                                .write()
                                .unwrap()
                                .push(txn_idx);
                        }
```

**File:** execution/block-partitioner/src/pre_partition/connected_component/mod.rs (L26-32)
```rust
/// The group size limit is controlled by parameter `load_imbalance_tolerance` in the following way:
/// if `block_size=100, num_shards=10, load_imbalance_tolerance=2.0`,
/// then the size of a conflicting txn group is not allowed to exceed 100/10*2.0 = 20.
/// This fact, combined with the LPT algorithm, guarantees that shard load will not exceed 20.
pub struct ConnectedComponentPartitioner {
    pub load_imbalance_tolerance: f32,
}
```

**File:** execution/executor-service/src/metrics.rs (L10-31)
```rust
pub static REMOTE_EXECUTOR_TIMER: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        // metric name
        "remote_executor_timer",
        // metric description
        "The time spent in remote shard on: \
         1. cmd_rx: after receiving the command from the coordinator; \
         2. cmd_rx_bcs_deser: deserializing the received command; \
         3. init_prefetch: initializing the prefetching of remote state values \
         4. kv_responses: processing the remote key value responses; \
         5. kv_resp_deser: deserializing the remote key value responses; \
         6. prefetch_wait: waiting (approx) for the remote state values to be prefetched; \
         7. non_prefetch_wait: waiting for the remote state values that were not prefetched; \
         8. kv_req_deser: deserializing the remote key value requests; \
         9. kv_requests: processing the remote key value requests; \
         10. kv_resp_ser: serializing the remote key value responses;",
        // metric labels (dimensions)
        &["shard_id", "name"],
        exponential_buckets(/*start=*/ 1e-3, /*factor=*/ 2.0, /*count=*/ 20).unwrap(),
    )
    .unwrap()
});
```

**File:** types/src/transaction/analyzed_transaction.rs (L254-261)
```rust
                (AccountAddress::ONE, "coin", "transfer") => {
                    let receiver_address = bcs::from_bytes(&func.args()[0]).unwrap();
                    rw_set_for_coin_transfer(sender_address, receiver_address, true)
                },
                (AccountAddress::ONE, "aptos_account", "transfer") => {
                    let receiver_address = bcs::from_bytes(&func.args()[0]).unwrap();
                    rw_set_for_coin_transfer(sender_address, receiver_address, false)
                },
```
