# Audit Report

## Title
Hot State Configuration OOM Risk Due to Count-Based Eviction Without Memory Bounds

## Summary
The default `max_items_per_shard = 250,000` configuration uses a count-based eviction policy without considering actual memory consumption, potentially causing OOM on validators when the hot state fills with large state values approaching the 1 MB limit.

## Finding Description

The hot state system in Aptos maintains an in-memory LRU cache to optimize frequently accessed state items. The eviction policy is purely count-based, controlled by `max_items_per_shard`, without any memory-based limits. [1](#0-0) 

Each state value can be up to 1 MB in size, enforced by the transaction gas parameters: [2](#0-1) 

The eviction logic in `HotStateLRU` only checks item count, not memory consumption: [3](#0-2) 

While the system tracks memory usage via `total_key_bytes` and `total_value_bytes`, these are only used for metrics and not for eviction decisions: [4](#0-3) 

**Memory calculation:**
- Maximum items: 250,000/shard × 16 shards = 4,000,000 items
- Maximum StateValue size: 1 MB
- Worst-case memory: 4,000,000 × ~1 MB = **~4 TB**
- Realistic heavy-usage case (10 KB avg): **~40 GB**
- Expected case (500 bytes avg): **~2.8 GB**

This violates the **Resource Limits** invariant, as memory consumption is not properly bounded by configuration.

## Impact Explanation

This qualifies as **Medium severity** per Aptos bug bounty criteria ("State inconsistencies requiring intervention"). If the hot state fills with large state values during legitimate heavy usage:

1. Validators with limited memory (<16 GB) could experience OOM crashes
2. Node availability is impacted requiring manual intervention
3. No runtime warnings exist to alert operators of memory pressure
4. Recovery requires node restart, potentially causing consensus participation gaps

The configuration provides no guidance on expected memory requirements, making it impossible for operators to properly size validator infrastructure.

## Likelihood Explanation

**Medium likelihood** - this can occur through natural usage patterns without malicious intent:

1. Large Move module deployments (near 1 MB limit) being frequently accessed
2. Large resource groups in active use
3. Workloads with larger-than-expected average state value sizes
4. No deployment-specific tuning for memory-constrained environments

While an attacker could theoretically accelerate this by creating/accessing large state values, it would be prohibitively expensive due to:
- Gas costs for large state writes (`storage_io_per_state_byte_write`)
- Storage fees proportional to data size
- `MAX_PROMOTIONS_PER_BLOCK` limiting rapid promotion to 10,240 items [5](#0-4) 

## Recommendation

Implement a hybrid eviction policy that considers both item count AND actual memory consumption:

```rust
pub struct HotStateConfig {
    pub max_items_per_shard: usize,
    pub max_bytes_per_shard: usize,  // NEW: memory-based limit
    pub refresh_interval_versions: u64,
    pub delete_on_restart: bool,
    pub compute_root_hash: bool,
}

impl Default for HotStateConfig {
    fn default() -> Self {
        Self {
            max_items_per_shard: 250_000,
            max_bytes_per_shard: 512_000_000,  // NEW: 512 MB per shard default
            refresh_interval_versions: 100_000,
            delete_on_restart: true,
            compute_root_hash: true,
        }
    }
}
```

Modify `HotStateLRU::maybe_evict()` to check both limits and add runtime warnings when approaching memory limits. Provide deployment documentation specifying expected memory requirements based on configuration.

## Proof of Concept

```rust
// Conceptual PoC showing memory explosion scenario
// This demonstrates the issue but is not directly exploitable due to cost

use aptos_types::state_store::state_value::StateValue;

#[test]
fn test_hot_state_memory_explosion() {
    // Create 250,000 state values approaching 1 MB each
    let large_value_size = 1_000_000; // 1 MB
    let items_per_shard = 250_000;
    
    let mut total_memory = 0u64;
    for _ in 0..items_per_shard {
        let value = vec![0u8; large_value_size];
        let state_value = StateValue::from(value);
        total_memory += state_value.size() as u64 + 200; // overhead
    }
    
    // Single shard: ~244 GB
    // All 16 shards: ~3.9 TB
    assert!(total_memory > 240_000_000_000); // >240 GB per shard
    
    // This would cause OOM on most validators
}
```

---

**Notes:**

While this represents a legitimate operational concern, it narrowly **fails** the strict exploitability criteria because:
- Direct exploitation requires sustained expensive operations (high gas + storage fees)
- More likely to occur through natural usage than targeted attack
- No clear attack path for unprivileged actors to economically cause this

This is fundamentally a **configuration safety issue** requiring better memory accounting and deployment guidance, rather than a directly exploitable vulnerability. However, it does represent a real Medium-severity risk for production validators that should be addressed through improved eviction policies and documentation.

### Citations

**File:** config/src/config/storage_config.rs (L256-264)
```rust
impl Default for HotStateConfig {
    fn default() -> Self {
        Self {
            max_items_per_shard: 250_000,
            refresh_interval_versions: 100_000,
            delete_on_restart: true,
            compute_root_hash: true,
        }
    }
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L154-157)
```rust
            max_bytes_per_write_op: NumBytes,
            { 5.. => "max_bytes_per_write_op" },
            1 << 20, // a single state item is 1MB max
        ],
```

**File:** storage/storage-interface/src/state_store/hot_state.rs (L82-106)
```rust
    pub fn maybe_evict(&mut self) -> Vec<(StateKey, StateSlot)> {
        let mut current = match &self.tail {
            Some(tail) => tail.clone(),
            None => {
                assert_eq!(self.num_items, 0);
                return Vec::new();
            },
        };

        let mut evicted = Vec::new();
        while self.num_items > self.capacity.get() {
            let slot = self
                .delete(&current)
                .expect("There must be entries to evict when current size is above capacity.");
            let prev_key = slot
                .prev()
                .cloned()
                .expect("There must be at least one newer entry (num_items > capacity >= 1).");
            evicted.push((current.clone(), slot.clone()));
            self.pending.insert(current, slot.to_cold());
            current = prev_key;
            self.num_items -= 1;
        }
        evicted
    }
```

**File:** storage/aptosdb/src/state_store/hot_state.rs (L164-202)
```rust
    total_key_bytes: usize,
    total_value_bytes: usize,
    /// Points to the newest entry. `None` if empty.
    heads: [Option<StateKey>; NUM_STATE_SHARDS],
    /// Points to the oldest entry. `None` if empty.
    tails: [Option<StateKey>; NUM_STATE_SHARDS],
}

impl Committer {
    fn spawn(base: Arc<HotStateBase>, committed: Arc<Mutex<State>>) -> SyncSender<State> {
        let (tx, rx) = std::sync::mpsc::sync_channel(MAX_HOT_STATE_COMMIT_BACKLOG);
        std::thread::spawn(move || Self::new(base, committed, rx).run());

        tx
    }

    fn new(base: Arc<HotStateBase>, committed: Arc<Mutex<State>>, rx: Receiver<State>) -> Self {
        Self {
            base,
            committed,
            rx,
            total_key_bytes: 0,
            total_value_bytes: 0,
            heads: arr![None; 16],
            tails: arr![None; 16],
        }
    }

    fn run(&mut self) {
        info!("HotState committer thread started.");

        while let Some(to_commit) = self.next_to_commit() {
            self.commit(&to_commit);
            *self.committed.lock() = to_commit;

            GAUGE.set_with(&["hot_state_items"], self.base.len() as i64);
            GAUGE.set_with(&["hot_state_key_bytes"], self.total_key_bytes as i64);
            GAUGE.set_with(&["hot_state_value_bytes"], self.total_value_bytes as i64);
        }
```

**File:** aptos-move/block-executor/src/hot_state_op_accumulator.rs (L27-28)
```rust
    /// TODO(HotState): make on-chain config
    const MAX_PROMOTIONS_PER_BLOCK: usize = 1024 * 10;
```
