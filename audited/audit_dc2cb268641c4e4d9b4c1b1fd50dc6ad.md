# Audit Report

## Title
Hot State Promotion Quota Exhaustion Enables Performance Degradation Attack

## Summary
An attacker can exploit the hardcoded 10,240 per-block limit on hot state promotions to fill the promotion quota with reads from arbitrary state keys, preventing critical system state (governance proposals, staking pools) from being cached in hot state, forcing expensive cold storage reads and degrading validator performance.

## Finding Description

The `BlockHotStateOpAccumulator` in `hot_state_op_accumulator.rs` tracks state keys that should be promoted to hot state (L2 cache) at block epilogue. The promotion mechanism has a hardcoded limit to prevent heavy epilogues: [1](#0-0) 

When transactions execute, reads are added to the promotion queue in the order transactions are processed: [2](#0-1) 

Once the quota is reached, subsequent reads are silently ignored (the `continue` statement on line 59), and a counter is incremented.

**Attack Mechanism:**

1. **Transaction Ordering Control**: Mempool orders transactions primarily by gas price: [3](#0-2) 

2. **Early Queue Filling**: An attacker submits transactions with high gas prices that read from 10,240+ unique, arbitrary state keys. Due to high gas price, these transactions execute early in the block.

3. **Quota Exhaustion**: As attacker transactions execute, their reads fill the `to_make_hot` set. The accumulator processes transactions sequentially during block execution: [4](#0-3) 

4. **Critical State Exclusion**: When legitimate transactions later read critical system state (governance proposals at `@aptos_framework`, staking pool configurations), these reads are rejected because the quota is full.

5. **Performance Impact**: In subsequent blocks, reads of critical state miss the hot cache and require expensive cold storage lookups: [5](#0-4) 

The cache miss forces a disk I/O operation, significantly slower than memory access.

6. **Sustained Attack**: The attacker can repeat this in every block, maintaining continuous performance degradation for critical system operations.

## Impact Explanation

This qualifies as **High Severity** per Aptos bug bounty criteria ("Validator node slowdowns"). 

**Affected Operations:**
- Governance proposal queries by validators and users
- Staking pool state reads during reward calculations
- System configuration reads (consensus config, gas schedule)
- Any frequently-accessed state not written during the block

**Quantified Impact:**
- Cold storage reads are orders of magnitude slower than hot state cache hits
- If governance proposals are queried frequently but not cached, each query incurs disk I/O
- Sustained attack across multiple blocks can cause noticeable validator slowdowns
- Impact scales with transaction volume that needs to read critical uncached state

**Severity Justification:**
While this doesn't break consensus correctness or cause fund loss, it degrades validator performance system-wide by preventing performance-critical state from being cached. The TODO comment suggests this was recognized as needing configuration but hasn't been addressed: [6](#0-5) 

## Likelihood Explanation

**Likelihood: Medium-High**

**Attacker Requirements:**
- Sufficient funds to pay gas fees for 10,240+ state reads per block
- Ability to identify arbitrary state keys to read (trivial - can be random keys)
- Ability to pay higher gas prices than legitimate transactions

**Economic Feasibility:**
- State reads consume gas but are relatively cheap operations
- Attacker only needs to outbid legitimate transactions on gas price
- The attack can be profitable if the performance degradation impacts network operations sufficiently

**Complexity:**
- Attack is straightforward to execute
- No special privileges required
- Can be automated and sustained across blocks

**Detection Difficulty:**
- Monitoring would show the `max_promotions_per_block_hit` counter incrementing
- However, distinguishing malicious from legitimate quota exhaustion is difficult

## Recommendation

**Short-term Mitigation:**
1. Implement priority-based promotion to ensure critical system state (addresses under `@aptos_framework`, `@aptos_governance`, staking pools) are promoted before user state
2. Add on-chain monitoring and alerting for quota exhaustion

**Long-term Solution:**
Implement the TODO from line 27 - make `max_promotions_per_block` an on-chain configuration parameter with:
- Dynamic adjustment based on block execution characteristics
- Separate quotas for system state vs user state
- Priority queuing mechanism that ensures critical state promotion

**Proposed Code Fix:**

```rust
pub struct BlockHotStateOpAccumulator<Key> {
    to_make_hot_system: BTreeSet<Key>,  // Priority queue for system state
    to_make_hot_user: BTreeSet<Key>,     // Regular queue for user state
    writes: hashbrown::HashSet<Key>,
    max_promotions_system: usize,         // Higher limit for critical state
    max_promotions_user: usize,           // Lower limit for user state
}

pub fn add_transaction<'a>(
    &mut self,
    writes: impl Iterator<Item = &'a Key>,
    reads: impl Iterator<Item = &'a Key>,
) where Key: 'a {
    for key in reads {
        if self.writes.contains(key) {
            continue;
        }
        
        // Prioritize system addresses
        if is_system_address(key) {
            if self.to_make_hot_system.len() < self.max_promotions_system {
                self.to_make_hot_system.insert(key.clone());
            }
        } else {
            if self.to_make_hot_user.len() < self.max_promotions_user {
                self.to_make_hot_user.insert(key.clone());
            }
        }
    }
}
```

## Proof of Concept

**Rust Test Scenario:**

```rust
#[test]
fn test_hot_state_quota_exhaustion_attack() {
    let mut accumulator = BlockHotStateOpAccumulator::<StateKey>::new();
    
    // Attacker fills quota with junk reads (10,240 keys)
    for i in 0..10240 {
        let junk_key = StateKey::resource(&AccountAddress::random(), b"JunkResource").unwrap();
        accumulator.add_transaction(
            std::iter::empty(),  // no writes
            std::iter::once(&junk_key)
        );
    }
    
    // Critical governance state read attempt
    let gov_key = StateKey::resource(
        &AccountAddress::from_hex_literal("0x1").unwrap(),
        b"GovernanceProposal"
    ).unwrap();
    
    accumulator.add_transaction(
        std::iter::empty(),
        std::iter::once(&gov_key)
    );
    
    let to_promote = accumulator.get_keys_to_make_hot();
    
    // Assert: Governance key is NOT in promotion set despite being read
    assert!(!to_promote.contains(&gov_key), 
        "Critical state should be promoted but was excluded due to quota");
    assert_eq!(to_promote.len(), 10240, "Quota filled with attacker's junk keys");
}
```

**Attack Execution Steps:**
1. Attacker prepares 100 transactions, each reading 103 unique state keys
2. Sets gas price 2x higher than typical mempool transactions
3. Submits all transactions to mempool
4. Block proposer selects attacker's transactions first (high gas price)
5. Block execution fills hot state promotion quota with attacker's keys
6. Legitimate governance/staking reads in same block are not promoted
7. Repeat for subsequent blocks to maintain degraded performance

## Notes

This vulnerability exploits an intentional design limitation acknowledged in the codebase. While the hot state cache is a performance optimization (not a correctness requirement), its systematic manipulation constitutes a denial-of-service attack on validator performance. The lack of prioritization for critical system state makes this exploitation feasible and economically viable for motivated attackers.

### Citations

**File:** aptos-move/block-executor/src/hot_state_op_accumulator.rs (L27-28)
```rust
    /// TODO(HotState): make on-chain config
    const MAX_PROMOTIONS_PER_BLOCK: usize = 1024 * 10;
```

**File:** aptos-move/block-executor/src/hot_state_op_accumulator.rs (L56-65)
```rust
        for key in reads {
            if self.to_make_hot.len() >= self.max_promotions_per_block {
                COUNTER.inc_with(&["max_promotions_per_block_hit"]);
                continue;
            }
            if self.writes.contains(key) {
                continue;
            }
            self.to_make_hot.insert(key.clone());
        }
```

**File:** mempool/src/core_mempool/index.rs (L194-198)
```rust
        // Higher gas preferred
        match self.gas_ranking_score.cmp(&other.gas_ranking_score) {
            Ordering::Equal => {},
            ordering => return ordering,
        }
```

**File:** aptos-move/block-executor/src/limit_processor.rs (L90-92)
```rust
            if let Some(x) = &mut self.hot_state_op_accumulator {
                x.add_transaction(rw_summary.keys_written(), rw_summary.keys_read());
            }
```

**File:** storage/storage-interface/src/state_store/state_view/cached_state_view.rs (L239-247)
```rust
        } else if let Some(slot) = self.hot.get_state_slot(state_key) {
            COUNTER.inc_with(&["sv_hit_hot"]);
            slot
        } else if let Some(base_version) = self.base_version() {
            COUNTER.inc_with(&["sv_cold"]);
            StateSlot::from_db_get(
                self.cold
                    .get_state_value_with_version_by_version(state_key, base_version)?,
            )
```
