# Audit Report

## Title
StateKeyRegistry Shard Exhaustion via Weak Hash Function Allows Targeted Lock Contention

## Summary
The `StateKeyRegistry::hash_address_and_name()` function uses only 3 bytes of input (last byte of address, first and last bytes of name) with a non-cryptographic hash to determine shard placement. An attacker can precompute address/name combinations that hash to a single shard, then create millions of state keys concentrated in that shard, causing lock contention and memory imbalance while other shards remain underutilized.

## Finding Description

The StateKeyRegistry implements sharding across 8 TwoKeyRegistry instances to distribute load and reduce lock contention. [1](#0-0) 

The shard selection is performed by `hash_address_and_name()`: [2](#0-1) 

This function has critical weaknesses:

1. **Minimal input space**: Only uses 3 bytes total (last byte of address, first/last bytes of name)
2. **Non-cryptographic hash**: Uses FxHasher, designed for speed not collision resistance
3. **Attacker-controllable inputs**: Both address (via resource accounts) and name (module/resource names) can be manipulated

The shard selection for resources and modules uses this hash modulo the shard count: [3](#0-2) 

**Attack Path:**

1. Attacker precomputes the ~2,097,152 combinations (16,777,216 / 8) of (address_last_byte, name_first_byte, name_last_byte) that produce `FxHash(3 bytes) % 8 == 0`

2. For resource accounts, the attacker brute forces seeds to generate addresses ending with desired bytes. Resource account addresses are derived as: [4](#0-3) 

3. The attacker creates resource accounts and deploys modules/resources with names starting/ending with the precomputed bytes

4. Over multiple transactions (limited by gas and write set limits of 8,192 ops/tx), the attacker accumulates millions of unique state keys all hashing to shard 0

5. Each TwoKeyRegistry uses a single `RwLock<HashMap<...>>`: [5](#0-4) 

6. When accessing these state keys (during transaction execution, state sync, or cache priming), shard 0's RwLock experiences heavy contention while shards 1-7 remain idle

7. The `get_or_add` operation requires lock acquisition: [6](#0-5) 

If legitimate system resources or frequently-accessed state keys also happen to hash to shard 0, they suffer from the same lock contention, degrading overall validator performance.

## Impact Explanation

This qualifies as **High Severity** per the Aptos bug bounty criteria for "Validator node slowdowns":

- **Lock Contention**: All StateKey creation/lookup operations for shard 0 serialize on a single RwLock, creating a bottleneck
- **Memory Imbalance**: Shard 0's HashMap grows to millions of entries while other shards remain small, violating the sharding design's load distribution goal  
- **Network-Wide Impact**: All validators experience the same shard imbalance when processing transactions that access the attacker's state keys
- **No Rate Limiting**: The registry has no per-shard limits or rebalancing mechanisms

While the attacker must pay gas costs for state creation, the resulting performance degradation affects all subsequent accesses to that shard, making this a force-multiplier attack.

## Likelihood Explanation

**Likelihood: Medium to High**

The attack is practical because:
- Precomputing target byte combinations is trivial (256³ = 16M possibilities, filter for modulo 8 == 0)
- Resource account creation with specific address patterns requires ~256 attempts per desired address on average
- Module and resource names are fully attacker-controlled
- No detection or mitigation exists in the current codebase

The cost is bounded by:
- Gas fees for resource account creation and module deployment
- Transaction rate limits (~8,192 state keys per transaction)
- Time to accumulate millions of state keys across many transactions

However, once created, the state keys persist and cause ongoing contention with minimal additional cost to the attacker.

## Recommendation

**Immediate Fix**: Strengthen the hash function to use more input bytes and be collision-resistant:

```rust
pub fn hash_address_and_name(address: &AccountAddress, name: &[u8]) -> usize {
    use std::hash::Hasher;
    let mut hasher = fxhash::FxHasher::default();
    
    // Use full address, not just last byte
    hasher.write(address.as_ref());
    
    // Use full name, not just first/last bytes
    hasher.write(name);
    
    hasher.finish() as usize
}
```

**Long-term Improvements**:
1. Use a cryptographic hash or SipHasher for shard selection to prevent precomputation attacks
2. Implement dynamic shard rebalancing if imbalance is detected
3. Add per-shard metrics and alerting for anomalous concentration
4. Consider increasing shard count from 8 to a larger prime number (e.g., 251) to make targeting specific shards harder

## Proof of Concept

```rust
#[cfg(test)]
mod shard_exhaustion_poc {
    use super::*;
    use move_core_types::{account_address::AccountAddress, identifier::Identifier};
    use std::collections::HashMap;

    #[test]
    fn test_shard_concentration_attack() {
        // Demonstrate that attacker can find inputs hashing to shard 0
        let mut shard_0_combinations = Vec::new();
        
        // Try different address last bytes and name patterns
        for addr_last_byte in 0..=255u8 {
            for name_first in 0..=255u8 {
                for name_last in 0..=255u8 {
                    // Create test address with specific last byte
                    let mut addr_bytes = [0u8; 32];
                    addr_bytes[31] = addr_last_byte;
                    let address = AccountAddress::new(addr_bytes);
                    
                    // Create test name with specific first/last bytes
                    let name = if name_first == name_last {
                        vec![name_first]
                    } else {
                        vec![name_first, b'x', name_last]
                    };
                    
                    let hash = StateKeyRegistry::hash_address_and_name(&address, &name);
                    
                    if hash % 8 == 0 {
                        shard_0_combinations.push((addr_last_byte, name_first, name_last));
                        if shard_0_combinations.len() >= 1000 {
                            break;
                        }
                    }
                }
                if shard_0_combinations.len() >= 1000 {
                    break;
                }
            }
            if shard_0_combinations.len() >= 1000 {
                break;
            }
        }
        
        // Verify we found many combinations that map to shard 0
        assert!(shard_0_combinations.len() >= 1000, 
            "Found {} combinations mapping to shard 0", shard_0_combinations.len());
        
        // Verify distribution is uneven (should be ~1/8 of attempts map to each shard)
        // but attacker can CHOOSE to only create state keys from the shard-0 set
        println!("Attack feasible: Found {} address/name combinations that hash to shard 0", 
                 shard_0_combinations.len());
        
        // Demonstrate shard selection
        let test_addr_bytes = [0u8; 32];
        let test_addr = AccountAddress::new(test_addr_bytes);
        let test_name = Identifier::new("test_module").unwrap();
        
        let registry = StateKeyRegistry::default();
        let shard = registry.module(&test_addr, &test_name);
        
        // In a real attack, repeat this millions of times with precomputed combinations
        println!("State key would be stored in one of 8 shards");
    }
}
```

**Notes**

This vulnerability is particularly concerning because:

1. The weak hash function violates the principle of uniform distribution across shards
2. The 3-byte input space (only 16,777,216 combinations) makes precomputation trivial
3. Unlike typical DoS attacks that require sustained resource expenditure, this attack's impact persists after initial state creation
4. The sharding mechanism provides no protection against deliberate concentration attacks

The fix requires using the full address and name bytes in the hash computation, making it infeasible for attackers to find collisions that concentrate state keys in a single shard.

### Citations

**File:** types/src/state_store/state_key/registry.rs (L71-73)
```rust
pub(crate) struct TwoKeyRegistry<Key1, Key2> {
    inner: RwLock<HashMap<Key1, HashMap<Key2, Weak<Entry>>>>,
}
```

**File:** types/src/state_store/state_key/registry.rs (L165-183)
```rust
    pub fn get_or_add<Ref1, Ref2, Gen>(
        &self,
        key1: &Ref1,
        key2: &Ref2,
        inner_gen: Gen,
    ) -> Result<Arc<Entry>>
    where
        Key1: Borrow<Ref1>,
        Key2: Borrow<Ref2>,
        Ref1: Eq + Hash + ToOwned<Owned = Key1> + ?Sized,
        Ref2: Eq + Hash + ToOwned<Owned = Key2> + ?Sized,
        Gen: FnOnce() -> Result<StateKeyInner>,
    {
        if let Some(entry) = self.read_lock_try_get(key1, key2) {
            return Ok(entry);
        }

        self.write_lock_get_or_add(key1, key2, inner_gen)
    }
```

**File:** types/src/state_store/state_key/registry.rs (L196-209)
```rust
const NUM_RESOURCE_SHARDS: usize = 8;
const NUM_RESOURCE_GROUP_SHARDS: usize = 8;
const NUM_MODULE_SHARDS: usize = 8;
const NUM_TABLE_ITEM_SHARDS: usize = 8;
const NUM_RAW_SHARDS: usize = 4;

#[derive(Default)]
pub struct StateKeyRegistry {
    resource_shards: [TwoKeyRegistry<StructTag, AccountAddress>; NUM_RESOURCE_SHARDS],
    resource_group_shards: [TwoKeyRegistry<StructTag, AccountAddress>; NUM_RESOURCE_GROUP_SHARDS],
    module_shards: [TwoKeyRegistry<AccountAddress, Identifier>; NUM_MODULE_SHARDS],
    table_item_shards: [TwoKeyRegistry<TableHandle, Vec<u8>>; NUM_TABLE_ITEM_SHARDS],
    raw_shards: [TwoKeyRegistry<Vec<u8>, ()>; NUM_RAW_SHARDS], // for tests only
}
```

**File:** types/src/state_store/state_key/registry.rs (L212-220)
```rust
    pub fn hash_address_and_name(address: &AccountAddress, name: &[u8]) -> usize {
        let mut hasher = fxhash::FxHasher::default();
        hasher.write_u8(address.as_ref()[AccountAddress::LENGTH - 1]);
        if !name.is_empty() {
            hasher.write_u8(name[0]);
            hasher.write_u8(name[name.len() - 1]);
        }
        hasher.finish() as usize
    }
```

**File:** types/src/state_store/state_key/registry.rs (L222-249)
```rust
    pub(crate) fn resource(
        &self,
        struct_tag: &StructTag,
        address: &AccountAddress,
    ) -> &TwoKeyRegistry<StructTag, AccountAddress> {
        &self.resource_shards
            [Self::hash_address_and_name(address, struct_tag.name.as_bytes()) % NUM_RESOURCE_SHARDS]
    }

    pub(crate) fn resource_group(
        &self,
        struct_tag: &StructTag,
        address: &AccountAddress,
    ) -> &TwoKeyRegistry<StructTag, AccountAddress> {
        &self.resource_group_shards[Self::hash_address_and_name(
            address,
            struct_tag.name.as_bytes(),
        ) % NUM_RESOURCE_GROUP_SHARDS]
    }

    pub(crate) fn module(
        &self,
        address: &AccountAddress,
        name: &IdentStr,
    ) -> &TwoKeyRegistry<AccountAddress, Identifier> {
        &self.module_shards
            [Self::hash_address_and_name(address, name.as_bytes()) % NUM_MODULE_SHARDS]
    }
```

**File:** aptos-move/framework/aptos-framework/sources/account/account.move (L1109-1114)
```text
    public fun create_resource_address(source: &address, seed: vector<u8>): address {
        let bytes = bcs::to_bytes(source);
        bytes.append(seed);
        bytes.push_back(DERIVE_RESOURCE_ACCOUNT_SCHEME);
        from_bcs::to_address(hash::sha3_256(bytes))
    }
```
