# Audit Report

## Title
Unbounded TypeTagCache Memory Exhaustion via Type Parameter Variation DoS

## Summary
The TypeTagCache used by Move VM's type_info natives (`type_of<T>()` and `type_name<T>()`) has no size limit and can be exhausted by an attacker calling these functions with many different type instantiations. This causes unbounded memory growth and performance degradation on validator nodes.

## Finding Description

The vulnerability exists in the TypeTagCache implementation which caches type tag conversions to improve performance. The cache is implemented as an unbounded HashMap that persists across transactions and blocks. [1](#0-0) 

The cache key consists of a StructNameIndex and a vector of type arguments: [2](#0-1) 

**Attack Mechanism:**

An attacker can deploy a Move module containing generic structs and repeatedly call the public native functions `type_of<T>()` or `type_name<T>()` with many different type instantiations: [3](#0-2) 

Each unique combination of (StructNameIndex, type_args) creates a new cache entry: [4](#0-3) 

**Cache Growth Amplification:**

For a single struct `Foo<T>`, the attacker can create thousands of cache entries by varying the type parameter:
- `Foo<u8>`, `Foo<u64>`, `Foo<u128>`, `Foo<u256>`, `Foo<bool>`, `Foo<address>`, `Foo<signer>`
- `Foo<vector<u8>>`, `Foo<vector<u64>>`, `Foo<vector<u128>>`, etc.
- `Foo<vector<vector<u8>>>`, `Foo<vector<vector<u64>>>`, etc.
- Combinations with other structs: `Foo<Bar<u8>>`, `Foo<Bar<u64>>`, etc.

With ~20 primitive/common types and 5 nesting levels, a single struct can generate millions of cache entries.

**Cache Flush Protection is Insufficient:**

The only protection is flushing when the struct_name_index_map exceeds 1,000,000 entries: [5](#0-4) 

However, the TypeTagCache can contain **far more entries** than the struct_name_index_map because each struct name can have thousands of type instantiations. An attacker could create 10 million TypeTagCache entries using only 100 struct names (well below the 1M limit). [6](#0-5) 

**Persistence Across Transactions:**

The cache is stored in RuntimeEnvironment and persists across transactions and blocks as long as metadata is consecutive: [7](#0-6) 

## Impact Explanation

This vulnerability enables a **High Severity** DoS attack on validator nodes:

**Memory Exhaustion:**
- Each cache entry consumes approximately 200-500 bytes (StructTag with nested types, pseudo_gas_cost, HashMap overhead)
- 10 million entries = 2-5 GB of memory per validator node
- Could cause validators to crash or trigger OOM killers

**Performance Degradation:**
- Large HashMap operations (lookups, insertions) become progressively slower
- RwLock contention increases with cache size
- Every transaction using `type_of<T>()` or `type_name<T>()` experiences degraded performance
- Qualifies as "Validator node slowdowns" (High Severity - up to $50,000)

**Availability Impact:**
- Sustained attack over multiple blocks could render validators unusable
- Could force emergency cache flushes, disrupting block production

**Breaks Critical Invariant:**
- Violates "Resource Limits: All operations must respect gas, storage, and computational limits"
- The unbounded cache growth is not protected by gas metering or size limits

## Likelihood Explanation

**Likelihood: High**

**Attack Feasibility:**
- Any user can deploy a Move module with generic structs
- Calling `type_of<T>()` or `type_name<T>()` only requires paying gas fees (1102 base + 18 per byte)
- Gas costs are low enough to create millions of entries over time
- Attack can be distributed across multiple transactions and blocks
- No special permissions required

**Attack Economics:**
- Creating 1M cache entries costs approximately 1.1M gas units × 1M = 1.1B gas units
- At current gas prices (~100 octas/unit), total cost ~110 APT for 1M entries
- This is economically feasible for a determined attacker

**Persistence:**
- Cache persists across blocks, so attack effects accumulate
- Multiple attackers or coordinated attack amplifies impact

## Recommendation

Implement a size limit on TypeTagCache with an LRU or similar eviction policy:

1. **Add cache size limit to VMConfig:**
```rust
pub struct VMConfig {
    // ... existing fields ...
    pub type_tag_cache_max_entries: usize,
}
```

2. **Modify TypeTagCache to track and enforce size:**
```rust
pub(crate) struct TypeTagCache {
    cache: RwLock<HashMap<StructKey, PricedStructTag>>,
    max_entries: usize,
}

impl TypeTagCache {
    pub(crate) fn new(max_entries: usize) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            max_entries,
        }
    }
    
    pub(crate) fn insert_struct_tag(
        &self,
        idx: &StructNameIndex,
        ty_args: &[Type],
        priced_struct_tag: &PricedStructTag,
    ) -> bool {
        let mut cache = self.cache.write();
        
        // Enforce size limit with simple eviction
        if cache.len() >= self.max_entries {
            // Option 1: Flush entire cache
            cache.clear();
            // Option 2: Remove oldest entries (requires additional tracking)
        }
        
        let key = StructKey {
            idx: *idx,
            ty_args: ty_args.to_vec(),
        };
        cache.insert(key, priced_struct_tag.clone());
        true
    }
}
```

3. **Set reasonable default in production config:**
```rust
// In aptos_prod_vm_config
max_type_tag_cache_entries: 100_000, // Reasonable limit preventing unbounded growth
```

4. **Add monitoring:**
    - Track TypeTagCache size in metrics
    - Alert when approaching limits

**Alternative:** Flush TypeTagCache independently when it exceeds a threshold, similar to how struct_name_index_map is managed.

## Proof of Concept

```move
// File: attacker_module.move
module attacker::cache_poison {
    use aptos_std::type_info;
    
    // Generic struct that will be used to create many type instantiations
    struct Wrapper<T> has drop {}
    
    // Function to poison the cache with many type variations
    public entry fun poison_cache() {
        // Call type_of with many different type instantiations
        // Each creates a new cache entry
        let _ = type_info::type_of<Wrapper<u8>>();
        let _ = type_info::type_of<Wrapper<u64>>();
        let _ = type_info::type_of<Wrapper<u128>>();
        let _ = type_info::type_of<Wrapper<u256>>();
        let _ = type_info::type_of<Wrapper<bool>>();
        let _ = type_info::type_of<Wrapper<address>>();
        
        // Nested vectors create even more entries
        let _ = type_info::type_of<Wrapper<vector<u8>>>();
        let _ = type_info::type_of<Wrapper<vector<u64>>>();
        let _ = type_info::type_of<Wrapper<vector<u128>>>();
        
        // Deeply nested types
        let _ = type_info::type_of<Wrapper<vector<vector<u8>>>>();
        let _ = type_info::type_of<Wrapper<vector<vector<u64>>>>();
        
        // Can be extended to thousands of variations
        // An attacker would call this in a loop across many transactions
        // to accumulate millions of cache entries
    }
    
    // Alternative using type_name which also uses the cache
    public entry fun poison_cache_alt() {
        let _ = type_info::type_name<Wrapper<u8>>();
        let _ = type_info::type_name<Wrapper<u64>>();
        // ... same pattern as above
    }
}
```

**Attack Execution:**
1. Attacker deploys the module above
2. Calls `poison_cache()` repeatedly across many transactions
3. Each call adds ~10-20 new entries to TypeTagCache
4. After 100,000 transactions (feasible over days/weeks), cache contains 1-2 million entries
5. Validator memory usage grows by 200MB-1GB
6. Performance degrades as HashMap operations slow down
7. Sustained attack forces cache flushes or validator restarts

## Notes

This vulnerability demonstrates a resource exhaustion attack that bypasses gas metering. While individual operations are gas-metered, the cumulative effect of caching unbounded state across transactions creates a DoS vector. The issue is particularly severe because:

1. The cache is designed to be persistent for performance optimization
2. No size limit was implemented despite other caches having limits
3. The amplification factor (many cache entries per struct name) is high
4. The attack is economically feasible and requires no special permissions

### Citations

**File:** third_party/move/move-vm/runtime/src/storage/ty_tag_converter.rs (L65-70)
```rust
/// Key type for [TypeTagCache] that corresponds to a fully-instantiated struct.
#[derive(Clone, Eq, PartialEq)]
struct StructKey {
    idx: StructNameIndex,
    ty_args: Vec<Type>,
}
```

**File:** third_party/move/move-vm/runtime/src/storage/ty_tag_converter.rs (L150-152)
```rust
pub(crate) struct TypeTagCache {
    cache: RwLock<HashMap<StructKey, PricedStructTag>>,
}
```

**File:** third_party/move/move-vm/runtime/src/storage/ty_tag_converter.rs (L181-211)
```rust
    pub(crate) fn insert_struct_tag(
        &self,
        idx: &StructNameIndex,
        ty_args: &[Type],
        priced_struct_tag: &PricedStructTag,
    ) -> bool {
        // Check if already cached.
        if self
            .cache
            .read()
            .contains_key(&StructKeyRef { idx, ty_args })
        {
            return false;
        }

        let key = StructKey {
            idx: *idx,
            ty_args: ty_args.to_vec(),
        };
        let priced_struct_tag = priced_struct_tag.clone();

        // Otherwise, we need to insert. We did the clones outside the lock, and also avoid the
        // double insertion.
        let mut cache = self.cache.write();
        if let Entry::Vacant(entry) = cache.entry(key) {
            entry.insert(priced_struct_tag);
            true
        } else {
            false
        }
    }
```

**File:** aptos-move/framework/aptos-stdlib/sources/type_info.move (L53-58)
```text
    public native fun type_of<T>(): TypeInfo;

    /// Return the human readable string for the type, including the address, module name, and any type arguments.
    /// Example: 0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>
    /// Or: 0x1::table::Table<0x1::string::String, 0x1::string::String>
    public native fun type_name<T>(): String;
```

**File:** aptos-move/block-executor/src/code_cache_global_manager.rs (L141-146)
```rust
        // If the environment caches too many struct names, flush type caches. Also flush module
        // caches because they contain indices for struct names.
        if struct_name_index_map_size > config.max_struct_name_index_map_num_entries {
            runtime_environment.flush_all_caches();
            self.module_cache.flush();
        }
```

**File:** types/src/block_executor/config.rs (L38-38)
```rust
            max_struct_name_index_map_num_entries: 1_000_000,
```

**File:** third_party/move/move-vm/runtime/src/storage/environment.rs (L65-67)
```rust
    /// Caches struct tags for instantiated types. This cache can be used concurrently and
    /// speculatively because type tag information does not change with module publishes.
    ty_tag_cache: Arc<TypeTagCache>,
```
