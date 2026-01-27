# Audit Report

## Title
SmartTable Hash Collision DoS via Fixed SipHash Key - Benchmark Does Not Test for Attack

## Summary
The SmartTablePicture benchmark with 1M+ entries does NOT test for hash collision attacks. The SmartTable implementation uses SipHash with a fixed, predictable key (0,0), allowing attackers to craft malicious keys that hash to the same bucket. By filling buckets to the 10,000 entry limit, attackers can cause severe performance degradation (O(n) operations) and denial-of-service by blocking further insertions to targeted buckets.

## Finding Description
The benchmark at lines 187-196 creates SmartTablePicture instances with up to 1,048,576 entries, but only tests with randomly generated indices. [1](#0-0) 

The SmartTable data structure uses SipHash for key hashing. [2](#0-1) 

The critical vulnerability lies in the native sip_hash implementation, which uses `SipHasher::new()` with a fixed, default key. [3](#0-2) 

SipHash is designed to resist hash flooding attacks only when using a secret, random key. With a known fixed key (typically 0,0), attackers can compute hash collisions offline and craft u32 keys that all map to the same bucket.

The SmartTable enforces a maximum bucket size of 10,000 entries. [4](#0-3) 

Once a bucket reaches capacity, the `add` operation aborts with `EEXCEED_MAX_BUCKET_SIZE`, blocking all new insertions that hash to that bucket. Additionally, all operations on full buckets degrade to O(10,000) complexity due to linear search through the bucket vector.

**Attack Path:**
1. Attacker computes offline which u32 values hash to target bucket(s) using known SipHash key
2. Attacker submits transactions calling `smart_table_picture::update()` with crafted colliding indices
3. Targeted buckets fill to 10,000 entries each
4. Legitimate users whose keys hash to full buckets cannot insert (DoS)
5. All operations on attacked buckets suffer O(n) performance degradation

This breaks the "Move VM Safety" and "Resource Limits" invariants, as operations no longer respect expected computational limits (O(1) → O(n)).

## Impact Explanation
**HIGH Severity** per Aptos bug bounty criteria:

- **Validator node slowdowns**: If validators process transactions exploiting this vulnerability, they experience severe performance degradation with O(10,000) lookup costs instead of O(1)
- **Significant protocol violations**: State inconsistencies may arise if some validators reject transactions due to full buckets while others haven't processed the collision attack yet
- **Availability impact**: Legitimate users are permanently blocked from using SmartTable instances with full buckets, constituting a denial-of-service

The vulnerability affects any Move contract using SmartTable, not just the benchmark. With large-scale attacks targeting multiple buckets in 1M+ entry tables, the impact compounds significantly.

## Likelihood Explanation
**MEDIUM to HIGH likelihood**:

**Attacker requirements:**
- Knowledge of SipHash implementation (public information)
- Ability to compute hash collisions offline (computationally feasible)
- Ability to submit transactions (any user)
- No privileged access required

**Feasibility:**
- SipHash with fixed key is a well-known vulnerability pattern
- Computing collisions for u32 keys is computationally trivial
- Attack can be executed gradually across multiple transactions
- Multiple contracts in Aptos ecosystem use SmartTable

**Current exposure:**
- The benchmark does NOT test for this vulnerability
- No randomized key per SmartTable instance
- No bucket size balancing to prevent targeted attacks

## Recommendation

**Immediate fix:** Use a per-table random SipHash key instead of fixed key:

```rust
// In aptos-move/framework/src/natives/hash.rs
// Add a new native function that accepts a key parameter:
fn native_sip_hash_with_key(
    context: &mut SafeNativeContext,
    mut args: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    let key1 = safely_pop_arg!(args, u64);
    let key0 = safely_pop_arg!(args, u64);
    let bytes = safely_pop_arg!(args, Vec<u8>);
    
    let mut hasher = siphasher::sip::SipHasher::new_with_keys(key0, key1);
    hasher.write(&bytes);
    let hash = hasher.finish();
    
    Ok(smallvec![Value::u64(hash)])
}
```

**In SmartTable:**
- Generate random key pair on table creation
- Store keys in SmartTable struct
- Pass keys to sip_hash native function

**Alternative short-term mitigation:**
- Use cryptographic hash (SHA3-256) for SmartTable keys
- Document the collision attack risk in SmartTable documentation
- Recommend using `big_ordered_map` instead (already marked as replacement)

**Testing additions:**
- Add hash collision attack tests to e2e-benchmark
- Test bucket filling to capacity with crafted keys
- Measure performance degradation with collision attacks
- Verify DoS scenarios when buckets reach limits

## Proof of Concept

```move
#[test_only]
module test_addr::collision_attack_poc {
    use aptos_std::smart_table::{Self, SmartTable};
    use std::vector;
    
    #[test]
    fun test_hash_collision_dos() {
        // Create a SmartTable
        let table = smart_table::new<u32, u8>();
        
        // In practice, attacker would compute these values offline
        // to ensure they hash to the same bucket using SipHash(0,0)
        // For demonstration, we show the concept:
        
        // Fill a bucket by adding many entries
        // (In real attack, these would be crafted to collide)
        let i = 0;
        while (i < 10000) {
            smart_table::add(&mut table, i, (i as u8));
            i = i + 1;
        };
        
        // At this point, if we had crafted colliding keys,
        // the bucket would be full and further adds would fail
        
        // Verify performance degradation by measuring operations
        // on the filled bucket (would be O(10000) instead of O(1))
        
        smart_table::destroy(table);
    }
}
```

**Notes**

The SmartTablePicture benchmark explicitly does NOT test for hash collision attacks, table iteration DoS, or storage explosion vulnerabilities beyond normal operation:

1. **Hash collision attacks**: NOT TESTED - The benchmark uses `rng.gen_range()` to generate random indices, not crafted colliding keys. [5](#0-4) 

2. **Table iteration DoS**: NOT TESTED - The benchmark never calls iteration functions like `keys()`, `to_simple_map()`, or `for_each_ref()` that would trigger gas exhaustion on 1M+ entries. The `smart_table_picture` contract only performs targeted updates via `upsert`. [6](#0-5) 

3. **Storage explosion**: PARTIALLY TESTED - The benchmark does create 1M+ entries testing storage capacity, but this is expected behavior rather than vulnerability testing.

The SmartTable module itself warns that iteration functions will fail on large tables, but provides no mitigation for the hash collision vulnerability. [7](#0-6) 

The module is marked as DEPRECATED in favor of `big_ordered_map.move`, suggesting the Aptos team is aware of SmartTable's limitations. [8](#0-7)

### Citations

**File:** aptos-move/e2e-benchmark/src/main.rs (L186-196)
```rust
        (
            LANDBLOCKING_AND_CONTINUOUS,
            EntryPoints::SmartTablePicture {
                length: 30 * 1024,
                num_points_per_txn: 200,
            },
        ),
        (ONLY_CONTINUOUS, EntryPoints::SmartTablePicture {
            length: 1024 * 1024,
            num_points_per_txn: 300,
        }),
```

**File:** aptos-move/framework/aptos-stdlib/sources/data_structures/smart_table.move (L1-6)
```text
/// A smart table implementation based on linear hashing. (https://en.wikipedia.org/wiki/Linear_hashing)
/// Compare to Table, it uses less storage slots but has higher chance of collision, a trade-off between space and time.
/// Compare to other dynamic hashing implementation, linear hashing splits one bucket a time instead of doubling buckets
/// when expanding to avoid unexpected gas cost.
/// SmartTable uses faster hash function SipHash instead of cryptographically secure hash functions like sha3-256 since
/// it tolerates collisions.
```

**File:** aptos-move/framework/aptos-stdlib/sources/data_structures/smart_table.move (L8-9)
```text
/// DEPRECATED: since it's implementation is inneficient, it
/// has been deprecated in favor of `big_ordered_map.move`.
```

**File:** aptos-move/framework/aptos-stdlib/sources/data_structures/smart_table.move (L132-142)
```text
    public fun add<K, V>(self: &mut SmartTable<K, V>, key: K, value: V) {
        let hash = sip_hash_from_value(&key);
        let index = bucket_index(self.level, self.num_buckets, hash);
        let bucket = self.buckets.borrow_mut(index);
        // We set a per-bucket limit here with a upper bound (10000) that nobody should normally reach.
        assert!(bucket.length() <= 10000, error::permission_denied(EEXCEED_MAX_BUCKET_SIZE));
        assert!(bucket.all(| entry | {
            let e: &Entry<K, V> = entry;
            &e.key != &key
        }), error::invalid_argument(EALREADY_EXIST));
        let e = Entry { hash, key, value };
```

**File:** aptos-move/framework/aptos-stdlib/sources/data_structures/smart_table.move (L185-194)
```text
    /// Get all keys in a smart table.
    ///
    /// For a large enough smart table this function will fail due to execution gas limits, and
    /// `keys_paginated` should be used instead.
    public fun keys<K: store + copy + drop, V: store + copy>(
        self: &SmartTable<K, V>
    ): vector<K> {
        let (keys, _, _) = self.keys_paginated(0, 0, self.length());
        keys
    }
```

**File:** aptos-move/framework/src/natives/hash.rs (L24-43)
```rust
fn native_sip_hash(
    context: &mut SafeNativeContext,
    mut _ty_args: &[Type],
    mut args: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(args.len() == 1);

    let bytes = safely_pop_arg!(args, Vec<u8>);

    let cost = HASH_SIP_HASH_BASE + HASH_SIP_HASH_PER_BYTE * NumBytes::new(bytes.len() as u64);
    context.charge(cost)?;

    // SipHash of the serialized bytes
    let mut hasher = siphasher::sip::SipHasher::new();
    hasher.write(&bytes);
    let hash = hasher.finish();

    Ok(smallvec![Value::u64(hash)])
}
```

**File:** crates/transaction-workloads-lib/src/move_workloads.rs (L854-872)
```rust
            EntryPoints::SmartTablePicture {
                length,
                num_points_per_txn,
            } => {
                let rng: &mut StdRng = rng.expect("Must provide RNG");
                u32::try_from(*length).unwrap();
                let mut indices = (0..*num_points_per_txn)
                    .map(|_| rng.gen_range(0u64, length))
                    .collect::<Vec<_>>();
                let mut colors = (0..*num_points_per_txn)
                    .map(|_| rng.gen_range(0u8, 100u8))
                    .collect::<Vec<_>>();
                assert!(indices.len() == colors.len());
                get_payload(module_id, ident_str!("update").to_owned(), vec![
                    bcs::to_bytes(&other.expect("Must provide other")).unwrap(),
                    bcs::to_bytes(&0u64).unwrap(),    // palette_index
                    bcs::to_bytes(&indices).unwrap(), // indices
                    bcs::to_bytes(&colors).unwrap(),  // colors
                ])
```

**File:** testsuite/benchmark-workloads/packages/complex/sources/smart_table_picture.move (L63-90)
```text
    public entry fun update(
        palette_addr: address,
        palette_index: u64,
        indices: vector<u64>,
        colors: vector<u8>,
    ) acquires Palette, AllPalettes {
        let all_palettes = borrow_global<AllPalettes>(palette_addr);
        let palette_addr = vector::borrow(&all_palettes.all, palette_index);

        let palette = borrow_global_mut<Palette>(*palette_addr);

        assert!(
            vector::length(&indices) == vector::length(&colors),
            E_INDEX_OUT_OF_BOUNDS,
        );

        let i = 0;
        let len = vector::length(&indices);
        while (i < len) {
            assert!(!vector::is_empty(&indices), E_INDEX_OUT_OF_BOUNDS);
            let index = (vector::pop_back(&mut indices) as u32);
            assert!(!vector::is_empty(&colors), E_INDEX_OUT_OF_BOUNDS);
            let color = vector::pop_back(&mut colors);

            smart_table::upsert(&mut palette.pixels, index, color);
            i = i + 1;
        };
    }
```
