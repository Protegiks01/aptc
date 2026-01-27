# Audit Report

## Title
Missing Duplicate Key Validation in Gas Schedule Allows Silent Parameter Overwriting

## Summary
The gas schedule loading system lacks runtime validation for duplicate parameter keys. When a `GasScheduleV2` with duplicate entries is converted to a `BTreeMap`, later values silently overwrite earlier ones, potentially causing incorrect gas metering if a malicious or corrupted gas schedule is loaded on-chain.

## Finding Description

The gas parameter loading system has a critical missing validation. When gas schedules are deserialized from on-chain state and converted to a `BTreeMap`, there is no check for duplicate keys.

The vulnerability exists in the following flow:

1. **Gas Schedule Storage**: On-chain gas schedules are stored as `vector<GasEntry>` in Move [1](#0-0) 

2. **No Validation During Updates**: When gas schedules are updated via governance, only non-empty and version checks are performed - no duplicate key validation: [2](#0-1) 

3. **Conversion to BTreeMap**: When loaded by validators, the gas schedule is converted to a `BTreeMap` with a TODO comment explicitly noting the missing validation: [3](#0-2) 

4. **Silent Overwriting**: Rust's `BTreeMap::collect()` silently keeps the last value when duplicate keys exist, causing earlier legitimate values to be overwritten by later malicious ones.

5. **VM Loads Incorrect Values**: The VM then loads gas parameters from this corrupted BTreeMap: [4](#0-3) 

**Attack Scenario**: A governance proposal containing duplicate gas parameter entries (e.g., both `("aptos_framework.account_create_address_base", 1102)` and `("aptos_framework.account_create_address_base", 0)` hidden in a 500+ entry list) could pass review with the duplicate unnoticed. Upon application, the gas parameter would be set to 0, making account creation free and enabling resource exhaustion attacks.

## Impact Explanation

This is a **High Severity** vulnerability according to Aptos bug bounty criteria because:

1. **Significant Protocol Violation**: Breaks the "Move VM Safety: Bytecode execution must respect gas limits" invariant by allowing incorrect gas values to be loaded.

2. **DoS Potential**: If critical gas parameters are set to 0 or very low values, operations become free/cheap, enabling:
   - Unlimited resource creation (accounts, objects, etc.)
   - Transaction spam to exhaust validator resources
   - State bloat attacks

3. **Deterministic Impact**: All validators load the same corrupted gas schedule, causing network-wide mispricing rather than consensus divergence.

However, this does NOT reach Critical severity because it doesn't directly cause consensus splits, fund theft, or network partition.

## Likelihood Explanation

**Likelihood: Medium to Low**

**Factors increasing likelihood:**
- Multiple TODO comments show developers are aware but haven't implemented validation
- Long gas schedule lists (300+ entries) make manual review difficult
- No automated duplicate detection in governance proposal tooling

**Factors decreasing likelihood:**
- Requires governance control or successful malicious proposal passage
- Aptos governance involves multiple reviewers and voting
- Hash validation in `set_for_next_epoch_check_hash` provides some protection against unexpected modifications
- Normal gas schedule generation from `AptosGasParameters::to_on_chain_gas_schedule()` produces unique keys (enforced by compile-time test)

The vulnerability is most likely exploited through:
1. A bug in gas schedule generation tools accidentally creating duplicates
2. A sophisticated malicious proposal that hides duplicates in a long entry list
3. A compromised governance participant

## Recommendation

**Add runtime duplicate key validation in multiple layers:**

1. **In Move module** (`gas_schedule.move`), add validation before storing:
```move
fun validate_no_duplicates(entries: &vector<GasEntry>): bool {
    let len = vector::length(entries);
    let i = 0;
    while (i < len) {
        let j = i + 1;
        let entry_i = vector::borrow(entries, i);
        while (j < len) {
            let entry_j = vector::borrow(entries, j);
            if (entry_i.key == entry_j.key) {
                return false
            };
            j = j + 1;
        };
        i = i + 1;
    };
    true
}
```

2. **In Rust conversion** (`gas_schedule.rs`), detect and error on duplicates:
```rust
pub fn into_btree_map(self) -> Result<BTreeMap<String, u64>, String> {
    let mut map = BTreeMap::new();
    for (key, value) in self.entries {
        if map.insert(key.clone(), value).is_some() {
            return Err(format!("Duplicate gas parameter key: {}", key));
        }
    }
    Ok(map)
}
```

3. **In proposal generation tools**, add pre-submission validation to detect duplicates before governance submission.

## Proof of Concept

```rust
#[test]
fn test_duplicate_gas_keys_overwrite() {
    use aptos_types::on_chain_config::GasScheduleV2;
    use std::collections::BTreeMap;
    
    // Create a gas schedule with duplicate keys
    let malicious_schedule = GasScheduleV2 {
        feature_version: 100,
        entries: vec![
            ("aptos_framework.account_create_address_base".to_string(), 1102),
            ("aptos_framework.ed25519_base".to_string(), 551),
            // Hidden duplicate with malicious value
            ("aptos_framework.account_create_address_base".to_string(), 0),
            ("move_stdlib.hash_sha2_256_base".to_string(), 11028),
        ],
    };
    
    // Convert to BTreeMap - duplicates are silently overwritten
    let map = malicious_schedule.into_btree_map();
    
    // The malicious value (0) overwrites the legitimate value (1102)
    assert_eq!(map.get("aptos_framework.account_create_address_base"), Some(&0));
    
    // This demonstrates that legitimate gas values can be overwritten
    // by duplicate entries later in the vector, bypassing gas metering
    println!("VULNERABILITY: Gas parameter overwritten from 1102 to 0");
}
```

**Notes:**

While this is a real technical vulnerability with clear security implications, it requires governance-level access to exploit directly. The missing validation represents a defense-in-depth failure that could enable attacks if combined with governance compromise, proposal review failures, or bugs in gas schedule generation tooling. The explicit TODO comments throughout the codebase indicate developers recognized this issue but have not yet implemented the necessary validation.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L37-40)
```text
    struct GasScheduleV2 has key, copy, drop, store {
        feature_version: u64,
        entries: vector<GasEntry>,
    }
```

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L91-103)
```text
    public fun set_for_next_epoch(aptos_framework: &signer, gas_schedule_blob: vector<u8>) acquires GasScheduleV2 {
        system_addresses::assert_aptos_framework(aptos_framework);
        assert!(!vector::is_empty(&gas_schedule_blob), error::invalid_argument(EINVALID_GAS_SCHEDULE));
        let new_gas_schedule: GasScheduleV2 = from_bytes(gas_schedule_blob);
        if (exists<GasScheduleV2>(@aptos_framework)) {
            let cur_gas_schedule = borrow_global<GasScheduleV2>(@aptos_framework);
            assert!(
                new_gas_schedule.feature_version >= cur_gas_schedule.feature_version,
                error::invalid_argument(EINVALID_GAS_FEATURE_VERSION)
            );
        };
        config_buffer::upsert(new_gas_schedule);
    }
```

**File:** types/src/on_chain_config/gas_schedule.rs (L56-60)
```rust
impl GasScheduleV2 {
    pub fn into_btree_map(self) -> BTreeMap<String, u64> {
        // TODO: what if the gas schedule contains duplicated entries?
        self.entries.into_iter().collect()
    }
```

**File:** aptos-move/aptos-vm-environment/src/gas.rs (L28-35)
```rust
        Some((gas_schedule, bytes)) => {
            sha3_256.update(&bytes);
            let feature_version = gas_schedule.feature_version;
            let map = gas_schedule.into_btree_map();
            (
                AptosGasParameters::from_on_chain_gas_schedule(&map, feature_version),
                feature_version,
            )
```
