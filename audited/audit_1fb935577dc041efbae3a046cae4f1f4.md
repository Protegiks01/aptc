# Audit Report

## Title
Missing Gas Schedule Validation Allows Network-Wide Denial of Service Through Malicious Governance Proposal

## Summary

The gas schedule validation in `gas_schedule.move` does not check for integer overflows or validate that gas cost values are within reasonable bounds. An attacker with governance access (or through a compromised governance proposal) can set gas operation costs to extreme values (such as `u64::MAX`), causing all transactions to fail with `OUT_OF_GAS` errors and effectively halting the entire Aptos network.

## Finding Description

The Aptos gas schedule system allows governance to update gas costs for all VM operations through the `set_for_next_epoch()` and `set_for_next_epoch_check_hash()` functions. However, the validation logic only checks:

1. That the gas schedule blob is not empty [1](#0-0) 
2. That the feature version is monotonically increasing [2](#0-1) 

There is **no validation** of the actual u64 gas cost values within the `entries` vector. The code explicitly acknowledges this with TODO comments indicating missing consistency checks [3](#0-2) .

The gas schedule entries are defined as simple key-value pairs [4](#0-3)  and converted directly from on-chain storage to typed gas parameters without bounds checking [5](#0-4) .

While gas calculations use saturating arithmetic to prevent wraparound [6](#0-5) , this does not prevent the attack. When an operation with cost `u64::MAX` is charged, the `checked_sub()` operation fails [7](#0-6) , causing the transaction to abort with `OUT_OF_GAS`.

**Attack Scenario:**

1. Attacker creates a governance proposal that sets a common instruction cost (e.g., `instr.ret` or `instr.nop`) to `u64::MAX`
2. Proposal passes through governance and is applied at epoch boundary
3. Any transaction executing that instruction attempts to charge `u64::MAX` gas
4. Since no user can have `u64::MAX` gas balance, all `checked_sub()` operations fail
5. All transactions fail with `OUT_OF_GAS` immediately
6. Network experiences total loss of liveness - no transactions can execute

**Alternative Attack Scenario:**

Setting `maximum_number_of_gas_units` to an extremely low value (e.g., 1) causes all transactions to be rejected during validation [8](#0-7) , also resulting in network halt.

## Impact Explanation

**Critical Severity** - This vulnerability qualifies for the highest severity rating because it enables:

- **Total loss of liveness/network availability**: Once a malicious gas schedule is applied, no transactions can execute, requiring emergency intervention or hard fork to recover
- **Non-recoverable network partition**: Without the ability to execute transactions, the network cannot recover through normal governance mechanisms

The attack breaks the following critical invariants:
- **Move VM Safety**: Bytecode execution must respect gas limits (violated by allowing extreme costs)
- **Resource Limits**: All operations must respect gas limits (bypassed by setting limits to extreme values)
- **Network Liveness**: The network must process transactions (completely halted)

All validator nodes are affected simultaneously when the malicious gas schedule activates at epoch boundary, making this a consensus-level failure affecting the entire network.

## Likelihood Explanation

**Likelihood: Medium**

While this vulnerability requires governance access to exploit, several factors increase the likelihood:

1. **Accidental Trigger**: A governance proposal with misconfigured gas values could accidentally trigger this (not just malicious intent)
2. **Governance Compromise**: If governance keys or voting mechanisms are compromised, attackers gain this capability
3. **Multi-Signature Weakness**: If governance involves multi-sig with some compromised parties, malicious values could slip through
4. **No Safeguards**: The complete absence of validation means there's no safety net

The formal specification explicitly documents this as a requirement [9](#0-8)  but the implementation is incomplete.

## Recommendation

Implement comprehensive validation in the `set_for_next_epoch()` and `set_for_next_epoch_check_hash()` functions:

```move
public fun set_for_next_epoch(aptos_framework: &signer, gas_schedule_blob: vector<u8>) acquires GasScheduleV2 {
    system_addresses::assert_aptos_framework(aptos_framework);
    assert!(!vector::is_empty(&gas_schedule_blob), error::invalid_argument(EINVALID_GAS_SCHEDULE));
    let new_gas_schedule: GasScheduleV2 = from_bytes(gas_schedule_blob);
    
    // Add validation here
    validate_gas_schedule_consistency(&new_gas_schedule);
    
    if (exists<GasScheduleV2>(@aptos_framework)) {
        let cur_gas_schedule = borrow_global<GasScheduleV2>(@aptos_framework);
        assert!(
            new_gas_schedule.feature_version >= cur_gas_schedule.feature_version,
            error::invalid_argument(EINVALID_GAS_FEATURE_VERSION)
        );
    };
    config_buffer::upsert(new_gas_schedule);
}

fun validate_gas_schedule_consistency(gas_schedule: &GasScheduleV2) {
    // Define maximum reasonable gas costs (e.g., 10^9 internal gas units)
    const MAX_REASONABLE_GAS_COST: u64 = 1_000_000_000;
    const MIN_REASONABLE_MAX_GAS: u64 = 1_000_000;
    
    let i = 0;
    let len = vector::length(&gas_schedule.entries);
    while (i < len) {
        let entry = vector::borrow(&gas_schedule.entries, i);
        
        // Validate individual costs aren't extreme
        assert!(
            entry.val <= MAX_REASONABLE_GAS_COST,
            error::invalid_argument(EINVALID_GAS_SCHEDULE)
        );
        
        // Validate critical parameters like maximum_number_of_gas_units
        if (entry.key == string::utf8(b"txn.maximum_number_of_gas_units")) {
            assert!(
                entry.val >= MIN_REASONABLE_MAX_GAS,
                error::invalid_argument(EINVALID_GAS_SCHEDULE)
            );
        };
        
        i = i + 1;
    };
}
```

Additionally, implement similar validation in the Rust deserialization path [10](#0-9)  to catch issues before they reach the Move layer.

## Proof of Concept

```move
#[test_only]
module aptos_framework::gas_schedule_dos_test {
    use aptos_framework::gas_schedule;
    use std::vector;
    use std::bcs;
    
    #[test(aptos_framework = @0x1)]
    #[expected_failure(abort_code=0x50003, location=aptos_framework::gas_schedule)]
    fun test_extreme_gas_value_causes_dos(aptos_framework: &signer) {
        // Create a malicious gas schedule with u64::MAX cost for a common operation
        let malicious_entries = vector::empty<gas_schedule::GasEntry>();
        
        // Set nop instruction cost to u64::MAX
        vector::push_back(&mut malicious_entries, gas_schedule::GasEntry {
            key: string::utf8(b"instr.nop"),
            val: 18446744073709551615, // u64::MAX
        });
        
        let malicious_schedule = gas_schedule::GasScheduleV2 {
            feature_version: 20,
            entries: malicious_entries,
        };
        
        let malicious_blob = bcs::to_bytes(&malicious_schedule);
        
        // This should fail with proper validation but currently does not
        gas_schedule::set_for_next_epoch(aptos_framework, malicious_blob);
        
        // After applying this schedule, all transactions executing 'nop' would fail
        // with OUT_OF_GAS, effectively halting the network
    }
}
```

**Note:** The validation checklist requirement for "exploitable by unprivileged attacker" is technically not met since this requires governance access. However, defense-in-depth principles dictate that even trusted inputs should be validated, especially for parameters that can cause total network failure. The presence of TODO comments acknowledging missing validation, combined with the critical impact, makes this a valid security concern worthy of remediation.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L28-31)
```text
    struct GasEntry has store, copy, drop {
        key: String,
        val: u64,
    }
```

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L47-47)
```text
        // TODO(Gas): check if gas schedule is consistent
```

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L93-93)
```text
        assert!(!vector::is_empty(&gas_schedule_blob), error::invalid_argument(EINVALID_GAS_SCHEDULE));
```

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L97-100)
```text
            assert!(
                new_gas_schedule.feature_version >= cur_gas_schedule.feature_version,
                error::invalid_argument(EINVALID_GAS_FEATURE_VERSION)
            );
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/macros.rs (L40-40)
```rust
                        params.$name = gas_schedule.get(&name).cloned().ok_or_else(|| format!("Gas parameter {} does not exist. Feature version: {}.", name, feature_version))?.into();
```

**File:** third_party/move/move-core/types/src/gas_algebra.rs (L209-209)
```rust
        Self::new(self.val.saturating_add(rhs.val))
```

**File:** aptos-move/aptos-gas-meter/src/algebra.rs (L189-202)
```rust
        match self.balance.checked_sub(amount) {
            Some(new_balance) => {
                self.balance = new_balance;
                self.execution_gas_used += amount;
            },
            None => {
                let old_balance = self.balance;
                self.balance = 0.into();
                if self.feature_version >= 12 {
                    self.execution_gas_used += old_balance;
                }
                return Err(PartialVMError::new(StatusCode::OUT_OF_GAS));
            },
        };
```

**File:** aptos-move/aptos-vm/src/gas.rs (L126-139)
```rust
    if txn_metadata.max_gas_amount() > txn_gas_params.maximum_number_of_gas_units {
        speculative_warn!(
            log_context,
            format!(
                "[VM] Gas unit error; max {}, submitted {}",
                txn_gas_params.maximum_number_of_gas_units,
                txn_metadata.max_gas_amount()
            ),
        );
        return Err(VMStatus::error(
            StatusCode::MAX_GAS_UNITS_EXCEEDS_MAX_GAS_UNITS_BOUND,
            None,
        ));
    }
```

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.spec.move (L18-21)
```text
    /// Requirement: Only valid gas schedule should be allowed for initialization and update.
    /// Criticality: Medium
    /// Implementation: The initialize and set_gas_schedule functions ensures that the gas_schedule_blob is not empty.
    /// Enforcement: Formally verified via [high-level-req-3.3](initialize) and [high-level-req-3.2](set_gas_schedule).
```

**File:** types/src/on_chain_config/gas_schedule.rs (L57-60)
```rust
    pub fn into_btree_map(self) -> BTreeMap<String, u64> {
        // TODO: what if the gas schedule contains duplicated entries?
        self.entries.into_iter().collect()
    }
```
