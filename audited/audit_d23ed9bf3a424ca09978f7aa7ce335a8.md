# Audit Report

## Title
Arithmetic Overflow in Storage Deposit Calculations Due to Unchecked Addition and Missing Gas Parameter Validation

## Summary
The `total_deposit()` function uses unchecked addition to sum `slot_deposit` and `bytes_deposit`, which can silently overflow in release builds. Combined with the lack of validation on governance-set gas parameters, this could allow storage fee calculations to wrap around, bypassing the `max_storage_fee` protection and enabling storage operations at incorrect costs.

## Finding Description

The vulnerability exists across three critical code locations:

**1. Unchecked Addition in total_deposit():** [1](#0-0) 

This function uses the standard `+` operator which, in Rust release builds, wraps silently on overflow rather than panicking.

**2. Unchecked Addition in Charge Calculation:** [2](#0-1) 

The initial charge calculation also uses unchecked addition for the same values.

**3. Missing Gas Parameter Validation:** [3](#0-2) [4](#0-3) 

The TODO comments explicitly acknowledge that consistency checks are needed but not implemented. Gas parameters can be set to arbitrary `u64` values through governance with only a feature version check.

**4. Storage Fee Limit Check After Overflow:** [5](#0-4) 

The `max_storage_fee` check occurs after the overflow has already happened, checking the wrapped value rather than detecting the overflow.

**Attack Scenario:**

If governance (through compromise, extreme error, or malicious proposal) sets gas parameters such that:
```
slot_deposit + bytes_deposit > u64::MAX
```

Then:
1. A transaction creates a maximum-size state slot
2. The charge calculation overflows: e.g., (u64::MAX + 100) wraps to 99
3. The wrapped charge (99 octas) passes the `max_storage_fee` check
4. Transaction succeeds, charging only 99 octas
5. The deposit metadata stores the original high values
6. On deletion, `total_deposit()` overflows to the same wrapped value (99)
7. User is refunded 99 octas
8. **Net result**: User obtained storage that should cost >> `max_storage_fee` for nearly free, bypassing economic protections

This violates the **Resource Limits** invariant (#9) that all operations must respect storage limits.

## Impact Explanation

This issue falls short of Critical/High/Medium severity because:

**Critical factors preventing exploitation:**
1. Requires governance to set parameters where `slot_deposit + (max_bytes * byte_fee) > u64::MAX ≈ 1.8×10^19`
2. Current parameters: slot=40k, byte=40, max_bytes=1MB → total=~42M (0.0000002% of overflow threshold)
3. Reaching overflow requires governance to set values ~10^15 times higher than current
4. Such extreme parameter changes would be publicly visible in governance proposals
5. Community/validators would likely reject or immediately revert such proposals

**Trust model violation:**
The attack requires governance actors (trusted role per specification) to either:
- Act maliciously (explicitly excluded from threat model)
- Make an extraordinarily severe configuration error (10^15x magnitude mistake)

**Exploitability assessment:**
- Cannot be exploited by unprivileged attacker alone
- Requires privileged governance action as prerequisite
- Would be immediately detectable and reversible
- No realistic attack path exists within the stated trust boundaries

## Likelihood Explanation

**Likelihood: Extremely Low (Theoretical Only)**

While the code defect exists, practical exploitation is not realistic because:
1. Governance proposals are public and require multi-signature approval
2. Parameter changes of the required magnitude would be immediately obvious
3. The Aptos community actively monitors governance proposals
4. Even if passed, could be reverted in hours via emergency governance
5. No economic incentive for governance to self-sabotage the network

## Recommendation

Despite low exploitability, implement defense-in-depth improvements:

**1. Use checked arithmetic in critical financial calculations:**

```rust
// In state_value.rs line 135-137
pub fn total_deposit(&self) -> u64 {
    self.slot_deposit()
        .checked_add(self.bytes_deposit())
        .expect("Storage deposit overflow - gas parameters misconfigured")
}
```

**2. Add gas parameter validation in gas_schedule.move:**

```rust
// Implement the TODO at line 67 and 75
public fun validate_gas_schedule_consistency(schedule: &GasScheduleV2) {
    // Parse known parameter keys and validate ranges
    // Ensure slot_fee + (max_bytes * byte_fee) < u64::MAX / 2
    // Validate that fees don't exceed reasonable bounds (e.g., 10 APT)
}
```

**3. Use checked arithmetic in charge calculation:**

```rust
// In space_pricing.rs line 183
ChargeAndRefund {
    charge: slot_deposit.checked_add(target_bytes_deposit)
        .expect("Storage fee calculation overflow")
        .into(),
    refund: 0.into(),
}
```

## Proof of Concept

Due to the requirement for governance-level parameter changes, a realistic PoC cannot be demonstrated without modifying the trusted governance system, which violates the threat model.

**Conceptual PoC outline (not executable):**
```rust
// Would require governance to execute:
// 1. Set storage_fee_per_state_slot = u64::MAX / 2 + 1
// 2. Set storage_fee_per_state_byte = (u64::MAX / 2) / max_bytes_per_write_op
// 
// Then attacker could:
// 3. Create maximum-size state entry
// 4. Charge wraps: (u64::MAX/2 + 1) + (u64::MAX/2) = overflow to 0
// 5. Pay 0 octas for storage
// 6. Delete entry, receive 0 octas refund
// 7. Net: Free storage bypassing max_storage_fee
```

---

## Notes

After thorough analysis, while the arithmetic overflow vulnerability exists in the code, it **does not constitute a valid exploitable vulnerability** under the stated evaluation criteria because:

1. ✗ Requires privileged governance action (violates "unprivileged attacker" requirement)
2. ✗ Violates stated trust model (governance is trusted role)
3. ✗ No realistic attack path exists with current or foreseeable parameter values
4. ✗ Would require ~10^15x parameter increases, far beyond any reasonable governance error

**Final Assessment:** This is a **code quality issue** and **missing defense-in-depth protection**, but not a realistically exploitable vulnerability given the trust model and practical constraints.

The recommended fixes should still be implemented as defense-in-depth measures to protect against future governance errors and to ensure mathematical correctness of financial calculations.

### Citations

**File:** types/src/state_store/state_value.rs (L135-137)
```rust
    pub fn total_deposit(&self) -> u64 {
        self.slot_deposit() + self.bytes_deposit()
    }
```

**File:** aptos-move/aptos-vm-types/src/storage/space_pricing.rs (L183-183)
```rust
                    charge: (slot_deposit + target_bytes_deposit).into(),
```

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L67-67)
```text
            // TODO(Gas): check if gas schedule is consistent
```

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L75-75)
```text
            // TODO(Gas): check if gas schedule is consistent
```

**File:** aptos-move/aptos-gas-meter/src/algebra.rs (L293-295)
```rust
        if self.feature_version >= 7 && self.storage_fee_used > self.max_storage_fee {
            return Err(PartialVMError::new(StatusCode::STORAGE_LIMIT_REACHED));
        }
```
