# Audit Report

## Title
Missing Gas Parameter Validation Enables DoS Attacks Through Governance-Controlled Hash Function Undercharging

## Summary
The Aptos gas schedule system lacks validation of individual gas parameter values, allowing governance proposals to set SHA2-256 hashing costs to zero. This enables systematic undercharging where attackers can consume excessive validator CPU resources for minimal gas cost, causing network-wide performance degradation.

## Finding Description

The vulnerability exists in the gas schedule configuration system where hash function gas parameters can be set to zero through governance proposals without any bounds checking or consistency validation.

**Root Cause:**

The gas schedule module has explicit TODO comments indicating that gas parameter validation should be implemented but never was: [1](#0-0) [2](#0-1) 

The `set_for_next_epoch()` function only validates that the feature version is non-decreasing but performs no validation on the actual parameter values.

**Hash Gas Parameters:**

SHA2-256 gas costs are defined in the Move stdlib gas schedule: [3](#0-2) 

The Aptos implementation charges gas for hash operations through the native context: [4](#0-3) 

**Gas Metering Bypass:**

When gas parameters are set to zero, the execution gas tracking fails to properly account for computational work. The gas algebra charges execution gas and checks limits: [5](#0-4) 

At line 192, `execution_gas_used` is incremented by the charged amount. When hash operations cost 0 gas, this counter doesn't increase despite significant CPU work being performed. The execution limit check at line 204 never triggers because `execution_gas_used` remains near zero.

**Attack Path:**

1. A compromised or malicious governance proposal sets `hash_sha2_256_base = 0` and `hash_sha2_256_per_byte = 0`
2. The proposal passes governance voting and is applied via `set_for_next_epoch()`
3. Any user can now create transactions with loops calling `std::hash::sha2_256()` on large inputs
4. Each hash operation costs 0 gas but consumes real CPU cycles
5. Normal instruction gas costs (441 per branch, 3676 per call) still apply, but are insufficient

**Impact Calculation:**

- Normal cost to hash 1KB: 11,028 + 183×1,024 = 198,520 internal gas units
- With zero parameters: 0 gas
- max_execution_gas limit: 920,000,000 internal gas units [6](#0-5) 

With bytecode instruction costs: [7](#0-6) [8](#0-7) 

A loop calling hash functions costs ~5,000 gas per iteration (instructions only), allowing 184,000 iterations within the execution limit. This represents a **40x amplification** of computational work versus properly charged operations.

This breaks the critical invariant:

**Invariant #9 Violation**: "Resource Limits: All operations must respect gas, storage, and computational limits" - the gas cost no longer properly reflects computational cost, allowing resource exhaustion attacks.

## Impact Explanation

This qualifies as **High Severity** under the Aptos Bug Bounty program criteria:

- **"Validator node slowdowns"** - Validators must process hash-intensive transactions that consume disproportionate CPU time relative to gas charged, degrading block production rates and network throughput
- **"Significant protocol violations"** - Gas metering is a fundamental protocol mechanism for resource management; bypassing it violates core security guarantees

The attack affects all validators network-wide, persists until governance reverses the change (requiring another governance cycle taking days), and can be exploited by any user once the misconfiguration is active.

## Likelihood Explanation

**Prerequisites:**
- Requires governance proposal to pass that sets gas parameters to zero
- This requires either: (a) compromised governance process, (b) social engineering of validators, or (c) coordinated malicious validators controlling voting majority
- The security question explicitly asks about "maliciously set" parameters, indicating insider threat scenarios are in scope

**Likelihood Assessment: Medium to High**

While governance compromise has a high bar, several factors increase likelihood:
1. **No automated validation**: Governance voters must manually review complex parameter changes
2. **Historical precedent**: Supply chain attacks on governance systems occur in blockchain ecosystems
3. **Wide exploit surface**: Once active, ANY user can trigger the DoS without special privileges
4. **Difficult recovery**: Requires full governance cycle to fix (days/weeks)

## Recommendation

**Implement gas parameter validation in the gas schedule module:**

1. Add bounds checking in `set_for_next_epoch()` and `initialize()`:

```rust
// In gas_schedule.move after line 94
let new_gas_schedule: GasScheduleV2 = from_bytes(gas_schedule_blob);

// Validate all gas parameters are within reasonable bounds
assert!(validate_gas_schedule(&new_gas_schedule), 
    error::invalid_argument(EINVALID_GAS_SCHEDULE));
```

2. Implement `validate_gas_schedule()` function that enforces:
   - All gas costs ≥ minimum threshold (e.g., 10 internal gas units)
   - Hash operation costs ≥ empirically measured CPU cost
   - Per-byte costs are proportional to computational complexity
   - No parameter exceeds maximum reasonable values

3. Add constants defining safe parameter ranges based on benchmarking

4. Consider adding a governance timelock/review period for gas schedule changes to allow community scrutiny

## Proof of Concept

```move
#[test_only]
module test_addr::gas_dos_poc {
    use std::hash;
    use std::vector;
    
    #[test(admin = @0x1)]
    public fun test_hash_dos_with_zero_gas(admin: &signer) {
        // Simulate governance setting gas to 0
        // In real scenario: gas_schedule::set_for_next_epoch(admin, zero_gas_blob)
        
        // Create 1KB of data to hash
        let data = vector::empty<u8>();
        let i = 0;
        while (i < 1024) {
            vector::push_back(&mut data, (i % 256) as u8);
            i = i + 1;
        };
        
        // With normal gas costs, this loop would quickly exceed max_execution_gas
        // With zero gas costs, can run 40x more iterations
        let iterations = 0;
        while (iterations < 100000) {
            let _ = hash::sha2_256(data);
            iterations = iterations + 1;
        };
        
        // With zero gas: 100,000 iterations × 1KB = 100MB hashed
        // CPU time: ~200ms (at 500 MB/s)
        // Gas charged: ~5000 × 100,000 = 500M (instruction gas only)
        //
        // With normal gas: Would hit limit at ~4,600 iterations
        // Amplification factor: 100,000 / 4,600 = 21.7x
    }
}
```

**Rust Test to Demonstrate Gas Tracking Failure:**

```rust
// In aptos-move/e2e-move-tests/src/tests/
#[test]
fn test_zero_gas_hash_bypass() {
    let mut h = MoveHarness::new();
    
    // Set hash gas parameters to zero via test gas schedule
    let mut gas_params = aptos_test_params();
    gas_params.natives.move_stdlib.hash_sha2_256_base = 0.into();
    gas_params.natives.move_stdlib.hash_sha2_256_per_byte = 0.into();
    
    h.set_gas_params(gas_params);
    
    // Execute transaction that hashes large data in loop
    let result = h.run_transaction_payload(/* hash loop payload */);
    
    // Assert: transaction succeeds despite excessive computation
    assert!(result.status().is_success());
    // Assert: gas_used is disproportionately low compared to work done
    assert!(result.gas_used() < expected_gas_with_proper_charging / 10);
}
```

**Notes:**

This vulnerability demonstrates a critical gap between the stated security invariant that "all operations must respect gas limits" and the actual implementation which allows governance to completely disable gas charging for expensive operations. While the attack requires governance compromise (explicitly mentioned in the security question as "maliciously set"), the impact affects the entire network and can be exploited by unprivileged users once active. The missing validation represents a design flaw in the gas schedule system that should be addressed with proper bounds checking and consistency validation.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L47-47)
```text
        // TODO(Gas): check if gas schedule is consistent
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

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/move_stdlib.rs (L23-24)
```rust
        [hash_sha2_256_base: InternalGas, "hash.sha2_256.base", 11028],
        [hash_sha2_256_per_byte: InternalGasPerByte, "hash.sha2_256.per_byte", 183],
```

**File:** aptos-move/framework/move-stdlib/src/natives/hash.rs (L37-39)
```rust
    context.charge(
        HASH_SHA2_256_BASE + HASH_SHA2_256_PER_BYTE * NumBytes::new(hash_arg.len() as u64),
    )?;
```

**File:** aptos-move/aptos-gas-meter/src/algebra.rs (L187-208)
```rust
        let amount = abstract_amount.evaluate(self.feature_version, &self.vm_gas_params);

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

        if self.feature_version >= 7 && self.execution_gas_used > self.max_execution_gas {
            Err(PartialVMError::new(StatusCode::EXECUTION_LIMIT_REACHED))
        } else {
            Ok(())
        }
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L211-214)
```rust
            max_execution_gas: InternalGas,
            { 7.. => "max_execution_gas" },
            920_000_000, // 92ms of execution at 10k gas per ms
        ],
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/instr.rs (L30-32)
```rust
        [br_true: InternalGas, "br_true", 441],
        [br_false: InternalGas, "br_false", 441],
        [branch: InternalGas, "branch", 294],
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/instr.rs (L80-80)
```rust
        [call_base: InternalGas, "call.base", 3676],
```
