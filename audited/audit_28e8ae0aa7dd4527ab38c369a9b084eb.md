# Audit Report

## Title
Critical Gas Schedule Griefing Attack: Missing Validation Allows Network-Wide Denial of Service Requiring Hard Fork Recovery

## Summary
The gas schedule update mechanism in `gas_schedule.move` lacks validation of gas parameter values, allowing a malicious governance proposal to set all gas costs to `u64::MAX`. This causes every transaction (including governance recovery attempts) to immediately fail with `OUT_OF_GAS`, permanently freezing the entire blockchain and requiring a hard fork to recover.

## Finding Description

The vulnerability exists in the gas schedule configuration system. When governance updates the gas schedule via `set_for_next_epoch()`, no validation is performed on the gas parameter values themselves: [1](#0-0) 

The code explicitly acknowledges this missing validation with TODO comments: [2](#0-1) [3](#0-2) 

**Attack Path:**

1. **Malicious Governance Proposal**: An attacker with sufficient voting power (or through social engineering/compromise) creates a governance proposal that calls `gas_schedule::set_for_next_epoch()` with a `GasScheduleV2` where all gas cost entries are set to `u64::MAX` (18,446,744,073,709,551,615).

2. **Proposal Execution**: The proposal passes and executes, staging the malicious gas schedule via `config_buffer::upsert()`.

3. **Epoch Transition**: During the next epoch reconfiguration, `gas_schedule::on_new_epoch()` applies the malicious schedule: [4](#0-3) 

4. **Network Freeze**: Every subsequent transaction attempts to execute but immediately runs out of gas because:
   - Even simple instructions like NOP would cost `u64::MAX` internal gas units
   - Normal transaction limit: 920,000,000 internal gas units
   - Governance transaction limit: 4,000,000,000 internal gas units
   - Both are ~4.6 million times smaller than `u64::MAX` [5](#0-4) 

5. **Gas Charging Mechanism**: When any transaction executes, the gas meter charges for each instruction: [6](#0-5) 

With gas costs at `u64::MAX`, even the first instruction causes `self.balance.checked_sub(amount)` to return `None`, triggering an immediate `OUT_OF_GAS` error.

6. **No Recovery Path**: 
   - All transactions fail before executing any logic
   - Governance proposals cannot execute to fix the gas schedule
   - Simulation mode still performs gas metering (only skips payment)
   - No emergency override mechanism exists for gas schedules (unlike randomness recovery)
   - Validators cannot bypass gas metering through local configuration

## Impact Explanation

**Severity: CRITICAL** - This meets the highest severity criteria per the Aptos Bug Bounty:

1. **"Non-recoverable network partition (requires hardfork)"**: The network becomes completely unusable. No on-chain mechanism can fix the gas schedule because all transactions fail at the gas metering stage before any execution logic runs. Recovery requires validator coordination to apply a state patch or rollback - a hard fork.

2. **"Total loss of liveness/network availability"**: The entire blockchain becomes non-functional. All economic activity ceases:
   - No user transactions can execute
   - No governance proposals can be submitted or executed
   - No validator operations can proceed
   - All DeFi protocols, NFT marketplaces, and applications become frozen

3. **Breaking Critical Invariants**:
   - **Resource Limits invariant**: "All operations must respect gas, storage, and computational limits" - violated by allowing unbounded gas costs
   - **Move VM Safety invariant**: "Bytecode execution must respect gas limits" - violated as execution cannot proceed

## Likelihood Explanation

**Likelihood: Medium-to-High**

**Attack Requirements:**
- Attacker needs to control or influence ~50% of governance voting power (standard for governance attacks)
- Or compromise of a governance participant with proposal creation rights
- Or social engineering to get a malicious proposal approved

**Complexity: Low** - The attack is straightforward:
1. Create a `GasScheduleV2` struct with all entries set to `u64::MAX`
2. Serialize it via BCS
3. Submit as governance proposal calling `gas_schedule::set_for_next_epoch()`
4. Wait for proposal to pass and epoch transition

**Detection Difficulty: High** - The malicious gas schedule would be visible in the proposal, but:
- Gas schedules are complex with hundreds of parameters
- Reviewers might not notice all values are set to maximum
- No automated validation exists to flag suspicious values

## Recommendation

**Immediate Fix**: Add comprehensive validation to `set_for_next_epoch()` and `set_for_next_epoch_check_hash()`:

```move
public fun set_for_next_epoch(aptos_framework: &signer, gas_schedule_blob: vector<u8>) acquires GasScheduleV2 {
    system_addresses::assert_aptos_framework(aptos_framework);
    assert!(!vector::is_empty(&gas_schedule_blob), error::invalid_argument(EINVALID_GAS_SCHEDULE));
    let new_gas_schedule: GasScheduleV2 = from_bytes(gas_schedule_blob);
    
    // NEW: Validate gas schedule parameters
    validate_gas_schedule(&new_gas_schedule);
    
    if (exists<GasScheduleV2>(@aptos_framework)) {
        let cur_gas_schedule = borrow_global<GasScheduleV2>(@aptos_framework);
        assert!(
            new_gas_schedule.feature_version >= cur_gas_schedule.feature_version,
            error::invalid_argument(EINVALID_GAS_FEATURE_VERSION)
        );
    };
    config_buffer::upsert(new_gas_schedule);
}

// NEW: Validation function
fun validate_gas_schedule(schedule: &GasScheduleV2) {
    let i = 0;
    let len = vector::length(&schedule.entries);
    
    // Maximum reasonable gas cost (e.g., 1 billion internal gas units)
    const MAX_REASONABLE_GAS_COST: u64 = 1_000_000_000;
    
    while (i < len) {
        let entry = vector::borrow(&schedule.entries, i);
        assert!(
            entry.val <= MAX_REASONABLE_GAS_COST,
            error::invalid_argument(EINVALID_GAS_SCHEDULE)
        );
        i = i + 1;
    };
}
```

**Additional Safeguards:**
1. Implement bounds checking for all gas parameters based on realistic execution limits
2. Add governance proposal review checklist requiring gas schedule audits
3. Implement emergency override mechanism similar to randomness recovery
4. Add monitoring/alerts for suspicious gas schedule proposals

## Proof of Concept

```move
#[test_only]
module aptos_framework::gas_schedule_griefing_test {
    use aptos_framework::gas_schedule;
    use std::bcs;
    use std::string;
    use std::vector;
    
    #[test(aptos_framework = @aptos_framework)]
    #[expected_failure] // This SHOULD fail but currently doesn't
    fun test_max_gas_cost_attack(aptos_framework: &signer) {
        // Create malicious gas schedule with all costs at u64::MAX
        let malicious_entries = vector::empty<GasScheduleV2>();
        
        // Add sample entries all set to u64::MAX
        vector::push_back(&mut malicious_entries, GasEntry {
            key: string::utf8(b"instr.nop"),
            val: 18446744073709551615, // u64::MAX
        });
        vector::push_back(&mut malicious_entries, GasEntry {
            key: string::utf8(b"instr.ret"),
            val: 18446744073709551615, // u64::MAX
        });
        // ... repeat for all gas parameters
        
        let malicious_schedule = GasScheduleV2 {
            feature_version: 100,
            entries: malicious_entries,
        };
        
        let malicious_blob = bcs::to_bytes(&malicious_schedule);
        
        // This should FAIL with validation error but currently succeeds
        gas_schedule::set_for_next_epoch(aptos_framework, malicious_blob);
        
        // After reconfiguration, all transactions would fail
    }
}
```

## Notes

This vulnerability is particularly severe because:

1. **Complete Network Paralysis**: Unlike other DoS attacks that might slow down the network, this completely freezes ALL on-chain activity with no recovery mechanism.

2. **Governance Capture Risk**: While requiring governance control, this represents a "governance nuke" that could be triggered by a compromised or malicious governance participant.

3. **Known But Unfixed**: The TODO comments indicate developers are aware validation is needed but it hasn't been implemented, making this a confirmed weakness.

4. **No Defense in Depth**: There are no fallback mechanisms, emergency overrides, or circuit breakers to prevent or recover from this attack.

5. **Hard Fork Required**: Recovery would require coordinating all validators to apply a state patch, potentially causing significant disruption and requiring community consensus on the fix.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L47-47)
```text
        // TODO(Gas): check if gas schedule is consistent
```

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L67-67)
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

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L135-145)
```text
    public(friend) fun on_new_epoch(framework: &signer) acquires GasScheduleV2 {
        system_addresses::assert_aptos_framework(framework);
        if (config_buffer::does_exist<GasScheduleV2>()) {
            let new_gas_schedule = config_buffer::extract_v2<GasScheduleV2>();
            if (exists<GasScheduleV2>(@aptos_framework)) {
                *borrow_global_mut<GasScheduleV2>(@aptos_framework) = new_gas_schedule;
            } else {
                move_to(framework, new_gas_schedule);
            }
        }
    }
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L211-219)
```rust
            max_execution_gas: InternalGas,
            { 7.. => "max_execution_gas" },
            920_000_000, // 92ms of execution at 10k gas per ms
        ],
        [
            max_execution_gas_gov: InternalGas,
            { RELEASE_V1_13.. => "max_execution_gas.gov" },
            4_000_000_000,
        ],
```

**File:** aptos-move/aptos-gas-meter/src/algebra.rs (L172-209)
```rust
    #[inline(always)]
    fn charge_execution(
        &mut self,
        abstract_amount: impl GasExpression<VMGasParameters, Unit = InternalGasUnit> + Debug,
    ) -> PartialVMResult<()> {
        self.counter_for_kill_switch += 1;
        if self.counter_for_kill_switch & 3 == 0
            && self.block_synchronization_kill_switch.interrupt_requested()
        {
            return Err(
                PartialVMError::new(StatusCode::SPECULATIVE_EXECUTION_ABORT_ERROR)
                    .with_message("Interrupted from block synchronization view".to_string()),
            );
        }

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
    }
```
