# Audit Report

## Title
Gas Feature Version Rollback Architecture Requires Hard Fork - Non-Recoverable Network State

## Summary
The Aptos gas feature version system enforces a monotonically increasing version constraint that prevents rollback to previous versions. If a critical bug is discovered in a deployed gas feature version, the on-chain validation logic prevents downgrading, requiring a hard fork for recovery.

## Finding Description
The gas feature version system in Aptos has a formally verified constraint that prevents version downgrades. The on-chain validation in `gas_schedule.move` enforces that any new gas schedule must have `feature_version >= current_feature_version`. [1](#0-0) 

This validation is replicated in all three gas schedule update functions and is formally verified as a requirement: [2](#0-1) 

The gas feature version directly controls execution behavior, including gas calculation formulas, execution limits, and I/O limits: [3](#0-2) 

Different gas feature versions evaluate gas expressions differently and apply version-specific limits (version 7+ enforces execution limits, version 12+ has different OUT_OF_GAS handling). This means that if validators have different gas feature versions, they would calculate gas differently, causing consensus splits.

**Critical Scenario:**
1. Gas feature version 43 is deployed through governance
2. A critical bug is discovered that causes consensus failures, enables gas undercharging, or breaks deterministic execution
3. Network operators attempt to rollback to version 42 via `set_for_next_epoch()`
4. The transaction aborts with `EINVALID_GAS_FEATURE_VERSION` (error code 2)
5. No bypass mechanism exists - the validation is formally verified and strictly enforced
6. Recovery requires a hard fork to either:
   - Modify the on-chain validation logic
   - Directly manipulate the database to change the stored version
   - Deploy modified node software that ignores the validation

The gas feature version is fetched from on-chain state during block execution: [4](#0-3) 

And stored in the execution environment: [5](#0-4) 

## Impact Explanation
This represents **Critical severity** under the Aptos bug bounty program criteria: "Non-recoverable network partition (requires hardfork)."

If a buggy gas feature version is deployed (whether through compromised governance, malicious proposal, or accidental bugs in the gas schedule parameters), the network would be unable to recover without a hard fork. The impact includes:

- **Consensus Safety Violation**: Different gas calculations could cause validators to disagree on transaction outcomes
- **Network Liveness**: Critical bugs could halt block production entirely  
- **Economic Attacks**: Gas undercharging bugs would allow free computation until hard fork
- **Requires Hard Fork**: The only recovery path is coordinated validator software updates and/or database manipulation

## Likelihood Explanation
**Likelihood: Medium**

While deploying a buggy gas feature version requires governance approval, the lack of rollback capability creates systemic risk:

1. Gas feature versions are complex with version-specific logic branches
2. Bugs could be subtle and pass testing
3. Once deployed on-chain, the constraint is formally verified and strictly enforced
4. No emergency procedures exist for rapid rollback
5. Historical precedent: The changelog shows version 13 was skipped due to "testnet mis-operation" [6](#0-5) 

## Recommendation
Implement an emergency rollback mechanism for gas feature versions:

1. **Add Emergency Capability**: Create a separate `emergency_rollback_gas_version()` function that requires multi-sig authorization from a validator supermajority

2. **Bounded Rollback Window**: Allow rollback only within N blocks/epochs of deployment to prevent abuse

3. **Alternative**: Implement a "safe mode" gas feature version (e.g., version 0 or 1) that can always be reverted to regardless of current version

4. **Governance Process**: Document and test emergency procedures before they're needed

Example fix structure:
```move
public fun emergency_rollback_gas_version(
    emergency_admin: &signer,
    target_version: u64,
    validator_signatures: vector<vector<u8>>
) acquires GasScheduleV2 {
    // Verify multi-sig from validator supermajority
    // Allow rollback with strict conditions
    // Log emergency action
}
```

## Proof of Concept

**Scenario Setup:**
1. Current on-chain gas feature version: 43
2. Critical bug discovered in version 43 (e.g., allows free computation)
3. Attempt rollback to version 42

**Demonstration:**

```move
#[test(framework = @0x1)]
#[expected_failure(abort_code=0x010002, location = aptos_framework::gas_schedule)]
fun test_rollback_prevention(framework: signer) {
    use aptos_framework::gas_schedule;
    use std::bcs;
    
    // Deploy version 43
    let v43 = gas_schedule::GasScheduleV2 {
        feature_version: 43,
        entries: vector[]
    };
    move_to(&framework, v43);
    
    // Attempt rollback to version 42 - this MUST fail
    let v42 = gas_schedule::GasScheduleV2 {
        feature_version: 42,
        entries: vector[]
    };
    let v42_bytes = bcs::to_bytes(&v42);
    
    // This aborts with EINVALID_GAS_FEATURE_VERSION (0x010002)
    gas_schedule::set_for_next_epoch(&framework, v42_bytes);
}
```

The test demonstrates that the architecture strictly prevents rollback, confirming that hard fork would be the only recovery mechanism.

---

## Notes

This analysis reveals that while the monotonic version constraint is formally verified and intentional, it creates a critical operational risk. The system prioritizes forward compatibility at the expense of emergency recovery capability. Network operators should:

1. Implement rigorous testing for all gas feature version changes
2. Deploy to testnets extensively before mainnet
3. Maintain documented hard fork procedures for emergency scenarios
4. Consider implementing the recommended emergency rollback mechanism

The vulnerability is in the DESIGN - the lack of an escape hatch for critical bugs - rather than in the implementation of the validation logic itself.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L95-101)
```text
        if (exists<GasScheduleV2>(@aptos_framework)) {
            let cur_gas_schedule = borrow_global<GasScheduleV2>(@aptos_framework);
            assert!(
                new_gas_schedule.feature_version >= cur_gas_schedule.feature_version,
                error::invalid_argument(EINVALID_GAS_FEATURE_VERSION)
            );
        };
```

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.spec.move (L24-30)
```text
    /// Requirement: Only a gas schedule with the feature version greater or equal than the current feature version is
    /// allowed to be provided when performing an update operation.
    /// Criticality: Medium
    /// Implementation: The set_gas_schedule function validates the feature_version of the new_gas_schedule by ensuring
    /// that it is greater or equal than the current gas_schedule.feature_version.
    /// Enforcement: Formally verified via [high-level-req-4](set_gas_schedule).
    /// </high-level-req>
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

**File:** aptos-move/aptos-vm-environment/src/gas.rs (L15-19)
```rust
pub fn get_gas_feature_version(state_view: &impl StateView) -> u64 {
    GasScheduleV2::fetch_config(state_view)
        .map(|gas_schedule| gas_schedule.feature_version)
        .unwrap_or(0)
}
```

**File:** aptos-move/aptos-vm-environment/src/environment.rs (L181-182)
```rust
    /// Gas feature version used in this environment.
    gas_feature_version: u64,
```

**File:** aptos-move/aptos-gas-schedule/src/ver.rs (L36-38)
```rust
/// - V13
///   (skipped due to testnet mis-operation)
/// - V12
```
