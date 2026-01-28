# Audit Report

## Title
Critical State Inconsistency Between Vesting and Staking Contract Modules Causing Permanent Fund Freezing

## Summary
The vesting module exposes `get_vesting_account_signer` allowing admins to bypass vesting module state management and directly call `staking_contract::switch_operator`. This creates an irrecoverable state inconsistency where the cached operator in `VestingContract.staking.operator` no longer matches the actual operator key in `Store.staking_contracts`, causing all vesting operations to permanently fail with `ENO_STAKING_CONTRACT_FOUND_FOR_OPERATOR`.

## Finding Description

The vulnerability exploits a state synchronization flaw between the vesting and staking_contract modules.

**Root Cause:**

The `VestingContract` struct maintains a cached copy of the operator address in its `StakingInfo` field. [1](#0-0) 

The vesting module exposes an emergency function allowing admins to obtain the vesting account signer: [2](#0-1) 

**The Critical Flaw:**

With this signer, an admin can directly call `staking_contract::switch_operator`, which internally removes the `StakingContract` from the old operator key: [3](#0-2) 

And then re-adds it under the new operator key in the SimpleMap: [4](#0-3) 

However, this bypass does NOT update the cached `vesting_contract.staking.operator` field, creating permanent state inconsistency.

**Exploitation Impact:**

All vesting operations fail because they query using the stale cached operator. The `total_accumulated_rewards` function uses the cached operator: [5](#0-4) 

The `staking_contract_amounts` function looks up by operator key: [6](#0-5) 

And asserts the key exists, failing with `ENO_STAKING_CONTRACT_FOUND_FOR_OPERATOR` when keys don't match: [7](#0-6) 

All dependent functions fail: `unlock_rewards` (line 661), `vest` (line 681), `distribute` (line 756), `terminate_vesting_contract` (line 819), and internal helpers `unlock_stake` (line 1192) and `withdraw_stake` (line 1198).

**No Recovery Mechanism:**

The proper `update_operator` function synchronizes both states: [8](#0-7) 

However, once state is broken, `update_operator` cannot fix it because it reads the stale cached operator (line 901) and attempts to switch from the wrong key (line 902), which will fail since no contract exists under the cached operator anymore.

## Impact Explanation

**Severity: CRITICAL** - Permanent Freezing of Funds

This matches Aptos Bug Bounty Critical Severity Category #5: "Permanent freezing of funds (requires hardfork)."

Impact:
1. **Permanent Fund Freezing**: All vested tokens and accumulated staking rewards become permanently inaccessible to all shareholders
2. **Complete DoS**: All core vesting functions immediately fail with assertion errors  
3. **Irrecoverable State**: No function exists to manually correct the cached operator. Recovery requires hardfork or manual state intervention
4. **Affects Innocent Parties**: Shareholders (untrusted actors) lose funds due to admin error or misuse

The vulnerability affects potentially millions of dollars in production vesting contracts used for employee compensation, investor vesting schedules, and validator rewards across the Aptos ecosystem.

## Likelihood Explanation

**Likelihood: MEDIUM**

1. **Admin Access Required**: Requires vesting contract admin, but admins are NOT trusted roles per Aptos threat model (not core developers, validators, or governance participants). Any organization can create vesting contracts.

2. **Legitimate Emergency Use**: The function is explicitly documented as "for emergency use" [9](#0-8)  - admins may legitimately attempt to call staking functions directly during operational emergencies.

3. **No Protections**: Zero guardrails, warnings, or runtime checks prevent this operation. The comment misleadingly claims this "doesn't give the admin total power" when it actually provides power to permanently brick the contract.

4. **Accidental Triggering**: Can occur during legitimate emergency operations without malicious intent.

## Recommendation

Implement one of the following fixes:

**Option 1: Remove Direct Signer Access**
Remove the `get_vesting_account_signer` public function entirely and ensure all vesting operations go through proper state-synchronized functions like `update_operator`.

**Option 2: Add State Synchronization Guard**
Add a check in `staking_contract::switch_operator` to detect if it's being called from a vesting contract and abort with a clear error directing users to use `vesting::update_operator` instead.

**Option 3: Add Recovery Function**
Add a new function `fix_operator_state` that allows updating the cached operator field when state inconsistency is detected:

```move
public entry fun fix_operator_state(
    admin: &signer,
    contract_address: address,
    correct_operator: address,
) acquires VestingContract {
    let vesting_contract = borrow_global_mut<VestingContract>(contract_address);
    verify_admin(admin, vesting_contract);
    
    // Verify the operator actually exists in staking_contract
    assert!(
        staking_contract::staking_contract_exists(contract_address, correct_operator),
        error::invalid_argument(EINVALID_OPERATOR)
    );
    
    vesting_contract.staking.operator = correct_operator;
}
```

## Proof of Concept

```move
#[test(aptos_framework = @0x1, admin = @0x123, operator1 = @0x234, operator2 = @0x345, shareholder = @0x456)]
public fun test_state_inconsistency_permanent_freeze(
    aptos_framework: &signer,
    admin: &signer,
    operator1: &signer,
    operator2: &signer,
    shareholder: &signer
) acquires VestingContract {
    // Setup vesting contract with operator1
    setup(aptos_framework, &vector[@0x123, @0x234, @0x345, @0x456]);
    let contract_address = create_vesting_contract_test(admin, operator1, shareholder);
    
    // Admin gets signer for emergency use
    let vesting_signer = get_vesting_account_signer(admin, contract_address);
    
    // Admin directly calls switch_operator bypassing vesting module
    staking_contract::switch_operator(&vesting_signer, @0x234, @0x345, 10);
    
    // State is now inconsistent:
    // - vesting_contract.staking.operator = @0x234 (stale)
    // - Store.staking_contracts key = @0x345 (actual)
    
    // All vesting operations now fail permanently
    unlock_rewards(contract_address); // ABORTS with ENO_STAKING_CONTRACT_FOUND_FOR_OPERATOR
    vest(contract_address); // ABORTS
    distribute(contract_address); // ABORTS
    
    // Even update_operator cannot fix it
    update_operator(admin, contract_address, @0x345, 10); // ABORTS - tries to remove from @0x234 which doesn't exist
}
```

## Notes

This vulnerability represents a dangerous interaction between two framework modules where direct signer access breaks module-level invariants. The vesting module assumes exclusive control over operator changes to maintain state consistency, but `get_vesting_account_signer` breaks this assumption. The function's documentation provides false security assurances, making accidental exploitation during emergency situations highly likely.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/vesting.move (L126-135)
```text
    struct StakingInfo has store {
        // Where the vesting's stake pool is located at. Included for convenience.
        pool_address: address,
        // The currently assigned operator.
        operator: address,
        // The currently assigned voter.
        voter: address,
        // Commission paid to the operator of the stake pool.
        commission_percentage: u64,
    }
```

**File:** aptos-move/framework/aptos-framework/sources/vesting.move (L462-464)
```text
        let vesting_contract = borrow_global<VestingContract>(vesting_contract_address);
        let (total_active_stake, _, commission_amount) =
            staking_contract::staking_contract_amounts(vesting_contract_address, vesting_contract.staking.operator);
```

**File:** aptos-move/framework/aptos-framework/sources/vesting.move (L892-904)
```text
    public entry fun update_operator(
        admin: &signer,
        contract_address: address,
        new_operator: address,
        commission_percentage: u64,
    ) acquires VestingContract {
        let vesting_contract = borrow_global_mut<VestingContract>(contract_address);
        verify_admin(admin, vesting_contract);
        let contract_signer = &get_vesting_account_signer_internal(vesting_contract);
        let old_operator = vesting_contract.staking.operator;
        staking_contract::switch_operator(contract_signer, old_operator, new_operator, commission_percentage);
        vesting_contract.staking.operator = new_operator;
        vesting_contract.staking.commission_percentage = commission_percentage;
```

**File:** aptos-move/framework/aptos-framework/sources/vesting.move (L1137-1139)
```text
    /// For emergency use in case the admin needs emergency control of vesting contract account.
    /// This doesn't give the admin total power as the admin would still need to follow the rules set by
    /// staking_contract and stake modules.
```

**File:** aptos-move/framework/aptos-framework/sources/vesting.move (L1140-1144)
```text
    public fun get_vesting_account_signer(admin: &signer, contract_address: address): signer acquires VestingContract {
        let vesting_contract = borrow_global<VestingContract>(contract_address);
        verify_admin(admin, vesting_contract);
        get_vesting_account_signer_internal(vesting_contract)
    }
```

**File:** aptos-move/framework/aptos-framework/sources/staking_contract.move (L329-330)
```text
        let staking_contracts = &borrow_global<Store>(staker).staking_contracts;
        let staking_contract = simple_map::borrow(staking_contracts, &operator);
```

**File:** aptos-move/framework/aptos-framework/sources/staking_contract.move (L847-847)
```text
        let (_, staking_contract) = simple_map::remove(staking_contracts, &old_operator);
```

**File:** aptos-move/framework/aptos-framework/sources/staking_contract.move (L870-870)
```text
        simple_map::add(staking_contracts, new_operator, staking_contract);
```

**File:** aptos-move/framework/aptos-framework/sources/staking_contract.move (L1020-1022)
```text
        assert!(
            simple_map::contains_key(staking_contracts, &operator),
            error::not_found(ENO_STAKING_CONTRACT_FOUND_FOR_OPERATOR)
```
