# Audit Report

## Title
Rosetta API Incorrectly Reports Staking Rewards Without Deducting Operator Commission

## Summary
The `get_stake_balances()` function in the Rosetta API returns inflated staking reward values by including operator commission that doesn't belong to the staker. This creates a discrepancy between reported and actual withdrawable rewards, potentially causing accounting errors in external systems and user confusion.

## Finding Description

The vulnerability exists in the reward balance reporting logic. When a user queries their staking rewards through the Rosetta API, the function returns the total `accumulated_rewards` value without deducting the operator's commission. [1](#0-0) 

The function retrieves three values from the on-chain staking contract: [2](#0-1) 

Based on the Move contract implementation, `accumulated_rewards` represents the **total** rewards including the operator's commission portion: [3](#0-2) 

The Move framework's `unlock_rewards` function demonstrates the correct calculation - it explicitly subtracts commission to determine the staker's actual rewards: [4](#0-3) 

This shows that the staker's true rewards are `accumulated_rewards - unpaid_commission`, not just `accumulated_rewards`.

Furthermore, the code itself contains a TODO comment acknowledging this issue: [5](#0-4) 

The inconsistency is evident when comparing how other stake types are calculated - both `active_stake` and `total_stake` properly subtract commission: [6](#0-5) [7](#0-6) 

## Impact Explanation

This qualifies as **Medium Severity** under the "Limited funds loss or manipulation" and "State inconsistencies requiring intervention" categories because:

1. **External System Accounting Errors**: Exchanges, wallets, and DeFi protocols relying on the Rosetta API will display inflated reward balances. If an exchange credits users based on this data, they may become insolvent when users attempt withdrawals.

2. **User Financial Harm**: Users making financial decisions based on reported rewards (e.g., selling staking positions, collateralizing loans) will receive less than expected, potentially causing losses.

3. **Ecosystem-Wide Impact**: All users of staking contracts with non-zero commission rates are affected, creating systematic discrepancies across the entire Aptos ecosystem.

4. **Data Integrity Violation**: The API provides incorrect information that contradicts the actual on-chain state, breaking the trust model for external integrations.

## Likelihood Explanation

**Likelihood: High**

This bug affects every staking contract query through the Rosetta API where:
- A staking contract exists between a staker and operator
- The commission percentage is greater than 0%
- A rewards balance query is made

The vulnerability is not an edge case - it impacts normal operations for any system querying staking rewards via the Rosetta API.

## Recommendation

Modify the rewards calculation to subtract the commission amount:

```rust
} else if owner_account.is_rewards() {
    // Staker's net rewards after commission
    requested_balance = Some((accumulated_rewards - commission_amount).to_string());
}
```

This aligns with how `active_stake` and `total_stake` are calculated and matches the on-chain semantics demonstrated in the `unlock_rewards` Move function.

## Proof of Concept

**Setup:**
1. Create a staking contract with 10% commission
2. Allow rewards to accumulate to 100 APT
3. Query the rewards balance via Rosetta API

**Current Buggy Behavior:**
- Rosetta API returns: 100 APT (total accumulated_rewards)
- Commission owed: 10 APT
- Actual staker rewards: 90 APT

**User attempts to unlock all "rewards":**
```move
// On-chain, unlock_rewards correctly calculates:
let staker_rewards = accumulated_rewards - unpaid_commission;
// staker_rewards = 100 - 10 = 90 APT
unlock_stake(staker, operator, staker_rewards);
```

**Result:** User receives 90 APT despite API reporting 100 APT, creating a 10 APT discrepancy.

**Reproduction Steps:**
1. Set up a staking contract with commission > 0
2. Wait for rewards to accumulate
3. Query via Rosetta API: `/account/balance` with rewards sub-account
4. Compare reported value to on-chain `staking_contract_amounts()` calculation
5. Observe that API returns `accumulated_rewards` instead of `accumulated_rewards - commission_amount`

## Notes

The vulnerability stems from an incomplete implementation in the Rosetta API layer. While the on-chain staking contract correctly handles commission calculations, the API translation layer fails to apply the same logic when reporting rewards. The presence of the TODO comment indicates this was a known issue that remained unaddressed.

### Citations

**File:** crates/aptos-rosetta/src/types/misc.rs (L338-340)
```rust
        let total_active_stake = staking_contract_amounts_response[0];
        let accumulated_rewards = staking_contract_amounts_response[1];
        let commission_amount = staking_contract_amounts_response[2];
```

**File:** crates/aptos-rosetta/src/types/misc.rs (L342-344)
```rust
        // TODO: I think all of these are off, probably need to recalculate all of them
        // see the get_staking_contract_amounts_internal function in staking_contract.move for more
        // information on why commission is only subtracted from active and total stake
```

**File:** crates/aptos-rosetta/src/types/misc.rs (L345-347)
```rust
        if owner_account.is_active_stake() {
            // active stake is principal and rewards (including commission) so subtract the commission
            requested_balance = Some((total_active_stake - commission_amount).to_string());
```

**File:** crates/aptos-rosetta/src/types/misc.rs (L357-360)
```rust
        } else if owner_account.is_total_stake() {
            // total stake includes commission since it includes active stake, which includes commission
            requested_balance =
                Some((stake_pool.get_total_staked_amount() - commission_amount).to_string());
```

**File:** crates/aptos-rosetta/src/types/misc.rs (L363-364)
```rust
        } else if owner_account.is_rewards() {
            requested_balance = Some(accumulated_rewards.to_string());
```

**File:** aptos-move/framework/aptos-framework/sources/staking_contract.move (L795-807)
```text
    /// Unlock all accumulated rewards since the last recorded principals.
    public entry fun unlock_rewards(
        staker: &signer, operator: address
    ) acquires Store, BeneficiaryForOperator {
        let staker_address = signer::address_of(staker);
        assert_staking_contract_exists(staker_address, operator);

        // Calculate how much rewards belongs to the staker after commission is paid.
        let (_, accumulated_rewards, unpaid_commission) =
            staking_contract_amounts(staker_address, operator);
        let staker_rewards = accumulated_rewards - unpaid_commission;
        unlock_stake(staker, operator, staker_rewards);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/staking_contract.move (L1057-1071)
```text
    fun get_staking_contract_amounts_internal(
        staking_contract: &StakingContract
    ): (u64, u64, u64) {
        // Pending_inactive is not included in the calculation because pending_inactive can only come from:
        // 1. Outgoing commissions. This means commission has already been extracted.
        // 2. Stake withdrawals from stakers. This also means commission has already been extracted as
        // request_commission_internal is called in unlock_stake
        let (active, _, pending_active, _) =
            stake::get_stake(staking_contract.pool_address);
        let total_active_stake = active + pending_active;
        let accumulated_rewards = total_active_stake - staking_contract.principal;
        let commission_amount =
            accumulated_rewards * staking_contract.commission_percentage / 100;

        (total_active_stake, accumulated_rewards, commission_amount)
```
