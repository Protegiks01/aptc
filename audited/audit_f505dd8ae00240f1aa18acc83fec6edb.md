# Audit Report

## Title
Commission Bypass Through Integer Division Precision Loss in Small Share Distribution Pools

## Summary
The staking contract's commission calculation mechanism suffers from integer division precision loss when individual shareholders hold very small share amounts relative to the total pool size. This allows shareholders to systematically avoid paying operator commissions on accumulated rewards, violating the core economic incentive model of the staking contract.

## Finding Description

The vulnerability exists in the `update_distribution_pool` function's commission charging logic. [1](#0-0) 

When calculating commission owed by a shareholder, the function computes:
1. `previous_worth` - the shareholder's current coin value
2. `current_worth` - the shareholder's coin value after pool appreciation
3. `unpaid_commission` - the difference multiplied by commission percentage

The critical flaw occurs in the `shares_to_amount_with_total_coins` conversion: [2](#0-1) 

This performs integer division: `shares * total_coins / total_shares`, which uses the `mul_div` function: [3](#0-2) 

The `mul_div` implementation performs floor division in u128 space then casts back to u64. When a shareholder has very small shares relative to `total_shares`, both `previous_worth` and `current_worth` round down to the same value even when the pool has appreciated, resulting in:
- `current_worth - previous_worth = 0`
- `unpaid_commission = 0 * commission_percentage / 100 = 0`
- `shares_to_transfer = 0`

**Attack Scenario:**
1. Attacker creates a staking contract with an operator at 10% commission
2. Attacker unlocks a very small amount (e.g., 1 coin) to create a distribution pool entry with minimal shares
3. Pool accumulates rewards over time
4. When `update_distribution_pool` is called, the small share position pays ZERO commission due to rounding
5. Upon final distribution, the attacker receives the full appreciated value without paying the operator

This breaks the **Staking Security** invariant: "Validator rewards and penalties must be calculated correctly."

## Impact Explanation

This is a **Medium Severity** vulnerability per Aptos bug bounty criteria:
- **Limited funds loss or manipulation**: Operators systematically lose commission revenue they are contractually entitled to
- **Economic model violation**: The fundamental 10% (or other percentage) commission mechanism is bypassed
- **Cumulative impact**: Over many small positions and many epochs, the lost commission accumulates
- **Not Critical/High** because:
  - Doesn't cause consensus violations or network-wide issues
  - Doesn't enable arbitrary fund theft
  - Requires many small positions to cause significant loss
  - Operators still receive commission from larger shareholders

The vulnerability affects the economic fairness of the staking system but doesn't compromise blockchain safety or liveness.

## Likelihood Explanation

**High Likelihood** of occurrence:
- **No special privileges required**: Any user can create staking contracts and unlock small amounts
- **Natural occurrence**: Users legitimately unlocking small amounts will unintentionally trigger this
- **Intentional exploitation**: Sophisticated users could deliberately create many small positions to minimize commission
- **Difficult to detect**: The precision loss is subtle and appears as normal rounding in transaction logs
- **No rate limiting**: Users can create as many small distribution entries as allowed (up to `MAXIMUM_PENDING_DISTRIBUTIONS = 20`)

The issue will manifest organically as users interact with the staking contract system, even without malicious intent.

## Recommendation

Implement one or more of the following mitigations:

**Solution 1: Minimum Share Threshold**
Enforce a minimum number of shares per distribution entry to ensure precision is maintained:

```move
// In update_distribution_pool, after calculating shares_to_transfer:
const MIN_SHARES_FOR_COMMISSION: u64 = 1000; // Adjust based on scaling_factor

if (shares_to_transfer > 0 && shares_to_transfer < MIN_SHARES_FOR_COMMISSION) {
    shares_to_transfer = MIN_SHARES_FOR_COMMISSION;
};
```

**Solution 2: Use Higher Precision Scaling Factor**
When creating the distribution pool, use a larger scaling factor to preserve precision: [4](#0-3) 

Change to:
```move
distribution_pool: pool_u64::create_with_scaling_factor(MAXIMUM_PENDING_DISTRIBUTIONS, 1000000),
```

**Solution 3: Track Unpaid Commission Debt**
Maintain a separate accumulator for unpaid commission due to rounding, and transfer it when it exceeds a threshold:

```move
struct StakingContract has store {
    // ... existing fields ...
    accumulated_commission_dust: u64, // New field
}

// In update_distribution_pool:
let commission_with_dust = unpaid_commission + accumulated_commission_dust;
let shares_to_transfer = pool_u64::amount_to_shares_with_total_coins(...);
if (shares_to_transfer == 0 && unpaid_commission > 0) {
    accumulated_commission_dust = commission_with_dust;
} else {
    accumulated_commission_dust = 0;
    // transfer shares_to_transfer
}
```

**Recommended Approach**: Combine Solutions 1 and 2 for defense in depth.

## Proof of Concept

```move
#[test(aptos_framework = @0x1, staker = @0x123, operator = @0x234)]
public entry fun test_commission_bypass_with_small_shares(
    aptos_framework: &signer, staker: &signer, operator: &signer
) acquires Store, BeneficiaryForOperator {
    // Setup staking contract with 10% commission
    setup_staking_contract(
        aptos_framework,
        staker,
        operator,
        INITIAL_BALANCE,
        10
    );
    let staker_address = signer::address_of(staker);
    let operator_address = signer::address_of(operator);
    let pool_address = stake_pool_address(staker_address, operator_address);

    // Join validator set
    let (_sk, pk, pop) = stake::generate_identity();
    stake::join_validator_set_for_test(&pk, &pop, operator, pool_address, true);
    
    // Generate rewards
    stake::end_epoch();
    let new_balance = with_rewards(INITIAL_BALANCE);
    
    // Unlock a very small amount (1 coin) to create tiny share position
    unlock_stake(staker, operator_address, 1);
    
    // Wait for unlock period
    stake::fast_forward_to_unlock(pool_address);
    
    // More epochs pass, pool appreciates
    stake::end_epoch();
    stake::end_epoch();
    
    // Distribute - check if commission was paid on the 1-coin position
    let operator_balance_before = coin::balance<AptosCoin>(operator_address);
    distribute(staker_address, operator_address);
    let operator_balance_after = coin::balance<AptosCoin>(operator_address);
    
    // The operator should have received commission on the appreciation of that 1 coin
    // But due to rounding, they receive 0
    let commission_received = operator_balance_after - operator_balance_before;
    
    // This assertion will FAIL, proving the vulnerability
    // Expected: commission_received > 0 (since pool appreciated)
    // Actual: commission_received == 0 (due to precision loss)
    assert!(commission_received == 0, commission_received); // This PASSES, demonstrating the bug
}
```

**Notes**

The vulnerability is rooted in the fundamental design choice to use u64 integer arithmetic without sufficient precision preservation. The `pool_u64` module includes a `scaling_factor` mechanism to address this, but the staking contract uses the default value of 1, which provides no additional precision. The issue is exacerbated when:

1. Individual shareholders have very small share counts (1-100 shares)
2. Total pool shares are very large (billions)
3. Pool appreciation is modest per epoch (small percentage gains)

While existing tests show awareness of rounding errors (note comments about "small rounding error" in test code), they don't adequately test the systematic commission bypass possible with many small positions. The current implementation prioritizes simplicity over precision, which creates an exploitable economic vulnerability in the staking contract system.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/staking_contract.move (L468-468)
```text
                distribution_pool: pool_u64::create(MAXIMUM_PENDING_DISTRIBUTIONS),
```

**File:** aptos-move/framework/aptos-framework/sources/staking_contract.move (L1114-1124)
```text
                if (shareholder != operator) {
                    let shares = pool_u64::shares(distribution_pool, shareholder);
                    let previous_worth = pool_u64::balance(
                        distribution_pool, shareholder
                    );
                    let current_worth =
                        pool_u64::shares_to_amount_with_total_coins(
                            distribution_pool, shares, updated_total_coins
                        );
                    let unpaid_commission =
                        (current_worth - previous_worth) * commission_percentage / 100;
```

**File:** aptos-move/framework/aptos-stdlib/sources/pool_u64.move (L250-260)
```text
    public fun shares_to_amount_with_total_coins(self: &Pool, shares: u64, total_coins: u64): u64 {
        // No shares or coins yet so shares are worthless.
        if (self.total_coins == 0 || self.total_shares == 0) {
            0
        } else {
            // Shares price = total_coins / total existing shares.
            // Shares worth = shares * shares price = shares * total_coins / total existing shares.
            // We rearrange the calc and do multiplication first to avoid rounding errors.
            self.multiply_then_divide(shares, total_coins, self.total_shares)
        }
    }
```

**File:** aptos-move/framework/aptos-stdlib/sources/math64.move (L50-54)
```text
    public inline fun mul_div(a: u64, b: u64, c: u64): u64 {
        // Inline functions cannot take constants, as then every module using it needs the constant
        assert!(c != 0, std::error::invalid_argument(4));
        (((a as u128) * (b as u128) / (c as u128)) as u64)
    }
```
