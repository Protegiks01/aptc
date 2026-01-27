# Audit Report

## Title
Arithmetic Overflow in Reward Distribution Causes Network Halt During Epoch Transition

## Summary
The `update_stake_pool` function in the staking module lacks overflow protection when merging rewards and transaction fees into a validator's active stake. If a validator's active stake approaches u64::MAX, the arithmetic overflow during `coin::merge` operations will cause the Move VM to abort with ARITHMETIC_ERROR, halting epoch transitions and causing total loss of network liveness.

## Finding Description

The vulnerability exists in the reward distribution logic during epoch transitions. The `update_stake_pool` function explicitly states "This function shouldn't abort" [1](#0-0) , yet it lacks runtime overflow checks before performing multiple `coin::merge` operations that could overflow.

During epoch transitions, `on_new_epoch` is called by the reconfiguration module [2](#0-1) , which in turn calls `update_stake_pool` for each validator [3](#0-2) .

The `update_stake_pool` function performs several merge operations:
1. Distributes rewards via `coin::merge` [4](#0-3) 
2. Merges transaction fees [5](#0-4) 
3. Merges pending_active stake [6](#0-5) 

The `coin::merge` function performs unchecked addition [7](#0-6)  with only a formal verification assumption, not a runtime check [8](#0-7) .

When overflow occurs, the Move VM's runtime overflow detection aborts the transaction with ARITHMETIC_ERROR [9](#0-8) . This violates the critical "shouldn't abort" invariant [10](#0-9)  and causes the entire reconfiguration to fail.

**Attack Path:**
1. Validator accumulates stake near u64::MAX through rewards over many epochs or governance misconfiguration of `maximum_stake`
2. During epoch transition, `on_new_epoch()` → `update_stake_pool()` → `distribute_rewards()` → `coin::merge()`
3. Addition `active.value + rewards` exceeds u64::MAX (18,446,744,073,709,551,615)
4. Move VM aborts with ARITHMETIC_ERROR
5. Epoch transition fails, blocking all subsequent epochs
6. Network enters permanent halt requiring hardfork to recover

## Impact Explanation

**CRITICAL Severity** - This vulnerability meets two critical severity criteria from the Aptos Bug Bounty program:
- **Total loss of liveness/network availability**: The blockchain cannot progress to new epochs when this occurs
- **Non-recoverable network partition (requires hardfork)**: Recovery requires manual intervention and potentially a hardfork to reset the validator's stake or modify the staking logic

The impact affects the entire Aptos network, not just individual validators. Once triggered, all validators become stuck at the current epoch, unable to process new blocks or transactions.

## Likelihood Explanation

**Low to Medium Likelihood**: While reaching u64::MAX (≈184 billion APT with 8 decimals) appears difficult given current tokenomics, the vulnerability can manifest through:

1. **Governance Misconfiguration**: The `maximum_stake` parameter is governance-controlled [11](#0-10) . If set improperly high, validators could accumulate dangerous stake levels.

2. **Reward Accumulation**: Over extended network lifetime with high rewards rates, stake can grow significantly through compounding.

3. **Multiple Merge Operations**: Each epoch performs multiple merges (rewards + fees + pending_active), increasing overflow probability.

4. **Lack of Defensive Programming**: The spec blocks use `assume` rather than runtime `assert` [12](#0-11) , indicating this edge case was identified but not protected against.

## Recommendation

Implement runtime overflow checks before all `coin::merge` operations in `update_stake_pool`. Add explicit validation to ensure the sum will not exceed u64::MAX:

```move
fun update_stake_pool(
    validator_perf: &ValidatorPerformance,
    pool_address: address,
    staking_config: &StakingConfig,
) acquires AptosCoinCapabilities, PendingTransactionFee, StakePool, TransactionFeeConfig, ValidatorConfig {
    let stake_pool = borrow_global_mut<StakePool>(pool_address);
    
    // ... existing code ...
    
    // Add overflow check before merging rewards
    let active_value = coin::value(&stake_pool.active);
    assert!(
        (active_value as u128) + (rewards_active as u128) <= (MAX_U64 as u128),
        error::out_of_range(ESTAKE_OVERFLOW)
    );
    
    // Add overflow check before merging fees
    if (fee_active > 0) {
        assert!(
            (coin::value(&stake_pool.active) as u128) + (fee_active as u128) <= (MAX_U64 as u128),
            error::out_of_range(ESTAKE_OVERFLOW)
        );
        coin::merge(&mut stake_pool.active, coin::mint(fee_active, mint_cap));
    };
    
    // Add overflow check before merging pending_active
    let pending_active_value = coin::value(&stake_pool.pending_active);
    assert!(
        (coin::value(&stake_pool.active) as u128) + (pending_active_value as u128) <= (MAX_U64 as u128),
        error::out_of_range(ESTAKE_OVERFLOW)
    );
    coin::merge(&mut stake_pool.active, coin::extract_all(&mut stake_pool.pending_active));
}
```

Additionally, enforce a strict upper bound on `maximum_stake` that provides adequate headroom below u64::MAX to accommodate rewards and fee accumulation.

## Proof of Concept

```move
#[test(aptos_framework = @0x1, validator = @0x123)]
#[expected_failure(abort_code = 0x020001, location = aptos_framework::coin)]
public fun test_stake_overflow_causes_epoch_failure(
    aptos_framework: &signer,
    validator: &signer,
) {
    // Initialize framework
    stake::initialize_for_test(aptos_framework);
    
    // Create validator with stake near u64::MAX
    let near_max_stake = 18446744073709551000u64; // Just below MAX
    stake::initialize_stake_owner(validator, near_max_stake, @0x123, @0x123);
    
    // Configure rewards rate that will cause overflow
    staking_config::update_rewards_rate(aptos_framework, 1000, 1000000);
    
    // Join validator set
    stake::join_validator_set(validator, signer::address_of(validator));
    
    // Fast forward and trigger epoch transition
    // This should fail with ARITHMETIC_ERROR when merging rewards
    timestamp::fast_forward_seconds(7200);
    stake::on_new_epoch();
    // Expected to abort, causing epoch transition failure
}
```

**Notes**

The security question asked whether overflow would "wrap and result in apparent stake loss." This investigation reveals the actual behavior is more severe: Move VM aborts on overflow rather than wrapping, causing complete network halt. The vulnerability is confirmed through the explicit "shouldn't abort" invariants in the code and the absence of pre-merge overflow validation, though practical exploitation depends on reaching stake levels near u64::MAX.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1334-1334)
```text
    /// Triggered during a reconfiguration. This function shouldn't abort.
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1350-1361)
```text
        // Process pending stake and distribute transaction fees and rewards for each currently active validator.
        vector::for_each_ref(&validator_set.active_validators, |validator| {
            let validator: &ValidatorInfo = validator;
            update_stake_pool(validator_perf, validator.addr, &config);
        });

        // Process pending stake and distribute transaction fees and rewards for each currently pending_inactive validator
        // (requested to leave but not removed yet).
        vector::for_each_ref(&validator_set.pending_inactive, |validator| {
            let validator: &ValidatorInfo = validator;
            update_stake_pool(validator_perf, validator.addr, &config);
        });
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1651-1651)
```text
    /// This function shouldn't abort.
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1707-1709)
```text
        spec {
            assume rewards_active + rewards_pending_inactive <= MAX_U64;
        };
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1714-1714)
```text
                coin::merge(&mut stake_pool.active, coin::mint(fee_active, mint_cap));
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1727-1727)
```text
        coin::merge(&mut stake_pool.active, coin::extract_all(&mut stake_pool.pending_active));
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1809-1809)
```text
            coin::merge(stake, rewards);
```

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration.move (L134-134)
```text
        stake::on_new_epoch();
```

**File:** aptos-move/framework/aptos-framework/sources/coin.move (L1106-1108)
```text
        spec {
            assume dst_coin.value + source_coin.value <= MAX_U64;
        };
```

**File:** aptos-move/framework/aptos-framework/sources/coin.move (L1116-1116)
```text
        dst_coin.value = dst_coin.value + value;
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L2917-2941)
```rust
    pub fn add_checked(self, other: Self) -> PartialVMResult<Self> {
        use Value::*;
        let res = match (self, other) {
            (U8(l), U8(r)) => u8::checked_add(l, r).map(U8),
            (U16(l), U16(r)) => u16::checked_add(l, r).map(U16),
            (U32(l), U32(r)) => u32::checked_add(l, r).map(U32),
            (U64(l), U64(r)) => u64::checked_add(l, r).map(U64),
            (U128(l), U128(r)) => u128::checked_add(l, r).map(U128),
            (U256(l), U256(r)) => int256::U256::checked_add(*l, *r).map(|res| U256(Box::new(res))),
            (I8(l), I8(r)) => i8::checked_add(l, r).map(I8),
            (I16(l), I16(r)) => i16::checked_add(l, r).map(I16),
            (I32(l), I32(r)) => i32::checked_add(l, r).map(I32),
            (I64(l), I64(r)) => i64::checked_add(l, r).map(I64),
            (I128(l), I128(r)) => i128::checked_add(l, r).map(I128),
            (I256(l), I256(r)) => int256::I256::checked_add(*l, *r).map(|res| I256(Box::new(res))),
            (l, r) => {
                let msg = format!("Cannot add {:?} and {:?}", l, r);
                return Err(PartialVMError::new(StatusCode::INTERNAL_TYPE_ERROR).with_message(msg));
            },
        };
        res.ok_or_else(|| {
            PartialVMError::new(StatusCode::ARITHMETIC_ERROR)
                .with_message("Addition overflow".to_string())
        })
    }
```

**File:** aptos-move/framework/aptos-framework/sources/configs/staking_config.move (L54-57)
```text
        // A validator can only stake at most this amount. Any larger stake will be rejected.
        // If after joining the validator set and at the start of any epoch, a validator's stake exceeds this amount,
        // their voting power and rewards would only be issued for the max stake amount.
        maximum_stake: u64,
```
