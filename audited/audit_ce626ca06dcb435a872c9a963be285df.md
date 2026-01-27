# Audit Report

## Title
Arithmetic Overflow in Stake Reward Distribution Causes Network Halt

## Summary
The `coin::merge` function performs unchecked u64 addition that will cause transaction abort when distributing rewards to validators with stake amounts near `u64::MAX`. Since genesis configuration allows `maximum_stake` to be set up to `u64::MAX` without upper bound validation, validators initialized with near-maximum stake will cause the `on_new_epoch` function to abort when rewards are added, resulting in total network liveness failure.

## Finding Description

The vulnerability exists in the reward distribution mechanism during epoch transitions. The attack path proceeds as follows:

**Step 1: Genesis Configuration**
During genesis setup, the `Layout` struct in `config.rs` allows `max_stake` to be set to any value, with the only validation being that `minimum_stake <= maximum_stake && maximum_stake > 0`. [1](#0-0) 

A validator can be initialized with `stake_amount` approaching `u64::MAX`: [2](#0-1) 

**Step 2: Stake Pool Initialization**
During genesis, the validator's stake pool is created with this amount via `initialize_stake_owner`, which calls `add_stake`: [3](#0-2) 

The `add_stake` function validates that `voting_power <= maximum_stake`, which passes if `maximum_stake = u64::MAX`: [4](#0-3) 

**Step 3: Epoch Transition Triggers Overflow**
During the first epoch transition, `on_new_epoch` calls `update_stake_pool` for each validator to distribute rewards: [5](#0-4) 

The `distribute_rewards` function mints rewards and merges them into the stake coin: [6](#0-5) 

**Step 4: Unchecked Arithmetic Overflow**
The `coin::merge` function performs direct u64 addition **without overflow protection**: [7](#0-6) 

The only "protection" is a specification assumption for formal verification (line 1107), which does **not** generate runtime checks. When `dst_coin.value` is near `u64::MAX` and any non-zero `value` is added, the addition at line 1116 overflows, causing the Move VM to abort the transaction.

**Invariant Violations:**
- **Staking Security (Invariant #6)**: Rewards cannot be distributed correctly
- **Deterministic Execution (Invariant #1)**: Epoch transition fails non-deterministically based on stake configuration
- **Resource Limits (Invariant #9)**: No upper bound protection on combined stake + rewards

## Impact Explanation

This is a **Critical Severity** vulnerability meeting the "Total loss of liveness/network availability" category:

1. **Network Halt**: When `on_new_epoch` aborts due to overflow, the epoch transition fails. All validators cannot progress to the next epoch, effectively halting the entire network.

2. **Requires Hard Fork**: Recovery requires a hard fork to either:
   - Reset the problematic validator's stake to a safe value
   - Modify the reward distribution logic
   - Update the coin merge implementation

3. **Consensus Impact**: The epoch transition is a consensus-critical operation. Its failure affects all validators simultaneously, creating a network-wide outage.

4. **Permanent State**: Once a validator reaches this state, every subsequent epoch transition will fail until manual intervention.

The same overflow can occur when distributing transaction fees: [8](#0-7) 

## Likelihood Explanation

**Likelihood: Medium to High for private/test networks, Low for mainnet**

**Requirements:**
- Control over genesis configuration (Layout `max_stake` value)
- Ability to set validator `stake_amount` to near `u64::MAX`

**In Production Mainnet:**
- Genesis configuration is controlled by Aptos Foundation/governance
- Unlikely to set `max_stake = u64::MAX` intentionally
- However, no code-level protection exists if governance is compromised

**In Private Chains/Testnets:**
- Network operators have full control over genesis configuration
- Accidental or intentional misconfiguration is more likely
- High impact for organizations running private Aptos chains

**Exploitability:**
Once configured, the vulnerability is deterministic and will trigger on the first epoch transition where rewards are distributed.

## Recommendation

**Immediate Fix:** Add overflow protection in `coin::merge` before performing addition:

```move
public fun merge<CoinType>(
    dst_coin: &mut Coin<CoinType>, source_coin: Coin<CoinType>
) {
    let Coin { value } = source_coin;
    // Add explicit overflow check
    assert!(
        (MAX_U64 - dst_coin.value) >= value,
        error::out_of_range(ECOIN_AMOUNT_OVERFLOW)
    );
    dst_coin.value = dst_coin.value + value;
}
```

**Additional Safeguards:**

1. **Validate maximum_stake upper bound** in staking_config:
```move
fun validate_required_stake(minimum_stake: u64, maximum_stake: u64) {
    assert!(
        minimum_stake <= maximum_stake && 
        maximum_stake > 0 && 
        maximum_stake < (MAX_U64 / 2), // Leave headroom for rewards
        error::invalid_argument(EINVALID_STAKE_RANGE)
    );
}
```

2. **Pre-check in distribute_rewards** before merging:
```move
if (rewards_amount > 0) {
    let stake_value = coin::value(stake);
    assert!(
        (MAX_U64 - stake_value) >= rewards_amount,
        error::out_of_range(EREWARDS_OVERFLOW)
    );
    let mint_cap = &borrow_global<AptosCoinCapabilities>(@aptos_framework).mint_cap;
    let rewards = coin::mint(rewards_amount, mint_cap);
    coin::merge(stake, rewards);
}
```

## Proof of Concept

```move
#[test_only]
module aptos_framework::stake_overflow_test {
    use aptos_framework::stake;
    use aptos_framework::coin;
    use aptos_framework::aptos_coin::AptosCoin;
    use std::signer;

    #[test(aptos_framework = @0x1, validator_owner = @0x123)]
    #[expected_failure(arithmetic_error, location = aptos_framework::coin)]
    fun test_stake_overflow_on_rewards(
        aptos_framework: &signer,
        validator_owner: &signer,
    ) {
        // Setup: Initialize with max stake
        let max_stake = 18446744073709551615u64; // u64::MAX
        
        // Initialize genesis with max_stake = u64::MAX
        setup_genesis_with_max_stake(aptos_framework, max_stake);
        
        // Initialize validator with stake near MAX
        let initial_stake = max_stake - 1000;
        stake::initialize_stake_owner(
            validator_owner,
            initial_stake,
            signer::address_of(validator_owner),
            signer::address_of(validator_owner),
        );
        
        // Trigger epoch transition with rewards
        // This will call distribute_rewards -> coin::merge
        // which will overflow when adding even 1 octa to near-max stake
        stake::on_new_epoch();
        // Test expects arithmetic_error abort from coin::merge
    }
}
```

## Notes

This vulnerability demonstrates a critical gap in defensive programming where:
1. Genesis configuration lacks upper bound validation on stake limits
2. The `coin::merge` function relies solely on formal verification assumptions rather than runtime checks
3. Epoch-critical operations lack overflow protection for edge cases

While mainnet genesis is controlled by trusted actors, this vulnerability affects:
- Private Aptos chain deployments
- Test networks with custom configurations  
- Any scenario where governance could be compromised

The fix is straightforward and should be applied to prevent accidental or malicious network configuration that could cause total liveness failure.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/configs/staking_config.move (L372-374)
```text
    fun validate_required_stake(minimum_stake: u64, maximum_stake: u64) {
        assert!(minimum_stake <= maximum_stake && maximum_stake > 0, error::invalid_argument(EINVALID_STAKE_RANGE));
    }
```

**File:** crates/aptos-genesis/src/config.rs (L167-167)
```rust
    pub stake_amount: u64,
```

**File:** aptos-move/framework/aptos-framework/sources/genesis.move (L361-366)
```text
            stake::initialize_stake_owner(
                owner,
                validator.stake_amount,
                validator.operator_address,
                validator.voter_address,
            );
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L844-845)
```text
        let voting_power = get_next_epoch_voting_power(stake_pool);
        assert!(voting_power <= maximum_stake, error::invalid_argument(ESTAKE_EXCEEDS_MAX));
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1351-1354)
```text
        vector::for_each_ref(&validator_set.active_validators, |validator| {
            let validator: &ValidatorInfo = validator;
            update_stake_pool(validator_perf, validator.addr, &config);
        });
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1713-1714)
```text
            if (fee_active > 0) {
                coin::merge(&mut stake_pool.active, coin::mint(fee_active, mint_cap));
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1806-1810)
```text
        if (rewards_amount > 0) {
            let mint_cap = &borrow_global<AptosCoinCapabilities>(@aptos_framework).mint_cap;
            let rewards = coin::mint(rewards_amount, mint_cap);
            coin::merge(stake, rewards);
        };
```

**File:** aptos-move/framework/aptos-framework/sources/coin.move (L1106-1116)
```text
        spec {
            assume dst_coin.value + source_coin.value <= MAX_U64;
        };
        spec {
            update supply<CoinType> = supply<CoinType> - source_coin.value;
        };
        let Coin { value } = source_coin;
        spec {
            update supply<CoinType> = supply<CoinType> + value;
        };
        dst_coin.value = dst_coin.value + value;
```
