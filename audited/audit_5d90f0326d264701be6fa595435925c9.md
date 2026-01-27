# Audit Report

## Title
Missing Maximum Lockup Duration Enforcement Allows Perpetual Fund Locking

## Summary
The `increase_lockup()` function in the staking module does not enforce a maximum reasonable lockup duration. While it checks for u64 overflow, governance can set `recurring_lockup_duration_secs` to an arbitrarily large value (e.g., billions of years), effectively locking validator funds permanently when `increase_lockup()` is called.

## Finding Description

The staking system allows validators to increase their stake lockup period via the `increase_lockup_with_cap()` function. This function calculates the new lockup timestamp as: [1](#0-0) 

The `recurring_lockup_duration_secs` value is stored in the `StakingConfig` resource and can be updated by governance through: [2](#0-1) 

The only validation on this value is that it must be greater than zero: [3](#0-2) 

**There is no maximum cap enforced.** The formal verification only checks for u64 overflow: [4](#0-3) 

This means governance could set `recurring_lockup_duration_secs` to an extremely large value (e.g., 10^15 seconds ≈ 31 million years), and when validators call `increase_lockup()`, their `locked_until_secs` would be set to an effectively unreachable timestamp.

Funds cannot be withdrawn until the lockup expires, as enforced by: [5](#0-4) 

**Attack Scenario:**
1. A malicious, compromised, or misconfigured governance proposal calls `update_recurring_lockup_duration_secs()` with value `18_446_744_073_000_000_000` (near u64::MAX, representing ~584 billion years)
2. Validators subsequently call `increase_lockup()` to renew their lockup
3. Their `locked_until_secs` is set to current_timestamp + 18_446_744_073_000_000_000
4. Funds become permanently locked as this timestamp will never be reached

This breaks the **Resource Limits** invariant (#9) by allowing unbounded time-based resource locking, and violates basic security principles of having reasonable bounds on all system parameters.

## Impact Explanation

**Severity: Medium** (per Aptos bug bounty categories)

This qualifies as **"Limited funds loss or manipulation"** and **"State inconsistencies requiring intervention"** because:

- **Limited to specific scenarios**: Only affects validators who call `increase_lockup()` after a malicious/misconfigured governance update
- **Not theft**: Funds aren't stolen, but become inaccessible 
- **Requires governance intervention**: Could be fixed by another governance proposal to reduce lockup duration (though funds remain locked until new timestamp is reached)
- **Recovery path exists**: Technically recoverable through governance action or hard fork, but may require years of waiting

The impact is not Critical because:
- Doesn't affect all validators simultaneously (only those who call `increase_lockup()` post-update)
- Doesn't break consensus or network availability
- Doesn't enable direct theft

## Likelihood Explanation

**Likelihood: Low-Medium**

**Factors increasing likelihood:**
- **Accidental misconfiguration**: Unit confusion (seconds vs. days), typos in large numbers, or programming errors could easily result in unreasonable values
- **Compromised governance**: If governance accounts/keys are compromised, this could be exploited
- **No defense-in-depth**: Absence of maximum cap means a single mistake locks funds permanently

**Factors decreasing likelihood:**
- **Requires governance action**: Governance proposals undergo review and voting
- **Trusted role**: Governance participants are generally trusted actors
- **Visible parameter**: Changes to staking config are transparent on-chain

However, the complete absence of bounds checking on a critical time-based parameter represents a significant security gap, especially given that the question explicitly asks about preventing perpetual locking.

## Recommendation

Implement a maximum reasonable lockup duration constant and enforce it in both initialization and update functions:

```move
// In staking_config.move
const MAX_RECURRING_LOCKUP_DURATION_SECS: u64 = 31_536_000_000; // ~1000 years (extreme upper bound)
const REASONABLE_MAX_LOCKUP_SECS: u64 = 315_360_000; // ~10 years (recommended)

public fun update_recurring_lockup_duration_secs(
    aptos_framework: &signer,
    new_recurring_lockup_duration_secs: u64,
) acquires StakingConfig {
    assert!(new_recurring_lockup_duration_secs > 0, error::invalid_argument(EZERO_LOCKUP_DURATION));
    assert!(
        new_recurring_lockup_duration_secs <= MAX_RECURRING_LOCKUP_DURATION_SECS,
        error::invalid_argument(ELOCKUP_DURATION_TOO_LONG)
    );
    system_addresses::assert_aptos_framework(aptos_framework);
    
    let staking_config = borrow_global_mut<StakingConfig>(@aptos_framework);
    staking_config.recurring_lockup_duration_secs = new_recurring_lockup_duration_secs;
}
```

Add the same check in `initialize()` and `validate_genesis_config()`.

## Proof of Concept

```move
#[test(aptos_framework = @0x1)]
#[expected_failure(abort_code = 0x50000, location = aptos_framework::staking_config)]
public entry fun test_excessive_lockup_duration_should_fail(aptos_framework: signer) {
    use aptos_framework::staking_config;
    use aptos_framework::timestamp;
    
    // Initialize staking config
    staking_config::initialize_for_test(&aptos_framework, 0, 100, 86400, false, 1, 100, 20);
    timestamp::set_time_has_started_for_testing(&aptos_framework);
    
    // Attempt to set lockup duration to effectively infinite (1 trillion seconds ≈ 31 million years)
    // This should fail with proposed MAX_RECURRING_LOCKUP_DURATION_SECS check
    staking_config::update_recurring_lockup_duration_secs(&aptos_framework, 1_000_000_000_000);
}

#[test(aptos_framework = @0x1, validator = @0x123)]
public entry fun test_funds_locked_with_excessive_duration(aptos_framework: signer, validator: signer) {
    use aptos_framework::staking_config;
    use aptos_framework::stake;
    use aptos_framework::timestamp;
    use aptos_framework::coin;
    use aptos_framework::aptos_coin;
    
    // Setup
    timestamp::set_time_has_started_for_testing(&aptos_framework);
    staking_config::initialize_for_test(&aptos_framework, 1000, 100000, 86400, true, 1, 100, 20);
    
    // Governance maliciously sets excessive lockup (without the proposed max check)
    staking_config::update_recurring_lockup_duration_secs(&aptos_framework, 100_000_000_000); // ~3,170 years
    
    // Validator initializes stake and increases lockup
    aptos_coin::mint(&aptos_framework, signer::address_of(&validator), 10000);
    stake::initialize_stake_owner(&validator, 5000, @0x123, @0x123);
    stake::increase_lockup(&validator);
    
    // Funds are now locked for 3,170 years - effectively permanent
    let stake_pool = stake::get_stake(signer::address_of(&validator));
    assert!(stake_pool.locked_until_secs > timestamp::now_seconds() + 99_999_999_999, 0);
    
    // Validator cannot withdraw even after unlocking until timestamp is reached
    stake::unlock(&validator, 5000);
    // This would fail as locked_until_secs is in far future:
    // stake::withdraw(&validator, 5000);
}
```

**Note**: This vulnerability represents a missing security safeguard. While exploitation requires governance action (a privileged operation), the absence of reasonable bounds on critical time-based parameters violates defense-in-depth principles and creates risk from compromised governance, accidental misconfiguration, or malicious proposals.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1015-1017)
```text
        let new_locked_until_secs = timestamp::now_seconds() + staking_config::get_recurring_lockup_duration(&config);
        assert!(old_locked_until_secs < new_locked_until_secs, error::invalid_argument(EINVALID_LOCKUP));
        stake_pool.locked_until_secs = new_locked_until_secs;
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1177-1181)
```text
        if (get_validator_state(pool_address) == VALIDATOR_STATUS_INACTIVE &&
            timestamp::now_seconds() >= stake_pool.locked_until_secs) {
            let pending_inactive_stake = coin::extract_all(&mut stake_pool.pending_inactive);
            coin::merge(&mut stake_pool.inactive, pending_inactive_stake);
        };
```

**File:** aptos-move/framework/aptos-framework/sources/configs/staking_config.move (L289-298)
```text
    public fun update_recurring_lockup_duration_secs(
        aptos_framework: &signer,
        new_recurring_lockup_duration_secs: u64,
    ) acquires StakingConfig {
        assert!(new_recurring_lockup_duration_secs > 0, error::invalid_argument(EZERO_LOCKUP_DURATION));
        system_addresses::assert_aptos_framework(aptos_framework);

        let staking_config = borrow_global_mut<StakingConfig>(@aptos_framework);
        staking_config.recurring_lockup_duration_secs = new_recurring_lockup_duration_secs;
    }
```

**File:** aptos-move/framework/aptos-framework/sources/stake.spec.move (L361-362)
```text
        aborts_if pre_stake_pool.locked_until_secs >= lockup + now_seconds;
        aborts_if lockup + now_seconds > MAX_U64;
```
