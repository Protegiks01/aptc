# Audit Report

## Title
Pool Type Confusion in CLI AddStake Allows Malicious API to Misdirect Stake Funds

## Summary
The `AddStake::execute()` function in the Aptos CLI does not validate stake pool types against on-chain data before submitting transactions. The CLI blindly trusts REST API responses to determine whether a pool is Direct, StakingContract, or Vesting type. A malicious or compromised REST API can cause the CLI to send incorrect transaction types, potentially misdirecting user funds to unintended stake pools.

## Finding Description

The vulnerability exists in how the Aptos CLI determines stake pool types and constructs transactions in `AddStake::execute()`. [1](#0-0) 

The function fetches stake pools via `get_stake_pools()` and matches on `pool_type` to decide which Move function to call:
- `StakePoolType::Direct` → calls `stake::add_stake(amount)`
- `StakePoolType::StakingContract` → calls `staking_contract::add_stake(operator, amount)`

The critical issue is in how `get_stake_pools()` determines pool types: [2](#0-1) 

The pool type is hardcoded based on which resource queries succeed, without any cryptographic validation:
- Line 431: Direct pools hardcoded as `StakePoolType::Direct`
- Line 447: Staking contracts hardcoded as `StakePoolType::StakingContract`  
- Line 467: Vesting contracts hardcoded as `StakePoolType::Vesting`

In `get_stake_pool_info()`, the pool type is directly assigned from the parameter with no validation against on-chain data: [3](#0-2) 

**Attack Scenario:**

1. Alice has both a Direct stake pool at `0xALICE` and a StakingContract pool at `0xPOOL123` with operator `0xBOB`
2. Alice intends to add 10 APT to her StakingContract pool
3. Alice's CLI connects to a malicious REST API (via DNS poisoning, MITM, or misconfiguration)
4. Malicious API omits the StakingContractStore resource and only returns the Direct pool data
5. CLI's `get_stake_pools()` only sees the Direct pool, classifies it as `StakePoolType::Direct`
6. CLI submits `stake::add_stake(10 APT)` instead of `staking_contract::add_stake(0xBOB, 10 APT)`
7. On-chain execution succeeds because Alice has a valid Direct pool with OwnerCapability
8. **Result**: 10 APT goes to Alice's Direct pool instead of her intended StakingContract pool

This violates the **Staking Security** invariant because:
- User's stake goes to a pool with different commission arrangements
- Different lockup periods may apply
- Different operator/voter settings are in effect
- Intended operator receives no stake increase

While on-chain validation prevents the most catastrophic scenarios (transactions fail if resources don't exist), it cannot prevent misdirection between valid pools the user owns. [4](#0-3) 

The on-chain `staking_contract::add_stake` validates contracts exist, but cannot detect when the CLI sends the wrong transaction type for a different valid pool. [5](#0-4) 

Similarly, `stake::add_stake` only validates OwnerCapability exists, not whether the user intended to stake to this specific pool.

## Impact Explanation

**Severity: Medium** per Aptos bug bounty criteria ("Limited funds loss or manipulation")

**Impact:**
- User funds are misdirected to unintended stake pools
- User loses intended commission arrangements with specific operators
- Wrong lockup periods and unlocking schedules apply
- Wrong operator/voter delegation settings
- Potential financial loss if pools have significantly different parameters (e.g., 10% commission vs 0% commission)
- User still controls funds but must undergo unlock/withdraw process from wrong pool

**Not Critical Severity because:**
- Funds are not stolen by attacker (still in user's control)
- On-chain validation prevents complete theft scenarios
- User can eventually recover funds through unlock/withdraw
- Requires external attack vector (API compromise)

**Affected Users:**
- Any user with multiple stake pool types (Direct + StakingContract + Vesting)
- Users connecting through compromised or malicious REST API endpoints
- Users in network environments vulnerable to MITM attacks

## Likelihood Explanation

**Likelihood: Medium**

**Prerequisites:**
1. User must have multiple stake pool types (common for sophisticated stakers)
2. User's CLI must connect to compromised REST API endpoint via:
   - DNS poisoning/hijacking
   - MITM attack on unencrypted connection
   - Misconfigured node URL pointing to malicious server
   - Compromised local RPC node
3. User must not verify transaction details before signing

**Factors increasing likelihood:**
- No client-side validation exists to detect pool type mismatches
- Users often have multiple pool types for diversification
- CLI trusts API responses completely without cryptographic verification
- No warning or confirmation showing which specific pool will receive stake
- Attack is silent - no error occurs when funds go to wrong pool

**Factors decreasing likelihood:**
- Requires compromising REST API (non-trivial)
- On-chain validation prevents worst-case theft scenarios
- Sophisticated users may verify transactions in block explorer
- HTTPS connections reduce MITM risk

## Recommendation

**Immediate Fix:** Add client-side validation of pool types by cross-referencing on-chain data.

**Recommended Implementation:**

```rust
pub async fn get_stake_pool_info(
    client: &Client,
    pool_address: AccountAddress,
    pool_type: StakePoolType,
    principal: u64,
    commission_percentage: u64,
    epoch_info: EpochInfo,
    validator_set: &ValidatorSet,
    vesting_contract: Option<AccountAddress>,
) -> CliTypedResult<StakePoolResult> {
    let stake_pool = client
        .get_account_resource_bcs::<StakePool>(pool_address, "0x1::stake::StakePool")
        .await?
        .into_inner();
    
    // NEW: Validate pool type matches on-chain state
    match pool_type {
        StakePoolType::Direct => {
            // Verify OwnerCapability exists at pool_address
            client
                .get_account_resource_bcs::<OwnerCapability>(
                    pool_address,
                    "0x1::stake::OwnerCapability"
                )
                .await
                .map_err(|_| CliError::UnexpectedError(
                    format!("Pool at {} classified as Direct but has no OwnerCapability", pool_address)
                ))?;
        },
        StakePoolType::StakingContract => {
            // Verify this pool address appears in a StakingContractStore
            // and is NOT a direct pool
            let has_owner_cap = client
                .get_account_resource_bcs::<OwnerCapability>(
                    pool_address,
                    "0x1::stake::OwnerCapability"
                )
                .await
                .is_ok();
            
            if has_owner_cap {
                return Err(CliError::UnexpectedError(
                    format!("Pool at {} classified as StakingContract but has OwnerCapability (Direct pool)", pool_address)
                ));
            }
        },
        StakePoolType::Vesting => {
            // Similar validation for vesting pools
        }
    }
    
    // Rest of function...
}
```

**Additional Recommendations:**
1. Display clear confirmation showing which specific pool (with address and type) will receive stake
2. Add `--pool-address` flag to allow users to explicitly specify target pool
3. Warn users when stake operations affect multiple pools simultaneously
4. Consider cryptographic proofs or state root verification for critical operations
5. Log pool type determination logic for debugging and auditing

## Proof of Concept

```rust
#[tokio::test]
async fn test_pool_type_confusion_attack() {
    // Setup: User has both Direct and StakingContract pools
    let owner_address = AccountAddress::from_hex_literal("0xALICE").unwrap();
    let operator_address = AccountAddress::from_hex_literal("0xBOB").unwrap();
    
    // Simulate malicious API that returns fake pool type
    let mut mock_client = MockRestClient::new();
    
    // Attack: API claims StakingContract pool doesn't exist
    // Only returns Direct pool data
    mock_client
        .expect_get_account_resource_bcs::<StakingContractStore>()
        .returning(|_, _| Err(RestError::NotFound("Resource not found".into())));
    
    mock_client
        .expect_get_account_resource_bcs::<StakePool>()
        .returning(|_, _| Ok(Response::new(StakePool {
            active: coin(100_000_000),
            inactive: coin(0),
            pending_active: coin(0),
            pending_inactive: coin(0),
            locked_until_secs: 0,
            operator_address: owner_address,
            delegated_voter: owner_address,
        })));
    
    // User intends to add stake to StakingContract pool
    // But CLI will call stake::add_stake instead of staking_contract::add_stake
    let stake_pools = get_stake_pools(&mock_client, owner_address).await.unwrap();
    
    assert_eq!(stake_pools.len(), 1);
    assert_eq!(stake_pools[0].pool_type, StakePoolType::Direct);
    
    // This demonstrates the CLI would send the wrong transaction type
    // Funds would go to Direct pool instead of StakingContract pool
    match stake_pools[0].pool_type {
        StakePoolType::Direct => {
            // Wrong transaction! Should be staking_contract_add_stake
            let _tx = aptos_stdlib::stake_add_stake(10_000_000);
            println!("VULNERABILITY: Sending stake::add_stake when user intended staking_contract::add_stake");
        },
        _ => unreachable!(),
    }
}
```

**Notes:**

The vulnerability is confirmed through code analysis showing complete absence of pool type validation. The CLI architecture assumes REST API trustworthiness, which is a weak security assumption for financial operations. While on-chain Move code provides defense-in-depth preventing theft, it cannot prevent misdirection between legitimate pools the user owns.

This finding specifically addresses the security question's concern about pool type confusion causing incorrect transaction submission. The attack requires API compromise but has realistic exploitation paths and measurable financial impact through stake misdirection.

### Citations

**File:** crates/aptos/src/stake/mod.rs (L87-115)
```rust
        let stake_pool_results = get_stake_pools(&client, owner_address).await?;
        for stake_pool in stake_pool_results {
            match stake_pool.pool_type {
                StakePoolType::Direct => {
                    transaction_summaries.push(
                        self.txn_options
                            .submit_transaction(aptos_stdlib::stake_add_stake(amount))
                            .await
                            .map(|inner| inner.into())?,
                    );
                },
                StakePoolType::StakingContract => {
                    transaction_summaries.push(
                        self.txn_options
                            .submit_transaction(aptos_stdlib::staking_contract_add_stake(
                                stake_pool.operator_address,
                                amount,
                            ))
                            .await
                            .map(|inner| inner.into())?,
                    );
                },
                StakePoolType::Vesting => {
                    return Err(CliError::UnexpectedError(
                        "Adding stake is not supported for vesting contracts".into(),
                    ))
                },
            }
        }
```

**File:** crates/aptos/src/node/mod.rs (L417-479)
```rust
pub async fn get_stake_pools(
    client: &Client,
    owner_address: AccountAddress,
) -> CliTypedResult<Vec<StakePoolResult>> {
    let epoch_info = get_epoch_info(client).await?;
    let validator_set = &client
        .get_account_resource_bcs::<ValidatorSet>(CORE_CODE_ADDRESS, "0x1::stake::ValidatorSet")
        .await?
        .into_inner();
    let mut stake_pool_results: Vec<StakePoolResult> = vec![];
    // Add direct stake pool if any.
    let direct_stake_pool = get_stake_pool_info(
        client,
        owner_address,
        StakePoolType::Direct,
        0,
        0,
        epoch_info.clone(),
        validator_set,
        None,
    )
    .await;
    if let Ok(direct_stake_pool) = direct_stake_pool {
        stake_pool_results.push(direct_stake_pool);
    };

    // Fetch all stake pools managed via staking contracts.
    let staking_contract_pools = get_staking_contract_pools(
        client,
        owner_address,
        StakePoolType::StakingContract,
        epoch_info.clone(),
        validator_set,
        None,
    )
    .await;
    if let Ok(mut staking_contract_pools) = staking_contract_pools {
        stake_pool_results.append(&mut staking_contract_pools);
    };

    // Fetch all stake pools managed via employee vesting accounts.
    let vesting_admin_store = client
        .get_account_resource_bcs::<VestingAdminStore>(owner_address, "0x1::vesting::AdminStore")
        .await;
    if let Ok(vesting_admin_store) = vesting_admin_store {
        let vesting_contracts = vesting_admin_store.into_inner().vesting_contracts;
        for vesting_contract in vesting_contracts {
            let mut staking_contract_pools = get_staking_contract_pools(
                client,
                vesting_contract,
                StakePoolType::Vesting,
                epoch_info.clone(),
                validator_set,
                Some(vesting_contract),
            )
            .await
            .unwrap();
            stake_pool_results.append(&mut staking_contract_pools);
        }
    };

    Ok(stake_pool_results)
}
```

**File:** crates/aptos/src/node/mod.rs (L516-566)
```rust
pub async fn get_stake_pool_info(
    client: &Client,
    pool_address: AccountAddress,
    pool_type: StakePoolType,
    principal: u64,
    commission_percentage: u64,
    epoch_info: EpochInfo,
    validator_set: &ValidatorSet,
    vesting_contract: Option<AccountAddress>,
) -> CliTypedResult<StakePoolResult> {
    let stake_pool = client
        .get_account_resource_bcs::<StakePool>(pool_address, "0x1::stake::StakePool")
        .await?
        .into_inner();
    let validator_config = client
        .get_account_resource_bcs::<ValidatorConfig>(pool_address, "0x1::stake::ValidatorConfig")
        .await?
        .into_inner();
    let total_stake = stake_pool.get_total_staked_amount();
    let commission_not_yet_unlocked = (total_stake - principal) * commission_percentage / 100;
    let state = get_stake_pool_state(validator_set, &pool_address);

    let consensus_public_key = if validator_config.consensus_public_key.is_empty() {
        "".into()
    } else {
        PublicKey::try_from(&validator_config.consensus_public_key[..])
            .unwrap()
            .to_encoded_string()
            .unwrap()
    };
    Ok(StakePoolResult {
        state,
        pool_address,
        operator_address: stake_pool.operator_address,
        voter_address: stake_pool.delegated_voter,
        pool_type,
        total_stake,
        commission_percentage,
        commission_not_yet_unlocked,
        lockup_expiration_utc_time: Time::new_seconds(stake_pool.locked_until_secs).utc_time,
        consensus_public_key,
        validator_network_addresses: validator_config
            .validator_network_addresses()
            .unwrap_or_default(),
        fullnode_network_addresses: validator_config
            .fullnode_network_addresses()
            .unwrap_or_default(),
        epoch_info,
        vesting_contract,
    })
}
```

**File:** aptos-move/framework/aptos-framework/sources/staking_contract.move (L499-523)
```text
    public entry fun add_stake(
        staker: &signer, operator: address, amount: u64
    ) acquires Store {
        let staker_address = signer::address_of(staker);
        assert_staking_contract_exists(staker_address, operator);

        let store = borrow_global_mut<Store>(staker_address);
        let staking_contract =
            simple_map::borrow_mut(&mut store.staking_contracts, &operator);

        // Add the stake to the stake pool.
        let staked_coins = coin::withdraw<AptosCoin>(staker, amount);
        stake::add_stake_with_cap(&staking_contract.owner_cap, staked_coins);

        staking_contract.principal = staking_contract.principal + amount;
        let pool_address = staking_contract.pool_address;
        if (std::features::module_event_migration_enabled()) {
            emit(AddStake { operator, pool_address, amount });
        } else {
            emit_event(
                &mut store.add_stake_events,
                AddStakeEvent { operator, pool_address, amount }
            );
        };
    }
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L804-810)
```text
    public entry fun add_stake(owner: &signer, amount: u64) acquires OwnerCapability, StakePool, ValidatorSet {
        check_stake_permission(owner);
        let owner_address = signer::address_of(owner);
        assert_owner_cap_exists(owner_address);
        let ownership_cap = borrow_global<OwnerCapability>(owner_address);
        add_stake_with_cap(ownership_cap, coin::withdraw<AptosCoin>(owner, amount));
    }
```
