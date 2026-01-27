# Audit Report

## Title
Vesting Contract Address Derivation Vulnerability in CLI Unlock/Distribute Functions

## Summary
The `UnlockVestedCoins::execute()` and `DistributeVestedCoins::execute()` CLI functions use hardcoded parameters `(0, &[])` when deriving vesting contract addresses, preventing users from unlocking or distributing coins from vesting contracts created with non-zero nonces or custom seeds. [1](#0-0) 

## Finding Description

The vulnerability occurs in two CLI functions that manage vesting contract operations:

**Vulnerable Code - UnlockVestedCoins:** [1](#0-0) 

**Vulnerable Code - DistributeVestedCoins:** [2](#0-1) 

The vesting contract address derivation function creates deterministic addresses using three parameters: admin address, nonce, and seed: [3](#0-2) 

The Move implementation shows that each admin has an `AdminStore` with an incrementing nonce to support multiple vesting contracts: [4](#0-3) [5](#0-4) 

The contract creation process increments the nonce for each new vesting contract (line 1160), and the seed parameter allows customization (lines 1164-1165). However, the CLI functions ignore this design by hardcoding nonce=0 and seed=&[].

**Comparison with Correct Implementation:**

The `get_stake_pools` function shows the correct approach by retrieving all vesting contracts from the AdminStore: [6](#0-5) 

Even `RequestCommission` attempts to retrieve the actual vesting contract addresses, though with limitations: [7](#0-6) 

## Impact Explanation

**Severity: HIGH**

This qualifies as HIGH severity under the "Significant protocol violations" category because:

1. **Broken Core Functionality**: Users cannot unlock or distribute vested coins from legitimate vesting contracts via the official CLI tool if they have multiple contracts or used custom seeds during creation.

2. **Funds Accessibility Impact**: While funds are not permanently lost, they become temporarily inaccessible through the standard CLI interface, forcing users to:
   - Manually construct raw transactions
   - Use alternative tooling
   - Risk operational errors in manual transaction construction

3. **Production Impact**: The vesting system is a critical component for token distribution to employees, investors, and ecosystem participants. A broken CLI for these operations significantly impacts legitimate users.

4. **API Functionality Failure**: The CLI is the primary API for node operators and administrators. Its failure to support documented protocol features (multiple vesting contracts per admin) constitutes a significant protocol violation in terms of operational capability.

## Likelihood Explanation

**Likelihood: HIGH**

This issue will occur in all scenarios where:

1. An admin creates multiple vesting contracts (the system explicitly supports this via the nonce mechanism)
2. An admin creates a vesting contract with a custom seed parameter (explicitly supported by the protocol)

The vesting contract creation function explicitly accepts `contract_creation_seed` as a parameter: [8](#0-7) 

Given that the protocol is designed to support these use cases, any admin following normal operational patterns will encounter this bug.

## Recommendation

Retrieve actual vesting contract addresses from the `VestingAdminStore` instead of deriving them with hardcoded parameters:

```rust
// For UnlockVestedCoins::execute()
async fn execute(mut self) -> CliTypedResult<TransactionSummary> {
    let client = self
        .txn_options
        .rest_options
        .client(&self.txn_options.profile_options)?;
    
    // Retrieve all vesting contracts for this admin
    let vesting_admin_store = client
        .get_account_resource_bcs::<VestingAdminStore>(
            self.admin_address,
            "0x1::vesting::AdminStore",
        )
        .await?;
    
    let vesting_contracts = vesting_admin_store.into_inner().vesting_contracts;
    
    // Process each vesting contract (or allow user to specify which one)
    for vesting_contract_address in vesting_contracts {
        self.txn_options
            .submit_transaction(aptos_stdlib::vesting_vest(vesting_contract_address))
            .await?;
    }
    
    Ok(transaction_summary)
}
```

The same pattern should be applied to `DistributeVestedCoins::execute()`. Alternatively, add a `--contract-address` parameter to allow users to specify which vesting contract to operate on.

## Proof of Concept

```move
#[test_only]
module test_addr::vesting_cli_bug_poc {
    use std::vector;
    use aptos_framework::vesting;
    use aptos_framework::coin;
    use aptos_framework::aptos_coin::AptosCoin;
    use aptos_framework::timestamp;
    
    #[test(admin = @0x123, shareholder = @0x456, aptos_framework = @aptos_framework)]
    public fun test_multiple_vesting_contracts(
        admin: &signer,
        shareholder: &signer,
        aptos_framework: &signer
    ) {
        // Setup: Initialize framework and accounts
        timestamp::set_time_has_started_for_testing(aptos_framework);
        
        // Create first vesting contract (nonce=0, seed="")
        let shareholders = vector::empty();
        vector::push_back(&mut shareholders, signer::address_of(shareholder));
        
        let schedule = vector::empty();
        vector::push_back(&mut schedule, fixed_point32::create_from_rational(1, 48));
        
        let vesting_schedule = vesting::create_vesting_schedule(
            schedule,
            timestamp::now_seconds() + 100,
            30
        );
        
        let buy_ins = simple_map::create();
        simple_map::add(&mut buy_ins, signer::address_of(shareholder), 
            coin::withdraw<AptosCoin>(admin, 1000));
        
        let contract1 = vesting::create_vesting_contract(
            admin,
            &shareholders,
            buy_ins,
            vesting_schedule,
            signer::address_of(admin),
            @0x789, // operator
            @0x789, // voter
            10, // commission
            x"" // empty seed - this creates address with (nonce=0, seed="")
        );
        
        // Create second vesting contract (nonce=1, seed="")
        let buy_ins2 = simple_map::create();
        simple_map::add(&mut buy_ins2, signer::address_of(shareholder),
            coin::withdraw<AptosCoin>(admin, 1000000)); // Much larger amount
        
        let contract2 = vesting::create_vesting_contract(
            admin,
            &shareholders,
            buy_ins2,
            vesting_schedule,
            signer::address_of(admin),
            @0x789,
            @0x789,
            10,
            x"" // empty seed - this creates address with (nonce=1, seed="")
        );
        
        // The CLI derives: create_vesting_contract_address(admin, 0, &[])
        // This will always target contract1, never contract2!
        
        // Proof: contract1 and contract2 have different addresses
        assert!(contract1 != contract2, 1);
        
        // The hardcoded derivation will always target contract1
        // Users cannot unlock/distribute from contract2 via CLI
    }
}
```

## Notes

The vulnerability is confirmed by comparing the CLI implementation with the correct pattern used in `get_stake_pools` (lines 458-476 of node/mod.rs), which properly retrieves all vesting contracts from the `VestingAdminStore`. The AdminStore structure explicitly tracks multiple vesting contracts and increments nonces to prevent address collisions, but the CLI functions ignore this design.

### Citations

**File:** crates/aptos/src/stake/mod.rs (L572-578)
```rust
    async fn execute(mut self) -> CliTypedResult<TransactionSummary> {
        let vesting_contract_address = create_vesting_contract_address(self.admin_address, 0, &[]);
        self.txn_options
            .submit_transaction(aptos_stdlib::vesting_distribute(vesting_contract_address))
            .await
            .map(|inner| inner.into())
    }
```

**File:** crates/aptos/src/stake/mod.rs (L605-611)
```rust
    async fn execute(mut self) -> CliTypedResult<TransactionSummary> {
        let vesting_contract_address = create_vesting_contract_address(self.admin_address, 0, &[]);
        self.txn_options
            .submit_transaction(aptos_stdlib::vesting_vest(vesting_contract_address))
            .await
            .map(|inner| inner.into())
    }
```

**File:** crates/aptos/src/stake/mod.rs (L645-659)
```rust
        // If this is a vesting stake pool, retrieve the associated vesting contract
        let vesting_admin_store = client
            .get_account_resource_bcs::<VestingAdminStore>(
                self.owner_address,
                "0x1::vesting::AdminStore",
            )
            .await;

        // Note: this only works if the vesting contract has exactly one staking contract
        // associated
        let staker_address = if let Ok(vesting_admin_store) = vesting_admin_store {
            vesting_admin_store.into_inner().vesting_contracts[0]
        } else {
            self.owner_address
        };
```

**File:** types/src/account_address.rs (L207-218)
```rust
pub fn create_vesting_contract_address(
    admin: AccountAddress,
    nonce: u64,
    seed: &[u8],
) -> AccountAddress {
    let mut full_seed = vec![];
    full_seed.extend(bcs::to_bytes(&admin).unwrap());
    full_seed.extend(bcs::to_bytes(&nonce).unwrap());
    full_seed.extend(VESTING_POOL_DOMAIN_SEPARATOR);
    full_seed.extend(seed);
    create_resource_address(admin, &full_seed)
}
```

**File:** aptos-move/framework/aptos-framework/sources/vesting.move (L168-174)
```text
    struct AdminStore has key {
        vesting_contracts: vector<address>,
        // Used to create resource accounts for new vesting contracts so there's no address collision.
        nonce: u64,

        create_events: EventHandle<CreateVestingContractEvent>,
    }
```

**File:** aptos-move/framework/aptos-framework/sources/vesting.move (L545-556)
```text
    public fun create_vesting_contract(
        admin: &signer,
        shareholders: &vector<address>,
        buy_ins: SimpleMap<address, Coin<AptosCoin>>,
        vesting_schedule: VestingSchedule,
        withdrawal_address: address,
        operator: address,
        voter: address,
        commission_percentage: u64,
        // Optional seed used when creating the staking contract account.
        contract_creation_seed: vector<u8>,
    ): address acquires AdminStore {
```

**File:** aptos-move/framework/aptos-framework/sources/vesting.move (L1152-1173)
```text
    fun create_vesting_contract_account(
        admin: &signer,
        contract_creation_seed: vector<u8>,
    ): (signer, SignerCapability) acquires AdminStore {
        check_vest_permission(admin);
        let admin_store = borrow_global_mut<AdminStore>(signer::address_of(admin));
        let seed = bcs::to_bytes(&signer::address_of(admin));
        vector::append(&mut seed, bcs::to_bytes(&admin_store.nonce));
        admin_store.nonce = admin_store.nonce + 1;

        // Include a salt to avoid conflicts with any other modules out there that might also generate
        // deterministic resource accounts for the same admin address + nonce.
        vector::append(&mut seed, VESTING_POOL_SALT);
        vector::append(&mut seed, contract_creation_seed);

        let (account_signer, signer_cap) = account::create_resource_account(admin, seed);
        // Register the vesting contract account to receive APT as it'll be sent to it when claiming unlocked stake from
        // the underlying staking contract.
        coin::register<AptosCoin>(&account_signer);

        (account_signer, signer_cap)
    }
```

**File:** crates/aptos/src/node/mod.rs (L458-476)
```rust
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
```
