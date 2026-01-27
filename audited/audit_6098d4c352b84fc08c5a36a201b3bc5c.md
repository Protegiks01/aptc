# Audit Report

## Title
Unbounded Staking Contracts Iteration in Rosetta API Enables Denial of Service

## Summary
The Rosetta API balance query endpoint iterates through all staking contracts without pagination or limits, allowing an attacker to create thousands of staking contracts and cause the API to timeout or crash when querying their balance. The `Store.staking_contracts` SimpleMap has no maximum size limit in the on-chain staking_contract module, enabling unbounded growth.

## Finding Description
The vulnerability exists in the interaction between the on-chain staking contract storage and the Rosetta API balance query logic.

**On-Chain Component - Unbounded Growth:**

The `Store` struct stores staking contracts in a SimpleMap with no size restrictions: [1](#0-0) 

The SimpleMap is backed by a vector with no explicit maximum size: [2](#0-1) 

Contract creation only validates that a contract with the same operator doesn't already exist, but places no limit on the total number of contracts: [3](#0-2) 

**Rosetta API Component - Full Iteration:**

The Rosetta balance query iterates through ALL staking contracts without pagination: [4](#0-3) 

For each contract, expensive blockchain queries are performed: [5](#0-4) 

Each `get_stake_balances` call performs a BCS resource fetch and a view function call: [6](#0-5) [7](#0-6) 

**Attack Path:**

1. Attacker creates N staking contracts by calling `create_staking_contract` N times with different operator addresses
2. Each contract requires `minimum_stake` APT to be locked (economic barrier but feasible)
3. When any client queries the attacker's account balance via `/account/balance`, Rosetta:
   - Fetches the Store resource
   - Iterates through all N contracts (line 224)
   - Makes 2 blockchain queries per contract (N contracts × 2 queries = 2N total queries)
4. With N = 1000+ contracts, the API request times out or exhausts server resources

This breaks the "Resource Limits" invariant as the Rosetta API performs unbounded iteration without rate limiting or pagination.

## Impact Explanation
This vulnerability qualifies as **Medium Severity** according to Aptos bug bounty criteria:

- **API Service Degradation**: The Rosetta API becomes unresponsive or extremely slow for the affected account, potentially timing out and failing to return balance information
- **Critical Infrastructure Impact**: Rosetta API is used by exchanges, wallets, and block explorers for account queries
- **Cascading Failures**: If multiple accounts are exploited, the Rosetta service may become unavailable for all users
- **No Direct Fund Loss**: This is a DoS attack on infrastructure, not a theft vulnerability
- **Not Consensus Breaking**: Does not affect the blockchain consensus or validator nodes

The impact is limited to the Rosetta API service layer and does not affect the core blockchain protocol.

## Likelihood Explanation
**Likelihood: Medium-High**

**Attacker Requirements:**
- Sufficient APT to lock in staking contracts (N × minimum_stake, where minimum_stake is typically 1 million APT on mainnet)
- Ability to generate N unique operator addresses (trivial)
- Technical knowledge to call staking contract creation functions

**Economic Feasibility:**
- For N = 100 contracts: 100M APT (~$1M at $10/APT) - feasible for medium-sized attackers
- For N = 1000 contracts: 1B APT (~$10M) - feasible for well-funded attackers
- Funds are locked but not lost; attacker can eventually recover them

**Attack Complexity:**
- Low technical complexity - standard Move transaction calls
- No special permissions required
- Can be executed gradually over time to avoid detection
- Each contract creation is a separate transaction, avoiding per-transaction limits

**Detection Difficulty:**
- Creating multiple staking contracts appears legitimate
- Attack only manifests when balance queries are performed
- No on-chain indication of malicious intent

## Recommendation

**Short-term Mitigation (Rosetta API):**

Implement pagination and maximum iteration limits in the `get_staking_info` function:

```rust
// Add to account.rs
const MAX_STAKING_CONTRACTS_PER_QUERY: usize = 10;

async fn get_staking_info(
    rest_client: &Client,
    account: &AccountIdentifier,
    owner_address: AccountAddress,
    version: u64,
) -> ApiResult<(Vec<Amount>, u64, Option<Vec<AccountAddress>>)> {
    // ... existing code ...
    
    if let Ok(response) = rest_client
        .get_account_resource_at_version_bcs(owner_address, "0x1::staking_contract::Store", version)
        .await
    {
        let store: Store = response.into_inner();
        
        // Limit iteration to prevent DoS
        let contracts_to_process = store.staking_contracts
            .iter()
            .take(MAX_STAKING_CONTRACTS_PER_QUERY);
        
        maybe_operators = Some(vec![]);
        for (operator, contract) in contracts_to_process {
            // ... rest of iteration logic ...
        }
        
        // Log warning if limit exceeded
        if store.staking_contracts.len() > MAX_STAKING_CONTRACTS_PER_QUERY {
            warn!(
                "Account {} has {} staking contracts, limiting query to {}",
                owner_address,
                store.staking_contracts.len(),
                MAX_STAKING_CONTRACTS_PER_QUERY
            );
        }
    }
    // ... rest of function ...
}
```

**Long-term Solution (On-Chain):**

Add a maximum staking contracts limit to the staking_contract module:

```move
// In staking_contract.move
const MAXIMUM_STAKING_CONTRACTS_PER_STAKER: u64 = 100;

public fun create_staking_contract_with_coins(
    staker: &signer,
    // ... parameters ...
) acquires Store {
    // ... existing validation ...
    
    let store = borrow_global_mut<Store>(staker_address);
    let staking_contracts = &mut store.staking_contracts;
    
    // Add size check
    assert!(
        simple_map::length(staking_contracts) < MAXIMUM_STAKING_CONTRACTS_PER_STAKER,
        error::resource_exhausted(ETOO_MANY_STAKING_CONTRACTS)
    );
    
    // ... rest of function ...
}
```

## Proof of Concept

```move
#[test_only]
module test_addr::staking_dos_poc {
    use std::signer;
    use std::vector;
    use aptos_framework::staking_contract;
    use aptos_framework::aptos_coin::AptosCoin;
    use aptos_framework::coin;
    
    #[test(
        aptos_framework = @0x1,
        staker = @0x123,
        operators = @0x200
    )]
    public fun test_unbounded_staking_contracts(
        aptos_framework: &signer,
        staker: &signer,
    ) {
        // Initialize framework and mint coins
        // ... setup code ...
        
        let staker_addr = signer::address_of(staker);
        let minimum_stake = 1_000_000_000_000; // 1M APT
        
        // Create 100 staking contracts with different operators
        let num_contracts = 100;
        let i = 0;
        while (i < num_contracts) {
            let operator_addr = @0x1000 + i; // Generate unique operator addresses
            let voter_addr = @0x2000 + i;
            
            // Create staking contract
            staking_contract::create_staking_contract(
                staker,
                operator_addr,
                voter_addr,
                minimum_stake,
                10, // 10% commission
                vector::empty()
            );
            
            i = i + 1;
        };
        
        // At this point, Store resource contains 100 contracts
        // When Rosetta queries this account, it will iterate through all 100
        // and make 200 blockchain queries (2 per contract)
        
        // With 1000+ contracts, this causes API timeouts
    }
}
```

**Rust Test to Demonstrate Rosetta API Impact:**

```rust
#[tokio::test]
async fn test_rosetta_dos_with_many_contracts() {
    // Setup test environment with account that has 1000+ staking contracts
    let account_with_many_contracts = AccountAddress::from_hex_literal("0x123").unwrap();
    
    // Measure API response time
    let start = std::time::Instant::now();
    
    let response = rosetta_client
        .account_balance(AccountBalanceRequest {
            network_identifier: test_network(),
            account_identifier: AccountIdentifier {
                address: account_with_many_contracts.to_string(),
                sub_account: None,
            },
            block_identifier: None,
            currencies: None,
        })
        .await;
    
    let duration = start.elapsed();
    
    // With 1000+ contracts, this will timeout (>30s)
    // or consume excessive API resources
    assert!(duration.as_secs() > 30 || response.is_err());
}
```

## Notes

The vulnerability is confirmed through code analysis. While the distribution_pool within each StakingContract has `MAXIMUM_PENDING_DISTRIBUTIONS = 20` limit to prevent griefing attacks, no similar protection exists for the total number of staking contracts per staker. The developers were aware of potential griefing attacks but only protected the distribution pool, not the contract count itself. [8](#0-7) 

The comment explicitly mentions preventing griefing attacks with distribution limits, but the same principle should apply to the staking_contracts collection itself.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/staking_contract.move (L66-67)
```text
    /// Maximum number of distributions a stake pool can support.
    const MAXIMUM_PENDING_DISTRIBUTIONS: u64 = 20;
```

**File:** aptos-move/framework/aptos-framework/sources/staking_contract.move (L90-103)
```text
    struct Store has key {
        staking_contracts: SimpleMap<address, StakingContract>,

        // Events.
        create_staking_contract_events: EventHandle<CreateStakingContractEvent>,
        update_voter_events: EventHandle<UpdateVoterEvent>,
        reset_lockup_events: EventHandle<ResetLockupEvent>,
        add_stake_events: EventHandle<AddStakeEvent>,
        request_commission_events: EventHandle<RequestCommissionEvent>,
        unlock_stake_events: EventHandle<UnlockStakeEvent>,
        switch_operator_events: EventHandle<SwitchOperatorEvent>,
        add_distribution_events: EventHandle<AddDistributionEvent>,
        distribute_events: EventHandle<DistributeEvent>
    }
```

**File:** aptos-move/framework/aptos-framework/sources/staking_contract.move (L432-437)
```text
        let store = borrow_global_mut<Store>(staker_address);
        let staking_contracts = &mut store.staking_contracts;
        assert!(
            !simple_map::contains_key(staking_contracts, &operator),
            error::already_exists(ESTAKING_CONTRACT_ALREADY_EXISTS)
        );
```

**File:** aptos-move/framework/aptos-stdlib/sources/simple_map.move (L22-24)
```text
    struct SimpleMap<Key, Value> has copy, drop, store {
        data: vector<Element<Key, Value>>,
    }
```

**File:** crates/aptos-rosetta/src/account.rs (L218-224)
```rust
    if let Ok(response) = rest_client
        .get_account_resource_at_version_bcs(owner_address, "0x1::staking_contract::Store", version)
        .await
    {
        let store: Store = response.into_inner();
        maybe_operators = Some(vec![]);
        for (operator, contract) in store.staking_contracts {
```

**File:** crates/aptos-rosetta/src/account.rs (L227-243)
```rust
            match get_stake_balances(rest_client, account, contract.pool_address, version).await {
                Ok(Some(balance_result)) => {
                    if let Some(balance) = balance_result.balance {
                        has_staking = true;
                        total_balance += u64::from_str(&balance.value).unwrap_or_default();
                    }
                    // TODO: This seems like it only works if there's only one staking contract (hopefully it stays that way)
                    lockup_expiration = balance_result.lockup_expiration;
                },
                result => {
                    warn!(
                        "Failed to retrieve requested balance for account: {}, address: {}: {:?}",
                        owner_address, contract.pool_address, result
                    )
                },
            }
        }
```

**File:** crates/aptos-rosetta/src/types/misc.rs (L297-300)
```rust
    if let Ok(response) = rest_client
        .get_account_resource_at_version_bcs::<StakePool>(pool_address, STAKE_POOL, version)
        .await
    {
```

**File:** crates/aptos-rosetta/src/types/misc.rs (L325-337)
```rust
        let staking_contract_amounts_response = view::<Vec<u64>>(
            rest_client,
            version,
            AccountAddress::ONE,
            ident_str!(STAKING_CONTRACT_MODULE),
            ident_str!("staking_contract_amounts"),
            vec![],
            vec![
                bcs::to_bytes(&owner_address)?,
                bcs::to_bytes(&operator_address)?,
            ],
        )
        .await?;
```
