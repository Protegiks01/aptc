# Audit Report

## Title
Silent Operation Omission in Rosetta API Due to BCS Deserialization Failures

## Summary
The `Transaction::from_transaction()` function in the Aptos Rosetta implementation silently omits individual operations when BCS deserialization fails, rather than returning an error. This causes transactions to be returned with incomplete operation sets, leading to incorrect balance tracking and state representation for API consumers without any indication of data loss.

## Finding Description

The Rosetta API is a standardized blockchain integration used by exchanges, wallets, and block explorers to track balances and transaction history. In the Aptos implementation, when `Transaction::from_transaction()` processes on-chain transaction data, it calls multiple parsing functions to extract operations from write set changes. [1](#0-0) 

The critical issue is that when BCS deserialization fails in any parsing function, instead of propagating an error upward, the functions silently return empty operation vectors: [2](#0-1) [3](#0-2) [4](#0-3) 

This pattern is consistent across all operation parsing functions. The result is that when malformed or version-mismatched data is encountered, operations are silently dropped. Since the transaction is still included in the block response (unless ALL operations are missing and `keep_empty_transactions` is false), API consumers receive transactions with incomplete operation sets without any error indication.

**Attack Scenario:**
1. Chain undergoes an upgrade that changes struct layouts (e.g., adds fields to `AccountResource`, `CoinStoreResourceUntyped`, etc.)
2. Rosetta server is not immediately updated to match new struct definitions
3. Valid on-chain transactions contain write sets with new struct formats
4. Rosetta's BCS deserialization fails due to struct mismatch
5. Operations are silently omitted from Rosetta responses
6. Exchanges/wallets show incorrect balances (missing deposits/withdrawals)
7. Users withdraw based on inflated balances OR are denied withdrawals due to deflated balances

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos bug bounty program criteria: "State inconsistencies requiring intervention" and potentially "Limited funds loss or manipulation."

**Specific Impacts:**
- **Data Integrity Violation**: Rosetta's fundamental guarantee is accurate representation of on-chain state. Silent operation omission breaks this invariant.
- **Financial Loss**: Exchanges relying on Rosetta for balance tracking may allow over-withdrawals if deposit operations are missing, or block legitimate withdrawals if withdrawal operations are missing.
- **Silent Failure**: No error is returned to API callers, making the issue undetectable without cross-referencing with alternative data sources.
- **Compliance Issues**: Regulatory compliance systems using Rosetta for transaction monitoring will have incomplete audit trails.

## Likelihood Explanation

**Likelihood: Medium to High**

This vulnerability can be triggered by:

1. **Version Mismatches**: During chain upgrades, if Rosetta is not updated synchronously with on-chain struct definitions
2. **Struct Evolution**: Any addition/removal of fields in framework resources (AccountResource, StakePool, CoinStore, etc.)
3. **Type System Changes**: Changes to TypeTag representations or generics handling

The likelihood is elevated because:
- Aptos is actively developed with frequent upgrades
- Rosetta definitions must manually track on-chain struct changes
- No automated validation ensures struct definition parity
- The issue is silent, so it could persist undetected

## Recommendation

**Immediate Fix**: Propagate errors instead of silently returning empty vectors.

Modify all parsing functions to return `Err(ApiError::DeserializationFailed(...))` when BCS deserialization fails:

```rust
fn parse_account_resource_changes(
    version: u64,
    address: AccountAddress,
    data: &[u8],
    maybe_sender: Option<AccountAddress>,
    operation_index: u64,
) -> ApiResult<Vec<Operation>> {
    let mut operations = Vec::new();
    let account = bcs::from_bytes::<AccountResource>(data)
        .map_err(|e| ApiError::DeserializationFailed(Some(
            format!("Failed to parse AccountResource for {} at version {}: {}", address, version, e)
        )))?;
    
    if 0 == account.sequence_number() {
        operations.push(Operation::create_account(
            operation_index,
            Some(OperationStatusType::Success),
            address,
            maybe_sender.unwrap_or(AccountAddress::ONE),
        ));
    }
    
    Ok(operations)
}
```

Apply this pattern to: [5](#0-4) [6](#0-5) [7](#0-6) 

**Long-term Fix**: 
- Implement automated struct definition synchronization between chain and Rosetta
- Add integration tests that verify Rosetta can parse all on-chain transaction types
- Include schema version metadata in Rosetta responses to indicate compatibility

## Proof of Concept

```rust
// Reproduction steps:
// 1. Deploy Rosetta with AccountResource definition lacking a field
// 2. Execute on-chain transaction that creates an account with the new field
// 3. Query the block via Rosetta API

use aptos_rosetta::types::objects::Transaction;
use aptos_types::account_config::AccountResource;

#[tokio::test]
async fn test_silent_operation_omission() {
    // Simulate AccountResource with extra field that Rosetta doesn't know about
    let malformed_account_data = vec![/* BCS bytes with extra field */];
    
    // This should return an error but instead returns Ok(vec![])
    let result = parse_account_resource_changes(
        100,
        AccountAddress::random(),
        &malformed_account_data,
        None,
        0,
    );
    
    // Current behavior: Returns Ok(vec![]) - WRONG
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
    
    // Expected behavior: Should return Err(ApiError::DeserializationFailed)
    // assert!(result.is_err());
}
```

**Notes**

While Rosetta is not part of the consensus-critical path and doesn't affect validator operations, it is an officially supported integration component that many production systems (exchanges, wallets, compliance tools) rely on for accurate blockchain data representation. The silent data loss violates the API's fundamental contract and can lead to financial losses for consumers. The issue is particularly concerning because it provides no indication of incomplete data, making it difficult for consumers to detect and mitigate.

### Citations

**File:** crates/aptos-rosetta/src/block.rs (L91-100)
```rust
    if let Some(txns) = block.transactions {
        // Convert transactions to Rosetta format
        for txn in txns {
            let transaction = Transaction::from_transaction(server_context, txn).await?;

            // Skip transactions that don't have any operations, since that's the only thing that's being used by Rosetta
            if keep_empty_transactions || !transaction.operations.is_empty() {
                transactions.push(transaction)
            }
        }
```

**File:** crates/aptos-rosetta/src/types/objects.rs (L1471-1479)
```rust
            let resource_group = match maybe_resource_group {
                Ok(resource_group) => resource_group,
                Err(err) => {
                    warn!(
                        "Failed to parse object resource group in version {}: {:#}",
                        version, err
                    );
                    return vec![];
                },
```

**File:** crates/aptos-rosetta/src/types/objects.rs (L1531-1559)
```rust
fn parse_account_resource_changes(
    version: u64,
    address: AccountAddress,
    data: &[u8],
    maybe_sender: Option<AccountAddress>,
    operation_index: u64,
) -> ApiResult<Vec<Operation>> {
    // TODO: Handle key rotation
    let mut operations = Vec::new();
    if let Ok(account) = bcs::from_bytes::<AccountResource>(data) {
        // Account sequence number increase (possibly creation)
        // Find out if it's the 0th sequence number (creation)
        if 0 == account.sequence_number() {
            operations.push(Operation::create_account(
                operation_index,
                Some(OperationStatusType::Success),
                address,
                maybe_sender.unwrap_or(AccountAddress::ONE),
            ));
        }
    } else {
        warn!(
            "Failed to parse AccountResource for {} at version {}",
            address, version
        );
    }

    Ok(operations)
}
```

**File:** crates/aptos-rosetta/src/types/objects.rs (L1768-1850)
```rust
async fn parse_staking_contract_resource_changes(
    owner_address: AccountAddress,
    data: &[u8],
    events: &[ContractEvent],
    mut operation_index: u64,
    changes: &WriteSet,
) -> ApiResult<Vec<Operation>> {
    let mut operations = Vec::new();

    // This only handles the voter events from the staking contract
    // If there are direct events on the pool, they will be ignored
    if let Ok(store) = bcs::from_bytes::<Store>(data) {
        // Collect all the stake pools that were created
        let stake_pools: BTreeMap<AccountAddress, StakePool> = changes
            .write_op_iter()
            .filter_map(|(state_key, write_op)| {
                let data = write_op.bytes();

                let mut ret = None;
                if let (StateKeyInner::AccessPath(path), Some(data)) = (state_key.inner(), data) {
                    if let Some(struct_tag) = path.get_struct_tag() {
                        if let (AccountAddress::ONE, STAKE_MODULE, STAKE_POOL_RESOURCE) = (
                            struct_tag.address,
                            struct_tag.module.as_str(),
                            struct_tag.name.as_str(),
                        ) {
                            if let Ok(pool) = bcs::from_bytes::<StakePool>(data) {
                                ret = Some((path.address, pool))
                            }
                        }
                    }
                }

                ret
            })
            .collect();

        // Collect all operator events for all the stake pools, and add the total stake
        let mut set_operator_operations = vec![];
        let mut total_stake = 0;
        for (operator, staking_contract) in store.staking_contracts {
            if let Some(stake_pool) = stake_pools.get(&staking_contract.pool_address) {
                // Skip mismatched operators
                if operator != stake_pool.operator_address {
                    continue;
                }
                total_stake += stake_pool.get_total_staked_amount();

                // Get all set operator events for this stake pool
                let set_operator_events = filter_events(
                    events,
                    stake_pool.set_operator_events.key(),
                    |event_key, event| {
                        if let Ok(event) = bcs::from_bytes::<SetOperatorEvent>(event.event_data()) {
                            Some(event)
                        } else {
                            // If we can't parse the withdraw event, then there's nothing
                            warn!(
                                "Failed to parse set operator event!  Skipping for {}:{}",
                                event_key.get_creator_address(),
                                event_key.get_creation_number()
                            );
                            None
                        }
                    },
                );
                let set_operator_events_v2 =
                    filter_v2_events(&SET_OPERATOR_EVENT_TAG, events, |event| {
                        if let Ok(event) = bcs::from_bytes::<SetOperatorEvent>(event.event_data()) {
                            Some(event)
                        } else {
                            // If we can't parse the withdraw event, then there's nothing
                            warn!("Failed to parse set operator event!  Skipping",);
                            None
                        }
                    });

                for event in set_operator_events
                    .into_iter()
                    .chain(set_operator_events_v2)
                {
                    set_operator_operations.push(Operation::set_operator(
                        operation_index,
```

**File:** crates/aptos-rosetta/src/types/objects.rs (L2067-2126)
```rust
fn parse_coinstore_changes(
    currency: Currency,
    coin_type: String,
    version: u64,
    address: AccountAddress,
    data: &[u8],
    events: &[ContractEvent],
    mut operation_index: u64,
) -> ApiResult<Vec<Operation>> {
    let coin_store: CoinStoreResourceUntyped = if let Ok(coin_store) = bcs::from_bytes(data) {
        coin_store
    } else {
        warn!(
            "Coin store failed to parse for coin type {:?} and address {} at version {}",
            currency, address, version
        );
        return Ok(vec![]);
    };

    let mut operations = vec![];

    // Skip if there is no currency that can be found
    let mut withdraw_amounts = get_amount_from_event(events, coin_store.withdraw_events().key());
    withdraw_amounts.append(&mut get_amount_from_event_v2(
        events,
        &COIN_WITHDRAW_TYPE_TAG,
        address,
        &coin_type,
    ));
    for amount in withdraw_amounts {
        operations.push(Operation::withdraw(
            operation_index,
            Some(OperationStatusType::Success),
            AccountIdentifier::base_account(address),
            currency.clone(),
            amount,
        ));
        operation_index += 1;
    }

    let mut deposit_amounts = get_amount_from_event(events, coin_store.deposit_events().key());
    deposit_amounts.append(&mut get_amount_from_event_v2(
        events,
        &COIN_DEPOSIT_TYPE_TAG,
        address,
        &coin_type,
    ));
    for amount in deposit_amounts {
        operations.push(Operation::deposit(
            operation_index,
            Some(OperationStatusType::Success),
            AccountIdentifier::base_account(address),
            currency.clone(),
            amount,
        ));
        operation_index += 1;
    }

    Ok(operations)
}
```
