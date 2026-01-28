# Audit Report

## Title
Integer Overflow in REST API Balance Aggregation for Paired Coin/Fungible Asset Accounts

## Summary
The REST API's `get_account_balance` endpoint contains an unchecked integer addition that causes a panic when querying accounts that hold both legacy CoinStore balances and paired fungible asset balances exceeding u64::MAX in sum. This results in API endpoint failure for affected accounts.

## Finding Description

The vulnerability exists in the balance aggregation logic within the REST API's account balance query handler. [2](#0-1) 

When processing a balance query for a coin type, the API first retrieves the CoinStore balance, then performs an unchecked addition with the paired fungible asset's primary store balance. [3](#0-2) 

The critical issue is that Rust's overflow checks are explicitly enabled in the release profile. [1](#0-0)  This means the `+=` operator will panic if the sum exceeds u64::MAX, causing the spawned task to fail and the API endpoint to return a 500 Internal Server Error.

**How the vulnerable state is created:**

The Aptos coin-to-fungible-asset migration framework explicitly allows CoinStore and primary FungibleStore to coexist with separate balances before migration occurs. [4](#0-3) 

1. An account has a legacy `CoinStore<CoinType>` with balance B1 (from before migration)
2. Fungible assets are deposited to the account's primary store, creating balance B2
3. Both balances are individually valid since Move's deposit function only validates the individual store's overflow. [5](#0-4) 
4. When B1 + B2 > u64::MAX, the REST API aggregation panics

The Move framework itself has the same aggregation pattern but handles overflow gracefully by aborting the transaction. [6](#0-5)  However, the Rust API code panics instead, which is caught by tokio's panic handler and converted to a 500 error. [7](#0-6) 

## Impact Explanation

**Severity: Medium**

This vulnerability aligns with the Aptos bug bounty's "API Crashes (High)" category but is more accurately classified as **Medium Severity** due to its limited scope:

- **Targeted API Denial-of-Service**: Attackers can create account states that cause deterministic API query failures for those specific accounts
- **Limited Scope**: Only affects balance queries for accounts in this dual-balance state; does not impact consensus, state integrity, or on-chain operations
- **API Availability Impact**: Affected accounts cannot have their balances queried via the REST API until migration occurs
- **No Fund Safety Impact**: Does not affect the ability to withdraw, transfer, or manage funds on-chain

The vulnerability represents a state inconsistency between what the Move framework can handle (graceful abort) and what the REST API can handle (panic), requiring manual intervention to migrate affected accounts.

## Likelihood Explanation

**Likelihood: Medium**

The attack feasibility varies by coin type:

**For Custom Coins (HIGH likelihood)**:
- An attacker controlling a custom coin can mint large balances to their CoinStore
- The same attacker can deposit large paired fungible asset amounts to their primary store  
- Both operations are individually valid since each store only checks its own balance
- No special privileges beyond normal coin minting capabilities are required

**For APT (LOW likelihood)**:
- Total APT supply constraints make accumulating sufficient balances across both representations difficult
- Would require an entity to accumulate > u64::MAX/2 in each representation

**Exploitation Requirements**:
- Account must have unmigrated CoinStore with balance > u64::MAX/2
- Primary fungible store must have balance > u64::MAX/2
- Attack is deterministic once this state exists
- No special API access or privileges required

## Recommendation

Use checked arithmetic for balance aggregation to handle overflow gracefully:

```rust
// In api/src/accounts.rs, replace unchecked additions
balance = balance.checked_add(fa_store_resource.balance())
    .ok_or_else(|| BasicErrorWith404::bad_request_with_code(
        "Total balance exceeds maximum value",
        AptosErrorCode::InvalidInput,
        &self.latest_ledger_info,
    ))?;
```

Alternatively, use saturating addition if the intent is to return the maximum representable value:

```rust
balance = balance.saturating_add(fa_store_resource.balance());
```

This approach would align the REST API behavior with the Move framework's graceful handling of overflow conditions.

## Proof of Concept

The following demonstrates the vulnerable state can be created:

1. Create an account with a legacy CoinStore<CustomCoin> containing balance = u64::MAX - 1000
2. Deposit fungible assets to the primary store with amount = 2000  
3. Query GET /accounts/{address}/balance/0x1::coin::Coin<CustomCoin>
4. API panics on line 390 during `balance += fa_store_resource.balance()`
5. Endpoint returns 500 Internal Server Error

The panic occurs because: (u64::MAX - 1000) + 2000 = u64::MAX + 1000, which exceeds u64::MAX and triggers the overflow check configured in the release profile.

### Citations

**File:** Cargo.toml (L921-923)
```text
[profile.release]
debug = true
overflow-checks = true
```

**File:** api/src/accounts.rs (L319-424)
```rust
    pub fn balance(
        &self,
        asset_type: AssetType,
        accept_type: &AcceptType,
    ) -> BasicResultWith404<u64> {
        let (fa_metadata_address, mut balance) = match asset_type {
            AssetType::Coin(move_struct_tag) => {
                let coin_store_type_tag =
                    StructTag::from_str(&format!("0x1::coin::CoinStore<{}>", move_struct_tag))
                        .map_err(|err| {
                            BasicErrorWith404::internal_with_code(
                                err,
                                AptosErrorCode::InternalError,
                                &self.latest_ledger_info,
                            )
                        })?;
                // query coin balance
                let state_value = self.context.get_state_value_poem(
                    &StateKey::resource(&self.address.into(), &coin_store_type_tag).map_err(
                        |err| {
                            BasicErrorWith404::internal_with_code(
                                err,
                                AptosErrorCode::InternalError,
                                &self.latest_ledger_info,
                            )
                        },
                    )?,
                    self.ledger_version,
                    &self.latest_ledger_info,
                )?;
                let coin_balance = match state_value {
                    None => 0,
                    Some(bytes) => bcs::from_bytes::<CoinStoreResourceUntyped>(&bytes)
                        .map_err(|err| {
                            BasicErrorWith404::internal_with_code(
                                err,
                                AptosErrorCode::InternalError,
                                &self.latest_ledger_info,
                            )
                        })?
                        .coin(),
                };
                (
                    get_paired_fa_metadata_address(&move_struct_tag),
                    coin_balance,
                )
            },
            AssetType::FungibleAsset(fa_metadata_adddress) => (fa_metadata_adddress.into(), 0),
        };
        let primary_fungible_store_address =
            get_paired_fa_primary_store_address(self.address.into(), fa_metadata_address);
        if let Some(data_blob) = self.context.get_state_value_poem(
            &StateKey::resource_group(
                &primary_fungible_store_address,
                &ObjectGroupResource::struct_tag(),
            ),
            self.ledger_version,
            &self.latest_ledger_info,
        )? {
            if let Ok(object_group) = bcs::from_bytes::<ObjectGroupResource>(&data_blob) {
                if let Some(fa_store) = object_group.group.get(&FungibleStoreResource::struct_tag())
                {
                    let fa_store_resource = bcs::from_bytes::<FungibleStoreResource>(fa_store)
                        .map_err(|err| {
                            BasicErrorWith404::internal_with_code(
                                err,
                                AptosErrorCode::InternalError,
                                &self.latest_ledger_info,
                            )
                        })?;
                    if fa_store_resource.balance != 0 {
                        balance += fa_store_resource.balance();
                    } else if let Some(concurrent_fa_balance) = object_group
                        .group
                        .get(&ConcurrentFungibleBalanceResource::struct_tag())
                    {
                        // query potential concurrent fa balance
                        let concurrent_fa_balance_resource =
                            bcs::from_bytes::<ConcurrentFungibleBalanceResource>(
                                concurrent_fa_balance,
                            )
                            .map_err(|err| {
                                BasicErrorWith404::internal_with_code(
                                    err,
                                    AptosErrorCode::InternalError,
                                    &self.latest_ledger_info,
                                )
                            })?;
                        balance += concurrent_fa_balance_resource.balance();
                    }
                }
            }
        }
        match accept_type {
            AcceptType::Json => BasicResponse::try_from_json((
                balance,
                &self.latest_ledger_info,
                BasicResponseStatus::Ok,
            )),
            AcceptType::Bcs => BasicResponse::try_from_encoded((
                bcs::to_bytes(&balance).unwrap(),
                &self.latest_ledger_info,
                BasicResponseStatus::Ok,
            )),
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/coin.move (L687-691)
```text
                // Note:
                // It is possible the primary fungible store may already exist before this function call.
                // In this case, if the account owns a frozen CoinStore and an unfrozen primary fungible store, this
                // function would convert and deposit the rest coin into the primary store and freeze it to make the
                // `frozen` semantic as consistent as possible.
```

**File:** aptos-move/framework/aptos-framework/sources/coin.move (L752-760)
```text
    public fun balance<CoinType>(owner: address): u64 acquires CoinConversionMap, CoinStore {
        let paired_metadata = paired_metadata<CoinType>();
        coin_balance<CoinType>(owner)
            + if (option::is_some(&paired_metadata)) {
                primary_fungible_store::balance(
                    owner, option::extract(&mut paired_metadata)
                )
            } else { 0 }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/fungible_asset.move (L1244-1269)
```text
    inline fun unchecked_deposit_with_no_events_inline(
        store_addr: address, fa: FungibleAsset
    ): u64 {
        let FungibleAsset { metadata, amount } = fa;
        assert!(
            exists<FungibleStore>(store_addr),
            error::not_found(EFUNGIBLE_STORE_EXISTENCE)
        );
        let store = borrow_global_mut<FungibleStore>(store_addr);
        assert!(
            metadata == store.metadata,
            error::invalid_argument(EFUNGIBLE_ASSET_AND_STORE_MISMATCH)
        );

        if (amount != 0) {
            if (store.balance == 0
                && concurrent_fungible_balance_exists_inline(store_addr)) {
                let balance_resource =
                    borrow_global_mut<ConcurrentFungibleBalance>(store_addr);
                balance_resource.balance.add(amount);
            } else {
                store.balance += amount;
            };
        };
        amount
    }
```

**File:** api/src/context.rs (L1645-1654)
```rust
pub async fn api_spawn_blocking<F, T, E>(func: F) -> Result<T, E>
where
    F: FnOnce() -> Result<T, E> + Send + 'static,
    T: Send + 'static,
    E: InternalError + Send + 'static,
{
    tokio::task::spawn_blocking(func)
        .await
        .map_err(|err| E::internal_with_code_no_info(err, AptosErrorCode::InternalError))?
}
```
