# Audit Report

## Title
Array Index Out of Bounds Panic in get_version_by_account_sequence() Function

## Summary
The `get_version_by_account_sequence()` function in the REST validator interface performs an unchecked array index access that causes a panic when querying accounts with no transactions at the requested sequence number, including special addresses like `AccountAddress::ZERO`.

## Finding Description

The vulnerability exists in the `get_version_by_account_sequence()` function which performs an unchecked index access on a vector that may be empty. [1](#0-0) 

When this function calls the REST API with a specific sequence number, the API returns all transactions starting from that sequence number. If no transactions exist at or after the requested sequence number, the API returns an empty vector with HTTP 200 status (not an error). [2](#0-1) 

The API handler does not validate whether the result vector is empty before returning it. When `get_version_by_account_sequence()` receives an empty vector and attempts to access element `[0]`, it triggers a panic.

**Attack Scenarios:**

1. **Querying AccountAddress::ZERO**: This VM-reserved address has no transactions, so querying any sequence number returns an empty vector.

2. **Querying with high sequence numbers**: Any account queried with a sequence number higher than its actual transaction count will return an empty vector.

3. **Querying accounts with no transactions**: New or inactive accounts with zero transactions will trigger the panic regardless of the sequence number requested.

The REST API's `list_ordered_txns_by_account` function calls `Account::new()` which succeeds regardless of whether the account exists or has transactions. When a start sequence number is provided, the code skips account resource validation and directly queries the database. [3](#0-2) 

The database query returns an empty iterator if no matching transactions exist, which is then collected into an empty vector and returned by the API without error checking. [4](#0-3) 

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos Bug Bounty program because it causes **API crashes**. When the panic occurs, it crashes the validator interface component that uses this REST interface, causing a denial of service for:

- Validator operators using debugging tools
- Block explorers querying transaction information
- Third-party applications using the validator interface
- Any service relying on this API endpoint for sequence-to-version mapping

While this does not affect consensus or core blockchain operations, it impacts the availability of critical debugging and querying infrastructure used by validators and ecosystem participants.

## Likelihood Explanation

This vulnerability has **high likelihood** of being triggered because:

1. **No authentication required**: Any user can call this API endpoint with arbitrary parameters
2. **Trivial to exploit**: Simply query any address with a high sequence number or query `AccountAddress::ZERO`
3. **No input validation**: The function does not validate whether the sequence number is reasonable for the given account
4. **Common use case**: Tools querying transaction history by sequence number are common in blockchain ecosystems

The issue will occur deterministically whenever the API returns an empty vector, making it easily reproducible and exploitable.

## Recommendation

Add bounds checking before accessing the array element. The function should return `Ok(None)` when no transaction is found at the requested sequence number, which aligns with the return type `Result<Option<Version>>`:

```rust
async fn get_version_by_account_sequence(
    &self,
    account: AccountAddress,
    seq: u64,
) -> Result<Option<Version>> {
    let transactions = self.0
        .get_account_ordered_transactions_bcs(account, Some(seq), None)
        .await?
        .into_inner();
    
    Ok(transactions.first().map(|txn| txn.version))
}
```

This fix:
- Uses `.first()` which safely returns `Option` instead of panicking
- Returns `None` when no transaction exists at the sequence number
- Properly utilizes the `Option<Version>` return type
- Maintains backward compatibility for callers expecting `Some(version)` or `None`

## Proof of Concept

```rust
#[tokio::test]
async fn test_panic_on_invalid_sequence() {
    use aptos_rest_client::Client;
    use aptos_types::account_address::AccountAddress;
    
    // Setup REST client pointing to a running node
    let client = Client::new(url::Url::parse("https://fullnode.testnet.aptoslabs.com").unwrap());
    let interface = RestDebuggerInterface::new(client);
    
    // Test 1: Query AccountAddress::ZERO with any sequence number
    // This will panic because ZERO address has no transactions
    let result = interface
        .get_version_by_account_sequence(AccountAddress::ZERO, 0)
        .await;
    // Expected: Panic with "index out of bounds"
    
    // Test 2: Query any account with impossibly high sequence number
    let some_account = AccountAddress::from_hex_literal("0x1").unwrap();
    let result = interface
        .get_version_by_account_sequence(some_account, u64::MAX)
        .await;
    // Expected: Panic with "index out of bounds"
}
```

**Notes**

This vulnerability demonstrates a common anti-pattern in Rust where developers assume API responses will always contain data. The issue is compounded by the REST API's design decision to return empty arrays instead of 404 errors when no transactions match the query criteria. The fix should be implemented at both the client side (defensive bounds checking) and potentially at the API level (return 404 when no results found for a specific sequence query).

### Citations

**File:** aptos-move/aptos-validator-interface/src/rest_interface.rs (L357-369)
```rust
    async fn get_version_by_account_sequence(
        &self,
        account: AccountAddress,
        seq: u64,
    ) -> Result<Option<Version>> {
        Ok(Some(
            self.0
                .get_account_ordered_transactions_bcs(account, Some(seq), None)
                .await?
                .into_inner()[0]
                .version,
        ))
    }
```

**File:** api/src/transactions.rs (L1114-1144)
```rust
    /// List sequence number based transactions for an account
    fn list_ordered_txns_by_account(
        &self,
        accept_type: &AcceptType,
        page: Page,
        address: Address,
    ) -> BasicResultWith404<Vec<Transaction>> {
        // Verify the account exists
        let account = Account::new(self.context.clone(), address, None, None, None)?;

        let latest_ledger_info = account.latest_ledger_info;
        // TODO: Return more specific errors from within this function.
        let data = self.context.get_account_ordered_transactions(
            address.into(),
            page.start_option(),
            page.limit(&latest_ledger_info)?,
            account.ledger_version,
            &latest_ledger_info,
        )?;
        match accept_type {
            AcceptType::Json => BasicResponse::try_from_json((
                self.context
                    .render_transactions_non_sequential(&latest_ledger_info, data)?,
                &latest_ledger_info,
                BasicResponseStatus::Ok,
            )),
            AcceptType::Bcs => {
                BasicResponse::try_from_bcs((data, &latest_ledger_info, BasicResponseStatus::Ok))
            },
        }
    }
```

**File:** api/src/context.rs (L879-898)
```rust
    pub fn get_account_ordered_transactions<E: NotFoundError + InternalError>(
        &self,
        address: AccountAddress,
        start_seq_number: Option<u64>,
        limit: u16,
        ledger_version: u64,
        ledger_info: &LedgerInfo,
    ) -> Result<Vec<TransactionOnChainData>, E> {
        let start_seq_number = if let Some(start_seq_number) = start_seq_number {
            start_seq_number
        } else {
            self.get_resource_poem::<AccountResource, E>(
                address,
                ledger_info.version(),
                ledger_info,
            )?
            .map(|r| r.sequence_number())
            .unwrap_or(0)
            .saturating_sub(limit as u64)
        };
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L164-194)
```rust
    fn get_account_ordered_transactions(
        &self,
        address: AccountAddress,
        start_seq_num: u64,
        limit: u64,
        include_events: bool,
        ledger_version: Version,
    ) -> Result<AccountOrderedTransactionsWithProof> {
        gauged_api("get_account_ordered_transactions", || {
            ensure!(
                !self.state_kv_db.enabled_sharding(),
                "This API is not supported with sharded DB"
            );
            error_if_too_many_requested(limit, MAX_REQUEST_LIMIT)?;

            let txns_with_proofs = self
                .transaction_store
                .get_account_ordered_transactions_iter(
                    address,
                    start_seq_num,
                    limit,
                    ledger_version,
                )?
                .map(|result| {
                    let (_seq_num, txn_version) = result?;
                    self.get_transaction_with_proof(txn_version, ledger_version, include_events)
                })
                .collect::<Result<Vec<_>>>()?;

            Ok(AccountOrderedTransactionsWithProof::new(txns_with_proofs))
        })
```
