# Audit Report

## Title
Integer Sign Conversion Vulnerability in Rosetta API Transfer Validation Allows Incorrect Balance Updates

## Summary
The Rosetta API's `Transfer::extract_transfer` function contains a validation flaw where negative deposit amounts and positive withdraw amounts are not rejected, allowing integer sign conversion to cause wrap-around when casting from `i128` to `u64`. This results in transactions being constructed with drastically incorrect transfer amounts (e.g., -100 becoming 18446744073709551516). [1](#0-0) 

## Finding Description
The Rosetta API establishes a convention where withdraw operations must have negative amounts and deposit operations must have positive amounts. This is implemented in the operation constructors: [2](#0-1) [3](#0-2) 

However, the `Transfer::extract_transfer` function fails to enforce this convention when parsing user-provided operations. The vulnerability exists in the validation logic:

1. **Parsing without sign validation**: Withdraw and deposit amounts are parsed from strings to `i128` without checking their signs. [4](#0-3) 

2. **Insufficient validation**: The code only checks that amounts are negatives of each other, not that they have the correct signs. [5](#0-4) 

3. **Missing negative value check**: The range check only validates against `u64::MAX` but does not check for negative values. [6](#0-5) 

4. **Unsafe cast**: The code casts `i128` to `u64` without validating non-negativity, causing wrap-around for negative values. [7](#0-6) 

**Attack Scenario:**
An attacker provides malformed operations with reversed signs:
- `withdraw_amount.value = "100"` (positive, should be negative)
- `deposit_amount.value = "-100"` (negative, should be positive)

This passes validation because:
- Line 2905: `-(100) == -100` ✓
- Line 2913: `-100 > u64::MAX` is false ✓
- Line 2919: `(-100i128) as u64` wraps to `18446744073709551516`

The resulting Transfer object is used to construct transaction payloads: [8](#0-7) 

The malformed Transfer flows through the construction pipeline: [9](#0-8) [10](#0-9) 

## Impact Explanation
**Severity: High** (up to $50,000 per Aptos Bug Bounty)

This vulnerability enables construction of financially dangerous transactions:

1. **Fund Loss**: Services using the Rosetta API for transaction construction could create transactions that transfer massively incorrect amounts, potentially draining user accounts if they have sufficient balance and sign the transaction.

2. **API Validation Bypass**: The vulnerability breaks the Rosetta API's validation invariants, allowing malformed inputs that violate the established withdraw/deposit amount conventions.

3. **Service Compromise**: Automated systems (exchanges, wallets, custodial services) that rely on the Rosetta API could be exploited to construct malicious transactions.

This qualifies as High severity per the Aptos Bug Bounty framework because:
- It causes significant protocol violations (incorrect transaction construction)
- It can lead to limited fund loss (dependent on victim balance and signature)
- It's more severe than a simple "API crash" as it actively constructs dangerous transactions
- It affects transaction validation guarantees in production code

## Likelihood Explanation
**Likelihood: Medium-High**

Exploitation requirements:
1. Attacker can influence operations sent to Rosetta API endpoints (e.g., compromised service, malicious frontend, direct API access)
2. Victim signs the resulting transaction without careful manual verification of the raw transaction data
3. For actual fund loss: Victim has sufficient balance for the wrapped amount

Likelihood is elevated because:
- Rosetta API is widely deployed by exchanges and custodial services for Aptos integration
- Automated transaction construction systems may not implement secondary amount validation
- Users typically trust amounts displayed in UIs rather than verifying raw transaction bytes
- The vulnerability exists in production code with no visible safeguards
- No additional validation layer catches the sign reversal before transaction construction

## Recommendation
Add explicit sign validation in `Transfer::extract_transfer` before casting:

```rust
// After line 2909, add:
if withdraw_value >= 0 {
    return Err(ApiError::InvalidTransferOperations(Some(
        "Withdraw amount must be negative",
    )));
}

if deposit_value <= 0 {
    return Err(ApiError::InvalidTransferOperations(Some(
        "Deposit amount must be positive",
    )));
}

// Before line 2919, replace line 2913 with:
if deposit_value < 0 || deposit_value > u64::MAX as i128 {
    return Err(ApiError::InvalidTransferOperations(Some(
        "Transfer amount must be between 0 and u64::MAX",
    )));
}
```

## Proof of Concept
The vulnerability can be demonstrated by calling the Rosetta API construction endpoints with malformed operations:

```rust
// Construct malformed operations
let operations = vec![
    Operation {
        operation_identifier: OperationIdentifier { index: 0 },
        operation_type: "withdraw".to_string(),
        account: Some(AccountIdentifier::base_account(sender)),
        amount: Some(Amount {
            value: "100".to_string(),  // POSITIVE (should be negative)
            currency: native_coin(),
        }),
        status: None,
        metadata: None,
    },
    Operation {
        operation_identifier: OperationIdentifier { index: 1 },
        operation_type: "deposit".to_string(),
        account: Some(AccountIdentifier::base_account(receiver)),
        amount: Some(Amount {
            value: "-100".to_string(),  // NEGATIVE (should be positive)
            currency: native_coin(),
        }),
        status: None,
        metadata: None,
    },
];

// Call InternalOperation::extract
let result = InternalOperation::extract(&server_context, &operations);

// Result will be Transfer with amount = 18446744073709551516
// instead of the intended 100
```

## Notes
This vulnerability affects the Aptos Rosetta API integration, which is part of the in-scope API layer. The bug allows malformed inputs to bypass validation and construct transactions with incorrect amounts due to integer wrap-around during `i128` to `u64` casting. While the on-chain execution would still require user signature and sufficient balance, the Rosetta API itself fails to enforce its documented amount sign conventions, creating a serious validation bypass that could lead to fund loss in automated systems.

### Citations

**File:** crates/aptos-rosetta/src/types/objects.rs (L304-322)
```rust
    pub fn deposit(
        operation_index: u64,
        status: Option<OperationStatusType>,
        account: AccountIdentifier,
        currency: Currency,
        amount: u64,
    ) -> Operation {
        Operation::new(
            OperationType::Deposit,
            operation_index,
            status,
            account,
            Some(Amount {
                value: amount.to_string(),
                currency,
            }),
            None,
        )
    }
```

**File:** crates/aptos-rosetta/src/types/objects.rs (L324-342)
```rust
    pub fn withdraw(
        operation_index: u64,
        status: Option<OperationStatusType>,
        account: AccountIdentifier,
        currency: Currency,
        amount: u64,
    ) -> Operation {
        Operation::new(
            OperationType::Withdraw,
            operation_index,
            status,
            account,
            Some(Amount {
                value: format!("-{}", amount),
                currency,
            }),
            None,
        )
    }
```

**File:** crates/aptos-rosetta/src/types/objects.rs (L2641-2708)
```rust
            InternalOperation::Transfer(transfer) => {
                // Check if the currency is known
                let currency = &transfer.currency;

                // We special case APT, because we don't want the behavior to change
                if currency == &native_coin() {
                    return Ok((
                        aptos_stdlib::aptos_account_transfer(transfer.receiver, transfer.amount.0),
                        transfer.sender,
                    ));
                }

                // For all other coins and FAs we need to handle them accordingly
                if let Some(ref metadata) = currency.metadata {
                    match (&metadata.move_type, &metadata.fa_address) {
                        // For currencies with the coin type, we will always use the coin functionality, even if migrated
                        (Some(coin_type), Some(_)) | (Some(coin_type), None) => {
                            let coin_type_tag = parse_type_tag(coin_type)
                                .map_err(|err| ApiError::InvalidInput(Some(err.to_string())))?;
                            (
                                aptos_stdlib::aptos_account_transfer_coins(
                                    coin_type_tag,
                                    transfer.receiver,
                                    transfer.amount.0,
                                ),
                                transfer.sender,
                            )
                        },
                        // For FA only currencies, we use the FA functionality
                        (None, Some(fa_address_str)) => {
                            let fa_address = AccountAddress::from_str(fa_address_str)?;

                            (
                                TransactionPayload::EntryFunction(EntryFunction::new(
                                    ModuleId::new(
                                        AccountAddress::ONE,
                                        ident_str!("primary_fungible_store").to_owned(),
                                    ),
                                    ident_str!("transfer").to_owned(),
                                    vec![TypeTag::Struct(Box::new(StructTag {
                                        address: AccountAddress::ONE,
                                        module: ident_str!(OBJECT_MODULE).into(),
                                        name: ident_str!(OBJECT_CORE_RESOURCE).into(),
                                        type_args: vec![],
                                    }))],
                                    vec![
                                        bcs::to_bytes(&fa_address).unwrap(),
                                        bcs::to_bytes(&transfer.receiver).unwrap(),
                                        bcs::to_bytes(&transfer.amount.0).unwrap(),
                                    ],
                                )),
                                transfer.sender,
                            )
                        },
                        _ => {
                            return Err(ApiError::InvalidInput(Some(format!(
                                "{} does not have a move type provided",
                                currency.symbol
                            ))))
                        },
                    }
                } else {
                    // This should never happen unless the server's currency list is improperly set
                    return Err(ApiError::InvalidInput(Some(format!(
                        "{} does not have a currency information provided",
                        currency.symbol
                    ))));
                }
```

**File:** crates/aptos-rosetta/src/types/objects.rs (L2815-2927)
```rust
    pub fn extract_transfer(
        server_context: &RosettaContext,
        operations: &Vec<Operation>,
    ) -> ApiResult<Transfer> {
        // Only support 1:1 P2P transfer
        // This is composed of a Deposit and a Withdraw operation
        if operations.len() != 2 {
            return Err(ApiError::InvalidTransferOperations(Some(
                "Must have exactly 2 operations a withdraw and a deposit",
            )));
        }

        let mut op_map = HashMap::new();
        for op in operations {
            let op_type = OperationType::from_str(&op.operation_type)?;
            op_map.insert(op_type, op);
        }

        if !op_map.contains_key(&OperationType::Deposit) {
            return Err(ApiError::InvalidTransferOperations(Some(
                "Must have a deposit",
            )));
        }

        // Verify accounts and amounts
        let (sender, withdraw_amount) = if let Some(withdraw) = op_map.get(&OperationType::Withdraw)
        {
            if let (Some(account), Some(amount)) = (&withdraw.account, &withdraw.amount) {
                if account.is_base_account() {
                    (account.account_address()?, amount)
                } else {
                    return Err(ApiError::InvalidInput(Some(
                        "Transferring stake amounts is not supported".to_string(),
                    )));
                }
            } else {
                return Err(ApiError::InvalidTransferOperations(Some(
                    "Invalid withdraw account provided",
                )));
            }
        } else {
            return Err(ApiError::InvalidTransferOperations(Some(
                "Must have a withdraw",
            )));
        };

        let (receiver, deposit_amount) = if let Some(deposit) = op_map.get(&OperationType::Deposit)
        {
            if let (Some(account), Some(amount)) = (&deposit.account, &deposit.amount) {
                if account.is_base_account() {
                    (account.account_address()?, amount)
                } else {
                    return Err(ApiError::InvalidInput(Some(
                        "Transferring stake amounts is not supported".to_string(),
                    )));
                }
            } else {
                return Err(ApiError::InvalidTransferOperations(Some(
                    "Invalid deposit account provided",
                )));
            }
        } else {
            return Err(ApiError::InvalidTransferOperations(Some(
                "Must have a deposit",
            )));
        };

        // Currencies have to be the same
        if withdraw_amount.currency != deposit_amount.currency {
            return Err(ApiError::InvalidTransferOperations(Some(
                "Currency mismatch between withdraw and deposit",
            )));
        }

        // Check that the currency is supported
        if !server_context
            .currencies
            .contains(&withdraw_amount.currency)
        {
            return Err(ApiError::UnsupportedCurrency(Some(
                withdraw_amount.currency.symbol.clone(),
            )));
        }

        let withdraw_value = i128::from_str(&withdraw_amount.value)
            .map_err(|_| ApiError::InvalidTransferOperations(Some("Withdraw amount is invalid")))?;
        let deposit_value = i128::from_str(&deposit_amount.value)
            .map_err(|_| ApiError::InvalidTransferOperations(Some("Deposit amount is invalid")))?;

        // We can't create or destroy coins, they must be negatives of each other
        if -withdraw_value != deposit_value {
            return Err(ApiError::InvalidTransferOperations(Some(
                "Withdraw amount must be equal to negative of deposit amount",
            )));
        }

        // We converted to u128 to ensure no loss of precision in comparison,
        // but now we actually have to check it's a u64
        if deposit_value > u64::MAX as i128 {
            return Err(ApiError::InvalidTransferOperations(Some(
                "Transfer amount must not be greater than u64 max",
            )));
        }

        let transfer_amount = deposit_value as u64;

        Ok(Transfer {
            sender,
            receiver,
            amount: transfer_amount.into(),
            currency: deposit_amount.currency.clone(),
        })
    }
```

**File:** crates/aptos-rosetta/src/construction.rs (L1173-1209)
```rust
async fn construction_payloads(
    request: ConstructionPayloadsRequest,
    server_context: RosettaContext,
) -> ApiResult<ConstructionPayloadsResponse> {
    debug!("/construction/payloads {:?}", request);
    check_network(request.network_identifier, &server_context)?;

    // Retrieve the real operation we're doing, this identifies the sub-operations to a function
    let mut operation = InternalOperation::extract(&server_context, &request.operations)?;

    // For some reason, metadata is optional on the Rosetta spec, we enforce it here, otherwise we
    // can't build the [RawTransaction] offline.
    let metadata = if let Some(ref metadata) = request.metadata {
        metadata
    } else {
        return Err(ApiError::MissingPayloadMetadata);
    };

    // This is a hack to ensure that the payloads actually have overridden operators if not provided
    // It ensures that the operations provided match the metadata provided.
    // TODO: Move this to a separate function
    match &mut operation {
        InternalOperation::CreateAccount(_) => {
            if operation != metadata.internal_operation {
                return Err(ApiError::InvalidInput(Some(format!(
                    "CreateAccount operation doesn't match metadata {:?} vs {:?}",
                    operation, metadata.internal_operation
                ))));
            }
        },
        InternalOperation::Transfer(_) => {
            if operation != metadata.internal_operation {
                return Err(ApiError::InvalidInput(Some(format!(
                    "Transfer operation doesn't match metadata {:?} vs {:?}",
                    operation, metadata.internal_operation
                ))));
            }
```

**File:** crates/aptos-rosetta/src/construction.rs (L1427-1435)
```rust
async fn construction_preprocess(
    request: ConstructionPreprocessRequest,
    server_context: RosettaContext,
) -> ApiResult<ConstructionPreprocessResponse> {
    debug!("/construction/preprocess {:?}", request);
    check_network(request.network_identifier, &server_context)?;

    // Determine the actual operation from the collection of Rosetta [Operation]
    let internal_operation = InternalOperation::extract(&server_context, &request.operations)?;
```
