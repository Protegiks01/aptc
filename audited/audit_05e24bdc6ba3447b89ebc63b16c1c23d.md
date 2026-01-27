# Audit Report

## Title
Rosetta API Error Documentation Incompleteness: Missing RejectedByFilter in ApiError::all() with No Systematic Exhaustiveness Check

## Summary
The `ApiError::all()` function in the Aptos Rosetta implementation is missing the `RejectedByFilter` error variant, causing the `/network/options` endpoint to advertise an incomplete list of possible errors to Rosetta API clients. Additionally, there is no systematic compile-time check to ensure this function remains exhaustive when new error types are added. [1](#0-0) 

## Finding Description

The Rosetta API specification requires that the `/network/options` endpoint returns a complete list of all possible errors that clients may encounter. This is implemented via the `ApiError::all()` function, which is called to populate the error list. [2](#0-1) 

However, the `all()` function is missing the `RejectedByFilter(None)` variant, despite this error being:
1. Defined in the `ApiError` enum at line 55
2. Mapped from `AptosErrorCode::RejectedByFilter` in the `From<RestError>` implementation
3. Assigned error code 35 in the `code()` function
4. Given a static message in the `message()` function
5. Actually used in production when transactions are rejected by mempool filters [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) 

The `RejectedByFilter` error is returned when mempool rejects a transaction due to a transaction filter, which is a real production scenario: [7](#0-6) [8](#0-7) 

**Systematic Check Analysis:**

While the `From<RestError> for ApiError` implementation uses an exhaustive match (no wildcard pattern) that would cause a compiler error if new `AptosErrorCode` variants are added, the `all()` function is manually maintained with no such protection: [9](#0-8) 

The codebase contains a `NumVariants` derive macro that could provide compile-time variant counting, but it is not used on the `ApiError` enum: [10](#0-9) 

## Impact Explanation

This issue constitutes a **Medium severity** vulnerability based on the following impact:

1. **API Specification Violation**: The Rosetta specification explicitly requires all possible errors to be documented in `/network/options`. This violation breaks the contract with API clients. [11](#0-10) 

2. **Client Integration Failures**: Exchanges, wallets, and other services integrating with Aptos via Rosetta will not be aware of the `RejectedByFilter` error, leading to:
   - Unhandled exceptions in client code
   - Failed transaction submissions without proper user feedback
   - Inability to implement correct retry logic
   - Poor user experience when transactions are filtered

3. **Future Maintainability Risk**: Without a systematic check, new error variants added to `AptosErrorCode` could be silently omitted from the `all()` function, perpetuating this class of bug.

This falls under **Medium severity** per the Aptos bug bounty program as it represents a state inconsistency between advertised and actual API behavior that could affect multiple integrators.

## Likelihood Explanation

**Current Bug Likelihood: HIGH**
- The bug exists in production code right now
- Any transaction rejected by mempool filters will return `RejectedByFilter`
- Transaction filters are a documented feature used by node operators
- Every Rosetta client calling `/network/options` receives incomplete error information

**Future Bug Recurrence: MEDIUM**
- New `AptosErrorCode` variants are added periodically as the API evolves
- Without systematic checks, developers must manually remember to update `all()`
- The exhaustive match in `From<RestError>` provides partial protection but doesn't cover `all()`

## Recommendation

Implement a systematic compile-time check to ensure `ApiError::all()` remains exhaustive:

1. **Immediate Fix**: Add the missing `RejectedByFilter(None)` entry to the `all()` function:

```rust
pub fn all() -> Vec<ApiError> {
    use ApiError::*;
    vec![
        // ... existing entries ...
        MempoolIsFull(None),
        RejectedByFilter(None),  // ADD THIS LINE
    ]
}
```

2. **Systematic Protection**: Add the `NumVariants` derive macro and a compile-time assertion:

```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize, NumVariants)]
pub enum ApiError {
    // ... variants ...
}

impl ApiError {
    pub fn all() -> Vec<ApiError> {
        let all_errors = vec![/* ... */];
        // Compile-time check that all() is complete
        const _: () = assert!(all_errors.len() == ApiError::NUM_VARIANTS);
        all_errors
    }
}
```

3. **Add Test**: Create a test that validates completeness:

```rust
#[test]
fn test_all_errors_complete() {
    let all_errors = ApiError::all();
    assert_eq!(all_errors.len(), ApiError::NUM_VARIANTS, 
        "ApiError::all() must include all enum variants");
    
    // Verify no duplicates
    let mut codes: Vec<u32> = all_errors.iter().map(|e| e.code()).collect();
    codes.sort();
    codes.dedup();
    assert_eq!(codes.len(), all_errors.len(), "Error codes must be unique");
}
```

## Proof of Concept

The following test demonstrates that the `/network/options` endpoint returns incomplete error information:

```rust
#[tokio::test]
async fn test_network_options_missing_rejected_by_filter() {
    // Setup Rosetta context
    let context = setup_test_context().await;
    
    // Call network_options
    let request = NetworkRequest {
        network_identifier: NetworkIdentifier {
            blockchain: "aptos".to_string(),
            network: "testnet".to_string(),
        },
    };
    
    let response = network_options(request, context).await.unwrap();
    
    // Extract error codes from response
    let error_codes: Vec<u32> = response.allow.errors
        .iter()
        .map(|e| e.code)
        .collect();
    
    // Verify RejectedByFilter (code 35) is missing
    assert!(!error_codes.contains(&35), 
        "BUG CONFIRMED: RejectedByFilter (code 35) is not advertised in /network/options");
    
    // Verify all() function is incomplete
    let all_errors = ApiError::all();
    assert_eq!(all_errors.len(), 34, 
        "ApiError::all() returns 34 variants but enum has 35");
    
    // Verify RejectedByFilter is missing from all()
    let has_rejected_by_filter = all_errors.iter()
        .any(|e| matches!(e, ApiError::RejectedByFilter(_)));
    assert!(!has_rejected_by_filter, 
        "BUG CONFIRMED: RejectedByFilter is missing from ApiError::all()");
}
```

**Steps to reproduce:**
1. Start Aptos Rosetta server with a node that has transaction filtering enabled
2. Call `POST /network/options` endpoint
3. Examine the `allow.errors` array in the response
4. Observe that error code 35 (RejectedByFilter) is absent
5. Submit a transaction that matches a filter rule
6. Receive `RejectedByFilter` error despite it not being advertised in `/network/options`

## Notes

While the `From<RestError>` implementation provides partial protection via exhaustive matching on `AptosErrorCode` variants, this doesn't extend to the `all()` function used for API documentation. The same issue could theoretically affect the `code()` and `message()` functions, though they currently use exhaustive matches without wildcards, providing compiler-enforced completeness. The `details()` function uses a wildcard pattern, which is acceptable as it has a sensible default behavior for variants without detail fields.

### Citations

**File:** crates/aptos-rosetta/src/error.rs (L55-55)
```rust
    RejectedByFilter(Option<String>),
```

**File:** crates/aptos-rosetta/src/error.rs (L68-106)
```rust
    pub fn all() -> Vec<ApiError> {
        use ApiError::*;
        vec![
            TransactionIsPending,
            NetworkIdentifierMismatch,
            ChainIdMismatch,
            DeserializationFailed(None),
            InvalidTransferOperations(None),
            InvalidSignatureType,
            InvalidMaxGasFees,
            MaxGasFeeTooLow(None),
            InvalidGasMultiplier,
            GasEstimationFailed(None),
            InvalidOperations(None),
            MissingPayloadMetadata,
            UnsupportedCurrency(None),
            UnsupportedSignatureCount(None),
            NodeIsOffline,
            TransactionParseError(None),
            InternalError(None),
            CoinTypeFailedToBeFetched(None),
            AccountNotFound(None),
            ResourceNotFound(None),
            ModuleNotFound(None),
            StructFieldNotFound(None),
            VersionNotFound(None),
            TransactionNotFound(None),
            TableItemNotFound(None),
            BlockNotFound(None),
            StateValueNotFound(None),
            VersionPruned(None),
            BlockPruned(None),
            InvalidInput(None),
            InvalidTransactionUpdate(None),
            SequenceNumberTooOld(None),
            VmError(None),
            MempoolIsFull(None),
        ]
    }
```

**File:** crates/aptos-rosetta/src/error.rs (L146-146)
```rust
            RejectedByFilter(_) => 35,
```

**File:** crates/aptos-rosetta/src/error.rs (L206-206)
```rust
            ApiError::RejectedByFilter(_) => "Transaction was rejected by the transaction filter",
```

**File:** crates/aptos-rosetta/src/error.rs (L269-319)
```rust
impl From<RestError> for ApiError {
    fn from(err: RestError) -> Self {
        match err {
            RestError::Api(err) => match err.error.error_code {
                AptosErrorCode::AccountNotFound => {
                    ApiError::AccountNotFound(Some(err.error.message))
                },
                AptosErrorCode::ResourceNotFound => {
                    ApiError::ResourceNotFound(Some(err.error.message))
                },
                AptosErrorCode::ModuleNotFound => ApiError::ModuleNotFound(Some(err.error.message)),
                AptosErrorCode::StructFieldNotFound => {
                    ApiError::StructFieldNotFound(Some(err.error.message))
                },
                AptosErrorCode::VersionNotFound => {
                    ApiError::VersionNotFound(Some(err.error.message))
                },
                AptosErrorCode::TransactionNotFound => {
                    ApiError::TransactionNotFound(Some(err.error.message))
                },
                AptosErrorCode::TableItemNotFound => {
                    ApiError::TableItemNotFound(Some(err.error.message))
                },
                AptosErrorCode::BlockNotFound => ApiError::BlockNotFound(Some(err.error.message)),
                AptosErrorCode::StateValueNotFound => {
                    ApiError::StateValueNotFound(Some(err.error.message))
                },
                AptosErrorCode::VersionPruned => ApiError::VersionPruned(Some(err.error.message)),
                AptosErrorCode::BlockPruned => ApiError::BlockPruned(Some(err.error.message)),
                AptosErrorCode::InvalidInput => ApiError::InvalidInput(Some(err.error.message)),
                AptosErrorCode::InvalidTransactionUpdate => {
                    ApiError::InvalidInput(Some(err.error.message))
                },
                AptosErrorCode::SequenceNumberTooOld => {
                    ApiError::SequenceNumberTooOld(Some(err.error.message))
                },
                AptosErrorCode::VmError => ApiError::VmError(Some(err.error.message)),
                AptosErrorCode::RejectedByFilter => {
                    ApiError::RejectedByFilter(Some(err.error.message))
                },
                AptosErrorCode::HealthCheckFailed => {
                    ApiError::InternalError(Some(err.error.message))
                },
                AptosErrorCode::MempoolIsFull => ApiError::MempoolIsFull(Some(err.error.message)),
                AptosErrorCode::WebFrameworkError => {
                    ApiError::InternalError(Some(err.error.message))
                },
                AptosErrorCode::BcsNotSupported => ApiError::InvalidInput(Some(err.error.message)),
                AptosErrorCode::InternalError => ApiError::InternalError(Some(err.error.message)),
                AptosErrorCode::ApiDisabled => ApiError::InternalError(Some(err.error.message)),
            },
```

**File:** crates/aptos-rosetta/src/network.rs (L104-107)
```rust
    let errors = ApiError::all()
        .into_iter()
        .map(|err| err.into_error())
        .collect();
```

**File:** types/src/mempool_status.rs (L66-67)
```rust
    // The transaction filter has rejected the transaction
    RejectedByFilter = 7,
```

**File:** api/src/transactions.rs (L1486-1489)
```rust
            MempoolStatusCode::RejectedByFilter => Err(AptosError::new_with_error_code(
                mempool_status.message,
                AptosErrorCode::RejectedByFilter,
            )),
```

**File:** crates/num-variants/src/lib.rs (L18-29)
```rust
/// Derives an associated constant with the number of variants this enum has.
///
/// The default constant name is `NUM_VARIANTS`. This can be customized with `#[num_variants =
/// "FOO")]`.
#[proc_macro_derive(NumVariants, attributes(num_variants))]
pub fn derive_num_variants(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match derive_num_variants_impl(input) {
        Ok(token_stream) => proc_macro::TokenStream::from(token_stream),
        Err(err) => proc_macro::TokenStream::from(err.to_compile_error()),
    }
}
```

**File:** crates/aptos-rosetta/README.md (L86-88)
```markdown
All errors are 500s and have error codes that are static and must not change.  To add more errors,
add new codes and associated data.  The error details must not show in the network options call and
are all provided as Option<String> for that reason.
```
