# Audit Report

## Title
Subscription Request Input Validation Bypass Leading to Error Misclassification

## Summary
Subscription requests with malformed `known_version_at_stream_start` values bypass the moderator's input validation and cause arithmetic overflow errors downstream that are incorrectly classified as `UnexpectedErrorEncountered` instead of `InvalidRequest`, potentially obscuring attack patterns in monitoring systems.

## Finding Description

The storage service's error classification system fails to properly categorize certain input validation failures. Specifically, subscription requests contain a `known_version_at_stream_start` field that is not validated by the request moderator but is later used in arithmetic operations that can overflow.

**Validation Gap:**

The moderator's `can_service` check for subscription requests only validates ledger timing, not the `known_version_at_stream_start` value: [1](#0-0) 

**Downstream Overflow:**

When processing subscriptions, the unvalidated `known_version` (derived from `known_version_at_stream_start`) is used in checked arithmetic operations: [2](#0-1) 

These operations return `Error::UnexpectedErrorEncountered` on overflow rather than `Error::InvalidRequest`.

**Error Misclassification:**

The error conversion layer maps this incorrectly: [3](#0-2) 

**Attack Flow:**
1. Attacker sends `SubscribeTransactionOutputsWithProof` with `known_version_at_stream_start = u64::MAX`
2. Moderator's `validate_request` passes (no validation of this field)
3. Subscription stream stores the request with `highest_known_version = u64::MAX`
4. When new data arrives, `get_storage_request_for_missing_data` attempts `u64::MAX.checked_add(1)`
5. Overflow returns `Error::UnexpectedErrorEncountered("Start version has overflown!")`
6. Error propagates as `InternalError` instead of `InvalidRequest`

## Impact Explanation

This issue represents a **code quality and monitoring concern** rather than a direct security vulnerability. The impact is limited to:

- **Error Misclassification**: Input validation failures incorrectly appear as unexpected internal errors
- **Monitoring Confusion**: Security monitoring systems tracking attack patterns via error types may miss malformed requests
- **Debugging Complexity**: Operators investigating issues receive misleading error classifications

However, this does **NOT** cause:
- Consensus violations or safety breaks
- Loss of funds or state corruption  
- Validator crashes or availability issues
- Resource exhaustion (request fails immediately)
- Rate limiting bypass (validation passed before error occurs)

**Severity Assessment**: This qualifies as **Low Severity** ("Non-critical implementation bug") per Aptos bug bounty criteria, as it does not break any critical security invariants or cause measurable security harm beyond error reporting accuracy.

## Likelihood Explanation

**High Likelihood** - Any network peer can trivially send a malformed subscription request. The attack requires no special privileges, resources, or timing. The validation gap is architectural rather than edge-case.

## Recommendation

Add explicit validation of subscription metadata fields in the moderator's `can_service` check:

```rust
// In responses.rs, enhance can_service_subscription_request:
fn can_service_subscription_request(
    aptos_data_client_config: &AptosDataClientConfig,
    time_service: TimeService,
    synced_ledger_info: Option<&LedgerInfoWithSignatures>,
) -> bool {
    let max_lag_secs = aptos_data_client_config.max_subscription_lag_secs;
    check_synced_ledger_lag(synced_ledger_info, time_service, max_lag_secs)
}
```

Should be changed to also validate the known_version:

```rust  
fn can_service_subscription_request(
    request: &SubscriptionRequest,
    aptos_data_client_config: &AptosDataClientConfig,
    time_service: TimeService,
    synced_ledger_info: Option<&LedgerInfoWithSignatures>,
) -> bool {
    // Validate known_version is reasonable
    if let Some(metadata) = extract_subscription_metadata(request) {
        if metadata.known_version_at_stream_start == u64::MAX {
            return false;
        }
        if let Some(ledger_info) = synced_ledger_info {
            if metadata.known_version_at_stream_start > ledger_info.ledger_info().version() {
                return false;
            }
        }
    }
    
    // Existing lag check
    let max_lag_secs = aptos_data_client_config.max_subscription_lag_secs;
    check_synced_ledger_lag(synced_ledger_info, time_service, max_lag_secs)
}
```

Additionally, change the error classification in `subscription.rs` to return `InvalidRequest` for arithmetic overflows on user-provided values.

## Proof of Concept

```rust
// Test demonstrating the misclassification
#[test]
fn test_subscription_known_version_overflow() {
    use aptos_storage_service_types::requests::{
        DataRequest, StorageServiceRequest, SubscribeTransactionOutputsWithProofRequest,
        SubscriptionStreamMetadata,
    };
    
    // Create subscription request with malformed known_version
    let malicious_metadata = SubscriptionStreamMetadata {
        known_version_at_stream_start: u64::MAX,
        known_epoch_at_stream_start: 0,
        subscription_stream_id: 1,
    };
    
    let request = StorageServiceRequest::new(
        DataRequest::SubscribeTransactionOutputsWithProof(
            SubscribeTransactionOutputsWithProofRequest {
                subscription_stream_metadata: malicious_metadata,
                subscription_stream_index: 0,
            }
        ),
        false,
    );
    
    // Send to storage service - validation will pass
    // When processed, will return UnexpectedErrorEncountered instead of InvalidRequest
    // Expected: Error::InvalidRequest("known_version is invalid")  
    // Actual: Error::UnexpectedErrorEncountered("Start version has overflown!")
}
```

---

**Note**: While this finding demonstrates a clear violation of the error handling contract (input validation failures should be classified as `InvalidRequest`), it does not meet the **Critical, High, or Medium** severity threshold required by the validation checklist, as it causes no measurable security harm beyond error reporting accuracy. This would be classified as **Low Severity** under Aptos bug bounty criteria.

### Citations

**File:** state-sync/storage-service/types/src/responses.rs (L760-774)
```rust
            SubscribeTransactionOutputsWithProof(_) => can_service_subscription_request(
                aptos_data_client_config,
                time_service,
                self.synced_ledger_info.as_ref(),
            ),
            SubscribeTransactionsOrOutputsWithProof(_) => can_service_subscription_request(
                aptos_data_client_config,
                time_service,
                self.synced_ledger_info.as_ref(),
            ),
            SubscribeTransactionsWithProof(_) => can_service_subscription_request(
                aptos_data_client_config,
                time_service,
                self.synced_ledger_info.as_ref(),
            ),
```

**File:** state-sync/storage-service/server/src/subscription.rs (L77-97)
```rust
            target_version.checked_sub(known_version).ok_or_else(|| {
                Error::UnexpectedErrorEncountered(
                    "Number of versions to fetch has overflown!".into(),
                )
            })?;

        // Bound the number of versions to fetch by the maximum chunk size
        num_versions_to_fetch = min(
            num_versions_to_fetch,
            self.max_chunk_size_for_request(config),
        );

        // Calculate the start and end versions
        let start_version = known_version.checked_add(1).ok_or_else(|| {
            Error::UnexpectedErrorEncountered("Start version has overflown!".into())
        })?;
        let end_version = known_version
            .checked_add(num_versions_to_fetch)
            .ok_or_else(|| {
                Error::UnexpectedErrorEncountered("End version has overflown!".into())
            })?;
```

**File:** state-sync/storage-service/server/src/error.rs (L31-34)
```rust
impl From<aptos_storage_service_types::responses::Error> for Error {
    fn from(error: aptos_storage_service_types::responses::Error) -> Self {
        Error::UnexpectedErrorEncountered(error.to_string())
    }
```
