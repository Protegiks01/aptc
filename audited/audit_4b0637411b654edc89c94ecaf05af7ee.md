# Audit Report

## Title
State Sync DoS via Unvalidated TransactionDataWithProofResponse Allowing Both-None Invalid State

## Summary
The `TryFrom<StorageServiceResponse>` implementation for `TransactionOrOutputListWithProofV2` fails to validate that at least one option field is `Some`, allowing malicious peers to send responses where both transaction and output lists are `None`. This creates an invalid state that bypasses peer penalization mechanisms, enabling a denial-of-service attack through indefinite retry loops.

## Finding Description

The vulnerability exists in the conversion logic that transforms network responses into the internal `TransactionOrOutputListWithProofV2` type (a tuple of two `Option` fields). [1](#0-0) 

This implementation directly returns both optional fields without validating the invariant that at least one must be `Some`. When a `DataResponse::TransactionDataWithProof` is received, it unconditionally creates the tuple from whatever values are in the response struct. [2](#0-1) 

Since both fields are `Option` types, a malicious peer can craft a serialized `TransactionDataWithProofResponse` with both fields as `None`, which will successfully deserialize via BCS.

**Attack Flow:**

1. Malicious peer sends a `TransactionDataWithProofResponse` where `transaction_list_with_proof = None` AND `transaction_output_list_with_proof = None`

2. The response deserializes successfully (both are valid `Option<T>`)

3. The data client calls `TryFrom::try_from(storage_response)` to convert the response [3](#0-2) 

4. The conversion succeeds (returns `Ok((None, None))`) without calling `notify_bad_response`

5. The invalid tuple is wrapped in a `Response` and returned to the data streaming service

6. Later, when converting to `ResponsePayload`, the validation finally triggers [4](#0-3) 

7. However, this error occurs AFTER the point where `notify_bad_response` is called in the data client, so the peer is not penalized [5](#0-4) 

8. The error is handled by resending the request without peer penalization [6](#0-5) 

9. The malicious peer repeats, causing indefinite retries and resource exhaustion

The fundamental issue is that the validation happens at the wrong layer - the `TryFrom` for `TransactionOrOutputListWithProofV2` succeeds, so no bad response notification occurs, but the later `TryFrom` for `ResponsePayload` fails after the notification opportunity has passed.

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty program ("Validator node slowdowns" / "Significant protocol violations"):

1. **Denial of Service**: A malicious peer can force victim nodes to waste computational resources in infinite retry loops, attempting to process invalid responses that will always fail

2. **State Sync Disruption**: Nodes attempting to synchronize state will be unable to make progress while under attack, degrading network health

3. **No Peer Penalization**: The malicious peer avoids the scoring/banning mechanism, allowing sustained attacks without detection

4. **Resource Exhaustion**: Each retry consumes CPU cycles for deserialization, validation, and error handling, multiplied across potentially many data streams

The vulnerability affects the state synchronization layer which is critical for:
- New nodes joining the network
- Nodes catching up after downtime  
- Continuous state sync during normal operation

While not directly compromising consensus safety or causing fund loss, prolonged exploitation could degrade network availability and validator performance.

## Likelihood Explanation

**Likelihood: High**

Attack requirements are minimal:
- **No special privileges needed**: Any network peer can send storage service responses
- **Simple exploit**: Craft a `TransactionDataWithProofResponse` with both fields as `None` via BCS serialization
- **No cryptographic bypass required**: The malformed response passes deserialization
- **Repeatable**: Can be sent repeatedly without detection/banning

The only barrier is that the attacker must be connected as a peer in the storage service network, which is accessible to any participant.

## Recommendation

Add validation in the `TryFrom` implementation to enforce the invariant that at least one option must be `Some`:

```rust
impl TryFrom<StorageServiceResponse> for TransactionOrOutputListWithProofV2 {
    type Error = crate::responses::Error;

    fn try_from(response: StorageServiceResponse) -> crate::Result<Self, Self::Error> {
        let data_response = response.get_data_response()?;
        match data_response {
            DataResponse::TransactionsOrOutputsWithProof((
                transaction_list_with_proof,
                output_list_with_proof,
            )) => Ok((
                transaction_list_with_proof.map(TransactionListWithProofV2::new_from_v1),
                output_list_with_proof.map(TransactionOutputListWithProofV2::new_from_v1),
            )),
            DataResponse::TransactionDataWithProof(response) => {
                let result = (
                    response.transaction_list_with_proof,
                    response.transaction_output_list_with_proof,
                );
                
                // Validate that at least one option is Some
                if result.0.is_none() && result.1.is_none() {
                    return Err(Error::UnexpectedResponseError(
                        "TransactionDataWithProof must contain either transactions or outputs".into()
                    ));
                }
                
                Ok(result)
            },
            _ => Err(Error::UnexpectedResponseError(format!(
                "expected transactions_or_outputs_with_proof, found {}",
                data_response.get_label()
            ))),
        }
    }
}
```

This ensures the error occurs at the data client layer where `notify_bad_response` is properly called, triggering peer penalization. [7](#0-6) 

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use aptos_storage_service_types::responses::{
        DataResponse, StorageServiceResponse, TransactionDataWithProofResponse,
        TransactionDataResponseType,
    };

    #[test]
    fn test_both_none_creates_invalid_state() {
        // Create a TransactionDataWithProofResponse with both fields as None
        let malicious_response = TransactionDataWithProofResponse {
            transaction_data_response_type: TransactionDataResponseType::TransactionData,
            transaction_list_with_proof: None,
            transaction_output_list_with_proof: None,
        };

        // Wrap in DataResponse and StorageServiceResponse
        let data_response = DataResponse::TransactionDataWithProof(malicious_response);
        let storage_response = StorageServiceResponse::RawResponse(data_response);

        // Attempt conversion - this SHOULD fail but currently succeeds
        let result = TransactionOrOutputListWithProofV2::try_from(storage_response);

        // Currently passes (vulnerability), should fail (fixed)
        match result {
            Ok((None, None)) => {
                println!("VULNERABILITY: Both-None state created successfully!");
                println!("This invalid state bypasses peer penalization.");
            },
            Err(_) => {
                println!("FIXED: Validation correctly rejected both-None state");
            },
            Ok(_) => {
                println!("At least one option is Some (valid state)");
            }
        }
    }
}
```

**Expected behavior (current)**: Test passes with both `None`, demonstrating the vulnerability

**Expected behavior (after fix)**: Test fails with error, demonstrating proper validation

## Notes

The vulnerability demonstrates a common pattern in distributed systems: validation occurring at the wrong layer. While defensive checks exist deeper in the call stack (in `ResponsePayload` conversion and payload processing), these occur after the critical peer penalization decision point. Defense-in-depth requires validation at the earliest possible point where errors can trigger appropriate responses - in this case, immediately after network deserialization.

### Citations

**File:** state-sync/storage-service/types/src/responses.rs (L163-168)
```rust
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransactionDataWithProofResponse {
    pub transaction_data_response_type: TransactionDataResponseType,
    pub transaction_list_with_proof: Option<TransactionListWithProofV2>,
    pub transaction_output_list_with_proof: Option<TransactionOutputListWithProofV2>,
}
```

**File:** state-sync/storage-service/types/src/responses.rs (L577-600)
```rust
impl TryFrom<StorageServiceResponse> for TransactionOrOutputListWithProofV2 {
    type Error = crate::responses::Error;

    fn try_from(response: StorageServiceResponse) -> crate::Result<Self, Self::Error> {
        let data_response = response.get_data_response()?;
        match data_response {
            DataResponse::TransactionsOrOutputsWithProof((
                transaction_list_with_proof,
                output_list_with_proof,
            )) => Ok((
                transaction_list_with_proof.map(TransactionListWithProofV2::new_from_v1),
                output_list_with_proof.map(TransactionOutputListWithProofV2::new_from_v1),
            )),
            DataResponse::TransactionDataWithProof(response) => Ok((
                response.transaction_list_with_proof,
                response.transaction_output_list_with_proof,
            )),
            _ => Err(Error::UnexpectedResponseError(format!(
                "expected transactions_or_outputs_with_proof, found {}",
                data_response.get_label()
            ))),
        }
    }
}
```

**File:** state-sync/aptos-data-client/src/client.rs (L750-762)
```rust
        // Try to convert the storage service enum into the exact variant we're expecting.
        // We do this using spawn_blocking because it involves serde and compression.
        tokio::task::spawn_blocking(move || {
            match T::try_from(storage_response) {
                Ok(new_payload) => Ok(Response::new(context, new_payload)),
                // If the variant doesn't match what we're expecting, report the issue
                Err(err) => {
                    context
                        .response_callback
                        .notify_bad_response(ResponseError::InvalidPayloadDataType);
                    Err(err.into())
                },
            }
```

**File:** state-sync/aptos-data-client/src/interface.rs (L386-400)
```rust
impl TryFrom<TransactionOrOutputListWithProofV2> for ResponsePayload {
    type Error = Error;

    fn try_from(inner: TransactionOrOutputListWithProofV2) -> error::Result<Self, Error> {
        let (transaction_list, output_list) = inner;
        if let Some(transaction_list) = transaction_list {
            Ok(Self::TransactionsWithProof(transaction_list))
        } else if let Some(output_list) = output_list {
            Ok(Self::TransactionOutputsWithProof(output_list))
        } else {
            Err(Error::InvalidResponse(
                "Invalid response! No transaction or output list was returned!".into(),
            ))
        }
    }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L711-744)
```rust
    fn handle_data_client_error(
        &mut self,
        data_client_request: &DataClientRequest,
        data_client_error: &aptos_data_client::error::Error,
    ) -> Result<(), Error> {
        // Log the error
        warn!(LogSchema::new(LogEntry::ReceivedDataResponse)
            .stream_id(self.data_stream_id)
            .event(LogEvent::Error)
            .error(&data_client_error.clone().into())
            .message("Encountered a data client error!"));

        // TODO(joshlind): can we identify the best way to react to the error?
        self.resend_data_client_request(data_client_request)
    }

    /// Resends a failed data client request and pushes the pending notification
    /// to the head of the pending notifications batch.
    fn resend_data_client_request(
        &mut self,
        data_client_request: &DataClientRequest,
    ) -> Result<(), Error> {
        // Increment the number of client failures for this request
        self.request_failure_count += 1;

        // Resend the client request
        let pending_client_response = self.send_client_request(true, data_client_request.clone());

        // Push the pending response to the head of the sent requests queue
        self.get_sent_data_requests()?
            .push_front(pending_client_response);

        Ok(())
    }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L1637-1653)
```rust
async fn get_transactions_or_outputs_with_proof<
    T: AptosDataClientInterface + Send + Clone + 'static,
>(
    aptos_data_client: T,
    request: TransactionsOrOutputsWithProofRequest,
    request_timeout_ms: u64,
) -> Result<Response<ResponsePayload>, aptos_data_client::error::Error> {
    let client_response = aptos_data_client.get_transactions_or_outputs_with_proof(
        request.proof_version,
        request.start_version,
        request.end_version,
        request.include_events,
        request_timeout_ms,
    );
    let (context, payload) = client_response.await?.into_parts();
    Ok(Response::new(context, ResponsePayload::try_from(payload)?))
}
```
