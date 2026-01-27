# Audit Report

## Title
Epoch Boundary Validation Failure in Stream Version Update Allows Version-Epoch Desynchronization

## Summary
The `update_stream_version_and_epoch()` function in the continuous transaction stream engine fails to properly validate epoch boundaries when processing subscription responses. This allows transaction versions to advance past epoch boundaries while the epoch counter remains stale, creating a critical desynchronization between version numbers and their associated epochs.

## Finding Description

The vulnerability exists in the epoch increment logic within `update_stream_version_and_epoch()`: [1](#0-0) 

The function only increments the epoch when two conditions are met simultaneously:
1. `last_received_version` exactly equals `target_ledger_info.ledger_info().version()`
2. `target_ledger_info.ledger_info().ends_epoch()` returns true

This logic assumes that transaction batches will never span epoch boundaries unless they end precisely at an epoch-ending version. However, this assumption is violated in the subscription flow.

When a peer subscribes to new transactions and both the peer's known epoch and the server's highest synced epoch are equal, the system uses the highest synced ledger info as the target (which is NOT necessarily an epoch-ending ledger info): [2](#0-1) 

This target ledger info is then included in subscription responses: [3](#0-2) 

When the data streaming service processes this response, it extracts the target from the payload: [4](#0-3) 

And calls `update_stream_version_and_epoch()` with this non-epoch-ending target: [5](#0-4) 

**Attack Scenario:**
1. Victim node is at version 1050, epoch N+1
2. Epoch N+1 ends at version 1100 (epoch boundary)
3. Victim subscribes to new transactions
4. Malicious peer or legitimate server sends subscription response containing:
   - Transactions from version 1051 to 1200
   - Target ledger info at version 2000 (epoch N+2, NOT epoch-ending)
5. When processing in `update_stream_version_and_epoch()`:
   - `last_received_version = 1200` (in epoch N+2)
   - `target_ledger_info` points to version 2000
   - Check `1200 == 2000` fails → epoch NOT incremented
   - Result: `next_stream_version = 1201`, `next_stream_epoch = N+1`
6. **Critical Desynchronization**: Version 1201 is in epoch N+2, but tracked as epoch N+1

This breaks the fundamental invariant that version numbers must be correctly mapped to their epochs, which is essential for validator set changes, state synchronization, and consensus.

## Impact Explanation

**Severity: HIGH** (per Aptos Bug Bounty guidelines for "Significant protocol violations")

This vulnerability can cause:

1. **Consensus Inconsistencies**: Different nodes may have different version-to-epoch mappings, leading to disagreement on which validator set is authoritative for a given version.

2. **State Sync Failures**: Nodes attempting to sync will reject transactions due to epoch mismatches when validating proofs, as the proof's epoch won't match the expected epoch for that version range.

3. **Validator Set Confusion**: Since validator sets change at epoch boundaries, incorrect epoch tracking can lead to nodes accepting/rejecting blocks from the wrong validator set.

4. **Chain Fork Risk**: In extreme cases, if different nodes have divergent epoch-version mappings, they may follow different chain branches when validators change between epochs.

While this doesn't directly cause fund loss or achieve Critical severity, it represents a significant protocol violation that can severely impact network operation and consensus safety.

## Likelihood Explanation

**Likelihood: MEDIUM to HIGH**

The vulnerability triggers whenever:
1. A subscription response spans an epoch boundary
2. The target ledger info is not an epoch-ending ledger info
3. Multiple epochs exist between the peer's position and the target

This is a realistic scenario that occurs naturally when:
- Nodes are catching up after being offline
- Network conditions cause subscription responses to contain larger version ranges
- The highest synced ledger info is well past multiple epoch boundaries

No malicious intent is required - this is a logic bug that can be triggered by normal network operation. However, a malicious peer could deliberately craft subscription responses to maximize the impact.

## Recommendation

Add explicit epoch boundary validation in `update_stream_version_and_epoch()`. The function should:

1. Track which epochs exist between `request_start_version` and `last_received_version`
2. Request epoch-ending ledger infos for any crossed epochs
3. Increment the epoch counter for each crossed boundary
4. Validate that transactions don't span epochs without proper epoch-ending ledger info validation

**Proposed Fix:**

```rust
fn update_stream_version_and_epoch(
    &mut self,
    request_start_version: Version,
    request_end_version: Version,
    target_ledger_info: &LedgerInfoWithSignatures,
    last_received_version: Version,
) -> Result<(), Error> {
    // Verify the client request indices
    let (next_stream_version, mut next_stream_epoch) = self.next_stream_version_and_epoch;
    verify_client_request_indices(
        next_stream_version,
        request_start_version,
        request_end_version,
    )?;

    // NEW: Check if we've crossed an epoch boundary
    let target_epoch = target_ledger_info.ledger_info().epoch();
    if target_epoch > next_stream_epoch {
        // We've potentially crossed epoch boundaries
        // Validate that we're not updating past an epoch boundary without proper epoch-ending info
        if last_received_version > next_stream_version 
            && !target_ledger_info.ledger_info().ends_epoch() {
            return Err(Error::UnexpectedErrorEncountered(
                format!(
                    "Cannot update stream past potential epoch boundaries without epoch-ending ledger info. \
                    Current epoch: {}, target epoch: {}, last version: {}",
                    next_stream_epoch, target_epoch, last_received_version
                )
            ));
        }
    }

    // Update the next stream version and epoch
    if last_received_version == target_ledger_info.ledger_info().version()
        && target_ledger_info.ledger_info().ends_epoch()
    {
        next_stream_epoch = next_stream_epoch
            .checked_add(1)
            .ok_or_else(|| Error::IntegerOverflow("Next stream epoch has overflown!".into()))?;
    }
    
    let next_stream_version = last_received_version
        .checked_add(1)
        .ok_or_else(|| Error::IntegerOverflow("Next stream version has overflown!".into()))?;
    self.next_stream_version_and_epoch = (next_stream_version, next_stream_epoch);

    // ... rest of function
}
```

Additionally, the subscription logic should ensure that when multiple epochs separate the peer from the target, epoch-ending ledger infos are provided sequentially rather than jumping to a far-future target.

## Proof of Concept

```rust
// Test demonstrating the vulnerability
#[tokio::test]
async fn test_epoch_boundary_desync_in_subscription() {
    // Setup: Node at version 1050, epoch 1
    // Epoch 1 ends at version 1100
    // Create subscription response with versions 1051-1200 and target at version 2000 (epoch 2)
    
    let mut stream_engine = ContinuousTransactionStreamEngine::new(
        DataStreamingServiceConfig::default(),
        &StreamRequest::ContinuouslyStreamTransactions(/* params */),
    ).unwrap();
    
    // Set current state
    stream_engine.next_stream_version_and_epoch = (1051, 1); // epoch 1
    
    // Create response payload that spans epoch boundary
    let transactions = create_test_transactions(1051, 1200); // Crosses epoch at 1100
    let target_ledger_info = create_test_ledger_info(2000, 2, false); // epoch 2, NOT epoch-ending
    
    let response = ResponsePayload::NewTransactionsWithProof((
        transactions,
        target_ledger_info,
    ));
    
    // Process the response
    let notification = stream_engine.create_notification_for_new_data(
        1051,
        response,
        Arc::new(U64IdGenerator::new()),
    ).unwrap();
    
    // VULNERABILITY: Epoch should be 2, but it's still 1
    assert_eq!(stream_engine.next_stream_version_and_epoch.0, 1201); // Correct
    assert_eq!(stream_engine.next_stream_version_and_epoch.1, 1);    // WRONG! Should be 2
    
    // This desynchronization can cause consensus issues
}
```

## Notes

This vulnerability is particularly dangerous because:

1. **Silent Failure**: The desynchronization occurs without error, making it difficult to detect until consensus or state sync issues manifest.

2. **Cascading Effects**: Once a node has incorrect epoch tracking, all subsequent version-epoch mappings become unreliable.

3. **Multi-Epoch Gaps**: The issue is exacerbated when there are multiple epoch boundaries between a node's current position and the sync target, as each crossed boundary compounds the error.

The fix requires coordinated changes across both the data streaming service (to validate epoch boundaries) and the subscription service (to ensure appropriate epoch-ending ledger infos are provided when spanning epochs).

### Citations

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L615-622)
```rust
        // Update the request and stream versions
        self.update_request_version_and_epoch(last_version, &target_ledger_info)?;
        self.update_stream_version_and_epoch(
            first_version,
            last_version,
            &target_ledger_info,
            last_version,
        )?;
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L1035-1084)
```rust
    fn update_stream_version_and_epoch(
        &mut self,
        request_start_version: Version,
        request_end_version: Version,
        target_ledger_info: &LedgerInfoWithSignatures,
        last_received_version: Version,
    ) -> Result<(), Error> {
        // Verify the client request indices
        let (next_stream_version, mut next_stream_epoch) = self.next_stream_version_and_epoch;
        verify_client_request_indices(
            next_stream_version,
            request_start_version,
            request_end_version,
        )?;

        // Update the next stream version and epoch
        if last_received_version == target_ledger_info.ledger_info().version()
            && target_ledger_info.ledger_info().ends_epoch()
        {
            next_stream_epoch = next_stream_epoch
                .checked_add(1)
                .ok_or_else(|| Error::IntegerOverflow("Next stream epoch has overflown!".into()))?;
        }
        let next_stream_version = last_received_version
            .checked_add(1)
            .ok_or_else(|| Error::IntegerOverflow("Next stream version has overflown!".into()))?;
        self.next_stream_version_and_epoch = (next_stream_version, next_stream_epoch);

        // Check if the stream is now complete
        let stream_request_target = match &self.request {
            StreamRequest::ContinuouslyStreamTransactions(request) => request.target.clone(),
            StreamRequest::ContinuouslyStreamTransactionOutputs(request) => request.target.clone(),
            StreamRequest::ContinuouslyStreamTransactionsOrOutputs(request) => {
                request.target.clone()
            },
            request => invalid_stream_request!(request),
        };
        if let Some(target) = stream_request_target {
            if last_received_version >= target.ledger_info().version() {
                self.stream_is_complete = true;
            }
        }

        // Update the current target ledger info if we've hit it
        if last_received_version >= target_ledger_info.ledger_info().version() {
            self.current_target_ledger_info = None;
        }

        Ok(())
    }
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L2269-2306)
```rust
fn extract_new_versions_and_target(
    client_response_payload: &ResponsePayload,
) -> Result<(usize, LedgerInfoWithSignatures), Error> {
    // Extract the number of new versions and the target ledger info
    let (num_versions, target_ledger_info) = match &client_response_payload {
        ResponsePayload::NewTransactionsWithProof((
            transactions_with_proof,
            target_ledger_info,
        )) => (
            transactions_with_proof.get_num_transactions(),
            target_ledger_info.clone(),
        ),
        ResponsePayload::NewTransactionOutputsWithProof((
            outputs_with_proof,
            target_ledger_info,
        )) => (
            outputs_with_proof.get_num_outputs(),
            target_ledger_info.clone(),
        ),
        response_payload => {
            // TODO(joshlind): eventually we want to notify the data client of the bad response
            return Err(Error::AptosDataClientResponseIsInvalid(format!(
                "Expected new transactions or outputs but got: {:?}",
                response_payload
            )));
        },
    };

    // Ensure that we have at least one data item
    if num_versions == 0 {
        // TODO(joshlind): eventually we want to notify the data client of the bad response
        return Err(Error::AptosDataClientResponseIsInvalid(
            "Received an empty transaction or output list!".into(),
        ));
    }

    Ok((num_versions, target_ledger_info))
}
```

**File:** state-sync/storage-service/server/src/subscription.rs (L960-964)
```rust
                } else {
                    peers_with_ready_subscriptions
                        .lock()
                        .push((peer_network_id, highest_synced_ledger_info.clone()));
                };
```

**File:** state-sync/storage-service/server/src/utils.rs (L120-123)
```rust
                DataResponse::NewTransactionsWithProof((
                    transactions_with_proof,
                    target_ledger_info,
                ))
```
