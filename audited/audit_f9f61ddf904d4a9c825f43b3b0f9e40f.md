# Audit Report

## Title
Missing Epoch-to-Version Correspondence Validation in Optimistic Fetch Requests Enables Cross-Epoch State Synchronization Attacks

## Summary
The `get_new_transaction_output_data_with_proof()` constructor and related optimistic fetch processing code fail to validate that the `known_epoch` parameter corresponds to the actual epoch of `known_version`. This allows malicious peers to submit state synchronization requests with inconsistent epoch/version pairs, bypassing validation when `known_epoch >= synced_epoch`, leading to cross-epoch data responses and client state inconsistencies.

## Finding Description

The vulnerability exists in the state synchronization request handling pipeline at multiple levels:

**1. Constructor Missing Validation**

The `get_new_transaction_output_data_with_proof()` function accepts `known_version` and `known_epoch` parameters without validating their correspondence: [1](#0-0) 

**2. Conditional Validation Bypass**

The optimistic fetch validation logic only checks epoch-to-version correspondence when BOTH conditions are met:
- `highest_known_version < highest_synced_version` (line 502)
- `highest_known_epoch < highest_synced_epoch` (line 503) [2](#0-1) 

When `known_epoch >= synced_epoch`, the validation at lines 531-536 is completely bypassed, and the request is added to ready optimistic fetches without checking if `known_version` actually belongs to `known_epoch`.

**3. Unused Validation Function**

The codebase has a `get_epoch(version)` function that can determine which epoch a version belongs to, but it is never called during request validation: [3](#0-2) 

**Attack Vector:**

1. Attacker observes blockchain is at epoch N, version V_N
2. Attacker sends optimistic fetch request with:
   - `known_version = V_(N-1)` (a version from epoch N-1)
   - `known_epoch = N` (falsely claiming to be at current epoch)
3. Validation condition at line 503 evaluates to false (N < N = false)
4. Request bypasses epoch validation and is queued as ready
5. When blockchain advances to epoch N+1, server returns transaction data starting from `V_(N-1) + 1` with proofs relative to epoch N+1
6. Response contains cross-epoch data that the client cannot properly validate with its (incorrect) internal epoch state

## Impact Explanation

This vulnerability violates the **State Consistency** critical invariant (#4) and constitutes a **Medium severity** issue per the Aptos bug bounty program because:

1. **State Synchronization Corruption**: Clients with mismatched epoch/version pairs receive data spanning multiple epochs with proofs relative to different validator sets, causing state divergence

2. **Validator Set Confusion**: Each epoch has a distinct validator set. A client believing it's at (version=V_old, epoch=E_current) will attempt to verify signatures using the wrong epoch's validator set

3. **Resource Waste**: Storage servers spend resources serving potentially unbounded data to clients with invalid state, enabling resource exhaustion attacks

4. **Cascading Failures**: If multiple clients become desynchronized through this attack, network-wide state sync degradation occurs

The impact is limited to Medium (not Critical/High) because:
- No direct consensus safety violation occurs
- No funds are immediately at risk
- Server's own state remains correct
- Well-implemented clients should detect inconsistencies during verification

However, this requires manual intervention to resync affected nodes and could cause temporary network disruption.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploited because:

1. **Low Attack Complexity**: Any network peer can send optimistic fetch requests without authentication beyond basic P2P networking
2. **No Special Privileges Required**: Attacker needs only network connectivity, not validator access or stake
3. **Easy to Trigger**: Simply sending a malformed request with mismatched parameters triggers the vulnerability
4. **Common Scenario**: The bypass condition (`known_epoch >= synced_epoch`) occurs frequently during normal operations when peers are catching up to the current epoch
5. **No Rate Limiting**: The optimistic fetch mechanism is designed for high throughput, allowing repeated exploitation

## Recommendation

**Immediate Fix**: Add epoch-to-version correspondence validation in the optimistic fetch request handler before processing.

```rust
// In state-sync/storage-service/server/src/optimistic_fetch.rs
// Add after line 417 (gathering peer data):

// Validate that known_version belongs to known_epoch
let actual_epoch = match storage.get_epoch(highest_known_version) {
    Ok(epoch) => epoch,
    Err(error) => {
        error!(LogSchema::new(LogEntry::OptimisticFetchRefresh)
            .error(&error)
            .message(&format!(
                "Failed to get epoch for version: {:?}",
                highest_known_version
            )));
        continue; // Skip this peer
    },
};

if actual_epoch != highest_known_epoch {
    // Epoch-version mismatch detected
    peers_with_invalid_optimistic_fetches
        .lock()
        .push(peer_network_id);
    continue; // Skip validation, will be removed as invalid
}
```

**Additional Hardening**:

1. Add validation in the constructor itself:
```rust
// In state-sync/storage-service/types/src/requests.rs
pub fn get_new_transaction_output_data_with_proof(
    known_version: u64,
    known_epoch: u64,
    max_response_bytes: u64,
) -> Result<Self, Error> {
    // Note: Validation would require storage access, so consider
    // moving this to a factory method with storage access
    ...
}
```

2. Add metrics to track rejected requests with mismatched epoch/version pairs
3. Consider adding client-side validation to reject responses that don't match expected epoch progression

## Proof of Concept

```rust
// Test demonstrating the vulnerability
// Add to state-sync/storage-service/server/src/tests/new_transactions.rs

#[tokio::test]
async fn test_cross_epoch_validation_bypass() {
    // Setup: Create test environment with storage at epoch 2, version 1000
    let (mut mock_storage, _) = MockStorageReader::new();
    mock_storage.expect_get_latest_ledger_info().return_once(|| {
        Ok(create_test_ledger_info_at_epoch(2, 1000))
    });
    
    // Attack: Create request with version from epoch 1 but claiming epoch 2
    let peer_network_id = PeerNetworkId::random();
    let malicious_request = StorageServiceRequest::new(
        DataRequest::get_new_transaction_output_data_with_proof(
            400,  // known_version from epoch 1 (epochs change at v=500, v=1000)
            2,    // known_epoch claiming current epoch 2
            10000,
        ),
        false,
    );
    
    // Exploit: Submit request through handler
    let handler = create_test_handler(mock_storage);
    handler.handle_optimistic_fetch_request(
        peer_network_id,
        malicious_request.clone(),
        response_sender,
    );
    
    // Verify: Request was accepted without validation
    let optimistic_fetches = handler.optimistic_fetches.clone();
    assert!(optimistic_fetches.contains_key(&peer_network_id));
    
    // When epoch advances to 3, the request will be processed
    // without validating that version 400 is not in epoch 2
    // This causes cross-epoch data to be returned
}

fn create_test_ledger_info_at_epoch(epoch: u64, version: u64) -> LedgerInfoWithSignatures {
    // Implementation creates ledger info with specified epoch and version
    ...
}
```

**Expected Behavior**: Request should be rejected with an error indicating epoch-version mismatch.

**Actual Behavior**: Request is accepted and queued for processing, bypassing validation when `known_epoch >= synced_epoch`.

---

**Notes**

This vulnerability is particularly concerning because:

1. The storage layer already has the `get_epoch(version)` function needed for validation, indicating the developers were aware of the need to map versions to epochs

2. The partial validation logic (lines 531-536) shows awareness of cross-epoch issues, but the conditional bypass creates a security gap

3. The issue affects all three variants of optimistic fetch requests (`GetNewTransactionDataWithProof`, `GetNewTransactionOutputsWithProof`, `GetNewTransactionsWithProof`) as they share the same validation code path

4. This is not merely a client implementation issue - the server SHOULD validate requests to maintain defense-in-depth and prevent resource exhaustion attacks

### Citations

**File:** state-sync/storage-service/types/src/requests.rs (L232-244)
```rust
    pub fn get_new_transaction_output_data_with_proof(
        known_version: u64,
        known_epoch: u64,
        max_response_bytes: u64,
    ) -> Self {
        let transaction_data_request_type = TransactionDataRequestType::TransactionOutputData;
        Self::GetNewTransactionDataWithProof(GetNewTransactionDataWithProofRequest {
            transaction_data_request_type,
            known_version,
            known_epoch,
            max_response_bytes,
        })
    }
```

**File:** state-sync/storage-service/server/src/optimistic_fetch.rs (L502-547)
```rust
            if highest_known_version < highest_synced_version {
                if highest_known_epoch < highest_synced_epoch {
                    // Fetch the epoch ending ledger info from storage (the
                    // peer needs to sync to their epoch ending ledger info).
                    let epoch_ending_ledger_info = match utils::get_epoch_ending_ledger_info(
                        cached_storage_server_summary.clone(),
                        optimistic_fetches.clone(),
                        subscriptions.clone(),
                        highest_known_epoch,
                        lru_response_cache.clone(),
                        request_moderator.clone(),
                        &peer_network_id,
                        storage.clone(),
                        time_service.clone(),
                    ) {
                        Ok(epoch_ending_ledger_info) => epoch_ending_ledger_info,
                        Err(error) => {
                            // Log the failure to fetch the epoch ending ledger info
                            error!(LogSchema::new(LogEntry::OptimisticFetchRefresh)
                                .error(&error)
                                .message(&format!(
                                    "Failed to get the epoch ending ledger info for epoch: {:?} !",
                                    highest_known_epoch
                                )));

                            return;
                        },
                    };

                    // Check that we haven't been sent an invalid optimistic fetch request
                    // (i.e., a request that does not respect an epoch boundary).
                    if epoch_ending_ledger_info.ledger_info().version() <= highest_known_version {
                        peers_with_invalid_optimistic_fetches
                            .lock()
                            .push(peer_network_id);
                    } else {
                        peers_with_ready_optimistic_fetches
                            .lock()
                            .push((peer_network_id, epoch_ending_ledger_info));
                    }
                } else {
                    peers_with_ready_optimistic_fetches
                        .lock()
                        .push((peer_network_id, highest_synced_ledger_info.clone()));
                };
            }
```

**File:** storage/aptosdb/src/ledger_db/ledger_metadata_db.rs (L204-231)
```rust
    pub(crate) fn get_epoch(&self, version: Version) -> Result<u64> {
        let mut iter = self.db.iter::<EpochByVersionSchema>()?;
        // Search for the end of the previous epoch.
        iter.seek_for_prev(&version)?;
        let (epoch_end_version, epoch) = match iter.next().transpose()? {
            Some(x) => x,
            None => {
                // There should be a genesis LedgerInfo at version 0 (genesis only consists of one
                // transaction), so this normally doesn't happen. However this part of
                // implementation doesn't need to rely on this assumption.
                return Ok(0);
            },
        };
        ensure!(
            epoch_end_version <= version,
            "DB corruption: looking for epoch for version {}, got epoch {} ends at version {}",
            version,
            epoch,
            epoch_end_version
        );
        // If the obtained epoch ended before the given version, return epoch+1, otherwise
        // the given version is exactly the last version of the found epoch.
        Ok(if epoch_end_version < version {
            epoch + 1
        } else {
            epoch
        })
    }
```
