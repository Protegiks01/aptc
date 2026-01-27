# Audit Report

## Title
Information Leakage of Latest Epoch Through Error Messages in Epoch Retrieval Validation

## Summary
The `check_epoch_ending_ledger_infos_request` function in the storage layer and the request moderator both leak information about the node's latest sealed epoch to any network peer through error messages. While the validation order (checking `start_epoch <= end_epoch` before `end_epoch <= latest_epoch`) correctly minimizes unnecessary information disclosure, error messages still reveal `latest_epoch - 1` to unauthorized peers who send requests with end epochs beyond the available range. [1](#0-0) 

## Finding Description

The validation logic performs checks in the correct order:

1. First checks if `start_epoch <= end_epoch` to reject malformed requests early
2. Then fetches `latest_epoch` from the database
3. Finally checks if `end_epoch <= latest_epoch` [2](#0-1) 

However, when the second validation fails, the error message explicitly includes `latest_epoch - 1` in the response. This error propagates through the storage service handler and is returned to the requesting peer as an `InternalError`. [3](#0-2) 

Additionally, the request moderator performs its own validation and includes the entire storage server summary (containing the `epoch_ending_ledger_infos` range) in error messages when requests cannot be satisfied: [4](#0-3) [5](#0-4) 

**Attack Path:**
1. An attacker sends a `GetEpochEndingLedgerInfos` request with `start_epoch = 0` and `end_epoch = u64::MAX`
2. The request passes the first validation (`0 <= u64::MAX`)
3. Either the moderator rejects it (revealing the epoch range in the storage summary) or it reaches the storage layer
4. The storage layer check fails, returning an error: "Unable to provide epoch change ledger info for still open epoch. asked upper bound: {end_epoch}, last sealed epoch: {latest_epoch - 1}"
5. The attacker learns the current `latest_epoch` value

The validation order is actually CORRECT (checking range validity before checking against latest_epoch minimizes leakage), but the error messages themselves leak the information.

## Impact Explanation

This is a **Low Severity** vulnerability per the Aptos bug bounty categories, specifically falling under "Minor information leaks". The impact is limited because:

- Epoch information is generally public blockchain state accessible through normal queries
- No impact on consensus safety, funds security, or system availability
- The information leaked is eventually public once blocks are committed
- Cannot be used to directly attack consensus or steal funds

However, it does provide reconnaissance value to attackers:
- Identifying which nodes are fully synced vs lagging behind
- Timing analysis for epoch transitions
- Mapping network topology based on node sync status

## Likelihood Explanation

**Likelihood: HIGH** - This vulnerability is trivially exploitable:
- Any peer can connect to the storage service and send requests
- No authentication or authorization required beyond network connectivity
- Simple request with well-formed parameters (start_epoch <= end_epoch but end_epoch > latest)
- Deterministic response revealing the epoch information
- Can be automated to continuously monitor epoch progression across multiple nodes

## Recommendation

Remove sensitive epoch information from error messages returned to untrusted peers. Instead of revealing the exact `latest_epoch`, return a generic error message:

```rust
fn check_epoch_ending_ledger_infos_request(
    &self,
    start_epoch: u64,
    end_epoch: u64,
) -> Result<()> {
    ensure!(
        start_epoch <= end_epoch,
        "Bad epoch range [{}, {})",
        start_epoch,
        end_epoch,
    );
    
    let latest_epoch = self
        .ledger_db
        .metadata_db()
        .get_latest_ledger_info()?
        .ledger_info()
        .next_block_epoch();
    ensure!(
        end_epoch <= latest_epoch,
        "Unable to provide epoch change ledger info for the requested range"
        // Do NOT include latest_epoch or latest_epoch - 1 in the error
    );
    Ok(())
}
```

Similarly, the moderator should avoid including the complete storage summary in error messages sent to peers. Instead, return a generic "request cannot be satisfied" message without revealing the available data ranges.

## Proof of Concept

```rust
// Proof of concept demonstrating epoch information leakage
// This would be executed by a malicious peer connecting to a storage service node

use aptos_storage_service_types::{
    requests::{DataRequest, EpochEndingLedgerInfoRequest, StorageServiceRequest},
};

async fn exploit_epoch_leakage() {
    // Connect to target node's storage service
    let storage_client = connect_to_storage_service("target_node_address").await;
    
    // Send request with valid range but impossibly high end_epoch
    let request = StorageServiceRequest {
        data_request: DataRequest::GetEpochEndingLedgerInfos(
            EpochEndingLedgerInfoRequest {
                start_epoch: 0,
                expected_end_epoch: u64::MAX, // Intentionally beyond available epochs
            }
        ),
        use_compression: false,
    };
    
    // Send request and observe error response
    let response = storage_client.send_request(request).await;
    
    // Error message will contain:
    // "Unable to provide epoch change ledger info for still open epoch. 
    //  asked upper bound: 18446744073709551615, last sealed epoch: {LEAKED_EPOCH}"
    //
    // Or from moderator:
    // "The given request cannot be satisfied. Request: {...}, 
    //  storage summary: DataSummary { 
    //    epoch_ending_ledger_infos: Some(CompleteDataRange { 
    //      lowest: 0, highest: {LEAKED_EPOCH} 
    //    }), ... 
    //  }"
    
    if let Err(error) = response {
        // Parse error message to extract latest_epoch
        let leaked_epoch = extract_epoch_from_error(&error);
        println!("Successfully leaked latest epoch: {}", leaked_epoch);
    }
}
```

## Notes

The validation order itself (checking `start_epoch <= end_epoch` BEFORE `end_epoch <= latest_epoch`) is actually the CORRECT approach and minimizes information leakage by filtering out obviously malformed requests before querying the database. The vulnerability lies not in the validation order, but in the error messages that reveal internal state information to untrusted peers.

While epoch information is generally considered public in blockchain systems, revealing it via error messages before it's officially committed provides reconnaissance value to attackers without requiring them to process blockchain state or wait for official announcements.

### Citations

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L1007-1034)
```rust
    fn check_epoch_ending_ledger_infos_request(
        &self,
        start_epoch: u64,
        end_epoch: u64,
    ) -> Result<()> {
        ensure!(
            start_epoch <= end_epoch,
            "Bad epoch range [{}, {})",
            start_epoch,
            end_epoch,
        );
        // Note that the latest epoch can be the same with the current epoch (in most cases), or
        // current_epoch + 1 (when the latest ledger_info carries next validator set)

        let latest_epoch = self
            .ledger_db
            .metadata_db()
            .get_latest_ledger_info()?
            .ledger_info()
            .next_block_epoch();
        ensure!(
            end_epoch <= latest_epoch,
            "Unable to provide epoch change ledger info for still open epoch. asked upper bound: {}, last sealed epoch: {}",
            end_epoch,
            latest_epoch - 1,  // okay to -1 because genesis LedgerInfo has .next_block_epoch() == 1
        );
        Ok(())
    }
```

**File:** state-sync/storage-service/server/src/handler.rs (L196-202)
```rust
        process_result.map_err(|error| match error {
            Error::InvalidRequest(error) => StorageServiceError::InvalidRequest(error),
            Error::TooManyInvalidRequests(error) => {
                StorageServiceError::TooManyInvalidRequests(error)
            },
            error => StorageServiceError::InternalError(error.to_string()),
        })
```

**File:** state-sync/storage-service/server/src/moderator.rs (L181-184)
```rust
                return Err(Error::InvalidRequest(format!(
                    "The given request cannot be satisfied. Request: {:?}, storage summary: {:?}",
                    request, storage_server_summary
                )));
```

**File:** state-sync/storage-service/types/src/responses.rs (L667-686)
```rust
pub struct DataSummary {
    /// The ledger info corresponding to the highest synced version in storage.
    /// This indicates the highest version and epoch that storage can prove.
    pub synced_ledger_info: Option<LedgerInfoWithSignatures>,
    /// The range of epoch ending ledger infos in storage, e.g., if the range
    /// is [(X,Y)], it means all epoch ending ledger infos for epochs X->Y
    /// (inclusive) are held.
    pub epoch_ending_ledger_infos: Option<CompleteDataRange<Epoch>>,
    /// The range of states held in storage, e.g., if the range is
    /// [(X,Y)], it means all states are held for every version X->Y
    /// (inclusive).
    pub states: Option<CompleteDataRange<Version>>,
    /// The range of transactions held in storage, e.g., if the range is
    /// [(X,Y)], it means all transactions for versions X->Y (inclusive) are held.
    pub transactions: Option<CompleteDataRange<Version>>,
    /// The range of transaction outputs held in storage, e.g., if the range
    /// is [(X,Y)], it means all transaction outputs for versions X->Y
    /// (inclusive) are held.
    pub transaction_outputs: Option<CompleteDataRange<Version>>,
}
```
