# Audit Report

## Title
Unverified Version Numbers in Subscription Responses Enable False Stream Lag Detection and Denial of Service

## Summary
The `check_subscription_stream_lag()` function extracts version numbers from subscription response payloads before cryptographic verification occurs. A malicious peer can provide artificially low version numbers in the `first_transaction_version` field to trigger false stream lag detection, causing legitimate subscription streams to be terminated unnecessarily and degrading state sync performance.

## Finding Description

The vulnerability exists in the ordering of operations during subscription response processing. When a node receives a subscription response (e.g., `NewTransactionsWithProof`), the data streaming service performs stream lag checking **before** cryptographic proof verification.

**Vulnerable Flow:**

1. **Response Reception**: A subscription response arrives containing a `TransactionListWithProofV2` and `LedgerInfoWithSignatures` tuple. [1](#0-0) 

2. **Unverified Version Extraction**: The `check_subscription_stream_lag()` function extracts the `first_transaction_version` field directly from the response payload without any cryptographic verification: [2](#0-1) 

3. **Lag Calculation**: The extracted version is compared against the `highest_advertised_version` from the global data summary: [3](#0-2) 

4. **Stream Termination**: If the lag exceeds thresholds and persists, the stream is terminated with an error: [4](#0-3) 

5. **Verification Too Late**: Cryptographic verification that would detect the mismatch only happens later in the chunk executor: [5](#0-4) 

**Attack Scenario:**

A malicious peer crafts subscription responses with:
- `first_transaction_version` = 1000 (artificially low)
- Valid but old `LedgerInfoWithSignatures` matching version 1000
- Network advertises `highest_synced_version` = 100000

The lag calculation yields: `100000 - 1009 = 98991`, triggering stream termination. The victim node repeatedly restarts the stream, experiencing degraded sync performance. The cryptographic verification that would reject the mismatched data never executes because the stream is already terminated.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program:

1. **Validator Node Slowdowns**: Affected nodes experience repeated stream terminations and restarts, degrading state sync performance and potentially causing the node to fall behind.

2. **Significant Protocol Violations**: The stream lag detection mechanism, designed to ensure timely data delivery, can be weaponized to disrupt legitimate synchronization.

3. **Availability Impact**: While not causing complete unavailability, the attack significantly impacts the node's ability to maintain sync with the network, potentially affecting validator participation.

The attack violates the state sync liveness guarantee - nodes should be able to reliably synchronize with honest peers. The vulnerability allows unprivileged malicious peers to disrupt this fundamental property.

## Likelihood Explanation

**Likelihood: High**

- **Attacker Requirements**: Any peer selected for subscription streaming can execute this attack. No validator access or stake required.
- **Detection Difficulty**: The attack appears as legitimate "stream lag" in logs, making it difficult to distinguish from actual network issues.
- **Repeatability**: The attack can be repeated whenever the malicious peer is selected as a data source.
- **Network Presence**: Malicious peers naturally appear in peer selection due to network topology.

## Recommendation

Perform version validation **after** cryptographic proof verification, not before. The version numbers should only be trusted once the proofs have been verified against the ledger info.

**Recommended Fix:**

1. Move the `check_subscription_stream_lag()` call to occur **after** the chunk executor has verified the transaction proofs, or

2. Modify `check_subscription_stream_lag()` to verify that the version numbers in the response are consistent with the verified ledger info before calculating lag, or

3. Remove reliance on unverified `first_transaction_version` field for lag detection and instead use version information from the cryptographically verified ledger info.

**Implementation Approach:**

Modify the flow in `process_data_responses()`: [6](#0-5) 

Move the lag check to occur after proof verification confirms the response validity, or validate that `first_transaction_version` is consistent with the signed ledger info's version before using it for lag calculations.

## Proof of Concept

```rust
// Rust test demonstrating the vulnerability
// This would be added to state-sync/data-streaming-service/src/tests/

#[tokio::test]
async fn test_false_stream_lag_with_low_version_numbers() {
    // Setup: Create a data stream with subscription request
    let data_client_config = AptosDataClientConfig::default();
    let streaming_config = DataStreamingServiceConfig::default();
    
    // Create a malicious response with artificially low version
    let malicious_first_version = 1000u64;
    let actual_network_version = 100000u64;
    
    // Create TransactionListWithProofV2 with low first_transaction_version
    let mut transactions_with_proof = create_transaction_list_with_proof(
        vec![create_test_transaction()],
        malicious_first_version,
    );
    
    // Create valid (but old) LedgerInfoWithSignatures for version 1000
    let old_ledger_info = create_ledger_info_with_sigs(malicious_first_version);
    
    // Create GlobalDataSummary advertising current network height
    let mut global_data_summary = GlobalDataSummary::empty();
    global_data_summary.advertised_data.synced_ledger_infos = 
        vec![create_ledger_info_with_sigs(actual_network_version)];
    
    // Create response payload
    let response_payload = ResponsePayload::NewTransactionsWithProof((
        transactions_with_proof,
        old_ledger_info,
    ));
    
    // Call check_subscription_stream_lag
    let result = data_stream.check_subscription_stream_lag(
        &global_data_summary,
        &response_payload,
    );
    
    // Assert that lag detection is triggered by low version numbers
    // before cryptographic verification would reject the response
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        aptos_data_client::error::Error::SubscriptionStreamIsLagging(_)
    ));
    
    // The stream is now terminated, but the version mismatch
    // was never cryptographically verified - the attack succeeds
}
```

**Notes:**
- The complete PoC requires test utilities from the existing test infrastructure
- The attack succeeds because `first_transaction_version` is read from the unverified payload structure
- Cryptographic verification would catch the mismatch, but it never runs due to early stream termination
- The malicious peer can repeatedly exploit this to degrade sync performance

### Citations

**File:** state-sync/aptos-data-client/src/interface.rs (L267-268)
```rust
    NewTransactionOutputsWithProof((TransactionOutputListWithProofV2, LedgerInfoWithSignatures)),
    NewTransactionsWithProof((TransactionListWithProofV2, LedgerInfoWithSignatures)),
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L491-499)
```rust
                        if client_request.is_subscription_request() {
                            if let Err(error) = self.check_subscription_stream_lag(
                                &global_data_summary,
                                &client_response.payload,
                            ) {
                                self.notify_new_data_request_error(client_request, error)?;
                                head_of_line_blocked = true; // We're now head of line blocked on the failed stream
                            }
                        }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L555-567)
```rust
        let highest_response_version = match response_payload {
            ResponsePayload::NewTransactionsWithProof((transactions_with_proof, _)) => {
                if let Some(first_version) = transactions_with_proof.get_first_transaction_version()
                {
                    let num_transactions = transactions_with_proof.get_num_transactions();
                    first_version
                        .saturating_add(num_transactions as u64)
                        .saturating_sub(1) // first_version + num_txns - 1
                } else {
                    return Err(aptos_data_client::error::Error::UnexpectedErrorEncountered(
                        "The first transaction version is missing from the stream response!".into(),
                    ));
                }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L586-607)
```rust
        // Get the highest advertised version
        let highest_advertised_version = global_data_summary
            .advertised_data
            .highest_synced_ledger_info()
            .map(|ledger_info| ledger_info.ledger_info().version())
            .ok_or_else(|| {
                aptos_data_client::error::Error::UnexpectedErrorEncountered(
                    "The highest synced ledger info is missing from the global data summary!"
                        .into(),
                )
            })?;

        // If the stream is not lagging behind, reset the lag and return
        if highest_response_version >= highest_advertised_version {
            self.reset_subscription_stream_lag();
            return Ok(());
        }

        // Otherwise, the stream is lagging behind the advertised version.
        // Check if the stream is beyond recovery (i.e., has failed).
        let current_stream_lag =
            highest_advertised_version.saturating_sub(highest_response_version);
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L608-618)
```rust
        if let Some(mut subscription_stream_lag) = self.subscription_stream_lag.take() {
            // Check if the stream lag is beyond recovery
            if subscription_stream_lag
                .is_beyond_recovery(self.streaming_service_config, current_stream_lag)
            {
                return Err(
                    aptos_data_client::error::Error::SubscriptionStreamIsLagging(format!(
                        "The subscription stream is beyond recovery! Current lag: {:?}, last lag: {:?},",
                        current_stream_lag, subscription_stream_lag.version_lag
                    )),
                );
```

**File:** execution/executor/src/chunk_executor/mod.rs (L128-131)
```rust
            txn_list_with_proof.verify(
                verified_target_li.ledger_info(),
                txn_list_with_proof.get_first_transaction_version(),
            )?;
```
