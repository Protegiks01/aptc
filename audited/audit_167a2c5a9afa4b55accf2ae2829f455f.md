# Audit Report

## Title
Malicious Peer Can Cause State Sync Denial of Service Through Unvalidated Advertised Ledger Info Version

## Summary
A malicious peer can advertise a storage summary containing a ledger info with an arbitrarily high version number (without valid signatures). This unvalidated version is used in subscription stream lag calculations, causing the stream to be incorrectly flagged as "beyond recovery" and terminating state synchronization, effectively denying service to the victim node.

## Finding Description

The vulnerability exists in the state sync subsystem's handling of peer-advertised storage summaries and subscription stream lag detection.

**Root Cause:**

When peers advertise their storage summaries, the `synced_ledger_info` field is aggregated into the global data summary without signature verification. [1](#0-0) 

The `LedgerInfoWithSignatures` has a `verify_signatures()` method that should validate signatures: [2](#0-1) 

However, this verification is never called when aggregating peer advertisements.

**Exploitation Path:**

1. Malicious peer connects to victim node and is polled for storage summary: [3](#0-2) 

2. The storage summary is stored without validation: [4](#0-3) 

3. When calculating global data summary, the malicious ledger info is included: [5](#0-4) 

4. The `highest_synced_ledger_info()` method returns the ledger info with the highest version (which would be the malicious one): [6](#0-5) 

5. In `check_subscription_stream_lag()`, this malicious version causes incorrect lag calculation: [7](#0-6) 

6. The huge calculated lag triggers the "beyond recovery" check: [8](#0-7) 

7. The stream fails with `SubscriptionStreamIsLagging` error, notifying the stream engine and clearing the request queue: [9](#0-8) 

**Security Guarantee Broken:**
This breaks the state sync liveness guarantee. A victim node cannot synchronize new transactions and states, making it unable to participate in the network.

## Impact Explanation

This vulnerability enables a **Denial of Service** attack on state synchronization, classified as **Medium Severity** per the Aptos bug bounty program:

- **State inconsistencies requiring intervention**: The victim node cannot sync and becomes stale, requiring manual intervention (reconnection to honest peers or restart)
- Does not directly cause fund loss, consensus safety violations, or permanent network damage
- Affects individual nodes rather than the entire network
- Aligns with "Validator node slowdowns" and "State inconsistencies requiring intervention" categories

The attack disrupts critical node functionality but does not compromise blockchain integrity or validator consensus.

## Likelihood Explanation

**Likelihood: HIGH**

- **Attack Requirements**: Attacker only needs to establish a peer connection to the victim node (standard P2P networking)
- **Complexity**: Trivial - simply send a malformed storage summary with `synced_ledger_info.version = u64::MAX`
- **Detection**: The peer scoring system may eventually penalize the malicious peer for other errors, but the damage occurs immediately
- **Mitigation Gaps**: No signature verification on advertised data, no sanity checks on advertised versions

The attack is realistic and easily reproducible against any full node accepting peer connections.

## Recommendation

**Add signature verification for peer-advertised ledger infos before including them in the global data summary:**

```rust
// In peer_states.rs, calculate_global_data_summary()
for summary in storage_summaries {
    // ...
    if let Some(synced_ledger_info) = summary.data_summary.synced_ledger_info.as_ref() {
        // Verify signatures before trusting this ledger info
        if let Some(validator_verifier) = get_validator_verifier_for_epoch(synced_ledger_info.ledger_info().epoch()) {
            match synced_ledger_info.verify_signatures(&validator_verifier) {
                Ok(_) => {
                    advertised_data.synced_ledger_infos.push(synced_ledger_info.clone());
                }
                Err(e) => {
                    warn!("Peer advertised ledger info with invalid signatures: {:?}", e);
                    // Penalize peer for malicious behavior
                }
            }
        }
    }
    // ...
}
```

**Additional safeguards:**

1. Implement version sanity checking - reject advertised versions that are unreasonably far ahead of local synced version
2. Penalize peers that advertise invalid ledger infos with the `Malicious` error type to trigger aggressive score reduction
3. Consider requiring advertised ledger infos to be within an acceptable range of the node's current synced state

## Proof of Concept

```rust
// Reproduction test for state-sync/data-streaming-service/src/data_stream.rs

#[cfg(test)]
mod malicious_peer_test {
    use super::*;
    use aptos_types::ledger_info::{LedgerInfo, LedgerInfoWithSignatures};
    use aptos_types::aggregate_signature::AggregateSignature;
    
    #[tokio::test]
    async fn test_malicious_advertised_version_causes_stream_failure() {
        // Setup: Create a data stream with normal configuration
        let (data_stream, _listener) = create_test_data_stream();
        
        // Attack: Create a malicious storage summary with extremely high version
        let malicious_version = u64::MAX - 1000;
        let malicious_ledger_info = LedgerInfo::new(
            BlockInfo::new(/* ... */),
            /* consensus_data_hash */ HashValue::zero(),
        );
        let malicious_ledger_info_with_sigs = LedgerInfoWithSignatures::new(
            malicious_ledger_info,
            AggregateSignature::empty(), // Invalid/empty signatures
        );
        
        // Create malicious global data summary
        let mut global_data_summary = GlobalDataSummary::empty();
        global_data_summary.advertised_data.synced_ledger_infos.push(
            malicious_ledger_info_with_sigs
        );
        
        // Normal subscription response with legitimate version
        let normal_response_version = 100_000u64;
        let response_payload = create_subscription_response(normal_response_version);
        
        // Trigger stream lag check
        let result = data_stream.check_subscription_stream_lag(
            &global_data_summary,
            &response_payload,
        );
        
        // Verify: Stream should detect massive lag
        // current_stream_lag = (u64::MAX - 1000) - 100_000 ≈ u64::MAX - 101_000
        
        // After max_subscription_stream_lag_secs, stream should fail
        tokio::time::sleep(Duration::from_secs(config.max_subscription_stream_lag_secs + 1)).await;
        
        let result = data_stream.check_subscription_stream_lag(
            &global_data_summary,
            &response_payload,
        );
        
        // Assert: Stream should be beyond recovery
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            aptos_data_client::error::Error::SubscriptionStreamIsLagging(_)
        ));
        
        // Verify: Request queue should be cleared
        assert!(data_stream.sent_data_requests.as_ref().unwrap().is_empty());
    }
}
```

**Note**: The above PoC demonstrates the vulnerability concept. A complete implementation would require mocking the peer advertisement flow and validator verifier setup, but the core attack vector is clear: unvalidated high version → incorrect lag calculation → stream failure.

### Citations

**File:** state-sync/aptos-data-client/src/peer_states.rs (L339-408)
```rust
    pub fn calculate_global_data_summary(&self) -> GlobalDataSummary {
        // Gather all storage summaries, but exclude peers that are ignored
        let storage_summaries: Vec<StorageServerSummary> = self
            .peer_to_state
            .iter()
            .filter_map(|peer_state| {
                peer_state
                    .value()
                    .get_storage_summary_if_not_ignored()
                    .cloned()
            })
            .collect();

        // If we have no peers, return an empty global summary
        if storage_summaries.is_empty() {
            return GlobalDataSummary::empty();
        }

        // Calculate the global data summary using the advertised peer data
        let mut advertised_data = AdvertisedData::empty();
        let mut max_epoch_chunk_sizes = vec![];
        let mut max_state_chunk_sizes = vec![];
        let mut max_transaction_chunk_sizes = vec![];
        let mut max_transaction_output_chunk_sizes = vec![];
        for summary in storage_summaries {
            // Collect aggregate data advertisements
            if let Some(epoch_ending_ledger_infos) = summary.data_summary.epoch_ending_ledger_infos
            {
                advertised_data
                    .epoch_ending_ledger_infos
                    .push(epoch_ending_ledger_infos);
            }
            if let Some(states) = summary.data_summary.states {
                advertised_data.states.push(states);
            }
            if let Some(synced_ledger_info) = summary.data_summary.synced_ledger_info.as_ref() {
                advertised_data
                    .synced_ledger_infos
                    .push(synced_ledger_info.clone());
            }
            if let Some(transactions) = summary.data_summary.transactions {
                advertised_data.transactions.push(transactions);
            }
            if let Some(transaction_outputs) = summary.data_summary.transaction_outputs {
                advertised_data
                    .transaction_outputs
                    .push(transaction_outputs);
            }

            // Collect preferred max chunk sizes
            max_epoch_chunk_sizes.push(summary.protocol_metadata.max_epoch_chunk_size);
            max_state_chunk_sizes.push(summary.protocol_metadata.max_state_chunk_size);
            max_transaction_chunk_sizes.push(summary.protocol_metadata.max_transaction_chunk_size);
            max_transaction_output_chunk_sizes
                .push(summary.protocol_metadata.max_transaction_output_chunk_size);
        }

        // Calculate optimal chunk sizes based on the advertised data
        let optimal_chunk_sizes = calculate_optimal_chunk_sizes(
            &self.data_client_config,
            max_epoch_chunk_sizes,
            max_state_chunk_sizes,
            max_transaction_chunk_sizes,
            max_transaction_output_chunk_sizes,
        );
        GlobalDataSummary {
            advertised_data,
            optimal_chunk_sizes,
        }
    }
```

**File:** types/src/ledger_info.rs (L303-308)
```rust
    pub fn verify_signatures(
        &self,
        validator: &ValidatorVerifier,
    ) -> ::std::result::Result<(), VerifyError> {
        validator.verify_multi_signatures(self.ledger_info(), &self.signatures)
    }
```

**File:** state-sync/aptos-data-client/src/poller.rs (L436-439)
```rust
        // Update the summary for the peer
        data_summary_poller
            .data_client
            .update_peer_storage_summary(peer, storage_summary);
```

**File:** state-sync/aptos-data-client/src/client.rs (L213-214)
```rust
    pub fn update_peer_storage_summary(&self, peer: PeerNetworkId, summary: StorageServerSummary) {
        self.peer_states.update_summary(peer, summary)
```

**File:** state-sync/aptos-data-client/src/global_summary.rs (L184-198)
```rust
    pub fn highest_synced_ledger_info(&self) -> Option<LedgerInfoWithSignatures> {
        let highest_synced_position = self
            .synced_ledger_infos
            .iter()
            .map(|ledger_info_with_sigs| ledger_info_with_sigs.ledger_info().version())
            .position_max();

        if let Some(highest_synced_position) = highest_synced_position {
            self.synced_ledger_infos
                .get(highest_synced_position)
                .cloned()
        } else {
            None
        }
    }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L586-618)
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

**File:** state-sync/data-streaming-service/src/data_stream.rs (L633-644)
```rust
    /// Notifies the stream engine that a new data request error was encountered
    fn notify_new_data_request_error(
        &mut self,
        client_request: &DataClientRequest,
        error: aptos_data_client::error::Error,
    ) -> Result<(), Error> {
        // Notify the stream engine and clear the requests queue
        self.stream_engine
            .notify_new_data_request_error(client_request, error)?;
        self.clear_sent_data_requests_queue();

        Ok(())
```
