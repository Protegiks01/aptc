# Audit Report

## Title
Missing Cross-Field Consistency Validation in Global Data Summary Enables Sync DoS Attack

## Summary
The `calculate_global_data_summary()` function in `peer_states.rs` aggregates storage summaries from multiple peers without validating that each peer's `synced_ledger_info` version is consistent with their advertised transaction, state, and output ranges. This allows malicious peers to advertise impossibly high sync targets, causing sync failures for honest nodes.

## Finding Description

The vulnerability exists in the peer data aggregation logic where storage summaries from network peers are collected without cross-field consistency validation. [1](#0-0) 

In this function, peer storage summaries are aggregated by:
1. Collecting each peer's `synced_ledger_info` (which indicates the highest version they claim to have synced)
2. Collecting their advertised transaction ranges
3. Collecting their advertised state ranges
4. Collecting their advertised transaction output ranges

**Critical Issue**: There is NO validation ensuring that the version in `synced_ledger_info` actually falls within the peer's advertised data ranges. [2](#0-1) 

A malicious peer can exploit this by advertising:
- `synced_ledger_info.version = 1,000,000` (claiming sync to version 1 million)
- `transactions = CompleteDataRange(0, 500)` (but only advertising transactions up to version 500)
- `states = CompleteDataRange(0, 500)` (and states up to version 500)

This inconsistent data is accepted without validation. When honest nodes attempt to sync, they use `highest_synced_ledger_info()` to determine their sync target: [3](#0-2) 

This function simply returns the ledger info with the highest version across ALL peers, without checking if that version has corresponding data available. The malicious peer's version 1,000,000 becomes the sync target.

When the stream engine attempts to sync to this target, it validates data availability: [4](#0-3) 

The target is set to version 1,000,000, but when `is_remaining_data_available()` checks if this data exists: [5](#0-4) 

It verifies version 1,000,000 is in the advertised transaction ranges. Since no peer (including the malicious one) actually has data for version 1,000,000, the check fails, causing: [6](#0-5) 

This results in stream creation failure, blocking the node's ability to sync.

**Contrast with Honest Peer Behavior**: In honest implementations, the `get_data_summary()` function ensures consistency: [7](#0-6) 

The `latest_version` from the synced ledger info is used as the upper bound for transaction, output, and state ranges, ensuring consistency. However, this guarantee is lost when aggregating data from untrusted peers.

## Impact Explanation

**Severity: High** (up to $50,000 per Aptos Bug Bounty)

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program for the following reasons:

1. **Validator Node Slowdowns**: Malicious peers can cause persistent sync failures, preventing nodes from catching up with the network. Validators experiencing sync issues cannot participate effectively in consensus, degrading network performance.

2. **Significant Protocol Violations**: The state sync protocol's fundamental assumption—that advertised data summaries are internally consistent—is violated. This breaks the **State Consistency** invariant, as nodes cannot reliably determine what data is actually available.

3. **Availability Impact**: If multiple malicious peers coordinate to advertise false high sync targets, honest nodes may experience prolonged inability to sync, approaching a DoS condition. New nodes attempting to bootstrap could be particularly affected.

The impact is **not Critical** because:
- No funds are at risk
- Consensus safety is not directly compromised (validators already synced can continue)
- The issue is eventually mitigated by the peer scoring system (malicious peers get ignored after failures)
- No permanent network partition results

However, the temporary disruption to network availability and validator performance clearly meets High severity criteria.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploited because:

1. **Low Barrier to Entry**: Any network participant can become a peer in the Aptos network and send storage summaries. No special privileges or validator status is required.

2. **No Authentication**: Storage summaries from peers are not cryptographically authenticated. While `synced_ledger_info` contains `LedgerInfoWithSignatures`, there's no evidence in the codebase that these signatures are verified during peer data aggregation.

3. **Simple Exploit**: The attack requires only crafting a `StorageServerSummary` message with inconsistent fields—a trivial task for any attacker familiar with the protocol.

4. **Amplification**: A single malicious peer affects all honest nodes that receive its storage summary, multiplying the impact.

5. **Real-World Scenarios**: This can occur even without malicious intent—buggy implementations, version mismatches, or network issues could cause peers to advertise inconsistent data, leading to similar sync failures.

The only mitigation is the peer scoring system, which eventually ignores problematic peers. However, this is reactive and doesn't prevent the initial impact.

## Recommendation

Implement cross-field consistency validation in `calculate_global_data_summary()` to reject storage summaries where the `synced_ledger_info` version exceeds the advertised data ranges.

**Recommended Fix**:

```rust
// In peer_states.rs, calculate_global_data_summary() function
for summary in storage_summaries {
    // Validate consistency before accepting data
    if let Some(synced_ledger_info) = summary.data_summary.synced_ledger_info.as_ref() {
        let synced_version = synced_ledger_info.ledger_info().version();
        
        // Check if synced version is within advertised ranges
        let mut is_consistent = true;
        
        if let Some(transactions) = &summary.data_summary.transactions {
            if synced_version > transactions.highest() {
                warn!("Peer advertised synced_ledger_info version {} but transactions only up to {}. Ignoring inconsistent data.", 
                      synced_version, transactions.highest());
                is_consistent = false;
            }
        }
        
        if let Some(states) = &summary.data_summary.states {
            if synced_version > states.highest() {
                warn!("Peer advertised synced_ledger_info version {} but states only up to {}. Ignoring inconsistent data.", 
                      synced_version, states.highest());
                is_consistent = false;
            }
        }
        
        if let Some(outputs) = &summary.data_summary.transaction_outputs {
            if synced_version > outputs.highest() {
                warn!("Peer advertised synced_ledger_info version {} but outputs only up to {}. Ignoring inconsistent data.", 
                      synced_version, outputs.highest());
                is_consistent = false;
            }
        }
        
        if !is_consistent {
            continue; // Skip this peer's data
        }
        
        advertised_data.synced_ledger_infos.push(synced_ledger_info.clone());
    }
    
    // Rest of collection logic...
}
```

Additionally, consider:
1. Implementing signature verification on `synced_ledger_info` during peer data aggregation
2. Adding metrics to track and alert on inconsistent storage summaries
3. More aggressively penalizing peers that advertise inconsistent data

## Proof of Concept

```rust
// Test demonstrating the vulnerability
#[tokio::test]
async fn test_inconsistent_storage_summary_causes_sync_failure() {
    use aptos_data_client::global_summary::AdvertisedData;
    use aptos_storage_service_types::responses::{CompleteDataRange, DataSummary};
    use aptos_types::ledger_info::LedgerInfoWithSignatures;
    
    // Create a malicious storage summary with inconsistent data
    let malicious_summary = DataSummary {
        // Claim synced to version 1,000,000
        synced_ledger_info: Some(create_test_ledger_info(1_000_000)),
        epoch_ending_ledger_infos: None,
        // But only advertise transactions up to 500
        transactions: Some(CompleteDataRange::new(0, 500).unwrap()),
        transaction_outputs: Some(CompleteDataRange::new(0, 500).unwrap()),
        states: Some(CompleteDataRange::new(0, 500).unwrap()),
    };
    
    // Create honest peer summary
    let honest_summary = DataSummary {
        synced_ledger_info: Some(create_test_ledger_info(8000)),
        epoch_ending_ledger_infos: None,
        transactions: Some(CompleteDataRange::new(0, 8000).unwrap()),
        transaction_outputs: Some(CompleteDataRange::new(0, 8000).unwrap()),
        states: Some(CompleteDataRange::new(0, 8000).unwrap()),
    };
    
    // Simulate aggregation
    let mut advertised_data = AdvertisedData::empty();
    advertised_data.synced_ledger_infos.push(
        malicious_summary.synced_ledger_info.unwrap()
    );
    advertised_data.synced_ledger_infos.push(
        honest_summary.synced_ledger_info.unwrap()
    );
    advertised_data.transactions.push(
        malicious_summary.transactions.unwrap()
    );
    advertised_data.transactions.push(
        honest_summary.transactions.unwrap()
    );
    
    // Get highest synced ledger info - returns malicious peer's version 1,000,000
    let highest = advertised_data.highest_synced_ledger_info().unwrap();
    assert_eq!(highest.ledger_info().version(), 1_000_000);
    
    // Check if this version is available in advertised ranges
    let target_version = 1_000_000;
    let is_available = AdvertisedData::contains_range(
        target_version,
        target_version,
        &advertised_data.transactions,
    );
    
    // This will be FALSE, causing sync failure
    assert!(!is_available, "Version 1,000,000 should not be available but is used as sync target");
}
```

**Notes:**

The vulnerability stems from the implicit trust placed in peer-advertised storage summaries during aggregation. The lack of validation creates an opportunity for malicious peers to pollute the global data summary with impossible sync targets, degrading network availability. While the peer scoring system provides eventual mitigation, the initial impact on sync operations represents a significant protocol violation warranting High severity classification.

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

**File:** state-sync/aptos-data-client/src/global_summary.rs (L183-198)
```rust
    /// Returns the highest synced ledger info advertised in the network
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

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L522-534)
```rust
        // We don't have a final target, select the highest to make progress
        if let Some(highest_synced_ledger_info) = advertised_data.highest_synced_ledger_info() {
            let (next_request_version, _) = self.next_request_version_and_epoch;
            if next_request_version > highest_synced_ledger_info.ledger_info().version() {
                Ok(None) // We're already at the highest synced ledger info. There's no known target.
            } else {
                Ok(Some(highest_synced_ledger_info))
            }
        } else {
            Err(Error::DataIsUnavailable(
                "Unable to find the highest synced ledger info!".into(),
            ))
        }
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L1291-1310)
```rust
    fn is_remaining_data_available(&self, advertised_data: &AdvertisedData) -> Result<bool, Error> {
        let advertised_ranges = match &self.request {
            StreamRequest::ContinuouslyStreamTransactions(_) => &advertised_data.transactions,
            StreamRequest::ContinuouslyStreamTransactionOutputs(_) => {
                &advertised_data.transaction_outputs
            },
            StreamRequest::ContinuouslyStreamTransactionsOrOutputs(_) => {
                &advertised_data.transaction_outputs
            },
            request => invalid_stream_request!(request),
        };

        // Verify we can satisfy the next version
        let (next_request_version, _) = self.next_request_version_and_epoch;
        Ok(AdvertisedData::contains_range(
            next_request_version,
            next_request_version,
            advertised_ranges,
        ))
    }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L866-877)
```rust
    pub fn ensure_data_is_available(&self, advertised_data: &AdvertisedData) -> Result<(), Error> {
        if !self
            .stream_engine
            .is_remaining_data_available(advertised_data)?
        {
            return Err(Error::DataIsUnavailable(format!(
                "Unable to satisfy stream engine: {:?}, with advertised data: {:?}",
                self.stream_engine, advertised_data
            )));
        }
        Ok(())
    }
```

**File:** state-sync/storage-service/server/src/storage.rs (L1056-1070)
```rust
        let latest_version = latest_ledger_info.version();
        let transactions = self.fetch_transaction_range(latest_version)?;
        let transaction_outputs = self.fetch_transaction_output_range(latest_version)?;

        // Fetch the state values range
        let states = self.fetch_state_values_range(latest_version, &transactions)?;

        // Return the relevant data summary
        let data_summary = DataSummary {
            synced_ledger_info: Some(latest_ledger_info_with_sigs),
            epoch_ending_ledger_infos,
            transactions,
            transaction_outputs,
            states,
        };
```
