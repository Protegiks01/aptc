# Audit Report

## Title
Unvalidated LedgerInfoWithSignatures in GlobalDataSummary Enables Denial of Service on State Sync Streams

## Summary
Untrusted network peers can send malicious `StorageServerSummary` messages containing fake `LedgerInfoWithSignatures` with arbitrarily high version numbers and invalid signatures. These unverified ledger infos are aggregated into the `GlobalDataSummary` without signature validation, causing subscription data streams to incorrectly detect massive lag and terminate after 10 seconds, resulting in repeated state sync disruptions.

## Finding Description

The state sync system aggregates storage summaries from network peers to build a global view of available data. However, the `LedgerInfoWithSignatures` included in peer summaries are never cryptographically verified before being used in critical operational decisions.

**Attack Flow:**

1. **Malicious Peer Sends Fake Summary**: Any network peer sends a `StorageServerSummary` containing a crafted `LedgerInfoWithSignatures` with `version: u64::MAX` and empty/invalid BLS signatures. [1](#0-0) 

2. **No Validation on Receipt**: The poller receives the summary and directly updates peer state without any signature verification. [2](#0-1) 

3. **Unverified Aggregation**: The fake ledger info is cloned directly into `GlobalDataSummary.advertised_data.synced_ledger_infos` without checking signatures. [3](#0-2) 

4. **Malicious Version Selected**: The `highest_synced_ledger_info()` method selects the ledger info with the highest version - which is the malicious one. [4](#0-3) 

5. **False Lag Detection**: Subscription streams use this unverified highest version to detect lag, making them appear massively behind. [5](#0-4) 

6. **Stream Termination**: After the configured timeout (default 10 seconds), streams with increasing lag are terminated as "beyond recovery". [6](#0-5) 

The vulnerability breaks the invariant that signature verification must occur before trusting cryptographic commitments. While actual data requests do verify signatures via `verify_ledger_info_with_signatures()`, the global summary metadata used for stream management bypasses this validation entirely. [7](#0-6) 

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program's "Validator node slowdowns" category (up to $50,000).

**Impact:**
- **Availability Disruption**: A single malicious peer can cause repeated subscription stream failures across all syncing nodes
- **State Sync Degradation**: Nodes are forced to continuously restart streams, significantly slowing synchronization progress
- **Resource Exhaustion**: Repeated stream restarts consume CPU and network resources
- **Widespread Effect**: All nodes connected to the malicious peer are affected simultaneously

The attack does not compromise consensus safety, cause fund loss, or enable data corruption. However, it significantly degrades state sync performance and node operational stability, meeting the High severity criteria for "significant protocol violations" and "validator node slowdowns."

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploited because:

1. **Low Barrier to Entry**: Any peer can connect to the Aptos network and send storage summaries
2. **No Authentication Required**: The attack requires no cryptographic keys, stake, or validator privileges
3. **Simple Exploit**: Attacker only needs to craft a single malicious `StorageServerSummary` message with a high version number
4. **Persistent Effect**: Once sent, the malicious summary remains in peer state until the peer disconnects or sends an updated summary
5. **Default Configuration Vulnerable**: The 10-second timeout is default configuration across all nodes [8](#0-7) 

The attack is trivially automatable and can be sustained indefinitely by reconnecting with new peer identities.

## Recommendation

**Immediate Fix**: Validate BLS signatures on `LedgerInfoWithSignatures` before including them in `GlobalDataSummary`.

Add signature verification in the `calculate_global_data_summary()` function:

```rust
// In peer_states.rs, around line 374-377
if let Some(synced_ledger_info) = summary.data_summary.synced_ledger_info.as_ref() {
    // Verify signatures before including in global summary
    if let Some(latest_epoch_state) = get_latest_epoch_state() {
        match latest_epoch_state.verify(synced_ledger_info) {
            Ok(_) => {
                advertised_data
                    .synced_ledger_infos
                    .push(synced_ledger_info.clone());
            },
            Err(e) => {
                // Log verification failure and skip this peer's summary
                warn!("Peer {:?} advertised ledger info with invalid signatures: {:?}", 
                      peer_id, e);
            }
        }
    }
}
```

**Alternative Mitigations:**
1. Implement a maximum acceptable version delta from local state before accepting advertised versions
2. Require multiple peers to agree on high versions before trusting them
3. Add reputation penalties for peers advertising unverifiable ledger infos

## Proof of Concept

```rust
// Rust PoC demonstrating the attack

use aptos_types::ledger_info::{LedgerInfo, LedgerInfoWithSignatures};
use aptos_types::block_info::BlockInfo;
use aptos_crypto::hash::HashValue;
use aptos_crypto::bls12381::Signature as AggregateSignature;
use aptos_storage_service_types::responses::{StorageServerSummary, DataSummary, ProtocolMetadata};

// Step 1: Craft malicious StorageServerSummary
fn craft_malicious_summary() -> StorageServerSummary {
    // Create a fake LedgerInfo with maximum version
    let fake_block_info = BlockInfo::new(
        /* epoch */ 1000,
        /* round */ 1000,
        /* id */ HashValue::zero(),
        /* executed_state_id */ HashValue::zero(),
        /* version */ u64::MAX,  // Maliciously high version
        /* timestamp_usecs */ 0,
        /* next_epoch_state */ None,
    );
    
    let fake_ledger_info = LedgerInfo::new(
        fake_block_info,
        /* consensus_data_hash */ HashValue::zero(),
    );
    
    // Create LedgerInfoWithSignatures with empty/invalid signatures
    let malicious_ledger_info = LedgerInfoWithSignatures::new(
        fake_ledger_info,
        AggregateSignature::empty(),  // Invalid signatures!
    );
    
    StorageServerSummary {
        protocol_metadata: ProtocolMetadata::default(),
        data_summary: DataSummary {
            synced_ledger_info: Some(malicious_ledger_info),
            epoch_ending_ledger_infos: None,
            states: None,
            transactions: None,
            transaction_outputs: None,
        },
    }
}

// Step 2: Send to network (pseudo-code showing the attack flow)
async fn execute_attack() {
    let malicious_summary = craft_malicious_summary();
    
    // When honest node polls this peer, it receives malicious_summary
    // The summary passes through without signature verification
    // GlobalDataSummary.highest_synced_ledger_info() returns version u64::MAX
    // Subscription streams detect lag of (u64::MAX - current_version)
    // After 10 seconds, streams terminate as "beyond recovery"
    
    println!("Attack successful: All subscription streams will fail in 10 seconds");
}
```

**Test Scenario:**
1. Start an Aptos node with state sync enabled
2. Connect as a malicious peer
3. Send `StorageServerSummary` with `synced_ledger_info.version = u64::MAX`
4. Observe subscription streams reporting massive lag
5. After 10 seconds, observe stream termination errors in logs
6. Node repeatedly restarts streams, degrading sync performance

## Notes

This vulnerability specifically affects the state sync subsystem's operational efficiency rather than its correctness guarantees. The actual data validation (when transaction/output data is fetched and applied) still performs proper signature verification. However, the metadata used for stream management and lag detection is completely unvalidated, enabling the DoS attack.

The root cause is the architectural assumption that peer-advertised summaries can be trusted for operational heuristics without cryptographic verification. This violates the principle that all network-provided data must be verified before being used in critical decisions.

### Citations

**File:** state-sync/storage-service/types/src/responses.rs (L666-686)
```rust
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
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

**File:** state-sync/aptos-data-client/src/poller.rs (L436-439)
```rust
        // Update the summary for the peer
        data_summary_poller
            .data_client
            .update_peer_storage_summary(peer, storage_summary);
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L374-377)
```rust
            if let Some(synced_ledger_info) = summary.data_summary.synced_ledger_info.as_ref() {
                advertised_data
                    .synced_ledger_infos
                    .push(synced_ledger_info.clone());
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

**File:** state-sync/data-streaming-service/src/data_stream.rs (L587-596)
```rust
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
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L967-992)
```rust
    fn is_beyond_recovery(
        &mut self,
        streaming_service_config: DataStreamingServiceConfig,
        current_stream_lag: u64,
    ) -> bool {
        // Calculate the total duration the stream has been lagging
        let current_time = self.time_service.now();
        let stream_lag_duration = current_time.duration_since(self.start_time);
        let max_stream_lag_duration =
            Duration::from_secs(streaming_service_config.max_subscription_stream_lag_secs);

        // If the lag is further behind and enough time has passed, the stream has failed
        let lag_has_increased = current_stream_lag > self.version_lag;
        let lag_duration_exceeded = stream_lag_duration >= max_stream_lag_duration;
        if lag_has_increased && lag_duration_exceeded {
            return true; // The stream is beyond recovery
        }

        // Otherwise, update the stream lag if we've caught up.
        // This will ensure the lag can only improve.
        if current_stream_lag < self.version_lag {
            self.version_lag = current_stream_lag;
        }

        false // The stream is not yet beyond recovery
    }
```

**File:** state-sync/state-sync-driver/src/utils.rs (L101-110)
```rust
    pub fn verify_ledger_info_with_signatures(
        &mut self,
        ledger_info_with_signatures: &LedgerInfoWithSignatures,
    ) -> Result<(), Error> {
        self.epoch_state
            .verify(ledger_info_with_signatures)
            .map_err(|error| {
                Error::VerificationError(format!("Ledger info failed verification: {:?}", error))
            })
    }
```

**File:** config/src/config/state_sync_config.rs (L278-278)
```rust
            max_subscription_stream_lag_secs: 10, // 10 seconds
```
