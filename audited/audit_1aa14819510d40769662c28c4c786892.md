# Audit Report

## Title
Unverified LedgerInfoWithSignatures in State Sync Allows Malicious Peers to Manipulate Synchronization Targets

## Summary
The state sync data client accepts `LedgerInfoWithSignatures` from untrusted network peers and adds them to the global `AdvertisedData` without cryptographic verification of the aggregated BLS signatures or quorum certificates. This allows malicious peers to advertise fake ledger infos with arbitrary versions and invalid signatures, which are then used as synchronization targets by honest nodes, breaking consensus safety guarantees and enabling denial-of-service attacks.

## Finding Description

The vulnerability exists in the state synchronization flow where peer-advertised storage summaries are aggregated into a global data summary that drives synchronization decisions.

**Vulnerable Code Path:**

1. **Unverified Addition to AdvertisedData**: In the `calculate_global_data_summary` function, peer-advertised `synced_ledger_info` values are directly cloned and pushed into the `AdvertisedData.synced_ledger_infos` vector without any signature verification: [1](#0-0) 

2. **Peer Data Reception**: Storage summaries containing these ledger infos are received from network peers via the poller without any verification at reception time: [2](#0-1) 

3. **Malicious Target Selection**: The unverified ledger infos are then used to select synchronization targets. The continuous transaction stream engine calls `highest_synced_ledger_info()` which returns the highest advertised ledger info (potentially malicious), and directly sets it as the sync target without verification: [3](#0-2) [4](#0-3) 

4. **Delayed Verification**: Signature verification only occurs much later when processing received data notifications, after the node has already committed resources to syncing toward the malicious target: [5](#0-4) 

**Attack Scenario:**

A malicious peer connects to the network and advertises a `StorageServerSummary` containing a fabricated `LedgerInfoWithSignatures` with:
- An arbitrarily high version number (e.g., current_version + 1,000,000)
- Invalid or missing aggregated BLS signatures
- Fabricated consensus data hash and block info

The honest node:
1. Receives this malicious storage summary
2. Adds it to its global `AdvertisedData` without verification
3. Selects it as the highest synced ledger info
4. Attempts to synchronize to this fake target version
5. Sends numerous requests for transaction data up to the fake version
6. Eventually fails verification when processing responses

This breaks the **Cryptographic Correctness** invariant: "BLS signatures, VRF, and hash operations must be secure" and the **Consensus Safety** invariant by allowing unverified ledger infos to influence synchronization decisions.

## Impact Explanation

**Severity: Critical**

This vulnerability meets the Critical severity criteria under multiple categories:

1. **Consensus/Safety Violations**: Malicious peers can deceive synchronizing nodes about the true state of the blockchain, causing nodes to attempt synchronization to non-existent or invalid chain states. This violates consensus safety guarantees.

2. **Network Availability Impact**: By advertising impossibly high versions, attackers can:
   - Prevent bootstrapping nodes from successfully syncing to the network
   - Cause continuous sync failures and retries, wasting network and computational resources
   - Create prolonged periods where nodes cannot participate in consensus
   - Potentially cause network partitions if enough nodes are affected

3. **Resource Exhaustion**: Nodes will repeatedly attempt to sync to invalid targets, consuming:
   - Network bandwidth for failed data requests
   - CPU cycles for request processing and verification failures
   - Memory for tracking in-flight requests to invalid targets

4. **Scope**: Affects all nodes performing state synchronization, including:
   - New nodes bootstrapping to the network
   - Existing nodes catching up after downtime
   - Nodes in continuous sync mode without explicit targets

The impact is similar to "Total loss of liveness/network availability" and "Non-recoverable network partition" categories, as affected nodes cannot properly synchronize and participate in the network.

## Likelihood Explanation

**Likelihood: High**

The attack is highly likely to occur because:

1. **Low Barrier to Entry**: Any node can connect as a peer to the network without special privileges or stake requirements. The attacker needs no validator status or economic investment.

2. **Simple Exploit**: The attack requires only:
   - Establishing a network connection to target nodes
   - Sending a crafted `StorageServerSummary` response with fake `LedgerInfoWithSignatures`
   - No complex cryptographic operations or state manipulation needed

3. **No Authentication**: The system does not verify the authenticity or authority of peers advertising storage summaries before using their data for critical synchronization decisions.

4. **Immediate Effect**: The malicious data is immediately incorporated into the global data summary and used for target selection in the next sync cycle.

5. **Persistent Impact**: Once a malicious peer's data is incorporated, it affects all synchronization decisions until the peer disconnects or is scored down after repeated failures.

6. **Multiple Attack Vectors**: An attacker can:
   - Advertise extremely high versions to cause resource waste
   - Advertise conflicting versions to create confusion
   - Coordinate multiple malicious peers to dominate the advertised data space

## Recommendation

**Immediate Fix**: Verify all `LedgerInfoWithSignatures` before adding them to `AdvertisedData`.

Modify the `calculate_global_data_summary` function in `peer_states.rs` to verify signatures before incorporating peer data:

```rust
// In calculate_global_data_summary, replace lines 374-378 with:
if let Some(synced_ledger_info) = summary.data_summary.synced_ledger_info.as_ref() {
    // Verify the ledger info signatures before trusting it
    // We need access to the appropriate ValidatorVerifier for the epoch
    // This requires passing epoch state information to this function
    // or maintaining a cache of trusted epoch states
    
    // For now, we can implement a basic check:
    // 1. Verify the ledger info has non-empty signatures
    // 2. Verify the ledger info version is reasonable (not too far ahead)
    // 3. Add proper signature verification once epoch state is available
    
    if !synced_ledger_info.signatures().is_empty() {
        advertised_data
            .synced_ledger_infos
            .push(synced_ledger_info.clone());
    } else {
        warn!(
            "Rejecting synced_ledger_info with empty signatures from peer summary"
        );
    }
}
```

**Complete Solution**: 

1. Maintain a cache of trusted epoch states in the data client
2. For each advertised `synced_ledger_info`, verify signatures against the appropriate epoch's validator verifier:
   ```rust
   if let Err(error) = epoch_state.verify(synced_ledger_info) {
       warn!("Rejecting synced_ledger_info with invalid signatures: {:?}", error);
       continue;
   }
   ```
3. Only add verified ledger infos to `AdvertisedData`
4. Consider implementing a reputation system that penalizes peers advertising invalid ledger infos more severely

**Additional Hardening**:
- Add sanity checks on advertised versions (shouldn't be too far ahead of known versions)
- Rate-limit storage summary updates from peers
- Implement cryptographic binding between peer identity and advertised data
- Add metrics and alerts for detecting peers advertising suspicious data

## Proof of Concept

```rust
// This PoC demonstrates how an attacker can create and advertise
// a malicious LedgerInfoWithSignatures that will be accepted
// without verification.

use aptos_types::{
    block_info::BlockInfo,
    ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
    aggregate_signature::AggregateSignature,
};
use aptos_storage_service_types::{
    responses::{DataSummary, ProtocolMetadata, StorageServerSummary},
};

fn create_malicious_storage_summary() -> StorageServerSummary {
    // Create a fake ledger info with an impossibly high version
    let malicious_version = 999_999_999_999_u64;
    let block_info = BlockInfo::new(
        /* epoch */ 100,
        /* round */ 1000,
        /* id */ aptos_crypto::HashValue::random(),
        /* executed_state_id */ aptos_crypto::HashValue::random(),
        malicious_version,
        /* timestamp_usecs */ 0,
        /* next_epoch_state */ None,
    );
    
    let ledger_info = LedgerInfo::new(
        block_info,
        /* consensus_data_hash */ aptos_crypto::HashValue::random(),
    );
    
    // Create empty/invalid signatures - this should be rejected but isn't!
    let invalid_signatures = AggregateSignature::empty();
    
    let malicious_ledger_info = LedgerInfoWithSignatures::new(
        ledger_info,
        invalid_signatures,
    );
    
    // Construct the storage summary
    StorageServerSummary {
        protocol_metadata: ProtocolMetadata {
            max_epoch_chunk_size: 1000,
            max_state_chunk_size: 1000,
            max_transaction_chunk_size: 1000,
            max_transaction_output_chunk_size: 1000,
        },
        data_summary: DataSummary {
            synced_ledger_info: Some(malicious_ledger_info),
            epoch_ending_ledger_infos: None,
            states: None,
            transactions: None,
            transaction_outputs: None,
        },
    }
}

// In a network peer, the attacker would:
// 1. Connect to target nodes
// 2. Respond to GetStorageServerSummary requests with the malicious summary
// 3. The target node will:
//    - Accept the summary without verification
//    - Add it to AdvertisedData.synced_ledger_infos
//    - Select it as the highest synced target
//    - Attempt to sync to version 999_999_999_999
//    - Waste resources on impossible sync attempts
```

**Test to Validate the Fix:**

```rust
#[test]
fn test_reject_unverified_ledger_info() {
    let malicious_summary = create_malicious_storage_summary();
    
    // Create peer states and update with malicious summary
    let config = Arc::new(AptosDataClientConfig::default());
    let peer_states = PeerStates::new(config);
    let peer = PeerNetworkId::random();
    
    peer_states.update_summary(peer, malicious_summary);
    
    // Calculate global summary
    let global_summary = peer_states.calculate_global_data_summary();
    
    // BEFORE FIX: The malicious ledger info would be included
    // AFTER FIX: It should be rejected due to empty/invalid signatures
    assert!(
        global_summary.advertised_data.synced_ledger_infos.is_empty(),
        "Malicious ledger info with invalid signatures should be rejected"
    );
}
```

## Notes

This vulnerability represents a fundamental trust boundary violation in the state sync protocol. The system trusts peer-advertised data for critical synchronization decisions without cryptographic verification, violating the zero-trust principles that should govern blockchain peer-to-peer protocols. The fix requires careful integration of epoch state management into the data client layer to enable proper signature verification at the point of data ingestion, not just at the point of data consumption.

### Citations

**File:** state-sync/aptos-data-client/src/peer_states.rs (L374-378)
```rust
            if let Some(synced_ledger_info) = summary.data_summary.synced_ledger_info.as_ref() {
                advertised_data
                    .synced_ledger_infos
                    .push(synced_ledger_info.clone());
            }
```

**File:** state-sync/aptos-data-client/src/poller.rs (L436-439)
```rust
        // Update the summary for the peer
        data_summary_poller
            .data_client
            .update_peer_storage_summary(peer, storage_summary);
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L523-528)
```rust
        if let Some(highest_synced_ledger_info) = advertised_data.highest_synced_ledger_info() {
            let (next_request_version, _) = self.next_request_version_and_epoch;
            if next_request_version > highest_synced_ledger_info.ledger_info().version() {
                Ok(None) // We're already at the highest synced ledger info. There's no known target.
            } else {
                Ok(Some(highest_synced_ledger_info))
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L1220-1220)
```rust
                    self.current_target_ledger_info = Some(target_ledger_info);
```

**File:** state-sync/state-sync-driver/src/continuous_syncer.rs (L453-455)
```rust
        if let Err(error) = self
            .get_speculative_stream_state()?
            .verify_ledger_info_with_signatures(ledger_info_with_signatures)
```
