# Audit Report

## Title
Unverified Synced Ledger Info Allows Malicious Peers to Manipulate State Sync Peer Selection

## Summary
Malicious peers can provide fake `synced_ledger_info` with invalid signatures that pass `can_service()` checks in the state sync data client, causing validator node slowdowns during bootstrapping and continuous syncing through resource exhaustion and peer selection manipulation.

## Finding Description

The `DataSummary` struct's `synced_ledger_info` field is used for peer selection decisions without signature verification, violating the security principle that cryptographically signed data must be verified before trust. [1](#0-0) 

When a peer sends a `StorageServerSummary`, it is received and stored without any validation of the `synced_ledger_info` signatures: [2](#0-1) [3](#0-2) 

The stored summary is then used for peer selection via `can_service()` checks, which only validate version numbers and timestamps, NOT signatures: [4](#0-3) [5](#0-4) [6](#0-5) 

The peer selection logic filters peers based on these unverified checks: [7](#0-6) 

**Attack Path:**
1. Malicious peer crafts `LedgerInfoWithSignatures` with arbitrarily high version (e.g., 999,999,999) and recent timestamp, but with invalid/empty BLS signatures
2. Honest node polls peer and stores the fake summary without verification
3. Fake `synced_ledger_info` passes `can_service()` checks (only version and timestamp are checked)
4. Malicious peer gets selected for data requests
5. When actual data is requested, proof verification fails, but only after wasting resources
6. Peer score degrades by 0.8x per failure, reaching ignore threshold after ~4 requests
7. Malicious peer disconnects and reconnects to reset score to starting value (50.0), repeating the attack [8](#0-7) 

While proof verification eventually catches invalid data, this occurs AFTER peer selection and network communication: [9](#0-8) 

## Impact Explanation

This qualifies as **High Severity** under "Validator node slowdowns" per the Aptos bug bounty criteria. 

During bootstrapping or continuous syncing, validators are particularly vulnerable. An attacker controlling multiple peer identities (Sybil attack) can:
- Cause significant resource exhaustion through repeated failed verification attempts
- Manipulate peer selection to crowd out legitimate peers
- Force continuous stream resets and retry cycles
- Each malicious peer wastes ~4 request/response cycles before being ignored (starting score 50.0, malicious multiplier 0.8x, ignore threshold 25.0)
- With 10+ malicious peers cycling through disconnect/reconnect, a validator can be severely slowed

The impact is amplified during:
- Initial bootstrapping when the node has no prior peer reputation information
- Network partitions when few legitimate peers are available
- Epoch transitions when peers need to re-synchronize

## Likelihood Explanation

**Likelihood: High**

The attack is trivially easy to execute:
- No special privileges required - any network peer can participate
- Crafting fake `LedgerInfoWithSignatures` requires only setting arbitrary version/timestamp values
- No cryptographic work needed (invalid signatures are not checked)
- Sybil attacks are feasible in permissionless P2P networks
- The disconnect/reconnect pattern to reset scores is simple to automate

The peer scoring mitigation is insufficient because:
- Score resets on disconnect/reconnect enable persistent attacks
- Multiple malicious identities can sustain the attack indefinitely
- The ignore threshold (25.0) is reached only after ~4 failed attempts per peer

## Recommendation

Add signature verification when storing peer summaries. The `synced_ledger_info` should be verified against the appropriate epoch state before being trusted for any decision-making.

**Option 1: Verify on Receipt**
Verify signatures when `update_summary()` is called, requiring access to `EpochState`:

```rust
// In peer_states.rs
pub fn update_summary(
    &self, 
    peer: PeerNetworkId, 
    storage_summary: StorageServerSummary,
    epoch_state: &EpochState,
) -> Result<(), Error> {
    // Verify synced_ledger_info signatures if present
    if let Some(synced_ledger_info) = &storage_summary.data_summary.synced_ledger_info {
        epoch_state.verify(synced_ledger_info)
            .map_err(|e| Error::InvalidPeerSummary(format!("Invalid synced_ledger_info from peer {:?}: {:?}", peer, e)))?;
    }
    
    self.peer_to_state
        .entry(peer)
        .or_insert(PeerState::new(self.data_client_config.clone()))
        .update_storage_summary(storage_summary);
    Ok(())
}
```

**Option 2: Verify During can_service()**
Add verification in `DataSummary::can_service()` before trusting version/timestamp checks, though this is less efficient as it verifies on every request.

**Option 3: Mark as Unverified**
Add a flag indicating whether the `synced_ledger_info` has been verified, and only trust it for peer selection after verification.

## Proof of Concept

```rust
// Proof of concept demonstrating the vulnerability
use aptos_storage_service_types::responses::{DataSummary, StorageServerSummary, ProtocolMetadata};
use aptos_types::ledger_info::{LedgerInfo, LedgerInfoWithSignatures};
use aptos_types::block_info::BlockInfo;
use aptos_types::aggregate_signature::AggregateSignature;
use aptos_crypto::hash::HashValue;

// Create fake ledger info with arbitrarily high version
let fake_block_info = BlockInfo::new(
    999,                    // Fake epoch
    0,                      // Round
    HashValue::zero(),      // Block ID
    HashValue::zero(),      // Executed state ID
    999_999_999,            // Fake very high version
    1_700_000_000_000_000,  // Recent timestamp
    None,                   // No epoch state
);

let fake_ledger_info = LedgerInfo::new(fake_block_info, HashValue::zero());

// Create ledger info with INVALID/EMPTY signatures
let fake_synced_ledger_info = LedgerInfoWithSignatures::new(
    fake_ledger_info,
    AggregateSignature::empty(), // Invalid signatures!
);

// Create malicious summary
let malicious_summary = StorageServerSummary {
    protocol_metadata: ProtocolMetadata::default(),
    data_summary: DataSummary {
        synced_ledger_info: Some(fake_synced_ledger_info), // Fake high-version ledger info
        epoch_ending_ledger_infos: None,
        states: None,
        transactions: None,
        transaction_outputs: None,
    },
};

// This summary will be stored without verification and will pass can_service() checks
// for requests requiring version 999_999_999 or below, despite having invalid signatures.
// The honest node will select this malicious peer for requests, wasting resources
// when the actual data request fails verification.
```

## Notes

The core security invariant violated is that **cryptographically signed data must be verified before being trusted for any security-relevant decision**. The `LedgerInfoWithSignatures` type contains BLS signatures that MUST be verified using `verify_signatures()` before the ledger info can be trusted. [10](#0-9) 

The proper verification flow exists elsewhere in the codebase and should be applied here as well. [11](#0-10) 

While the peer scoring system provides some mitigation, it is insufficient because: (1) scores reset on disconnect/reconnect, (2) multiple malicious identities can sustain attacks, and (3) damage is already done during the ~4 requests before a peer is ignored.

### Citations

**File:** state-sync/storage-service/types/src/responses.rs (L665-686)
```rust
/// A summary of the data actually held by the storage service instance.
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

**File:** state-sync/storage-service/types/src/responses.rs (L689-808)
```rust
    /// Returns true iff the request can be serviced
    pub fn can_service(
        &self,
        aptos_data_client_config: &AptosDataClientConfig,
        time_service: TimeService,
        request: &StorageServiceRequest,
    ) -> bool {
        match &request.data_request {
            GetServerProtocolVersion | GetStorageServerSummary => true,
            GetEpochEndingLedgerInfos(request) => {
                let desired_range =
                    match CompleteDataRange::new(request.start_epoch, request.expected_end_epoch) {
                        Ok(desired_range) => desired_range,
                        Err(_) => return false,
                    };
                self.epoch_ending_ledger_infos
                    .map(|range| range.superset_of(&desired_range))
                    .unwrap_or(false)
            },
            GetNewTransactionOutputsWithProof(_) => can_service_optimistic_request(
                aptos_data_client_config,
                time_service,
                self.synced_ledger_info.as_ref(),
            ),
            GetNewTransactionsWithProof(_) => can_service_optimistic_request(
                aptos_data_client_config,
                time_service,
                self.synced_ledger_info.as_ref(),
            ),
            GetNewTransactionsOrOutputsWithProof(_) => can_service_optimistic_request(
                aptos_data_client_config,
                time_service,
                self.synced_ledger_info.as_ref(),
            ),
            GetNumberOfStatesAtVersion(version) => self
                .states
                .map(|range| range.contains(*version))
                .unwrap_or(false),
            GetStateValuesWithProof(request) => {
                let proof_version = request.version;

                let can_serve_states = self
                    .states
                    .map(|range| range.contains(request.version))
                    .unwrap_or(false);

                let can_create_proof = self
                    .synced_ledger_info
                    .as_ref()
                    .map(|li| li.ledger_info().version() >= proof_version)
                    .unwrap_or(false);

                can_serve_states && can_create_proof
            },
            GetTransactionOutputsWithProof(request) => self
                .can_service_transaction_outputs_with_proof(
                    request.start_version,
                    request.end_version,
                    request.proof_version,
                ),
            GetTransactionsWithProof(request) => self.can_service_transactions_with_proof(
                request.start_version,
                request.end_version,
                request.proof_version,
            ),
            GetTransactionsOrOutputsWithProof(request) => self
                .can_service_transactions_or_outputs_with_proof(
                    request.start_version,
                    request.end_version,
                    request.proof_version,
                ),
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

            // Transaction data v2 requests (transactions with auxiliary data)
            GetTransactionDataWithProof(request) => match request.transaction_data_request_type {
                TransactionDataRequestType::TransactionData(_) => self
                    .can_service_transactions_with_proof(
                        request.start_version,
                        request.end_version,
                        request.proof_version,
                    ),
                TransactionDataRequestType::TransactionOutputData => self
                    .can_service_transaction_outputs_with_proof(
                        request.start_version,
                        request.end_version,
                        request.proof_version,
                    ),
                TransactionDataRequestType::TransactionOrOutputData(_) => self
                    .can_service_transactions_or_outputs_with_proof(
                        request.start_version,
                        request.end_version,
                        request.proof_version,
                    ),
            },
            GetNewTransactionDataWithProof(_) => can_service_optimistic_request(
                aptos_data_client_config,
                time_service,
                self.synced_ledger_info.as_ref(),
            ),
            SubscribeTransactionDataWithProof(_) => can_service_subscription_request(
                aptos_data_client_config,
                time_service,
                self.synced_ledger_info.as_ref(),
            ),
        }
    }
```

**File:** state-sync/storage-service/types/src/responses.rs (L810-816)
```rust
    /// Returns true iff the peer can create a proof for the given version
    fn can_create_proof(&self, proof_version: u64) -> bool {
        self.synced_ledger_info
            .as_ref()
            .map(|li| li.ledger_info().version() >= proof_version)
            .unwrap_or(false)
    }
```

**File:** state-sync/storage-service/types/src/responses.rs (L914-934)
```rust
/// Returns true iff the synced ledger info timestamp
/// is within the given lag (in seconds).
fn check_synced_ledger_lag(
    synced_ledger_info: Option<&LedgerInfoWithSignatures>,
    time_service: TimeService,
    max_lag_secs: u64,
) -> bool {
    if let Some(synced_ledger_info) = synced_ledger_info {
        // Get the ledger info timestamp (in microseconds)
        let ledger_info_timestamp_usecs = synced_ledger_info.ledger_info().timestamp_usecs();

        // Get the current timestamp and max version lag (in microseconds)
        let current_timestamp_usecs = time_service.now_unix_time().as_micros() as u64;
        let max_version_lag_usecs = max_lag_secs * NUM_MICROSECONDS_IN_SECOND;

        // Return true iff the synced ledger info timestamp is within the max version lag
        ledger_info_timestamp_usecs + max_version_lag_usecs > current_timestamp_usecs
    } else {
        false // No synced ledger info was found!
    }
}
```

**File:** state-sync/aptos-data-client/src/poller.rs (L404-439)
```rust
    let poller = async move {
        // Construct the request for polling
        let data_request = DataRequest::GetStorageServerSummary;
        let use_compression = data_summary_poller.data_client_config.use_compression;
        let storage_request = StorageServiceRequest::new(data_request, use_compression);

        // Fetch the storage summary for the peer and stop the timer
        let request_timeout = data_summary_poller.data_client_config.response_timeout_ms;
        let result: crate::error::Result<StorageServerSummary> = data_summary_poller
            .data_client
            .send_request_to_peer_and_decode(peer, storage_request, request_timeout)
            .await
            .map(Response::into_payload);

        // Mark the in-flight poll as now complete
        data_summary_poller.in_flight_request_complete(&peer);

        // Check the storage summary response
        let storage_summary = match result {
            Ok(storage_summary) => storage_summary,
            Err(error) => {
                warn!(
                    (LogSchema::new(LogEntry::StorageSummaryResponse)
                        .event(LogEvent::PeerPollingError)
                        .message("Error encountered when polling peer!")
                        .error(&error)
                        .peer(&peer))
                );
                return;
            },
        };

        // Update the summary for the peer
        data_summary_poller
            .data_client
            .update_peer_storage_summary(peer, storage_summary);
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L324-330)
```rust
    /// Updates the storage summary for the given peer
    pub fn update_summary(&self, peer: PeerNetworkId, storage_summary: StorageServerSummary) {
        self.peer_to_state
            .entry(peer)
            .or_insert(PeerState::new(self.data_client_config.clone()))
            .update_storage_summary(storage_summary);
    }
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L332-336)
```rust
    /// Garbage collects the peer states to remove data for disconnected peers
    pub fn garbage_collect_peer_states(&self, connected_peers: HashSet<PeerNetworkId>) {
        self.peer_to_state
            .retain(|peer_network_id, _| connected_peers.contains(peer_network_id));
    }
```

**File:** state-sync/aptos-data-client/src/client.rs (L540-560)
```rust
    fn identify_serviceable(
        &self,
        peers_by_priorities: &BTreeMap<PeerPriority, HashSet<PeerNetworkId>>,
        priority: PeerPriority,
        request: &StorageServiceRequest,
    ) -> HashSet<PeerNetworkId> {
        // Get the peers for the specified priority
        let prospective_peers = peers_by_priorities
            .get(&priority)
            .unwrap_or(&hashset![])
            .clone();

        // Identify and return the serviceable peers
        prospective_peers
            .into_iter()
            .filter(|peer| {
                self.peer_states
                    .can_service_request(peer, self.time_service.clone(), request)
            })
            .collect()
    }
```

**File:** state-sync/state-sync-driver/src/continuous_syncer.rs (L425-466)
```rust
    async fn verify_proof_ledger_info(
        &mut self,
        consensus_sync_request: Arc<Mutex<Option<ConsensusSyncRequest>>>,
        notification_id: NotificationId,
        ledger_info_with_signatures: &LedgerInfoWithSignatures,
    ) -> Result<(), Error> {
        // If we're syncing to a specific target, verify the ledger info isn't too high
        let sync_request_target = consensus_sync_request
            .lock()
            .as_ref()
            .and_then(|sync_request| sync_request.get_sync_target());
        if let Some(sync_request_target) = sync_request_target {
            let sync_request_version = sync_request_target.ledger_info().version();
            let proof_version = ledger_info_with_signatures.ledger_info().version();
            if sync_request_version < proof_version {
                self.reset_active_stream(Some(NotificationAndFeedback::new(
                    notification_id,
                    NotificationFeedback::PayloadProofFailed,
                )))
                .await?;
                return Err(Error::VerificationError(format!(
                    "Proof version is higher than the sync target. Proof version: {:?}, sync version: {:?}.",
                    proof_version, sync_request_version
                )));
            }
        }

        // Verify the ledger info state and signatures
        if let Err(error) = self
            .get_speculative_stream_state()?
            .verify_ledger_info_with_signatures(ledger_info_with_signatures)
        {
            self.reset_active_stream(Some(NotificationAndFeedback::new(
                notification_id,
                NotificationFeedback::PayloadProofFailed,
            )))
            .await?;
            Err(error)
        } else {
            Ok(())
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

**File:** types/src/epoch_state.rs (L40-50)
```rust
impl Verifier for EpochState {
    fn verify(&self, ledger_info: &LedgerInfoWithSignatures) -> anyhow::Result<()> {
        ensure!(
            self.epoch == ledger_info.ledger_info().epoch(),
            "LedgerInfo has unexpected epoch {}, expected {}",
            ledger_info.ledger_info().epoch(),
            self.epoch
        );
        ledger_info.verify_signatures(&self.verifier)?;
        Ok(())
    }
```
