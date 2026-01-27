# Audit Report

## Title
Eclipse Attack Enables Premature Bootstrapping Completion via Stale Epoch State Manipulation

## Summary
The bootstrapping logic in `fetch_missing_state_snapshot_data()` allows a node to complete bootstrapping based solely on peer-advertised blockchain state, without verifying this represents the actual network head. An attacker performing an eclipse attack can feed valid but stale epoch ending ledger infos to keep the victim node's calculated `num_versions_behind` below the threshold, causing premature bootstrapping completion while the node remains arbitrarily far behind the real network.

## Finding Description

The vulnerability exists in the bootstrapping threshold check that determines whether a node should skip snapshot synchronization. [1](#0-0) 

The `num_versions_behind` calculation depends on `highest_known_ledger_info`, which is derived from the maximum of local storage and verified epoch states from the network. [2](#0-1) 

The verified epoch states come from epoch ending ledger infos fetched based on `global_data_summary`, which aggregates data advertised by connected peers. [3](#0-2) 

**Attack Scenario:**

1. Attacker eclipses the victim node (controls all peer connections)
2. Real network progresses to epoch 1000, version 100,000,000
3. Victim node is synced to version 50,000,000
4. Attacker's controlled peers advertise epoch ending ledger infos only up to version 50,000,100 (valid historical data)
5. Node calculates: `num_versions_behind = 50,000,100 - 50,000,000 = 100`
6. Since 100 < `num_versions_to_skip_snapshot_sync` (default: 400,000,000), bootstrapping completes [4](#0-3) 
7. Node believes continuous syncer will catch it up, but all peers continue providing stale data
8. Node remains 50,000,000 versions behind indefinitely

The epoch ending ledger infos are cryptographically valid (they must pass signature verification), but they represent outdated blockchain state. [5](#0-4) 

This breaks the **State Consistency** invariant—the node believes it has current state when it's actually serving historical data.

## Impact Explanation

**High Severity** per Aptos bug bounty criteria:

**For Validator Nodes:**
- Cannot participate in current epoch consensus (validator node slowdown/failure)
- May sign conflicting messages if consensus layer expects current epoch while bootstrap state is stale
- Loss of validator rewards and potential slashing for non-participation
- Constitutes "Significant protocol violations"

**For Fullnodes:**
- Serve stale blockchain state to users indefinitely
- API queries return outdated account balances, transaction status, and smart contract state
- No automatic recovery mechanism since continuous syncer also relies on same malicious peers
- Users making decisions based on this data suffer integrity violations

The default threshold of 400M versions (approximately 24 hours at 5K TPS) provides a large attack window where the node can be arbitrarily far behind while still completing bootstrapping.

## Likelihood Explanation

**Moderate Likelihood:**

**Attacker Requirements:**
- Must perform eclipse attack (control all peer connections to victim node)
- Requires network-level capabilities (BGP hijacking, ISP-level attack, or controlling all publicly advertised peers)
- Must maintain persistent control to prevent node from discovering honest peers

**Mitigating Factors:**
- Eclipse attacks require significant resources
- Nodes with diverse peer connections are harder to eclipse
- Validator operators typically use well-connected infrastructure

**Aggravating Factors:**
- No time-based freshness checks on advertised data
- No out-of-band verification mechanism (checkpoints, trusted relays)
- Once eclipsed, node has no way to detect stale peer data
- Continuous syncer perpetuates the problem using same peer set

Eclipse attacks are well-documented in blockchain systems (Bitcoin, Ethereum) and considered realistic threats in adversarial network environments.

## Recommendation

Implement multi-layered defenses:

**1. Add Timestamp-Based Freshness Validation:**
```rust
// In verify_waypoint_is_satisfiable or fetch_epoch_ending_ledger_infos
fn verify_advertised_data_freshness(
    &self,
    highest_advertised_ledger_info: &LedgerInfoWithSignatures,
) -> Result<(), Error> {
    let advertised_timestamp = highest_advertised_ledger_info.ledger_info().timestamp_usecs();
    let current_time = self.time_service.now_unix_time().as_micros();
    let max_acceptable_age_secs = self.driver_configuration.config.max_advertised_data_age_secs;
    
    let age_secs = current_time.saturating_sub(advertised_timestamp) / 1_000_000;
    
    if age_secs > max_acceptable_age_secs {
        return Err(Error::AdvertisedDataError(format!(
            "Advertised data is too stale! Age: {} seconds, max: {} seconds",
            age_secs, max_acceptable_age_secs
        )));
    }
    Ok(())
}
```

**2. Require Minimum Peer Diversity:**
Ensure global_data_summary comes from peers across multiple networks/ASNs before trusting the advertised state.

**3. Add Configuration for Trusted Checkpoints:**
Allow operators to configure recent trusted checkpoints (ledger info hashes at specific versions) that must be verifiable through peer data.

**4. Implement Peer Score-Based Confidence:**
Weight advertised data by peer reputation scores and require high-confidence consensus before completing bootstrap.

## Proof of Concept

```rust
#[tokio::test]
async fn test_eclipse_attack_premature_bootstrap() {
    // Setup: Create a node synced to version 1M
    let mut bootstrapper = create_bootstrapper_with_synced_version(1_000_000).await;
    
    // Simulate eclipse attack: All peers advertise stale epoch ending ledger infos
    // Real network is at 100M, but attacker only advertises up to 1.0001M
    let stale_epoch_ending_ledger_info = create_valid_epoch_ending_ledger_info(
        1_000_100,  // Only 100 versions ahead
        50,         // Epoch 50 (real network is at epoch 1000)
    );
    
    // Create malicious global_data_summary with only stale peers
    let mut malicious_global_summary = GlobalDataSummary::empty();
    malicious_global_summary.advertised_data.synced_ledger_infos = 
        vec![stale_epoch_ending_ledger_info.clone()];
    
    // Mock the verified epoch states to return stale ledger info
    bootstrapper
        .get_verified_epoch_states()
        .update_verified_epoch_states(&stale_epoch_ending_ledger_info, &Waypoint::default())
        .unwrap();
    
    // Trigger bootstrapping
    let result = bootstrapper
        .fetch_missing_state_snapshot_data(
            1_000_000,  // highest_synced_version
            stale_epoch_ending_ledger_info,  // highest_known_ledger_info (stale)
        )
        .await;
    
    // VULNERABILITY: Node completes bootstrapping despite being 99M versions behind real network
    assert!(result.is_ok());
    assert!(bootstrapper.is_bootstrapped()); // This should NOT be true!
    
    // In reality, node is 99,000,000 versions behind (100M - 1M)
    // but calculated num_versions_behind = 100 (1.0001M - 1M)
    // Since 100 < 400M (default threshold), bootstrap completed prematurely
}
```

## Notes

The vulnerability is fundamentally a **trust assumption violation**—the code assumes peer-advertised data represents the actual blockchain head when it may not under eclipse attack conditions. While eclipse attacks require significant attacker capabilities, the consequences (validator failure, stale data serving) justify HIGH severity classification.

The 400M version threshold, while generous for normal network disruptions, becomes a liability under adversarial conditions. Combining threshold-based logic with timestamp validation and peer diversity requirements would provide defense-in-depth against this attack vector.

### Citations

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L103-108)
```rust
        // Verify the ledger info against the latest epoch state
        self.latest_epoch_state
            .verify(epoch_ending_ledger_info)
            .map_err(|error| {
                Error::VerificationError(format!("Ledger info failed verification: {:?}", error))
            })?;
```

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L563-571)
```rust
            if num_versions_behind < max_num_versions_behind {
                info!(LogSchema::new(LogEntry::Bootstrapper).message(&format!(
                    "The node is only {} versions behind, will skip bootstrapping.",
                    num_versions_behind
                )));
                // We've already bootstrapped to an initial state snapshot. If this a fullnode, the
                // continuous syncer will take control and get the node up-to-date. If this is a
                // validator, consensus will take control and sync depending on how it sees fit.
                self.bootstrapping_complete().await
```

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L1445-1462)
```rust
    fn get_highest_known_ledger_info(&self) -> Result<LedgerInfoWithSignatures, Error> {
        // Fetch the highest synced ledger info from storage
        let mut highest_known_ledger_info =
            utils::fetch_latest_synced_ledger_info(self.storage.clone())?;

        // Fetch the highest verified ledger info (from the network) and take
        // the maximum.
        if let Some(verified_ledger_info) =
            self.verified_epoch_states.get_highest_known_ledger_info()?
        {
            if verified_ledger_info.ledger_info().version()
                > highest_known_ledger_info.ledger_info().version()
            {
                highest_known_ledger_info = verified_ledger_info;
            }
        }
        Ok(highest_known_ledger_info)
    }
```

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

**File:** config/src/config/state_sync_config.rs (L149-149)
```rust
            num_versions_to_skip_snapshot_sync: 400_000_000, // At 5k TPS, this allows a node to fail for about 24 hours.
```
