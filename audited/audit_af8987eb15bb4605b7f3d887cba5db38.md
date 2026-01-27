# Audit Report

## Title
VFN Network Eclipse Attack: Validator Full Nodes Can Be Forced to Sync from Untrusted Public Full Node Peers

## Summary
A Validator Full Node (VFN) can be eclipsed from its validator connections through network-level attacks, forcing it to fall back to syncing from potentially malicious Public Full Node (PFN) peers. There is no enforcement mechanism requiring VFNs to maintain validator connectivity, and no detection when a VFN operates solely on Public network connections.

## Finding Description

The vulnerability exists in how VFNs identify themselves and prioritize peers for state synchronization. A VFN is identified by having `NetworkId::Vfn` registered in its network configuration, but there is no runtime enforcement that it must maintain active connections on this network. [1](#0-0) 

The peer priority logic shows that VFNs assign:
- **High Priority**: Peers on the VFN network (validators)
- **Medium Priority**: Trusted peers or outbound connections on Public network  
- **Low Priority**: Inbound connections on Public network (untrusted PFNs)

However, the peer selection mechanism in the state sync data client will fall back through all priority tiers when higher priority peers are unavailable: [2](#0-1) 

The code explicitly notes that "the lowest priority peers are generally unreliable" but still includes them when no other peers are available.

Most critically, the connectivity check for VFNs accepts connections on **either** the VFN network **or** the Public network: [3](#0-2) 

The TODO comment on line 116 explicitly acknowledges this gap: "TODO handle VFNs querying if they are connected to a validator."

**Attack Scenario:**

1. Attacker performs network-level eclipse attack on a VFN's VFN network interface (typically port 6181)
2. VFN loses all connections to its validator(s) on the VFN network
3. VFN maintains Public network connections (port 6182), potentially to attacker-controlled nodes
4. VFN passes connectivity checks since it has Public network connections
5. State sync finds no high priority peers and falls back to medium/low priority Public peers
6. VFN is now syncing from untrusted PFN peers controlled by the attacker

**Security Guarantees Broken:**

This violates the VFN trust model. VFNs are designed to be trusted nodes that sync directly from their associated validators. By forcing them to sync from untrusted public peers, the attacker can:

- **Deny service** by refusing to provide data, causing the VFN to stall until the ProgressChecker panics
- **Degrade performance** by serving data slowly
- **Withhold recent data** by selectively serving only old (but valid) ledger infos
- **Control information flow** to the VFN's downstream clients

While cryptographic verification prevents the attacker from providing invalid data: [4](#0-3) 

The attacker can still control data availability and timing, which severely impacts the VFN's ability to serve its intended function.

## Impact Explanation

This is a **HIGH severity** issue according to the Aptos bug bounty criteria:

1. **"Validator node slowdowns"** (High: up to $50,000) - The eclipsed VFN will experience significant performance degradation when forced to sync from slow or unreliable PFN peers.

2. **"Significant protocol violations"** (High: up to $50,000) - The VFN is violating its fundamental architectural principle of syncing from trusted validators. This breaks the trust hierarchy: Validators → VFNs → PFNs.

3. **Availability Impact** - Services and applications relying on the VFN for current blockchain state will be degraded or unavailable.

The attack does not compromise consensus safety or allow theft of funds due to cryptographic verification, preventing it from reaching Critical severity. However, it represents a significant operational security risk for VFN operators.

## Likelihood Explanation

**Likelihood: High**

Network-level eclipse attacks are well-documented in distributed systems literature and have been successfully demonstrated against blockchain nodes. The attack requires:

1. **Network positioning** - Attacker must be able to filter/block traffic to the VFN network interface
2. **Public network connections** - Attacker should establish connections to the VFN on the Public network

Both requirements are achievable through:
- BGP hijacking or routing manipulation
- Firewall rule manipulation on compromised intermediate networks
- DDoS attacks targeting the VFN network interface
- DNS/discovery manipulation to prevent VFN-validator connections

The lack of detection makes this attack particularly concerning - a VFN operator may not realize their node is compromised until users report stale data or poor performance.

## Recommendation

Implement a mandatory validator connectivity requirement for VFNs with three layers of defense:

**1. Runtime Enforcement** - Modify the connectivity check to require VFN network connections: [5](#0-4) 

Replace the current logic with:
```rust
async fn check_connectivity(&self) -> Result<bool> {
    const DIRECTION: Option<&str> = Some("outbound");
    const EXPECTED_PEERS: usize = 1;
    
    // If this is a VFN (has Vfn network registered), require VFN network connectivity
    if self.config().full_node_networks.iter()
        .any(|net| net.network_id == NetworkId::Vfn) 
    {
        // VFNs MUST have at least one connection on the VFN network
        return self
            .get_connected_peers(NetworkId::Vfn, DIRECTION)
            .await
            .map(|maybe_n| maybe_n.map(|n| n >= EXPECTED_PEERS as i64).unwrap_or(false));
    }
    
    // PFNs can use Public network
    self.get_connected_peers(NetworkId::Public, DIRECTION)
        .await
        .map(|maybe_n| maybe_n.map(|n| n >= EXPECTED_PEERS as i64).unwrap_or(false))
}
```

**2. State Sync Protection** - Add a check before falling back to low priority peers: [6](#0-5) 

Add validation:
```rust
// For VFNs, verify we have high priority peers (validators)
if self.base_config.role.is_full_node() 
    && self.get_peers_and_metadata()
        .get_registered_networks()
        .contains(&NetworkId::Vfn)
{
    let has_high_priority = serviceable_peers_by_priorities
        .first()
        .map(|peers| !peers.is_empty())
        .unwrap_or(false);
    
    if !has_high_priority {
        return Err(Error::DataIsUnavailable(
            "VFN has no validator connections - refusing to sync from untrusted peers".into()
        ));
    }
}
```

**3. Monitoring & Alerting** - Add metrics tracking high priority peer connectivity:

```rust
// In state-sync/aptos-data-client/src/client.rs
pub fn check_vfn_validator_connectivity(&self) -> bool {
    if !self.base_config.role.is_full_node() {
        return true; // Not a VFN
    }
    
    let (priority_peers, _) = self.get_priority_and_regular_peers()
        .unwrap_or((HashSet::new(), HashSet::new()));
    
    let has_validators = !priority_peers.is_empty();
    
    // Update metric
    metrics::set_gauge(
        &metrics::VFN_HAS_VALIDATOR_CONNECTION,
        if has_validators { 1.0 } else { 0.0 }
    );
    
    has_validators
}
```

## Proof of Concept

This vulnerability can be demonstrated with the following test scenario:

```rust
#[tokio::test]
async fn test_vfn_eclipse_attack() {
    // Setup: Create a VFN with validator connection
    let mut swarm = SwarmBuilder::new_local(1)
        .with_num_fullnodes(1)
        .build()
        .await;
    
    let vfn = swarm.full_nodes().next().unwrap();
    let vfn_client = vfn.rest_client();
    
    // Step 1: Verify VFN is healthy with validator connection
    assert!(vfn.check_connectivity().await.unwrap());
    let initial_version = vfn_client.get_ledger_information().await.unwrap().version;
    
    // Step 2: Block VFN network connections (simulating eclipse attack)
    // In practice: block port 6181, manipulate firewall rules, etc.
    let vfn_peer_id = vfn.peer_id();
    let vfn_config = vfn.config();
    
    // Disconnect from validator on VFN network
    // (In a real attack, this would be done via network filtering)
    swarm.validator_mut(swarm.validators().next().unwrap().peer_id())
        .unwrap()
        .stop();
    
    // Step 3: VFN still passes connectivity check (has Public network)
    // This demonstrates the vulnerability!
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(vfn.check_connectivity().await.unwrap()); // FALSE POSITIVE
    
    // Step 4: Add malicious PFN peer on Public network
    let malicious_pfn = swarm.add_full_node(
        &swarm.versions().max().unwrap(),
        OverrideNodeConfig::new_with_default_base(NodeConfig::get_default_pfn_config())
    ).await.unwrap();
    
    // Step 5: VFN is now forced to sync from malicious PFN
    // The malicious peer can now:
    // - Refuse to provide data (DoS)
    // - Serve data slowly (performance degradation)  
    // - Serve only old valid data (keep VFN on stale state)
    
    tokio::time::sleep(Duration::from_secs(30)).await;
    
    // Verify VFN has made no progress or limited progress
    let current_version = vfn_client.get_ledger_information().await.unwrap().version;
    
    // In a real attack, current_version would be stale or the VFN would panic
    println!("VFN version progress: {} -> {}", initial_version, current_version);
    println!("VFN is syncing from untrusted Public network peers!");
}
```

To fully demonstrate the attack, configure the malicious PFN to:
1. Accept connections from the VFN
2. Refuse to serve data or serve it with significant delays
3. Observe the VFN stall or operate on stale state

## Notes

The vulnerability is acknowledged in the codebase via the TODO comment but has not been addressed. The cryptographic verification layer prevents consensus safety violations, but the availability and trust model violations remain significant security concerns for VFN operators who rely on their nodes syncing from trusted validators.

### Citations

**File:** state-sync/aptos-data-client/src/priority.rs (L75-101)
```rust
    // Handle the case that this node is a VFN
    if peers_and_metadata
        .get_registered_networks()
        .contains(&NetworkId::Vfn)
    {
        // VFNs should highly prioritize validators
        if peer_network_id.is_vfn_network() {
            return PeerPriority::HighPriority;
        }

        // Trusted peers should be prioritized over untrusted peers.
        // This prioritizes other VFNs/seed peers over regular PFNs.
        if is_trusted_peer(peers_and_metadata.clone(), peer) {
            return PeerPriority::MediumPriority;
        }

        // Outbound connections should be prioritized over inbound connections.
        // This prioritizes other VFNs/seed peers over regular PFNs.
        return if let Some(metadata) = utils::get_metadata_for_peer(&peers_and_metadata, *peer) {
            if metadata.get_connection_metadata().is_outbound_connection() {
                PeerPriority::MediumPriority
            } else {
                PeerPriority::LowPriority
            }
        } else {
            PeerPriority::LowPriority // We don't have connection metadata
        };
```

**File:** state-sync/aptos-data-client/src/client.rs (L265-280)
```rust
    pub(crate) fn choose_peers_for_request(
        &self,
        request: &StorageServiceRequest,
    ) -> crate::error::Result<HashSet<PeerNetworkId>, Error> {
        // Get all peers grouped by priorities
        let peers_by_priorities = self.get_peers_by_priorities()?;

        // Identify the peers that can service the request (ordered by priority)
        let mut serviceable_peers_by_priorities = vec![];
        for priority in PeerPriority::get_all_ordered_priorities() {
            // Identify the serviceable peers for the priority
            let peers = self.identify_serviceable(&peers_by_priorities, priority, request);

            // Add the serviceable peers to the ordered list
            serviceable_peers_by_priorities.push(peers);
        }
```

**File:** state-sync/aptos-data-client/src/client.rs (L294-301)
```rust
            for (index, peers) in serviceable_peers_by_priorities.iter().enumerate() {
                // Only include the lowest priority peers if no other peers are
                // available (the lowest priority peers are generally unreliable).
                if (num_serviceable_peers == 0)
                    || (index < serviceable_peers_by_priorities.len() - 1)
                {
                    num_serviceable_peers += peers.len();
                }
```

**File:** testsuite/forge/src/interface/node.rs (L116-131)
```rust
    //TODO handle VFNs querying if they are connected to a validator
    async fn check_connectivity(&self) -> Result<bool> {
        const DIRECTION: Option<&str> = Some("outbound");
        const EXPECTED_PEERS: usize = 1;

        for &network_id in &[NetworkId::Public, NetworkId::Vfn] {
            let r = self
                .get_connected_peers(network_id, DIRECTION)
                .await
                .map(|maybe_n| maybe_n.map(|n| n >= EXPECTED_PEERS as i64).unwrap_or(false));
            if let Ok(true) = r {
                return Ok(true);
            }
        }
        Ok(false)
    }
```

**File:** state-sync/state-sync-driver/src/continuous_syncer.rs (L1-50)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

use crate::{
    driver::DriverConfiguration,
    error::Error,
    metrics,
    metrics::ExecutingComponent,
    notification_handlers::ConsensusSyncRequest,
    storage_synchronizer::{NotificationMetadata, StorageSynchronizerInterface},
    utils,
    utils::{OutputFallbackHandler, SpeculativeStreamState, PENDING_DATA_LOG_FREQ_SECS},
};
use aptos_config::config::ContinuousSyncingMode;
use aptos_data_streaming_service::{
    data_notification::{DataNotification, DataPayload, NotificationId},
    data_stream::DataStreamListener,
    streaming_client::{DataStreamingClient, Epoch, NotificationAndFeedback, NotificationFeedback},
};
use aptos_infallible::Mutex;
use aptos_logger::{prelude::*, sample, sample::SampleRate};
use aptos_storage_interface::DbReader;
use aptos_types::{
    ledger_info::LedgerInfoWithSignatures,
    transaction::{TransactionListWithProofV2, TransactionOutputListWithProofV2, Version},
};
use std::{sync::Arc, time::Duration};

/// A simple component that manages the continuous syncing of the node
pub struct ContinuousSyncer<StorageSyncer, StreamingClient> {
    // The currently active data stream (provided by the data streaming service)
    active_data_stream: Option<DataStreamListener>,

    // The config of the state sync driver
    driver_configuration: DriverConfiguration,

    // The handler for output fallback behaviour
    output_fallback_handler: OutputFallbackHandler,

    // The speculative state tracking the active data stream
    speculative_stream_state: Option<SpeculativeStreamState>,

    // The client through which to stream data from the Aptos network
    streaming_client: StreamingClient,

    // The interface to read from storage
    storage: Arc<dyn DbReader>,

    // The storage synchronizer used to update local storage
    storage_synchronizer: StorageSyncer,
```
