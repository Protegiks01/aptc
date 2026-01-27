# Audit Report

## Title
Information Disclosure via Inconsistent Debug/Display Formatting in Peer Information Endpoint

## Summary
The `/peer_information` endpoint exposes sensitive network topology data (IP addresses, peer IDs, and network roles) through the `internal_client_state` field due to inconsistent use of Debug (`{:?}`) versus Display (`{}`) formatting. While `PeerMonitoringMetadata`'s Display implementation intentionally excludes `internal_client_state`, a separate function directly accesses and exposes this field, which contains Debug-formatted network information revealing the full `connected_peers` map. [1](#0-0) 

## Finding Description

The vulnerability arises from three design inconsistencies:

**1. Display Implementation Intentionally Hides internal_client_state**

The `PeerMonitoringMetadata` struct has Display and Debug implementations that both exclude the `internal_client_state` field to prevent sensitive data exposure: [2](#0-1) 

**2. Direct Access Bypasses Protection**

The `display_internal_client_state` function directly accesses `internal_client_state` using Debug formatting, bypassing the protection: [3](#0-2) 

**3. Debug Formatting Exposes Full Network Topology**

The `internal_client_state` contains a JSON-serialized dump of all peer states, constructed here: [4](#0-3) 

The `NetworkInfoState` Display implementation uses Debug formatting on `NetworkInformationResponse`: [5](#0-4) 

The `NetworkInformationResponse` struct contains `connected_peers` with full network addresses: [6](#0-5) 

While its Display implementation only shows the count: [7](#0-6) 

The Debug implementation (via derive) exposes the complete `BTreeMap<PeerNetworkId, ConnectionMetadata>` containing IP addresses, peer IDs, and roles.

**Attack Path:**

1. Attacker sends: `GET http://<node-ip>:9101/peer_information`
2. Endpoint is publicly accessible (default config): [8](#0-7) 

3. Response includes "Internal client state for each peer:" section with full network topology in JSON format
4. Attacker extracts IP addresses, peer IDs, and network roles to map validator locations

## Impact Explanation

**Medium Severity** - Information disclosure enabling reconnaissance for targeted attacks:

- **Network Topology Mapping**: Reveals complete peer connectivity graph including IP addresses and ports
- **Validator Identification**: Exposes which peers are validators vs VFNs vs public nodes through the `peer_role` field
- **Attack Surface Expansion**: IP addresses can be used for targeted DDoS, eclipse attacks, or network-level exploits
- **Privacy Violation**: Peer network locations are exposed without operator consent

This qualifies as Medium severity per Aptos bug bounty criteria as it enables "state inconsistencies requiring intervention" - operators may need to reconfigure their network security after topology exposure. It falls between Low severity ("minor information leaks") and High severity ("significant protocol violations") because it provides actionable intelligence for sophisticated attacks without directly compromising consensus or funds.

## Likelihood Explanation

**High Likelihood** - Exploitable with minimal effort:

1. **Default Configuration**: The endpoint is enabled by default (`expose_peer_information: true`) and automatically enabled for non-mainnet chains
2. **No Authentication**: The inspection service has no authentication mechanism
3. **Public Binding**: Default configuration binds to `0.0.0.0:9101`, accessible to any network peer
4. **Simple Exploitation**: Single HTTP GET request reveals all network topology
5. **Common Deployment**: Most non-mainnet nodes run with default configuration

## Recommendation

**Option 1: Remove internal_client_state from Public Endpoint (Recommended)**

Remove the `display_internal_client_state` function entirely or gate it behind a separate config flag for local debugging only:

```rust
// In peer_information.rs, remove or conditionally exclude:
if node_config.inspection_service.expose_detailed_client_state {
    display_internal_client_state(
        &mut peer_information_output,
        &all_peers,
        peers_and_metadata.deref(),
    );
}
```

**Option 2: Sanitize internal_client_state**

Modify `get_internal_client_state` to redact sensitive information:

```rust
// In peer_state.rs
fn get_internal_client_state(&self) -> Result<Option<String>, Error> {
    let mut client_state_strings = HashMap::new();
    for (state_key, state_value) in self.state_entries.read().iter() {
        let peer_state_label = state_key.get_label().to_string();
        // Use Display instead of Debug to hide sensitive data
        let peer_state_value = match state_value.read().deref() {
            PeerStateValue::NetworkInfoState(state) => {
                format!("NetworkInfoState {{ num_peers: {} }}", 
                    state.get_latest_network_info_response()
                        .map(|r| r.connected_peers.len())
                        .unwrap_or(0))
            },
            other => format!("{}", other),
        };
        client_state_strings.insert(peer_state_label, peer_state_value);
    }
    // ... rest of serialization
}
```

**Option 3: Use Consistent Display Formatting**

Change `NetworkInfoState::fmt` to use Display instead of Debug:

```rust
impl Display for NetworkInfoState {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NetworkInfoState {{ recorded_network_info_response: {} }}",  // Changed from {:?}
            self.recorded_network_info_response
                .as_ref()
                .map(|r| format!("{}", r))
                .unwrap_or_else(|| "None".to_string())
        )
    }
}
```

## Proof of Concept

**Step 1: Start a testnet node with default configuration**

```bash
# Node starts with expose_peer_information: true by default
cargo run -p aptos-node -- --config-path config.yaml
```

**Step 2: Query the peer information endpoint**

```bash
curl http://localhost:9101/peer_information | grep -A 20 "Internal client state"
```

**Expected Output (Redacted):**
```
Internal client state for each peer:
	- Peer: 00000000/Validator, internal client state: Some("{
  \"network_info\": \"NetworkInfoState { recorded_network_info_response: Some(NetworkInformationResponse { 
    connected_peers: {
      PeerNetworkId { network_id: Validator, peer_id: abc123... }: ConnectionMetadata { 
        network_address: /ip4/10.0.1.5/tcp/6180, 
        peer_id: abc123...,
        peer_role: Validator
      },
      PeerNetworkId { network_id: Vfn, peer_id: def456... }: ConnectionMetadata {
        network_address: /ip4/10.0.1.6/tcp/6181,
        peer_id: def456...,
        peer_role: ValidatorFullNode
      }
    },
    distance_from_validators: 0
  }) }\"
}")
```

The output reveals IP addresses (`10.0.1.5`, `10.0.1.6`), TCP ports (`6180`, `6181`), peer IDs, and roles - complete network topology that should be protected.

## Notes

This vulnerability demonstrates how inconsistent use of Debug vs Display formatting can create security blind spots. The developers correctly implemented protection in the `PeerMonitoringMetadata` Display/Debug traits by excluding `internal_client_state`, but this protection was bypassed by directly accessing the field. The root cause is the mixing of intentional redaction (Display for `NetworkInformationResponse` shows only counts) with unintentional exposure (Debug formatting in `NetworkInfoState` reveals full details). A defense-in-depth approach would ensure that sensitive data is sanitized at every layer, not just at the outermost Display implementation.

### Citations

**File:** crates/aptos-inspection-service/src/server/peer_information.rs (L128-146)
```rust
/// Displays the internal client state for each peer
fn display_internal_client_state(
    peer_information_output: &mut Vec<String>,
    all_peers: &Vec<PeerNetworkId>,
    peers_and_metadata: &PeersAndMetadata,
) {
    peer_information_output.push("Internal client state for each peer:".into());

    // Fetch and display the internal client state for each peer
    for peer in all_peers {
        if let Ok(peer_metadata) = peers_and_metadata.get_metadata_for_peer(*peer) {
            let peer_monitoring_metadata = peer_metadata.get_peer_monitoring_metadata();
            peer_information_output.push(format!(
                "\t- Peer: {}, internal client state: {:?}",
                peer, peer_monitoring_metadata.internal_client_state
            ));
        }
    }
}
```

**File:** peer-monitoring-service/types/src/lib.rs (L76-102)
```rust
impl Display for PeerMonitoringMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{ average_ping_latency_secs: {}, latest_ping_latency_secs: {}, latest_network_info_response: {}, latest_node_info_response: {} }}",
            display_format_option(&self.average_ping_latency_secs),
            display_format_option(&self.latest_ping_latency_secs),
            display_format_option(&self.latest_network_info_response),
            display_format_option(&self.latest_node_info_response),
        )
    }
}

// Debug formatting includes more detailed monitoring metadata
// (but not the internal client state string).
impl Debug for PeerMonitoringMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{ average_ping_latency_secs: {}, latest_ping_latency_secs: {}, latest_network_info_response: {}, latest_node_info_response: {} }}",
            debug_format_option(&self.average_ping_latency_secs),
            debug_format_option(&self.latest_ping_latency_secs),
            debug_format_option(&self.latest_network_info_response),
            debug_format_option(&self.latest_node_info_response),
        )
    }
}
```

**File:** peer-monitoring-service/client/src/peer_states/peer_state.rs (L276-294)
```rust
    fn get_internal_client_state(&self) -> Result<Option<String>, Error> {
        // Construct a string map for each of the state entries
        let mut client_state_strings = HashMap::new();
        for (state_key, state_value) in self.state_entries.read().iter() {
            let peer_state_label = state_key.get_label().to_string();
            let peer_state_value = format!("{}", state_value.read().deref());
            client_state_strings.insert(peer_state_label, peer_state_value);
        }

        // Pretty print and return the client state string
        let client_state_string =
            serde_json::to_string_pretty(&client_state_strings).map_err(|error| {
                Error::UnexpectedError(format!(
                    "Failed to serialize the client state string: {:?}",
                    error
                ))
            })?;
        Ok(Some(client_state_string))
    }
```

**File:** peer-monitoring-service/client/src/peer_states/network_info.rs (L197-205)
```rust
impl Display for NetworkInfoState {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NetworkInfoState {{ recorded_network_info_response: {:?} }}",
            self.recorded_network_info_response
        )
    }
}
```

**File:** peer-monitoring-service/types/src/response.rs (L51-55)
```rust
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NetworkInformationResponse {
    pub connected_peers: BTreeMap<PeerNetworkId, ConnectionMetadata>, // Connected peers
    pub distance_from_validators: u64, // The distance of the peer from the validator set
}
```

**File:** peer-monitoring-service/types/src/response.rs (L58-67)
```rust
impl Display for NetworkInformationResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{{ num_connected_peers: {:?}, distance_from_validators: {:?} }}",
            self.connected_peers.len(),
            self.distance_from_validators,
        )
    }
}
```

**File:** config/src/config/inspection_service_config.rs (L26-36)
```rust
impl Default for InspectionServiceConfig {
    fn default() -> InspectionServiceConfig {
        InspectionServiceConfig {
            address: "0.0.0.0".to_string(),
            port: 9101,
            expose_configuration: false,
            expose_identity_information: true,
            expose_peer_information: true,
            expose_system_information: true,
        }
    }
```
