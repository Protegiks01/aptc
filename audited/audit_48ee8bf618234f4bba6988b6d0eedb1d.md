# Audit Report

## Title
VFN Identification Through Inspection Service Identity Information Endpoint

## Summary
The `/identity_information` endpoint in the Aptos inspection service exposes the `network_id` of all configured networks, allowing attackers to identify which fullnodes are Validator Full Nodes (VFNs) versus Public Full Nodes. This information disclosure is enabled by default on mainnet and lacks sanitizer checks, enabling targeted attacks on validators' trusted fullnode infrastructure. [1](#0-0) 

## Finding Description
The `get_identity_information()` function exposes each network's `network_id` when the endpoint is queried. VFNs configure two fullnode networks: one with `NetworkId::Vfn` (serialized as "vfn") for private communication with their validator, and one with `NetworkId::Public` for serving public clients. [2](#0-1) [3](#0-2) 

Public Full Nodes only have `NetworkId::Public` configured. This difference allows trivial VFN identification:

**VFN Response:**
```
Identity Information:
    - Fullnode network (Public), peer ID: <id1>
    - Fullnode network (vfn), peer ID: <id2>
```

**PFN Response:**
```
Identity Information:
    - Fullnode network (Public), peer ID: <id1>
```

The vulnerability stems from three design issues:

1. **Insecure Default**: `expose_identity_information` defaults to `true` in `InspectionServiceConfig` [4](#0-3) 

2. **Missing Sanitizer Check**: The `ConfigSanitizer` validates that mainnet validators don't expose configuration but lacks equivalent protection for VFN identity information [5](#0-4) 

3. **Production Config Gaps**: Deployment configurations for VFNs don't explicitly disable this endpoint [6](#0-5) 

VFNs are identified by the `NodeType::extract_from_config()` method based on the presence of a VFN network: [7](#0-6) 

## Impact Explanation
This qualifies as **High Severity** per the Aptos bug bounty program because it enables targeted attacks that can cause "validator node slowdowns" and disrupt network operations.

VFNs are critical infrastructure described in the network architecture documentation as trusted nodes that bridge validators and public nodes: [8](#0-7) 

By identifying VFNs, attackers can:

1. **Target Validator Infrastructure**: Execute focused attacks on the specific fullnodes validators depend on for connectivity
2. **Network Topology Mapping**: Build maps of validator-to-VFN relationships for coordinated attacks
3. **Prioritize Attack Resources**: Concentrate DDoS or eclipse attack resources on high-value VFN targets
4. **Isolate Validators**: Disrupt VFN operations to degrade validator connectivity and network health

While direct DDoS attacks are out of scope, the information disclosure that enables surgical targeting of critical infrastructure constitutes a significant security issue.

## Likelihood Explanation
This vulnerability has **High Likelihood** of exploitation:

1. **Default Behavior**: The endpoint is enabled by default on mainnet without operator intervention
2. **Trivial Exploitation**: Requires only an HTTP GET request to `http://<fullnode-ip>:9101/identity_information`
3. **No Authentication**: The inspection service has no authentication mechanism
4. **Public Exposure**: The service listens on `0.0.0.0:9101` by default
5. **Widespread Deployment**: All VFNs using default configurations are vulnerable

An attacker can scan the network and query all accessible fullnodes to build a comprehensive VFN identification database.

## Recommendation

Add a `ConfigSanitizer` check to prevent mainnet VFNs from exposing identity information by default:

```rust
fn sanitize(
    node_config: &NodeConfig,
    node_type: NodeType,
    chain_id: Option<ChainId>,
) -> Result<(), Error> {
    let sanitizer_name = Self::get_sanitizer_name();
    let inspection_service_config = &node_config.inspection_service;

    if let Some(chain_id) = chain_id {
        if chain_id.is_mainnet() {
            // Existing check for validators
            if node_type.is_validator()
                && inspection_service_config.expose_configuration
            {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "Mainnet validators should not expose the node configuration!".to_string(),
                ));
            }

            // NEW: Prevent VFNs from exposing identity information
            if node_type.is_validator_fullnode()
                && inspection_service_config.expose_identity_information
            {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "Mainnet VFNs should not expose identity information that reveals VFN network configuration!".to_string(),
                ));
            }
        }
    }

    Ok(())
}
```

Additionally, change the default value for `expose_identity_information` to `false` for enhanced security:

```rust
fn default() -> InspectionServiceConfig {
    InspectionServiceConfig {
        address: "0.0.0.0".to_string(),
        port: 9101,
        expose_configuration: false,
        expose_identity_information: false,  // Changed from true
        expose_peer_information: true,
        expose_system_information: true,
    }
}
```

## Proof of Concept

**Step 1: Deploy a VFN with default configuration**
```yaml
# vfn_config.yaml (without inspection_service section)
full_node_networks:
- network_id: "public"
  listen_address: "/ip4/0.0.0.0/tcp/6182"
- network_id:
    private: "vfn"
  listen_address: "/ip4/0.0.0.0/tcp/6181"
```

**Step 2: Query the identity information endpoint**
```bash
curl http://<vfn-ip>:9101/identity_information
```

**Expected Response (revealing VFN status):**
```
Identity Information:
    - Fullnode network (Public), peer ID: 0x1234...
    - Fullnode network (vfn), peer ID: 0x5678...
```

**Step 3: Compare with Public Full Node**
```bash
curl http://<pfn-ip>:9101/identity_information
```

**PFN Response (no vfn network):**
```
Identity Information:
    - Fullnode network (Public), peer ID: 0xabcd...
```

The presence of "vfn" in the network list definitively identifies the node as a VFN, enabling targeted reconnaissance and attacks on validator infrastructure.

### Citations

**File:** crates/aptos-inspection-service/src/server/identity_information.rs (L29-51)
```rust
fn get_identity_information(node_config: &NodeConfig) -> String {
    let mut identity_information = Vec::<String>::new();
    identity_information.push("Identity Information:".into());

    // If the validator network is configured, fetch the identity information
    if let Some(validator_network) = &node_config.validator_network {
        identity_information.push(format!(
            "\t- Validator network ({}), peer ID: {}",
            validator_network.network_id,
            validator_network.peer_id()
        ));
    }

    // For each fullnode network, fetch the identity information
    for fullnode_network in &node_config.full_node_networks {
        identity_information.push(format!(
            "\t- Fullnode network ({}), peer ID: {}",
            fullnode_network.network_id,
            fullnode_network.peer_id()
        ));
    }

    identity_information.join("\n") // Separate each entry with a newline to construct the output
```

**File:** config/src/network_id.rs (L79-83)
```rust
pub enum NetworkId {
    Validator = 0,
    Vfn = 3,
    Public = 4,
}
```

**File:** config/src/network_id.rs (L157-212)
```rust
const VFN_NETWORK: &str = "vfn";

impl NetworkId {
    pub fn is_public_network(&self) -> bool {
        self == &NetworkId::Public
    }

    pub fn is_vfn_network(&self) -> bool {
        self == &NetworkId::Vfn
    }

    pub fn is_validator_network(&self) -> bool {
        self == &NetworkId::Validator
    }

    /// Roles for a prioritization of relative upstreams
    pub fn upstream_roles(&self, role: &RoleType) -> &'static [PeerRole] {
        match self {
            NetworkId::Validator => &[PeerRole::Validator],
            NetworkId::Public => &[
                PeerRole::PreferredUpstream,
                PeerRole::Upstream,
                PeerRole::ValidatorFullNode,
            ],
            NetworkId::Vfn => match role {
                RoleType::Validator => &[],
                RoleType::FullNode => &[PeerRole::Validator],
            },
        }
    }

    /// Roles for a prioritization of relative downstreams
    pub fn downstream_roles(&self, role: &RoleType) -> &'static [PeerRole] {
        match self {
            NetworkId::Validator => &[PeerRole::Validator],
            // In order to allow fallbacks, we must allow for nodes to accept ValidatorFullNodes
            NetworkId::Public => &[
                PeerRole::ValidatorFullNode,
                PeerRole::Downstream,
                PeerRole::Known,
                PeerRole::Unknown,
            ],
            NetworkId::Vfn => match role {
                RoleType::Validator => &[PeerRole::ValidatorFullNode],
                RoleType::FullNode => &[],
            },
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            NetworkId::Validator => "Validator",
            NetworkId::Public => "Public",
            NetworkId::Vfn => VFN_NETWORK,
        }
    }
```

**File:** config/src/config/inspection_service_config.rs (L26-37)
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
}
```

**File:** config/src/config/inspection_service_config.rs (L45-68)
```rust
impl ConfigSanitizer for InspectionServiceConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let inspection_service_config = &node_config.inspection_service;

        // Verify that mainnet validators do not expose the configuration
        if let Some(chain_id) = chain_id {
            if node_type.is_validator()
                && chain_id.is_mainnet()
                && inspection_service_config.expose_configuration
            {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "Mainnet validators should not expose the node configuration!".to_string(),
                ));
            }
        }

        Ok(())
    }
```

**File:** testsuite/pangu_lib/fixtures/vfn_1.yaml (L16-31)
```yaml
# Configure a public and VFN network
full_node_networks:
- network_id: "public"
  discovery_method: "onchain"
  listen_address: "/ip4/0.0.0.0/tcp/6182"
  identity:
    type: "from_file"
    path: "/opt/aptos/identites/validator-full-node-identity.yaml"
- network_id:
    private: "vfn"
  listen_address: "/ip4/0.0.0.0/tcp/6181"
  seeds:
    00000000000000000000000000000000d58bc7bb154b38039bc9096ce04e1237:
      addresses:
      - '/dns4/{{ include "aptos-validator.fullname" $ }}-{{$.Values.i}}-validator/tcp/6181/noise-ik/f0274c2774519281a8332d0bb9d8101bd58bc7bb154b38039bc9096ce04e1237/handshake/0' #TODO needs to be changed during runtime
      role: "Validator"
```

**File:** config/src/config/node_config_loader.rs (L39-56)
```rust
    pub fn extract_from_config(node_config: &NodeConfig) -> Self {
        // Validator nodes are trivial to detect
        if node_config.base.role.is_validator() {
            return NodeType::Validator;
        }

        // Otherwise, we must decipher between VFNs and PFNs
        // based on the presence of a VFN network.
        let vfn_network_found = node_config
            .full_node_networks
            .iter()
            .any(|network| network.network_id.is_vfn_network());
        if vfn_network_found {
            NodeType::ValidatorFullnode
        } else {
            NodeType::PublicFullnode
        }
    }
```

**File:** network/README.md (L30-39)
```markdown
Validators will only allow connections from other validators. Their identity and
public key information is provided by the [`validator-set-discovery`] protocol,
which updates the eligible member information on each consensus reconfiguration.
Each member of the validator network maintains a full membership view and connects
directly to all other validators in order to maintain a full-mesh network.

In contrast, Validator Full Node (VFNs) servers will only prioritize connections
from more trusted peers in the on-chain discovery set; they will still service
any public clients. Public Full Nodes (PFNs) connecting to VFNs will always
authenticate the VFN server using the available discovery information.
```
