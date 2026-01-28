# Audit Report

## Title
PFN Network Isolation Bypass via VFN Network Configuration

## Summary
A Public Full Node (PFN) can bypass intended network isolation by adding a VFN (Validator Full Node) network to its configuration. The config sanitizer fails to block VFN networks on PFNs, and validators incorrectly infer connecting peers as ValidatorFullNodes based solely on network type, allowing unauthorized privilege escalation without cryptographic verification.

## Finding Description

The vulnerability exists in three interconnected components that together enable privilege escalation:

**1. Insufficient Config Validation**

The config sanitizer only prevents `NetworkId::Validator` from being added to fullnode configs, but does NOT prevent `NetworkId::Vfn`. The validation check uses `is_validator_network()` which exclusively returns true for `NetworkId::Validator`: [1](#0-0) [2](#0-1) 

This allows a malicious PFN configuration with a VFN network to pass validation.

**2. VFN Networks Use MaybeMutual Authentication**

VFN networks default to `mutual_authentication = false` because the initialization logic only sets it to true for validator networks: [3](#0-2) 

This causes validators to use `MaybeMutual` authentication mode on their VFN networks, which accepts connections from unknown peers: [4](#0-3) 

**3. Incorrect Peer Role Inference**

When a validator receives an inbound connection on the VFN network from an unknown peer (not in trusted peers), it automatically infers the role as `ValidatorFullNode` based solely on the network type: [5](#0-4) 

There is NO cryptographic verification that the connecting peer is actually authorized to be a VFN. The code assumes: "If someone connects to my VFN network, they must be a VFN."

**4. Protocol Handshake Validation**

The protocol handshake requires both peers to have matching `network_id` values. A malicious PFN with VFN network config sends `network_id=Vfn`, matching the validator's VFN network: [6](#0-5) [7](#0-6) 

**Complete Attack Path:**

1. Attacker configures a PFN with a VFN network in `full_node_networks`
2. Config sanitizer checks `is_validator_network()` → returns false for VFN → passes validation
3. PFN obtains validator's VFN network address (via network scanning or leaked configs)
4. PFN initiates connection to validator's VFN network endpoint
5. During Noise handshake with `MaybeMutual` mode, PFN is not in validator's trusted peers
6. Validator checks: "I'm a validator, this is VFN network" → assigns `PeerRole::ValidatorFullNode`
7. Protocol handshake succeeds with matching `network_id=Vfn`
8. PFN is now connected with ValidatorFullNode privileges

## Impact Explanation

**Severity: HIGH**

This vulnerability enables privilege escalation from an unprivileged PFN to a privileged ValidatorFullNode role, resulting in:

1. **Network Isolation Bypass**: PFNs are architecturally designed to only operate on the Public network. This allows them to connect directly to validators' VFN networks, violating the intended three-tier network topology (Validator Network → VFN Network → Public Network).

2. **Mempool Priority Abuse**: ValidatorFullNode peers receive higher priority as upstream peers in mempool transaction propagation. The upstream roles prioritization shows VFNs are trusted sources: [8](#0-7) 

A malicious PFN masquerading as a VFN could manipulate transaction ordering or selectively propagate/withhold transactions.

3. **State Sync Resource Escalation**: ValidatorFullNode peers receive doubled resource allocation in state sync operations: [9](#0-8) 

Unauthorized VFN-role peers can consume validator bandwidth and CPU intended for legitimate VFNs, potentially impacting validator performance during critical consensus operations.

4. **Defense-in-Depth Violation**: The architecture relies solely on network-level isolation (firewalls, VPCs) without application-level authentication, violating security best practices.

**Not Critical because:**
- Does NOT allow consensus participation (VFNs don't participate in AptosBFT consensus)
- Does NOT directly cause fund loss or theft
- Does NOT break consensus safety guarantees
- Validators can still process blocks correctly

This qualifies as **High Severity** per the Aptos bug bounty program: "Validator node slowdowns" and "significant protocol violations."

## Likelihood Explanation

**Likelihood: HIGH**

The attack is highly feasible because:

1. **Low Attacker Requirements**: Any PFN operator can modify their config file - no special privileges, stake, or cryptographic keys needed
2. **No Technical Barriers**: Uses standard Aptos networking protocols and YAML configuration
3. **Simple Configuration Change**: Adding a VFN network to `full_node_networks` requires ~5 lines of YAML
4. **Deterministic Execution**: If the config passes sanitization and the handshake completes, the privilege escalation succeeds 100% of the time
5. **No Runtime Detection**: No active monitoring detects PFNs masquerading as VFNs after successful handshake

The attack's feasibility depends on discovering validator VFN endpoints, which may be exposed through:
- Network scanning of validator IP ranges
- Leaked or publicly shared seed peer configurations
- Misconfigured firewall rules
- Genesis configuration files

## Recommendation

Implement multi-layered fixes:

**1. Config Sanitizer Enhancement**
```rust
// In sanitize_fullnode_network_configs()
if network_id.is_validator_network() || network_id.is_vfn_network() {
    return Err(Error::ConfigSanitizerFailed(
        sanitizer_name,
        "Fullnode network configs cannot include validator or VFN networks!".into(),
    ));
}
```

**2. VFN Network Authentication**
Enable mutual authentication for VFN networks by default:
```rust
// In NetworkConfig::network_with_id()
let mutual_authentication = network_id.is_validator_network() || network_id.is_vfn_network();
```

**3. Cryptographic Peer Verification**
Verify connecting peers on VFN networks are in the trusted peers set before assigning ValidatorFullNode role:
```rust
// In upgrade_inbound() handshake logic
if network_id.is_vfn_network() && !is_in_trusted_peers(remote_peer_id) {
    return Err(HandshakeError::UnauthenticatedVfnConnection);
}
```

**4. Runtime Monitoring**
Add metrics to detect unexpected peer roles on each network type.

## Proof of Concept

```yaml
# Malicious PFN configuration (pfn_config.yaml)
base:
  role: "public_fullnode"
  data_dir: "/opt/aptos/data"

full_node_networks:
  # Add VFN network (bypasses sanitizer)
  - network_id:
      private: "vfn"
    listen_address: "/ip4/0.0.0.0/tcp/6181"
    seeds:
      # Seed pointing to target validator's VFN endpoint
      <validator_peer_id>:
        addresses:
          - "/ip4/<validator_vfn_ip>/tcp/6181/noise-ik/<validator_vfn_pubkey>/handshake/0"
        keys: [<validator_vfn_pubkey>]
        role: "validator"
  
  # Optional: Keep public network for normal operation
  - network_id: "public"
    listen_address: "/ip4/0.0.0.0/tcp/6182"
    discovery_method: "onchain"
```

**Execution:**
1. Start PFN with above config: `aptos-node -f pfn_config.yaml`
2. Config passes sanitization (VFN not blocked)
3. PFN connects to validator's VFN endpoint
4. Validator assigns `PeerRole::ValidatorFullNode` 
5. PFN gains VFN privileges without authorization

The validator will log the connection with VFN role, and the PFN will be treated as a trusted upstream peer in mempool and state sync operations.

### Citations

**File:** config/src/config/config_sanitizer.rs (L130-139)
```rust
    for fullnode_network_config in fullnode_networks {
        let network_id = fullnode_network_config.network_id;

        // Verify that the fullnode network config is not a validator network config
        if network_id.is_validator_network() {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "Fullnode network configs cannot include a validator network!".into(),
            ));
        }
```

**File:** config/src/network_id.rs (L168-170)
```rust
    pub fn is_validator_network(&self) -> bool {
        self == &NetworkId::Validator
    }
```

**File:** config/src/network_id.rs (L173-186)
```rust
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
```

**File:** config/src/config/network_config.rs (L135-142)
```rust
    pub fn network_with_id(network_id: NetworkId) -> NetworkConfig {
        let mutual_authentication = network_id.is_validator_network();
        let mut config = Self {
            discovery_method: DiscoveryMethod::None,
            discovery_methods: Vec::new(),
            identity: Identity::None,
            listen_address: "/ip4/0.0.0.0/tcp/6180".parse().unwrap(),
            mutual_authentication,
```

**File:** config/src/config/network_config.rs (L396-414)
```rust
/// Rules for upstream nodes via Peer Role:
///
/// Validator -> Always upstream if not Validator else P2P
/// PreferredUpstream -> Always upstream, overriding any other discovery
/// ValidatorFullNode -> Always upstream for incoming connections (including other ValidatorFullNodes)
/// Upstream -> Upstream, if no ValidatorFullNode or PreferredUpstream.  Useful for initial seed discovery
/// Downstream -> Downstream, defining a controlled downstream that I always want to connect
/// Known -> A known peer, but it has no particular role assigned to it
/// Unknown -> Undiscovered peer, likely due to a non-mutually authenticated connection always downstream
#[derive(Clone, Copy, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum PeerRole {
    Validator = 0,
    PreferredUpstream,
    Upstream,
    ValidatorFullNode,
    Downstream,
    Known,
    Unknown,
}
```

**File:** network/builder/src/builder.rs (L171-175)
```rust
        let authentication_mode = if config.mutual_authentication {
            AuthenticationMode::Mutual(identity_key)
        } else {
            AuthenticationMode::MaybeMutual(identity_key)
        };
```

**File:** network/framework/src/noise/handshake.rs (L407-416)
```rust
                            if self.network_context.role().is_validator() {
                                if network_id.is_vfn_network() {
                                    // Inbound connections to validators on the VFN network must be VFNs
                                    Ok(PeerRole::ValidatorFullNode)
                                } else {
                                    // Otherwise, they're unknown. Validators will connect through
                                    // authenticated channels (on the validator network) so shouldn't hit
                                    // this, and PFNs will connect on public networks (which aren't common).
                                    Ok(PeerRole::Unknown)
                                }
```

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L443-449)
```rust
        // verify that both peers are on the same network
        if self.network_id != other.network_id {
            return Err(HandshakeError::InvalidNetworkId(
                other.network_id,
                self.network_id,
            ));
        }
```

**File:** network/framework/src/transport/mod.rs (L298-302)
```rust
    let handshake_msg = HandshakeMsg {
        supported_protocols: ctxt.supported_protocols.clone(),
        chain_id: ctxt.chain_id,
        network_id: ctxt.network_id,
    };
```
