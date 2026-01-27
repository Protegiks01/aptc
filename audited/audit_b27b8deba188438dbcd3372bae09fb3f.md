# Audit Report

## Title
Inspection Service Exposes Private Validator Network Architecture Without Sanitizer Protection on Mainnet

## Summary
The `get_identity_information()` function in the inspection service exposes both validator network and fullnode network (including private VFN) peer IDs and network IDs through an HTTP endpoint that binds to `0.0.0.0` by default and lacks sanitizer protection for mainnet validators, allowing external attackers to enumerate internal network architecture.

## Finding Description
The inspection service provides a `/identity_information` endpoint that exposes network identity information for debugging purposes. [1](#0-0) 

The function exposes both validator network and fullnode network information in a single response, including private VFN (Validator Full Node) network peer IDs that should remain separate from publicly accessible information.

The service binds to `0.0.0.0` (all network interfaces) by default [2](#0-1)  and the `expose_identity_information` flag defaults to `true` [3](#0-2) .

The critical issue is that while the sanitizer explicitly prevents mainnet validators from exposing the `/configuration` endpoint [4](#0-3) , there is **no corresponding sanitizer check** for `expose_identity_information`, creating an inconsistent security posture.

Validators run both validator networks (for consensus with other validators) and VFN networks (private connections to their fullnodes). [5](#0-4)  The VFN network uses a private network ID ("vfn") and is meant to be a trusted connection. [6](#0-5) 

While validators only allow connections from other validators on the validator network [7](#0-6) , the inspection service endpoint makes it trivial for external attackers to:

1. Enumerate which specific IP addresses run validator networks
2. Identify nodes running private VFN networks
3. Map the internal network architecture of validators
4. Correlate validator and VFN peer IDs for targeted reconnaissance

## Impact Explanation
This qualifies as **Medium severity** per the Aptos bug bounty criteria for the following reasons:

1. **Information Disclosure**: The endpoint exposes internal network architecture that aids attackers in reconnaissance, violating the **Access Control** invariant that system components should be protected.

2. **Inconsistent Security Controls**: The sanitizer protects `expose_configuration` on mainnet validators but not `expose_identity_information`, indicating a security oversight rather than deliberate design.

3. **Attack Surface Expansion**: While the information alone doesn't cause direct harm, it enables attackers to:
   - Identify and target specific validator infrastructure
   - Plan more sophisticated network-level attacks
   - Correlate on-chain validator addresses with off-chain network configurations

4. **Violation of Network Separation Principle**: The Aptos architecture explicitly separates validator and fullnode networks for security, but this endpoint mixes them together, undermining that separation.

This does not reach Critical or High severity because it doesn't directly cause fund loss, consensus violations, or service disruption, but exceeds Low severity due to the reconnaissance value and security control inconsistency.

## Likelihood Explanation
This vulnerability is **highly likely** to be exploited because:

1. **Default Configuration**: The endpoint is enabled by default (`expose_identity_information: true`) and the service binds to all interfaces (`0.0.0.0`).

2. **No Barriers to Entry**: Any attacker who can reach the HTTP endpoint (default port 9101) can query it without authentication.

3. **Automated Discovery**: Attackers can easily scan for exposed endpoints using automated tools.

4. **Realistic Scenario**: Validator operators may enable the inspection service for debugging without realizing the security implications, especially since only `expose_configuration` is explicitly blocked by the sanitizer on mainnet.

The optimizer automatically enables this endpoint for non-mainnet nodes [8](#0-7) , and operators may inadvertently leave it enabled when deploying to mainnet.

## Recommendation

Add a sanitizer check to prevent mainnet validators from exposing identity information, consistent with the existing protection for `expose_configuration`:

In `config/src/config/inspection_service_config.rs`, modify the `sanitize()` function to:

```rust
// Verify that mainnet validators do not expose the configuration
if let Some(chain_id) = chain_id {
    if node_type.is_validator() && chain_id.is_mainnet() {
        if inspection_service_config.expose_configuration {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "Mainnet validators should not expose the node configuration!".to_string(),
            ));
        }
        
        // Add this new check:
        if inspection_service_config.expose_identity_information {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "Mainnet validators should not expose network identity information!".to_string(),
            ));
        }
    }
}
```

Additionally, consider:
1. Changing the default binding address to `127.0.0.1` instead of `0.0.0.0` for production deployments
2. Separating validator and fullnode network information into distinct endpoints with separate access controls
3. Updating documentation to warn operators about the security implications of exposing this endpoint

## Proof of Concept

**Attack Scenario:**
1. Attacker identifies a mainnet validator node (e.g., from on-chain validator set)
2. Attacker queries the inspection service endpoint:
   ```bash
   curl http://<validator-ip>:9101/identity_information
   ```
3. Response reveals both validator and VFN network information:
   ```
   Identity Information:
       - Validator network (Validator), peer ID: <validator_peer_id>
       - Fullnode network (Vfn), peer ID: <vfn_peer_id>
   ```
4. Attacker now knows:
   - This specific IP is running a validator node
   - The exact peer IDs for both validator and VFN networks
   - The internal network architecture of this validator

**Reproduction Steps:**
1. Set up a validator node with default inspection service configuration
2. Ensure `expose_identity_information: true` (the default)
3. Query the endpoint from a remote machine:
   ```bash
   curl http://<validator-ip>:9101/identity_information
   ```
4. Observe that both validator and fullnode network information is returned without authentication

**Expected vs. Actual Behavior:**
- **Expected**: Mainnet validators should not expose identity information by default, protected by sanitizer
- **Actual**: Sanitizer allows `expose_identity_information: true` on mainnet validators, only blocking `expose_configuration`

## Notes

This vulnerability represents an **inconsistency in security controls** rather than a catastrophic failure. The sanitizer's protection of `expose_configuration` but not `expose_identity_information` suggests this is an oversight. While peer IDs are available on-chain, the inspection endpoint makes reconnaissance trivial and exposes the relationship between validator and VFN networks, which should remain architecturally separate per the Aptos security model.

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

**File:** config/src/config/inspection_service_config.rs (L54-64)
```rust
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
```

**File:** config/src/config/inspection_service_config.rs (L90-92)
```rust
                if local_inspection_config_yaml["expose_identity_information"].is_null() {
                    inspection_service_config.expose_identity_information = true;
                    modified_config = true;
```

**File:** config/src/config/test_data/validator.yaml (L21-38)
```yaml
# For validator node we setup two networks, validator_network to allow validator connect to each other,
# and full_node_networks to allow fullnode connects to validator.

full_node_networks:
    - listen_address: "/ip4/0.0.0.0/tcp/6181"
      max_outbound_connections: 0
      identity:
          type: "from_storage"
          key_name: "fullnode_network"
          peer_id_name: "owner_account"
          backend:
              type: "vault"
              server: "https://127.0.0.1:8200"
              ca_certificate: "/full/path/to/certificate"
              token:
                  from_disk: "/full/path/to/token"
      network_id:
          private: "vfn"
```

**File:** config/src/config/test_data/validator_full_node.yaml (L15-16)
```yaml
# For validator fullnode we setup two network ids, the private "vfn" identity will allow it to connect to the validator node,
# and the public identity will allow it to connects to other fullnodes onchain.
```

**File:** network/README.md (L30-34)
```markdown
Validators will only allow connections from other validators. Their identity and
public key information is provided by the [`validator-set-discovery`] protocol,
which updates the eligible member information on each consensus reconfiguration.
Each member of the validator network maintains a full membership view and connects
directly to all other validators in order to maintain a full-mesh network.
```
