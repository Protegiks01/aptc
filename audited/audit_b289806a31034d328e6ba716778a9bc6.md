# Audit Report

## Title
Missing Network Address Validation in File-Based Peer Discovery Allows Malicious Peer Injection

## Summary
The `load_file()` function in the file-based peer discovery mechanism does not validate network addresses after YAML deserialization, allowing injection of arbitrary IP addresses and ports. This creates an inconsistent security posture where seed peers undergo strict validation while file discovery peers bypass all address validation checks.

## Finding Description

The file-based peer discovery system loads peer information from a YAML file and directly propagates it to the connectivity manager without validation. [1](#0-0) 

After YAML parsing, the `PeerSet` is returned directly without any validation of the network addresses it contains. This PeerSet flows through the discovery listener: [2](#0-1) 

The connectivity manager receives these peers and stores them without validation: [3](#0-2) 

The addresses are directly added to the internal peer state: [4](#0-3) 

In contrast, seed peers from the network configuration undergo strict validation: [5](#0-4) 

This `verify_address()` method checks that addresses conform to the proper AptosNet format using `is_aptosnet_addr()`. However, this validation is only applied to seed configuration: [6](#0-5) 

File discovery peers completely bypass this validation check.

**Attack Scenario:**
1. Attacker gains write access to the file discovery YAML file (through misconfiguration, operator error, or partial system compromise)
2. Attacker injects malicious peer entries with attacker-controlled IP addresses/ports
3. The node reloads the file at the configured interval
4. The malicious addresses are accepted without validation
5. The node attempts to connect to attacker-controlled endpoints
6. Attacker can perform man-in-the-middle attacks, intercept traffic, or disrupt network operations

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty program criteria for the following reasons:

**Security Impact:**
- Allows injection of malicious peer addresses that bypass validation
- Can lead to connections with attacker-controlled nodes
- Potential for network disruption and information disclosure
- Creates inconsistent security posture between different discovery methods

**Limitations:**
- Requires file system write access (not remotely exploitable)
- Assumes partial compromise or misconfiguration
- Does not directly lead to funds loss or consensus safety violations
- Can be mitigated with proper file permissions

The impact aligns with "State inconsistencies requiring intervention" and "Significant protocol violations" (Medium severity), as malicious peers could disrupt normal network operations but do not directly compromise consensus safety or cause funds loss.

## Likelihood Explanation

**Likelihood: Medium**

This vulnerability can occur in realistic scenarios:
- **Operator Error**: Misconfigured file permissions allowing unauthorized writes
- **Partial Compromise**: Attacker gains limited file system access without full node control
- **Configuration Mistakes**: Discovery file placed in world-writable location
- **Container Escape**: In containerized deployments, escape to host with file access

However, the likelihood is reduced by:
- Requires file system access (not network-exploitable)
- Proper deployment practices should restrict file permissions
- Most production deployments use on-chain discovery as primary method
- File discovery typically used for testing or backup scenarios

## Recommendation

**Implement validation for file discovery peers similar to seed peer validation:**

```rust
fn load_file(path: &Path) -> Result<PeerSet, DiscoveryError> {
    let contents = std::fs::read_to_string(path).map_err(DiscoveryError::IO)?;
    let peer_set: PeerSet = serde_yaml::from_str(&contents)
        .map_err(|err| DiscoveryError::Parsing(err.to_string()))?;
    
    // Validate all peer addresses
    for (peer_id, peer) in peer_set.iter() {
        for addr in peer.addresses.iter() {
            if !addr.is_aptosnet_addr() {
                return Err(DiscoveryError::Parsing(format!(
                    "Invalid address format for peer {}: {}",
                    peer_id, addr
                )));
            }
        }
        
        // Validate that peer has at least one public key
        if peer.keys.is_empty() && peer.addresses.is_empty() {
            return Err(DiscoveryError::Parsing(format!(
                "Peer {} has no public keys or addresses",
                peer_id
            )));
        }
    }
    
    Ok(peer_set)
}
```

This ensures consistent validation across all peer discovery methods and implements defense-in-depth principles.

## Proof of Concept

```rust
#[cfg(test)]
mod malicious_peer_injection_test {
    use super::*;
    use aptos_config::config::{Peer, PeerRole, PeerSet};
    use aptos_temppath::TempPath;
    use aptos_types::PeerId;
    use std::collections::HashSet;

    #[test]
    fn test_malicious_peer_injection() {
        // Create a malicious peer set with invalid addresses
        let mut malicious_peers = PeerSet::new();
        
        // This address should fail validation but currently doesn't
        let malicious_addr = "/ip4/192.168.1.1/tcp/6666".parse().unwrap();
        let peer = Peer::new(
            vec![malicious_addr],
            HashSet::new(),
            PeerRole::Upstream,
        );
        malicious_peers.insert(PeerId::random(), peer);
        
        // Write malicious peer set to file
        let path = TempPath::new();
        path.create_as_file().unwrap();
        let file_contents = serde_yaml::to_vec(&malicious_peers).unwrap();
        std::fs::write(path.as_ref(), file_contents).unwrap();
        
        // Current implementation accepts invalid addresses
        let result = load_file(path.as_ref());
        assert!(result.is_ok(), "Malicious peers were accepted without validation");
        
        // After fix, this should fail
        // assert!(result.is_err(), "Malicious peers should be rejected");
    }
}
```

## Notes

**Defense-in-Depth Consideration**: While this vulnerability requires file system access, implementing validation provides defense-in-depth protection against:
- Configuration errors
- Partial system compromises  
- Privilege escalation scenarios
- Accidental exposure of discovery files

**Consistency**: All peer discovery mechanisms should apply the same security controls. The current implementation creates an inconsistent security boundary where some discovery methods validate addresses while others do not.

### Citations

**File:** network/discovery/src/file.rs (L50-53)
```rust
fn load_file(path: &Path) -> Result<PeerSet, DiscoveryError> {
    let contents = std::fs::read_to_string(path).map_err(DiscoveryError::IO)?;
    serde_yaml::from_str(&contents).map_err(|err| DiscoveryError::Parsing(err.to_string()))
}
```

**File:** network/discovery/src/lib.rs (L141-149)
```rust
        while let Some(update) = source_stream.next().await {
            if let Ok(update) = update {
                trace!(
                    NetworkSchema::new(&network_context),
                    "{} Sending update: {:?}",
                    network_context,
                    update
                );
                let request = ConnectivityRequest::UpdateDiscoveredPeers(discovery_source, update);
```

**File:** network/framework/src/connectivity_manager/mod.rs (L886-898)
```rust
    fn handle_update_discovered_peers(
        &mut self,
        src: DiscoverySource,
        new_discovered_peers: PeerSet,
    ) {
        // Log the update event
        info!(
            NetworkSchema::new(&self.network_context),
            "{} Received updated list of discovered peers! Source: {:?}, num peers: {:?}",
            self.network_context,
            src,
            new_discovered_peers.len()
        );
```

**File:** network/framework/src/connectivity_manager/mod.rs (L958-970)
```rust
            // Update the peer's addresses
            if peer.addrs.update(src, discovered_peer.addresses) {
                info!(
                    NetworkSchema::new(&self.network_context).remote_peer(&peer_id),
                    network_addresses = &peer.addrs,
                    "{} addresses updated for peer: {}, update src: {:?}, addrs: {}",
                    self.network_context,
                    peer_id.short_str(),
                    src,
                    &peer.addrs,
                );
                peer_updated = true;
            }
```

**File:** config/src/config/network_config.rs (L306-316)
```rust
    fn verify_address(peer_id: &PeerId, addr: &NetworkAddress) -> Result<(), Error> {
        if !addr.is_aptosnet_addr() {
            return Err(Error::InvariantViolation(format!(
                "Unexpected seed peer address format: peer_id: {}, addr: '{}'",
                peer_id.short_str(),
                addr,
            )));
        }

        Ok(())
    }
```

**File:** network/builder/src/builder.rs (L473-474)
```rust
fn merge_seeds(config: &NetworkConfig) -> PeerSet {
    config.verify_seeds().expect("Seeds must be well formed");
```
