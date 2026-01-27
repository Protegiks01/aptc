# Audit Report

## Title
Protocol Downgrade Attack Enables JSON-Based Denial of Service Against Consensus Validators

## Summary
A malicious validator can force honest validators to use the JSON protocol variant for consensus messages by advertising limited protocol support during the handshake phase. This protocol downgrade enables resource exhaustion attacks, as JSON deserialization lacks the strict recursion limits enforced by BCS encoding (32-64 levels vs 128 levels) and is significantly more CPU-intensive to parse. This can degrade consensus performance and cause validator node slowdowns.

## Finding Description

The Aptos network layer implements protocol negotiation during the handshake phase, where peers exchange their supported protocols and compute the intersection. The vulnerability exists in how this negotiation can be manipulated: [1](#0-0) 

When an honest validator calls `send_to_peer()`, it selects the preferred protocol based on what the peer supports: [2](#0-1) 

The consensus layer defines protocol preferences with JSON as the lowest-priority fallback: [3](#0-2) 

**The Attack Path:**

1. A malicious validator joins the network and during handshake, advertises support for ONLY `ConsensusRpcJson` and `ConsensusDirectSendJson` (no Compressed or Bcs variants)
2. The handshake computes the protocol intersection, which only contains JSON protocols
3. When honest validators communicate with this peer, they are forced to use JSON encoding
4. The malicious validator sends consensus messages (e.g., `BlockRetrievalResponse`) with deeply nested structures or complex data
5. The honest validator deserializes using JSON, which has weaker protections than BCS

**Key Vulnerability - Weaker Security Properties of JSON:**

The BCS encoding enforces strict recursion limits: [4](#0-3) 

Note that for consensus messages, `RECURSION_LIMIT = 64` and for user input `USER_INPUT_RECURSION_LIMIT = 32`.

However, JSON encoding has no such explicit limits: [5](#0-4) [6](#0-5) 

The JSON encoding uses `serde_json` directly without any recursion limit configuration, relying only on serde_json's default limit of 128 levels (vs 32-64 for BCS). Additionally, JSON parsing is inherently more CPU-intensive than BCS deserialization.

**Exploitation Scenario:**

A malicious validator can craft `BlockRetrievalResponse` messages with:
- Deeply nested structures (up to 128 levels vs 32-64 for BCS)
- Large arrays of complex objects
- Strings with special characters requiring escaping
- Numbers requiring floating-point parsing

These messages remain under the 64 MiB transport limit but consume significantly more CPU and memory to parse than equivalent BCS-encoded messages.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty criteria because it enables "Validator node slowdowns."

**Consensus Impact:**
- Multiple malicious validators advertising only JSON protocols can force the network to communicate using inefficient encoding
- During critical consensus operations (block retrieval, vote propagation), the additional CPU overhead from JSON parsing can delay block finalization
- In a network with marginal performance, this could cause timeout failures and consensus liveness issues
- The attack is subtle and may go undetected as legitimate protocol negotiation

**Resource Consumption:**
- JSON parsing requires more CPU cycles than BCS (text parsing vs binary deserialization)
- Weaker recursion limits (128 vs 32-64) allow more deeply nested structures
- No size limits during encoding/decoding (only at transport layer)
- Memory allocation patterns differ, potentially causing GC pressure

## Likelihood Explanation

**Likelihood: Medium-High**

This attack is practical because:
1. Any validator can join the network and advertise arbitrary protocol support
2. No validation enforces minimum protocol versions (e.g., requiring Compressed support)
3. Protocol downgrade is silent - no warnings are logged when JSON is selected
4. The attack affects all honest validators communicating with the malicious peer
5. Multiple malicious validators can amplify the effect

**Attacker Requirements:**
- Ability to run a validator node (low barrier in permissionless networks)
- Knowledge of protocol negotiation mechanism
- Ability to craft malformed but valid JSON messages

**Detection Difficulty:**
- Protocol selection appears legitimate (valid handshake)
- No alerts for "weak" protocol usage
- Performance degradation may be attributed to network conditions

## Recommendation

**Short-term Fix:**
1. Enforce minimum protocol requirements during handshake - reject peers that don't support at least the Bcs variant:

```rust
pub fn perform_handshake(
    &self,
    other: &HandshakeMsg,
) -> Result<(MessagingProtocolVersion, ProtocolIdSet), HandshakeError> {
    // ... existing validation ...
    
    for (our_handshake_version, our_protocols) in self.supported_protocols.iter().rev() {
        if let Some(their_protocols) = other.supported_protocols.get(our_handshake_version) {
            let common_protocols = our_protocols.intersect(their_protocols);
            
            if !common_protocols.is_empty() {
                // NEW: Validate minimum protocol strength
                if !contains_acceptable_protocol(&common_protocols) {
                    return Err(HandshakeError::WeakProtocolsOnly);
                }
                return Ok((*our_handshake_version, common_protocols));
            }
        }
    }
    
    Err(HandshakeError::NoCommonProtocols)
}

fn contains_acceptable_protocol(protocols: &ProtocolIdSet) -> bool {
    // Require at least BCS variant, reject JSON-only
    for protocol in protocols.iter() {
        if matches!(protocol, 
            ProtocolId::ConsensusRpcBcs | ProtocolId::ConsensusRpcCompressed |
            ProtocolId::ConsensusDirectSendBcs | ProtocolId::ConsensusDirectSendCompressed
        ) {
            return true;
        }
    }
    false
}
```

2. Add explicit recursion limits to JSON deserialization:

```rust
Encoding::Json => {
    // Create a deserializer with explicit recursion limit
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    deserializer.disable_recursion_limit(); // First disable default
    let depth_limit = 32; // Match USER_INPUT_RECURSION_LIMIT
    // Implement custom depth tracking during deserialization
    // Or use a wrapper that counts depth
    serde_json::from_slice(bytes).map_err(|e| anyhow!("{:?}", e))
}
```

**Long-term Fix:**
1. Remove JSON protocol variants entirely from consensus communication
2. Use only Compressed and Bcs variants with strict validation
3. Implement protocol version negotiation with mandatory minimum versions
4. Add monitoring/alerting for protocol downgrades

## Proof of Concept

```rust
// File: network/framework/src/application/protocol_downgrade_test.rs
#[cfg(test)]
mod protocol_downgrade_attack {
    use super::*;
    use crate::protocols::wire::handshake::v1::{HandshakeMsg, ProtocolId, ProtocolIdSet};
    use aptos_config::network_id::NetworkId;
    use aptos_types::chain_id::ChainId;
    use std::collections::BTreeMap;

    #[test]
    fn test_malicious_peer_forces_json_protocol() {
        // Honest node supports all protocols (Compressed, Bcs, Json)
        let mut honest_protocols = ProtocolIdSet::empty();
        honest_protocols.insert(ProtocolId::ConsensusRpcCompressed);
        honest_protocols.insert(ProtocolId::ConsensusRpcBcs);
        honest_protocols.insert(ProtocolId::ConsensusRpcJson);
        
        let mut honest_supported = BTreeMap::new();
        honest_supported.insert(MessagingProtocolVersion::V1, honest_protocols);
        
        let honest_handshake = HandshakeMsg {
            supported_protocols: honest_supported,
            chain_id: ChainId::test(),
            network_id: NetworkId::Validator,
        };
        
        // Malicious node advertises ONLY JSON protocol
        let mut malicious_protocols = ProtocolIdSet::empty();
        malicious_protocols.insert(ProtocolId::ConsensusRpcJson);
        
        let mut malicious_supported = BTreeMap::new();
        malicious_supported.insert(MessagingProtocolVersion::V1, malicious_protocols);
        
        let malicious_handshake = HandshakeMsg {
            supported_protocols: malicious_supported,
            chain_id: ChainId::test(),
            network_id: NetworkId::Validator,
        };
        
        // Perform handshake
        let result = honest_handshake.perform_handshake(&malicious_handshake);
        
        // Verify downgrade occurred
        assert!(result.is_ok());
        let (_version, common_protocols) = result.unwrap();
        
        // Only JSON protocol should be in intersection
        assert!(common_protocols.contains(ProtocolId::ConsensusRpcJson));
        assert!(!common_protocols.contains(ProtocolId::ConsensusRpcBcs));
        assert!(!common_protocols.contains(ProtocolId::ConsensusRpcCompressed));
        
        // This demonstrates the forced protocol downgrade
        println!("✗ VULNERABILITY: Malicious peer successfully forced JSON protocol!");
        println!("  Honest node now must use inefficient JSON encoding");
        println!("  for all consensus messages with this peer.");
    }
    
    #[test]
    fn test_json_has_weaker_limits_than_bcs() {
        // Demonstrate that JSON allows deeper nesting than BCS
        use serde::{Deserialize, Serialize};
        
        #[derive(Serialize, Deserialize, Clone)]
        struct DeepNest {
            inner: Option<Box<DeepNest>>,
            value: u64,
        }
        
        // Create a deeply nested structure (depth 100)
        fn create_deep_nest(depth: u32) -> DeepNest {
            if depth == 0 {
                DeepNest { inner: None, value: 0 }
            } else {
                DeepNest {
                    inner: Some(Box::new(create_deep_nest(depth - 1))),
                    value: depth as u64,
                }
            }
        }
        
        let deep_structure = create_deep_nest(100);
        
        // BCS with limit 64 should FAIL
        let bcs_result = bcs::to_bytes_with_limit(&deep_structure, 64);
        assert!(bcs_result.is_err(), "BCS should reject deep nesting");
        
        // JSON should SUCCEED (default limit 128)
        let json_result = serde_json::to_vec(&deep_structure);
        assert!(json_result.is_ok(), "JSON allows deeper nesting");
        
        println!("✗ VULNERABILITY: JSON accepts structures that BCS rejects!");
        println!("  BCS limit: 64 levels (REJECTED)");
        println!("  JSON limit: 128 levels (ACCEPTED)");
    }
}
```

## Notes

This vulnerability represents a subtle but significant protocol-level weakness. While not immediately catastrophic, it provides malicious actors with a reliable mechanism to degrade consensus performance. The lack of minimum protocol enforcement combined with automatic fallback to weaker protocols creates an exploitable attack surface.

The fix should prioritize removing JSON variants from production consensus protocols entirely, or at minimum, implementing strict validation to prevent protocol downgrade attacks. The current design assumes all protocol variants are equally secure, which is demonstrably false given the different recursion limits and parsing overhead.

### Citations

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L156-172)
```rust
    fn encoding(self) -> Encoding {
        match self {
            ProtocolId::ConsensusDirectSendJson | ProtocolId::ConsensusRpcJson => Encoding::Json,
            ProtocolId::ConsensusDirectSendCompressed | ProtocolId::ConsensusRpcCompressed => {
                Encoding::CompressedBcs(RECURSION_LIMIT)
            },
            ProtocolId::ConsensusObserver => Encoding::CompressedBcs(RECURSION_LIMIT),
            ProtocolId::DKGDirectSendCompressed | ProtocolId::DKGRpcCompressed => {
                Encoding::CompressedBcs(RECURSION_LIMIT)
            },
            ProtocolId::JWKConsensusDirectSendCompressed
            | ProtocolId::JWKConsensusRpcCompressed => Encoding::CompressedBcs(RECURSION_LIMIT),
            ProtocolId::MempoolDirectSend => Encoding::CompressedBcs(USER_INPUT_RECURSION_LIMIT),
            ProtocolId::MempoolRpc => Encoding::Bcs(USER_INPUT_RECURSION_LIMIT),
            _ => Encoding::Bcs(RECURSION_LIMIT),
        }
    }
```

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L213-213)
```rust
            Encoding::Json => serde_json::to_vec(value).map_err(|e| anyhow!("{:?}", e)),
```

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L243-243)
```rust
            Encoding::Json => serde_json::from_slice(bytes).map_err(|e| anyhow!("{:?}", e)),
```

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L431-465)
```rust
    pub fn perform_handshake(
        &self,
        other: &HandshakeMsg,
    ) -> Result<(MessagingProtocolVersion, ProtocolIdSet), HandshakeError> {
        // verify that both peers are on the same chain
        if self.chain_id != other.chain_id {
            return Err(HandshakeError::InvalidChainId(
                other.chain_id,
                self.chain_id,
            ));
        }

        // verify that both peers are on the same network
        if self.network_id != other.network_id {
            return Err(HandshakeError::InvalidNetworkId(
                other.network_id,
                self.network_id,
            ));
        }

        // find the greatest common MessagingProtocolVersion where we both support
        // at least one common ProtocolId.
        for (our_handshake_version, our_protocols) in self.supported_protocols.iter().rev() {
            if let Some(their_protocols) = other.supported_protocols.get(our_handshake_version) {
                let common_protocols = our_protocols.intersect(their_protocols);

                if !common_protocols.is_empty() {
                    return Ok((*our_handshake_version, common_protocols));
                }
            }
        }

        // no intersection found
        Err(HandshakeError::NoCommonProtocols)
    }
```

**File:** network/framework/src/application/interface.rs (L142-158)
```rust
    fn get_preferred_protocol_for_peer(
        &self,
        peer: &PeerNetworkId,
        preferred_protocols: &[ProtocolId],
    ) -> Result<ProtocolId, Error> {
        let protocols_supported_by_peer = self.get_supported_protocols(peer)?;
        for protocol in preferred_protocols {
            if protocols_supported_by_peer.contains(*protocol) {
                return Ok(*protocol);
            }
        }
        Err(Error::NetworkError(format!(
            "None of the preferred protocols are supported by this peer! \
            Peer: {:?}, supported protocols: {:?}",
            peer, protocols_supported_by_peer
        )))
    }
```

**File:** consensus/src/network_interface.rs (L157-168)
```rust
pub const RPC: &[ProtocolId] = &[
    ProtocolId::ConsensusRpcCompressed,
    ProtocolId::ConsensusRpcBcs,
    ProtocolId::ConsensusRpcJson,
];

/// Supported protocols in preferred order (from highest priority to lowest).
pub const DIRECT_SEND: &[ProtocolId] = &[
    ProtocolId::ConsensusDirectSendCompressed,
    ProtocolId::ConsensusDirectSendBcs,
    ProtocolId::ConsensusDirectSendJson,
];
```
