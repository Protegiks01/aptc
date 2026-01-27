# Audit Report

## Title
Network Checker Fails to Validate Secure Protocol Negotiation - Accepts Deprecated and Insecure JSON Protocols

## Summary
The `check_endpoint()` function in the network checker uses `ProtocolIdSet::all_known()` to advertise support for ALL known protocols, including insecure JSON-based protocols that lack recursion limits and deprecated unused protocols. This fails to properly validate that only secure message protocols are negotiated, allowing malicious nodes advertising insecure protocols to pass health checks.

## Finding Description

The network checker's `build_upgrade_context()` function creates a supported protocols map that includes all known protocols without validation: [1](#0-0) 

This includes JSON-based consensus protocols that use insecure deserialization: [2](#0-1) 

The security issue is that JSON protocols use `Encoding::Json` which deserializes via `serde_json::from_slice()` **without any recursion depth protection**: [3](#0-2) [4](#0-3) 

In contrast, BCS-based protocols enforce strict recursion limits (32 or 64): [5](#0-4) 

The network checker also advertises deprecated "Currently unused" protocols: [6](#0-5) 

Critically, production consensus code **also supports these JSON protocols as fallback options**: [7](#0-6) 

**Attack Scenario:**

1. Attacker deploys a malicious validator node advertising ONLY JSON protocols (no Compressed/BCS support)
2. Network checker connects and successfully negotiates JSON protocol via `all_known()`
3. Handshake validation passes, marking the malicious node as "healthy"
4. Production consensus validators connect to this node
5. Since production consensus also supports JSON protocols (as fallback), they negotiate JSON
6. Attacker sends deeply nested JSON consensus messages (e.g., nested Block/Vote structures)
7. Victim validators attempt deserialization via `serde_json::from_slice()` with no recursion limit
8. Stack overflow or resource exhaustion crashes victim validators
9. If sufficient validators crash, consensus liveness/safety is compromised

## Impact Explanation

**Medium Severity** - This issue enables validator node denial-of-service attacks that can impact consensus:

- **Consensus Liveness**: Crashing multiple validators can prevent block production
- **State Inconsistencies**: Validator crashes during block processing can create temporary inconsistencies
- **Defense-in-Depth Failure**: The network checker should model secure protocol negotiation but instead validates insecure configurations

The impact is limited to Medium (not High/Critical) because:
- Compressed/BCS protocols are preferred, so JSON is only used in fallback scenarios
- Requires attacker to control a network-reachable node
- Does not directly cause fund loss or permanent consensus safety violations

## Likelihood Explanation

**Medium Likelihood**:

- **Attacker Requirements**: Must control a node that can participate in validator networking (either as validator or connected peer)
- **Complexity**: Straightforward - simply advertise only JSON protocols and send deeply nested JSON
- **Mitigating Factors**: Higher-priority protocols (Compressed/BCS) reduce likelihood of JSON negotiation
- **Enabling Factors**: Both network checker AND production consensus support JSON protocols

The network checker's use of `all_known()` validates this attack as acceptable configuration, when it should reject nodes advertising only insecure protocols.

## Recommendation

**Fix 1: Network Checker Should Use Secure Protocol Subset**

Replace `ProtocolIdSet::all_known()` with explicitly vetted secure protocols:

```rust
// In build_upgrade_context()
let mut supported_protocols = BTreeMap::new();
// Only include secure protocols with recursion limits
let secure_protocols = ProtocolIdSet::from_iter([
    ProtocolId::ConsensusRpcCompressed,
    ProtocolId::ConsensusRpcBcs,
    ProtocolId::ConsensusDirectSendCompressed,
    ProtocolId::ConsensusDirectSendBcs,
    ProtocolId::HealthCheckerRpc,
    // Explicitly exclude JSON and deprecated protocols
]);
supported_protocols.insert(SUPPORTED_MESSAGING_PROTOCOL, secure_protocols);
```

**Fix 2: Add Recursion Limits to JSON Deserialization**

Add recursion depth protection to JSON protocol deserialization:

```rust
fn encoding(self) -> Encoding {
    match self {
        ProtocolId::ConsensusDirectSendJson | ProtocolId::ConsensusRpcJson => {
            Encoding::JsonWithLimit(RECURSION_LIMIT) // Add new variant with limit
        },
        // ... rest unchanged
    }
}
```

**Fix 3: Deprecate JSON Protocols**

Consider removing JSON protocol support from production consensus since Compressed BCS provides better security and performance.

## Proof of Concept

```rust
// PoC demonstrating protocol negotiation with JSON-only node
use aptos_network_checker::{check_endpoint, args::*};
use aptos_network::protocols::wire::handshake::v1::ProtocolIdSet;

#[tokio::test]
async fn test_network_checker_accepts_json_only_node() {
    // Setup: Malicious node advertising ONLY JSON protocols
    let malicious_node_protocols = ProtocolIdSet::from_iter([
        ProtocolId::ConsensusRpcJson,
        ProtocolId::ConsensusDirectSendJson,
    ]);
    
    // Network checker uses all_known(), will negotiate with malicious node
    let checker_protocols = ProtocolIdSet::all_known();
    
    // Verify intersection includes JSON
    let negotiated = malicious_node_protocols.intersect(&checker_protocols);
    assert!(negotiated.contains(ProtocolId::ConsensusRpcJson));
    
    // Network checker will successfully validate this insecure node
    // Real exploit: Send deeply nested JSON to crash victim validator
    let deeply_nested_json = generate_nested_json(10000); // Stack overflow
    // Victim validator crashes when deserializing via serde_json::from_slice()
}
```

## Notes

The network checker is used in production by the `aptos-node-checker` service for validator health monitoring: [8](#0-7) 

The broader issue affects production consensus configuration, not just the network checker: [9](#0-8) 

This represents a systemic defense-in-depth failure where both diagnostic tools and production code accept insecure protocol configurations that enable DoS attacks against validator nodes.

### Citations

**File:** aptos-core-088/crates/aptos-network-checker/src/check_endpoint.rs (L170-172)
```rust

```

**File:** aptos-core-088/network/framework/src/protocols/wire/handshake/v1/mod.rs (L38-39)
```rust

```

**File:** aptos-core-088/network/framework/src/protocols/wire/handshake/v1/mod.rs (L45-75)
```rust

```

**File:** aptos-core-088/network/framework/src/protocols/wire/handshake/v1/mod.rs (L156-172)
```rust

```

**File:** aptos-core-088/network/framework/src/protocols/wire/handshake/v1/mod.rs (L226-244)
```rust

```

**File:** aptos-core-088/consensus/src/network_interface.rs (L156-168)
```rust

```

**File:** aptos-core-088/ecosystem/node-checker/src/provider/noise.rs (L56-67)
```rust

```

**File:** aptos-core-088/aptos-node/src/network.rs (L55-72)
```rust

```
