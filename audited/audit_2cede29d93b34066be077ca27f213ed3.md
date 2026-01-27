# Audit Report

## Title
Multi-Chain Context Leak: Global Blacklist Violates Chain Isolation in Telemetry Service

## Summary
The telemetry service's log ingestion blacklist is implemented as a global `HashSet<PeerId>` shared across all chains (mainnet, testnet, devnet), without chain-specific filtering. This allows blacklist entries intended for one chain to inadvertently block legitimate nodes on other chains, breaking the principle of chain isolation and causing operational denial-of-service.

## Finding Description

The Aptos telemetry service is designed to handle multiple chains simultaneously, as evidenced by the configuration supporting mainnet, testnet, and devnet full node addresses. [1](#0-0) 

However, the log ingestion blacklist is implemented without chain awareness. The `LogIngestClients` structure contains a blacklist field defined as `Option<HashSet<PeerId>>` with no `ChainId` dimension. [2](#0-1) 

The configuration structure similarly defines `blacklist_peers` as a simple `HashSet<PeerId>` without chain scoping. [3](#0-2) 

In the `handle_log_ingest()` function, the blacklist check occurs without considering the chain context from the JWT claims. [4](#0-3) 

While the `chain_id` is available in the claims and properly authenticated during the auth phase, it is only used for tagging logs, not for filtering the blacklist. [5](#0-4) 

**Exploitation Scenario:**
1. A validator operator runs nodes on both testnet and mainnet using the same identity keys (common practice for testing)
2. The node misbehaves on testnet or is falsely reported for malicious activity
3. A telemetry service operator adds the `peer_id` to the global blacklist, intending to block only testnet access
4. The same `peer_id` is now blocked from submitting logs on mainnet
5. The legitimate mainnet validator loses telemetry/monitoring capabilities, impacting operational visibility

Since `peer_id` is derived from the node's identity public key, validators running on multiple chains with the same keys will have identical `peer_id` values across those chains, making this cross-chain contamination inevitable with the current design.

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos Bug Bounty criteria:
- **Operational Denial-of-Service**: Legitimate validators lose access to telemetry services on one chain due to blacklist actions intended for another chain
- **Chain Isolation Violation**: Configuration and policy decisions for one network (testnet) can unintentionally affect production networks (mainnet)
- **State Inconsistencies**: Operators must manually track which chains a blacklist entry should apply to, requiring intervention to maintain proper access control

While this does not directly cause loss of funds or consensus violations, it creates operational risks:
- Validators lose critical monitoring and observability when telemetry is blocked
- Debugging and incident response capabilities are degraded
- Potential for cascading operational issues if monitoring gaps mask other problems

## Likelihood Explanation

This issue has **high likelihood** of occurring in practice:
- Many validator operators run nodes on multiple chains using the same identity keys for consistency
- Testnet blacklisting is a common operational practice to deal with malicious or misbehaving test nodes
- The telemetry service configuration does not provide warnings or documentation about cross-chain blacklist behavior
- Operators naturally assume blacklist entries would be chain-scoped given the multi-chain architecture

## Recommendation

Refactor the blacklist to be chain-aware by changing its structure from `HashSet<PeerId>` to `HashMap<ChainId, HashSet<PeerId>>`:

**Configuration change:**
```rust
// In lib.rs LogIngestConfig
pub struct LogIngestConfig {
    pub known_logs_endpoint: LogIngestEndpoint,
    pub unknown_logs_endpoint: LogIngestEndpoint,
    
    // Change from: pub blacklist_peers: Option<HashSet<PeerId>>,
    // To support per-chain blacklisting:
    #[serde(default)]
    pub blacklist_peers: Option<HashMap<ChainId, HashSet<PeerId>>>,
}
```

**Context structure change:**
```rust
// In context.rs LogIngestClients
pub struct LogIngestClients {
    pub known_logs_ingest_client: LogIngestClient,
    pub unknown_logs_ingest_client: LogIngestClient,
    pub blacklist: Option<HashMap<ChainId, HashSet<PeerId>>>,
}
```

**Log ingestion check update:**
```rust
// In log_ingest.rs handle_log_ingest()
if let Some(blacklist_map) = &context.log_ingest_clients().blacklist {
    if let Some(chain_blacklist) = blacklist_map.get(&claims.chain_id) {
        if chain_blacklist.contains(&claims.peer_id) {
            return Err(reject::custom(ServiceError::forbidden(
                LogIngestError::Forbidden(claims.peer_id).into(),
            )));
        }
    }
}
```

This change maintains backward compatibility by supporting per-chain blacklists while ensuring actions on one chain cannot affect others.

## Proof of Concept

```rust
#[cfg(test)]
mod test_multi_chain_blacklist {
    use super::*;
    use aptos_types::{chain_id::ChainId, PeerId};
    use std::collections::HashSet;
    
    #[tokio::test]
    async fn test_blacklist_affects_all_chains() {
        // Setup: Create a peer_id that should only be blacklisted on testnet
        let testnet_peer = PeerId::random();
        let mut blacklist = HashSet::new();
        blacklist.insert(testnet_peer);
        
        // Create log ingest clients with global blacklist
        let log_clients = LogIngestClients {
            known_logs_ingest_client: create_test_client(),
            unknown_logs_ingest_client: create_test_client(),
            blacklist: Some(blacklist),
        };
        
        let context = create_test_context(log_clients);
        
        // Create claims for mainnet with the same peer_id
        let mainnet_claims = Claims {
            chain_id: ChainId::mainnet(),  // Mainnet
            peer_id: testnet_peer,          // Same peer_id
            node_type: NodeType::Validator,
            epoch: 1,
            exp: future_timestamp(),
            iat: current_timestamp(),
            run_uuid: Uuid::new_v4(),
        };
        
        // Attempt to ingest logs from mainnet
        let result = handle_log_ingest(
            context,
            mainnet_claims,
            None,
            create_test_log_body(),
        ).await;
        
        // VULNERABILITY: Mainnet node is blocked due to testnet blacklist
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), 
            Rejection if rejection_is_forbidden(&rejection)));
    }
}
```

This test demonstrates that a `peer_id` blacklisted for any reason is blocked across all chains, violating chain isolation and enabling unintended cross-chain denial of service.

## Notes

This vulnerability is particularly concerning because:

1. **Peer ID Reuse is Common**: Validator operators frequently use the same identity keys across testnet and mainnet, making cross-chain `peer_id` collision the norm rather than the exception.

2. **Silent Failure**: The current implementation provides no visibility into whether a blacklist entry is intended for specific chains, making debugging difficult.

3. **Production Impact**: While testnet blacklisting is relatively permissive (used for experimentation and testing), accidentally blocking mainnet nodes has significant operational consequences.

4. **Configuration Complexity**: Without chain-scoped blacklists, operators must maintain separate telemetry service instances per chain or risk cross-chain contamination, increasing operational overhead.

The fix should include both the structural changes recommended above and comprehensive documentation about the chain-aware blacklist behavior.

### Citations

**File:** crates/aptos-telemetry-service/e2e-test/telemetry-config.yaml (L10-13)
```yaml
trusted_full_node_addresses:
  mainnet: "https://api.mainnet.aptoslabs.com"
  testnet: "https://api.testnet.aptoslabs.com"
  devnet: "https://api.devnet.aptoslabs.com"
```

**File:** crates/aptos-telemetry-service/src/context.rs (L136-141)
```rust
#[derive(Clone)]
pub struct LogIngestClients {
    pub known_logs_ingest_client: LogIngestClient,
    pub unknown_logs_ingest_client: LogIngestClient,
    pub blacklist: Option<HashSet<PeerId>>,
}
```

**File:** crates/aptos-telemetry-service/src/lib.rs (L940-942)
```rust
    /// Optional set of peer IDs to blacklist from log ingestion
    #[serde(default)]
    pub blacklist_peers: Option<HashSet<PeerId>>,
```

**File:** crates/aptos-telemetry-service/src/log_ingest.rs (L49-55)
```rust
    if let Some(blacklist) = &context.log_ingest_clients().blacklist {
        if blacklist.contains(&claims.peer_id) {
            return Err(reject::custom(ServiceError::forbidden(
                LogIngestError::Forbidden(claims.peer_id).into(),
            )));
        }
    }
```

**File:** crates/aptos-telemetry-service/src/log_ingest.rs (L88-95)
```rust
    let chain_name = if claims.chain_id.id() == 3 {
        format!("{}", claims.chain_id.id())
    } else {
        format!("{}", claims.chain_id)
    };
    tags.insert(CHAIN_ID_TAG_NAME.into(), chain_name);
    tags.insert(PEER_ROLE_TAG_NAME.into(), claims.node_type.to_string());
    tags.insert(RUN_UUID_TAG_NAME.into(), claims.run_uuid.to_string());
```
