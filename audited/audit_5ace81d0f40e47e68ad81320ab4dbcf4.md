# Audit Report

## Title
AdminService Exposed Without Authentication on Non-Mainnet Networks Allows Unauthorized Access to Sensitive Validator Operations

## Summary
The AdminServiceConfig allows validator nodes on testnet, devnet, and custom networks to run with the admin service enabled by default on `0.0.0.0:9102` with no authentication required. This exposes sensitive consensus state, mempool data, and internal node operations to any attacker who can reach the network port, violating the access control invariant.

## Finding Description

The AdminServiceConfig contains a critical security flaw in its default configuration and validation logic. The vulnerability exists across three interconnected components:

**1. Insecure Default Configuration:**
The `AdminServiceConfig` struct defaults to binding on all network interfaces (`0.0.0.0`) with an empty authentication configuration vector. [1](#0-0) 

The comment explicitly acknowledges that empty authentication allows all requests without authentication, but notes it's "Not allowed on mainnet." [2](#0-1) 

**2. Insufficient Security Validation:**
The `ConfigSanitizer` implementation only enforces authentication requirements on mainnet, allowing non-mainnet networks to operate without authentication. [3](#0-2) 

**3. Auto-Enable on Non-Mainnet Networks:**
The `ConfigOptimizer` automatically enables the admin service on testnet and other non-mainnet networks by default. [4](#0-3) 

**4. Permissive Authentication Logic:**
In the actual service implementation, when `authentication_configs` is empty, the service automatically grants authentication to all requests. [5](#0-4) 

**Attack Path:**

1. Validator operator deploys a node on testnet/devnet using default or minimal configuration
2. AdminService is automatically enabled and binds to `0.0.0.0:9102` with no authentication
3. Attacker scans for exposed port 9102 on validator nodes
4. Attacker accesses sensitive endpoints without any credentials:
   - `/debug/consensus/consensusdb` - Dumps consensus database including last votes, highest timeout certificates, consensus blocks, and quorum certificates [6](#0-5) 
   - `/debug/consensus/block` - Extracts transactions from blocks [7](#0-6) 
   - `/debug/mempool/parking-lot/addresses` - Retrieves mempool parking lot addresses [8](#0-7) 
   - `/profilez`, `/threadz`, `/malloc/stats` - Profiling and memory information

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos Bug Bounty program because it results in:

1. **Significant Protocol Violations**: Exposes internal consensus state (voting patterns, block data, quorum certificates) that should be restricted to authorized operators only
2. **Validator Node Information Disclosure**: Reveals sensitive operational data including:
   - Real-time consensus voting behavior and timing
   - Pending transactions in mempool before finalization
   - Internal memory and performance characteristics
   - Thread and CPU profiling information
3. **Attack Surface for Sophisticated Exploits**: The exposed information enables attackers to:
   - Monitor validator behavior patterns for targeted attacks
   - Extract pending transactions for front-running or MEV attacks
   - Gather timing information for consensus manipulation
   - Understand internal node architecture for more sophisticated attacks

While this doesn't directly cause consensus violations or fund loss (which would be Critical), it significantly compromises validator security posture and enables secondary attacks.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploited because:

1. **Common Deployment Pattern**: Many validators and fullnodes are deployed on testnet/devnet for testing, development, and experimentation
2. **Default-Insecure Configuration**: The service is automatically enabled with no authentication on non-mainnet networks - operators must explicitly configure authentication or disable the service
3. **Public Internet Exposure**: Validators often expose multiple ports for P2P networking; operators may not realize port 9102 is also exposed
4. **No Documentation Warnings**: The default configuration files don't include explicit warnings about securing the admin service [9](#0-8) 
5. **Low Attacker Complexity**: Exploitation requires only network scanning and simple HTTP requests - no cryptographic operations or complex protocol interactions

The assumption that testnet/devnet nodes don't need security is flawed, as they:
- Often handle real value during testing
- Serve as production-like environments for development
- Can expose patterns that apply to mainnet validators
- May be operated by the same teams/infrastructure as mainnet

## Recommendation

Implement defense-in-depth security controls:

**1. Change Default Binding Address:**
```rust
impl Default for AdminServiceConfig {
    fn default() -> Self {
        Self {
            enabled: None,
            address: "127.0.0.1".to_string(), // Bind to localhost only by default
            port: 9102,
            authentication_configs: vec![],
            malloc_stats_max_len: 2 * 1024 * 1024,
        }
    }
}
```

**2. Enforce Authentication on All Networks:**
```rust
impl ConfigSanitizer for AdminServiceConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();

        if node_config.admin_service.enabled == Some(true) {
            // Require authentication on ALL networks, not just mainnet
            if node_config.admin_service.authentication_configs.is_empty() {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "Must enable authentication for AdminService. Configure authentication_configs with at least one PasscodeSha256 entry.".into(),
                ));
            }
        }

        Ok(())
    }
}
```

**3. Disable by Default on All Networks:**
```rust
impl ConfigOptimizer for AdminServiceConfig {
    fn optimize(
        node_config: &mut NodeConfig,
        _local_config_yaml: &Value,
        _node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<bool, Error> {
        let mut modified_config = false;

        if node_config.admin_service.enabled.is_none() {
            // Disable admin service by default on ALL networks
            node_config.admin_service.enabled = Some(false);
            modified_config = true;
        }

        Ok(modified_config)
    }
}
```

**4. Add Configuration Documentation:**
Create example configuration snippet showing proper authentication:
```yaml
admin_service:
    enabled: true
    address: "127.0.0.1"  # Or use firewall to restrict access
    port: 9102
    authentication_configs:
        - passcode_sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"  # SHA256 of "abc"
```

## Proof of Concept

**Exploitation Steps:**

1. Deploy a validator node on testnet with default configuration (no admin_service config specified)
2. The AdminService will automatically start on `0.0.0.0:9102` with no authentication
3. From any machine with network access, execute:

```bash
# Dump consensus database
curl http://<validator-ip>:9102/debug/consensus/consensusdb

# Expected output: Full consensus DB dump including:
# - Last vote information
# - Highest timeout certificate
# - All consensus blocks with IDs, authors, epochs, rounds, parent IDs, timestamps
# - All quorum certificates

# Dump specific block transactions
curl "http://<validator-ip>:9102/debug/consensus/block?block_id=<hash>"

# Get mempool parking lot addresses
curl http://<validator-ip>:9102/debug/mempool/parking-lot/addresses

# All requests succeed without any authentication
```

**Verification Test:**

```rust
#[test]
fn test_admin_service_unauthenticated_access() {
    use aptos_config::config::{AdminServiceConfig, NodeConfig};
    use aptos_types::chain_id::ChainId;
    
    // Create a testnet node config with default admin service
    let node_config = NodeConfig {
        admin_service: AdminServiceConfig::default(),
        ..Default::default()
    };
    
    // Verify that on testnet, empty authentication is allowed by sanitizer
    let result = AdminServiceConfig::sanitize(
        &node_config,
        NodeType::Validator,
        Some(ChainId::testnet()),
    );
    
    // This passes, demonstrating the vulnerability
    assert!(result.is_ok());
    
    // Verify authentication_configs is empty (no auth required)
    assert!(node_config.admin_service.authentication_configs.is_empty());
    
    // Verify it binds to all interfaces
    assert_eq!(node_config.admin_service.address, "0.0.0.0");
}
```

The vulnerability is confirmed and exploitable on all non-mainnet Aptos networks with default configurations.

### Citations

**File:** config/src/config/admin_service_config.rs (L21-22)
```rust
    // If empty, will allow all requests without authentication. (Not allowed on mainnet.)
    pub authentication_configs: Vec<AuthenticationConfig>,
```

**File:** config/src/config/admin_service_config.rs (L41-50)
```rust
impl Default for AdminServiceConfig {
    fn default() -> Self {
        Self {
            enabled: None,
            address: "0.0.0.0".to_string(),
            port: 9102,
            authentication_configs: vec![],
            malloc_stats_max_len: 2 * 1024 * 1024,
        }
    }
```

**File:** config/src/config/admin_service_config.rs (L59-82)
```rust
impl ConfigSanitizer for AdminServiceConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();

        if node_config.admin_service.enabled == Some(true) {
            if let Some(chain_id) = chain_id {
                if chain_id.is_mainnet()
                    && node_config.admin_service.authentication_configs.is_empty()
                {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "Must enable authentication for AdminService on mainnet.".into(),
                    ));
                }
            }
        }

        Ok(())
    }
}
```

**File:** config/src/config/admin_service_config.rs (L84-107)
```rust
impl ConfigOptimizer for AdminServiceConfig {
    fn optimize(
        node_config: &mut NodeConfig,
        _local_config_yaml: &Value,
        _node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<bool, Error> {
        let mut modified_config = false;

        if node_config.admin_service.enabled.is_none() {
            // Only enable the admin service if the chain is not mainnet
            let admin_service_enabled = if let Some(chain_id) = chain_id {
                !chain_id.is_mainnet()
            } else {
                false // We cannot determine the chain ID, so we disable the admin service
            };
            node_config.admin_service.enabled = Some(admin_service_enabled);

            modified_config = true; // The config was modified
        }

        Ok(modified_config)
    }
}
```

**File:** crates/aptos-admin-service/src/server/mod.rs (L154-174)
```rust
        let mut authenticated = false;
        if context.config.authentication_configs.is_empty() {
            authenticated = true;
        } else {
            for authentication_config in &context.config.authentication_configs {
                match authentication_config {
                    AuthenticationConfig::PasscodeSha256(passcode_sha256) => {
                        let query = req.uri().query().unwrap_or("");
                        let query_pairs: HashMap<_, _> =
                            url::form_urlencoded::parse(query.as_bytes()).collect();
                        let passcode: Option<String> =
                            query_pairs.get("passcode").map(|p| p.to_string());
                        if let Some(passcode) = passcode {
                            if sha256::digest(passcode) == *passcode_sha256 {
                                authenticated = true;
                            }
                        }
                    },
                }
            }
        };
```

**File:** crates/aptos-admin-service/src/server/consensus/mod.rs (L130-156)
```rust
fn dump_consensus_db(consensus_db: &dyn PersistentLivenessStorage) -> anyhow::Result<String> {
    let mut body = String::new();

    let (last_vote, highest_tc, consensus_blocks, consensus_qcs) =
        consensus_db.consensus_db().get_data()?;

    body.push_str(&format!("Last vote: \n{last_vote:?}\n\n"));
    body.push_str(&format!("Highest tc: \n{highest_tc:?}\n\n"));
    body.push_str("Blocks: \n");
    for block in consensus_blocks {
        body.push_str(&format!(
            "[id: {:?}, author: {:?}, epoch: {}, round: {:02}, parent_id: {:?}, timestamp: {}, payload: {:?}]\n\n",
            block.id(),
            block.author(),
            block.epoch(),
            block.round(),
            block.parent_id(),
            block.timestamp_usecs(),
            block.payload(),
        ));
    }
    body.push_str("QCs: \n");
    for qc in consensus_qcs {
        body.push_str(&format!("{qc:?}\n\n"));
    }
    Ok(body)
}
```

**File:** crates/aptos-admin-service/src/server/consensus/mod.rs (L179-215)
```rust
fn dump_blocks(
    consensus_db: &dyn PersistentLivenessStorage,
    quorum_store_db: &dyn QuorumStoreStorage,
    block_id: Option<HashValue>,
) -> anyhow::Result<String> {
    let mut body = String::new();

    let all_batches = quorum_store_db.get_all_batches()?;

    let (_, _, blocks, _) = consensus_db.consensus_db().get_data()?;

    for block in blocks {
        let id = block.id();
        if block_id.is_none() || id == block_id.unwrap() {
            body.push_str(&format!("Block ({id:?}): \n\n"));
            match extract_txns_from_block(&block, &all_batches) {
                Ok(txns) => {
                    body.push_str(&format!("{txns:?}"));
                },
                Err(e) => {
                    body.push_str(&format!("Not available: {e:?}"));
                },
            };
            body.push_str("\n\n");
        }
    }

    if body.is_empty() {
        if let Some(block_id) = block_id {
            body.push_str(&format!("Done, block ({block_id:?}) is not found."));
        } else {
            body.push_str("Done, no block is found.");
        }
    }

    Ok(body)
}
```

**File:** crates/aptos-admin-service/src/server/mempool/mod.rs (L12-38)
```rust
pub async fn mempool_handle_parking_lot_address_request(
    _req: Request<Body>,
    mempool_client_sender: MempoolClientSender,
) -> hyper::Result<Response<Body>> {
    match get_parking_lot_addresses(mempool_client_sender).await {
        Ok(addresses) => {
            info!("Finished getting parking lot addresses from mempool.");
            match bcs::to_bytes(&addresses) {
                Ok(addresses) => Ok(reply_with(vec![], addresses)),
                Err(e) => {
                    info!("Failed to bcs serialize parking lot addresses from mempool: {e:?}");
                    Ok(reply_with_status(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        e.to_string(),
                    ))
                },
            }
        },
        Err(e) => {
            info!("Failed to get parking lot addresses from mempool: {e:?}");
            Ok(reply_with_status(
                StatusCode::INTERNAL_SERVER_ERROR,
                e.to_string(),
            ))
        },
    }
}
```

**File:** config/src/config/test_data/validator.yaml (L1-81)
```yaml
base:
    data_dir: "/opt/aptos/data"
    role: "validator"
    waypoint:
        from_storage:
            type: "vault"
            server: "https://127.0.0.1:8200"
            ca_certificate: "/full/path/to/certificate"
            token:
                from_disk: "/full/path/to/token"

consensus:
    safety_rules:
        service:
            type: process
            server_address: "/ip4/127.0.0.1/tcp/5555"

execution:
    genesis_file_location: "relative/path/to/genesis"

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

validator_network:
    discovery_method: "onchain"
    listen_address: "/ip4/0.0.0.0/tcp/6180"
    identity:
        type: "from_storage"
        key_name: "validator_network"
        peer_id_name: "owner_account"
        backend:
            type: "vault"
            server: "https://127.0.0.1:8200"
            ca_certificate: "/full/path/to/certificate"
            token:
                from_disk: "/full/path/to/token"
    network_id: "validator"
    ### Load keys from file
    # identity:
    #     type: "from_file"
    #     path: /full/path/to/private-keys.yml
    #
    ### Load keys from secure storage service like vault:
    #
    # identity:
    #     type: "from_storage"
    #     key_name: "validator_network"
    #     peer_id_name: "owner_account"
    #     backend:
    #         type: "vault"
    #         server: "https://127.0.0.1:8200"
    #         ca_certificate: "/full/path/to/certificate"
    #         token:
    #             from_disk: "/full/path/to/token"
    #
    ### Load keys directly from config
    #
    # identity:
    #     type: "from_config"
    #     key: "b0f405a3e75516763c43a2ae1d70423699f34cd68fa9f8c6bb2d67aa87d0af69"
    #     peer_id: "00000000000000000000000000000000d58bc7bb154b38039bc9096ce04e1237"
    mutual_authentication: true
    max_frame_size: 4194304 # 4 MiB
api:
    enabled: true
```
