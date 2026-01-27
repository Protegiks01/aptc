# Audit Report

## Title
Admin Service Authentication Bypass on Non-Mainnet Networks Exposes Critical Node Internals

## Summary
The AdminService in Aptos nodes is enabled by default on testnet, devnet, and custom chain nodes without any authentication mechanism, while binding to all network interfaces (0.0.0.0). This allows unauthorized remote attackers to access sensitive consensus database dumps, mempool state, and trigger heap profile dumps to disk, potentially enabling reconnaissance for more sophisticated attacks or causing denial of service.

## Finding Description

The AdminService is initialized in the `setup_environment_and_start_node()` function and provides privileged debugging endpoints for accessing internal node state. [1](#0-0) 

The service configuration defaults to an empty authentication configuration array. [2](#0-1) 

When authentication configurations are empty, the authentication check is bypassed entirely, allowing all requests without credentials. [3](#0-2) 

The service binds to all network interfaces by default (0.0.0.0), not localhost. [4](#0-3) 

The configuration optimizer automatically enables the admin service on all non-mainnet chains without authentication. [5](#0-4) 

The sanitizer only enforces authentication requirements for mainnet, leaving testnet and devnet nodes unprotected. [6](#0-5) 

**Exposed Endpoints Without Authentication:**

The admin service registers the AptosDB database handle, allowing database access. [7](#0-6) 

It also registers the mempool client sender, providing mempool access. [8](#0-7) 

Critical endpoints include consensus database dumps, quorum store dumps, block transaction dumps, and mempool parking lot queries. [9](#0-8) 

The heap profile dump endpoint writes files to the filesystem, potentially enabling disk-filling attacks. [10](#0-9) 

**Attack Path:**
1. Attacker scans for open port 9102 on testnet/devnet validator or fullnode
2. Sends HTTP GET requests to `/debug/consensus/consensusdb` to retrieve consensus voting state, blocks, and quorum certificates
3. Accesses `/debug/consensus/block` to dump transaction contents before public commitment
4. Queries `/debug/mempool/parking-lot/addresses` to identify accounts with failed transactions
5. Repeatedly calls `/malloc/dump_profile` to fill disk space with heap profile dumps in `/tmp/`

## Impact Explanation

This vulnerability constitutes **High Severity** per Aptos bug bounty criteria as it represents a significant protocol violation through unauthorized access to privileged node internals.

**Information Disclosure Impact:**
- Consensus state exposure reveals voting patterns, quorum certificates, and block proposals that could be used to time attacks or identify network topology
- Transaction data exposure before public commitment violates privacy expectations and could enable front-running on testnet systems handling real value
- Mempool parking lot data reveals accounts experiencing transaction failures, potentially exposing system weaknesses

**Operational Impact:**  
- Production testnet and devnet nodes used for development, staging, or ecosystem testing are exposed
- Organizations running private chains for enterprise applications have no authentication protection by default
- The disk-filling capability through repeated heap profile dumps can degrade node performance or cause failures

**Security Impact:**
- Information gathered can be used to plan more sophisticated attacks against consensus or state sync mechanisms
- Node fingerprinting through profiling endpoints aids targeted exploitation
- Lack of authentication violates the principle of least privilege for administrative interfaces

## Likelihood Explanation

**Very High Likelihood:**

1. **Default Configuration:** The vulnerability exists in the default configuration with no user intervention required. Any node operator who deploys a testnet or devnet node without explicitly configuring authentication is vulnerable.

2. **Network Exposure:** The service binds to 0.0.0.0 (all interfaces) rather than 127.0.0.1 (localhost only), making it accessible from the network by default. Many cloud deployments expose this port accidentally.

3. **Attacker Accessibility:** Simple port scanning tools can identify open port 9102, and exploitation requires only standard HTTP GET requests—no specialized tools or deep protocol knowledge needed.

4. **Wide Attack Surface:** All testnet validators, fullnodes, devnet nodes, and custom chain deployments are affected unless operators manually configure authentication.

5. **Operational Reality:** Many organizations run long-lived testnet nodes for development or staging purposes, treating them as production infrastructure despite the "test" designation.

## Recommendation

**Immediate Fix (Defense in Depth):**

1. **Change default binding to localhost:** Modify the default address from "0.0.0.0" to "127.0.0.1" so the admin service is only accessible from the local machine by default. Operators who need remote access can explicitly configure it.

2. **Enforce authentication on all chains:** Remove the mainnet-only restriction in the sanitizer. Require authentication whenever the admin service is enabled, regardless of chain ID.

3. **Add configuration warnings:** Log prominent warnings when the admin service starts without authentication or binds to non-localhost interfaces.

4. **Implement default authentication:** Generate a random passcode during node initialization and log it securely, requiring operators to explicitly retrieve and use it.

**Recommended Code Changes:**

In `config/src/config/admin_service_config.rs`, change the default address:
```rust
address: "127.0.0.1".to_string(),  // Changed from "0.0.0.0"
```

In `config/src/config/admin_service_config.rs`, enforce authentication universally:
```rust
if node_config.admin_service.enabled == Some(true) 
    && node_config.admin_service.authentication_configs.is_empty() 
{
    return Err(Error::ConfigSanitizerFailed(
        sanitizer_name,
        "Must enable authentication for AdminService on all networks.".into(),
    ));
}
```

## Proof of Concept

**Step 1: Start a testnet node with default configuration**
```bash
cargo run -p aptos-node -- --test --test-dir /tmp/test-node
```

**Step 2: Verify admin service is accessible without authentication**
```bash
# Query consensus database (no authentication required)
curl http://localhost:9102/debug/consensus/consensusdb

# Query mempool parking lot
curl http://localhost:9102/debug/mempool/parking-lot/addresses

# Dump heap profile to disk
curl http://localhost:9102/malloc/dump_profile

# The above commands will succeed and return sensitive data without any credentials
```

**Step 3: Verify network exposure**
```bash
# From another machine on the same network:
curl http://<node-ip>:9102/debug/consensus/consensusdb

# This will also succeed if the node is network-accessible on port 9102
```

**Expected Behavior:** All requests should return HTTP 511 (Network Authentication Required) unless valid authentication credentials are provided.

**Actual Behavior:** All requests succeed without authentication on non-mainnet networks, exposing consensus state, mempool information, and allowing heap profile dumps.

## Notes

This vulnerability exists by design for developer convenience on test networks, but creates security risks for production testnet deployments and custom chains. The fix should balance developer ergonomics with security by defaulting to secure configurations (localhost binding + required authentication) while allowing operators to explicitly opt into less secure configurations when appropriate for their use case.

The admin service currently exposes only read operations and heap profiling capabilities, not write/control operations for mempool or consensus. However, the exposed information is still highly sensitive and could enable reconnaissance for more sophisticated attacks on node infrastructure.

### Citations

**File:** aptos-node/src/lib.rs (L701-701)
```rust
    let mut admin_service = services::start_admin_service(&node_config);
```

**File:** aptos-node/src/lib.rs (L707-707)
```rust
    admin_service.set_aptos_db(db_rw.clone().into());
```

**File:** aptos-node/src/lib.rs (L798-798)
```rust
    admin_service.set_mempool_client_sender(mempool_client_sender);
```

**File:** config/src/config/admin_service_config.rs (L45-45)
```rust
            address: "0.0.0.0".to_string(),
```

**File:** config/src/config/admin_service_config.rs (L47-47)
```rust
            authentication_configs: vec![],
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

**File:** config/src/config/admin_service_config.rs (L93-100)
```rust
        if node_config.admin_service.enabled.is_none() {
            // Only enable the admin service if the chain is not mainnet
            let admin_service_enabled = if let Some(chain_id) = chain_id {
                !chain_id.is_mainnet()
            } else {
                false // We cannot determine the chain ID, so we disable the admin service
            };
            node_config.admin_service.enabled = Some(admin_service_enabled);
```

**File:** crates/aptos-admin-service/src/server/mod.rs (L154-156)
```rust
        let mut authenticated = false;
        if context.config.authentication_configs.is_empty() {
            authenticated = true;
```

**File:** crates/aptos-admin-service/src/server/mod.rs (L194-241)
```rust
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
```

**File:** crates/aptos-admin-service/src/server/malloc.rs (L46-63)
```rust
fn dump_heap_profile() -> anyhow::Result<String> {
    let _ = jemalloc_ctl::epoch::advance();

    let key = b"prof.dump\0";
    let path = format!(
        "{}.{}",
        PROFILE_PATH_PREFIX,
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_millis()
    );
    let value = CString::new(path.clone())?;
    unsafe {
        jemalloc_ctl::raw::write(key, value.as_ptr())
            .map_err(|e| anyhow::anyhow!("prof.dump error: {e}"))?;
    }
    Ok(path)
}
```
