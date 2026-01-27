# Audit Report

## Title
Unauthenticated Consensus Database Dump Endpoint on Non-Mainnet Networks

## Summary
The admin service's `/debug/consensus/consensusdb` endpoint allows unauthenticated access to complete consensus state (last votes, timeout certificates, all blocks, and quorum certificates) on testnet, devnet, and private chain deployments due to default empty authentication configuration.

## Finding Description

The `handle_dump_consensus_db_request()` function in the admin service exposes complete consensus database state without requiring authentication on non-mainnet networks. [1](#0-0) 

The authentication mechanism in the admin service automatically grants access when `authentication_configs` is empty: [2](#0-1) 

The default configuration sets `authentication_configs` to an empty vector: [3](#0-2) 

The service binds to all network interfaces by default: [4](#0-3) 

While the sanitizer enforces authentication on mainnet, it explicitly allows empty authentication on non-mainnet chains: [5](#0-4) 

The exposed data includes sensitive consensus information that could aid attack reconnaissance: [6](#0-5) 

An attacker with network access to port 9102 can execute:
```
curl http://<validator-ip>:9102/debug/consensus/consensusdb
```
to retrieve all consensus blocks, QCs, last votes, and timeout certificates without any credentials.

## Impact Explanation

This finding represents an **information disclosure vulnerability** on non-mainnet networks. While it does not directly cause consensus safety violations or fund loss, it exposes:

1. **Validator voting patterns** - revealing which validators voted for which blocks
2. **Consensus timing data** - showing block proposal and voting latencies  
3. **Complete block history** - including all proposals and their authors
4. **Quorum certificate details** - with aggregated signatures

However, the impact is limited because:
- **Mainnet (production) is protected** by the sanitizer enforcing authentication requirements
- The exposed information is historical and cannot directly manipulate consensus
- Exploiting this data requires subsequent compromise of validator keys
- Test networks (testnet/devnet) may intentionally allow this for debugging

This qualifies as **Low to Medium Severity** under the bug bounty criteria - it's an information leak that could facilitate attack planning but doesn't directly compromise the network.

## Likelihood Explanation

**High likelihood** on non-mainnet deployments where:
- Admin service is enabled by default on testnet/devnet
- Authentication configs remain empty (default)
- Port 9102 is exposed to the network (default binding to 0.0.0.0)
- Network policies don't restrict access to the admin port

**Zero likelihood** on mainnet due to sanitizer enforcement.

## Recommendation

Enforce authentication on all networks, not just mainnet. Modify the sanitizer to require authentication regardless of chain:

```rust
// In config/src/config/admin_service_config.rs
impl ConfigSanitizer for AdminServiceConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();

        if node_config.admin_service.enabled == Some(true) {
            // Enforce authentication on ALL networks, not just mainnet
            if node_config.admin_service.authentication_configs.is_empty() {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "Must enable authentication for AdminService on all networks.".into(),
                ));
            }
        }

        Ok(())
    }
}
```

Additionally, change default binding from `0.0.0.0` to `127.0.0.1` to restrict access to localhost only.

## Proof of Concept

```bash
# On a testnet/devnet validator node with default configuration:

# 1. Check if admin service is accessible
curl http://<validator-ip>:9102/debug/consensus/consensusdb

# Expected result: Full consensus database dump without authentication
# Including:
# - Last vote with signature
# - Highest timeout certificate  
# - All consensus blocks with authors, epochs, rounds
# - All quorum certificates with aggregated signatures

# 2. Dump specific block
curl "http://<validator-ip>:9102/debug/consensus/block?block_id=<hash>"

# 3. Dump quorum store
curl http://<validator-ip>:9102/debug/consensus/quorumstoredb
```

**Notes:**
- This vulnerability only affects non-mainnet deployments (testnet, devnet, private chains)
- Mainnet validators are protected by the configuration sanitizer
- The security impact is indirect - it aids reconnaissance but doesn't directly compromise consensus
- Operators running private production chains should explicitly configure authentication

### Citations

**File:** crates/aptos-admin-service/src/server/consensus/mod.rs (L17-38)
```rust
pub async fn handle_dump_consensus_db_request(
    _req: Request<Body>,
    consensus_db: Arc<dyn PersistentLivenessStorage>,
) -> hyper::Result<Response<Body>> {
    info!("Dumping consensus db.");

    match spawn_blocking(move || dump_consensus_db(consensus_db.as_ref())).await {
        Ok(result) => {
            info!("Finished dumping consensus db.");
            let headers: Vec<(_, HeaderValue)> =
                vec![(CONTENT_LENGTH, HeaderValue::from(result.len()))];
            Ok(reply_with(headers, result))
        },
        Err(e) => {
            info!("Failed to dump consensus db: {e:?}");
            Ok(reply_with_status(
                StatusCode::INTERNAL_SERVER_ERROR,
                e.to_string(),
            ))
        },
    }
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

**File:** crates/aptos-admin-service/src/server/mod.rs (L154-156)
```rust
        let mut authenticated = false;
        if context.config.authentication_configs.is_empty() {
            authenticated = true;
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
