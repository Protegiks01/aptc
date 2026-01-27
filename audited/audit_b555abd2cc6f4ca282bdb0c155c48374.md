# Audit Report

## Title
Admin Service Exposes Uncommitted Transaction Details Through BCS Serialization Endpoint

## Summary
The admin service endpoint `/debug/consensus/block?bcs=true` exposes complete transaction details from blocks stored in the consensus database, including transactions that have been proposed but not yet committed to the public ledger. This creates a window where sensitive financial information (sender addresses, recipient addresses, transfer amounts, smart contract function arguments) can be extracted before transactions are publicly visible, enabling potential front-running attacks and privacy violations.

## Finding Description

The vulnerability exists in the interaction between the consensus database's block storage policy and the admin service's block dumping functionality.

**Core Issue**: The consensus database stores blocks when they are **proposed** but not yet **committed**: [1](#0-0) 

When the admin endpoint `/debug/consensus/block?bcs=true` is called, it retrieves ALL blocks from the consensus database: [2](#0-1) 

These blocks include both committed and uncommitted transactions. The function then extracts and serializes complete `SignedTransaction` objects: [3](#0-2) 

**What is Exposed**: Each `SignedTransaction` contains a `RawTransaction` with complete transaction details: [4](#0-3) 

This includes the `payload` field, which for `EntryFunction` transactions contains the function arguments - these can include recipient addresses, transfer amounts, and other sensitive data: [5](#0-4) 

**Access Control Weakness**: The admin service has weak default security posture:
- Enabled by default on non-mainnet networks with no authentication: [6](#0-5) 
- When authentication is empty, all requests are automatically authenticated: [7](#0-6) 
- Binds to `0.0.0.0` by default, exposing it to all network interfaces: [8](#0-7) 

**Attack Path**:
1. Attacker gains network access to a validator's admin port (9102 by default)
2. On testnet/devnet: Service is enabled with no authentication
3. On mainnet: Service might be misconfigured or attacker obtains passcode
4. Attacker polls `/debug/consensus/block?bcs=true` endpoint
5. Attacker deserializes BCS data to extract `SignedTransaction` objects
6. Attacker analyzes transaction payloads to identify high-value transfers
7. Attacker front-runs these transactions by submitting competing transactions with higher gas prices

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos Bug Bounty criteria for the following reasons:

1. **Significant Protocol Violation**: The consensus protocol's security model assumes that transaction details are only visible after commitment. This endpoint violates that assumption by exposing proposed-but-uncommitted transactions.

2. **Privacy Violation**: Users have a reasonable expectation that their transaction details remain private until they are committed to the public ledger. This endpoint allows extraction of:
   - Sender and recipient addresses
   - Transfer amounts (encoded in entry function arguments)
   - Smart contract interaction patterns
   - Trading strategies in DeFi applications

3. **Front-Running Enablement**: By seeing pending high-value transactions, attackers can:
   - Submit competing transactions with higher gas to execute first
   - Extract MEV (Maximal Extractable Value) from DeFi operations
   - Manipulate markets based on advance knowledge of large trades

4. **Broad Attack Surface**: The vulnerability is exploitable on:
   - All testnet/devnet deployments (enabled by default, no auth)
   - Misconfigured mainnet validators
   - Validators where admin credentials are compromised

## Likelihood Explanation

The likelihood is **MODERATE to HIGH**:

**Factors Increasing Likelihood**:
- Admin service is enabled by default on testnet and devnet with no authentication
- Many organizations run internal monitoring/debugging tools that could access this endpoint
- The endpoint binding to `0.0.0.0` makes it accessible from any network interface
- No rate limiting or audit logging to detect abuse
- Authentication uses SHA256 passcode in query parameter, which can be intercepted or leaked

**Factors Decreasing Likelihood**:
- On mainnet, service is disabled by default
- Requires network-level access to validator's admin port
- Mainnet deployments should have proper firewall rules

However, given the number of validators (hundreds), the probability that at least some have misconfigured admin services is significant.

## Recommendation

Implement multiple layers of defense:

**1. Remove Uncommitted Transaction Exposure**:
Modify `dump_blocks_bcs()` to only include committed blocks by checking against the latest committed ledger info before including blocks in the output.

**2. Add Warning and Audit Logging**:
Log all access attempts to this endpoint with source IP and timestamp for security monitoring.

**3. Strengthen Authentication**:
- Require authentication even on non-mainnet networks
- Use header-based authentication instead of query parameters
- Implement rate limiting per IP address

**4. Configuration Hardening**:
Change default binding address from `0.0.0.0` to `127.0.0.1` to prevent external access by default: [8](#0-7) 

**5. Add Explicit Filtering**:
Before returning transaction data, filter to only include transactions that have been committed to the ledger by comparing block rounds against the latest committed round.

## Proof of Concept

```rust
// POC: Extract pending transaction details from admin endpoint
// This can be run against any testnet validator with admin service enabled

use reqwest;
use aptos_types::transaction::Transaction;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Target testnet validator admin endpoint
    let validator_admin_url = "http://<validator-ip>:9102";
    
    // Request all blocks with BCS serialization
    let response = reqwest::get(format!("{}/debug/consensus/block?bcs=true", validator_admin_url))
        .await?
        .bytes()
        .await?;
    
    // Deserialize BCS data to get transactions
    let transactions: Vec<Transaction> = bcs::from_bytes(&response)?;
    
    // Extract sensitive information from uncommitted transactions
    for txn in transactions {
        if let Transaction::UserTransaction(signed_txn) = txn {
            println!("Sender: {:?}", signed_txn.sender());
            println!("Sequence Number: {}", signed_txn.sequence_number());
            
            // Extract payload details (includes transfer amounts, recipients)
            if let Some(payload) = signed_txn.payload() {
                println!("Payload: {:?}", payload);
                // Payload contains entry function arguments with sensitive data
            }
            
            println!("Gas Price: {}", signed_txn.gas_unit_price());
            println!("---");
        }
    }
    
    Ok(())
}
```

**To test**:
1. Deploy a testnet validator with default admin service config
2. Submit several transactions to the network
3. Before they commit (within 1-2 seconds), query the endpoint
4. Observe that uncommitted transaction details are visible

## Notes

This vulnerability demonstrates a fundamental tension between operational debugging needs and security requirements. While the admin service is designed for debugging, exposing uncommitted transaction data creates an information asymmetry that violates blockchain privacy guarantees and enables front-running attacks.

The issue is particularly severe because:
- The window of exposure (time between proposal and commitment) can be several seconds
- High-frequency monitoring can capture most pending transactions
- The data format (BCS serialization) makes it trivial to extract structured transaction details

Mitigation requires either restricting the endpoint to only committed blocks or implementing much stronger access controls with audit logging.

### Citations

**File:** consensus/src/persistent_liveness_storage.rs (L28-32)
```rust
/// PersistentLivenessStorage is essential for maintaining liveness when a node crashes.  Specifically,
/// upon a restart, a correct node will recover.  Even if all nodes crash, liveness is
/// guaranteed.
/// Blocks persisted are proposed but not yet committed.  The committed state is persisted
/// via StateComputer.
```

**File:** crates/aptos-admin-service/src/server/consensus/mod.rs (L224-224)
```rust
    let (_, _, blocks, _) = consensus_db.consensus_db().get_data()?;
```

**File:** crates/aptos-admin-service/src/server/consensus/mod.rs (L230-239)
```rust
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

**File:** types/src/transaction/mod.rs (L179-205)
```rust
pub struct RawTransaction {
    /// Sender's address.
    sender: AccountAddress,

    /// Sequence number of this transaction. This must match the sequence number
    /// stored in the sender's account at the time the transaction executes.
    sequence_number: u64,

    /// The transaction payload, e.g., a script to execute.
    payload: TransactionPayload,

    /// Maximal total gas to spend for this transaction.
    max_gas_amount: u64,

    /// Price to be paid per gas unit.
    gas_unit_price: u64,

    /// Expiration timestamp for this transaction, represented
    /// as seconds from the Unix Epoch. If the current blockchain timestamp
    /// is greater than or equal to this time, then the transaction has
    /// expired and will be discarded. This can be set to a large value far
    /// in the future to indicate that a transaction does not expire.
    expiration_timestamp_secs: u64,

    /// Chain ID of the Aptos network this transaction is intended for.
    chain_id: ChainId,
}
```

**File:** types/src/transaction/script.rs (L108-115)
```rust
#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct EntryFunction {
    module: ModuleId,
    function: Identifier,
    ty_args: Vec<TypeTag>,
    #[serde(with = "vec_bytes")]
    args: Vec<Vec<u8>>,
}
```

**File:** config/src/config/admin_service_config.rs (L45-45)
```rust
            address: "0.0.0.0".to_string(),
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
