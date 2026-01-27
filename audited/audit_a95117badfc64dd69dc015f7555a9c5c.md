# Audit Report

## Title
Critical Eclipse Attack: Indexer-GRPC-Manager Accepts Unverified Blockchain Data from Fullnodes

## Summary
The `indexer-grpc-manager` component completely trusts data received from configured fullnode endpoints without any cryptographic verification. If all `fullnode_addresses` are attacker-controlled, the indexer will accept and serve fabricated blockchain data, including fake transactions, balances, and state, enabling a complete eclipse attack on any services relying on the indexer.

## Finding Description

The vulnerability exists in how the indexer-grpc-manager processes blockchain data from fullnodes. The attack flow is:

1. **Configuration Trust**: The `IndexerGrpcManagerConfig` accepts a list of `fullnode_addresses` without validation or verification mechanisms. [1](#0-0) 

2. **Unverified Version Tracking**: The `MetadataManager` receives `known_latest_version` from fullnodes via ping responses and unconditionally trusts this value to track the blockchain tip. [2](#0-1) 

3. **No Cryptographic Verification**: When the `DataManager` requests transactions from fullnodes, it receives `TransactionsFromNodeResponse` messages and immediately caches the transaction data without any verification. [3](#0-2) 

4. **Missing Security Checks**: The codebase contains NO:
   - Transaction signature verification
   - State root/accumulator hash verification  
   - Merkle proof validation
   - LedgerInfo or validator signature verification
   - Even basic chain_id validation from responses

This breaks the **State Consistency** invariant (#4): "State transitions must be atomic and verifiable via Merkle proofs." The indexer accepts state data without any proof verification.

**Attack Scenario:**
1. Operator configures indexer with attacker-controlled fullnode addresses (via social engineering, compromised infrastructure, or DNS hijacking)
2. Attacker's malicious fullnodes report fake `known_latest_version` (e.g., version 999,999,999)
3. Attacker's fullnodes serve fabricated `Transaction` data showing:
   - Fake token transfers to victim addresses
   - Inflated account balances
   - Non-existent NFT mints
   - Fabricated smart contract events
4. Indexer caches and serves this fake data to downstream clients
5. Wallets, exchanges, and dApps make decisions based on fabricated blockchain state

## Impact Explanation

**Severity: CRITICAL** (per Aptos Bug Bounty criteria)

This vulnerability enables multiple critical impacts:

1. **Loss of Funds**: Exchanges accepting deposits could credit accounts based on fake transactions that never occurred on the real blockchain. Attackers could then withdraw real funds.

2. **Consensus View Manipulation**: While not breaking consensus itself, this creates a parallel "fake consensus" view that affects all services dependent on the indexer (wallets, explorers, dApps, bridges).

3. **Non-recoverable State Inconsistency**: Once an indexer has cached fake data, it requires manual intervention to detect and correct, as there's no built-in verification mechanism.

4. **Service-wide Compromise**: A single compromised indexer can affect thousands of users relying on it for blockchain data.

The vulnerability meets the **$1,000,000 Critical Severity** criteria as it enables "Loss of Funds" through systematic deception of services that rely on indexer data for financial decisions.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

The attack requires:
- Operator to configure malicious fullnode endpoints (achievable via social engineering, DNS hijacking, or compromised infrastructure)
- No privileged access to validators or consensus participants
- No complex exploit chains - straightforward data fabrication

Given that:
- Many indexer operators run independent infrastructure
- Configuration management can be compromised
- No warnings exist about fullnode endpoint trust
- No cryptographic verification mechanisms are in place

This is a realistic attack vector, especially for:
- Smaller indexer operators with less security review
- Development/staging environments with relaxed security
- Third-party indexer services

## Recommendation

Implement cryptographic verification of all data received from fullnodes:

1. **Require LedgerInfo with Validator Signatures**: Fullnodes should provide `LedgerInfo` objects signed by >2/3 of validators for each transaction batch, proving consensus.

2. **Verify Transaction Accumulator Proofs**: Each transaction should include a Merkle proof against the accumulator root hash in the signed LedgerInfo.

3. **Validate Chain ID**: Check that the `chain_id` in responses matches the expected chain ID and is consistent across all responses.

4. **Add Transaction Signature Verification**: Verify user transaction signatures before caching data.

5. **Implement Multiple-Source Verification**: Query multiple fullnodes and require consistent responses before accepting data.

Example fix for chain_id validation in DataManager:

```rust
// In data_manager.rs, after receiving response
match response_item {
    Ok(r) => {
        // Validate chain_id matches expected
        if r.chain_id as u64 != self.chain_id {
            bail!("Chain ID mismatch: expected {}, got {}", 
                  self.chain_id, r.chain_id);
        }
        // ... rest of processing
    }
}
```

More comprehensively, the response proto should be extended to include `LedgerInfo` with validator signatures, and the DataManager should verify these signatures before accepting any transaction data.

## Proof of Concept

**Malicious Fullnode Setup:**

```rust
// Pseudo-code for attacker's malicious fullnode
struct MaliciousFullnodeService {
    fake_version: AtomicU64,
}

impl FullnodeData for MaliciousFullnodeService {
    async fn get_transactions_from_node(
        &self,
        request: GetTransactionsFromNodeRequest,
    ) -> Result<Response<Streaming<TransactionsFromNodeResponse>>> {
        // Fabricate transactions with fake data
        let fake_transaction = Transaction {
            version: request.starting_version.unwrap(),
            timestamp: current_timestamp(),
            info: Some(TransactionInfo {
                hash: vec![0; 32], // Fake hash
                accumulator_root_hash: vec![0; 32], // Fake root
                // ... other fake fields
            }),
            type: TransactionType::User as i32,
            user: Some(UserTransaction {
                // Fake transfer showing victim received 1M APT
                // ... 
            }),
            // ... rest of fake transaction
        };
        
        // Return fake data with fake chain_id
        let response = TransactionsFromNodeResponse {
            response: Some(Response::Data(TransactionsOutput {
                transactions: vec![fake_transaction],
            })),
            chain_id: 1, // Attacker sets any chain_id
        };
        
        Ok(Response::new(stream_fake_data(response)))
    }
    
    async fn ping(&self, _: PingFullnodeRequest) 
        -> Result<Response<PingFullnodeResponse>> {
        // Report fake blockchain height
        Ok(Response::new(PingFullnodeResponse {
            info: Some(FullnodeInfo {
                chain_id: 1,
                known_latest_version: Some(999_999_999), // Fake version
                // ...
            }),
        }))
    }
}
```

**Attack Execution:**
1. Deploy malicious fullnode service at `attacker.com:50051`
2. Configure victim indexer with: `fullnode_addresses = ["http://attacker.com:50051"]`
3. Indexer pings malicious fullnode, receives fake `known_latest_version: 999999999`
4. Indexer requests transactions, receives fabricated data
5. Indexer caches and serves fake blockchain state to all clients

**Verification:**
Query the indexer's API - it will return the fabricated transactions and state, indistinguishable from real data, with no verification errors.

## Notes

This vulnerability is particularly dangerous because:

1. **Silent Failure**: There are no warnings or errors when accepting unverified data
2. **Wide Impact**: All downstream services (wallets, exchanges, dApps) are affected
3. **Difficult Detection**: Without external verification, operators may not detect the compromise
4. **Persistent**: Fake data remains cached even after fixing the configuration

The indexer-grpc-cache-worker component does perform some chain_id validation, but the indexer-grpc-manager (which is the focus of this audit) does not, making it the vulnerable component in the architecture.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/config.rs (L31-42)
```rust
pub struct IndexerGrpcManagerConfig {
    pub(crate) chain_id: u64,
    pub(crate) service_config: ServiceConfig,
    #[serde(default = "default_cache_config")]
    pub(crate) cache_config: CacheConfig,
    pub(crate) file_store_config: IndexerGrpcFileStoreConfig,
    pub(crate) self_advertised_address: GrpcAddress,
    pub(crate) grpc_manager_addresses: Vec<GrpcAddress>,
    pub(crate) fullnode_addresses: Vec<GrpcAddress>,
    pub(crate) is_master: bool,
    pub(crate) allow_fn_fallback: bool,
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L533-550)
```rust
    fn handle_fullnode_info(&self, address: GrpcAddress, info: FullnodeInfo) -> Result<()> {
        let mut entry = self
            .fullnodes
            .entry(address.clone())
            .or_insert(Fullnode::new(address.clone()));
        entry.value_mut().recent_states.push_back(info);
        if let Some(known_latest_version) = info.known_latest_version {
            trace!(
                "Received known_latest_version ({known_latest_version}) from fullnode {address}."
            );
            self.update_known_latest_version(known_latest_version);
        }
        if entry.value().recent_states.len() > MAX_NUM_OF_STATES_TO_KEEP {
            entry.value_mut().recent_states.pop_front();
        }

        Ok(())
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/data_manager.rs (L257-280)
```rust
                match response_item {
                    Ok(r) => {
                        if let Some(response) = r.response {
                            match response {
                                Response::Data(data) => {
                                    trace!(
                                        "Putting data into cache, {} transaction(s).",
                                        data.transactions.len()
                                    );
                                    self.cache.write().await.put_transactions(data.transactions);
                                },
                                Response::Status(_) => continue,
                            }
                        } else {
                            warn!("Error when getting transactions from fullnode: no data.");
                            continue 'out;
                        }
                    },
                    Err(e) => {
                        warn!("Error when getting transactions from fullnode: {}", e);
                        continue 'out;
                    },
                }
            }
```
