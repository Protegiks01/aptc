# Audit Report

## Title
Transaction Privacy Leak via Unencrypted Cross-Shard Hook Communication in Remote Sharded Execution

## Summary
The `TransactionCommitHook` mechanism in Aptos block execution leaks private transaction information (amounts, recipients, and all write set data) to external systems before transactions are publicly visible on-chain. When remote sharded execution is enabled, the `CrossShardCommitSender` implementation transmits transaction write sets over unencrypted HTTP connections, allowing network observers to intercept sensitive transaction data during block execution, before consensus finalization and public commitment.

## Finding Description

The vulnerability exists in the interaction between several components:

1. **Hook Invocation Timing**: The `TransactionCommitHook` is invoked during block execution, specifically in `record_finalized_output` for parallel execution and during `execute_transactions_sequential` for sequential execution, both occurring **before** transactions are finalized through consensus and committed to storage. [1](#0-0) [2](#0-1) 

2. **Sensitive Data Exposure**: The hook receives access to the complete `TransactionOutput` including write sets containing `WriteOp` objects with sensitive transaction data. [3](#0-2) 

3. **Cross-Shard Transmission**: The `CrossShardCommitSender` implementation sends transaction write sets to dependent shards via `RemoteTxnWrite` messages containing `StateKey` and `WriteOp` pairs. [4](#0-3) [5](#0-4) 

4. **Unencrypted HTTP Transport**: The `RemoteCrossShardClient` uses `NetworkController` which creates GRPC channels over plain HTTP (not HTTPS), transmitting sensitive data without encryption. [6](#0-5) 

5. **Production Usage**: Remote sharded execution is a real production feature, enabled when remote addresses are configured. [7](#0-6) 

**Attack Scenario:**

1. Validator operator configures remote sharded execution across multiple machines/networks
2. User submits a sensitive transaction (e.g., large token transfer)
3. Transaction enters block execution before consensus finalization
4. `CrossShardCommitSender.on_transaction_committed()` is triggered
5. Transaction write set (containing amounts, recipients, etc.) is serialized and sent over HTTP to dependent shards
6. Network observer (ISP, cloud provider, compromised network infrastructure, or MITM attacker) intercepts unencrypted HTTP traffic
7. Attacker extracts sensitive transaction information **before** it's publicly visible on-chain
8. Attacker uses early knowledge for front-running, privacy analysis, or competitive advantage

## Impact Explanation

This vulnerability qualifies as **Medium Severity** per Aptos bug bounty criteria because:

1. **Privacy Violation**: Leaks private transaction information before public visibility, violating user expectations of transaction privacy until commitment
2. **Front-Running Potential**: Early knowledge of transaction contents enables front-running attacks, leading to "limited funds loss or manipulation" (Medium severity criteria)
3. **Timing Advantage**: Provides significant timing advantage to network observers over legitimate market participants
4. **Design Flaw**: Fundamental design issue in the hook mechanism when combined with remote execution

The impact is limited to Medium (not Critical/High) because:
- Requires remote sharded execution configuration (not default)
- Requires network-level access to intercept traffic
- Information eventually becomes public (timing-based leak, not permanent secrecy breach)
- No direct theft or consensus violation

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability is exploitable when:
1. **Remote sharded execution is enabled**: Requires validator operator configuration via `set_remote_addresses()`, but this is a legitimate production feature for performance scaling
2. **Network access available**: Attacker needs ability to observe HTTP traffic between executor shards, which is feasible through:
   - Cloud provider monitoring (if shards run on cloud infrastructure)
   - ISP-level traffic inspection
   - Compromised network infrastructure
   - Man-in-the-middle attacks on unsecured networks
   - Shared infrastructure in data centers

The likelihood is Medium rather than Low because:
- Remote sharded execution is a documented production feature
- HTTP traffic observation is a well-understood attack vector
- Cloud providers and network operators routinely have visibility into unencrypted traffic
- The technical barrier is network access, not protocol exploitation

## Recommendation

**Immediate Fix:**

1. **Enable TLS/HTTPS for GRPC connections** in `GRPCNetworkMessageServiceClientWrapper`:

```rust
// In secure/net/src/grpc_network_service/mod.rs
async fn get_channel(remote_addr: String) -> NetworkMessageServiceClient<Channel> {
    info!("Trying to connect to remote server at {:?}", remote_addr);
    
    // Change from http:// to https:// with TLS configuration
    let tls_config = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(CA_CERT))
        .identity(Identity::from_pem(CLIENT_CERT, CLIENT_KEY));
    
    let conn = tonic::transport::Endpoint::new(remote_addr.replace("http://", "https://"))
        .unwrap()
        .tls_config(tls_config)
        .unwrap()
        .connect_lazy();
    
    NetworkMessageServiceClient::new(conn).max_decoding_message_size(MAX_MESSAGE_SIZE)
}
```

2. **Add mutual TLS authentication** to verify shard identities and prevent unauthorized interception

3. **Document security requirements** for remote sharded execution deployment, requiring encrypted network channels

**Alternative/Additional Mitigations:**

1. **Application-level encryption**: Encrypt sensitive data in `RemoteTxnWrite` messages before transmission
2. **Network segmentation**: Document requirement for isolated/VPN networks when using remote execution
3. **Hook access controls**: Add capability checks to limit what data hooks can access based on execution phase

## Proof of Concept

**Setup:**
1. Configure remote sharded execution with two executor shards on separate machines
2. Set up network traffic capture (e.g., tcpdump, Wireshark) on network between shards
3. Submit test transaction with identifiable data

**Reproduction Steps:**

```rust
// PoC demonstrating traffic interception (simplified)

// Step 1: Configure remote sharded execution
use aptos_executor_service::remote_executor_client;

let shard_addresses = vec![
    "192.168.1.10:52201".parse().unwrap(),
    "192.168.1.11:52202".parse().unwrap(),
];
remote_executor_client::set_remote_addresses(shard_addresses.clone());

// Step 2: Execute block with cross-shard dependencies
// (Actual PoC would require full node setup)

// Step 3: Capture network traffic between shards
// Using tcpdump: sudo tcpdump -i eth0 -A 'tcp port 52201 or tcp port 52202'
// 
// Expected observation: Plaintext BCS-serialized RemoteTxnWrite messages
// containing transaction write sets visible in captured packets

// Verification:
// 1. Observe HTTP POST requests to /NetworkMessageService/simple_msg_exchange
// 2. Extract BCS-serialized CrossShardMsg::RemoteTxnWriteMsg from packet payload
// 3. Deserialize to recover StateKey and WriteOp containing transaction data
// 4. Confirm transaction data visible BEFORE block finalization

// Example captured data structure:
// RemoteTxnWrite {
//     state_key: StateKey(0x1::coin::CoinStore<AptosCoin>...),
//     write_op: Some(Modification(StateValue { bytes: [amount_bytes...] }))
// }
```

**Validation:**
Run network capture during block execution with remote sharded execution enabled. Parse captured HTTP traffic to extract `RemoteTxnWrite` messages. Verify transaction write set data is visible in plaintext before block commitment.

---

## Notes

This vulnerability represents a **design-level privacy leak** in the transaction commit hook mechanism when combined with remote sharded execution. While the hook itself is a valid architectural component for cross-shard coordination, the lack of encryption in the transport layer creates a timing-based privacy vulnerability that violates reasonable expectations for transaction confidentiality before public commitment.

The fix requires adding TLS/HTTPS to the GRPC transport layer used by `NetworkController` and enforcing authenticated, encrypted channels for all cross-shard communication containing sensitive transaction data.

### Citations

**File:** aptos-move/block-executor/src/executor.rs (L1277-1278)
```rust
        if let Some(txn_commit_listener) = &self.transaction_commit_hook {
            last_input_output.notify_listener(txn_idx, txn_commit_listener)?;
```

**File:** aptos-move/block-executor/src/executor.rs (L2493-2496)
```rust
                    if let Some(commit_hook) = &self.transaction_commit_hook {
                        commit_hook
                            .on_transaction_committed(idx as TxnIndex, output.committed_output());
                    }
```

**File:** aptos-move/block-executor/src/txn_commit_hook.rs (L11-12)
```rust
pub trait TransactionCommitHook: Send + Sync {
    fn on_transaction_committed(&self, txn_idx: TxnIndex, output: &OnceCell<TransactionOutput>);
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_client.rs (L103-134)
```rust
    fn send_remote_update_for_success(
        &self,
        txn_idx: TxnIndex,
        txn_output: &OnceCell<TransactionOutput>,
    ) {
        let edges = self.dependent_edges.get(&txn_idx).unwrap();
        let write_set = txn_output
            .get()
            .expect("Committed output must be set")
            .write_set();

        for (state_key, write_op) in write_set.expect_write_op_iter() {
            if let Some(dependent_shard_ids) = edges.get(state_key) {
                for (dependent_shard_id, round_id) in dependent_shard_ids.iter() {
                    trace!("Sending remote update for success for shard id {:?} and txn_idx: {:?}, state_key: {:?}, dependent shard id: {:?}", self.shard_id, txn_idx, state_key, dependent_shard_id);
                    let message = RemoteTxnWriteMsg(RemoteTxnWrite::new(
                        state_key.clone(),
                        Some(write_op.clone()),
                    ));
                    if *round_id == GLOBAL_ROUND_ID {
                        self.cross_shard_client.send_global_msg(message);
                    } else {
                        self.cross_shard_client.send_cross_shard_msg(
                            *dependent_shard_id,
                            *round_id,
                            message,
                        );
                    }
                }
            }
        }
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_client.rs (L137-147)
```rust
impl TransactionCommitHook for CrossShardCommitSender {
    fn on_transaction_committed(
        &self,
        txn_idx: TxnIndex,
        txn_output: &OnceCell<TransactionOutput>,
    ) {
        let global_txn_idx = txn_idx + self.index_offset;
        if self.dependent_edges.contains_key(&global_txn_idx) {
            self.send_remote_update_for_success(global_txn_idx, txn_output);
        }
    }
```

**File:** secure/net/src/grpc_network_service/mod.rs (L124-137)
```rust
    pub fn new(rt: &Runtime, remote_addr: SocketAddr) -> Self {
        Self {
            remote_addr: remote_addr.to_string(),
            remote_channel: rt
                .block_on(async { Self::get_channel(format!("http://{}", remote_addr)).await }),
        }
    }

    async fn get_channel(remote_addr: String) -> NetworkMessageServiceClient<Channel> {
        info!("Trying to connect to remote server at {:?}", remote_addr);
        let conn = tonic::transport::Endpoint::new(remote_addr)
            .unwrap()
            .connect_lazy();
        NetworkMessageServiceClient::new(conn).max_decoding_message_size(MAX_MESSAGE_SIZE)
```

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L261-275)
```rust
        if !get_remote_addresses().is_empty() {
            Ok(V::execute_block_sharded(
                &REMOTE_SHARDED_BLOCK_EXECUTOR.lock(),
                partitioned_txns,
                state_view,
                onchain_config,
            )?)
        } else {
            Ok(V::execute_block_sharded(
                &SHARDED_BLOCK_EXECUTOR.lock(),
                partitioned_txns,
                state_view,
                onchain_config,
            )?)
        }
```
