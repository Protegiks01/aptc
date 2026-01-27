# Audit Report

## Title
Unauthenticated Remote Executor Service Allows Man-in-the-Middle Attacks Leading to Validator Consensus Failure

## Summary
The remote executor service implements sharded block execution using plain HTTP GRPC without TLS encryption, message authentication, or integrity protection. An attacker with network access between the coordinator and executor shards can intercept and manipulate `ExecuteBlockCommand` messages, causing affected validators to compute incorrect state roots and fail to participate in consensus, leading to network liveness failures.

## Finding Description

The `ProcessExecutorService::new()` function creates a distributed executor architecture where a coordinator process communicates with multiple shard processes over the network to parallelize block execution. This communication uses the `NetworkController` which establishes GRPC connections over plain HTTP without any cryptographic protection. [1](#0-0) 

The underlying GRPC client connects using unencrypted HTTP: [2](#0-1) 

When the coordinator sends execution commands to shards, these contain the complete `ExecuteBlockCommand` with transactions, cross-shard dependencies, and execution parameters. The shard receives and deserializes these messages without any authentication or integrity verification: [3](#0-2) 

**Attack Flow:**

1. Attacker positions themselves between coordinator and shard processes (requires network access to the communication path)
2. Intercepts `ExecuteBlockCommand` messages containing `SubBlocksForShard<AnalyzedTransaction>` 
3. Deserializes the BCS-encoded message
4. Manipulates the message by:
   - Reordering transactions within sub-blocks
   - Modifying `CrossShardDependencies` (required_edges/dependent_edges) to alter execution order
   - Changing execution parameters (`concurrency_level`, `onchain_config`)
   - Dropping select transactions
   - Replaying old execution commands
5. Re-serializes and forwards the modified message to the shard
6. Shard executes with tampered data, computes different state root than honest validators

This breaks the **Deterministic Execution** invariant: "All validators must produce identical state roots for identical blocks." The compromised validator will disagree with the network and fail to sign blocks, unable to participate in consensus.

The remote executor is integrated into the production execution workflow: [4](#0-3) 

## Impact Explanation

This vulnerability qualifies as **HIGH to CRITICAL severity**:

**High Severity Impact:**
- **Validator node slowdowns**: Affected validators fail consensus checks and cannot participate
- **Significant protocol violations**: Breaks deterministic execution invariant

**Critical Severity Impact (if multiple validators affected):**
- **Total loss of liveness/network availability**: If attacker compromises >1/3 of validators' internal networks, the network cannot reach consensus
- **Non-recoverable network partition**: Validators compute divergent states requiring intervention

The severity escalates based on deployment topology:
- **Single validator impact**: High (targeted DoS against one validator)
- **Multiple validators**: Critical (network-wide liveness failure)
- **Cloud deployments with cross-AZ shards**: Easier to exploit, higher likelihood

## Likelihood Explanation

**Likelihood: MEDIUM to HIGH** depending on deployment configuration.

**Attack Requirements:**
- Network access between coordinator and shard processes
- Ability to intercept and modify network traffic (MITM capability)
- Understanding of BCS serialization format

**Deployment Scenarios:**

1. **High Likelihood**: Shards distributed across multiple machines/datacenters
   - Attacker needs network access to datacenter or cloud infrastructure
   - Traffic crosses physical network boundaries
   - Common in production for performance scaling

2. **Medium Likelihood**: Shards on same machine but different processes
   - Traffic may use network interfaces even on localhost
   - Docker/container deployments may be vulnerable

3. **Low Likelihood**: Development/testing environments
   - Single-process execution with local shards

The vulnerability is realistic because:
- The code explicitly supports remote deployment with different `SocketAddr` per shard
- No warnings or security documentation about secure network requirements
- Deployment scripts (main.rs) accept arbitrary socket addresses from command line
- No built-in protection mechanisms (TLS, authentication, signing)

## Recommendation

Implement multiple layers of defense:

**1. Mandatory TLS Encryption:**
```rust
// In grpc_network_service/mod.rs
async fn get_channel(remote_addr: String) -> NetworkMessageServiceClient<Channel> {
    let tls_config = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(CA_CERT))
        .domain_name("executor-shard");
    
    let conn = tonic::transport::Endpoint::new(remote_addr)
        .unwrap()
        .tls_config(tls_config)?
        .connect_lazy();
    NetworkMessageServiceClient::new(conn)
}
```

**2. Message Authentication:**
Add HMAC or digital signatures to all `ExecuteBlockCommand` messages:
```rust
pub struct AuthenticatedMessage {
    pub message: Vec<u8>,
    pub signature: Signature,
    pub sender_id: ValidatorId,
}
```

Verify signatures before deserializing commands in `RemoteCoordinatorClient::receive_execute_command()`.

**3. Mutual TLS Authentication:**
Require both coordinator and shards to present certificates, verify identity before processing commands.

**4. Network Isolation:**
Document security requirements that coordinator-shard communication must occur on isolated, trusted networks.

**5. Message Sequence Numbers:**
Add monotonically increasing sequence numbers to prevent replay attacks:
```rust
pub struct ExecuteBlockCommand {
    pub sequence_number: u64,
    pub sub_blocks: SubBlocksForShard<AnalyzedTransaction>,
    // ... existing fields
}
```

**Immediate Mitigation:**
Until cryptographic protections are implemented, clearly document that the remote executor service should ONLY be deployed on:
- Localhost interfaces
- Air-gapped networks
- VPNs with strong encryption

Add runtime checks to warn if remote addresses are not localhost in production builds.

## Proof of Concept

```rust
// PoC: Intercepting and modifying ExecuteBlockCommand
// This demonstrates the vulnerability conceptually

use aptos_executor_service::{ExecuteBlockCommand, RemoteExecutionRequest};
use std::net::SocketAddr;

fn mitm_attack_simulation() {
    // 1. Setup: Attacker intercepts network traffic between coordinator and shard
    let intercepted_bytes: Vec<u8> = /* captured from network */;
    
    // 2. Deserialize the command (no authentication check!)
    let mut request: RemoteExecutionRequest = bcs::from_bytes(&intercepted_bytes).unwrap();
    
    // 3. Modify the command
    match request {
        RemoteExecutionRequest::ExecuteBlock(ref mut command) => {
            // Attack vector 1: Reorder transactions
            command.sub_blocks.sub_blocks[0].transactions.reverse();
            
            // Attack vector 2: Modify dependencies
            for txn in &mut command.sub_blocks.sub_blocks[0].transactions {
                // Remove required edges to cause premature execution
                txn.cross_shard_dependencies.required_edges.edges.clear();
            }
            
            // Attack vector 3: Change execution parameters
            command.concurrency_level = 1; // Force sequential execution
        }
    }
    
    // 4. Re-serialize and forward to shard
    let malicious_bytes = bcs::to_bytes(&request).unwrap();
    // Send to shard - it will execute without detecting tampering
    
    // Result: Shard computes different state root, validator fails consensus
}

// To demonstrate in practice:
// 1. Deploy coordinator and shards on separate machines
// 2. Use a packet capture tool (tcpdump, Wireshark) to intercept traffic on port 52200
// 3. Use a MITM proxy to modify the BCS-serialized messages
// 4. Observe that the affected validator computes different state and drops out of consensus
```

**Verification Steps:**
1. Deploy remote executor service with coordinator and shards on different hosts
2. Configure network interception (MITM proxy or packet manipulation)
3. Execute a block through the coordinator
4. Modify the `ExecuteBlockCommand` in transit (e.g., reorder transactions)
5. Observe shard executes modified block
6. Compare state root with honest validators - they will differ
7. Affected validator cannot participate in consensus

## Notes

This vulnerability is particularly concerning because:

1. **Silent Failure**: No error messages or warnings when messages are tampered with
2. **Production Impact**: The remote executor is integrated into the production execution workflow when remote addresses are configured
3. **Scalability Tension**: Feature designed for performance scaling introduces security risk
4. **Defense Depth**: Relies solely on network security with no application-layer protection

The issue does NOT allow injecting completely new transactions with forged signatures (transactions contain valid signatures from users), but manipulation of execution order, dependencies, and parameters is sufficient to break consensus for affected validators.

### Citations

**File:** execution/executor-service/src/process_executor_service.rs (L17-45)
```rust
    pub fn new(
        shard_id: ShardId,
        num_shards: usize,
        num_threads: usize,
        coordinator_address: SocketAddr,
        remote_shard_addresses: Vec<SocketAddr>,
    ) -> Self {
        let self_address = remote_shard_addresses[shard_id];
        info!(
            "Starting process remote executor service on {}; coordinator address: {}, other shard addresses: {:?}; num threads: {}",
            self_address, coordinator_address, remote_shard_addresses, num_threads
        );
        aptos_node_resource_metrics::register_node_metrics_collector(None);
        let _mp = MetricsPusher::start_for_local_run(
            &("remote-executor-service-".to_owned() + &shard_id.to_string()),
        );

        AptosVM::set_concurrency_level_once(num_threads);
        let mut executor_service = ExecutorService::new(
            shard_id,
            num_shards,
            num_threads,
            self_address,
            coordinator_address,
            remote_shard_addresses,
        );
        executor_service.start();
        Self { executor_service }
    }
```

**File:** secure/net/src/grpc_network_service/mod.rs (L124-138)
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
    }
```

**File:** execution/executor-service/src/remote_cordinator_client.rs (L80-112)
```rust
    fn receive_execute_command(&self) -> ExecutorShardCommand<RemoteStateViewClient> {
        match self.command_rx.recv() {
            Ok(message) => {
                let _rx_timer = REMOTE_EXECUTOR_TIMER
                    .with_label_values(&[&self.shard_id.to_string(), "cmd_rx"])
                    .start_timer();
                let bcs_deser_timer = REMOTE_EXECUTOR_TIMER
                    .with_label_values(&[&self.shard_id.to_string(), "cmd_rx_bcs_deser"])
                    .start_timer();
                let request: RemoteExecutionRequest = bcs::from_bytes(&message.data).unwrap();
                drop(bcs_deser_timer);

                match request {
                    RemoteExecutionRequest::ExecuteBlock(command) => {
                        let init_prefetch_timer = REMOTE_EXECUTOR_TIMER
                            .with_label_values(&[&self.shard_id.to_string(), "init_prefetch"])
                            .start_timer();
                        let state_keys = Self::extract_state_keys(&command);
                        self.state_view_client.init_for_block(state_keys);
                        drop(init_prefetch_timer);

                        let (sub_blocks, concurrency, onchain_config) = command.into();
                        ExecutorShardCommand::ExecuteSubBlocks(
                            self.state_view_client.clone(),
                            sub_blocks,
                            concurrency,
                            onchain_config,
                        )
                    },
                }
            },
            Err(_) => ExecutorShardCommand::Stop,
        }
```

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L261-267)
```rust
        if !get_remote_addresses().is_empty() {
            Ok(V::execute_block_sharded(
                &REMOTE_SHARDED_BLOCK_EXECUTOR.lock(),
                partitioned_txns,
                state_view,
                onchain_config,
            )?)
```
