# Audit Report

## Title
Unauthenticated Remote Executor Service Vulnerable to BCS Deserialization Panic Leading to Denial of Service

## Summary
The remote executor service infrastructure uses `NetworkController` without authentication and performs BCS deserialization with `.unwrap()` on network-received messages. An attacker with network access to internal executor service ports can send malformed messages, triggering panics that crash critical execution threads and prevent block processing.

## Finding Description

The remote executor service implements distributed block execution across multiple shards communicating via the `NetworkController`. However, this system has two critical security flaws:

1. **Lack of Authentication**: The `NetworkController` provides no authentication mechanism for incoming connections. Services bind to socket addresses and accept messages from any source that can reach them. [1](#0-0) 

2. **Unsafe Error Handling**: Multiple critical code paths deserialize BCS-encoded messages using `.unwrap()`, which panics on deserialization errors:

**Coordinator Client** (receives execution commands): [2](#0-1) 

**Executor Client** (receives execution results): [3](#0-2) 

**State View Service** (receives state requests): [4](#0-3) 

**State View Client** (receives state responses): [5](#0-4) 

The system is used in production when remote executor addresses are configured: [6](#0-5) 

**Attack Scenario:**
1. Attacker gains network access to executor service ports (via misconfiguration, compromised internal network, or insider position)
2. Attacker sends malformed BCS bytes to coordinator client's `execute_command` channel
3. Deserialization attempt at line 89 fails with `bcs::Error`
4. `.unwrap()` panics, crashing the coordinator client's command receiving loop
5. Shard becomes unable to process execution commands
6. Block execution fails across the distributed executor system
7. Consensus cannot commit blocks, halting chain progress

## Impact Explanation

This qualifies as **High Severity** per Aptos bug bounty criteria due to "Validator node slowdowns" and effective denial of service:

- **Availability Impact**: Panicked threads prevent block execution, stopping consensus progress
- **Scope**: Affects all validators using remote executor configuration  
- **Recovery**: Requires service restart and may cause block processing backlog
- **Chain Liveness**: Sustained attacks could significantly degrade or halt chain operation

While not directly causing "consensus message confusion" as the security question frames it, the lack of proper error handling creates a critical availability vulnerability in the execution pipeline that consensus depends on.

## Likelihood Explanation

**Likelihood: Medium to High** depending on deployment configuration

**Attack Requirements:**
- Network connectivity to internal executor service ports (typically firewalled but assumes network segmentation)
- Knowledge of port numbers and message formats (observable from codebase)
- Ability to send TCP/gRPC messages

**Mitigating Factors:**
- Services likely deployed on internal networks with firewall protection
- Requires some level of network compromise or misconfiguration

**Aggravating Factors:**
- Zero authentication creates single point of failure if network security is breached
- Simple attack - just send malformed bytes
- No rate limiting or anomaly detection visible in code
- Multiple attack surfaces (4 different deserialization points)

## Recommendation

Implement defense-in-depth by adding both authentication and proper error handling:

**1. Add Authentication to NetworkController:**
```rust
// In network_controller/mod.rs
pub struct NetworkController {
    auth_token: Option<String>,
    allowed_peers: HashSet<SocketAddr>,
    // ... existing fields
}

// Validate peer authentication before routing messages
fn validate_peer(&self, remote_addr: SocketAddr, auth_header: &str) -> Result<(), Error> {
    if !self.allowed_peers.contains(&remote_addr) {
        return Err(Error::UnauthorizedPeer);
    }
    // Add cryptographic authentication check
    Ok(())
}
```

**2. Replace `.unwrap()` with Proper Error Handling:**
```rust
// In remote_cordinator_client.rs
pub fn receive_execute_command(&self) -> ExecutorShardCommand<RemoteStateViewClient> {
    match self.command_rx.recv() {
        Ok(message) => {
            match bcs::from_bytes::<RemoteExecutionRequest>(&message.data) {
                Ok(request) => {
                    // ... existing logic
                },
                Err(e) => {
                    error!("BCS deserialization error: {:?}", e);
                    EXECUTOR_ERRORS.inc();
                    return ExecutorShardCommand::Stop;
                }
            }
        },
        Err(_) => ExecutorShardCommand::Stop,
    }
}
```

**3. Add Message Validation:**
```rust
// Validate message type matches expected deserialization target
fn validate_message_type(msg_type: &str, expected: &str) -> Result<(), Error> {
    if msg_type != expected {
        return Err(Error::InvalidMessageType);
    }
    Ok(())
}
```

## Proof of Concept

```rust
// PoC demonstrating the vulnerability
#[cfg(test)]
mod exploit_test {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    
    #[test]
    #[should_panic]
    fn test_malformed_bcs_causes_panic() {
        // Setup remote executor service
        let coordinator_addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST), 
            52200
        );
        let shard_addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST), 
            52201
        );
        
        let mut controller = NetworkController::new(
            "test-controller".to_string(),
            coordinator_addr,
            5000
        );
        
        let coordinator_client = RemoteCoordinatorClient::new(
            0,
            &mut controller,
            coordinator_addr
        );
        
        controller.start();
        
        // Attacker sends malformed BCS bytes
        let malicious_message = Message::new(vec![0xFF, 0xFF, 0xFF, 0xFF]);
        
        // Send via the execute_command channel
        // This will trigger the panic at remote_cordinator_client.rs:89
        coordinator_client.command_rx.send(malicious_message).unwrap();
        
        // This call will panic when trying to deserialize
        coordinator_client.receive_execute_command();
        // Test passes if panic occurs
    }
}
```

## Notes

While the security question asks about "consensus message confusion," the actual vulnerability found is a denial-of-service via panic rather than message confusion per se. BCS deserialization is strongly typed and will fail with an error rather than deserialize to the wrong type. However, the mishandling of these errors (via `.unwrap()`) combined with lack of authentication creates a critical availability vulnerability affecting the consensus execution pipeline.

The remote executor service is distinct from the main consensus network layer, which does implement authentication via Noise protocol. This architectural separation means consensus messages themselves are authenticated, but the execution service layer lacks equivalent protection.

### Citations

**File:** secure/net/src/grpc_network_service/mod.rs (L91-116)
```rust
#[tonic::async_trait]
impl NetworkMessageService for GRPCNetworkMessageServiceServerWrapper {
    async fn simple_msg_exchange(
        &self,
        request: Request<NetworkMessage>,
    ) -> Result<Response<Empty>, Status> {
        let _timer = NETWORK_HANDLER_TIMER
            .with_label_values(&[&self.self_addr.to_string(), "inbound_msgs"])
            .start_timer();
        let remote_addr = request.remote_addr();
        let network_message = request.into_inner();
        let msg = Message::new(network_message.message);
        let message_type = MessageType::new(network_message.message_type);

        if let Some(handler) = self.inbound_handlers.lock().unwrap().get(&message_type) {
            // Send the message to the registered handler
            handler.send(msg).unwrap();
        } else {
            error!(
                "No handler registered for sender: {:?} and msg type {:?}",
                remote_addr, message_type
            );
        }
        Ok(Response::new(Empty {}))
    }
}
```

**File:** execution/executor-service/src/remote_cordinator_client.rs (L86-90)
```rust
                let bcs_deser_timer = REMOTE_EXECUTOR_TIMER
                    .with_label_values(&[&self.shard_id.to_string(), "cmd_rx_bcs_deser"])
                    .start_timer();
                let request: RemoteExecutionRequest = bcs::from_bytes(&message.data).unwrap();
                drop(bcs_deser_timer);
```

**File:** execution/executor-service/src/remote_executor_client.rs (L166-169)
```rust
        for rx in self.result_rxs.iter() {
            let received_bytes = rx.recv().unwrap().to_bytes();
            let result: RemoteExecutionResult = bcs::from_bytes(&received_bytes).unwrap();
            results.push(result.inner?);
```

**File:** execution/executor-service/src/remote_state_view_service.rs (L83-87)
```rust
        let bcs_deser_timer = REMOTE_EXECUTOR_TIMER
            .with_label_values(&["0", "kv_req_deser"])
            .start_timer();
        let req: RemoteKVRequest = bcs::from_bytes(&message.data).unwrap();
        drop(bcs_deser_timer);
```

**File:** execution/executor-service/src/remote_state_view.rs (L251-255)
```rust
        let bcs_deser_timer = REMOTE_EXECUTOR_TIMER
            .with_label_values(&[&shard_id.to_string(), "kv_resp_deser"])
            .start_timer();
        let response: RemoteKVResponse = bcs::from_bytes(&message.data).unwrap();
        drop(bcs_deser_timer);
```

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L260-267)
```rust
    ) -> Result<Vec<TransactionOutput>> {
        if !get_remote_addresses().is_empty() {
            Ok(V::execute_block_sharded(
                &REMOTE_SHARDED_BLOCK_EXECUTOR.lock(),
                partitioned_txns,
                state_view,
                onchain_config,
            )?)
```
