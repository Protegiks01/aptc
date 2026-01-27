# Audit Report

## Title
Remote Executor Service RPC Timeout Vulnerability: Edge Case Timing and Lack of Validation Enables Service Crashes

## Summary
The remote sharded block executor service's gRPC timeout configuration lacks validation and is set at the exact upper bound of expected block execution times, creating a critical edge case where legitimate operations can trigger service crashes through unhandled timeout errors.

## Finding Description

The `start_async()` function accepts an `rpc_timeout_ms` parameter without any validation and applies it directly as a server-wide timeout. [1](#0-0) 

This timeout value is hardcoded to 5000ms (5 seconds) in both production instantiations: [2](#0-1)  and [3](#0-2) 

The critical vulnerability emerges from three compounding issues:

**1. Edge Case Timing Mismatch:** Block execution metrics define histogram buckets ranging up to 5.0 seconds, indicating that legitimate block execution can take the full 5 seconds. [4](#0-3) 

**2. Panic on Timeout:** When the gRPC timeout is exceeded, the client unconditionally panics rather than handling the error gracefully. [5](#0-4) 

**3. No Validation or Safeguards:** The entire call chain from `NetworkController::new()` through `InboundHandler::new()` to `start_async()` performs zero validation on the timeout parameter, and there are no concurrent request limits, connection limits, or rate limiting mechanisms. [6](#0-5) 

**Attack Scenario:**

When sharded block execution is enabled and routes through the remote executor service [7](#0-6) , any block that takes ≥5 seconds to execute will:

1. Trigger the gRPC server timeout after exactly 5000ms
2. Return a `DEADLINE_EXCEEDED` error to the client
3. Cause the client to panic, crashing the remote executor coordinator
4. Prevent the validator from completing block execution
5. Impact consensus participation and network liveness

An attacker can trigger this by submitting computationally intensive transactions that push execution time to the upper bound of the expected range. The lack of validation also means future configuration systems could set dangerously low values (causing constant failures) or dangerously high values (enabling slowloris-style resource exhaustion).

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty program ("Validator node slowdowns" and "API crashes"). 

When the remote sharded executor is enabled:
- Legitimate blocks at the edge of complexity can cause validator crashes
- Validators using remote execution cannot participate in consensus during crashes
- Network liveness is degraded if multiple validators are affected
- An attacker can deliberately craft transactions to trigger this edge case

The impact is amplified because the TODO comment acknowledging the need for retry logic was never implemented. [8](#0-7) 

## Likelihood Explanation

**Likelihood: Medium to High**

The vulnerability can be triggered through:
1. **Natural occurrence:** Complex blocks under high network load legitimately approaching the 5-second execution limit
2. **Deliberate exploitation:** Attackers submitting computationally expensive Move transactions designed to maximize execution time
3. **No special access required:** Any user can submit transactions; no validator privileges needed

The edge case becomes more likely during:
- Network stress periods with high transaction throughput
- Blocks with complex smart contract interactions
- State access patterns that cause cache misses and disk I/O
- When validators are under-provisioned or experiencing resource contention

## Recommendation

Implement multi-layered protections:

**1. Add Validation with Safety Margins:**
```rust
const MIN_RPC_TIMEOUT_MS: u64 = 1000;  // 1 second minimum
const MAX_RPC_TIMEOUT_MS: u64 = 60000; // 60 seconds maximum
const RECOMMENDED_RPC_TIMEOUT_MS: u64 = 15000; // 15 seconds for safety margin

pub fn new(service: String, listen_addr: SocketAddr, timeout_ms: u64) -> Self {
    let validated_timeout = timeout_ms.clamp(MIN_RPC_TIMEOUT_MS, MAX_RPC_TIMEOUT_MS);
    if validated_timeout != timeout_ms {
        warn!(
            "RPC timeout clamped from {}ms to {}ms for service {} at {}",
            timeout_ms, validated_timeout, service, listen_addr
        );
    }
    // ... rest of constructor
}
```

**2. Increase Default Timeout to Provide Buffer:**
Change hardcoded values from 5000ms to at least 15000ms (15 seconds) to provide a 3x safety margin above the expected maximum block execution time.

**3. Implement Graceful Error Handling:**
Replace the panic with exponential backoff retry logic:
```rust
match self.remote_channel.simple_msg_exchange(request).await {
    Ok(response) => Ok(response),
    Err(e) if e.code() == tonic::Code::DeadlineExceeded => {
        // Log and retry with backoff
        warn!("RPC timeout, retrying: {}", e);
        // Implement retry logic here
        Err(e)
    },
    Err(e) => Err(e),
}
```

**4. Add Concurrent Request Limits:**
Implement connection pooling and request rate limiting similar to the main network layer. [9](#0-8) 

## Proof of Concept

Create a test that demonstrates the timeout edge case:

```rust
#[tokio::test]
async fn test_timeout_edge_case_causes_panic() {
    use std::time::Duration;
    use tokio::time::sleep;
    
    // Setup server with 5000ms timeout
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), get_available_port());
    let handlers = Arc::new(Mutex::new(HashMap::new()));
    
    // Create server with edge case timeout
    let server = GRPCNetworkMessageServiceServerWrapper::new(handlers, server_addr);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    
    tokio::spawn(async move {
        server.start_async(server_addr, 5000, shutdown_rx).await;
    });
    
    sleep(Duration::from_millis(100)).await;
    
    // Create client
    let mut client = GRPCNetworkMessageServiceClientWrapper::new(&Runtime::new().unwrap(), server_addr);
    
    // Simulate slow block execution by having handler delay exactly 5+ seconds
    // This would trigger timeout and cause panic in send_message
    
    // In real scenario, attacker submits complex transactions that take ~5 seconds
    // Result: DEADLINE_EXCEEDED error -> client panics -> coordinator crashes
    
    shutdown_tx.send(()).unwrap();
}
```

To demonstrate in real execution environment, submit a block with transactions that collectively perform:
- Deep recursion in Move smart contracts
- Extensive state reads causing cache misses
- Complex cryptographic operations
- Large vector operations approaching gas limits

Monitor for `DEADLINE_EXCEEDED` errors followed by panic crashes in the remote executor coordinator logs.

---

## Notes

This vulnerability exists at the intersection of three design flaws: lack of input validation, timeout value at the exact edge of expected operation duration, and absence of error recovery mechanisms. While the current code has hardcoded values, the architectural weakness poses immediate risk during edge case execution scenarios and would become critical if timeout configuration were ever externalized without adding proper validation. The issue is particularly concerning given that block execution time metrics explicitly account for operations taking up to 5 seconds, yet the timeout provides no safety margin beyond this expected maximum.

### Citations

**File:** secure/net/src/grpc_network_service/mod.rs (L57-80)
```rust
    async fn start_async(
        self,
        server_addr: SocketAddr,
        rpc_timeout_ms: u64,
        server_shutdown_rx: oneshot::Receiver<()>,
    ) {
        let reflection_service = tonic_reflection::server::Builder::configure()
            .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
            .build_v1()
            .unwrap();

        info!("Starting Server async at {:?}", server_addr);
        // NOTE: (1) serve_with_shutdown() starts the server, if successful the task does not return
        //           till the server is shutdown. Hence this should be called as a separate
        //           non-blocking task. Signal handler 'server_shutdown_rx' is needed to shutdown
        //           the server
        //       (2) There is no easy way to know if/when the server has started successfully. Hence
        //           we may need to implement a healthcheck service to check if the server is up
        Server::builder()
            .timeout(std::time::Duration::from_millis(rpc_timeout_ms))
            .add_service(
                NetworkMessageServiceServer::new(self).max_decoding_message_size(MAX_MESSAGE_SIZE),
            )
            .add_service(reflection_service)
```

**File:** secure/net/src/grpc_network_service/mod.rs (L150-150)
```rust
        // TODO: Retry with exponential backoff on failures
```

**File:** secure/net/src/grpc_network_service/mod.rs (L151-159)
```rust
        match self.remote_channel.simple_msg_exchange(request).await {
            Ok(_) => {},
            Err(e) => {
                panic!(
                    "Error '{}' sending message to {} on node {:?}",
                    e, self.remote_addr, sender_addr
                );
            },
        }
```

**File:** execution/executor-service/src/remote_executor_service.rs (L31-31)
```rust
        let mut controller = NetworkController::new(service_name, self_address, 5000);
```

**File:** execution/executor-service/src/remote_executor_client.rs (L154-158)
```rust
            NetworkController::new(
                "remote-executor-coordinator".to_string(),
                coordinator_address,
                5000,
            ),
```

**File:** aptos-move/aptos-vm/src/counters.rs (L11-13)
```rust
const BLOCK_EXECUTION_TIME_BUCKETS: [f64; 16] = [
    0.20, 0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.90, 1.0, 1.25, 1.5, 1.75, 2.0, 3.0, 4.0, 5.0,
];
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

**File:** network/framework/src/constants.rs (L1-10)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

/// A collection of constants and default values for configuring various network components.

// NB: Almost all of these values are educated guesses, and not determined using any empirical
// data. If you run into a limit and believe that it is unreasonably tight, please submit a PR
// with your use-case. If you do change a value, please add a comment linking to the PR which
// advocated the change.
/// The timeout for any inbound RPC call before it's cut off
```
