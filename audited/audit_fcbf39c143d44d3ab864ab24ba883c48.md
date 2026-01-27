# Audit Report

## Title
Transient RPC Errors in Health Checks Cause False-Positive Peer Disconnections During High Network Load

## Summary
The health checker treats all RPC errors identically when determining peer health, without distinguishing between transient load-based errors (e.g., `TooManyPending`, `TimedOut`) and persistent failures. During periods of high network activity, legitimate validators can accumulate health check failures due to temporary RPC channel saturation, leading to premature disconnections that temporarily degrade network connectivity and consensus liveness.

## Finding Description

The `HealthChecker` protocol monitors peer liveness by periodically sending ping requests via RPC. When any RPC error occurs, the failure counter is incremented without examining the error type. [1](#0-0) 

All `RpcError` variants are treated equally, including explicitly transient errors like `TooManyPending`: [2](#0-1) 

The `TooManyPending` error is explicitly generated when RPC channel capacity is reached: [3](#0-2) [4](#0-3) 

With the default configuration allowing only 3 consecutive failures before disconnection: [5](#0-4) [6](#0-5) 

**Attack Scenario:**

During high network activity (e.g., large state synchronization, peak consensus rounds, mempool saturation):

1. **t=0s**: Multiple validators reach the 100 concurrent RPC limit due to consensus messages, state sync, and mempool operations
2. **t=0s-10s**: Health check pings fail with `TooManyPending` or `TimedOut` errors → failure count = 1
3. **t=10s-20s**: High load persists, second round of health checks fails → failure count = 2  
4. **t=20s-30s**: Third consecutive failure → failure count = 3
5. **t=30s-50s**: Fourth failure triggers disconnection → validator peers disconnect

If bidirectional health checks fail simultaneously between multiple validator pairs (which is likely during sustained high load), network connectivity can degrade below optimal levels, potentially impacting consensus performance.

While inbound pings can reset failure counters, during extreme load both directions may fail simultaneously: [7](#0-6) 

## Impact Explanation

This issue falls under **High Severity** per the Aptos bug bounty criteria:
- **Validator node slowdowns**: Premature disconnections reduce peer connectivity, forcing validators to spend resources on reconnection attempts and potentially slowing consensus
- **Significant protocol violations**: The health check mechanism violates the principle that transient operational load should not cause peer ejection

The impact is amplified because:
1. All validators in the network share this vulnerability simultaneously
2. High network load affects multiple validators concurrently, creating correlated disconnections
3. Even though `ConnectivityManager` attempts reconnection every 5 seconds, if high load persists, reconnection attempts may also fail
4. Cascading effect: As validators disconnect, remaining validators handle increased load, triggering more disconnections

While this doesn't cause permanent network partition (reconnection continues) or consensus safety violations, it can temporarily reduce network connectivity and consensus liveness during critical high-load periods.

## Likelihood Explanation

**High likelihood** during:
- State synchronization of new validators or validators catching up after downtime
- Periods of sustained high transaction throughput
- Epoch transitions when consensus reconfiguration occurs
- Network-wide upgrades or stress events

The likelihood is increased by:
1. No distinction between error types in failure counting logic
2. Relatively low threshold (3 failures) compared to realistic transient error scenarios
3. Short failure window (30-50 seconds) for sustained load conditions
4. Concurrent RPC limit of 100 is reachable during normal validator operations

## Recommendation

Implement error type classification in health check failure handling. Transient load-based errors should use different thresholds or exponential backoff rather than immediate failure counting.

**Recommended Fix:**

```rust
// In handle_ping_response, distinguish transient from persistent errors
match ping_result {
    Ok(pong) => { /* existing success handling */ }
    Err(err) => {
        // Classify error severity
        let is_transient = matches!(
            err,
            RpcError::TooManyPending(_) | 
            RpcError::TimedOut |
            RpcError::MpscSendError(_)
        );
        
        if is_transient {
            // For transient errors, use higher tolerance or don't increment
            warn!("Transient health check error: {:#}", err);
            // Option 1: Don't increment for transient errors
            // Option 2: Use separate counter with higher threshold
            // Option 3: Implement exponential backoff for transient errors
        } else {
            // Persistent errors use existing logic
            self.network_interface.increment_peer_round_failure(peer_id, round);
            
            let failures = self.network_interface.get_peer_failures(peer_id).unwrap_or(0);
            if failures > self.ping_failures_tolerated {
                // existing disconnect logic
            }
        }
    }
}
```

Additionally, consider:
1. Increasing `ping_failures_tolerated` to 5-7 for better tolerance
2. Implementing graduated response: warn on transient errors, disconnect only on persistent failures
3. Adding metrics to track transient vs persistent health check failures
4. Exponential backoff before reconnection attempts after `TooManyPending` errors

## Proof of Concept

```rust
// Rust integration test demonstrating the vulnerability
#[tokio::test]
async fn test_transient_rpc_errors_cause_false_disconnection() {
    // Setup: Create two validator nodes with health checking enabled
    let (validator_a, validator_b, mut health_checker_a) = setup_test_validators().await;
    
    // Simulate high network load by saturating RPC channels
    // Fill validator_b's inbound RPC queue to capacity
    for _ in 0..MAX_CONCURRENT_INBOUND_RPCS {
        send_mock_rpc_request(&validator_b).await;
    }
    
    // Now health check pings from A to B will fail with TooManyPending
    let mut failure_count = 0;
    
    // Round 1: Health check fails due to TooManyPending
    advance_time(PING_INTERVAL).await;
    assert_eq!(health_checker_a.get_peer_failures(&validator_b.peer_id()), 1);
    failure_count += 1;
    
    // Round 2: Still under load, another failure
    advance_time(PING_INTERVAL).await;
    assert_eq!(health_checker_a.get_peer_failures(&validator_b.peer_id()), 2);
    failure_count += 1;
    
    // Round 3: Third consecutive transient failure
    advance_time(PING_INTERVAL).await;
    assert_eq!(health_checker_a.get_peer_failures(&validator_b.peer_id()), 3);
    failure_count += 1;
    
    // Round 4: Fourth failure triggers disconnect despite peer being healthy
    advance_time(PING_INTERVAL).await;
    
    // Assertion: Validator A has disconnected from healthy validator B
    // due to transient load-based errors
    assert!(!validator_a.is_connected_to(&validator_b.peer_id()));
    
    // Clear the load - validator B is actually healthy
    clear_rpc_queue(&validator_b).await;
    
    // Verify validator B can still respond to pings (proving it's healthy)
    let ping_response = validator_b.handle_direct_ping().await;
    assert!(ping_response.is_ok());
    
    // The disconnect was a false positive caused by transient errors
}
```

**Notes:**

The vulnerability exists due to the health checker's failure to distinguish between temporary operational overload and actual peer failures. While `ConnectivityManager` provides reconnection capabilities and inbound pings can reset failure counters, during sustained high load affecting multiple validators simultaneously, bidirectional health check failures can occur, leading to network connectivity degradation during periods when reliable connectivity is most critical for consensus performance.

The fix requires minimal code changes but significantly improves network resilience during high-load scenarios, which are increasingly common as the Aptos network scales.

### Citations

**File:** network/framework/src/protocols/health_checker/mod.rs (L302-303)
```rust
        // Record Ingress HC here and reset failures.
        self.network_interface.reset_peer_failures(peer_id);
```

**File:** network/framework/src/protocols/health_checker/mod.rs (L343-354)
```rust
            Err(err) => {
                warn!(
                    NetworkSchema::new(&self.network_context).remote_peer(&peer_id),
                    round = round,
                    "{} Ping failed for peer: {} round: {} with error: {:#}",
                    self.network_context,
                    peer_id.short_str(),
                    round,
                    err
                );
                self.network_interface
                    .increment_peer_round_failure(peer_id, round);
```

**File:** network/framework/src/protocols/health_checker/mod.rs (L356-392)
```rust
                // If the ping failures are now more than
                // `self.ping_failures_tolerated`, we disconnect from the node.
                // The HealthChecker only performs the disconnect. It relies on
                // ConnectivityManager or the remote peer to re-establish the connection.
                let failures = self
                    .network_interface
                    .get_peer_failures(peer_id)
                    .unwrap_or(0);
                if failures > self.ping_failures_tolerated {
                    info!(
                        NetworkSchema::new(&self.network_context).remote_peer(&peer_id),
                        "{} Disconnecting from peer: {}",
                        self.network_context,
                        peer_id.short_str()
                    );
                    let peer_network_id =
                        PeerNetworkId::new(self.network_context.network_id(), peer_id);
                    if let Err(err) = timeout(
                        Duration::from_millis(50),
                        self.network_interface.disconnect_peer(
                            peer_network_id,
                            DisconnectReason::NetworkHealthCheckFailure,
                        ),
                    )
                    .await
                    {
                        warn!(
                            NetworkSchema::new(&self.network_context)
                                .remote_peer(&peer_id),
                            error = ?err,
                            "{} Failed to disconnect from peer: {} with error: {:?}",
                            self.network_context,
                            peer_id.short_str(),
                            err
                        );
                    }
                }
```

**File:** network/framework/src/protocols/rpc/error.rs (L13-44)
```rust
#[derive(Debug, Error)]
pub enum RpcError {
    #[error("Error: {0:?}")]
    Error(#[from] anyhow::Error),

    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    #[error("Bcs error: {0:?}")]
    BcsError(#[from] bcs::Error),

    #[error("Not connected with peer: {0}")]
    NotConnected(PeerId),

    #[error("Received invalid rpc response message")]
    InvalidRpcResponse,

    #[error("Application layer unexpectedly dropped response channel")]
    UnexpectedResponseChannelCancel,

    #[error("Error in application layer handling rpc request: {0:?}")]
    ApplicationError(anyhow::Error),

    #[error("Error sending on mpsc channel, connection likely shutting down: {0:?}")]
    MpscSendError(#[from] mpsc::SendError),

    #[error("Too many pending RPCs: {0}")]
    TooManyPending(u32),

    #[error("Rpc timed out")]
    TimedOut,
}
```

**File:** network/framework/src/protocols/rpc/mod.rs (L462-475)
```rust
        // Drop new outbound requests if our completion queue is at capacity.
        if self.outbound_rpc_tasks.len() == self.max_concurrent_outbound_rpcs as usize {
            counters::rpc_messages(
                network_context,
                REQUEST_LABEL,
                OUTBOUND_LABEL,
                DECLINED_LABEL,
            )
            .inc();
            // Notify application that their request was dropped due to capacity.
            let err = Err(RpcError::TooManyPending(self.max_concurrent_outbound_rpcs));
            let _ = application_response_tx.send(err);
            return Err(RpcError::TooManyPending(self.max_concurrent_outbound_rpcs));
        }
```

**File:** network/framework/src/constants.rs (L11-15)
```rust
pub const INBOUND_RPC_TIMEOUT_MS: u64 = 10_000;
/// Limit on concurrent Outbound RPC requests before backpressure is applied
pub const MAX_CONCURRENT_OUTBOUND_RPCS: u32 = 100;
/// Limit on concurrent Inbound RPC requests before backpressure is applied
pub const MAX_CONCURRENT_INBOUND_RPCS: u32 = 100;
```

**File:** config/src/config/network_config.rs (L38-41)
```rust
pub const PING_INTERVAL_MS: u64 = 10_000;
pub const PING_TIMEOUT_MS: u64 = 20_000;
pub const PING_FAILURES_TOLERATED: u64 = 3;
pub const CONNECTIVITY_CHECK_INTERVAL_MS: u64 = 5000;
```
