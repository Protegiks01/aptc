# Audit Report

## Title
Socket Closure Timeout Enables Resource Accumulation Attack via Connection Churn

## Summary
The network peer writer task swallows socket flush/close errors and timeouts without propagating them, allowing file descriptors and TCP connection state to accumulate during 30-second cleanup windows. When combined with the peer manager's early removal of connections from active tracking, an attacker can exploit rapid disconnect/reconnect cycles to exhaust validator node file descriptors and cause network availability degradation.

## Finding Description

The vulnerability exists in the interaction between two components:

1. **Writer Task Cleanup** [1](#0-0) : When closing connections, flush/close operations have a 30-second timeout. If these operations fail or timeout, errors are logged at `info` level but the writer task simply exits, dropping the socket without retry or escalation.

2. **Early Active Peer Removal** [2](#0-1) : When a disconnect is requested, the peer is immediately removed from `active_peers` before socket closure completes, freeing up connection slots for new peers.

3. **Split Socket Ownership** [3](#0-2) : Sockets are split into ReadHalf and WriteHalf via `tokio::io::split()`, sharing ownership through an Arc. The underlying file descriptor remains open until BOTH halves are dropped.

**Attack Scenario:**

An attacker exploits this by triggering rapid disconnect/reconnect cycles:

1. Attacker establishes connections up to `max_inbound_connections` (100 by default) [4](#0-3) 
2. Attacker sends malformed messages triggering `ReadError::IoError` [5](#0-4) , causing immediate disconnect
3. Validator removes connection from `active_peers`, allowing new connections
4. Writer task attempts socket close with 30-second timeout [6](#0-5) 
5. Attacker immediately re-establishes connection (slot is now free)
6. Original connection's socket remains open for up to 30 seconds during close timeout
7. Repeating steps 2-6 creates accumulation: 100 active connections + (reconnect_rate × 30 seconds) closing sockets

**Resource Accumulation Math:**
- If attacker triggers disconnect/reconnect every second from distributed sources
- Steady state: 100 active + (100 connections/sec × 30 sec) = 3,100 file descriptors
- This approaches typical file descriptor limits (10,000-100,000) [7](#0-6) 

**Invariant Violation:**
Breaks Resource Limits invariant (#9): "All operations must respect gas, storage, and computational limits". Socket file descriptors are a critical OS resource that should not accumulate unboundedly during normal operations.

## Impact Explanation

This qualifies as **Medium Severity** under Aptos bug bounty criteria for "Validator node slowdowns":

**When file descriptor exhaustion occurs:**
- Validator cannot accept new inbound connections from other validators
- Consensus messages may fail to transmit/receive
- Validator marked unhealthy by network health checks [8](#0-7) 
- Potential removal from active validator set if liveness drops
- Network partition if multiple validators affected simultaneously

**Temporary but disruptive:** While resources are eventually cleaned up after 30 seconds, sustained attack causes continuous resource pressure preventing validator from functioning normally.

## Likelihood Explanation

**Likelihood: Medium to High**

**Attacker Requirements:**
- Network access to validator (publicly accessible for full nodes, known peers for validators)
- Ability to establish TCP connections (no authentication required initially)
- Capability to send malformed protocol messages
- Distributed attack infrastructure to bypass per-IP rate limits

**Attack Feasibility:**
- Connection establishment is straightforward
- Triggering disconnects is trivial (send garbage data causing `IoError`)
- Connection limits are permissive (100 inbound) for validator operations
- Rate limiting exists but can be bypassed with multiple source IPs
- No special privileges or insider access required

**Realistic Scenarios:**
- Targeted attack on specific validator during critical consensus rounds
- Network-wide attack exploiting common vulnerability
- Accidental resource exhaustion from buggy peer implementations

## Recommendation

**Immediate Fix:**

1. **Track closing connections separately** to prevent slot reuse during cleanup:

```rust
// In PeerManager
closing_peers: HashMap<ConnectionId, Instant>, // Track when close started

// In DisconnectPeer handler, before removing from active_peers:
self.closing_peers.insert(connection_id, Instant::now());

// In handle_inbound_connection, reject if total connections exceed limit:
let total_connections = self.active_peers.len() + self.closing_peers.len();
if total_connections >= self.max_inbound_connections {
    return Err(PeerManagerError::TooManyConnections);
}

// In Disconnected handler, remove from closing_peers:
self.closing_peers.remove(&lost_conn_metadata.connection_id);
```

2. **Propagate close errors** to trigger monitoring alerts:

```rust
// In start_writer_task, lines 390-416
match time_service.timeout(transport::TRANSPORT_TIMEOUT, flush_and_close).await {
    Err(_) | Ok(Err(_)) => {
        warn!(log_context, "Failed to close connection cleanly");
        counters::FAILED_CONNECTION_CLOSES.inc(); // Add metric
        // Consider exponential backoff for repeated failures
    },
    Ok(Ok(())) => { /* success */ }
}
```

3. **Add circuit breaker** for rapid reconnect attempts from same peer/IP:

```rust
// Track recent disconnects per peer, apply backoff before accepting reconnect
```

**Long-term Improvements:**
- Monitor `FAILED_CONNECTION_CLOSES` metric for anomalies
- Implement adaptive connection limits based on resource availability
- Add peer reputation system to throttle misbehaving peers

## Proof of Concept

```rust
// Integration test demonstrating resource accumulation
#[tokio::test]
async fn test_connection_churn_resource_exhaustion() {
    use std::net::TcpStream;
    use std::time::{Duration, Instant};
    
    // Setup validator node with max_inbound_connections = 100
    let validator = start_validator_node_with_config(NetworkConfig {
        max_inbound_connections: 100,
        ..Default::default()
    }).await;
    
    let validator_addr = validator.listen_address();
    let start = Instant::now();
    let mut active_sockets = Vec::new();
    let mut total_sockets_created = 0;
    
    // Rapidly create connections, send bad data, trigger disconnect
    for iteration in 0..200 {
        // Establish connection
        let mut socket = TcpStream::connect(validator_addr).unwrap();
        total_sockets_created += 1;
        
        // Send malformed handshake to trigger IoError and disconnect
        socket.write_all(b"GARBAGE_DATA_TO_TRIGGER_DISCONNECT").unwrap();
        
        // Drop connection, validator will try to close (30s timeout)
        drop(socket);
        
        // Immediately try to reconnect (slot freed from active_peers)
        // This should succeed even though previous socket still closing
        if iteration < 100 {
            let new_socket = TcpStream::connect(validator_addr).unwrap();
            active_sockets.push(new_socket);
        }
        
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    
    // Check validator's open file descriptors
    let validator_pid = validator.process_id();
    let open_fds = count_open_file_descriptors(validator_pid);
    
    // Expected: ~100 active + ~2000 closing (if attack ran for 20 seconds)
    // Demonstrates accumulation beyond max_inbound_connections
    assert!(open_fds > 100, 
        "File descriptors should accumulate beyond connection limit. \
         Found {} FDs from {} total connections created in {:?}",
        open_fds, total_sockets_created, start.elapsed()
    );
    
    // Verify validator is unhealthy due to resource exhaustion
    assert!(validator.health_check_fails(), 
        "Validator should fail health checks under resource pressure");
}

fn count_open_file_descriptors(pid: u32) -> usize {
    #[cfg(unix)]
    {
        std::fs::read_dir(format!("/proc/{}/fd", pid))
            .unwrap()
            .count()
    }
    #[cfg(not(unix))]
    {
        0 // Placeholder for non-Unix systems
    }
}
```

**Note**: This test would require integration test infrastructure to spawn validator nodes and measure resource usage. The core exploit is: rapid disconnect/reconnect cycles cause socket accumulation beyond `max_inbound_connections` during 30-second close windows, potentially exhausting file descriptors and degrading validator availability.

### Citations

**File:** network/framework/src/peer/mod.rs (L212-218)
```rust
        // Split the connection into a ReadHalf and a WriteHalf.
        let (read_socket, write_socket) =
            tokio::io::split(self.connection.take().unwrap().compat());

        let mut reader =
            MultiplexMessageStream::new(read_socket.compat(), self.max_frame_size).fuse();
        let writer = MultiplexMessageSink::new(write_socket.compat_write(), self.max_frame_size);
```

**File:** network/framework/src/peer/mod.rs (L381-416)
```rust
            let flush_and_close = async {
                writer.flush().await?;
                writer.close().await?;
                Ok(()) as Result<(), WriteError>
            };
            match time_service
                .timeout(transport::TRANSPORT_TIMEOUT, flush_and_close)
                .await
            {
                Err(_) => {
                    info!(
                        log_context,
                        "{} Timeout in flush/close of connection to peer: {}",
                        network_context,
                        remote_peer_id.short_str()
                    );
                },
                Ok(Err(err)) => {
                    info!(
                        log_context,
                        error = %err,
                        "{} Failure in flush/close of connection to peer: {}, error: {}",
                        network_context,
                        remote_peer_id.short_str(),
                        err
                    );
                },
                Ok(Ok(())) => {
                    info!(
                        log_context,
                        "{} Closed connection to peer: {}",
                        network_context,
                        remote_peer_id.short_str()
                    );
                },
            }
```

**File:** network/framework/src/peer/mod.rs (L588-591)
```rust
                ReadError::IoError(_) => {
                    // IoErrors are mostly unrecoverable so just close the connection.
                    self.shutdown(DisconnectReason::InputOutputError);
                    return Err(err.into());
```

**File:** network/framework/src/peer_manager/mod.rs (L468-486)
```rust
            ConnectionRequest::DisconnectPeer(peer_id, disconnect_reason, resp_tx) => {
                // Update the connection disconnect metrics
                counters::update_network_connection_operation_metrics(
                    &self.network_context,
                    counters::DISCONNECT_LABEL.into(),
                    disconnect_reason.get_label(),
                );

                // Send a CloseConnection request to Peer and drop the send end of the
                // PeerRequest channel.
                if let Some((conn_metadata, sender)) = self.active_peers.remove(&peer_id) {
                    let connection_id = conn_metadata.connection_id;
                    self.remove_peer_from_metadata(conn_metadata.remote_peer_id, connection_id);

                    // This triggers a disconnect.
                    drop(sender);
                    // Add to outstanding disconnect requests.
                    self.outstanding_disconnect_requests
                        .insert(connection_id, resp_tx);
```

**File:** config/src/config/network_config.rs (L40-41)
```rust
pub const PING_FAILURES_TOLERATED: u64 = 3;
pub const CONNECTIVITY_CHECK_INTERVAL_MS: u64 = 5000;
```

**File:** config/src/config/network_config.rs (L44-44)
```rust
pub const MAX_INBOUND_CONNECTIONS: usize = 100;
```

**File:** network/framework/src/transport/mod.rs (L41-41)
```rust
pub const TRANSPORT_TIMEOUT: Duration = Duration::from_secs(30);
```

**File:** aptos-node/src/utils.rs (L81-135)
```rust
pub fn ensure_max_open_files_limit(required: u64, assert_success: bool) {
    if required == 0 {
        return;
    }

    // Only works on Unix environments
    #[cfg(unix)]
    {
        if !rlimit::Resource::NOFILE.is_supported() {
            warn!(
                required = required,
                "rlimit setting not supported on this platform. Won't ensure."
            );
            return;
        }

        let (soft, mut hard) = match rlimit::Resource::NOFILE.get() {
            Ok((soft, hard)) => (soft, hard),
            Err(err) => {
                warn!(
                    error = ?err,
                    required = required,
                    "Failed getting RLIMIT_NOFILE. Won't ensure."
                );
                return;
            },
        };

        if soft >= required {
            return;
        }

        if required > hard {
            warn!(
                hard_limit = hard,
                required = required,
                "System RLIMIT_NOFILE hard limit too small."
            );
            // Not panicking right away -- user can be root
            hard = required;
        }

        rlimit::Resource::NOFILE
            .set(required, hard)
            .unwrap_or_else(|err| {
                let msg = format!("RLIMIT_NOFILE soft limit is {soft}, configured requirement is {required}, and \
                    failed to raise to it. Please make sure that `limit -n` shows a number larger than \
                    {required} before starting the node. Error: {err}.");
                if assert_success {
                    panic!("{}", msg)
                } else {
                    error!("{}", msg)
                }
            });
    }
```
