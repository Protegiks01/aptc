# Audit Report

## Title
File Descriptor Exhaustion via Unbounded Pending Connection Upgrades

## Summary
The network transport layer's `TransportHandler` uses an unbounded `FuturesUnordered` collection to track pending inbound connection upgrades, allowing attackers to exhaust file descriptors by initiating many TCP connections that never complete the handshake protocol. This can lead to validator node unavailability and loss of liveness.

## Finding Description

The vulnerability exists in the connection acceptance and upgrade flow:

**Attack Flow:**

1. An attacker opens many TCP connections to a validator's listening port
2. Each TCP connection is immediately accepted by the `TcpListener` and consumes a file descriptor [1](#0-0) 
3. The accepted connection is wrapped in an upgrade future (Noise handshake + protocol negotiation) [2](#0-1) 
4. The upgrade future is added to an **unbounded** `FuturesUnordered` collection [3](#0-2) 
5. Each upgrade has a 30-second timeout before cleanup [4](#0-3) 

**Critical Gap:**

The `inbound_connection_limit` (default 100) only applies to **completed** connections after successful upgrade [5](#0-4) , not to pending connections in the upgrade phase.

**Exploitation:**

An attacker can:
- Open connections but never send handshake data (forcing 30s timeout)
- Send partial/invalid Noise handshake data to cause upgrade failures
- Use slowloris-style attacks (send data extremely slowly)
- Simply open connections rapidly (>100 connections/second)

With a sustained rate of 100 new connections per second, an attacker can accumulate ~3000 pending connections (100 conn/s × 30s timeout). Each pending connection holds a file descriptor. Typical Linux file descriptor limits are 1024 (soft) to 4096 (hard), making exhaustion realistic.

**Why Existing Protections Fail:**

- TCP backlog (256) only limits queued SYN packets, not accepted connections [6](#0-5) 
- `TRANSPORT_TIMEOUT` (30s) is too long for effective cleanup [7](#0-6) 
- The codebase has `FuturesUnorderedX` for bounded concurrency [8](#0-7)  but it's **not used** in `TransportHandler`

## Impact Explanation

**Severity: HIGH** (up to $50,000 per Aptos Bug Bounty)

When file descriptors are exhausted:
- The validator cannot accept new connections from legitimate peers
- Critical operations fail (opening database files, creating sockets for RPC)
- **Loss of liveness**: Node cannot participate in consensus if it cannot maintain peer connections
- **Validator slowdown/unavailability**: Meets HIGH severity criteria

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits" - here, file descriptor limits are not respected.

## Likelihood Explanation

**Likelihood: HIGH**

- **Attacker Requirements**: Any network peer can execute this attack; no privileged access required
- **Complexity**: Trivial - opening many TCP connections without completing handshakes
- **Cost**: Minimal - can be executed from a single machine with basic networking tools
- **Detection Difficulty**: May appear as normal network congestion initially
- **Success Rate**: High - no authentication required before file descriptor consumption

## Recommendation

Implement bounded concurrency for pending connection upgrades:

**Option 1**: Use `FuturesUnorderedX` with a configurable limit

```rust
// In TransportHandler::listen()
const MAX_PENDING_INBOUND_UPGRADES: usize = 200; // Configurable
let mut pending_inbound_connections = FuturesUnorderedX::new(MAX_PENDING_INBOUND_UPGRADES);
```

**Option 2**: Add an early check before accepting connections

Track the number of pending upgrades and reject new TCP connections when the limit is reached, immediately closing the socket before consuming resources.

**Option 3**: Reduce `TRANSPORT_TIMEOUT` to 5-10 seconds

This limits the attack window while still allowing legitimate slow connections to complete.

**Recommended Configuration**:
- `max_pending_inbound_upgrades`: 200-500 (2-5x `MAX_INBOUND_CONNECTIONS`)
- `transport_timeout`: 10 seconds (reduced from 30)
- Add metrics to monitor pending upgrade count

## Proof of Concept

```rust
// Attacker script (conceptual - demonstrates attack feasibility)
use tokio::net::TcpStream;
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() {
    let target = "validator_ip:6180"; // Validator's network port
    let mut connections = Vec::new();
    
    // Open connections rapidly
    for i in 0..3000 {
        if let Ok(stream) = TcpStream::connect(target).await {
            // Don't send any data - force timeout
            connections.push(stream);
            println!("Opened connection {}", i);
        }
        
        // Rate: ~100 connections/second
        if i % 100 == 0 {
            sleep(Duration::from_secs(1)).await;
        }
    }
    
    // Hold connections open
    println!("Holding {} connections, file descriptors exhausted", connections.len());
    sleep(Duration::from_secs(600)).await;
}
```

**Validation Steps:**

1. Run Aptos validator node
2. Check initial FD count: `lsof -p <validator_pid> | wc -l`
3. Execute attack script
4. Monitor FD consumption: watch FD count approach system limit
5. Observe validator inability to accept new legitimate connections
6. Verify node degradation in consensus participation

## Notes

This vulnerability is particularly severe because:
- It affects validator nodes critical to consensus
- Multiple validators can be attacked simultaneously
- The attack is sustainable and can be maintained indefinitely
- Recovery requires node restart, potentially causing consensus delays

The fix should be prioritized as it directly impacts network availability and validator liveness.

### Citations

**File:** network/netcore/src/transport/tcp.rs (L127-127)
```rust
        let listener = socket.listen(256)?;
```

**File:** network/netcore/src/transport/tcp.rs (L320-329)
```rust
        match self.inner.poll_accept(context) {
            Poll::Ready(Ok((socket, addr))) => {
                if let Err(e) = self.config.apply_config(&socket) {
                    return Poll::Ready(Some(Err(e)));
                }
                let dialer_addr = NetworkAddress::from(addr);
                Poll::Ready(Some(Ok((
                    future::ready(Ok(TcpSocket::new(socket))),
                    dialer_addr,
                ))))
```

**File:** network/framework/src/peer_manager/transport.rs (L91-109)
```rust
        let mut pending_inbound_connections = FuturesUnordered::new();
        let mut pending_outbound_connections = FuturesUnordered::new();

        debug!(
            NetworkSchema::new(&self.network_context),
            "{} Incoming connections listener Task started", self.network_context
        );

        loop {
            futures::select! {
                dial_request = self.transport_reqs_rx.select_next_some() => {
                    if let Some(fut) = self.dial_peer(dial_request) {
                        pending_outbound_connections.push(fut);
                    }
                },
                inbound_connection = self.listener.select_next_some() => {
                    if let Some(fut) = self.upgrade_inbound_connection(inbound_connection) {
                        pending_inbound_connections.push(fut);
                    }
```

**File:** network/framework/src/peer_manager/transport.rs (L127-155)
```rust
    /// Make an inbound request upgrade future e.g. Noise handshakes
    fn upgrade_inbound_connection(
        &self,
        incoming_connection: Result<(TTransport::Inbound, NetworkAddress), TTransport::Error>,
    ) -> Option<
        BoxFuture<
            'static,
            (
                Result<Connection<TSocket>, TTransport::Error>,
                NetworkAddress,
                Instant,
            ),
        >,
    > {
        match incoming_connection {
            Ok((upgrade, addr)) => {
                debug!(
                    NetworkSchema::new(&self.network_context).network_address(&addr),
                    "{} Incoming connection from {}", self.network_context, addr
                );

                counters::pending_connection_upgrades(
                    &self.network_context,
                    ConnectionOrigin::Inbound,
                )
                .inc();

                let start_time = self.time_service.now();
                Some(upgrade.map(move |out| (out, addr, start_time)).boxed())
```

**File:** network/framework/src/transport/mod.rs (L40-41)
```rust
/// A timeout for the connection to open and complete all of the upgrade steps.
pub const TRANSPORT_TIMEOUT: Duration = Duration::from_secs(30);
```

**File:** network/framework/src/transport/mod.rs (L627-627)
```rust
            let fut_upgrade = timeout_io(time_service.clone(), TRANSPORT_TIMEOUT, fut_upgrade);
```

**File:** network/framework/src/peer_manager/mod.rs (L352-388)
```rust
        if conn.metadata.origin == ConnectionOrigin::Inbound {
            // Everything below here is meant for unknown peers only. The role comes from
            // the Noise handshake and if it's not `Unknown` then it is trusted.
            if conn.metadata.role == PeerRole::Unknown {
                // TODO: Keep track of somewhere else to not take this hit in case of DDoS
                // Count unknown inbound connections
                let unknown_inbound_conns = self
                    .active_peers
                    .iter()
                    .filter(|(peer_id, (metadata, _))| {
                        metadata.origin == ConnectionOrigin::Inbound
                            && trusted_peers
                                .get(peer_id)
                                .is_none_or(|peer| peer.role == PeerRole::Unknown)
                    })
                    .count();

                // Reject excessive inbound connections made by unknown peers
                // We control outbound connections with Connectivity manager before we even send them
                // and we must allow connections that already exist to pass through tie breaking.
                if !self
                    .active_peers
                    .contains_key(&conn.metadata.remote_peer_id)
                    && unknown_inbound_conns + 1 > self.inbound_connection_limit
                {
                    info!(
                        NetworkSchema::new(&self.network_context)
                            .connection_metadata_with_address(&conn.metadata),
                        "{} Connection rejected due to connection limit: {}",
                        self.network_context,
                        conn.metadata
                    );
                    counters::connections_rejected(&self.network_context, conn.metadata.origin)
                        .inc();
                    self.disconnect(conn);
                    return;
                }
```

**File:** storage/backup/backup-cli/src/utils/stream/futures_unordered_x.rs (L15-36)
```rust
pub struct FuturesUnorderedX<T: Future> {
    queued: VecDeque<T>,
    in_progress: FuturesUnordered<T>,
    queued_outputs: VecDeque<T::Output>,
    max_in_progress: usize,
}

impl<T: Future> Unpin for FuturesUnorderedX<T> {}

impl<Fut: Future> FuturesUnorderedX<Fut> {
    /// Constructs a new, empty `FuturesOrderedX`
    ///
    /// The returned `FuturesOrderedX` does not contain any futures and, in this
    /// state, `FuturesOrdered::poll_next` will return `Poll::Ready(None)`.
    pub fn new(max_in_progress: usize) -> FuturesUnorderedX<Fut> {
        assert!(max_in_progress > 0);
        FuturesUnorderedX {
            queued: VecDeque::new(),
            in_progress: FuturesUnordered::new(),
            queued_outputs: VecDeque::new(),
            max_in_progress,
        }
```
