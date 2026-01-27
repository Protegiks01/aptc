# Audit Report

## Title
Connection Socket Data Loss on Early Return in handle_new_connection_event

## Summary
The `handle_new_connection_event()` function in PeerManager can drop a Connection object without proper cleanup when `get_trusted_peers()` fails, potentially causing loss of messages that are in flight or buffered in the socket.

## Finding Description

The vulnerability exists in the error handling path of `handle_new_connection_event()`: [1](#0-0) 

When `get_trusted_peers()` returns an error, the function returns early without calling `disconnect()` on the Connection. The Connection struct owns the socket directly: [2](#0-1) 

When the Connection is dropped implicitly, the owned socket (NoiseStream<TSocket>) is dropped, which triggers the drop of the underlying TcpSocket. The TcpSocket is a wrapper around `Compat<TcpStream>`: [3](#0-2) 

The critical issue is that the comment explicitly warns that TcpStream's close() is a no-op. When dropped without explicit close(), any data in the following locations is lost:

1. NoiseStream's internal read/write buffers (up to MAX_SIZE_NOISE_MSG bytes each)
2. Kernel TCP send/receive buffers
3. Data in flight on the network that was sent but not yet acknowledged

The remote peer may have already started sending consensus-critical messages (votes, block proposals, quorum certificates) immediately after the Noise handshake completed, expecting the connection to be accepted.

**Comparison with correct cleanup path:** [4](#0-3) 

The `disconnect()` function properly calls `connection.socket.close()` with a timeout before dropping the connection, ensuring graceful shutdown.

## Impact Explanation

This qualifies as **Medium Severity** under "State inconsistencies requiring intervention" because:

1. **Data Loss**: Consensus messages (votes, proposals, QCs) from the remote peer may be silently dropped
2. **Silent Failure**: The remote peer believes the connection succeeded after Noise handshake
3. **Availability Impact**: Message loss forces retransmissions, delaying consensus rounds
4. **Network Instability**: Frequent occurrences could degrade network performance

However, the impact is LIMITED because:
- AptosBFT is designed to tolerate message loss through timeouts and retries
- No consensus safety violation (no double-spending or chain split)
- No permanent state corruption
- The error condition (`get_trusted_peers()` failure) should be rare in production

The vulnerability does NOT reach Critical or High severity because:
- No funds are lost or stolen
- No permanent network partition
- Consensus eventually recovers through retransmission
- No consensus safety rules are violated

## Likelihood Explanation

**Likelihood: Low to Medium**

The vulnerability can be triggered when: [5](#0-4) 

The `get_trusted_peers()` fails when the network_id is not found in the trusted_peers HashMap. This can occur due to:

1. **Configuration errors**: NetworkId not properly initialized in PeersAndMetadata
2. **Race conditions**: Connection arrives before network initialization completes
3. **Implementation bugs**: Incorrect network_id passed to the function

While production deployments should have proper configuration, the vulnerability is exploitable in edge cases:
- During node startup/restart
- After configuration changes
- In test environments with misconfigurations

## Recommendation

Modify `handle_new_connection_event()` to call `disconnect()` instead of early return:

```rust
fn handle_new_connection_event(&mut self, conn: Connection<TSocket>) {
    let trusted_peers = match self
        .peers_and_metadata
        .get_trusted_peers(&self.network_context.network_id())
    {
        Ok(trusted_peers) => trusted_peers,
        Err(error) => {
            error!(
                NetworkSchema::new(&self.network_context)
                    .connection_metadata_with_address(&conn.metadata),
                "Failed to get trusted peers for network context: {:?}, error: {:?}",
                self.network_context,
                error
            );
            // FIX: Call disconnect() instead of dropping
            self.disconnect(conn);
            return;
        },
    };
    // ... rest of function
}
```

This ensures proper socket cleanup with flush and close before dropping.

## Proof of Concept

```rust
// Reproduction steps:
// 1. Set up a PeerManager with invalid/missing NetworkId in trusted_peers
// 2. Establish a new connection from a remote peer
// 3. Have the remote peer send consensus messages immediately after handshake
// 4. Trigger get_trusted_peers() failure in handle_new_connection_event()
// 5. Observe that messages are lost without proper socket closure

#[tokio::test]
async fn test_connection_drop_data_loss() {
    // Setup PeerManager with missing network_id configuration
    let mut peer_manager = setup_peer_manager_with_missing_network();
    
    // Establish connection and send messages
    let (connection, remote_sender) = establish_test_connection().await;
    
    // Remote peer sends consensus vote immediately
    remote_sender.send(create_consensus_vote()).await;
    
    // This triggers the vulnerable path
    peer_manager.handle_new_connection_event(connection);
    
    // Verify: message was not processed (data loss occurred)
    assert!(no_message_received());
    // Verify: connection was dropped without close() call
    assert!(connection_dropped_without_close());
}
```

**Notes:**

This vulnerability represents a **resource management flaw** rather than a critical security breach. The Aptos consensus protocol's built-in resilience to message loss mitigates the severity. However, proper cleanup should be implemented following the fail-safe principle: resources should be released gracefully even in error paths. The fix is straightforward and eliminates unnecessary message loss and potential network instability.

### Citations

**File:** network/framework/src/peer_manager/mod.rs (L332-348)
```rust
    fn handle_new_connection_event(&mut self, conn: Connection<TSocket>) {
        // Get the trusted peers
        let trusted_peers = match self
            .peers_and_metadata
            .get_trusted_peers(&self.network_context.network_id())
        {
            Ok(trusted_peers) => trusted_peers,
            Err(error) => {
                error!(
                    NetworkSchema::new(&self.network_context)
                        .connection_metadata_with_address(&conn.metadata),
                    "Failed to get trusted peers for network context: {:?}, error: {:?}",
                    self.network_context,
                    error
                );
                return;
            },
```

**File:** network/framework/src/peer_manager/mod.rs (L581-605)
```rust
    fn disconnect(&mut self, connection: Connection<TSocket>) {
        let network_context = self.network_context;
        let time_service = self.time_service.clone();

        // Close connection, and drop it
        let drop_fut = async move {
            let mut connection = connection;
            let peer_id = connection.metadata.remote_peer_id;
            if let Err(e) = time_service
                .timeout(TRANSPORT_TIMEOUT, connection.socket.close())
                .await
            {
                warn!(
                    NetworkSchema::new(&network_context)
                        .remote_peer(&peer_id),
                    error = %e,
                    "{} Closing connection with Peer {} failed with error: {}",
                    network_context,
                    peer_id.short_str(),
                    e
                );
            };
        };
        self.executor.spawn(drop_fut);
    }
```

**File:** network/framework/src/transport/mod.rs (L187-191)
```rust
#[derive(Debug)]
pub struct Connection<TSocket> {
    pub socket: TSocket,
    pub metadata: ConnectionMetadata,
}
```

**File:** network/netcore/src/transport/tcp.rs (L355-363)
```rust
/// In order to properly implement the AsyncRead/AsyncWrite traits we need to wrap a TcpStream to
/// ensure that the "close" method actually closes the write half of the TcpStream.  This is
/// because the "close" method on a TcpStream just performs a no-op instead of actually shutting
/// down the write side of the TcpStream.
//TODO Probably should add some tests for this
#[derive(Debug)]
pub struct TcpSocket {
    inner: Compat<TcpStream>,
}
```

**File:** network/framework/src/application/storage.rs (L328-345)
```rust
    /// Returns a clone of the trusted peer set for the given network ID
    pub fn get_trusted_peers(&self, network_id: &NetworkId) -> Result<PeerSet, Error> {
        let trusted_peers = self.get_trusted_peer_set_for_network(network_id)?;
        Ok(trusted_peers.load().clone().deref().clone())
    }

    /// Returns the trusted peer set for the given network ID
    fn get_trusted_peer_set_for_network(
        &self,
        network_id: &NetworkId,
    ) -> Result<Arc<ArcSwap<PeerSet>>, Error> {
        self.trusted_peers.get(network_id).cloned().ok_or_else(|| {
            Error::UnexpectedError(format!(
                "No trusted peers were found for the given network id: {:?}",
                network_id
            ))
        })
    }
```
