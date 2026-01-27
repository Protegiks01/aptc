# Audit Report

## Title
Cross-Shard Messages Transmitted in Plaintext Over Unencrypted HTTP/gRPC Connections

## Summary
The remote executor service's cross-shard communication transmits sensitive blockchain state information (account balances, smart contract data, state modifications) over unencrypted HTTP/gRPC connections. Network observers can intercept and read all cross-shard messages in plaintext, exposing confidential transaction execution details before they are committed to the blockchain.

## Finding Description

The `send_cross_shard_msg()` function in the remote executor service uses `aptos_secure_net::network_controller` for cross-shard communication. Despite its name suggesting security, this network layer provides **no encryption**. [1](#0-0) 

The message serialization and transmission occurs through the `NetworkController`, which uses gRPC over plain HTTP. The critical flaw is in the gRPC client initialization: [2](#0-1) 

The connection string explicitly uses `http://` (not `https://`), and there is no TLS/SSL configuration anywhere in the module. The underlying transport is plain TCP: [3](#0-2) 

**Sensitive Data Exposed:**

Cross-shard messages contain `CrossShardMsg` enums with `RemoteTxnWrite` data: [4](#0-3) 

Each message includes:
- `StateKey`: Blockchain state keys (account addresses, resource identifiers)
- `WriteOp`: State modifications containing `StateValue.data: Bytes` with actual state data including account balances, smart contract state, token holdings, and other sensitive information [5](#0-4) 

**Attack Scenario:**

1. Deploy remote executor shards across network (e.g., cloud instances, data centers)
2. Attacker positions themselves as network observer (MITM, compromised router, malicious ISP)
3. Intercept gRPC traffic between shards on documented ports
4. Deserialize BCS-encoded messages to extract `StateKey` and `WriteOp` data
5. Read sensitive state information before blockchain commitment
6. Potential for front-running, information leakage, competitive advantages

**Security Expectation Mismatch:**

The main Aptos validator network uses NoiseIK encryption for all peer communications: [6](#0-5) 

However, the remote executor sharding feature uses an entirely separate network stack (`aptos_secure_net`) without encryption, creating a dangerous security gap.

## Impact Explanation

**High Severity** per Aptos bug bounty criteria:

1. **Significant Protocol Violation**: The system exposes sensitive internal execution state over unencrypted channels, violating fundamental confidentiality expectations for distributed blockchain systems

2. **Information Disclosure**: Network observers can intercept:
   - Pre-commitment state modifications
   - Account balance changes
   - Smart contract execution patterns
   - Transaction ordering and execution flow
   - Resource access patterns

3. **Enabler for Further Attacks**: Information leakage could facilitate:
   - Front-running attacks using execution pattern knowledge
   - Targeted attacks on high-value accounts
   - Competitive intelligence gathering
   - Privacy violations for users

4. **Trust Model Violation**: While the module is named `aptos_secure_net`, it provides no transport security, creating a false sense of security for operators

## Likelihood Explanation

**High Likelihood** in production deployments:

1. **No Deployment Restrictions**: The executor service accepts arbitrary `SocketAddr` via command-line arguments with no warnings about network security requirements: [7](#0-6) 

2. **Natural Multi-Machine Deployment**: Performance-oriented sharding naturally encourages deploying across multiple machines/data centers over network connections

3. **No Documentation Warning**: No comments or documentation warn operators that these connections MUST be on private/VPN networks

4. **Simple Exploitation**: Any network observer with packet capture capabilities can intercept and read traffic

## Recommendation

**Immediate Fix**: Implement TLS/SSL encryption for all gRPC connections in the `aptos_secure_net` module.

**Code Changes Required**:

1. Modify `GRPCNetworkMessageServiceClientWrapper::get_channel()` to use HTTPS with TLS:

```rust
// In secure/net/src/grpc_network_service/mod.rs
async fn get_channel(remote_addr: String, tls_config: ClientTlsConfig) -> NetworkMessageServiceClient<Channel> {
    info!("Trying to connect to remote server at {:?}", remote_addr);
    let conn = tonic::transport::Endpoint::new(format!("https://{}", remote_addr))
        .unwrap()
        .tls_config(tls_config)
        .unwrap()
        .connect_lazy();
    NetworkMessageServiceClient::new(conn).max_decoding_message_size(MAX_MESSAGE_SIZE)
}
```

2. Update `GRPCNetworkMessageServiceServerWrapper` to use TLS server configuration with certificates

3. Add certificate management infrastructure (generation, distribution, validation)

**Alternative Mitigations**:

- Add prominent documentation warnings that remote executor service MUST run on isolated/VPN networks
- Implement network address validation to restrict to private IP ranges
- Add configuration flags requiring explicit opt-in for unencrypted mode with warnings

## Proof of Concept

**Demonstration Steps**:

1. Deploy two remote executor shards on separate machines:
```bash
# Shard 0
./executor-service --shard-id 0 --num-shards 2 \
  --remote-executor-addresses 10.0.1.1:9000 10.0.1.2:9000 \
  --coordinator-address 10.0.0.1:8000

# Shard 1  
./executor-service --shard-id 1 --num-shards 2 \
  --remote-executor-addresses 10.0.1.1:9000 10.0.1.2:9000 \
  --coordinator-address 10.0.0.1:8000
```

2. Use packet capture on network between shards:
```bash
tcpdump -i eth0 -w cross_shard.pcap port 9000
```

3. Execute transactions that trigger cross-shard communication

4. Analyze captured traffic:
```bash
wireshark cross_shard.pcap
# Filter: tcp.port == 9000
# Observe plaintext gRPC frames containing BCS-serialized CrossShardMsg
```

5. Decode messages using BCS deserializer:
```rust
use bcs;
use aptos_vm::sharded_block_executor::messages::CrossShardMsg;

let captured_bytes: Vec<u8> = /* extracted from packet capture */;
let msg: CrossShardMsg = bcs::from_bytes(&captured_bytes).unwrap();
// msg now contains plaintext StateKey and WriteOp data
```

**Expected Result**: All cross-shard state modifications are visible in plaintext to network observers, including sensitive state data that should remain confidential during execution.

## Notes

- This vulnerability affects the remote executor sharding feature, which may not be enabled in all deployments
- The main Aptos validator network is NOT affected as it uses NoiseIK encryption
- The severity is "High" rather than "Critical" because there is no direct fund loss, but it represents a significant protocol security violation
- Operators deploying remote executor shards over untrusted networks are immediately vulnerable
- The module name `aptos_secure_net` is misleading as it implies security properties that do not exist

### Citations

**File:** execution/executor-service/src/remote_cross_shard_client.rs (L55-59)
```rust
    fn send_cross_shard_msg(&self, shard_id: ShardId, round: RoundId, msg: CrossShardMsg) {
        let input_message = bcs::to_bytes(&msg).unwrap();
        let tx = self.message_txs[shard_id][round].lock().unwrap();
        tx.send(Message::new(input_message)).unwrap();
    }
```

**File:** secure/net/src/grpc_network_service/mod.rs (L124-130)
```rust
    pub fn new(rt: &Runtime, remote_addr: SocketAddr) -> Self {
        Self {
            remote_addr: remote_addr.to_string(),
            remote_channel: rt
                .block_on(async { Self::get_channel(format!("http://{}", remote_addr)).await }),
        }
    }
```

**File:** secure/net/src/lib.rs (L239-258)
```rust
            let mut stream = TcpStream::connect_timeout(&self.server, timeout);

            let sleeptime = time::Duration::from_millis(100);
            while let Err(err) = stream {
                self.increment_counter(Method::Connect, MethodResult::Failure);
                warn!(SecureNetLogSchema::new(
                    &self.service,
                    NetworkMode::Client,
                    LogEvent::ConnectionFailed,
                )
                .error(&err.into())
                .remote_peer(&self.server));

                thread::sleep(sleeptime);
                stream = TcpStream::connect_timeout(&self.server, timeout);
            }

            let stream = stream?;
            stream.set_nodelay(true)?;
            self.stream = Some(NetworkStream::new(stream, self.server, self.timeout_ms));
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/messages.rs (L7-18)
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum CrossShardMsg {
    RemoteTxnWriteMsg(RemoteTxnWrite),
    StopMsg,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RemoteTxnWrite {
    state_key: StateKey,
    // The write op is None if the transaction is aborted.
    write_op: Option<WriteOp>,
}
```

**File:** types/src/write_set.rs (L85-91)
```rust
#[derive(Clone, Debug, Eq, PartialEq, AsRefStr)]
pub enum BaseStateOp {
    Creation(StateValue),
    Modification(StateValue),
    Deletion(StateValueMetadata),
    MakeHot,
}
```

**File:** network/README.md (L24-28)
```markdown
* TCP for reliable transport.
* [NoiseIK] for authentication and full end-to-end encryption.
* On-chain [`NetworkAddress`](../types/src/network_address/mod.rs) set for discovery, with
  optional seed peers in the [`NetworkConfig`]
  as a fallback.
```

**File:** execution/executor-service/src/main.rs (L20-24)
```rust
    #[clap(long, num_args = 1..)]
    pub remote_executor_addresses: Vec<SocketAddr>,

    #[clap(long)]
    pub coordinator_address: SocketAddr,
```
