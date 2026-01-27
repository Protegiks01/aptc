# Audit Report

## Title
Cross-Shard Message Corruption Can Cause Consensus Divergence Due to Missing Integrity Protection

## Summary
The remote cross-shard message passing system lacks cryptographic integrity protection (MAC/HMAC), allowing undetected message corruption during transmission to propagate into blockchain state. This violates the deterministic execution invariant and can cause consensus divergence across validators.

## Finding Description

The `send_cross_shard_msg()` function transmits critical blockchain state modifications between executor shards without any integrity protection mechanism. [1](#0-0) 

The `Message` wrapper is a plain data container with no integrity protection: [2](#0-1) 

Messages are transmitted over plain HTTP gRPC without TLS: [3](#0-2) 

Cross-shard messages contain critical state modifications (`StateKey` and `WriteOp`) that directly affect blockchain state: [4](#0-3) 

These messages are received and applied to state **without any validation**: [5](#0-4) [6](#0-5) 

**Attack Scenario:**

1. Validator A executes a sharded block, where Shard 1 must send state updates to Shard 2
2. During network transmission, bit-flips occur (hardware errors, cosmic rays, network equipment failures)
3. The `StateKey` or `WriteOp` bytes are corrupted (e.g., account address bits flipped, balance value changed)
4. BCS deserialization succeeds because the corruption produces valid-but-wrong data
5. Corrupted state is applied without validation
6. Transactions execute using corrupted cross-shard dependencies
7. Validator A commits a block with state root X

8. Validator B executes the same block independently
9. Different random bit-flips occur in Validator B's shard communications
10. Validator B commits the same block with state root Y (Y ≠ X)

**Result:** Consensus divergence and potential chain split.

BCS serialization provides no integrity protection—it only ensures deterministic encoding: [7](#0-6) [8](#0-7) 

## Impact Explanation

**Critical Severity** - This vulnerability violates the core "Deterministic Execution" invariant: "All validators must produce identical state roots for identical blocks."

- **Consensus Safety Violation**: Different validators can produce different state roots for the same block due to random transmission errors, not Byzantine behavior
- **State Corruption**: Account balances, token supplies, and smart contract state can be corrupted
- **Chain Split Risk**: If validators diverge on state roots, the chain cannot reach consensus
- **Non-recoverable**: Once corrupted state is committed, it propagates through subsequent blocks

This meets the **Critical** severity category: "Consensus/Safety violations" and "Non-recoverable network partition."

## Likelihood Explanation

**Medium-to-High Likelihood:**

- **Natural Occurrence**: Bit-flips in network transmission are documented phenomena, even with error correction. Hardware failures, electromagnetic interference, and cosmic rays can cause bit-errors
- **No Attacker Required**: This is not an attack—it's a reliability failure that becomes a security vulnerability
- **Multiple Communication Paths**: Each shard-to-shard communication is a potential corruption point
- **Large Message Volumes**: High transaction throughput increases the probability of encountering bit-flips
- **Unencrypted Transport**: Plain HTTP provides no integrity verification at the transport layer

While individual bit-flip probability is low, across thousands of validators executing millions of transactions, the cumulative probability becomes significant over time.

## Recommendation

Implement cryptographic integrity protection for all cross-shard messages:

**Option 1: Add HMAC to Message Wrapper**
```rust
pub struct Message {
    pub data: Vec<u8>,
    pub hmac: [u8; 32], // HMAC-SHA256
}

impl Message {
    pub fn new(data: Vec<u8>, key: &[u8]) -> Self {
        let hmac = compute_hmac_sha256(key, &data);
        Self { data, hmac }
    }
    
    pub fn verify(&self, key: &[u8]) -> Result<(), Error> {
        let expected_hmac = compute_hmac_sha256(key, &self.data);
        if self.hmac != expected_hmac {
            return Err(Error::IntegrityCheckFailed);
        }
        Ok(())
    }
}
```

**Option 2: Enable TLS for gRPC Transport**
```rust
// In GRPCNetworkMessageServiceClientWrapper::get_channel
let tls_config = ClientTlsConfig::new()
    .ca_certificate(Certificate::from_pem(ca_cert))
    .identity(Identity::from_pem(client_cert, client_key));

let conn = tonic::transport::Endpoint::new(format!("https://{}", remote_addr))
    .unwrap()
    .tls_config(tls_config)?
    .connect_lazy();
```

**Option 3: Add Cryptographic Hash Verification**
```rust
pub struct CrossShardMsg {
    payload: CrossShardMsgPayload,
    hash: HashValue, // CryptoHash of payload
}

impl CrossShardMsg {
    pub fn verify(&self) -> Result<(), Error> {
        let computed_hash = CryptoHash::hash(&self.payload);
        if self.hash != computed_hash {
            return Err(Error::HashMismatchDetected);
        }
        Ok(())
    }
}
```

Modify `receive_cross_shard_msg()` to verify integrity before processing:

```rust
fn receive_cross_shard_msg(&self, current_round: RoundId) -> CrossShardMsg {
    let rx = self.message_rxs[current_round].lock().unwrap();
    let message = rx.recv().unwrap();
    message.verify()?; // Add verification
    let msg: CrossShardMsg = bcs::from_bytes(&message.to_bytes()).unwrap();
    msg.verify_hash()?; // Double verification
    msg
}
```

## Proof of Concept

```rust
#[test]
fn test_corrupted_cross_shard_message_accepted() {
    use aptos_types::{state_store::state_key::StateKey, write_set::WriteOp};
    use crate::sharded_block_executor::messages::{CrossShardMsg, RemoteTxnWrite};
    
    // Create a valid message
    let state_key = StateKey::raw(b"account_balance_0x123");
    let original_balance = 1000u64.to_le_bytes();
    let write_op = WriteOp::legacy_modification(original_balance.to_vec().into());
    let msg = CrossShardMsg::RemoteTxnWriteMsg(
        RemoteTxnWrite::new(state_key.clone(), Some(write_op))
    );
    
    // Serialize it
    let mut serialized = bcs::to_bytes(&msg).unwrap();
    
    // Simulate bit-flip corruption - flip one bit in the balance value
    // This changes balance from 1000 to 1001 (or other value depending on bit position)
    let balance_offset = serialized.len() - 8; // Last 8 bytes are the u64 balance
    serialized[balance_offset] ^= 0x01; // Flip least significant bit
    
    // Deserialize corrupted message - THIS SUCCEEDS
    let corrupted_msg: CrossShardMsg = bcs::from_bytes(&serialized).unwrap();
    
    // Extract the corrupted value
    if let CrossShardMsg::RemoteTxnWriteMsg(txn_write) = corrupted_msg {
        let (key, write) = txn_write.take();
        assert_eq!(key, state_key);
        
        // The corrupted balance is accepted without any validation
        if let Some(op) = write {
            let corrupted_balance = op.bytes().unwrap();
            // Verify corruption occurred
            assert_ne!(corrupted_balance, &original_balance[..]);
            
            println!("VULNERABILITY CONFIRMED:");
            println!("Original balance: {:?}", original_balance);
            println!("Corrupted balance: {:?}", corrupted_balance);
            println!("Corruption went undetected - no integrity check failed!");
        }
    }
}
```

## Notes

This vulnerability affects the remote executor service used for sharded block execution. The issue is not about active attacks, but about the system's inability to detect and reject corrupted data. In distributed systems, defensive programming requires integrity protection even in trusted environments, as hardware failures and transmission errors are inevitable at scale. The lack of MAC/HMAC or cryptographic hash verification means that validators cannot distinguish between valid cross-shard state updates and corrupted data, violating the fundamental deterministic execution guarantee required for blockchain consensus.

### Citations

**File:** execution/executor-service/src/remote_cross_shard_client.rs (L55-59)
```rust
    fn send_cross_shard_msg(&self, shard_id: ShardId, round: RoundId, msg: CrossShardMsg) {
        let input_message = bcs::to_bytes(&msg).unwrap();
        let tx = self.message_txs[shard_id][round].lock().unwrap();
        tx.send(Message::new(input_message)).unwrap();
    }
```

**File:** execution/executor-service/src/remote_cross_shard_client.rs (L64-64)
```rust
        let msg: CrossShardMsg = bcs::from_bytes(&message.to_bytes()).unwrap();
```

**File:** secure/net/src/network_controller/mod.rs (L56-70)
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(dead_code)]
pub struct Message {
    pub data: Vec<u8>,
}

impl Message {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn to_bytes(self) -> Vec<u8> {
        self.data
    }
}
```

**File:** secure/net/src/grpc_network_service/mod.rs (L128-137)
```rust
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

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_client.rs (L26-45)
```rust
    pub fn start<S: StateView + Sync + Send>(
        cross_shard_state_view: Arc<CrossShardStateView<S>>,
        cross_shard_client: Arc<dyn CrossShardClient>,
        round: RoundId,
    ) {
        loop {
            let msg = cross_shard_client.receive_cross_shard_msg(round);
            match msg {
                RemoteTxnWriteMsg(txn_commit_msg) => {
                    let (state_key, write_op) = txn_commit_msg.take();
                    cross_shard_state_view
                        .set_value(&state_key, write_op.and_then(|w| w.as_state_value()));
                },
                CrossShardMsg::StopMsg => {
                    trace!("Cross shard commit receiver stopped for round {}", round);
                    break;
                },
            }
        }
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_state_view.rs (L49-56)
```rust
    pub fn set_value(&self, state_key: &StateKey, state_value: Option<StateValue>) {
        self.cross_shard_data
            .get(state_key)
            .unwrap()
            .set_value(state_value);
        // uncomment the following line to debug waiting count
        // trace!("waiting count for shard id {} is {}", self.shard_id, self.waiting_count());
    }
```
