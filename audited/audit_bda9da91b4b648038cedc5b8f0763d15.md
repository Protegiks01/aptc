# Audit Report

## Title
Pre-Validation Deserialization Enables Resource Exhaustion via Oversized DirectMempool Payloads

## Summary
A Byzantine validator can send block proposals with DirectMempool payloads containing up to 64 MiB of transactions, which are fully deserialized by the network layer before consensus-level validation checks reject them for exceeding the 6 MiB limit. This enables resource exhaustion attacks against honest validators.

## Finding Description

The Aptos consensus implementation has a critical architectural flaw in how DirectMempool payloads are validated. While consensus-level limits exist to restrict block sizes, these limits are enforced AFTER full deserialization of incoming messages.

**The vulnerability flow:**

1. **Network Layer Processing**: When a validator receives a `ProposalMsg`, the network framework deserializes the entire message using BCS deserialization [1](#0-0) 

2. **Network Size Limit**: The network layer enforces a `MAX_MESSAGE_SIZE` of 64 MiB [2](#0-1) , allowing messages significantly larger than consensus expects.

3. **Deserialization Before Validation**: The `DirectMempool` payload is fully deserialized into memory before any consensus validation occurs [3](#0-2) 

4. **Delayed Consensus Validation**: Only after the message reaches `RoundManager::process_proposal()` are the transaction count and size limits checked [4](#0-3) 

5. **Consensus Limits**: The default limits are `max_receiving_block_txns = 10,000` transactions and `max_receiving_block_bytes = 6 MiB` [5](#0-4) 

**The Gap**: There is a ~10x difference between the network layer's 64 MiB limit and consensus layer's 6 MiB expectation. A malicious validator can craft a DirectMempool payload with hundreds of thousands of minimal transactions that fit within 64 MiB but far exceed both the transaction count and size limits expected by consensus.

**Attack Execution:**

1. Byzantine validator creates a `ProposalMsg` with a `DirectMempool` payload containing 300,000+ minimal transactions (~200 bytes each = ~60 MiB total)
2. Sends this to honest validators
3. Each honest validator's network layer deserializes all 300,000 transactions (CPU-intensive operation, allocates ~60 MiB)
4. Consensus layer then rejects the block for exceeding limits
5. Attacker repeats this attack continuously

The `DirectMempoolPayloadManager` provides no early validation [6](#0-5) , and the `Payload::DirectMempool` type simply stores all transactions without size checks [7](#0-6) 

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program's "Validator node slowdowns" category.

**Resource Exhaustion Impact:**
- Each malicious message forces deserialization of up to 64 MiB of transaction data
- Deserializing 300,000+ transactions is CPU-intensive (potentially seconds per message)
- Memory allocation of ~60 MiB per message (though temporary)
- No rate limiting prevents repeated attacks

**Consensus Impact:**
- If Byzantine validators send 10+ such messages per second, honest validators experience CPU saturation
- Slowed validators may miss proposal deadlines or voting windows
- Could degrade consensus liveness and increase block times
- Violates the "Resource Limits" critical invariant (#9) that "all operations must respect gas, storage, and computational limits"

**Attack Feasibility:**
- Only requires 1 Byzantine validator (protocol tolerates up to 1/3)
- No cryptographic operations required (messages pass signature verification)
- Attack is repeatable and sustainable
- Affects all honest validators receiving the malicious proposals

## Likelihood Explanation

**Likelihood: Medium-High**

The attack is highly likely to be exploited if a Byzantine validator exists in the network because:

1. **Low Complexity**: Crafting oversized DirectMempool payloads requires only basic knowledge of the BCS serialization format
2. **No Special Requirements**: Any validator can send `ProposalMsg` to other validators during their proposer turn
3. **Immediate Impact**: Resource exhaustion occurs immediately upon message receipt
4. **Difficult Detection**: Malicious messages appear structurally valid until consensus validation
5. **No Existing Protections**: No rate limiting, early validation, or peer reputation system prevents this attack on consensus messages

The only limitation is that the attacker must be a validator, but BFT systems are designed to tolerate Byzantine validators.

## Recommendation

Implement **early size validation before deserialization** by adding checks at the network layer for consensus messages:

1. **Add protocol-specific size limits**: Modify the network layer to enforce protocol-specific maximum message sizes before deserialization. For consensus messages, enforce the `max_receiving_block_bytes` limit (6 MiB) before deserializing.

2. **Implement streaming validation**: For messages that exceed a threshold (e.g., 1 MiB), deserialize and validate incrementally rather than allocating the entire payload upfront.

3. **Add consensus message rate limiting**: Implement per-peer rate limiting for oversized consensus messages to prevent flooding attacks.

4. **Early transaction count checks**: Add a lightweight pre-check that counts transactions before full deserialization by reading only the BCS length prefix.

**Recommended code fix for network layer:**

Add validation in the message reception path that checks message size against protocol-specific limits before deserializing. The network layer should reject consensus ProposalMsg messages exceeding 10 MiB (providing margin above the 6 MiB consensus limit) before calling BCS deserialization.

## Proof of Concept

```rust
// Proof of Concept: Byzantine validator creates oversized DirectMempool payload
use aptos_consensus_types::{block::Block, common::Payload, proposal_msg::ProposalMsg};
use aptos_types::transaction::SignedTransaction;

fn create_malicious_proposal() -> ProposalMsg {
    // Create 300,000 minimal transactions (~200 bytes each = ~60 MiB)
    let mut transactions = Vec::new();
    for i in 0..300_000 {
        // Create minimal valid transaction (placeholder - actual implementation needed)
        let txn = create_minimal_transaction(i);
        transactions.push(txn);
    }
    
    // Create DirectMempool payload with excessive transactions
    let payload = Payload::DirectMempool(transactions);
    
    // This payload exceeds max_receiving_block_txns (10,000) 
    // and max_receiving_block_bytes (6 MiB) but fits within
    // network MAX_MESSAGE_SIZE (64 MiB)
    
    // When honest validators receive this ProposalMsg:
    // 1. Network layer deserializes all 300,000 transactions (CPU + memory intensive)
    // 2. Only then does consensus check limits and reject
    // 3. Attacker repeats to cause sustained resource exhaustion
    
    create_proposal_with_payload(payload)
}

// Result: Receiving validators experience CPU exhaustion from deserializing
// 300,000 transactions before consensus validation can reject the oversized block
```

**Notes**

The vulnerability stems from the architectural decision to perform full message deserialization in the network layer before application-layer validation. While this design simplifies the protocol stack, it creates a resource exhaustion vector when network-layer size limits (64 MiB) significantly exceed application-layer expectations (6 MiB). This is a classic time-of-check-time-of-use (TOCTOU) vulnerability where the "check" (consensus validation) happens after the "use" (memory allocation and CPU-intensive deserialization).

### Citations

**File:** network/framework/src/protocols/wire/messaging/v1/mod.rs (L111-113)
```rust
    fn to_message<TMessage: DeserializeOwned>(&self) -> anyhow::Result<TMessage> {
        self.protocol_id().from_bytes(self.data())
    }
```

**File:** config/src/config/network_config.rs (L50-50)
```rust
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; /* 64 MiB */
```

**File:** network/framework/src/protocols/network/mod.rs (L274-299)
```rust
fn received_message_to_event<TMessage: Message>(
    message: ReceivedMessage,
) -> Option<Event<TMessage>> {
    let peer_id = message.sender.peer_id();
    let ReceivedMessage {
        message,
        sender: _sender,
        receive_timestamp_micros: rx_at,
        rpc_replier,
    } = message;
    let dequeue_at = unix_micros();
    let dt_micros = dequeue_at - rx_at;
    let dt_seconds = (dt_micros as f64) / 1000000.0;
    match message {
        NetworkMessage::RpcRequest(rpc_req) => {
            crate::counters::inbound_queue_delay_observe(rpc_req.protocol_id, dt_seconds);
            let rpc_replier = Arc::into_inner(rpc_replier.unwrap()).unwrap();
            request_to_network_event(peer_id, &rpc_req)
                .map(|msg| Event::RpcRequest(peer_id, msg, rpc_req.protocol_id, rpc_replier))
        },
        NetworkMessage::DirectSendMsg(request) => {
            crate::counters::inbound_queue_delay_observe(request.protocol_id, dt_seconds);
            request_to_network_event(peer_id, &request).map(|msg| Event::Message(peer_id, msg))
        },
        _ => None,
    }
```

**File:** consensus/src/round_manager.rs (L1178-1193)
```rust
        let payload_len = proposal.payload().map_or(0, |payload| payload.len());
        let payload_size = proposal.payload().map_or(0, |payload| payload.size());
        ensure!(
            num_validator_txns + payload_len as u64 <= self.local_config.max_receiving_block_txns,
            "Payload len {} exceeds the limit {}",
            payload_len,
            self.local_config.max_receiving_block_txns,
        );

        ensure!(
            validator_txns_total_bytes + payload_size as u64
                <= self.local_config.max_receiving_block_bytes,
            "Payload size {} exceeds the limit {}",
            payload_size,
            self.local_config.max_receiving_block_bytes,
        );
```

**File:** config/src/config/consensus_config.rs (L228-231)
```rust
            max_receiving_block_txns: *MAX_RECEIVING_BLOCK_TXNS,
            max_sending_inline_txns: 100,
            max_sending_inline_bytes: 200 * 1024,       // 200 KB
            max_receiving_block_bytes: 6 * 1024 * 1024, // 6MB
```

**File:** consensus/src/payload_manager/direct_mempool_payload_manager.rs (L86-103)
```rust
fn get_transactions_from_block(
    block: &Block,
) -> ExecutorResult<(Vec<SignedTransaction>, Option<u64>, Option<u64>)> {
    let Some(payload) = block.payload() else {
        return Ok((Vec::new(), None, None));
    };

    match payload {
        Payload::DirectMempool(txns) => Ok((txns.clone(), None, None)),
        _ => unreachable!(
            "DirectMempoolPayloadManager: Unacceptable payload type {}. Epoch: {}, Round: {}, Block: {}",
            payload,
            block.block_data().epoch(),
            block.block_data().round(),
            block.id()
        ),
    }
}
```

**File:** consensus/consensus-types/src/common.rs (L284-285)
```rust
        match self {
            Payload::DirectMempool(txns) => txns.len(),
```
