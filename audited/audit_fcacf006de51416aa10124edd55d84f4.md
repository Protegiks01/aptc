# Audit Report

## Title
Message Routing Failure for Quorum Store V2 Messages Breaks Consensus Formation

## Summary
The NetworkTask in `consensus/src/network.rs` fails to route V2 quorum store messages (`SignedBatchInfoMsgV2`, `BatchMsgV2`, `ProofOfStoreMsgV2`) to the appropriate handler channel. When these messages are received from the network, they fall through to the default case and are silently dropped, completely breaking quorum formation when the `enable_batch_v2` configuration flag is enabled.

## Finding Description
The batch coordinator sends `SignedBatchInfoMsgV2` messages as part of the quorum store protocol. [1](#0-0) 

However, the `NetworkTask::start()` method only routes V1 variants of quorum store messages: [2](#0-1) 

The V2 message variants (`SignedBatchInfoMsgV2`, `BatchMsgV2`, `ProofOfStoreMsgV2`) are defined in the ConsensusMsg enum [3](#0-2)  but are NOT included in the pattern match that routes quorum store messages to the `quorum_store_messages_tx` channel.

When V2 messages are received, they fall through to the catch-all default case which logs a warning and drops the message: [4](#0-3) 

The `enable_batch_v2` configuration flag controls whether V2 batches are created and broadcast: [5](#0-4) 

When enabled, validators broadcast V2 batches and send V2 signed batch info messages. However, recipient nodes drop these messages because the NetworkTask doesn't route them properly. This prevents validators from receiving the signed batch information needed to form quorums on batches, completely breaking the quorum store protocol.

**Invariant Violated:** Consensus Safety - AptosBFT must prevent liveness failures and ensure quorum formation succeeds.

## Impact Explanation
This is a **Critical Severity** vulnerability that causes total loss of liveness/network availability when triggered.

When `enable_batch_v2` is enabled:
1. Validators create and broadcast V2 batches
2. Validators send `SignedBatchInfoMsgV2` messages containing their signatures on batches
3. Recipients drop these messages due to the routing bug
4. The proof manager never receives the signed batch information
5. Quorum cannot form on batches (needs 2f+1 signatures)
6. The quorum store protocol stalls
7. Block proposals cannot include batch payloads
8. Consensus cannot progress

This affects **all validators** in the network simultaneously once the feature is enabled, causing a complete network halt requiring either a hotfix deployment or disabling the feature flag via governance.

## Likelihood Explanation
**Current State:** The vulnerability is dormant because `enable_batch_v2` defaults to `false`. [6](#0-5) 

**Future Risk:** This is a **latent critical bug** that will trigger during any protocol upgrade that enables V2 batches. The presence of the configuration flag, V2 message types, and complete V2 batch infrastructure indicates this feature is intended for production use. When enabled, the bug triggers **automatically and deterministically** on every V2 message transmission.

**Complexity:** No attacker action required - this is a code defect that breaks the network automatically when the feature is enabled.

## Recommendation
Add the V2 message variants to the quorum store message routing pattern in `NetworkTask::start()`:

**File:** `consensus/src/network.rs`

**Current code (lines 823-830):** Only matches V1 variants

**Fixed code:** Add V2 variants to the pattern match:
```rust
match msg {
    quorum_store_msg @ (ConsensusMsg::SignedBatchInfo(_)
    | ConsensusMsg::SignedBatchInfoMsgV2(_)  // ADD THIS
    | ConsensusMsg::BatchMsg(_)
    | ConsensusMsg::BatchMsgV2(_)            // ADD THIS
    | ConsensusMsg::ProofOfStoreMsg(_)
    | ConsensusMsg::ProofOfStoreMsgV2(_)) => {  // ADD THIS
        Self::push_msg(
            peer_id,
            quorum_store_msg,
            &self.quorum_store_messages_tx,
        );
    },
```

## Proof of Concept
**Reproduction Steps:**

1. Enable V2 batches in validator configuration:
```toml
[consensus.quorum_store]
enable_batch_v2 = true
```

2. Start two validators with this configuration

3. Observe validator logs for "Unexpected direct send msg" warnings when V2 messages arrive

4. Monitor consensus metrics - observe that:
   - Batches are created and broadcast
   - SignedBatchInfoMsgV2 messages are sent
   - Recipients log warnings and drop the messages
   - Proof manager never receives signatures
   - Quorum formation fails
   - Block proposals stall

**Expected behavior:** V2 messages should be routed to quorum store handlers and processed normally

**Actual behavior:** V2 messages are dropped, breaking consensus

## Notes
This vulnerability directly answers the security question: "Can the network layer modify or drop messages selectively, breaking quorum formation?" Yes, the network layer's message routing code **does** drop V2 messages selectively due to this bug, which breaks quorum formation. While not malicious tampering, the effect is identical - critical consensus messages are lost.

### Citations

**File:** consensus/src/quorum_store/batch_coordinator.rs (L108-110)
```rust
                    network_sender
                        .send_signed_batch_info_msg_v2(signed_batch_infos, vec![peer_id])
                        .await;
```

**File:** consensus/src/network.rs (L823-830)
```rust
                        quorum_store_msg @ (ConsensusMsg::SignedBatchInfo(_)
                        | ConsensusMsg::BatchMsg(_)
                        | ConsensusMsg::ProofOfStoreMsg(_)) => {
                            Self::push_msg(
                                peer_id,
                                quorum_store_msg,
                                &self.quorum_store_messages_tx,
                            );
```

**File:** consensus/src/network.rs (L937-940)
```rust
                        _ => {
                            warn!(remote_peer = peer_id, "Unexpected direct send msg");
                            continue;
                        },
```

**File:** consensus/src/network_interface.rs (L97-102)
```rust
    BatchMsgV2(Box<BatchMsg<BatchInfoExt>>),
    /// Quorum Store: Send a signed batch digest with BatchInfoExt. This is a vote for the batch and a promise that
    /// the batch of transactions was received and will be persisted until batch expiration.
    SignedBatchInfoMsgV2(Box<SignedBatchInfoMsg<BatchInfoExt>>),
    /// Quorum Store: Broadcast a certified proof of store (a digest that received 2f+1 votes) with BatchInfoExt.
    ProofOfStoreMsgV2(Box<ProofOfStoreMsg<BatchInfoExt>>),
```

**File:** config/src/config/quorum_store_config.rs (L102-102)
```rust
    pub enable_batch_v2: bool,
```

**File:** config/src/config/quorum_store_config.rs (L144-144)
```rust
            enable_batch_v2: false,
```
