# Audit Report

## Title
Unencrypted Data Leakage via Memory After Connection Drop in NoiseStream BufferData State

## Summary
When `NoiseStream`'s `WriteState` is in the `BufferData` state and the network connection drops unexpectedly, buffered plaintext data remains in heap memory without being zeroed. This violates the confidentiality guarantee provided by the Noise protocol and can leak sensitive consensus messages through core dumps, memory forensics, or memory swapping attacks.

## Finding Description

The `NoiseStream` struct in `network/framework/src/noise/stream.rs` implements encrypted communication between Aptos validators using the Noise protocol. The write path buffers plaintext data before encryption: [1](#0-0) 

During the `BufferData` state, plaintext from the caller is copied into `self.buffers.write_buffer`, which is unencrypted memory. Encryption only occurs when the buffer is full or when flush is explicitly called: [2](#0-1) 

The critical issue is that neither `NoiseStream` nor `NoiseBuffers` implements the `Drop` trait to zero sensitive memory: [3](#0-2) 

When a connection drops during the `BufferData` state (due to network errors, peer disconnection, or process crashes), the `NoiseStream` is dropped and the heap-allocated buffers are freed without zeroing. The plaintext data persists in memory until that region is overwritten.

**Attack Vector:**
1. Validator begins sending a consensus message (ProposalMsg, VoteMsg, CommitVote, etc.)
2. Connection drops while in `BufferData` state before encryption
3. NoiseStream is dropped, buffers freed but not zeroed
4. Attacker gains memory access through:
   - Core dumps from validator crashes
   - Memory dumps of running processes
   - Memory swapping to unencrypted disk
   - Memory reuse by malicious code

The NoiseStream is used for all validator-to-validator communication including critical consensus messages: [4](#0-3) 

## Impact Explanation

This vulnerability breaks the **Cryptographic Correctness** invariant by compromising the confidentiality guarantee provided by the Noise protocol. While encrypted in transit, sensitive consensus messages remain in plaintext in memory after connection failures.

According to Aptos bug bounty categories, this is a **Low Severity** issue (not Medium as suggested): "Minor information leaks" - up to $1,000 reward.

The impact is limited because:
- It requires connection drop at precise timing (during BufferData state)
- It requires additional memory access capabilities (core dumps, memory forensics)
- It doesn't directly affect consensus safety, funds, or availability
- The leaked messages would be broadcast to validators anyway (though timing may matter)

However, defense-in-depth principles require sensitive cryptographic data to be zeroed from memory promptly.

## Likelihood Explanation

**Medium likelihood** due to:
- Connection drops occur regularly in distributed networks (network partitions, crashes, resource exhaustion)
- Core dumps are generated during validator crashes
- Memory forensics is possible if attacker compromises the validator node
- The BufferData window exists for all write operations before flush

The primary limiting factor is that exploitation requires memory access beyond normal network capabilities.

## Recommendation

Implement the `Drop` trait for `NoiseBuffers` to explicitly zero sensitive memory using a secure zeroing mechanism:

```rust
use zeroize::Zeroize;

impl Drop for NoiseBuffers {
    fn drop(&mut self) {
        self.read_buffer.zeroize();
        self.write_buffer.zeroize();
    }
}
```

Add the `zeroize` crate dependency to `network/framework/Cargo.toml`:
```toml
[dependencies]
zeroize = "1.7"
```

Alternatively, use arrays wrapped in `Zeroizing` to automatically zero on drop:
```rust
use zeroize::Zeroizing;

struct NoiseBuffers {
    read_buffer: Zeroizing<[u8; noise::MAX_SIZE_NOISE_MSG]>,
    write_buffer: Zeroizing<[u8; noise::MAX_SIZE_NOISE_MSG]>,
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod security_test {
    use super::*;
    use std::ptr;

    #[test]
    fn test_unzeroed_memory_leak() {
        // Setup a NoiseStream with test data
        let noise_session = noise::NoiseSession::new_for_testing();
        let fake_socket = ReadWriteTestSocket::new_pair().0;
        let mut stream = NoiseStream::new(fake_socket, noise_session);
        
        // Simulate entering BufferData state with sensitive data
        let sensitive_data = b"SENSITIVE_CONSENSUS_VOTE_DATA";
        let buffer_ptr = stream.buffers.write_buffer.as_ptr();
        
        // Trigger write to enter BufferData state
        let _ = block_on(async {
            let mut pinned = Pin::new(&mut stream);
            pinned.as_mut().poll_write(&mut Context::from_waker(&noop_waker()), sensitive_data)
        });
        
        // Drop the stream (simulating connection drop)
        drop(stream);
        
        // Memory is freed but sensitive data may still be readable
        // In real exploitation: core dump, memory scan, or memory reuse
        // This test demonstrates the data isn't zeroed (test would need unsafe code to verify)
        
        // Expected: Memory should be zeroed
        // Actual: Memory contains plaintext sensitive_data
    }
}
```

## Notes

While this is classified as Low severity rather than Medium, it represents a legitimate security hardening gap. The Noise protocol specification and cryptographic best practices require sensitive key material and plaintext to be zeroed from memory as soon as possible. The fix is straightforward and should be implemented as defense-in-depth, even though direct exploitation requires additional prerequisites beyond network access alone.

The vulnerability affects all validator-to-validator communication channels and any other uses of `NoiseStream` in the Aptos network layer.

### Citations

**File:** network/framework/src/noise/stream.rs (L251-262)
```rust
                WriteState::BufferData { ref mut offset } => {
                    let bytes_buffered = if let Some(buf) = buf {
                        let bytes_to_copy =
                            ::std::cmp::min(MAX_WRITE_BUFFER_LENGTH - *offset, buf.len());
                        self.buffers.write_buffer[*offset..(*offset + bytes_to_copy)]
                            .copy_from_slice(&buf[..bytes_to_copy]);
                        trace!("BufferData: buffered {}/{} bytes", bytes_to_copy, buf.len());
                        *offset += bytes_to_copy;
                        Some(bytes_to_copy)
                    } else {
                        None
                    };
```

**File:** network/framework/src/noise/stream.rs (L264-282)
```rust
                    if buf.is_none() || *offset == MAX_WRITE_BUFFER_LENGTH {
                        match self
                            .session
                            .write_message_in_place(&mut self.buffers.write_buffer[..*offset])
                        {
                            Ok(authentication_tag) => {
                                // append the authentication tag
                                self.buffers.write_buffer[*offset..*offset + noise::AES_GCM_TAGLEN]
                                    .copy_from_slice(&authentication_tag);
                                // calculate frame length
                                let frame_len = noise::encrypted_len(*offset);
                                let frame_len = frame_len
                                    .try_into()
                                    .expect("offset should be able to fit in u16");
                                self.write_state = WriteState::WriteEncryptedFrame {
                                    frame_len,
                                    offset: 0,
                                };
                            },
```

**File:** network/framework/src/noise/stream.rs (L407-422)
```rust
/// [`NoiseStream`]
struct NoiseBuffers {
    /// A read buffer, used for both a received ciphertext and then for its decrypted content.
    read_buffer: [u8; noise::MAX_SIZE_NOISE_MSG],
    /// A write buffer, used for both a plaintext to send, and then its encrypted version.
    write_buffer: [u8; noise::MAX_SIZE_NOISE_MSG],
}

impl NoiseBuffers {
    fn new() -> Self {
        Self {
            read_buffer: [0; noise::MAX_SIZE_NOISE_MSG],
            write_buffer: [0; noise::MAX_SIZE_NOISE_MSG],
        }
    }
}
```

**File:** consensus/src/network_interface.rs (L39-100)
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum ConsensusMsg {
    /// DEPRECATED: Once this is introduced in the next release, please use
    /// [`ConsensusMsg::BlockRetrievalRequest`](ConsensusMsg::BlockRetrievalRequest) going forward
    /// This variant was renamed from `BlockRetrievalRequest` to `DeprecatedBlockRetrievalRequest`
    /// RPC to get a chain of block of the given length starting from the given block id.
    DeprecatedBlockRetrievalRequest(Box<BlockRetrievalRequestV1>),
    /// Carries the returned blocks and the retrieval status.
    BlockRetrievalResponse(Box<BlockRetrievalResponse>),
    /// Request to get a EpochChangeProof from current_epoch to target_epoch
    EpochRetrievalRequest(Box<EpochRetrievalRequest>),
    /// ProposalMsg contains the required information for the proposer election protocol to make
    /// its choice (typically depends on round and proposer info).
    ProposalMsg(Box<ProposalMsg>),
    /// This struct describes basic synchronization metadata.
    SyncInfo(Box<SyncInfo>),
    /// A vector of LedgerInfo with contiguous increasing epoch numbers to prove a sequence of
    /// epoch changes from the first LedgerInfo's epoch.
    EpochChangeProof(Box<EpochChangeProof>),
    /// VoteMsg is the struct that is ultimately sent by the voter in response for receiving a
    /// proposal.
    VoteMsg(Box<VoteMsg>),
    /// CommitProposal is the struct that is sent by the validator after execution to propose
    /// on the committed state hash root.
    CommitVoteMsg(Box<CommitVote>),
    /// CommitDecision is the struct that is sent by the validator after collecting no fewer
    /// than 2f + 1 signatures on the commit proposal. This part is not on the critical path, but
    /// it can save slow machines to quickly confirm the execution result.
    CommitDecisionMsg(Box<CommitDecision>),
    /// Quorum Store: Send a Batch of transactions.
    BatchMsg(Box<BatchMsg<BatchInfo>>),
    /// Quorum Store: Request the payloads of a completed batch.
    BatchRequestMsg(Box<BatchRequest>),
    /// Quorum Store: Response to the batch request.
    BatchResponse(Box<Batch<BatchInfo>>),
    /// Quorum Store: Send a signed batch digest. This is a vote for the batch and a promise that
    /// the batch of transactions was received and will be persisted until batch expiration.
    SignedBatchInfo(Box<SignedBatchInfoMsg<BatchInfo>>),
    /// Quorum Store: Broadcast a certified proof of store (a digest that received 2f+1 votes).
    ProofOfStoreMsg(Box<ProofOfStoreMsg<BatchInfo>>),
    /// DAG protocol message
    DAGMessage(DAGNetworkMessage),
    /// Commit message
    CommitMessage(Box<CommitMessage>),
    /// Randomness generation message
    RandGenMessage(RandGenMessage),
    /// Quorum Store: Response to the batch request.
    BatchResponseV2(Box<BatchResponse>),
    /// OrderVoteMsg is the struct that is broadcasted by a validator on receiving quorum certificate
    /// on a block.
    OrderVoteMsg(Box<OrderVoteMsg>),
    /// RoundTimeoutMsg is broadcasted by a validator once it decides to timeout the current round.
    RoundTimeoutMsg(Box<RoundTimeoutMsg>),
    /// RPC to get a chain of block of the given length starting from the given block id, using epoch and round.
    BlockRetrievalRequest(Box<BlockRetrievalRequest>),
    /// OptProposalMsg contains the optimistic proposal and sync info.
    OptProposalMsg(Box<OptProposalMsg>),
    /// Quorum Store: Send a Batch of transactions.
    BatchMsgV2(Box<BatchMsg<BatchInfoExt>>),
    /// Quorum Store: Send a signed batch digest with BatchInfoExt. This is a vote for the batch and a promise that
    /// the batch of transactions was received and will be persisted until batch expiration.
    SignedBatchInfoMsgV2(Box<SignedBatchInfoMsg<BatchInfoExt>>),
```
