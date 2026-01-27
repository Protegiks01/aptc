# Audit Report

## Title
Memory Exhaustion Vulnerability in OptProposalMsg Verification Due to Missing Pre-Verification Size Checks

## Summary
OptProposalMsg messages can bypass consensus payload size limits during verification, allowing malicious validators to cause memory exhaustion by sending payloads up to 64 MiB (10x the consensus limit of 6 MiB). The vulnerability occurs because payload size validation happens after cryptographic verification and memory-intensive operations, violating the Resource Limits invariant.

## Finding Description

The vulnerability exists in the message processing pipeline where OptProposalMsg messages are handled. The attack flow is:

**Step 1: Network-Level Deserialization**
Messages are received and fully deserialized at the network layer with a maximum size of 64 MiB. [1](#0-0) 

**Step 2: Verification Before Size Checks**
The deserialized OptProposalMsg undergoes cryptographic verification where the payload's `verify()` method is called, which includes memory-intensive operations. [2](#0-1) 

**Step 3: Memory Amplification During Verification**
For QuorumStoreInlineHybrid payloads, the verification process clones transaction vectors, potentially doubling memory consumption. [3](#0-2) 

**Step 4: Late Size Validation**
Size checks against consensus limits (max_receiving_block_bytes = 6 MiB) only occur in `process_proposal()`, which is called AFTER verification completes. [4](#0-3) [5](#0-4) 

**Attack Scenario:**
A malicious validator crafts OptProposalMsg messages with inline batches totaling ~60 MiB of transactions. Each message:
1. Passes network layer validation (64 MiB limit)
2. Gets fully deserialized (~60 MiB allocated)
3. Undergoes verification with transaction cloning (~120 MiB peak usage)
4. Gets rejected only after verification completes

By sending multiple such messages concurrently, an attacker can exhaust validator memory before size checks reject them.

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty program:
- **Validator node slowdowns**: Memory exhaustion degrades performance
- **Potential validator crashes**: Out-of-memory conditions can crash nodes
- **Liveness impact**: If multiple validators crash simultaneously, consensus liveness is affected

The 10x size gap (64 MiB network limit vs 6 MiB consensus limit) creates a significant attack surface where malicious validators can force honest validators to process oversized payloads.

## Likelihood Explanation

**Likelihood: Medium-High**

Requirements for exploitation:
- Attacker must control at least one validator (Byzantine fault model assumes up to 1/3)
- No special privileges beyond validator status required
- Attack is trivial to execute - simply send oversized OptProposalMsg messages

Mitigating factors:
- Requires validator access (but within Byzantine threat model)
- BoundedExecutor may limit concurrent processing

However, the vulnerability is easily exploitable by any malicious validator and the memory consumption occurs before any protective checks.

## Recommendation

Add payload size validation BEFORE cryptographic verification in the message processing pipeline:

1. **Immediate fix**: Add size checks in `epoch_manager.rs` before spawning verification tasks:

```rust
// In epoch_manager.rs, before line 1587
if let UnverifiedEvent::OptProposalMsg(proposal) = &unverified_event {
    let payload_size = proposal.block_data().payload().map_or(0, |p| p.size());
    ensure!(
        payload_size <= self.config.max_receiving_block_bytes,
        "OptProposalMsg payload size {} exceeds limit {} before verification",
        payload_size,
        self.config.max_receiving_block_bytes
    );
}
```

2. **Defense in depth**: Consider adding network-layer size limits specific to consensus messages that are stricter than the general 64 MiB limit.

3. **Remove unnecessary cloning**: Optimize `verify_inline_batches()` to avoid cloning transaction payloads during verification.

## Proof of Concept

```rust
// Rust PoC demonstrating the vulnerability
use aptos_consensus_types::opt_proposal_msg::OptProposalMsg;
use aptos_consensus_types::opt_block_data::OptBlockData;
use aptos_consensus_types::common::Payload;
use aptos_types::transaction::SignedTransaction;

// Malicious validator creates oversized OptProposalMsg
fn create_malicious_opt_proposal() -> OptProposalMsg {
    // Create large inline batches totaling ~60 MiB
    let mut large_txns = Vec::new();
    for _ in 0..6000 {
        // Each transaction ~10 KB = 60 MiB total
        large_txns.push(create_large_transaction(10_000));
    }
    
    let payload = Payload::QuorumStoreInlineHybrid(
        vec![(batch_info, large_txns)], // Will be cloned during verify()
        ProofWithData::empty(),
        None,
    );
    
    // OptBlockData and OptProposalMsg construction
    let block_data = OptBlockData::new(/*...with large payload...*/);
    OptProposalMsg::new(block_data, sync_info)
}

// When verify() is called:
// 1. Message already deserialized: ~60 MiB in memory
// 2. verify_inline_batches() clones transactions: another ~60 MiB
// 3. Total peak memory: ~120 MiB per message
// 4. Size check only happens AFTER verification fails
// 5. Multiply by concurrent messages for memory exhaustion
```

## Notes

The vulnerability violates the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." The gap between network-layer message limits and consensus-layer payload limits creates an exploitable window where excessive resources are consumed before validation occurs.

The fix should ensure that payload size validation happens before any expensive operations (deserialization, cryptographic verification, memory cloning) to prevent resource exhaustion attacks.

### Citations

**File:** config/src/config/network_config.rs (L50-50)
```rust
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; /* 64 MiB */
```

**File:** consensus/consensus-types/src/opt_proposal_msg.rs (L110-119)
```rust
        let (payload_verify_result, qc_verify_result) = rayon::join(
            || {
                self.block_data()
                    .payload()
                    .verify(validator, proof_cache, quorum_store_enabled)
            },
            || self.block_data().grandparent_qc().verify(validator),
        );
        payload_verify_result?;
        qc_verify_result?;
```

**File:** consensus/consensus-types/src/common.rs (L541-556)
```rust
    pub fn verify_inline_batches<'a, T: TBatchInfo + 'a>(
        inline_batches: impl Iterator<Item = (&'a T, &'a Vec<SignedTransaction>)>,
    ) -> anyhow::Result<()> {
        for (batch, payload) in inline_batches {
            // TODO: Can cloning be avoided here?
            let computed_digest = BatchPayload::new(batch.author(), payload.clone()).hash();
            ensure!(
                computed_digest == *batch.digest(),
                "Hash of the received inline batch doesn't match the digest value for batch {:?}: {} != {}",
                batch,
                computed_digest,
                batch.digest()
            );
        }
        Ok(())
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
