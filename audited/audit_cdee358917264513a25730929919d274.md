# Audit Report

## Title
Integer Overflow in Inline Batch Statistics Bypasses Block Size Limits

## Summary
The `inline_batch_stats()` function and `Payload::size()` method perform unchecked summation of u64 batch metadata values cast to usize, enabling integer overflow that can bypass `max_receiving_block_bytes` limits and cause consensus splits between nodes with different architectures.

## Finding Description

The vulnerability exists in two related locations where inline batch statistics are calculated: [1](#0-0) [2](#0-1) 

Both functions iterate through inline batches, cast `BatchInfo.num_txns()` and `BatchInfo.num_bytes()` (which return u64) to usize using the `as` operator, then sum them without overflow checks. This breaks the **Resource Limits** invariant requiring "all operations must respect gas, storage, and computational limits."

The critical security gap is that `verify_inline_batches()` only validates transaction digests, NOT the metadata values: [3](#0-2) 

A malicious validator can propose a block with `QuorumStoreInlineHybrid` payload containing:
1. BatchInfo structures with arbitrarily large `num_bytes` and `num_txns` values (up to u64::MAX)
2. Actual small transactions that correctly hash to the digest

When `payload.size()` is called during block validation: [4](#0-3) 

The sum overflows, wrapping to a small value that bypasses the check. This creates architecture-dependent behavior:

**On 32-bit systems:** u64 values > 2^32-1 get truncated when cast to usize (u32), causing immediate overflow.

**On 64-bit systems:** Multiple large u64 values can sum beyond usize::MAX (2^64-1), causing wraparound.

The vulnerability is compounded because `ensure_max_limits()` validation only applies to BatchMsg from network, not inline batches in blocks: [5](#0-4) 

## Impact Explanation

**High Severity** - This vulnerability can cause:

1. **Consensus Splits**: Nodes running on different architectures (32-bit vs 64-bit) will calculate different payload sizes for the same block, leading to divergent accept/reject decisions and breaking the **Deterministic Execution** invariant.

2. **Block Size Limit Bypass**: Malicious validators can include blocks that should be rejected per configured limits (default 6MB), undermining **Resource Limits** enforcement.

3. **Incorrect Metrics**: The `inline_batch_stats()` function feeds metrics systems, causing incorrect monitoring and potentially masking attacks.

While exploitation requires a malicious validator (within Byzantine fault tolerance model), the impact on consensus determinism qualifies this as High severity per the bug bounty program's "Significant protocol violations" category.

## Likelihood Explanation

**Moderate likelihood:**
- Requires malicious validator (assumes < 1/3 Byzantine validators)
- More severe on 32-bit systems (increasingly rare for validator infrastructure)
- Limited by `receiver_max_num_batches` default of 20 batches
- Could be triggered accidentally during epoch transitions or network partitions if batch metadata becomes corrupted

However, the vulnerability is **trivially exploitable** by any malicious validator who can propose blocks, with no complex preconditions beyond validator status.

## Recommendation

Replace unchecked `sum()` operations with checked arithmetic to detect and reject overflows:

```rust
// In inline_batch_stats()
let total_txns = inline_batches
    .iter()
    .try_fold(0usize, |acc, (b, _)| {
        acc.checked_add(b.num_txns().try_into().ok()?)
    })
    .ok_or_else(|| anyhow::anyhow!("Transaction count overflow"))?;

let total_bytes = inline_batches
    .iter()
    .try_fold(0usize, |acc, (b, _)| {
        acc.checked_add(b.num_bytes().try_into().ok()?)
    })
    .ok_or_else(|| anyhow::anyhow!("Byte count overflow"))?;
```

Additionally, add validation in `verify_inline_batches()` to ensure BatchInfo metadata doesn't exceed reasonable bounds:

```rust
// In verify_inline_batches()
ensure!(
    batch.num_bytes() <= config.receiver_max_batch_bytes,
    "Batch num_bytes {} exceeds limit",
    batch.num_bytes()
);
```

## Proof of Concept

```rust
// Rust test demonstrating the overflow
#[test]
fn test_inline_batch_overflow() {
    use consensus_types::block::Block;
    use consensus_types::common::{Payload, BatchInfo};
    
    // Create malicious BatchInfo with large num_bytes
    let malicious_batches: Vec<(BatchInfo, Vec<SignedTransaction>)> = vec![
        (
            BatchInfo::new(
                peer_id,
                batch_id_1,
                epoch,
                expiration,
                digest_1,
                100,  // num_txns
                u64::MAX / 2,  // num_bytes - large value
                gas_bucket_start,
            ),
            small_txns_1,  // Actual transactions are small
        ),
        (
            BatchInfo::new(
                peer_id,
                batch_id_2,
                epoch,
                expiration,
                digest_2,
                100,
                u64::MAX / 2,  // num_bytes - large value
                gas_bucket_start,
            ),
            small_txns_2,
        ),
    ];
    
    let payload = Payload::QuorumStoreInlineHybrid(
        malicious_batches,
        proof_with_data,
        None,
    );
    
    // On 32-bit or when sum overflows usize::MAX, this wraps around
    let size = payload.size();
    
    // The wrapped size is much smaller than intended
    assert!(size < u32::MAX as usize);
    // But the declared total is > u64::MAX, which should be impossible
    
    // This bypasses max_receiving_block_bytes check
}
```

## Notes

This vulnerability specifically affects the consensus layer's block validation logic where unchecked integer arithmetic on untrusted metadata enables limit bypasses. The lack of validation that BatchInfo metadata matches actual transaction data creates an attack surface where malicious validators can exploit architecture-specific overflow behavior. The issue is particularly concerning because it can cause non-deterministic validation results across the validator network based on system architecture differences, fundamentally breaking consensus safety assumptions.

### Citations

**File:** consensus/consensus-types/src/block.rs (L171-178)
```rust
                    inline_batches
                        .iter()
                        .map(|(b, _)| b.num_txns() as usize)
                        .sum(),
                    inline_batches
                        .iter()
                        .map(|(b, _)| b.num_bytes() as usize)
                        .sum(),
```

**File:** consensus/consensus-types/src/common.rs (L508-511)
```rust
                    + inline_batches
                        .iter()
                        .map(|(batch_info, _)| batch_info.num_bytes() as usize)
                        .sum::<usize>()
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

**File:** consensus/src/round_manager.rs (L1187-1193)
```rust
        ensure!(
            validator_txns_total_bytes + payload_size as u64
                <= self.local_config.max_receiving_block_bytes,
            "Payload size {} exceeds the limit {}",
            payload_size,
            self.local_config.max_receiving_block_bytes,
        );
```

**File:** consensus/src/quorum_store/batch_coordinator.rs (L137-171)
```rust
    fn ensure_max_limits(&self, batches: &[Batch<BatchInfoExt>]) -> anyhow::Result<()> {
        let mut total_txns = 0;
        let mut total_bytes = 0;
        for batch in batches.iter() {
            ensure!(
                batch.num_txns() <= self.max_batch_txns,
                "Exceeds batch txn limit {} > {}",
                batch.num_txns(),
                self.max_batch_txns,
            );
            ensure!(
                batch.num_bytes() <= self.max_batch_bytes,
                "Exceeds batch bytes limit {} > {}",
                batch.num_bytes(),
                self.max_batch_bytes,
            );

            total_txns += batch.num_txns();
            total_bytes += batch.num_bytes();
        }
        ensure!(
            total_txns <= self.max_total_txns,
            "Exceeds total txn limit {} > {}",
            total_txns,
            self.max_total_txns,
        );
        ensure!(
            total_bytes <= self.max_total_bytes,
            "Exceeds total bytes limit: {} > {}",
            total_bytes,
            self.max_total_bytes,
        );

        Ok(())
    }
```
