# Audit Report

## Title
Resource Exhaustion via Unbounded Payload Size Computation Before Validation

## Summary
A Byzantine validator can craft blocks containing an excessive number of transactions that force all validators to perform expensive `payload.size()` computation before block validation occurs, leading to validator CPU exhaustion and consensus delays.

## Finding Description

The vulnerability exists in the block proposal validation flow within `consensus/src/round_manager.rs`. When a block proposal is received, the `process_proposal()` function computes both the payload length and payload size before validating against configured limits. [1](#0-0) 

The critical issue is at line 1179 where `payload.size()` is called. For `DirectMempool` payloads, this triggers an expensive computation that iterates over ALL transactions in the block: [2](#0-1) 

This computation uses parallel iteration to sum the `raw_txn_bytes_len()` of every transaction. For each transaction where the size hasn't been cached, this requires BCS serialization: [3](#0-2) 

Since the `OnceCell` cache is not serialized/deserialized (marked with `#[serde(skip)]`), newly received transactions from the network will have empty caches, requiring full BCS serialization to compute their size. [4](#0-3) 

**Attack Path:**
1. Byzantine validator crafts a block with N transactions where N >> `max_receiving_block_txns` (default: 10,000)
2. Each transaction is kept small (e.g., ~100 bytes) so the total payload fits within the 64 MB network message limit
3. Example: 500,000 transactions × 100 bytes = 50 MB < 64 MB network limit
4. Block is broadcast to all validators
5. Each validator deserializes the block (transactions' `OnceCell` caches are empty)
6. `process_proposal()` executes:
   - Line 1178: `payload.len()` returns 500,000 (O(1) operation)
   - Line 1179: `payload.size()` iterates over all 500,000 transactions, computing BCS serialized size for each
   - Line 1181: Validation check fails (500,000 > 10,000), block is rejected
7. But the expensive computation at line 1179 has already consumed significant CPU time across all validators

The network-level BCS deserialization uses a recursion limit of 64, but this does NOT limit the number of elements in a vector: [5](#0-4) [6](#0-5) 

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program criteria: "Validator node slowdowns."

**Quantified Impact:**
- A single malicious block can force all N validators to perform O(M) expensive BCS serialization operations, where M is the number of transactions in the block
- With M = 500,000 transactions and assuming ~0.05ms per transaction size computation, the total CPU time per validator is ~25 seconds
- Even with parallel processing across multiple cores, this represents significant resource consumption
- A Byzantine validator can repeat this attack every time they are selected as proposer
- In a network with 100 validators and typical 5% proposer selection rate, a malicious validator gets ~5 proposal opportunities per 100 rounds
- Cumulative effect: Repeated attacks cause sustained validator CPU saturation, increasing consensus latency and potentially causing timeout-based issues

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." The system fails to enforce resource limits before performing expensive computation.

## Likelihood Explanation

**Likelihood: High**

The attack is feasible and realistic:

1. **Attacker Requirements:** Only requires being a validator in the active set. Byzantine validators (up to <1/3 of stake) are within the AptosBFT threat model.

2. **Complexity: Low**
   - Crafting a block with many small transactions is trivial
   - No sophisticated timing or coordination required
   - Can be executed during any round when the Byzantine validator is the proposer

3. **Detectability:** While the attack would be visible in logs (rejected proposals), the damage (CPU exhaustion) occurs before detection and rejection.

4. **Frequency:** Can be repeated every time the Byzantine validator is selected as proposer, providing sustained degradation.

## Recommendation

**Fix: Validate payload length BEFORE computing payload size**

Reorder the operations to check the transaction count limit before performing the expensive size computation:

```rust
// In consensus/src/round_manager.rs, modify process_proposal():

// Compute payload length first (cheap operation)
let payload_len = proposal.payload().map_or(0, |payload| payload.len());

// Validate count limit BEFORE computing size
ensure!(
    num_validator_txns + payload_len as u64 <= self.local_config.max_receiving_block_txns,
    "Payload len {} exceeds the limit {}",
    payload_len,
    self.local_config.max_receiving_block_txns,
);

// Only compute expensive size if count check passes
let payload_size = proposal.payload().map_or(0, |payload| payload.size());

ensure!(
    validator_txns_total_bytes + payload_size as u64
        <= self.local_config.max_receiving_block_bytes,
    "Payload size {} exceeds the limit {}",
    payload_size,
    self.local_config.max_receiving_block_bytes,
);
```

**Additional Hardening:**
1. Consider adding a BCS deserialization vector length limit at the network layer to prevent deserializing blocks with excessive transaction counts
2. Pre-compute and cache transaction sizes during mempool admission to avoid repeated computation

## Proof of Concept

```rust
// PoC: Demonstrating the attack scenario
// This would be added as a test in consensus/src/round_manager_tests/

#[tokio::test]
async fn test_resource_exhaustion_via_oversized_payload() {
    use std::time::Instant;
    
    // Setup test environment with validators
    let (mut round_manager, _validators) = setup_round_manager_for_test();
    
    // Craft a malicious block with excessive transactions
    let num_malicious_txns = 50_000; // Far exceeds max_receiving_block_txns (10,000)
    let mut malicious_txns = Vec::new();
    
    for i in 0..num_malicious_txns {
        // Create minimal valid transactions
        let txn = create_minimal_signed_transaction(i);
        malicious_txns.push(txn);
    }
    
    // Create block with malicious payload
    let malicious_block = create_block_with_payload(
        Payload::DirectMempool(malicious_txns),
        round_manager.current_round()
    );
    
    // Measure time to process this malicious proposal
    let start = Instant::now();
    let result = round_manager.process_proposal(malicious_block).await;
    let duration = start.elapsed();
    
    // The proposal should be rejected due to exceeding max_receiving_block_txns
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("exceeds the limit"));
    
    // But the processing time should be substantial due to payload.size() computation
    // Even with parallel processing, 50k transactions should take significant time
    println!("Processing time for malicious block: {:?}", duration);
    
    // Verify that a normal block with valid transaction count processes much faster
    let normal_txns = create_minimal_signed_transactions(1000); // Within limits
    let normal_block = create_block_with_payload(
        Payload::DirectMempool(normal_txns),
        round_manager.current_round() + 1
    );
    
    let start = Instant::now();
    let _ = round_manager.process_proposal(normal_block).await;
    let normal_duration = start.elapsed();
    
    println!("Processing time for normal block: {:?}", normal_duration);
    
    // The malicious block should take significantly longer to process
    // even though it's ultimately rejected
    assert!(duration > normal_duration * 10);
}
```

**Notes:**
- The vulnerability is exploitable within the Byzantine fault tolerance threat model (< 1/3 malicious validators)
- The expensive computation occurs in `Payload::size()` which uses parallel iteration but still consumes substantial CPU resources for hundreds of thousands of transactions
- The fix is simple: validate cheap checks (transaction count) before expensive checks (total byte size requiring iteration)
- This issue specifically affects `DirectMempool` payloads; `QuorumStore` payloads compute size differently from pre-aggregated batch metadata

### Citations

**File:** consensus/src/round_manager.rs (L1178-1185)
```rust
        let payload_len = proposal.payload().map_or(0, |payload| payload.len());
        let payload_size = proposal.payload().map_or(0, |payload| payload.size());
        ensure!(
            num_validator_txns + payload_len as u64 <= self.local_config.max_receiving_block_txns,
            "Payload len {} exceeds the limit {}",
            payload_len,
            self.local_config.max_receiving_block_txns,
        );
```

**File:** consensus/consensus-types/src/common.rs (L494-500)
```rust
    pub fn size(&self) -> usize {
        match self {
            Payload::DirectMempool(txns) => txns
                .par_iter()
                .with_min_len(100)
                .map(|txn| txn.raw_txn_bytes_len())
                .sum(),
```

**File:** types/src/transaction/mod.rs (L1047-1048)
```rust
    #[serde(skip)]
    raw_txn_size: OnceCell<usize>,
```

**File:** types/src/transaction/mod.rs (L1294-1298)
```rust
    pub fn raw_txn_bytes_len(&self) -> usize {
        *self.raw_txn_size.get_or_init(|| {
            bcs::serialized_size(&self.raw_txn).expect("Unable to serialize RawTransaction")
        })
    }
```

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L38-39)
```rust
pub const USER_INPUT_RECURSION_LIMIT: usize = 32;
pub const RECURSION_LIMIT: usize = 64;
```

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L156-171)
```rust
    fn encoding(self) -> Encoding {
        match self {
            ProtocolId::ConsensusDirectSendJson | ProtocolId::ConsensusRpcJson => Encoding::Json,
            ProtocolId::ConsensusDirectSendCompressed | ProtocolId::ConsensusRpcCompressed => {
                Encoding::CompressedBcs(RECURSION_LIMIT)
            },
            ProtocolId::ConsensusObserver => Encoding::CompressedBcs(RECURSION_LIMIT),
            ProtocolId::DKGDirectSendCompressed | ProtocolId::DKGRpcCompressed => {
                Encoding::CompressedBcs(RECURSION_LIMIT)
            },
            ProtocolId::JWKConsensusDirectSendCompressed
            | ProtocolId::JWKConsensusRpcCompressed => Encoding::CompressedBcs(RECURSION_LIMIT),
            ProtocolId::MempoolDirectSend => Encoding::CompressedBcs(USER_INPUT_RECURSION_LIMIT),
            ProtocolId::MempoolRpc => Encoding::Bcs(USER_INPUT_RECURSION_LIMIT),
            _ => Encoding::Bcs(RECURSION_LIMIT),
        }
```
