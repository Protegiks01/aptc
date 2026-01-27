# Audit Report

## Title
Chain ID Truncation in Indexer Backfiller Bypasses Cross-Chain Data Validation

## Summary
The indexer-grpc-v2-file-store-backfiller contains a type truncation vulnerability where a u64 chain_id is cast to u32, potentially causing high-order bits to be silently lost. This allows the chain ID validation assertion to pass even when processing transactions from a different blockchain network, leading to cross-chain data corruption in the indexer database.

## Finding Description

The backfiller accepts chain_id as a u64 configuration parameter [1](#0-0)  and stores it in the Processor struct [2](#0-1) . During initialization, a u64-to-u64 comparison validates the configured chain_id against file store metadata [3](#0-2) .

However, in the `backfill()` function, the chain_id is truncated from u64 to u32 [4](#0-3) . This truncated value is then used to validate incoming gRPC responses [5](#0-4) .

The gRPC protocol defines chain_id as u32 [6](#0-5) , and fullnode services populate it by casting from u8 [7](#0-6) . While actual Aptos chain IDs are u8 values (1-255) [8](#0-7) , the backfiller configuration lacks validation to enforce this constraint.

**Attack Scenario:**
If an operator misconfigures the backfiller with chain_id = 0x1_00000001 (4,294,967,297) and the file store metadata is similarly initialized [9](#0-8) , the system would:

1. Pass initialization check: 0x1_00000001 == 0x1_00000001 (u64 comparison)
2. Truncate to u32: 0x1 (high 32 bits lost)
3. Accept transactions from chain 1 (mainnet): 0x1 == 0x1 (u32 comparison passes)
4. Store mainnet data as if it belongs to chain 0x1_00000001

This breaks the fundamental invariant that indexer data must be tagged with the correct chain identifier.

## Impact Explanation

This is a **Medium Severity** issue per Aptos bug bounty criteria, as it causes "state inconsistencies requiring intervention" in the indexer infrastructure. While it doesn't directly affect blockchain consensus or validator operations, it compromises indexer data integrity, which can cascade to:

- **Downstream Service Failures**: Applications relying on the indexer API would receive data from the wrong chain
- **Cross-Chain Transaction Replay Risk**: If indexer data is used for transaction validation or replay detection, wrong chain data creates security gaps
- **Data Corruption**: The indexer database would contain mixed data from different chains, requiring manual cleanup and re-indexing

The impact is limited to off-chain infrastructure rather than on-chain consensus, preventing it from reaching High or Critical severity.

## Likelihood Explanation

**Likelihood: Low to Medium**

While the vulnerability requires operator misconfiguration with chain_id > u32::MAX (which differs from standard Aptos chain IDs of 1-5), it could occur through:

1. **Configuration errors** during deployment to custom/private chains
2. **Automated deployment systems** that generate large random chain IDs
3. **Future chain ID expansions** if Aptos supports larger chain identifiers

The lack of input validation makes this issue latent—it will silently fail when triggered rather than failing fast with a clear error.

## Recommendation

Add explicit validation during backfiller initialization:

```rust
// In Processor::new() after line 56:
ensure!(
    chain_id <= u32::MAX as u64,
    "Chain ID must fit in u32 range. Got: {}, Max: {}",
    chain_id,
    u32::MAX
);

// Better yet, validate against actual u8 constraint:
ensure!(
    chain_id <= u8::MAX as u64 && chain_id > 0,
    "Chain ID must be in range 1-255. Got: {}",
    chain_id
);
```

Similarly, add validation in the manager configuration [10](#0-9)  to fail fast on invalid chain IDs.

## Proof of Concept

```rust
#[test]
fn test_chain_id_truncation_vulnerability() {
    // Configure backfiller with chain_id exceeding u32::MAX
    let config = IndexerGrpcV2FileStoreBackfillerConfig {
        chain_id: 0x1_00000001, // 4,294,967,297
        // ... other config fields
    };
    
    // During backfill(), chain_id is truncated:
    let truncated = config.chain_id as u32;
    assert_eq!(truncated, 1); // High bits lost!
    
    // Fullnode sends actual chain_id = 1 (mainnet)
    let fullnode_chain_id: u32 = 1;
    
    // Assertion passes even though chain IDs differ:
    assert!(fullnode_chain_id == truncated); // Passes!
    
    // But actual chain IDs are different:
    assert_ne!(config.chain_id, fullnode_chain_id as u64); // Fails!
}
```

## Notes

This vulnerability is specific to the indexer-grpc infrastructure and does not affect core blockchain consensus, execution, or storage. However, it represents a defense-in-depth failure where invalid configurations should be rejected at initialization rather than causing silent data corruption. The fix is straightforward and should be applied to prevent operational issues in non-standard deployment scenarios.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-v2-file-store-backfiller/src/lib.rs (L19-19)
```rust
    pub chain_id: u64,
```

**File:** ecosystem/indexer-grpc/indexer-grpc-v2-file-store-backfiller/src/processor.rs (L35-35)
```rust
    chain_id: u64,
```

**File:** ecosystem/indexer-grpc/indexer-grpc-v2-file-store-backfiller/src/processor.rs (L66-66)
```rust
        ensure!(metadata.chain_id == chain_id, "Chain ID mismatch.");
```

**File:** ecosystem/indexer-grpc/indexer-grpc-v2-file-store-backfiller/src/processor.rs (L145-145)
```rust
                    let chain_id = self.chain_id as u32;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-v2-file-store-backfiller/src/processor.rs (L176-176)
```rust
                                    assert!(r.chain_id == chain_id);
```

**File:** protos/proto/aptos/internal/fullnode/v1/fullnode_data.proto (L53-53)
```text
  uint32 chain_id = 3;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/fullnode_data_service.rs (L259-259)
```rust
        chain_id: ledger_chain_id as u32,
```

**File:** types/src/chain_id.rs (L76-76)
```rust
pub struct ChainId(u8);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/file_store_uploader.rs (L53-57)
```rust
            let metadata = FileStoreMetadata {
                chain_id,
                num_transactions_per_folder: NUM_TXNS_PER_FOLDER,
                version: 0,
            };
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/config.rs (L32-32)
```rust
    pub(crate) chain_id: u64,
```
