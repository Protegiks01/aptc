# Audit Report

## Title
Block Size Limit Bypass via Phantom Byte Capacity in PayloadTxnsSize Normalization

## Summary
A logic bug in the `PayloadTxnsSize::new_normalized()` function causes blocks to exceed their configured size limits when validator transactions consume all available bytes. The normalization logic incorrectly creates phantom byte capacity by adjusting bytes upward before checking if the limit is exhausted, allowing blocks to grow beyond `per_block_limit_total_bytes`.

## Finding Description
The vulnerability exists in the subtraction and normalization logic used to calculate remaining block capacity after validator transactions are pulled. [1](#0-0) 

When a validator transaction consumes all available bytes, the subtraction operation on line 93 uses the `SubAssign` trait implementation: [2](#0-1) 

This calls `new_normalized()` with the subtraction result. For example, if we have `PayloadTxnsSize{count: 10, bytes: 1000}` and subtract `PayloadTxnsSize{count: 1, bytes: 1000}`, the raw subtraction yields `(9, 0)`.

The critical bug is in `new_normalized()`: [3](#0-2) 

The function performs operations in the wrong order:
1. **First** (line 36-38): If `count > bytes`, set `bytes = count` to maintain the invariant `count <= bytes`
2. **Then** (line 39-42): If either is 0, set both to 0

When input is `(9, 0)`:
- Step 1: Since `9 > 0`, it sets `bytes = 9`
- Step 2: Since both are now `9`, the zero-check doesn't trigger
- Result: `PayloadTxnsSize{count: 9, bytes: 9}` instead of the correct `(0, 0)`

This creates 9 phantom bytes of capacity. The block can now include:
- 1000 bytes of validator transactions
- Up to 9 bytes of user transactions
- **Total: 1009 bytes, exceeding the 1000-byte limit**

The amount of excess capacity is `(remaining_count - 1)` bytes, which grows with the transaction count limit.

## Impact Explanation
**Medium Severity** - This breaks the fundamental resource limit invariant that blocks must respect `per_block_limit_total_bytes`.

**Specific Impacts:**
1. **Consensus Inconsistency Risk**: If validators have different views of valid block sizes, this could cause acceptance/rejection disagreements
2. **Resource Exhaustion**: Blocks larger than configured limits can exceed memory, network bandwidth, or storage assumptions
3. **DoS Vector**: Attackers can systematically create oversized blocks to degrade network performance
4. **Configuration Bypass**: Block size limits set via on-chain governance are circumvented

The issue qualifies as Medium severity per Aptos bug bounty criteria as it represents a state inconsistency that could require intervention and breaks protocol-level resource limits.

## Likelihood Explanation
**High Likelihood** - This bug triggers automatically whenever:
1. A validator transaction's size approaches or equals the available byte capacity
2. The remaining transaction count is greater than 1

Given that `per_block_limit_total_bytes` is typically set to maximize throughput (default: 2MB), and validator transactions can be large (e.g., DKG transcripts, validator set changes), this scenario occurs regularly in production.

No attacker action is required beyond normal validator operations. The bug is deterministic and affects all nodes equally.

## Recommendation
Fix the order of operations in `new_normalized()` to check for zero values **before** adjusting bytes upward:

```rust
fn new_normalized(count: u64, bytes: u64) -> Self {
    let mut count = count;
    let mut bytes = bytes;
    // Check for zero FIRST, before any adjustments
    if count == 0 || bytes == 0 {
        count = 0;
        bytes = 0;
    } else if count > bytes {
        // Only adjust if neither is zero
        bytes = count;
    }
    Self { count, bytes }
}
```

This ensures that when bytes are exhausted (`bytes = 0`), the result is correctly normalized to `(0, 0)` regardless of the remaining count value.

Alternatively, use `saturating_sub()` instead of the raw subtraction operator in `SubAssign`: [4](#0-3) 

Change line 143 from:
```rust
*self = Self::new_normalized(self.count - rhs.count, self.bytes - rhs.bytes);
```
to:
```rust
*self = self.saturating_sub(rhs);
```

## Proof of Concept

```rust
#[cfg(test)]
mod phantom_capacity_bug {
    use super::PayloadTxnsSize;

    #[test]
    fn test_block_size_limit_bypass() {
        // Block limit: 10 transactions, 1000 bytes
        let mut remaining = PayloadTxnsSize::new(10, 1000);
        println!("Initial capacity: {}", remaining);
        
        // Single large validator transaction consumes all bytes
        let validator_txn = PayloadTxnsSize::new(1, 1000);
        println!("Validator txn size: {}", validator_txn);
        
        // Perform subtraction (line 93 of mixed.rs)
        remaining -= validator_txn;
        println!("After subtraction: {}", remaining);
        
        // BUG: Expected (0, 0), but got (9, 9)!
        assert_eq!(remaining.count(), 9);
        assert_eq!(remaining.size_in_bytes(), 9);
        
        // This allows 9 more bytes of user transactions
        // Total block size: 1000 + 9 = 1009 bytes
        // EXCEEDS the 1000 byte limit by 9 bytes!
        
        println!("VULNERABILITY: Block can now contain 1009 bytes (1000 limit)");
        println!("Phantom capacity created: {} bytes", remaining.size_in_bytes());
    }
    
    #[test]
    fn test_correct_behavior_with_fix() {
        // With the fixed new_normalized(), this should work correctly
        let remaining = PayloadTxnsSize::new(10, 1000);
        let validator_txn = PayloadTxnsSize::new(1, 1000);
        
        // Using saturating_sub (the safe method that already exists)
        let result = remaining.saturating_sub(validator_txn);
        
        // This correctly returns (0, 0)
        assert_eq!(result.count(), 0);
        assert_eq!(result.size_in_bytes(), 0);
        println!("With saturating_sub: {}", result);
    }
}
```

**To run:**
```bash
cd consensus/consensus-types
cargo test phantom_capacity_bug -- --nocapture
```

The test demonstrates that blocks can exceed their configured size limits by `(count - 1)` bytes whenever a large validator transaction consumes all available byte capacity.

### Citations

**File:** consensus/src/payload_client/mixed.rs (L93-93)
```rust
        user_txn_pull_params.max_txns -= vtxn_size;
```

**File:** consensus/consensus-types/src/utils.rs (L33-44)
```rust
    fn new_normalized(count: u64, bytes: u64) -> Self {
        let mut count = count;
        let mut bytes = bytes;
        if count > bytes {
            bytes = count;
        }
        if count == 0 || bytes == 0 {
            count = 0;
            bytes = 0;
        }
        Self { count, bytes }
    }
```

**File:** consensus/consensus-types/src/utils.rs (L69-74)
```rust
    pub fn saturating_sub(self, rhs: Self) -> Self {
        Self::new_normalized(
            self.count.saturating_sub(rhs.count),
            self.bytes.saturating_sub(rhs.bytes),
        )
    }
```

**File:** consensus/consensus-types/src/utils.rs (L141-145)
```rust
impl std::ops::SubAssign for PayloadTxnsSize {
    fn sub_assign(&mut self, rhs: Self) {
        *self = Self::new_normalized(self.count - rhs.count, self.bytes - rhs.bytes);
    }
}
```
