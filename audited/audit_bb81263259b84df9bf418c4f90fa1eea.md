# Audit Report

## Title
Integer Underflow in standardize_address() Causes Indexer GRPC Service Panic via Malicious Transaction Filters

## Summary
The `standardize_address()` function in the indexer-grpc transaction filter module performs unchecked subtraction that causes a panic when processing user-supplied address strings exceeding 64 hexadecimal characters. An attacker can crash the indexer GRPC service by submitting transaction filters with oversized address values.

## Finding Description

The `standardize_address()` function performs address normalization by padding short addresses with leading zeros to reach 64 hexadecimal characters. [1](#0-0) 

However, the function assumes `trimmed.len() <= 64` without validation. When a user-provided filter contains an address string longer than 64 hex characters (after stripping the "0x" prefix), the subtraction `64 - trimmed.len()` triggers integer underflow.

The Aptos codebase has `overflow-checks = true` enabled in release builds [2](#0-1) , which means this underflow causes an immediate panic even in production.

**Attack Path:**

1. Attacker sends a gRPC `TransactionsWithFilters` request containing a `UserTransactionFilter` with a malicious sender address
2. The filter is created without validation [3](#0-2) 
3. When the indexer processes transactions and attempts to match them against the filter, `get_standardized_sender()` is invoked [4](#0-3) 
4. This lazily calls `standardize_address()` on the malicious address [5](#0-4) 
5. Integer underflow panic occurs, crashing the indexer process

The same vulnerability exists for `EntryFunctionFilter.address` fields [6](#0-5)  and affects the move module filter as well [7](#0-6) .

Note that addresses from actual blockchain transactions are safe, as they undergo proper validation and formatting via `AccountAddress::to_standard_string()` [8](#0-7)  which always produces correctly-sized strings (either 3 chars for special addresses or 66 chars for full addresses). The vulnerability only affects user-supplied filter configuration strings from protobuf messages [9](#0-8) .

## Impact Explanation

**Severity: High**

This qualifies as **High Severity** per Aptos bug bounty criteria: "API crashes". The indexer-grpc service is a critical API component that provides transaction and event data to applications, wallets, explorers, and other ecosystem participants.

**Impact:**
- Complete denial of service for the indexer-grpc API
- Disruption to all downstream applications relying on the indexer
- Service requires restart to recover
- Attack can be repeated indefinitely with minimal effort
- No authentication or special privileges required

While this does not affect consensus, validator operation, or blockchain state safety, it severely impacts the availability of critical blockchain data infrastructure.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is trivially exploitable:
- Any user can send gRPC filter requests to the public indexer-grpc endpoints
- No authentication, rate limiting, or special permissions required
- Attack payload is simple: any address string with >64 hex characters
- Single malicious request triggers immediate crash
- Attack is deterministic and 100% reliable
- Can be automated and repeated

The barrier to exploitation is extremely low, requiring only knowledge of the gRPC API endpoint and the ability to craft a basic protobuf message.

## Recommendation

Add length validation before performing the subtraction. The function should either:

**Option 1: Validate and return an error for invalid addresses**
```rust
pub fn standardize_address(address: &str) -> Result<String, String> {
    let trimmed = address.strip_prefix("0x").unwrap_or(address);
    
    // Validate length
    if trimmed.len() > 64 {
        return Err(format!("Address too long: {} characters (max 64)", trimmed.len()));
    }
    
    // ... rest of logic
}
```

**Option 2: Truncate to 64 characters (lenient approach)**
```rust
pub fn standardize_address(address: &str) -> String {
    let trimmed = address.strip_prefix("0x").unwrap_or(address);
    
    // Ensure trimmed is at most 64 characters
    let trimmed = if trimmed.len() > 64 {
        &trimmed[..64]
    } else {
        trimmed
    };
    
    // ... rest of logic using the bounded trimmed value
}
```

**Option 3: Use saturating_sub (safe but may hide logic errors)**
```rust
result.push_str(&ZEROS[..64usize.saturating_sub(trimmed.len())]);
```

**Recommended approach:** Option 1 with validation at filter creation time in the `validate_state()` method, providing early feedback to users about invalid configuration.

## Proof of Concept

```rust
#[cfg(test)]
mod exploit {
    use super::*;

    #[test]
    #[should_panic(expected = "attempt to subtract with overflow")]
    fn test_oversized_address_causes_panic() {
        // Create an address with 65 hex characters (exceeds 64 limit)
        let malicious_address = "0x".to_string() + &"a".repeat(65);
        
        // This will panic due to integer underflow at line 33
        standardize_address(&malicious_address);
    }

    #[test]
    #[should_panic]
    fn test_filter_with_oversized_sender() {
        use aptos_transaction_filter::UserTransactionFilterBuilder;
        
        // Attacker creates filter with oversized sender address
        let malicious_sender = "0x".to_string() + &"f".repeat(65);
        let filter = UserTransactionFilterBuilder::default()
            .sender(malicious_sender)
            .build()
            .unwrap();
        
        // Filter validates successfully (no length check)
        assert!(filter.validate_state().is_ok());
        
        // But when we try to use it, it panics
        // This would happen when matching against actual transactions
        let _ = filter.get_standardized_sender();
    }
}
```

**Notes:**
- The vulnerability affects all indexer-grpc services that use transaction filters
- While not consensus-critical, this represents a significant availability issue for ecosystem infrastructure
- The fix should include input validation at the filter creation/validation stage to fail fast with clear error messages

### Citations

**File:** ecosystem/indexer-grpc/transaction-filter/src/utils.rs (L33-33)
```rust
    result.push_str(&ZEROS[..64 - trimmed.len()]);
```

**File:** Cargo.toml (L923-923)
```text
overflow-checks = true
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/user_transaction.rs (L40-44)
```rust
        self.standardized_sender.get_or_init(|| {
            self.sender
                .clone()
                .map(|address| standardize_address(&address))
        })
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/user_transaction.rs (L74-79)
```rust
    fn validate_state(&self) -> Result<(), FilterError> {
        if self.sender.is_none() && self.payload.is_none() {
            return Err(Error::msg("At least one of sender or payload must be set").into());
        };
        self.payload.is_valid()?;
        Ok(())
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/user_transaction.rs (L94-97)
```rust
        if let Some(sender_filter) = self.get_standardized_sender() {
            if &standardize_address(&user_request.sender) != sender_filter {
                return false;
            }
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/user_transaction.rs (L150-150)
```rust
                .map(|address| standardize_address(&address))
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/move_module.rs (L4-4)
```rust
use crate::{errors::FilterError, traits::Filterable, utils::standardize_address};
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/convert.rs (L861-861)
```rust
                    sender: ut.request.sender.to_string(),
```

**File:** protos/proto/aptos/indexer/v1/filter.proto (L34-34)
```text
  optional string sender = 1;
```
