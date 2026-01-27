# Audit Report

## Title
Integer Underflow Panic in Transaction Filter Address Standardization

## Summary
The `standardize_address()` function contains an integer underflow vulnerability that can be triggered by user-supplied transaction filters with malformed addresses exceeding 64 characters, causing a panic in the indexer gRPC service's request handlers.

## Finding Description
The vulnerability exists in the address standardization logic used by the transaction filter system. When a user provides a `MoveStructTagFilter` with an address field longer than 64 characters (after removing the "0x" prefix), the `standardize_address()` function attempts to perform an unchecked subtraction that causes a panic. [1](#0-0) 

The critical issue is at line 33, where the code performs `&ZEROS[..64 - trimmed.len()]` without validating that `trimmed.len() <= 64`. With overflow checks enabled in the release profile, this causes a panic when `trimmed.len() > 64`. [2](#0-1) 

The attack flow proceeds as follows:

1. An attacker sends a `GetTransactionsRequest` to the indexer gRPC service with a malicious `transaction_filter`
2. The filter contains a `MoveStructTagFilter` with an address field exceeding 64 characters (e.g., 100 'a' characters) [3](#0-2) 

3. When the filter is used to match transactions, the lazy-initialized `get_standardized_address()` is called
4. This triggers `standardize_address()` on the user-controlled input, causing a panic [4](#0-3) 

The filter validation only checks that at least one field is set, but does not validate the address format: [5](#0-4) 

## Impact Explanation
This vulnerability causes denial of service against the indexer gRPC service. However, the impact is **limited to Low severity** because:

1. The indexer is an off-chain data service in the ecosystem tooling, not part of the core blockchain consensus, execution, or storage layers
2. Panics occur in individual request handler tasks spawned via `scope.spawn()`, failing only that specific request rather than crashing the entire service [6](#0-5) 

3. The blockchain itself continues operating normally; only external clients querying historical data are affected
4. The vulnerability does not break any of the 10 critical blockchain invariants (consensus safety, deterministic execution, state consistency, etc.)
5. Network-level DoS attacks are explicitly out of scope per the bug bounty rules

Per the Aptos bug bounty criteria, this qualifies as **Low Severity**: "Non-critical implementation bugs" - not meeting the Critical/High/Medium threshold required for detailed reporting.

## Likelihood Explanation  
While the vulnerability is trivially exploitable (no authentication required, simple to craft malicious input), it only affects the indexer API service availability for individual requests, not the core blockchain operation.

## Recommendation
Add input validation to check address length before processing:

```rust
pub fn standardize_address(address: &str) -> String {
    let trimmed = address.strip_prefix("0x").unwrap_or(address);
    
    // Validate address length (32 bytes = 64 hex characters max)
    if trimmed.len() > 64 {
        // Return in long format with truncation or return error
        return format!("0x{}", &trimmed[..64]);
    }
    
    // ... rest of function
}
```

Alternatively, add validation in `MoveStructTagFilter::validate_state()` to reject malformed addresses early.

## Proof of Concept
```rust
#[test]
fn test_long_address_panic() {
    let long_address = "a".repeat(100);
    // This will panic with integer underflow
    let result = std::panic::catch_unwind(|| {
        standardize_address(&long_address)
    });
    assert!(result.is_err());
}
```

---

**Note**: While this is a real implementation bug, it does **not meet the severity threshold** (Critical/High/Medium) specified in the validation checklist, as it only affects ecosystem tooling with Low severity impact and does not compromise core blockchain security guarantees.

### Citations

**File:** ecosystem/indexer-grpc/transaction-filter/src/utils.rs (L10-36)
```rust
pub fn standardize_address(address: &str) -> String {
    // Remove "0x" prefix if it exists
    let trimmed = address.strip_prefix("0x").unwrap_or(address);

    // Check if the address is a special address by seeing if the first 31 bytes are zero and the last byte is smaller than 0b10000
    if let Some(last_char) = trimmed.chars().last() {
        if trimmed[..trimmed.len().saturating_sub(1)]
            .chars()
            .all(|c| c == '0')
            && last_char.is_ascii_hexdigit()
            && last_char <= 'f'
        {
            // Return special addresses in short format
            let mut result = String::with_capacity(3);
            result.push_str("0x");
            result.push(last_char);
            return result;
        }
    }

    // Return non-special addresses in long format
    let mut result = String::with_capacity(66);
    result.push_str("0x");
    result.push_str(&ZEROS[..64 - trimmed.len()]);
    result.push_str(trimmed);
    result
}
```

**File:** Cargo.toml (L921-924)
```text
[profile.release]
debug = true
overflow-checks = true

```

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/move_module.rs (L37-46)
```rust
impl MoveStructTagFilter {
    /// Returns a memoized standardized address, if an address is provided.
    fn get_standardized_address(&self) -> &Option<String> {
        self.standardized_address.get_or_init(|| {
            self.address
                .as_ref()
                .map(|address| standardize_address(address))
        })
    }
}
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/move_module.rs (L76-81)
```rust
    fn validate_state(&self) -> Result<(), FilterError> {
        if self.address.is_none() && self.module.is_none() && self.name.is_none() {
            return Err(anyhow!("At least one of address, module or name must be set").into());
        };
        Ok(())
    }
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/move_module.rs (L83-90)
```rust
    #[inline]
    fn matches(&self, struct_tag: &MoveStructTag) -> bool {
        self.get_standardized_address()
            .matches(&standardize_address(&struct_tag.address))
            && self.module.matches(&struct_tag.module)
            && self.name.matches(&struct_tag.name)
    }
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/mod.rs (L127-139)
```rust
                scope.spawn(async move {
                    self.start_streaming(
                        id,
                        starting_version,
                        ending_version,
                        max_num_transactions_per_batch,
                        MAX_BYTES_PER_BATCH,
                        filter,
                        request_metadata,
                        response_sender,
                    )
                    .await
                });
```
