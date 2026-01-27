# Audit Report

## Title
Address Length Validation Bypass in EventFilter Causes Panic During Transaction Matching

## Summary
The `MoveStructTagFilter` validation does not check the length or format of address strings, allowing attackers to craft EventFilter configurations with maliciously long addresses (>64 hex characters) that pass `validate_state()` but cause a panic during `matches()` when `standardize_address()` attempts to index beyond array bounds. This results in a denial of service on the indexer gRPC data service.

## Finding Description

The vulnerability exists in the validation-matching discrepancy of the `MoveStructTagFilter` component:

**Validation Path**: [1](#0-0) 

The `validate_state()` method only verifies that at least one field (address, module, or name) is set, but performs no validation on the address string's length or format. It never calls `standardize_address()` to test if the address is valid.

**Matching Path**: [2](#0-1) 

During matching, the filter calls `get_standardized_address()`, which lazily initializes by calling `standardize_address()` for the first time.

**Panic Trigger**: [3](#0-2) 

The `standardize_address()` function assumes addresses are ≤64 hex characters. At line 33, it performs `&ZEROS[..64 - trimmed.len()]`. If `trimmed.len() > 64`, this causes integer underflow (debug mode) or wraparound to a huge value (release mode), followed by an index out of bounds panic.

**Attack Vector**: An attacker crafts an EventFilter with a `MoveStructTagFilter` containing an address string with 65+ hex characters (e.g., "0x" + "1" repeated 65 times). This filter passes validation and is accepted by the gRPC service. When transactions are processed in `strip_transactions()`: [4](#0-3) 

The `matches()` call at line 935 triggers the panic, crashing the tokio task handling the transaction stream and causing a denial of service.

## Impact Explanation

**High Severity** - This qualifies as "API crashes" per the Aptos bug bounty program. The vulnerability causes:

1. **Denial of Service**: The indexer gRPC data service task panics and terminates when processing transactions with the malicious filter
2. **Filter Bypass**: The panic prevents proper filtering/stripping of transaction data, potentially exposing sensitive information if the service continues operating in a degraded state
3. **Service Disruption**: Clients using the affected filter experience connection termination and cannot retrieve transaction data

The impact is limited to the indexer service and does not affect consensus, execution, or state management, but represents a significant availability and data exposure risk for clients relying on filtered transaction streams.

## Likelihood Explanation

**High Likelihood** - The attack requires:
- No authentication beyond normal gRPC API access
- A single malformed filter request with an overly long address string
- No special timing or race conditions
- No validator access or privileged permissions

The vulnerability is trivially exploitable by any client with access to the indexer gRPC API. The attacker simply needs to construct an EventFilter with an address field containing more than 64 hex characters.

## Recommendation

Add address length validation to `MoveStructTagFilter::validate_state()`:

```rust
fn validate_state(&self) -> Result<(), FilterError> {
    if self.address.is_none() && self.module.is_none() && self.name.is_none() {
        return Err(anyhow!("At least one of address, module or name must be set").into());
    }
    
    // Validate address length if present
    if let Some(addr) = &self.address {
        let trimmed = addr.strip_prefix("0x").unwrap_or(addr);
        if trimmed.len() > 64 {
            return Err(anyhow!(
                "Address length exceeds maximum of 64 hex characters (got {})", 
                trimmed.len()
            ).into());
        }
    }
    
    Ok(())
}
```

Alternatively, make `standardize_address()` return `Result<String, Error>` instead of panicking, but the validation approach is cleaner.

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use crate::filters::MoveStructTagFilterBuilder;
    use crate::traits::Filterable;
    
    #[test]
    fn test_overly_long_address_validation_bypass() {
        // Create filter with 65-character hex address (exceeds 64 char limit)
        let long_address = "0x".to_string() + &"1".repeat(65);
        
        let filter = MoveStructTagFilterBuilder::default()
            .address(long_address)
            .build()
            .unwrap();
        
        // Validation passes (VULNERABILITY)
        assert!(filter.is_valid().is_ok());
        
        // Create a mock MoveStructTag to match against
        let struct_tag = aptos_protos::transaction::v1::MoveStructTag {
            address: "0x1".to_string(),
            module: "test".to_string(),
            name: "Test".to_string(),
            generic_type_params: vec![],
        };
        
        // This will panic due to index out of bounds in standardize_address()
        // In production, this crashes the tokio task processing transactions
        let _result = std::panic::catch_unwind(|| {
            filter.matches(&struct_tag)
        });
        
        // Verify panic occurred
        assert!(_result.is_err());
    }
}
```

This test demonstrates that:
1. A filter with a 65-character address passes validation
2. When `matches()` is called, it panics attempting to standardize the address
3. In the production gRPC service, this panic crashes the transaction processing task

## Notes

This vulnerability specifically affects the indexer gRPC data service transaction filtering system, not the core blockchain consensus or execution layers. However, it represents a significant availability issue for indexer clients and could potentially lead to exposure of unfiltered transaction data if the service continues operating after the panic in a degraded state.

### Citations

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/move_module.rs (L76-81)
```rust
    fn validate_state(&self) -> Result<(), FilterError> {
        if self.address.is_none() && self.module.is_none() && self.name.is_none() {
            return Err(anyhow!("At least one of address, module or name must be set").into());
        };
        Ok(())
    }
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/move_module.rs (L84-89)
```rust
    fn matches(&self, struct_tag: &MoveStructTag) -> bool {
        self.get_standardized_address()
            .matches(&standardize_address(&struct_tag.address))
            && self.module.matches(&struct_tag.module)
            && self.name.matches(&struct_tag.name)
    }
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/utils.rs (L30-35)
```rust
    // Return non-special addresses in long format
    let mut result = String::with_capacity(66);
    result.push_str("0x");
    result.push_str(&ZEROS[..64 - trimmed.len()]);
    result.push_str(trimmed);
    result
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/service.rs (L924-950)
```rust
fn strip_transactions(
    transactions: Vec<Transaction>,
    txns_to_strip_filter: &BooleanTransactionFilter,
) -> (Vec<Transaction>, usize) {
    let mut stripped_count = 0;

    let stripped_transactions: Vec<Transaction> = transactions
        .into_iter()
        .map(|mut txn| {
            // Note: `is_allowed` means the txn matches the filter, in which case
            // we strip it.
            if txns_to_strip_filter.matches(&txn) {
                stripped_count += 1;
                if let Some(info) = txn.info.as_mut() {
                    info.changes = vec![];
                }
                if let Some(TxnData::User(user_transaction)) = txn.txn_data.as_mut() {
                    user_transaction.events = vec![];
                    if let Some(utr) = user_transaction.request.as_mut() {
                        // Wipe the payload and signature.
                        utr.payload = None;
                        utr.signature = None;
                    }
                }
            }
            txn
        })
```
