# Audit Report

## Title
Insufficient Address Format Validation in EntryFunctionFilter Allows Service Crash via Malformed Configuration

## Summary
The `validate_state()` method in `EntryFunctionFilter` only checks for the presence of at least one field but does not validate the format of the address string. This allows invalid address formats (including addresses longer than 64 hex characters or containing non-hex characters) to pass validation, leading to a panic in `standardize_address()` when the filter is used during transaction processing.

## Finding Description

The `EntryFunctionFilter::validate_state()` implementation performs minimal validation: [1](#0-0) 

This validation only ensures at least one field (address, module, or function) is set, but does not verify the address format. When an invalid address is provided, it passes validation and is later used in the `matches()` function: [2](#0-1) 

The `standardize_address()` function is called to normalize addresses for comparison: [3](#0-2) 

**Critical Issue:** At line 33, when `trimmed.len() > 64`, the expression `&ZEROS[..64 - trimmed.len()]` causes an integer underflow resulting in a panic due to out-of-bounds array access.

The configuration loading process does not validate the filter: [4](#0-3) 

The filter is used during transaction processing: [5](#0-4) 

## Impact Explanation

**Severity: Medium** - This vulnerability causes Denial of Service of the indexer-grpc data service through operator misconfiguration. While this is not a consensus-critical component, the indexer service provides essential infrastructure for:
- Transaction querying and filtering for downstream applications
- Real-time transaction streaming to clients
- Data availability for ecosystem tools

A crash affects all connected clients and requires service restart. However, impact is limited to the indexing layer and does not affect blockchain consensus, validator operations, or fund security.

## Likelihood Explanation

**Likelihood: Medium-High** - This issue occurs when:
1. A service operator configures `txns_to_strip_filter` with an invalid address (>64 hex chars or non-hex characters)
2. The misconfigured service starts successfully (validation passes)
3. A transaction triggers the filter matching logic
4. The service panics and crashes

While this requires operator action rather than direct external attack, misconfigurations are common during deployment, especially when:
- Copying addresses from various sources with different formats
- Manual configuration without proper validation tools
- Automated configuration generation with bugs

## Recommendation

**Fix 1:** Add address format validation to `EntryFunctionFilter::validate_state()`:

```rust
fn validate_state(&self) -> Result<(), FilterError> {
    if self.address.is_none() && self.module.is_none() && self.function.is_none() {
        return Err(anyhow!("At least one of address, module or function must be set").into());
    }
    
    // Validate address format if present
    if let Some(addr) = &self.address {
        validate_address_format(addr)?;
    }
    
    Ok(())
}

fn validate_address_format(address: &str) -> Result<(), FilterError> {
    let trimmed = address.strip_prefix("0x").unwrap_or(address);
    
    // Check length (max 64 hex characters for 32-byte address)
    if trimmed.len() > 64 {
        return Err(anyhow!("Address exceeds maximum length of 64 hex characters").into());
    }
    
    // Check all characters are valid hex
    if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!("Address contains invalid non-hex characters").into());
    }
    
    Ok(())
}
```

**Fix 2:** Call validation in config to catch errors early:

```rust
fn validate(&self) -> Result<()> {
    if self.data_service_grpc_non_tls_config.is_none()
        && self.data_service_grpc_tls_config.is_none()
    {
        bail!("At least one of data_service_grpc_non_tls_config and data_service_grpc_tls_config must be set");
    }
    self.in_memory_cache_config.validate()?;
    
    // Validate the transaction filter
    self.txns_to_strip_filter.is_valid()
        .map_err(|e| anyhow::anyhow!("Invalid txns_to_strip_filter: {}", e))?;
    
    Ok(())
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod test_validation_panic {
    use super::*;
    use crate::filters::EntryFunctionFilterBuilder;
    
    #[test]
    #[should_panic(expected = "out of bounds")]
    fn test_invalid_address_length_causes_panic() {
        // Create filter with address longer than 64 characters
        let invalid_address = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456";
        
        let filter = EntryFunctionFilterBuilder::default()
            .address(invalid_address)
            .build()
            .unwrap();
        
        // Validation passes (incorrectly)
        assert!(filter.is_valid().is_ok());
        
        // But standardize_address panics when called
        let _ = standardize_address(invalid_address);
    }
    
    #[test]
    fn test_address_validation_should_reject_invalid_formats() {
        // These should fail validation but currently pass
        let test_cases = vec![
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234", // too long
            "0xGGGGGGGG", // invalid hex chars
            "not_an_address", // completely invalid
        ];
        
        for invalid_addr in test_cases {
            let filter = EntryFunctionFilterBuilder::default()
                .address(invalid_addr)
                .build()
                .unwrap();
            
            // Currently passes but should fail
            assert!(filter.is_valid().is_ok(), 
                "Validation incorrectly passed for: {}", invalid_addr);
        }
    }
}
```

## Notes

This vulnerability is specific to the indexer-grpc service configuration and does not affect blockchain consensus or validator operations. The fix should be applied to prevent operator misconfigurations from causing service outages. Additional validation at the configuration level (in `IndexerGrpcDataServiceConfig::validate()`) would provide defense-in-depth by catching errors before service startup.

### Citations

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/user_transaction.rs (L183-188)
```rust
    fn validate_state(&self) -> Result<(), FilterError> {
        if self.address.is_none() && self.module.is_none() && self.function.is_none() {
            return Err(anyhow!("At least one of address, name or function must be set").into());
        };
        Ok(())
    }
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/user_transaction.rs (L191-211)
```rust
    fn matches(&self, module_id: &EntryFunctionId) -> bool {
        if !self.function.matches(&module_id.name) {
            return false;
        }

        if self.address.is_some() || self.function.is_some() {
            if let Some(module) = &module_id.module.as_ref() {
                if !(self
                    .get_standardized_address()
                    .matches(&standardize_address(&module.address))
                    && self.module.matches(&module.name))
                {
                    return false;
                }
            } else {
                return false;
            }
        }

        true
    }
```

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

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/config.rs (L130-138)
```rust
    fn validate(&self) -> Result<()> {
        if self.data_service_grpc_non_tls_config.is_none()
            && self.data_service_grpc_tls_config.is_none()
        {
            bail!("At least one of data_service_grpc_non_tls_config and data_service_grpc_tls_config must be set");
        }
        self.in_memory_cache_config.validate()?;
        Ok(())
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/service.rs (L517-521)
```rust
        let (resp_items, num_stripped) = get_transactions_responses_builder(
            transaction_data,
            chain_id as u32,
            &txns_to_strip_filter,
        );
```
