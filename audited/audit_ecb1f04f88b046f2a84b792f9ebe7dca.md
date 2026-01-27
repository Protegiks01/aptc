# Audit Report

## Title
Integer Underflow Panic in standardize_address() Causes Indexer-gRPC Service Crash via Malformed Filter Addresses

## Summary
The `standardize_address()` function in the transaction filter parsing code lacks input validation for address string length, allowing an attacker to crash the indexer-gRPC service by sending a filter with an address string longer than 64 hexadecimal characters. This triggers an integer underflow panic during slice indexing, causing the entire service process to terminate via the global panic handler.

## Finding Description
The vulnerability exists in the address standardization logic used during transaction filter parsing. When a client sends a `GetTransactionsRequest` with a `transaction_filter` containing an address field, the filter is converted from protobuf to Rust types through several `From<proto>` trait implementations. [1](#0-0) 

During this conversion, filters containing addresses (UserTransactionFilter, EntryFunctionFilter, MoveStructTagFilter) automatically call `standardize_address()` to normalize addresses: [2](#0-1) [3](#0-2) 

The `standardize_address()` function attempts to pad short addresses to 64 characters using a constant string: [4](#0-3) 

The critical bug is on line 33: when `trimmed.len() > 64`, the expression `64 - trimmed.len()` causes integer underflow in debug builds or produces an invalid negative value that causes an out-of-bounds slice panic on the `ZEROS` constant (which is exactly 64 characters).

Since `From` trait implementations cannot return `Result` types, the panic propagates uncaught to the global panic handler: [5](#0-4) 

The panic handler logs the error and calls `process::exit(12)`, terminating the entire indexer-gRPC service process. This bypasses the error handling in `parse_transaction_filter()` which expects a `Result<BooleanTransactionFilter, Status>`. [6](#0-5) 

## Impact Explanation
This vulnerability qualifies as **Medium Severity** per the Aptos bug bounty criteria because it causes:

1. **API Service Crash**: The indexer-gRPC service terminates completely, affecting all connected clients
2. **Denial of Service**: Users cannot query transaction history until the service is manually restarted
3. **No Graceful Degradation**: The panic occurs before proper error handling, preventing a graceful error response

While this is a serious availability issue, it does not affect:
- Core blockchain consensus or validator operations
- On-chain state or fund security
- The ability to submit new transactions to the blockchain

The impact is limited to the indexing/query infrastructure rather than the core blockchain protocol.

## Likelihood Explanation
**Likelihood: High**

The vulnerability is trivially exploitable:
- Requires only a single malformed gRPC request
- No authentication or special privileges needed
- Attack can be scripted and automated
- No rate limiting prevents repeated exploitation

Any client can send a `GetTransactionsRequest` with a filter containing an address field set to a string of 65+ hexadecimal characters (e.g., "0x" + "1" repeated 65 times).

## Recommendation
Add input validation to `standardize_address()` to reject addresses longer than 64 characters before attempting slice operations:

```rust
pub fn standardize_address(address: &str) -> Result<String, FilterError> {
    let trimmed = address.strip_prefix("0x").unwrap_or(address);
    
    // Validate address length
    if trimmed.len() > 64 {
        return Err(FilterError::InvalidAddress(
            format!("Address too long: {} characters (max 64)", trimmed.len())
        ));
    }
    
    // Check if the address is a special address
    if let Some(last_char) = trimmed.chars().last() {
        if trimmed[..trimmed.len().saturating_sub(1)]
            .chars()
            .all(|c| c == '0')
            && last_char.is_ascii_hexdigit()
            && last_char <= 'f'
        {
            let mut result = String::with_capacity(3);
            result.push_str("0x");
            result.push(last_char);
            return Ok(result);
        }
    }
    
    let mut result = String::with_capacity(66);
    result.push_str("0x");
    result.push_str(&ZEROS[..64 - trimmed.len()]);
    result.push_str(trimmed);
    Ok(result)
}
```

Update all call sites to handle the `Result` type and convert to appropriate filter errors.

## Proof of Concept

```rust
#[cfg(test)]
mod poc {
    use super::*;

    #[test]
    #[should_panic]
    fn test_panic_on_oversized_address() {
        // Create an address string longer than 64 hex characters
        let oversized_address = format!("0x{}", "1".repeat(65));
        
        // This should panic with integer underflow or out-of-bounds slice
        let _ = standardize_address(&oversized_address);
    }
    
    #[test]
    fn test_service_crash_via_filter() {
        use aptos_protos::indexer::v1::{
            BooleanTransactionFilter, ApiFilter, UserTransactionFilter,
            boolean_transaction_filter::Filter as BooleanFilter,
            api_filter::Filter as ApiFilterEnum,
        };
        
        // Create a malicious filter with oversized address
        let oversized_address = format!("0x{}", "f".repeat(65));
        
        let proto_filter = BooleanTransactionFilter {
            filter: Some(BooleanFilter::ApiFilter(ApiFilter {
                filter: Some(ApiFilterEnum::UserTransactionFilter(
                    UserTransactionFilter {
                        sender: Some(oversized_address),
                        payload_filter: None,
                    }
                )),
            })),
        };
        
        // This will panic during conversion, crashing the service
        let result = std::panic::catch_unwind(|| {
            filter_utils::parse_transaction_filter(proto_filter, 1024)
        });
        
        assert!(result.is_err(), "Service should panic on oversized address");
    }
}
```

**Notes**

This vulnerability affects the indexer-gRPC infrastructure rather than core consensus. While it doesn't compromise blockchain security or fund safety, it represents a critical availability issue for the indexing service. The fix requires changing `standardize_address()` to return a `Result` type and updating all trait implementations to use `TryFrom` instead of `From`, or alternatively adding validation at the protobuf parsing layer before addresses reach the standardization function.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/filter_utils.rs (L9-15)
```rust
pub fn parse_transaction_filter(
    proto_filter: aptos_protos::indexer::v1::BooleanTransactionFilter,
    max_filter_size_bytes: usize,
) -> Result<BooleanTransactionFilter, Status> {
    BooleanTransactionFilter::new_from_proto(proto_filter, Some(max_filter_size_bytes))
        .map_err(|e| Status::invalid_argument(format!("Invalid transaction_filter: {e:?}.")))
}
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/user_transaction.rs (L48-60)
```rust
impl From<aptos_protos::indexer::v1::UserTransactionFilter> for UserTransactionFilter {
    fn from(proto_filter: aptos_protos::indexer::v1::UserTransactionFilter) -> Self {
        Self {
            standardized_sender: OnceCell::with_value(
                proto_filter
                    .sender
                    .as_ref()
                    .map(|address| standardize_address(address)),
            ),
            sender: proto_filter.sender,
            payload: proto_filter.payload_filter.map(|f| f.into()),
        }
    }
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/move_module.rs (L48-61)
```rust
impl From<aptos_protos::indexer::v1::MoveStructTagFilter> for MoveStructTagFilter {
    fn from(proto_filter: aptos_protos::indexer::v1::MoveStructTagFilter) -> Self {
        Self {
            standardized_address: OnceCell::with_value(
                proto_filter
                    .address
                    .as_ref()
                    .map(|address| standardize_address(address)),
            ),
            address: proto_filter.address,
            module: proto_filter.module,
            name: proto_filter.name,
        }
    }
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/utils.rs (L4-36)
```rust
// 64 "0"s
const ZEROS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Converts a "0x" prefixed address to display format (short for special addresses, long for all other addresses):
/// https://github.com/aptos-foundation/AIPs/blob/main/aips/aip-40.md#display-format
#[inline]
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

**File:** ecosystem/indexer-grpc/indexer-grpc-server-framework/src/lib.rs (L149-168)
```rust
pub fn setup_panic_handler() {
    std::panic::set_hook(Box::new(move |pi: &PanicHookInfo<'_>| {
        handle_panic(pi);
    }));
}

// Formats and logs panic information
fn handle_panic(panic_info: &PanicHookInfo<'_>) {
    // The Display formatter for a PanicHookInfo contains the message, payload and location.
    let details = format!("{}", panic_info);
    let backtrace = format!("{:#?}", Backtrace::new());
    let info = CrashInfo { details, backtrace };
    let crash_info = toml::to_string_pretty(&info).unwrap();
    error!("{}", crash_info);
    // TODO / HACK ALARM: Write crash info synchronously via eprintln! to ensure it is written before the process exits which error! doesn't guarantee.
    // This is a workaround until https://github.com/aptos-labs/aptos-core/issues/2038 is resolved.
    eprintln!("{}", crash_info);
    // Kill the process
    process::exit(12);
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/mod.rs (L98-115)
```rust
                let filter = if let Some(proto_filter) = request.transaction_filter {
                    match filter_utils::parse_transaction_filter(
                        proto_filter,
                        self.max_transaction_filter_size_bytes,
                    ) {
                        Ok(filter) => Some(filter),
                        Err(err) => {
                            info!("Client error: {err:?}.");
                            let _ = response_sender.blocking_send(Err(err));
                            COUNTER
                                .with_label_values(&["live_data_service_invalid_filter"])
                                .inc();
                            continue;
                        },
                    }
                } else {
                    None
                };
```
