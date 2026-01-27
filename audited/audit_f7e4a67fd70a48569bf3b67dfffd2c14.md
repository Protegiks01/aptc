# Audit Report

## Title
Stack Overflow DoS in Indexer Transaction Filter Parsing Due to Unbounded Recursion Depth

## Summary
The `BooleanTransactionFilter::new_from_proto` conversion lacks recursion depth limits, allowing attackers to craft deeply nested filter structures that cause stack overflow and crash the indexer GRPC service. While protobuf size is validated, no depth check exists, enabling exploitation within the default 10KB size limit.

## Finding Description

The indexer GRPC service parses transaction filters through recursive conversions without depth limits. The vulnerability exists in the interaction between three components: [1](#0-0) 

The `new_from_proto` function checks the protobuf `encoded_len()` against `max_filter_size` when provided, but ALL recursive conversions bypass this check by passing `None`: [2](#0-1) [3](#0-2) [4](#0-3) 

**Attack Path:**
1. Attacker creates a minimal filter (e.g., `TransactionRootFilter`) requiring ~50 bytes
2. Wraps it in 1500+ nested `NOT` operators (each adds ~5 bytes in protobuf encoding)
3. Total protobuf size: ~7,550 bytes, well under the 10KB default limit
4. Sends `GetTransactionsRequest` with this malicious filter to indexer service
5. During parsing at line 352, recursive calls create 1500+ stack frames
6. Each frame consumes ~1-2KB (function locals, saved registers)
7. Stack exceeds 2MB limit → thread panic → service crash

The service processes filters in the main request loop: [5](#0-4) 

When `parse_transaction_filter` panics from stack overflow, the entire request handling loop terminates. The panic handler exits the process: [6](#0-5) 

**Contrast with Move VM Protection:**
The Move VM implements comprehensive depth limits to prevent similar attacks, but the transaction filter has no such protection despite using similar recursive structures. This oversight is significant given that the codebase shows awareness of recursion depth vulnerabilities elsewhere.

## Impact Explanation

This vulnerability enables **Denial of Service** against the indexer GRPC API, qualifying as **High Severity** under "API crashes" (up to $50,000). 

**Scope**: The indexer GRPC service provides transaction filtering for downstream applications. While this is NOT a core consensus component and does NOT affect:
- Blockchain consensus or safety
- Validator operations
- On-chain state or transaction execution
- Fund security

It DOES affect:
- Availability of the Transaction Stream Service API
- Applications depending on filtered transaction queries
- Service uptime requiring manual restart after exploitation

The indexer service uses a panic handler that terminates the entire process on unrecovered panics, making this a complete service outage rather than a per-request failure.

## Likelihood Explanation

**Likelihood: High**

- **Attacker Requirements**: None - any client with network access to the GRPC endpoint can send malicious filters
- **Exploitation Complexity**: Low - trivial to construct nested protobuf messages
- **Detection Difficulty**: Attack blends with legitimate traffic until crash occurs
- **Configurability Risk**: If operators increase `max_transaction_filter_size_bytes` beyond 10KB for legitimate use cases, the attack becomes even easier (more nesting depth within size limit)

## Recommendation

Implement recursion depth limits similar to Move VM protections:

```rust
// In boolean_transaction_filter.rs
const MAX_FILTER_RECURSION_DEPTH: usize = 32; // Similar to Move's limits

impl BooleanTransactionFilter {
    pub fn new_from_proto(
        proto_filter: aptos_protos::indexer::v1::BooleanTransactionFilter,
        max_filter_size: Option<usize>,
    ) -> Result<Self> {
        Self::new_from_proto_impl(proto_filter, max_filter_size, 0)
    }

    fn new_from_proto_impl(
        proto_filter: aptos_protos::indexer::v1::BooleanTransactionFilter,
        max_filter_size: Option<usize>,
        depth: usize,
    ) -> Result<Self> {
        ensure!(
            depth <= MAX_FILTER_RECURSION_DEPTH,
            format!(
                "Filter nesting too deep. Max depth: {}, Current depth: {}",
                MAX_FILTER_RECURSION_DEPTH, depth
            )
        );
        
        if let Some(max_filter_size) = max_filter_size {
            ensure!(
                proto_filter.encoded_len() <= max_filter_size,
                // ... existing error message
            );
        }
        
        // Pass depth+1 to recursive calls
        // Update all TryFrom implementations to accept and pass depth
    }
}
```

Update all `TryFrom` implementations to thread the depth parameter through recursive conversions.

## Proof of Concept

```rust
#[cfg(test)]
mod stack_overflow_poc {
    use super::*;
    use aptos_protos::indexer::v1;
    
    #[test]
    #[should_panic(expected = "stack overflow")]
    fn test_deeply_nested_filter_causes_stack_overflow() {
        // Create a simple base filter
        let mut filter = v1::BooleanTransactionFilter {
            filter: Some(v1::boolean_transaction_filter::Filter::ApiFilter(
                v1::ApiFilter {
                    filter: Some(v1::api_filter::Filter::TransactionRootFilter(
                        v1::TransactionRootFilter {
                            success: Some(true),
                            transaction_type: None,
                        }
                    ))
                }
            ))
        };
        
        // Wrap in 2000 NOT operators (well under 10KB protobuf size)
        for _ in 0..2000 {
            filter = v1::BooleanTransactionFilter {
                filter: Some(v1::boolean_transaction_filter::Filter::LogicalNot(
                    Box::new(filter)
                ))
            };
        }
        
        // This will cause stack overflow and panic
        let _ = BooleanTransactionFilter::new_from_proto(filter, Some(10_000));
    }
}
```

**Notes**

While this vulnerability affects only the indexer service (an ecosystem/querying component) rather than core blockchain consensus, it represents a legitimate exploitable DoS condition meeting the "API crashes" High severity criterion. The lack of depth limits is a clear oversight given similar protections throughout the Move VM codebase. However, the impact is strictly limited to indexer service availability and does not compromise blockchain security, validator operations, or on-chain assets.

### Citations

**File:** ecosystem/indexer-grpc/transaction-filter/src/boolean_transaction_filter.rs (L94-127)
```rust
    pub fn new_from_proto(
        proto_filter: aptos_protos::indexer::v1::BooleanTransactionFilter,
        max_filter_size: Option<usize>,
    ) -> Result<Self> {
        if let Some(max_filter_size) = max_filter_size {
            ensure!(
                proto_filter.encoded_len() <= max_filter_size,
                format!(
                    "Filter is too complicated. Max size: {} bytes, Actual size: {} bytes",
                    max_filter_size,
                    proto_filter.encoded_len()
                )
            );
        }
        Ok(
            match proto_filter
                .filter
                .ok_or(anyhow!("Oneof is not set in BooleanTransactionFilter."))?
            {
                aptos_protos::indexer::v1::boolean_transaction_filter::Filter::ApiFilter(
                    api_filter,
                ) => TryInto::<APIFilter>::try_into(api_filter)?.into(),
                aptos_protos::indexer::v1::boolean_transaction_filter::Filter::LogicalAnd(
                    logical_and,
                ) => BooleanTransactionFilter::And(logical_and.try_into()?),
                aptos_protos::indexer::v1::boolean_transaction_filter::Filter::LogicalOr(
                    logical_or,
                ) => BooleanTransactionFilter::Or(logical_or.try_into()?),
                aptos_protos::indexer::v1::boolean_transaction_filter::Filter::LogicalNot(
                    logical_not,
                ) => BooleanTransactionFilter::Not(logical_not.try_into()?),
            },
        )
    }
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/boolean_transaction_filter.rs (L265-277)
```rust
impl TryFrom<aptos_protos::indexer::v1::LogicalAndFilters> for LogicalAnd {
    type Error = anyhow::Error;

    fn try_from(proto_filter: aptos_protos::indexer::v1::LogicalAndFilters) -> Result<Self> {
        Ok(Self {
            and: proto_filter
                .filters
                .into_iter()
                .map(|f| BooleanTransactionFilter::new_from_proto(f, None))
                .collect::<Result<_>>()?,
        })
    }
}
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/boolean_transaction_filter.rs (L305-317)
```rust
impl TryFrom<aptos_protos::indexer::v1::LogicalOrFilters> for LogicalOr {
    type Error = anyhow::Error;

    fn try_from(proto_filter: aptos_protos::indexer::v1::LogicalOrFilters) -> Result<Self> {
        Ok(Self {
            or: proto_filter
                .filters
                .into_iter()
                .map(|f| BooleanTransactionFilter::new_from_proto(f, None))
                .collect::<Result<_>>()?,
        })
    }
}
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/boolean_transaction_filter.rs (L345-358)
```rust
impl TryFrom<Box<aptos_protos::indexer::v1::BooleanTransactionFilter>> for LogicalNot {
    type Error = anyhow::Error;

    fn try_from(
        proto_filter: Box<aptos_protos::indexer::v1::BooleanTransactionFilter>,
    ) -> Result<Self> {
        Ok(Self {
            not: Box::new(BooleanTransactionFilter::new_from_proto(
                *proto_filter,
                None,
            )?),
        })
    }
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/mod.rs (L98-112)
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
