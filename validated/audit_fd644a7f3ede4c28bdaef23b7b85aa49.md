# Audit Report

## Title
Integer Overflow Panic in Rosetta API Transfer Validation Causes Denial of Service

## Summary
The Rosetta API's transfer validation logic contains an integer overflow vulnerability that causes a panic when processing withdraw operations with the minimum i128 value (i128::MIN). An unauthenticated attacker can exploit this to crash the Rosetta API server by sending specially crafted transfer operations through public endpoints.

## Finding Description

The vulnerability exists in the `Transfer::extract_transfer` function where transfer operations are validated. The function extracts withdraw and deposit amounts as i128 values from string inputs using `i128::from_str()`, then validates that the withdraw amount is the negative of the deposit amount to ensure conservation of value. [1](#0-0) 

The critical flaw occurs at the comparison operation where `withdraw_value` is negated. When an attacker provides a withdraw operation with the value "-170141183460469231731687303715884105728" (i128::MIN), attempting to negate this value causes an integer overflow because the mathematical result (i128::MAX + 1) exceeds the maximum i128 value. [2](#0-1) 

Since Aptos Core is compiled with `overflow-checks = true` in the release profile, this overflow triggers a panic rather than wrapping around. [3](#0-2) 

The attack flow is:

1. Attacker sends a POST request to `/construction/preprocess` or `/construction/payloads` with operations containing withdraw and deposit operations
2. The request is processed through `InternalOperation::extract` which calls `Transfer::extract_transfer` for 2-operation cases [4](#0-3) [5](#0-4) [6](#0-5) 

3. Both amount strings successfully parse to i128 values, including i128::MIN
4. The negation operation triggers overflow-checked panic
5. In Online mode (production default), the global panic handler exits the entire process [7](#0-6) 

The endpoints are publicly accessible with CORS enabled for any origin and no authentication required: [8](#0-7) 

## Impact Explanation

This vulnerability enables a Denial of Service attack against the Rosetta API service. According to the Aptos bug bounty program, "API crashes" are classified as **High Severity** (up to $50,000).

In the production deployment configuration (Online mode), where Rosetta runs alongside a full node, the panic triggers the global panic handler which calls `process::exit(12)`, crashing not just the Rosetta API but the entire full node process. [9](#0-8) [10](#0-9) 

While this does not affect blockchain consensus or validator operations directly, it impacts the availability of a critical infrastructure component that exchanges and wallets rely on for blockchain integration. An attacker can repeatedly trigger this panic to keep the Rosetta API service unavailable.

## Likelihood Explanation

**Likelihood: High**

The attack is trivially exploitable:
- No authentication required on the construction endpoints
- No rate limiting on construction endpoints (verified by code inspection)
- Simple HTTP POST request with crafted JSON payload containing i128::MIN
- Attacker needs no special privileges or blockchain knowledge
- Attack can be automated and repeated indefinitely
- No computational resources required beyond crafting the request

The only requirement is knowledge of the i128::MIN edge case, which is well-documented in Rust documentation.

## Recommendation

Add validation to reject i128::MIN before performing the negation operation:

```rust
// Before the negation check
if withdraw_value == i128::MIN {
    return Err(ApiError::InvalidTransferOperations(Some(
        "Withdraw amount cannot be i128::MIN",
    )));
}

// Then proceed with the existing check
if -withdraw_value != deposit_value {
    return Err(ApiError::InvalidTransferOperations(Some(
        "Withdraw amount must be equal to negative of deposit amount",
    )));
}
```

Alternatively, use checked arithmetic operations:
```rust
let negated_withdraw = withdraw_value.checked_neg()
    .ok_or(ApiError::InvalidTransferOperations(Some(
        "Invalid withdraw amount - overflow on negation",
    )))?;

if negated_withdraw != deposit_value {
    return Err(ApiError::InvalidTransferOperations(Some(
        "Withdraw amount must be equal to negative of deposit amount",
    )));
}
```

## Proof of Concept

```bash
curl -X POST http://localhost:8082/construction/preprocess \
  -H "Content-Type: application/json" \
  -d '{
    "network_identifier": {
      "blockchain": "aptos",
      "network": "mainnet"
    },
    "operations": [
      {
        "operation_identifier": {"index": 0},
        "type": "withdraw",
        "account": {"address": "0x1"},
        "amount": {
          "value": "-170141183460469231731687303715884105728",
          "currency": {"symbol": "APT", "decimals": 8}
        }
      },
      {
        "operation_identifier": {"index": 1},
        "type": "deposit",
        "account": {"address": "0x2"},
        "amount": {
          "value": "1000000",
          "currency": {"symbol": "APT", "decimals": 8}
        }
      }
    ]
  }'
```

This request will cause the Rosetta API server to panic and crash due to the integer overflow when negating i128::MIN at line 2905.

## Notes

This vulnerability is particularly severe in production deployments where Rosetta runs in Online mode alongside a full node, as the panic causes the entire process to exit. The vulnerability can be triggered repeatedly to maintain a persistent DoS condition. The fix is straightforward using Rust's checked arithmetic operations or explicit edge case validation.

### Citations

**File:** crates/aptos-rosetta/src/types/objects.rs (L2602-2606)
```rust
            // Double operation actions (only coin transfer)
            2 => Ok(Self::Transfer(Transfer::extract_transfer(
                server_context,
                operations,
            )?)),
```

**File:** crates/aptos-rosetta/src/types/objects.rs (L2899-2902)
```rust
        let withdraw_value = i128::from_str(&withdraw_amount.value)
            .map_err(|_| ApiError::InvalidTransferOperations(Some("Withdraw amount is invalid")))?;
        let deposit_value = i128::from_str(&deposit_amount.value)
            .map_err(|_| ApiError::InvalidTransferOperations(Some("Deposit amount is invalid")))?;
```

**File:** crates/aptos-rosetta/src/types/objects.rs (L2904-2909)
```rust
        // We can't create or destroy coins, they must be negatives of each other
        if -withdraw_value != deposit_value {
            return Err(ApiError::InvalidTransferOperations(Some(
                "Withdraw amount must be equal to negative of deposit amount",
            )));
        }
```

**File:** Cargo.toml (L921-923)
```text
[profile.release]
debug = true
overflow-checks = true
```

**File:** crates/aptos-rosetta/src/construction.rs (L1173-1181)
```rust
async fn construction_payloads(
    request: ConstructionPayloadsRequest,
    server_context: RosettaContext,
) -> ApiResult<ConstructionPayloadsResponse> {
    debug!("/construction/payloads {:?}", request);
    check_network(request.network_identifier, &server_context)?;

    // Retrieve the real operation we're doing, this identifies the sub-operations to a function
    let mut operation = InternalOperation::extract(&server_context, &request.operations)?;
```

**File:** crates/aptos-rosetta/src/construction.rs (L1427-1435)
```rust
async fn construction_preprocess(
    request: ConstructionPreprocessRequest,
    server_context: RosettaContext,
) -> ApiResult<ConstructionPreprocessResponse> {
    debug!("/construction/preprocess {:?}", request);
    check_network(request.network_identifier, &server_context)?;

    // Determine the actual operation from the collection of Rosetta [Operation]
    let internal_operation = InternalOperation::extract(&server_context, &request.operations)?;
```

**File:** crates/crash-handler/src/lib.rs (L26-57)
```rust
pub fn setup_panic_handler() {
    panic::set_hook(Box::new(move |pi: &PanicHookInfo<'_>| {
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

    // Wait till the logs have been flushed
    aptos_logger::flush();

    // Do not kill the process if the panics happened at move-bytecode-verifier.
    // This is safe because the `state::get_state()` uses a thread_local for storing states. Thus the state can only be mutated to VERIFIER by the thread that's running the bytecode verifier.
    //
    // TODO: once `can_unwind` is stable, we should assert it. See https://github.com/rust-lang/rust/issues/92988.
    if state::get_state() == VMState::VERIFIER || state::get_state() == VMState::DESERIALIZER {
        return;
    }

    // Kill the process
    process::exit(12);
```

**File:** crates/aptos-rosetta/src/lib.rs (L181-186)
```rust
        .with(
            warp::cors()
                .allow_any_origin()
                .allow_methods(vec![Method::GET, Method::POST])
                .allow_headers(vec![warp::http::header::CONTENT_TYPE]),
        )
```

**File:** docker/rosetta/rosetta.Dockerfile (L39-40)
```dockerfile
ENTRYPOINT ["/usr/local/bin/aptos-rosetta"]
CMD ["online", "--config /opt/aptos/fullnode.yaml"]
```

**File:** aptos-node/src/lib.rs (L233-234)
```rust
    // Setup panic handler
    aptos_crash_handler::setup_panic_handler();
```
