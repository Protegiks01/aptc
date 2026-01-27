# Audit Report

## Title
Missing Content Length Limit on Telemetry Custom Event Endpoint Enables Memory Exhaustion DoS

## Summary
The `/ingest/custom-event` and `/custom-contract/{name}/ingest/custom-event` endpoints lack content length limits on JSON deserialization, allowing authenticated attackers to send arbitrarily large JSON payloads that cause unbounded memory allocation and service crashes.

## Finding Description
The telemetry service uses the warp web framework to handle JSON deserialization. While other endpoints (e.g., `/ingest/logs`, `/ingest/metrics`) properly enforce a 1MB content length limit using `warp::body::content_length_limit(MAX_CONTENT_LENGTH)`, the custom event ingestion endpoints fail to apply this protection. [1](#0-0) 

This endpoint uses `warp::body::json()` directly without a preceding `content_length_limit()` filter. Similarly, the custom contract variant has the same vulnerability: [2](#0-1) 

In contrast, properly protected endpoints include the limit: [3](#0-2) 

The constant `MAX_CONTENT_LENGTH` is defined as 1MB: [4](#0-3) 

The `TelemetryEvent` struct contains a `BTreeMap<String, String>` for params: [5](#0-4) 

While the security question mentions "nested objects", the actual structure is a flat `BTreeMap<String, String>`. However, an attacker can still exploit this by sending:
1. Extremely large numbers of key-value pairs in the `params` BTreeMap
2. Very long strings for keys or values (megabytes or gigabytes)
3. Multiple large events in the `events` Vec within `TelemetryDump`

When `warp::body::json()` processes the request without a content length limit, it attempts to deserialize the entire payload into memory before invoking the handler function. This causes unbounded memory allocation that can exhaust available memory and crash the telemetry service.

## Impact Explanation
This vulnerability qualifies as **High Severity** per the Aptos bug bounty criteria:

1. **API crashes**: The telemetry service can be crashed by sending oversized payloads, disrupting telemetry collection for the entire Aptos network
2. **Validator node slowdowns**: While this is the telemetry service (not a validator node), crashing it degrades observability, making it harder to detect and diagnose actual validator issues
3. **Significant protocol violations**: Violates the Resource Limits invariant (#9) - the service should enforce computational and memory limits

The attack requires authentication (JWT tokens for node telemetry), but any authenticated node (validator, VFN, PFN, or even unknown node types) can exploit it. The telemetry service is critical infrastructure for monitoring the Aptos blockchain's health, and its unavailability creates operational blind spots.

## Likelihood Explanation
**High likelihood** - The attack is trivial to execute:

1. **Low complexity**: Attacker only needs to craft a large JSON payload and send it via HTTP POST
2. **Authentication required but broadly available**: Any node type can authenticate and access these endpoints
3. **No special privileges needed**: Standard authenticated nodes can exploit this
4. **Immediate impact**: Single request can cause memory exhaustion
5. **Detectable but easily repeatable**: Even if one attack is detected, the attacker can repeat it continuously

The vulnerability is also likely to be discovered through legitimate use cases (e.g., nodes accidentally sending oversized telemetry batches), making exploitation discovery probable.

## Recommendation
Add `content_length_limit()` filter before `warp::body::json()` on both affected endpoints to match the protection used by other endpoints:

**For `custom_event.rs`**:
```rust
pub fn custom_event_ingest(context: Context) -> BoxedFilter<(impl Reply,)> {
    warp::path!("ingest" / "custom-event")
        .and(warp::post())
        .and(context.clone().filter())
        .and(with_auth(context, vec![
            NodeType::Validator,
            NodeType::ValidatorFullNode,
            NodeType::PublicFullNode,
            NodeType::Unknown,
            NodeType::UnknownValidator,
            NodeType::UnknownFullNode,
        ]))
        .and(warp::body::content_length_limit(MAX_CONTENT_LENGTH))  // ADD THIS LINE
        .and(warp::body::json())
        .and(warp::header::optional("X-Forwarded-For"))
        .and_then(handle_custom_event)
        .boxed()
}
```

**For `custom_contract_ingest.rs`**:
```rust
pub fn custom_event_ingest(context: Context) -> BoxedFilter<(impl Reply,)> {
    warp::path!("custom-contract" / String / "ingest" / "custom-event")
        .and(warp::post())
        .and(context.clone().filter())
        .and(with_custom_contract_auth(context.clone()))
        .and(warp::body::content_length_limit(MAX_CONTENT_LENGTH))  // ADD THIS LINE
        .and(warp::body::json())
        .and_then(handle_custom_event_ingest)
        .boxed()
}
```

Import the constant at the top of both files:
```rust
use crate::constants::MAX_CONTENT_LENGTH;
```

## Proof of Concept

```rust
#[cfg(test)]
mod dos_test {
    use super::*;
    use warp::test::request;
    use serde_json::json;
    
    #[tokio::test]
    async fn test_oversized_payload_dos() {
        // Create a malicious TelemetryDump with extremely large params
        let mut large_params = std::collections::BTreeMap::new();
        
        // Add 100,000 key-value pairs with 1KB values each = ~100MB total
        for i in 0..100_000 {
            let key = format!("key_{}", i);
            let value = "A".repeat(1024); // 1KB string
            large_params.insert(key, value);
        }
        
        let malicious_payload = json!({
            "client_id": "test",
            "user_id": "0x1234",
            "timestamp_micros": "1000000",
            "events": [
                {
                    "name": "dos_event",
                    "params": large_params
                }
            ]
        });
        
        // Attempt to send this to the endpoint
        // Without content_length_limit, this would attempt to deserialize
        // ~100MB into memory, potentially crashing the service
        // With the fix, this returns 413 Payload Too Large
        
        let response = request()
            .method("POST")
            .path("/api/v1/ingest/custom-event")
            .header("Authorization", "Bearer <valid_jwt>")
            .json(&malicious_payload)
            .reply(&custom_event_ingest(test_context()))
            .await;
            
        // Expected: 413 Payload Too Large (with fix)
        // Actual: Service crashes or extreme memory usage (without fix)
        assert_eq!(response.status(), 413);
    }
}
```

**Notes**

While the security question specifically mentions "extremely large nested objects in the `params` BTreeMap", the actual vulnerability is slightly different but equally severe. The `params` field is defined as `BTreeMap<String, String>`, which is a flat structure, not nested objects. However, this does not diminish the vulnerability because:

1. Attackers can still send extremely large payloads through numerous key-value pairs or very long strings
2. The `TelemetryDump` struct contains a `Vec<TelemetryEvent>`, allowing multiple large events in a single request
3. The fundamental issue is the missing content length limit, not the nesting structure

The vulnerability affects both the standard telemetry endpoint (`/ingest/custom-event`) and custom contract telemetry endpoint (`/custom-contract/{name}/ingest/custom-event`). Additionally, the custom contract endpoints for metrics and logs also use `warp::body::bytes()` without explicit limits, though they process raw bytes rather than JSON, making exploitation slightly different but still concerning.

### Citations

**File:** crates/aptos-telemetry-service/src/custom_event.rs (L25-41)
```rust
pub fn custom_event_ingest(context: Context) -> BoxedFilter<(impl Reply,)> {
    warp::path!("ingest" / "custom-event")
        .and(warp::post())
        .and(context.clone().filter())
        .and(with_auth(context, vec![
            NodeType::Validator,
            NodeType::ValidatorFullNode,
            NodeType::PublicFullNode,
            NodeType::Unknown,
            NodeType::UnknownValidator,
            NodeType::UnknownFullNode,
        ]))
        .and(warp::body::json())
        .and(warp::header::optional("X-Forwarded-For"))
        .and_then(handle_custom_event)
        .boxed()
}
```

**File:** crates/aptos-telemetry-service/src/custom_contract_ingest.rs (L299-307)
```rust
pub fn custom_event_ingest(context: Context) -> BoxedFilter<(impl Reply,)> {
    warp::path!("custom-contract" / String / "ingest" / "custom-event")
        .and(warp::post())
        .and(context.clone().filter())
        .and(with_custom_contract_auth(context.clone()))
        .and(warp::body::json())
        .and_then(handle_custom_event_ingest)
        .boxed()
}
```

**File:** crates/aptos-telemetry-service/src/log_ingest.rs (L34-36)
```rust
        .and(warp::header::optional(CONTENT_ENCODING.as_str()))
        .and(warp::body::content_length_limit(MAX_CONTENT_LENGTH))
        .and(warp::body::aggregate())
```

**File:** crates/aptos-telemetry-service/src/constants.rs (L4-5)
```rust
/// The maximum content length to accept in the http body.
pub const MAX_CONTENT_LENGTH: u64 = 1024 * 1024;
```

**File:** crates/aptos-telemetry-service/src/types/telemetry.rs (L8-13)
```rust
/// A useful struct for serialization a telemetry event
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TelemetryEvent {
    pub name: String,
    pub params: BTreeMap<String, String>,
}
```
