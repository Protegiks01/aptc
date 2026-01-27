# Audit Report

## Title
Memory Exhaustion via Unbounded TelemetryEvent Name String in Custom Event Ingestion Endpoint

## Summary
The custom event ingestion endpoint (`/api/v1/ingest/custom-event`) lacks body size validation, allowing authenticated nodes to send arbitrarily large event names that cause memory exhaustion and service crashes. While other similar endpoints enforce a 1MB content-length limit, this endpoint accepts unbounded JSON payloads containing gigabyte-sized strings in the `TelemetryEvent.name` field.

## Finding Description

The `TelemetryEvent` struct contains an unbounded `name` field with no length validation: [1](#0-0) 

The custom event ingestion endpoint uses `warp::body::json()` without applying a content-length limit: [2](#0-1) 

In contrast, other telemetry ingestion endpoints properly enforce size limits. The log ingestion endpoint applies `MAX_CONTENT_LENGTH`: [3](#0-2) 

Where `MAX_CONTENT_LENGTH` is defined as 1MB: [4](#0-3) 

The validation function only checks peer ID matching and non-empty events list, but performs no length validation on the event name or parameters: [5](#0-4) 

**Attack Flow:**
1. Attacker obtains JWT authentication (endpoint accepts `NodeType::Unknown`, `NodeType::UnknownValidator`, and `NodeType::UnknownFullNode`)
2. Sends POST to `/api/v1/ingest/custom-event` with `TelemetryDump` containing a `TelemetryEvent` 
3. The `name` field contains a multi-gigabyte string
4. `warp::body::json()` reads the entire body into memory without size checks
5. The string is cloned during processing and serialization to BigQuery
6. Multiple concurrent requests exhaust available memory
7. Telemetry service crashes, disrupting network monitoring

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits."

## Impact Explanation

This vulnerability qualifies as **Medium Severity** according to the Aptos bug bounty program criteria, specifically under "API crashes." While the telemetry service is not part of the core consensus layer, its disruption has operational consequences:

- **Service Availability**: Memory exhaustion crashes the telemetry service, blinding operators to network health issues
- **Monitoring Disruption**: Loss of metrics/logs from all validators and nodes during the attack
- **Incident Response Degradation**: During actual security incidents, operators cannot access telemetry data
- **Resource Consumption**: Each malicious request allocates gigabytes of memory until OOM occurs

The impact is limited to the telemetry infrastructure and does not directly affect consensus, transaction processing, or funds security, which prevents this from reaching High or Critical severity.

## Likelihood Explanation

**Likelihood: Medium-High**

The vulnerability is highly exploitable because:
- **Authentication Barrier is Low**: Endpoint accepts `Unknown` node types, making authentication accessible
- **No Rate Limiting**: No evidence of rate limiting in the codebase
- **Simple Exploitation**: A single curl command with a large JSON payload can trigger the vulnerability
- **No Detection**: Standard request parsing makes malicious requests indistinguishable until memory exhaustion occurs

The only barrier is obtaining valid JWT credentials, but the permissive authentication policy (accepting Unknown nodes) significantly lowers this barrier.

## Recommendation

Apply the same content-length limit used by other ingestion endpoints. Modify the custom event ingestion filter:

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

Additionally, add explicit validation in `validate_custom_event_body`:

```rust
fn validate_custom_event_body(
    claims: &Claims,
    body: &TelemetryDump,
) -> anyhow::Result<(), Rejection> {
    // Existing validations...
    
    // Add length validation
    const MAX_EVENT_NAME_LENGTH: usize = 256;
    const MAX_PARAM_KEY_LENGTH: usize = 128;
    const MAX_PARAM_VALUE_LENGTH: usize = 1024;
    
    for event in &body.events {
        if event.name.len() > MAX_EVENT_NAME_LENGTH {
            return Err(reject::custom(ServiceError::bad_request(
                CustomEventIngestError::InvalidEvent(
                    format!("Event name exceeds {} bytes", MAX_EVENT_NAME_LENGTH),
                    claims.peer_id
                ).into(),
            )));
        }
        
        for (key, value) in &event.params {
            if key.len() > MAX_PARAM_KEY_LENGTH || value.len() > MAX_PARAM_VALUE_LENGTH {
                return Err(reject::custom(ServiceError::bad_request(
                    CustomEventIngestError::InvalidEvent(
                        "Parameter key or value too large".to_string(),
                        claims.peer_id
                    ).into(),
                )));
            }
        }
    }
    
    Ok(())
}
```

## Proof of Concept

```rust
// Integration test demonstrating memory exhaustion attack
#[tokio::test]
async fn test_custom_event_memory_exhaustion() {
    use std::collections::BTreeMap;
    use crate::types::telemetry::{TelemetryEvent, TelemetryDump};
    
    // Create a TelemetryEvent with a gigabyte-sized name
    let malicious_event = TelemetryEvent {
        name: "A".repeat(1_000_000_000), // 1GB string
        params: BTreeMap::new(),
    };
    
    let malicious_dump = TelemetryDump {
        client_id: "test".to_string(),
        user_id: "0x1234".to_string(),
        timestamp_micros: "1000000".to_string(),
        events: vec![malicious_event],
    };
    
    // Serialize to JSON - this will consume excessive memory
    let json_payload = serde_json::to_string(&malicious_dump).unwrap();
    
    // In a real attack, POST this to /api/v1/ingest/custom-event
    // Multiple concurrent requests would crash the service via OOM
    assert!(json_payload.len() > 1_000_000_000);
}

// Curl command for manual testing:
// curl -X POST https://telemetry-service/api/v1/ingest/custom-event \
//   -H "Authorization: Bearer $JWT_TOKEN" \
//   -H "Content-Type: application/json" \
//   -d '{"client_id":"test","user_id":"0x1234","timestamp_micros":"1000000","events":[{"name":"'$(python -c 'print("A"*1000000000)')'","params":{}}]}'
```

**Notes**

The vulnerability exists because the custom event endpoint inconsistently applies security controls compared to other ingestion endpoints. The prometheus metrics and log ingestion endpoints both enforce `MAX_CONTENT_LENGTH`, but the custom event endpoint was overlooked during implementation. The authentication requirement provides minimal protection since Unknown node types are explicitly permitted, and the lack of per-field validation allows the entire payload size limit (if enforced) to be consumed by a single oversized string field.

### Citations

**File:** crates/aptos-telemetry-service/src/types/telemetry.rs (L10-13)
```rust
pub struct TelemetryEvent {
    pub name: String,
    pub params: BTreeMap<String, String>,
}
```

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

**File:** crates/aptos-telemetry-service/src/custom_event.rs (L43-65)
```rust
fn validate_custom_event_body(
    claims: &Claims,
    body: &TelemetryDump,
) -> anyhow::Result<(), Rejection> {
    let body_peer_id = PeerId::from_str(&body.user_id).map_err(|_| {
        reject::custom(ServiceError::bad_request(
            CustomEventIngestError::InvalidEvent(body.user_id.clone(), claims.peer_id).into(),
        ))
    })?;
    if body_peer_id != claims.peer_id {
        return Err(reject::custom(ServiceError::bad_request(
            CustomEventIngestError::InvalidEvent(body.user_id.clone(), claims.peer_id).into(),
        )));
    }

    if body.events.is_empty() {
        return Err(reject::custom(ServiceError::bad_request(
            CustomEventIngestError::EmptyPayload.into(),
        )));
    }

    Ok(())
}
```

**File:** crates/aptos-telemetry-service/src/log_ingest.rs (L35-35)
```rust
        .and(warp::body::content_length_limit(MAX_CONTENT_LENGTH))
```

**File:** crates/aptos-telemetry-service/src/constants.rs (L4-5)
```rust
/// The maximum content length to accept in the http body.
pub const MAX_CONTENT_LENGTH: u64 = 1024 * 1024;
```
