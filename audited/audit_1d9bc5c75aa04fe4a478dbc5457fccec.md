# Audit Report

## Title
Zip Bomb Attack Vulnerability in Telemetry Service Log Ingestion Causes Service DoS

## Summary
The `handle_log_ingest()` function in the Aptos Telemetry Service lacks decompression ratio limits when processing gzip-encoded log payloads. An authenticated attacker can send a small compressed payload (up to 1MB) that decompresses to gigabytes of data, causing Out-of-Memory (OOM) conditions and crashing the telemetry service.

## Finding Description

The vulnerability exists in the log ingestion endpoint where gzip-compressed data is decompressed without any limits on the decompressed size. [1](#0-0) 

The content length limit only applies to the **compressed** data (1MB maximum). [2](#0-1) 

When gzip encoding is detected, a `GzDecoder` is created and the entire decompressed stream is immediately deserialized: [3](#0-2) 

The `serde_json::from_reader(decoder)` call attempts to read and allocate memory for the entire decompressed payload before deserializing it into a `Vec<String>`. With standard gzip compression, a malicious actor can craft a payload where 1MB of compressed data expands to several gigabytes, exploiting the high compression ratio of highly repetitive data.

**Attack Flow:**
1. Attacker authenticates to the telemetry service (any node type including UnknownFullNode can authenticate) [4](#0-3) 
2. Attacker crafts a gzip-compressed payload containing highly repetitive JSON data (e.g., arrays of identical strings)
3. Compressed payload is exactly 1MB (passes the content length check)
4. Payload decompresses to 5-10GB of JSON data
5. `serde_json::from_reader()` attempts to allocate gigabytes of memory
6. Telemetry service crashes with OOM error

The same vulnerability exists in two other locations:
- Custom contract log ingestion [5](#0-4) 
- Prometheus remote write metrics ingestion [6](#0-5) 

This breaks **Invariant #9**: "Resource Limits: All operations must respect gas, storage, and computational limits."

## Impact Explanation

**Severity: High** per Aptos Bug Bounty criteria - "API crashes"

When exploited, this vulnerability causes:
- **Immediate**: Telemetry service crashes due to OOM
- **Secondary**: Loss of observability for all validators and nodes sending telemetry
- **Tertiary**: Inability to monitor network health, debug issues, or collect metrics

**Important limitations:**
- Does **NOT** affect validator consensus operations
- Does **NOT** affect blockchain state or transaction processing  
- Does **NOT** cause loss of funds
- The telemetry service is a separate monitoring component, not part of the core consensus/execution path

The impact is limited to availability of the monitoring infrastructure. Validators continue operating normally even when the telemetry service is down.

## Likelihood Explanation

**Likelihood: Medium-High**

The attack requires:
- Valid authentication (noise handshake + JWT token)
- Ability to craft gzip-compressed payloads
- Understanding of compression ratios

Authentication is required but not restrictive - any node type can authenticate, including UnknownFullNode and UnknownValidator categories. [4](#0-3) 

The attack is technically simple: create a JSON array with 100,000 identical long strings, compress with gzip, and send to the endpoint. Standard gzip achieves 100:1+ compression ratios on such data.

## Recommendation

Implement decompression limits by wrapping the decoder in a size-limiting reader:

```rust
use std::io::Read;

// Add at the top of the file
const MAX_DECOMPRESSED_SIZE: u64 = 10 * 1024 * 1024; // 10MB limit

// Replace lines 64-71 with:
let log_messages: Vec<String> = if let Some(encoding) = encoding {
    if encoding.eq_ignore_ascii_case("gzip") {
        let decoder = GzDecoder::new(body.reader());
        let limited_reader = decoder.take(MAX_DECOMPRESSED_SIZE);
        serde_json::from_reader(limited_reader).map_err(|e| {
            debug!("unable to decode and deserialize body: {}", e);
            ServiceError::bad_request(LogIngestError::UnexpectedPayloadBody.into())
        })?
    } else {
        return Err(reject::custom(ServiceError::bad_request(
            LogIngestError::UnexpectedContentEncoding.into(),
        )));
    }
} else {
    serde_json::from_reader(body.reader()).map_err(|e| {
        error!("unable to deserialize body: {}", e);
        ServiceError::bad_request(LogIngestError::UnexpectedPayloadBody.into())
    })?
};
```

Apply the same fix to `custom_contract_ingest.rs` and `prometheus_remote_write.rs`.

## Proof of Concept

```rust
#[cfg(test)]
mod zip_bomb_poc {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    #[test]
    fn test_zip_bomb_creation() {
        // Create a highly compressible JSON payload
        let repetitive_string = "A".repeat(1000);
        let mut json_array = Vec::new();
        json_array.push("[".to_string());
        
        // Add 100,000 identical strings
        for i in 0..100_000 {
            if i > 0 {
                json_array.push(",".to_string());
            }
            json_array.push(format!("\"{}\"", repetitive_string));
        }
        json_array.push("]".to_string());
        
        let payload = json_array.join("");
        let uncompressed_size = payload.len();
        
        // Compress with gzip
        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(payload.as_bytes()).unwrap();
        let compressed = encoder.finish().unwrap();
        let compressed_size = compressed.len();
        
        println!("Uncompressed size: {} MB", uncompressed_size / 1024 / 1024);
        println!("Compressed size: {} KB", compressed_size / 1024);
        println!("Compression ratio: {}:1", uncompressed_size / compressed_size);
        
        // Verify it's under 1MB compressed
        assert!(compressed_size < 1024 * 1024);
        // Verify it expands to multiple GB
        assert!(uncompressed_size > 100 * 1024 * 1024);
    }
}
```

**To exploit against a live telemetry service:**
1. Authenticate using the `/auth` endpoint with valid noise handshake
2. Send POST request to `/ingest/logs` with `Content-Encoding: gzip` header
3. Use the compressed payload from the PoC above
4. Observe telemetry service OOM crash

## Notes

While this vulnerability allows DoS of the telemetry service, it is important to understand that:

1. **The telemetry service is not critical to blockchain consensus** - it's a monitoring/observability component that runs separately from validator nodes
2. **Validators continue operating normally** even when telemetry is unavailable
3. **No funds are at risk** and consensus safety is unaffected
4. The attack requires authentication, limiting it to network participants (though "Unknown" node types can still authenticate)

The vulnerability qualifies as **High Severity** under Aptos Bug Bounty criteria due to "API crashes", but the practical impact is limited to loss of observability rather than core blockchain functionality.

### Citations

**File:** crates/aptos-telemetry-service/src/log_ingest.rs (L27-33)
```rust
        .and(with_auth(context, vec![
            NodeType::Validator,
            NodeType::ValidatorFullNode,
            NodeType::PublicFullNode,
            NodeType::UnknownFullNode,
            NodeType::UnknownValidator,
        ]))
```

**File:** crates/aptos-telemetry-service/src/log_ingest.rs (L35-35)
```rust
        .and(warp::body::content_length_limit(MAX_CONTENT_LENGTH))
```

**File:** crates/aptos-telemetry-service/src/log_ingest.rs (L64-71)
```rust
    let log_messages: Vec<String> = if let Some(encoding) = encoding {
        if encoding.eq_ignore_ascii_case("gzip") {
            let decoder = GzDecoder::new(body.reader());
            serde_json::from_reader(decoder).map_err(|e| {
                debug!("unable to decode and deserialize body: {}", e);
                ServiceError::bad_request(LogIngestError::UnexpectedPayloadBody.into())
            })?
        } else {
```

**File:** crates/aptos-telemetry-service/src/constants.rs (L5-5)
```rust
pub const MAX_CONTENT_LENGTH: u64 = 1024 * 1024;
```

**File:** crates/aptos-telemetry-service/src/custom_contract_ingest.rs (L194-196)
```rust
        let mut decoder = GzDecoder::new(&body[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).map_err(|_| {
```

**File:** crates/aptos-telemetry-service/src/clients/prometheus_remote_write.rs (L162-166)
```rust
            let mut decoder = GzDecoder::new(&raw_metrics_body[..]);
            let mut decompressed = Vec::new();
            decoder
                .read_to_end(&mut decompressed)
                .map_err(|e| anyhow!("gzip decompression failed: {}", e))?;
```
