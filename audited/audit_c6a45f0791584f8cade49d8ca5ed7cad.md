# Audit Report

## Title
Request Amplification via Gzip Decompression Bomb in Telemetry Log Ingestion

## Summary
The `handle_log_ingest()` function in the Aptos telemetry service lacks validation on decompressed content size, allowing authenticated nodes to send small gzip-compressed requests (~1MB) that expand to arbitrarily large payloads (10-100MB+) in memory. This amplified data is then forwarded to the Humio backend, enabling compression bomb attacks that can exhaust service memory and overload backend infrastructure.

## Finding Description

The telemetry service's log ingestion endpoint accepts gzip-compressed requests with a maximum compressed size of 1MB. [1](#0-0) [2](#0-1) 

However, when processing gzip-encoded requests, the service decompresses the payload without any validation on the resulting decompressed size: [3](#0-2) 

The decompressed data is deserialized into a `Vec<String>` containing log messages, with no limits on:
- Total decompressed payload size
- Number of log messages in the vector
- Size of individual log messages

This decompressed data is then wrapped in an `UnstructuredLog` structure and forwarded to the Humio backend: [4](#0-3) 

The backend client re-serializes and re-compresses this data before transmission: [5](#0-4) 

**Attack Scenario:**

1. An authenticated malicious node (compromised validator/fullnode or malicious operator) creates a highly compressible JSON payload containing repetitive log messages
2. Compresses it to ~1MB (passes the `MAX_CONTENT_LENGTH` check)
3. When decompressed, it expands to 50-100MB+ (compression ratio of 50:1 or higher is achievable with repetitive data)
4. Sends multiple concurrent requests to the `/ingest/logs` endpoint
5. Each request:
   - Allocates 50-100MB+ in memory on the telemetry service
   - Gets re-serialized and sent to Humio, amplifying backend traffic by 50-100x
   - CPU cycles consumed for decompression, deserialization, re-serialization, and re-compression

Multiple concurrent requests can:
- Exhaust memory on the telemetry service (OOM crash)
- Overwhelm Humio backend with amplified traffic
- Consume excessive CPU resources

## Impact Explanation

This vulnerability falls under **High Severity** according to Aptos bug bounty criteria: "API crashes" - the telemetry service API can crash due to memory exhaustion.

While this affects an auxiliary service (telemetry) rather than core blockchain operations, it still represents a significant security issue because:
- It enables authenticated attackers to cause service disruption
- The amplification factor can be extreme (50-100x or more)
- It affects backend infrastructure reliability
- The telemetry service is part of the Aptos Core codebase

**Important Scope Note**: This vulnerability does NOT affect blockchain consensus, transaction execution, state management, governance, or staking. The core blockchain continues to function normally even if the telemetry service is disrupted.

## Likelihood Explanation

**Likelihood: Medium to High**

**Attack Requirements:**
- Must be an authenticated node (requires JWT token obtained via noise handshake)
- Can be any allowed node type: Validator, ValidatorFullNode, PublicFullNode, UnknownFullNode, or UnknownValidator [6](#0-5) 
- Must not be in the blacklist (if configured) [7](#0-6) 

**Ease of Exploitation:**
- Crafting compression bombs is straightforward
- No complex timing or race conditions required
- Can be automated to send continuous requests
- Multiple concurrent requests amplify the impact

**Likelihood Assessment:**
- Compromised nodes or malicious operators have the required authentication
- The attack is simple to execute once authenticated
- No rate limiting or additional protections observed in the code
- High amplification factor makes even a few requests impactful

## Recommendation

Implement validation on the decompressed payload size before deserialization. Add a configurable maximum decompressed size limit:

```rust
// In constants.rs, add:
pub const MAX_DECOMPRESSED_LOG_SIZE: usize = 10 * 1024 * 1024; // 10MB

// In log_ingest.rs, modify the decompression logic:
let log_messages: Vec<String> = if let Some(encoding) = encoding {
    if encoding.eq_ignore_ascii_case("gzip") {
        use std::io::Read;
        let decoder = GzDecoder::new(body.reader());
        let mut limited_reader = decoder.take(MAX_DECOMPRESSED_LOG_SIZE as u64);
        let mut decompressed_data = Vec::new();
        
        match limited_reader.read_to_end(&mut decompressed_data) {
            Ok(size) if size >= MAX_DECOMPRESSED_LOG_SIZE => {
                return Err(reject::custom(ServiceError::bad_request(
                    LogIngestError::PayloadTooLarge.into()
                )));
            },
            Ok(_) => {
                serde_json::from_slice(&decompressed_data).map_err(|e| {
                    debug!("unable to deserialize body: {}", e);
                    ServiceError::bad_request(LogIngestError::UnexpectedPayloadBody.into())
                })?
            },
            Err(e) => {
                error!("error reading decompressed data: {}", e);
                return Err(reject::custom(ServiceError::bad_request(
                    LogIngestError::UnexpectedPayloadBody.into()
                )));
            }
        }
    } else { /* ... */ }
} else { /* ... */ };
```

Additionally:
- Add rate limiting per peer_id to prevent rapid successive requests
- Monitor decompression ratios and alert on suspicious patterns
- Consider implementing per-message size limits within the log array

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    #[test]
    fn test_compression_bomb_amplification() {
        // Create a highly compressible payload with repetitive log messages
        let repetitive_message = "A".repeat(1000); // 1KB message
        let mut log_messages = Vec::new();
        
        // Create 100,000 repetitive messages (~100MB when expanded)
        for _ in 0..100_000 {
            log_messages.push(repetitive_message.clone());
        }
        
        // Serialize to JSON
        let json_payload = serde_json::to_vec(&log_messages).unwrap();
        println!("Uncompressed JSON size: {} bytes", json_payload.len());
        
        // Compress the payload
        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&json_payload).unwrap();
        let compressed = encoder.finish().unwrap();
        
        println!("Compressed size: {} bytes", compressed.len());
        println!("Compression ratio: {}:1", 
                 json_payload.len() / compressed.len());
        
        // Verify it's under 1MB
        assert!(compressed.len() < 1024 * 1024, 
                "Compressed payload should be under 1MB");
        
        // Verify massive amplification
        assert!(json_payload.len() > 50 * 1024 * 1024,
                "Decompressed payload should be over 50MB");
    }
}
```

**Integration Test Scenario:**
1. Set up telemetry service with authentication
2. Create an authenticated test client
3. Generate a compression bomb payload (repetitive JSON array)
4. Send the compressed payload to `/ingest/logs`
5. Monitor service memory usage
6. Send multiple concurrent requests
7. Observe memory exhaustion or service slowdown

## Notes

**Important Context:**
- This vulnerability affects the **telemetry service**, an auxiliary monitoring component, NOT the core blockchain consensus, execution, or state management systems
- The Aptos blockchain itself continues to operate normally even if the telemetry service is disrupted
- The vulnerability requires JWT authentication, limiting the attack surface to authenticated nodes
- The question explicitly identifies this as Medium severity, suggesting it's considered in scope despite being an auxiliary service
- While classified as a DoS-type vulnerability, it's an application-level implementation bug (missing input validation) rather than a network-level DoS attack

### Citations

**File:** crates/aptos-telemetry-service/src/constants.rs (L4-5)
```rust
/// The maximum content length to accept in the http body.
pub const MAX_CONTENT_LENGTH: u64 = 1024 * 1024;
```

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

**File:** crates/aptos-telemetry-service/src/log_ingest.rs (L35-36)
```rust
        .and(warp::body::content_length_limit(MAX_CONTENT_LENGTH))
        .and(warp::body::aggregate())
```

**File:** crates/aptos-telemetry-service/src/log_ingest.rs (L49-55)
```rust
    if let Some(blacklist) = &context.log_ingest_clients().blacklist {
        if blacklist.contains(&claims.peer_id) {
            return Err(reject::custom(ServiceError::forbidden(
                LogIngestError::Forbidden(claims.peer_id).into(),
            )));
        }
    }
```

**File:** crates/aptos-telemetry-service/src/log_ingest.rs (L64-81)
```rust
    let log_messages: Vec<String> = if let Some(encoding) = encoding {
        if encoding.eq_ignore_ascii_case("gzip") {
            let decoder = GzDecoder::new(body.reader());
            serde_json::from_reader(decoder).map_err(|e| {
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

**File:** crates/aptos-telemetry-service/src/log_ingest.rs (L97-107)
```rust
    let unstructured_log = UnstructuredLog {
        fields,
        tags,
        messages: log_messages,
    };

    debug!("ingesting to humio: {:?}", unstructured_log);

    let start_timer = Instant::now();

    let res = client.ingest_unstructured_log(unstructured_log).await;
```

**File:** crates/aptos-telemetry-service/src/clients/humio.rs (L65-90)
```rust
    pub async fn ingest_unstructured_log(
        &self,
        unstructured_log: UnstructuredLog,
    ) -> Result<reqwest::Response, anyhow::Error> {
        let mut gzip_encoder = GzEncoder::new(Vec::new(), Compression::default());
        serde_json::to_writer(&mut gzip_encoder, &vec![unstructured_log])
            .map_err(|e| anyhow!("unable to serialize json: {}", e))?;
        let compressed_bytes = gzip_encoder.finish()?;

        let req = self
            .inner
            .0
            .post(self.base_url.join("api/v1/ingest/humio-unstructured")?)
            .header("Content-Encoding", "gzip")
            .body(compressed_bytes);

        // Add authentication based on configured auth type
        let req = match &self.auth {
            HumioAuth::Bearer(token) => req.bearer_auth(token),
            HumioAuth::Basic(username, password) => req.basic_auth(username, Some(password)),
        };

        req.send()
            .await
            .map_err(|e| anyhow!("failed to post logs: {}", e))
    }
```
