# Audit Report

## Title
Memory Exhaustion Vulnerability in NFT Metadata Crawler via Content-Length Header Bypass

## Summary
The NFT metadata crawler's `write_image_to_gcs()` function lacks effective buffer size enforcement due to a flaw in the upstream size validation. When the `Content-Length` HTTP header is missing, malformed, or exceeds `u32::MAX`, the size check defaults to 0 and bypasses validation, allowing attackers to trigger unbounded memory allocation by serving arbitrarily large files.

## Finding Description

The vulnerability exists in the image download pipeline used by the NFT metadata crawler. The attack flow is:

1. **Size Check Bypass**: The `get_uri_metadata()` function performs a HEAD request to retrieve the file size from the `Content-Length` header [1](#0-0) 

2. **Default to Zero on Parse Failure**: If the header is absent or cannot be parsed as `u32`, the size defaults to 0 [1](#0-0) 

3. **Bypassed Validation**: The `ImageOptimizer::optimize()` function checks if `size > max_file_size_bytes` (default: 15MB), but when size is 0, this check passes [2](#0-1) 

4. **Unbounded Download**: The actual GET request downloads the entire response body into memory without size verification [3](#0-2) 

5. **Memory Amplification**: The downloaded buffer is cloned multiple times during retry logic in `write_image_to_gcs()` [4](#0-3) 

**Attack Vector:**
An attacker deploys an NFT with a malicious image URI pointing to a server that either:
- Omits the `Content-Length` header entirely
- Sends `Content-Length: invalid_value`
- Sends `Content-Length: 999999999999999999` (exceeds `u32::MAX`)

The crawler will accept the file and attempt to download it entirely into memory, causing memory exhaustion and service crash.

The same vulnerability affects `JSONParser::parse()` [5](#0-4) 

## Impact Explanation

**Important Scope Limitation**: The NFT metadata crawler is an **ecosystem service** for indexing NFT metadata, NOT a core blockchain component. This vulnerability:
- ❌ Does NOT affect consensus operations
- ❌ Does NOT affect validator nodes
- ❌ Does NOT affect blockchain state or funds
- ✅ DOES affect NFT metadata crawler service availability

This is classified as **Medium severity** per the security question's rating. While it could cause service disruption ("API crashes" - High severity category), the NFT metadata crawler is not a critical blockchain component, limiting the overall impact to ecosystem tooling availability.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is trivial to exploit:
1. No authentication required - any user can deploy NFTs
2. No special privileges needed
3. Attack is deterministic and reproducible
4. Attacker controls the HTTP server response
5. Multiple entry points (image URIs and animation URIs) [6](#0-5) 

The only requirement is deploying an NFT on Aptos (which is permissionless) and pointing its metadata to a malicious server.

## Recommendation

Implement defense-in-depth with both pre-download and streaming validation:

**Fix 1: Enforce strict Content-Length validation**
```rust
// In get_uri_metadata()
pub async fn get_uri_metadata(url: &str) -> anyhow::Result<(String, u32)> {
    // ... existing code ...
    let size = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or_else(|| anyhow::anyhow!("Content-Length header missing or invalid"))?;
    
    Ok((mime_type, size))
}
```

**Fix 2: Add streaming download with size limits**
```rust
// In ImageOptimizer::optimize()
let mut total_bytes = 0u64;
let mut buffer = Vec::new();
let mut stream = response.bytes_stream();

while let Some(chunk) = stream.next().await {
    let chunk = chunk.context("Failed to read chunk")?;
    total_bytes += chunk.len() as u64;
    
    if total_bytes > max_file_size_bytes as u64 {
        return Err(anyhow::anyhow!(
            "Download exceeded size limit: {} bytes", total_bytes
        ));
    }
    
    buffer.extend_from_slice(&chunk);
}
```

**Fix 3: Pre-allocate with capacity limits**
```rust
// Before downloading, verify size and pre-allocate
if size == 0 || size > max_file_size_bytes {
    return Err(anyhow::anyhow!("Invalid or excessive file size"));
}
let mut buffer = Vec::with_capacity(size as usize);
```

## Proof of Concept

```rust
// Malicious HTTP server simulation
use warp::Filter;

#[tokio::test]
async fn test_memory_exhaustion_attack() {
    // Start malicious server that omits Content-Length
    let malicious_route = warp::path!("malicious.jpg")
        .map(|| {
            // Return response WITHOUT Content-Length header
            // Server streams gigabytes of data
            warp::http::Response::builder()
                .header("Content-Type", "image/jpeg")
                // Intentionally omit Content-Length
                .body(vec![0u8; 1_000_000_000]) // 1GB payload
        });
    
    let server = warp::serve(malicious_route)
        .run(([127, 0, 0, 1], 8080));
    
    tokio::spawn(server);
    
    // Attempt to optimize the malicious image
    let result = ImageOptimizer::optimize(
        "http://127.0.0.1:8080/malicious.jpg",
        15_000_000,  // 15MB limit
        100,         // quality
        4096,        // max dimensions
    ).await;
    
    // Without the fix: Process OOMs or downloads entire 1GB
    // With the fix: Returns error for missing Content-Length
}
```

**Attack Steps:**
1. Deploy NFT contract with metadata URI: `https://attacker.com/metadata.json`
2. Configure `attacker.com` to serve JSON without `Content-Length` or with invalid value
3. JSON references image: `https://attacker.com/huge.jpg`
4. Image server returns multi-gigabyte response stream without `Content-Length`
5. NFT metadata crawler attempts to download entire file into memory
6. Service crashes due to OOM

## Notes

**Critical Clarification**: This vulnerability affects the **NFT metadata crawler ecosystem service**, which is separate from core Aptos blockchain operations. While the security question explicitly asks about this component and rates it as Medium severity, it's important to understand that:

- This does NOT compromise blockchain consensus, validator operations, or on-chain state
- This is an availability issue for an off-chain indexing service
- Core blockchain functionality remains unaffected even if the crawler crashes

The vulnerability is real and exploitable, but its scope is limited to ecosystem tooling rather than core protocol security. The fix should still be implemented to ensure reliable NFT metadata indexing services.

### Citations

**File:** ecosystem/nft-metadata-crawler/src/lib.rs (L31-35)
```rust
    let size = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
```

**File:** ecosystem/nft-metadata-crawler/src/utils/image_optimizer.rs (L41-50)
```rust
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

**File:** ecosystem/nft-metadata-crawler/src/utils/image_optimizer.rs (L67-70)
```rust
                let img_bytes = response
                    .bytes()
                    .await
                    .context("Failed to load image bytes")?;
```

**File:** ecosystem/nft-metadata-crawler/src/utils/gcs.rs (L101-116)
```rust
    let op = || {
        async {
            Ok(client
                .upload_object(
                    &UploadObjectRequest {
                        bucket: bucket.to_string(),
                        ..Default::default()
                    },
                    buffer.clone(),
                    &upload_type,
                )
                .await
                .context("Error uploading image to GCS")?)
        }
        .boxed()
    };
```

**File:** ecosystem/nft-metadata-crawler/src/utils/json_parser.rs (L32-49)
```rust
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

**File:** ecosystem/nft-metadata-crawler/src/parser/worker.rs (L247-253)
```rust
                let cdn_image_uri_result = write_image_to_gcs(
                    format,
                    &self.parser_config.bucket,
                    &raw_image_uri,
                    image,
                    &self.gcs_client,
                )
```
