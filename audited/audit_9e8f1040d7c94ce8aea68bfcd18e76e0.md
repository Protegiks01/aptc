# Audit Report

## Title
Cloudflare API Key Exposure Through Application Startup Logging in NFT Metadata Crawler

## Summary
The NFT metadata crawler exposes the Cloudflare API authentication key in plain text through application startup logging, allowing anyone with access to application logs to retrieve sensitive credentials.

## Finding Description

The NFT metadata crawler's configuration structure implements the `Debug` trait, which causes the Cloudflare API key to be logged in plain text when the service starts up. [1](#0-0) 

The exposure occurs through the following chain:

1. At startup, the entire configuration is logged using debug formatting
2. `NFTMetadataCrawlerConfig` derives `Debug` and contains `server_config: ServerConfig` [2](#0-1) 

3. `ServerConfig` derives `Debug` and includes the `AssetUploaderWorker` variant containing `AssetUploaderWorkerConfig` [3](#0-2) 

4. `AssetUploaderWorkerConfig` derives `Debug` and contains the sensitive `cloudflare_auth_key` field [4](#0-3) 

When the service starts in AssetUploaderWorker mode, the API key is logged and accessible through:
- Local log files
- Centralized logging systems (e.g., Elasticsearch, Splunk)
- Log monitoring dashboards
- Application log exports

The Authorization header itself is transmitted securely over HTTPS to Cloudflare [5](#0-4)  and is not logged in request/response logs [6](#0-5) , but the startup logging vulnerability exposes it regardless.

## Impact Explanation

This vulnerability represents an **information disclosure** issue that could lead to **unauthorized API access**. While this doesn't directly impact the Aptos blockchain consensus or core functionality, it affects the security of the NFT metadata infrastructure.

Per the Aptos bug bounty severity categories, this would be classified as **Low Severity** (up to $1,000) as it represents a "minor information leak" that doesn't directly affect blockchain consensus, validator operations, or on-chain funds. However, exploitation could lead to:

- Unauthorized use of the Cloudflare account for image storage
- Manipulation or deletion of NFT metadata images
- Financial cost implications from API abuse
- Reputational damage from compromised infrastructure

## Likelihood Explanation

**Likelihood: Medium to High**

The vulnerability triggers automatically on every service startup, making exposure inevitable rather than requiring specific attack conditions. The likelihood of exploitation depends on:

1. **Access Requirements**: Attackers need access to application logs through:
   - Compromised log aggregation systems
   - Insider access to production infrastructure
   - Misconfigured log permissions
   - Exposed log files in backup systems

2. **Detection**: Log access is common in production environments for debugging and monitoring, making this a realistic attack vector

3. **Complexity**: No sophisticated exploitation techniques required - simple log file access is sufficient

## Recommendation

Implement credential redaction for sensitive configuration fields:

```rust
// In ecosystem/nft-metadata-crawler/src/asset_uploader/worker/config.rs
use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssetUploaderWorkerConfig {
    /// Cloudflare API key
    pub cloudflare_auth_key: String,
    /// Cloudflare Account ID provided at the images home page used to authenticate requests
    pub cloudflare_account_id: String,
}

// Custom Debug implementation that redacts the API key
impl std::fmt::Debug for AssetUploaderWorkerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AssetUploaderWorkerConfig")
            .field("cloudflare_auth_key", &"[REDACTED]")
            .field("cloudflare_account_id", &self.cloudflare_account_id)
            .finish()
    }
}
```

**Alternative approach**: Remove the `Debug` derive from configuration structures containing secrets and avoid logging raw configuration objects.

## Proof of Concept

**Steps to reproduce:**

1. Configure the NFT metadata crawler with a valid Cloudflare API key in the YAML config:
```yaml
database_url: "postgresql://localhost/nft_metadata"
server_port: 8080
server_config:
  type: AssetUploaderWorker
  cloudflare_auth_key: "your-secret-api-key-here"
  cloudflare_account_id: "account-id"
```

2. Start the NFT metadata crawler service

3. Observe the startup logs - the output will contain:
```
[NFT Metadata Crawler] Starting with config: NFTMetadataCrawlerConfig { 
  database_url: "postgresql://localhost/nft_metadata", 
  server_port: 8080, 
  server_config: AssetUploaderWorker(AssetUploaderWorkerConfig { 
    cloudflare_auth_key: "your-secret-api-key-here", 
    cloudflare_account_id: "account-id" 
  }) 
}
```

4. The `cloudflare_auth_key` is now exposed in plain text in the application logs

5. Anyone with log access can use this key to make authenticated requests to the Cloudflare Images API

**Note**: This PoC demonstrates the logging issue without requiring network monitoring or request interception, as the credential is exposed directly through application startup logging.

---

## Notes

This vulnerability is specific to the NFT metadata crawler ecosystem tool and does not directly impact Aptos blockchain consensus, Move VM execution, state management, or core validator operations. However, it represents a security best practice violation in credential handling that should be addressed to protect auxiliary infrastructure components.

### Citations

**File:** ecosystem/nft-metadata-crawler/src/config.rs (L30-37)
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ServerConfig {
    Parser(ParserConfig),
    AssetUploaderWorker(AssetUploaderWorkerConfig),
    AssetUploaderApi,
    AssetUploaderThrottler(AssetUploaderThrottlerConfig),
}
```

**File:** ecosystem/nft-metadata-crawler/src/config.rs (L40-46)
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NFTMetadataCrawlerConfig {
    pub database_url: String,
    pub server_port: u16,
    pub server_config: ServerConfig,
}
```

**File:** ecosystem/nft-metadata-crawler/src/config.rs (L88-88)
```rust
        info!("[NFT Metadata Crawler] Starting with config: {:?}", self);
```

**File:** ecosystem/nft-metadata-crawler/src/asset_uploader/worker/config.rs (L7-14)
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssetUploaderWorkerConfig {
    /// Cloudflare API key
    pub cloudflare_auth_key: String,
    /// Cloudflare Account ID provided at the images home page used to authenticate requests
    pub cloudflare_account_id: String,
}
```

**File:** ecosystem/nft-metadata-crawler/src/asset_uploader/worker/mod.rs (L84-87)
```rust
        info!(
            asset_uri = ?url,
            "[Asset Uploader] Uploading asset to Cloudflare"
        );
```

**File:** ecosystem/nft-metadata-crawler/src/asset_uploader/worker/mod.rs (L89-101)
```rust
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
```
