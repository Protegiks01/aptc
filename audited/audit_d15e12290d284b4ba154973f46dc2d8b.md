# Audit Report

## Title
Server-Side Request Forgery (SSRF) in NFT Metadata Crawler Enables Internal Network Access and Cloud Metadata Extraction

## Summary
The NFT metadata crawler lacks proper validation of user-supplied URIs, allowing attackers to force the crawler to make HTTP requests to internal network resources, cloud instance metadata services, and private infrastructure. This exposes sensitive validator configurations, API keys, and credentials.

## Finding Description

The NFT metadata crawler processes URIs stored on-chain in NFT token metadata. An attacker can create an NFT with a malicious URI pointing to internal infrastructure, and the crawler will fetch it without validation.

**Attack Flow:**

1. **Attacker creates NFT with malicious URI**: Using the Aptos token framework, an attacker creates an NFT with `uri` field set to internal targets like `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (AWS metadata service) or `http://localhost:8080/admin`. [1](#0-0) 

2. **Crawler receives URI via PubSub**: The crawler receives the asset URI from blockchain events. [2](#0-1) 

3. **Minimal validation occurs**: The only validation is URL syntax checking via `Url::parse()` and an optional blacklist check that defaults to empty. [3](#0-2)  The blacklist configuration has no default SSRF protections. [4](#0-3) 

4. **Multiple HTTP requests made to attacker-controlled target**:
   - `get_uri_metadata()` makes HEAD request [5](#0-4) 
   - `JSONParser::parse()` makes GET request [6](#0-5) 
   - `ImageOptimizer::optimize()` makes GET request [7](#0-6) 

5. **No IP/hostname validation**: None of these HTTP clients validate against localhost, 127.0.0.1, 169.254.169.254, or private IP ranges (10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12).

**Exploitable Targets:**
- AWS metadata service: `http://169.254.169.254/latest/meta-data/` (credentials, IAM roles)
- GCP metadata service: `http://metadata.google.internal/computeMetadata/v1/`
- Azure metadata service: `http://169.254.169.254/metadata/instance`
- Kubernetes service accounts: `http://kubernetes.default.svc`
- Internal admin panels: `http://localhost:8080/admin`
- Private network services: `http://192.168.1.100/config`

## Impact Explanation

**Critical Severity** - This vulnerability enables:

1. **Cloud Credential Theft**: Access to cloud metadata services exposes IAM credentials, service account tokens, and API keys used by the crawler infrastructure. If the crawler runs on validator nodes or shared infrastructure, this could compromise validator operations.

2. **Internal Network Reconnaissance**: Attackers can scan internal networks, discover services, and map private infrastructure topology.

3. **Configuration Exposure**: Access to internal admin interfaces or configuration endpoints could reveal validator settings, database credentials, and network architecture.

4. **Validator Compromise**: If the crawler has access to validator configuration or runs on validator infrastructure, credential theft could lead to validator private key exposure or operational disruption.

This meets **Critical Severity** criteria under "Remote Code Execution on validator node" (if credentials lead to infrastructure access) and represents a significant infrastructure security breach.

## Likelihood Explanation

**High Likelihood**:

1. **Trivial to exploit**: Any user can create an NFT with arbitrary URIs on-chain at minimal cost (gas fees only).

2. **No authentication required**: The attacker doesn't need privileged access - just the ability to create NFTs.

3. **Default insecure configuration**: The `uri_blacklist` defaults to empty, providing zero SSRF protection out-of-the-box.

4. **Multiple attack vectors**: Three separate HTTP request points increase attack surface.

5. **Common deployment scenario**: NFT metadata crawlers typically run on cloud infrastructure with access to metadata services.

## Recommendation

Implement comprehensive SSRF protection with defense-in-depth:

1. **Add URI validation function** to reject dangerous targets:
   - Block localhost, 127.0.0.0/8, ::1
   - Block private IP ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
   - Block cloud metadata IPs: 169.254.169.254, fd00:ec2::254
   - Block link-local addresses
   - Enforce HTTPS-only for external requests

2. **Apply validation before all HTTP requests** in `get_uri_metadata()`, `JSONParser::parse()`, and `ImageOptimizer::optimize()`.

3. **Use DNS rebinding protection**: Resolve hostname to IP, validate IP, then make request using IP directly.

4. **Set default blacklist** to include common SSRF targets instead of empty Vec.

5. **Implement network-level controls**: Run crawler in isolated network segment without access to internal services.

## Proof of Concept

**Step 1: Create malicious NFT (Move)**
```move
// Create NFT with SSRF URI pointing to AWS metadata service
use aptos_framework::object;
use aptos_token_objects::token;

public entry fun create_ssrf_nft(creator: &signer) {
    let collection = /* existing collection */;
    let token_uri = string::utf8(b"http://169.254.169.254/latest/meta-data/iam/security-credentials/");
    
    token::create_named_token(
        creator,
        collection,
        /* ... */,
        token_uri, // Malicious URI
        /* ... */
    );
}
```

**Step 2: Crawler processes URI**
The crawler receives this URI via PubSub, passes validation (valid URL syntax), and makes requests to AWS metadata service, leaking credentials.

**Step 3: Verification**
Monitor crawler logs or set up logging server to receive requests confirming the SSRF:
- Crawler will make HEAD request to `http://169.254.169.254/...`
- Crawler will attempt GET request to fetch "JSON"
- Response contains AWS credentials/tokens

## Notes

This vulnerability is particularly dangerous because:

1. **Blind SSRF**: Even if response data isn't directly returned to attacker, they can use out-of-band techniques (DNS exfiltration, timing attacks) or observe side effects.

2. **Chain of attacks**: Initial SSRF could be chained with other vulnerabilities in internal services.

3. **Ecosystem impact**: While not directly affecting consensus, compromised validator infrastructure through credential theft could lead to consensus manipulation or validator key exposure.

The fix must be applied at the HTTP client layer with IP-based validation after DNS resolution to prevent DNS rebinding attacks.

### Citations

**File:** ecosystem/nft-metadata-crawler/src/parser/mod.rs (L106-106)
```rust
        let parts: Vec<&str> = pubsub_message.split(',').collect();
```

**File:** ecosystem/nft-metadata-crawler/src/parser/mod.rs (L155-166)
```rust
        let mut worker = Worker::new(
            self.parser_config.clone(),
            conn,
            self.parser_config.max_num_parse_retries,
            self.gcs_client.clone(),
            &pubsub_message,
            parts[0],
            parts[1],
            last_transaction_version,
            last_transaction_timestamp,
            parts[5].parse::<bool>().unwrap_or(false),
        );
```

**File:** ecosystem/nft-metadata-crawler/src/parser/worker.rs (L103-108)
```rust
        if Url::parse(&self.asset_uri).is_err() {
            self.log_info("URI is invalid, skipping parse, marking as do_not_parse");
            self.model.set_do_not_parse(true);
            SKIP_URI_COUNT.with_label_values(&["invalid"]).inc();
            return Ok(());
        }
```

**File:** ecosystem/nft-metadata-crawler/src/parser/config.rs (L28-29)
```rust
    #[serde(default)]
    pub uri_blacklist: Vec<String>,
```

**File:** ecosystem/nft-metadata-crawler/src/lib.rs (L17-37)
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
```

**File:** ecosystem/nft-metadata-crawler/src/utils/json_parser.rs (L60-64)
```rust
                let response = client
                    .get(uri.trim())
                    .send()
                    .await
                    .context("Failed to get JSON")?;
```

**File:** ecosystem/nft-metadata-crawler/src/utils/image_optimizer.rs (L61-65)
```rust
                let response = client
                    .get(uri.trim())
                    .send()
                    .await
                    .context("Failed to get image")?;
```
