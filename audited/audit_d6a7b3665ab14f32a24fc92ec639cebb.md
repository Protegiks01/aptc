# Audit Report

## Title
Server-Side Request Forgery (SSRF) in NFT Metadata Crawler via Unvalidated Collection URIs

## Summary
The `new_uri()` function returns URIs without validation, and downstream consumers in the NFT metadata crawler fail to properly validate these URIs before making HTTP requests. This enables attackers to perform Server-Side Request Forgery (SSRF) attacks against internal infrastructure by setting malicious collection URIs on-chain.

## Finding Description

The vulnerability exists in a multi-stage flow where unvalidated URIs propagate from on-chain storage to off-chain HTTP requests:

**Stage 1: Minimal On-Chain Validation**

The `new_uri()` function is a simple getter that returns the URI string without validation: [1](#0-0) 

When a collection creator mutates a collection URI, the only on-chain validation is a length check: [2](#0-1) 

The validation only checks `uri.length() <= MAX_URI_LENGTH` (512 characters). There is no validation of URI content, protocol, or target address.

**Stage 2: Insufficient Off-Chain Validation**

The NFT metadata crawler consumes these URIs from events. The validation in the crawler is inadequate: [3](#0-2) 

This validation only checks if the URI is syntactically parseable - it accepts `http://localhost`, `http://127.0.0.1`, `http://169.254.169.254`, and other internal addresses.

**Stage 3: Direct HTTP Requests to Attacker-Controlled URIs**

The JSONParser makes HTTP requests directly to these URIs without additional validation: [4](#0-3) 

Similarly, the ImageOptimizer performs unvalidated requests: [5](#0-4) 

**Attack Scenario:**
1. Attacker creates a collection with URI mutability enabled
2. Attacker calls `mutate_collection_uri()` with a malicious URI: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
3. The URI passes on-chain validation (length check only)
4. The NFT metadata crawler processes this collection
5. The crawler makes an HTTP request to the cloud metadata service
6. The attacker can potentially extract IAM credentials or probe internal services

## Impact Explanation

This is a **Medium Severity** vulnerability based on the following assessment:

While this vulnerability enables SSRF attacks that could lead to:
- Information disclosure from internal services
- Access to cloud metadata APIs (AWS, GCP, Azure) potentially leaking credentials
- Reconnaissance of internal network infrastructure
- Potential pivot points for further attacks

The impact is constrained because:
- It affects off-chain indexing infrastructure, not consensus or on-chain state
- Does not directly cause loss of funds or blockchain state corruption
- Does not affect validator nodes or consensus mechanism
- Requires the metadata crawler service to be running and processing the malicious URI

However, compromised cloud credentials or internal service access could escalate to more severe impacts depending on the infrastructure configuration.

## Likelihood Explanation

**Likelihood: HIGH**

The attack is highly likely to occur because:
- Any user can create collections (no special privileges required)
- URI mutation is a standard feature requiring only collection ownership
- The on-chain validation is minimal and easily bypassed
- The attack requires only a single transaction
- No sophisticated techniques or timing requirements
- The vulnerability will be triggered automatically when the crawler processes the collection

## Recommendation

Implement comprehensive URI validation at multiple layers:

**On-Chain (Move Framework):**
```move
// Add protocol validation
assert!(
    string::sub_string(&uri, 0, 8) == string::utf8(b"https://") ||
    string::sub_string(&uri, 0, 7) == string::utf8(b"ipfs://"),
    error::invalid_argument(EINVALID_URI_PROTOCOL)
);
```

**Off-Chain (Metadata Crawler):**
```rust
// Add to worker.rs before line 103
fn validate_uri_security(uri: &str) -> anyhow::Result<()> {
    let parsed = Url::parse(uri)?;
    
    // Only allow specific protocols
    match parsed.scheme() {
        "https" | "ipfs" | "ar" => {},
        _ => return Err(anyhow::anyhow!("Invalid protocol: only https, ipfs, ar allowed")),
    }
    
    // Block private IP addresses
    if let Some(host) = parsed.host_str() {
        // Block localhost
        if host == "localhost" || host == "127.0.0.1" || host == "::1" {
            return Err(anyhow::anyhow!("Localhost URIs not allowed"));
        }
        
        // Block private IP ranges
        if let Ok(addr) = host.parse::<std::net::IpAddr>() {
            if is_private_ip(&addr) {
                return Err(anyhow::anyhow!("Private IP addresses not allowed"));
            }
        }
        
        // Block cloud metadata services
        if host.contains("169.254.169.254") || host.contains("metadata.google.internal") {
            return Err(anyhow::anyhow!("Cloud metadata services blocked"));
        }
    }
    
    Ok(())
}

fn is_private_ip(addr: &std::net::IpAddr) -> bool {
    match addr {
        std::net::IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local()
        },
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback() || ((v6.segments()[0] & 0xfe00) == 0xfc00)
        },
    }
}
```

Call this validation function before processing any URI in the crawler.

## Proof of Concept

**Move Test:**
```move
#[test(creator = @0xBAD)]
fun test_ssrf_via_collection_uri(creator: &signer) acquires Collections {
    let creator_address = signer::address_of(creator);
    account::create_account_for_test(creator_address);
    
    // Create collection with URI mutability enabled
    create_collection(
        creator,
        string::utf8(b"Malicious Collection"),
        string::utf8(b"Description"),
        string::utf8(b"https://example.com/safe.json"),
        1000,
        vector<bool>[false, true, false], // URI is mutable
    );
    
    // Mutate to SSRF payload targeting AWS metadata
    let malicious_uri = string::utf8(b"http://169.254.169.254/latest/meta-data/iam/security-credentials/");
    mutate_collection_uri(
        creator,
        string::utf8(b"Malicious Collection"),
        malicious_uri
    );
    
    // The malicious URI is now stored on-chain
    let stored_uri = get_collection_uri(creator_address, string::utf8(b"Malicious Collection"));
    assert!(stored_uri == malicious_uri, 1);
    
    // When the metadata crawler processes this event, it will make an HTTP request
    // to the AWS metadata service, potentially leaking credentials
}
```

**Rust Test (Metadata Crawler):**
```rust
#[tokio::test]
async fn test_ssrf_vulnerability() {
    // Simulate malicious URI from on-chain event
    let malicious_uris = vec![
        "http://localhost:8080/admin",
        "http://127.0.0.1:6379/",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/internal",
        "http://192.168.1.1/router-config",
    ];
    
    for uri in malicious_uris {
        // Current implementation will attempt to parse these
        let result = Url::parse(uri);
        assert!(result.is_ok(), "URI passes current validation: {}", uri);
        
        // The crawler would then make HTTP requests to these internal addresses
        // demonstrating the SSRF vulnerability
    }
}
```

## Notes

This vulnerability demonstrates that consumers of `new_uri()` **cannot** assume the URI has been validated for security. The current implementation only validates length, not content. Consumers must perform their own comprehensive validation including:

- Protocol allowlisting (https, ipfs, ar only)
- Private IP address blocking
- Localhost blocking  
- Cloud metadata service blocking
- Internal hostname blocking

The vulnerability exists because there's an assumption mismatch: the on-chain code assumes minimal validation is sufficient for storage, while the off-chain crawler assumes the URIs are safe to use directly. This highlights the importance of defense-in-depth validation at every layer where untrusted data is consumed.

### Citations

**File:** types/src/account_config/events/collection_uri_mutate_event.rs (L55-57)
```rust
    pub fn new_uri(&self) -> &String {
        &self.new_uri
    }
```

**File:** aptos-move/framework/aptos-token/sources/token.move (L777-787)
```text
    public fun mutate_collection_uri(creator: &signer, collection_name: String, uri: String) acquires Collections {
        assert!(uri.length() <= MAX_URI_LENGTH, error::invalid_argument(EURI_TOO_LONG));
        let creator_address = signer::address_of(creator);
        assert_collection_exists(creator_address, collection_name);
        let collection_data = Collections[creator_address].collection_data.borrow_mut(
            collection_name
        );
        assert!(collection_data.mutability_config.uri, error::permission_denied(EFIELD_NOT_MUTABLE));
        token_event_store::emit_collection_uri_mutate_event(creator, collection_name, collection_data.uri , uri);
        collection_data.uri = uri;
    }
```

**File:** ecosystem/nft-metadata-crawler/src/parser/worker.rs (L102-108)
```rust
        // Skip if asset_uri is not a valid URI, do not write invalid URI to Postgres
        if Url::parse(&self.asset_uri).is_err() {
            self.log_info("URI is invalid, skipping parse, marking as do_not_parse");
            self.model.set_do_not_parse(true);
            SKIP_URI_COUNT.with_label_values(&["invalid"]).inc();
            return Ok(());
        }
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
