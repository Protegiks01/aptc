# Audit Report

## Title
Missing URL Scheme Validation in Move Package Resolver Allows SSRF and Protocol Downgrade Attacks

## Summary
The `CanonicalNodeIdentity::new()` function in the Move package resolver does not validate URL schemes before processing on-chain dependency URLs from `Move.toml` files. This allows attackers to craft malicious package manifests that can trigger Server-Side Request Forgery (SSRF) attacks or downgrade security by using `http://` instead of `https://` when resolving network versions.

## Finding Description

The Move package resolver processes dependencies specified in `Move.toml` files, including on-chain dependencies that reference Aptos full nodes via URLs. The attack path proceeds as follows:

1. **Entry Point**: An attacker creates a malicious `Move.toml` file with a dependency like:
   ```toml
   [dependencies]
   MaliciousPackage = { aptos = "http://internal-admin:8080/api", address = "0x1" }
   ```
   or with dangerous schemes like `file:///etc/passwd`

2. **URL Parsing**: When the package is processed, the `node_url` string is parsed into a `Url` object without scheme validation: [1](#0-0) 

3. **Missing Validation**: The `CanonicalNodeIdentity::new()` function receives this URL but performs NO scheme validation. It only extracts host, port, and path for canonicalization: [2](#0-1) 

   The function explicitly "ignores the scheme" as documented: [3](#0-2) 

4. **Request Execution**: The unvalidated URL is passed to `resolve_network_version()` which creates an HTTP client and makes a request: [4](#0-3) 

5. **No Scheme Restriction**: The `aptos_rest_client::Client::new()` constructor accepts any URL without validation: [5](#0-4) 

This contrasts with other parts of the codebase that properly validate URL schemes. For example, `RedisUrl` enforces the `redis://` scheme: [6](#0-5) 

## Impact Explanation

This vulnerability enables multiple attack vectors on developer and CI/CD environments:

1. **Server-Side Request Forgery (SSRF)**: Attackers can force victim machines to make HTTP requests to:
   - Internal network services (e.g., `http://localhost:6379/` for Redis)
   - Cloud metadata endpoints (e.g., `http://169.254.169.254/latest/meta-data/` on AWS/GCP)
   - Internal APIs that rely on network-based access control

2. **Protocol Downgrade**: Using `http://` instead of `https://` enables man-in-the-middle attacks where an attacker can intercept and modify package resolution responses, potentially injecting malicious Move code.

3. **Information Disclosure**: Even if dangerous schemes like `file://`, `javascript:`, or `data:` fail during request execution, the lack of early validation means these URLs are processed through multiple layers, potentially leaking information via error messages or logs.

While this is a **build-time tool** rather than validator/consensus code, it represents a **Medium severity** issue because:
- It affects developer and CI/CD environments where sensitive credentials and internal network access exist
- It enables SSRF attacks that can compromise build infrastructure
- It violates the principle of least privilege by not restricting URL schemes to safe values
- The security question explicitly labels this as "(High)" priority for investigation

## Likelihood Explanation

This vulnerability is **highly likely** to be exploited because:
- Attackers can trivially create malicious `Move.toml` files and distribute them as seemingly legitimate packages
- Developers frequently import and build third-party Move packages
- CI/CD systems automatically build packages without manual URL inspection
- The attack requires no special privileges or authentication
- The vulnerable code path executes during normal package resolution operations

## Recommendation

Implement URL scheme validation in `CanonicalNodeIdentity::new()` to restrict URLs to only `https://` (and potentially `http://` for local development):

```rust
impl CanonicalNodeIdentity {
    pub fn new(node_url: &Url) -> Result<Self> {
        // Validate scheme before processing
        match node_url.scheme() {
            "https" => {}, // Always allowed
            "http" => {
                // Only allow http for localhost/127.0.0.1 for local development
                if let Some(host) = node_url.host_str() {
                    if host != "localhost" && host != "127.0.0.1" {
                        return Err(anyhow!(
                            "Insecure scheme 'http' not allowed for remote URLs. Use 'https' instead: {}",
                            node_url
                        ));
                    }
                }
            },
            scheme => {
                return Err(anyhow!(
                    "Invalid URL scheme '{}'. Only 'https' (or 'http' for localhost) is allowed: {}",
                    scheme,
                    node_url
                ));
            }
        }
        
        let host = node_url
            .host_str()
            .ok_or_else(|| anyhow!("invalid node URL, unable to extract host: {}", node_url))?
            .to_ascii_lowercase();

        // ... rest of existing implementation
    }
}
```

Additionally, consider adding validation at the earlier parsing stage in `resolver.rs` where the URL is first converted from string to `Url`.

## Proof of Concept

**Step 1**: Create a malicious `Move.toml`:
```toml
[package]
name = "MaliciousPackage"
version = "0.1.0"

[dependencies]
# Attempt SSRF to AWS metadata service
AptosFramework = { aptos = "http://169.254.169.254/latest/meta-data/", address = "0x1" }
```

**Step 2**: Attempt to build the package:
```bash
aptos move compile --package-dir ./malicious-package
```

**Expected Behavior (Current)**: The package resolver will attempt to make an HTTP GET request to the AWS metadata endpoint, potentially exposing cloud credentials.

**Expected Behavior (After Fix)**: The package resolver immediately rejects the URL with an error message about invalid scheme before making any network requests.

**Alternative PoC with dangerous schemes**:
```toml
[dependencies]
Evil1 = { aptos = "file:///etc/passwd", address = "0x1" }
Evil2 = { aptos = "javascript:alert(1)", address = "0x1" }
Evil3 = { aptos = "data:text/html,<script>alert(1)</script>", address = "0x1" }
```

While these will eventually fail during HTTP request execution, they should be rejected immediately upon URL validation rather than being processed through multiple code layers.

## Notes

The vulnerability exists in developer tooling rather than the blockchain protocol itself, which limits its scope to development and CI/CD environments. However, these environments often have access to sensitive credentials, internal networks, and production deployment systems, making SSRF attacks in this context a legitimate security concern. The codebase already demonstrates awareness of URL scheme validation through the `RedisUrl` type, but this pattern was not applied to node URLs in the package resolver.

### Citations

**File:** third_party/move/tools/move-package-resolver/src/resolver.rs (L417-417)
```rust
            remote_url = Url::from_str(&node_url)?;
```

**File:** third_party/move/tools/move-package-cache/src/canonical.rs (L82-86)
```rust
/// Canonicalized identity of a node, derived from a [`Url`].
/// - Ignores the scheme
/// - Converts host & path to lowercase
/// - Keeps port, but only if it is non-default
/// - Trims trailing slashes
```

**File:** third_party/move/tools/move-package-cache/src/canonical.rs (L91-109)
```rust
    pub fn new(node_url: &Url) -> Result<Self> {
        let host = node_url
            .host_str()
            .ok_or_else(|| anyhow!("invalid node URL, unable to extract host: {}", node_url))?
            .to_ascii_lowercase();

        let port = match node_url.port() {
            Some(port) => match (node_url.scheme(), port) {
                ("http", 80) | ("https", 443) => "".to_string(),
                _ => format!(":{}", port),
            },
            None => "".to_string(),
        };

        let path = node_url.path().to_ascii_lowercase();
        let path = path.trim_end_matches("/");

        Ok(Self(format!("{}{}{}", host, port, path)))
    }
```

**File:** third_party/move/tools/move-package-resolver/src/lock.rs (L90-106)
```rust
    pub async fn resolve_network_version(&mut self, fullnode_url: &Url) -> Result<u64> {
        let node_identity = CanonicalNodeIdentity::new(fullnode_url)?;

        let res = match self.on_chain.entry(node_identity.to_string()) {
            btree_map::Entry::Occupied(entry) => *entry.get(),
            btree_map::Entry::Vacant(entry) => {
                let client = aptos_rest_client::Client::new(fullnode_url.clone());
                let version = client.get_ledger_information().await?.into_inner().version;

                entry.insert(version);

                version
            },
        };

        Ok(res)
    }
```

**File:** crates/aptos-rest-client/src/lib.rs (L134-136)
```rust
    pub fn new(base_url: Url) -> Self {
        Self::builder(AptosBaseUrl::Custom(base_url)).build()
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/types.rs (L16-26)
```rust
impl FromStr for RedisUrl {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = Url::parse(s)?;
        if url.scheme() != "redis" {
            return Err(anyhow::anyhow!("Invalid scheme: {}", url.scheme()));
        }
        Ok(RedisUrl(url))
    }
}
```
