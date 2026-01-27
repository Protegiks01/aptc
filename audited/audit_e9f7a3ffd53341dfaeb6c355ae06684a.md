# Audit Report

## Title
Unwrap Panic in Rosetta API Server TLS Configuration Causes Service Crash

## Summary
The `aptos-warp-webserver` crate's `serve()` function contains an unwrap panic vulnerability when `tls_cert_path` is Some but `tls_key_path` is None. This can be triggered through misconfigured CLI arguments or YAML configuration, causing an immediate crash of the Rosetta API server at startup.

## Finding Description

The vulnerability exists in the `WebServer::serve()` function where TLS configuration is handled. [1](#0-0) 

The code branches on `tls_cert_path` being Some, then unconditionally unwraps `tls_key_path` without verifying it's also Some. Since both fields are independently optional in the `ApiConfig` structure [2](#0-1) , it's possible to configure one without the other.

The Rosetta CLI accepts these as independent arguments [3](#0-2) , which are directly passed to `ApiConfig` without validation [4](#0-3) .

The `ApiConfig::sanitize()` method performs various validations but does NOT check for TLS field consistency. [5](#0-4) 

**Critical Clarification:** This vulnerability affects the **Rosetta API server only**, NOT validator nodes. The validator node's API server uses a different implementation with proper pattern matching. [6](#0-5) 

## Impact Explanation

This qualifies as **High Severity** per the Aptos bug bounty criteria: "API crashes". When triggered, the Rosetta API server panics immediately at startup, resulting in complete service unavailability. 

However, the original security question's premise about "validator crash" is **incorrect**. The `aptos-warp-webserver` crate is only used by the Rosetta service, not by validator nodes. Rosetta is a separate sidecar service that provides Rosetta API compatibility. A crash in Rosetta does NOT affect:
- Validator consensus operations
- Blockchain state or safety
- Other validator node APIs
- Network liveness

The impact is limited to denial of service of the Rosetta API, which is used by exchanges and wallets for Rosetta-compatible blockchain interaction.

## Likelihood Explanation

The likelihood is **Medium to High** for the following reasons:

**High likelihood factors:**
- Simple misconfiguration scenario (forgetting one CLI argument)
- No validation catches this error during configuration
- Crash occurs immediately at startup, making it easily triggerable
- Both CLI and YAML configuration paths are vulnerable

**Mitigating factors:**
- Operators would notice the crash immediately (fail-fast at startup)
- TLS is optional - most deployments run without TLS behind a reverse proxy
- The error message would clearly indicate the unwrap panic location

## Recommendation

Add validation to ensure TLS certificate and key paths are provided together. Implement this in multiple locations:

1. **In `ApiConfig::sanitize()`** - Add validation:
```rust
// Validate TLS configuration
if api_config.tls_cert_path.is_some() != api_config.tls_key_path.is_some() {
    return Err(Error::ConfigSanitizerFailed(
        sanitizer_name,
        "Both tls_cert_path and tls_key_path must be provided together for TLS".into(),
    ));
}
```

2. **In `WebServer::serve()`** - Replace unwrap with proper error handling:
```rust
Some(cert_path) => {
    let key_path = self.tls_key_path.as_ref()
        .ok_or_else(|| "tls_key_path must be provided when tls_cert_path is set")?;
    warp::serve(routes)
        .tls()
        .cert_path(cert_path)
        .key_path(key_path)
        .bind(self.address)
        .await
}
```

3. **Alternative: Follow the validator API pattern** - Use tuple pattern matching like the validator API does for safer handling.

## Proof of Concept

**Reproduction Steps:**

1. Start the Rosetta server with mismatched TLS configuration:
```bash
cargo run --bin aptos-rosetta -- offline \
    --listen-address 0.0.0.0:8082 \
    --tls-cert-path /tmp/cert.pem \
    --chain-id TESTNET
# Note: --tls-key-path is intentionally omitted
```

2. Expected behavior: Server attempts to start, enters `serve()` function, hits line 45, and panics:
```
thread 'tokio-runtime-worker' panicked at 'called `Option::unwrap()` on a `None` value'
```

**Alternative: YAML Configuration Reproduction:**
```yaml
# rosetta_config.yaml
api:
  enabled: true
  address: "0.0.0.0:8082"
  tls_cert_path: "/tmp/cert.pem"
  # tls_key_path intentionally omitted
```

The same panic would occur when loading this configuration.

## Notes

- This vulnerability does **not** affect validator nodes or blockchain consensus
- The validator API implementation (`api/src/runtime.rs`) handles this correctly
- Impact is limited to Rosetta API service availability
- The bug represents a violation of Rust's "no unwrap in production code" best practice
- While classified as High severity per bounty criteria (API crash), it's not a consensus or validator security issue

### Citations

**File:** crates/aptos-warp-webserver/src/webserver.rs (L39-49)
```rust
        match &self.tls_cert_path {
            None => warp::serve(routes).bind(self.address).await,
            Some(cert_path) => {
                warp::serve(routes)
                    .tls()
                    .cert_path(cert_path)
                    .key_path(self.tls_key_path.as_ref().unwrap())
                    .bind(self.address)
                    .await
            },
        }
```

**File:** config/src/config/api_config.rs (L23-28)
```rust
    /// Path to a local TLS certificate to enable HTTPS
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_cert_path: Option<String>,
    /// Path to a local TLS key to enable HTTPS
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_key_path: Option<String>,
```

**File:** config/src/config/api_config.rs (L163-200)
```rust
impl ConfigSanitizer for ApiConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let api_config = &node_config.api;

        // If the API is disabled, we don't need to do anything
        if !api_config.enabled {
            return Ok(());
        }

        // Verify that failpoints are not enabled in mainnet
        if let Some(chain_id) = chain_id {
            if chain_id.is_mainnet() && api_config.failpoints_enabled {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "Failpoints are not supported on mainnet nodes!".into(),
                ));
            }
        }

        // Validate basic runtime properties
        if api_config.max_runtime_workers.is_none() && api_config.runtime_worker_multiplier == 0 {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "runtime_worker_multiplier must be greater than 0!".into(),
            ));
        }

        // Sanitize the gas estimation config
        GasEstimationConfig::sanitize(node_config, node_type, chain_id)?;

        Ok(())
    }
}
```

**File:** crates/aptos-rosetta/src/main.rs (L176-181)
```rust
    /// Path to TLS cert for HTTPS support
    #[clap(long)]
    tls_cert_path: Option<String>,
    /// Path to TLS key for HTTPS support
    #[clap(long)]
    tls_key_path: Option<String>,
```

**File:** crates/aptos-rosetta/src/main.rs (L221-230)
```rust
    fn api_config(&self) -> ApiConfig {
        ApiConfig {
            enabled: true,
            address: self.listen_address,
            tls_cert_path: self.tls_cert_path.clone(),
            tls_key_path: self.tls_key_path.clone(),
            content_length_limit: self.content_length_limit,
            max_transactions_page_size: self.transactions_page_size,
            ..Default::default()
        }
```

**File:** api/src/runtime.rs (L191-210)
```rust
    let listener = match (&config.api.tls_cert_path, &config.api.tls_key_path) {
        (Some(tls_cert_path), Some(tls_key_path)) => {
            info!("Using TLS for API");
            let cert = std::fs::read_to_string(tls_cert_path).context(format!(
                "Failed to read TLS cert from path: {}",
                tls_cert_path
            ))?;
            let key = std::fs::read_to_string(tls_key_path).context(format!(
                "Failed to read TLS key from path: {}",
                tls_key_path
            ))?;
            let rustls_certificate = RustlsCertificate::new().cert(cert).key(key);
            let rustls_config = RustlsConfig::new().fallback(rustls_certificate);
            TcpListener::bind(address).rustls(rustls_config).boxed()
        },
        _ => {
            info!("Not using TLS for API");
            TcpListener::bind(address).boxed()
        },
    };
```
