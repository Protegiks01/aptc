# Audit Report

## Title
Debug Formatter Panic in IndexerConfig Causing Complete Node Crash via Inspection Service

## Summary
The `IndexerConfig::fmt()` Debug implementation contains an `.expect()` call on URL parsing that can panic when formatting a `NodeConfig` with a malformed `postgres_uri` field. This panic propagates through the inspection service's `/configuration` endpoint handler, triggering the global panic handler which terminates the entire Aptos node process with exit code 12. [1](#0-0) 

## Finding Description
The vulnerability exists in the custom Debug implementation for `IndexerConfig`. When the debug formatter attempts to sanitize the `postgres_uri` field (to mask passwords), it unconditionally calls `.expect("Invalid postgres uri")` on the URL parsing result. [2](#0-1) 

**Attack Path:**

1. A node operator creates a configuration file with a malformed `postgres_uri` (e.g., typo, invalid URL syntax like `"not a valid url"`)

2. During node startup, the config is loaded and deserialized. The `postgres_uri` field is stored as an `Option<String>` with no URL format validation at load time. [3](#0-2) 

3. The `IndexerConfig::optimize()` method checks if the field is set but does NOT validate URL syntax. [4](#0-3) 

4. The node starts successfully with the malformed config in memory.

5. When someone accesses the `/configuration` endpoint, `handle_configuration_request()` calls `format!("{:?}", node_config)`. [5](#0-4) 

6. The debug formatter recursively formats all fields, reaching `IndexerConfig::fmt()`, which calls `url::Url::parse(invalid_uri).expect(...)` and panics.

7. The panic is NOT caught by error handling in `serve_requests()` (the `unwrap_or_else` only catches Response builder errors, not handler panics). [6](#0-5) 

8. The global panic handler catches the panic and terminates the entire node process via `process::exit(12)`. [7](#0-6) 

This violates the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits" - Debug formatting should never cause unrecoverable failures.

## Impact Explanation
The impact is **complete node unavailability** - the entire Aptos node process terminates, not just the inspection service. This affects:
- Validator nodes: Loss of consensus participation
- Fullnodes: Loss of service for API clients and state sync peers

While this could be classified as High Severity ("API crashes"), the pre-classification as Low Severity is appropriate due to the extremely unlikely attack scenario requiring operator misconfiguration combined with endpoint exposure.

## Likelihood Explanation
**Very Low likelihood** due to multiple prerequisites:

1. Node operator must misconfigure `postgres_uri` with invalid URL syntax
2. Most operators test configurations before production deployment
3. The `/configuration` endpoint is disabled by default on mainnet validators (for security reasons) [8](#0-7) 

4. Even on non-mainnet nodes where the endpoint auto-enables, it's typically not publicly exposed
5. The indexer config is only present if indexer functionality is being used

However, once triggered, the impact is deterministic and immediate.

## Recommendation
Replace the `.expect()` call with graceful error handling in the Debug implementation:

```rust
impl Debug for IndexerConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let postgres_uri = self.postgres_uri.as_ref().map(|u| {
            match url::Url::parse(u) {
                Ok(mut parsed_url) => {
                    if parsed_url.password().is_some() {
                        parsed_url.set_password(Some("*")).ok();
                    }
                    parsed_url.to_string()
                },
                Err(_) => {
                    // If URL parsing fails, redact the entire string
                    format!("<invalid URL: {}>", u.chars().take(20).collect::<String>())
                }
            }
        });
        // ... rest of implementation
    }
}
```

Additionally, add URL validation during config loading in `IndexerConfig::optimize()`:

```rust
// After setting postgres_uri, validate it
if let Some(uri) = &indexer_config.postgres_uri {
    if url::Url::parse(uri).is_err() {
        return Err(Error::Unexpected(format!(
            "Invalid postgres_uri: URL parsing failed for '{}'", uri
        )));
    }
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod test_panic_on_invalid_url {
    use crate::config::{IndexerConfig, NodeConfig};

    #[test]
    #[should_panic(expected = "Invalid postgres uri")]
    fn test_debug_panic_on_malformed_postgres_uri() {
        // Create a NodeConfig with malformed postgres_uri
        let mut node_config = NodeConfig::default();
        node_config.indexer = IndexerConfig {
            enabled: true,
            postgres_uri: Some("not a valid url".to_string()),
            ..Default::default()
        };

        // This will panic when Debug formatter tries to parse the invalid URL
        let _debug_output = format!("{:?}", node_config);
    }

    #[test]
    fn test_debug_succeeds_with_valid_postgres_uri() {
        let mut node_config = NodeConfig::default();
        node_config.indexer = IndexerConfig {
            enabled: true,
            postgres_uri: Some("postgresql://user:pass@localhost/db".to_string()),
            ..Default::default()
        };

        // This should succeed
        let debug_output = format!("{:?}", node_config);
        assert!(debug_output.contains("IndexerConfig"));
        // Password should be masked
        assert!(!debug_output.contains("pass"));
    }
}
```

## Notes

This vulnerability demonstrates that panic-inducing code in trait implementations (especially `Debug`) can have severe cascading effects in systems with global panic handlers. The Rust ecosystem convention is that `Debug` implementations should never panic on valid (even if semantically incorrect) data structures. 

The issue is exacerbated by Aptos's global panic handler which terminates the process rather than allowing panic recovery. While this design choice ensures deterministic failure modes, it means any panic in non-VM code paths becomes a denial-of-service vector.

The classification as Low severity is justified by the extremely low probability of occurrence, requiring both operator error and endpoint exposure. However, the technical impact (complete node crash) is severe when triggered.

### Citations

**File:** config/src/config/indexer_config.rs (L25-36)
```rust
#[derive(Clone, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct IndexerConfig {
    /// Whether the indexer is enabled or not
    /// Alternatively can set the `INDEXER_ENABLED` env var
    #[serde(default)]
    pub enabled: bool,

    /// Postgres database uri, ex: "postgresql://user:pass@localhost/postgres"
    /// Alternatively can set the `INDEXER_DATABASE_URL` env var
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postgres_uri: Option<String>,
```

**File:** config/src/config/indexer_config.rs (L92-116)
```rust
impl Debug for IndexerConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let postgres_uri = self.postgres_uri.as_ref().map(|u| {
            let mut parsed_url = url::Url::parse(u).expect("Invalid postgres uri");
            if parsed_url.password().is_some() {
                parsed_url.set_password(Some("*")).unwrap();
            }
            parsed_url.to_string()
        });
        f.debug_struct("IndexerConfig")
            .field("enabled", &self.enabled)
            .field("postgres_uri", &postgres_uri)
            .field("processor", &self.processor)
            .field("starting_version", &self.starting_version)
            .field("skip_migrations", &self.skip_migrations)
            .field("check_chain_id", &self.check_chain_id)
            .field("batch_size", &self.batch_size)
            .field("fetch_tasks", &self.fetch_tasks)
            .field("processor_tasks", &self.processor_tasks)
            .field("emit_every", &self.emit_every)
            .field("gap_lookback_versions", &self.gap_lookback_versions)
            .field("ans_contract_address", &self.ans_contract_address)
            .field("nft_points_contract", &self.nft_points_contract)
            .finish()
    }
```

**File:** config/src/config/indexer_config.rs (L138-145)
```rust
        indexer_config.postgres_uri = env_var_or_default(
            INDEXER_DATABASE_URL,
            indexer_config.postgres_uri.clone(),
            Some(format!(
                "Either 'config.indexer.postgres_uri' or '{}' must be set!",
                INDEXER_DATABASE_URL
            )),
        );
```

**File:** crates/aptos-inspection-service/src/server/configuration.rs (L13-20)
```rust
pub fn handle_configuration_request(node_config: &NodeConfig) -> (StatusCode, Body, String) {
    // Only return configuration if the endpoint is enabled
    let (status_code, body) = if node_config.inspection_service.expose_configuration {
        // We format the configuration using debug formatting. This is important to
        // prevent secret/private keys from being serialized and leaked (i.e.,
        // all secret keys are marked with SilentDisplay and SilentDebug).
        let encoded_configuration = format!("{:?}", node_config);
        (StatusCode::OK, Body::from(encoded_configuration))
```

**File:** crates/aptos-inspection-service/src/server/mod.rs (L104-197)
```rust
async fn serve_requests(
    req: Request<Body>,
    node_config: NodeConfig,
    aptos_data_client: AptosDataClient,
    peers_and_metadata: Arc<PeersAndMetadata>,
) -> Result<Response<Body>, hyper::Error> {
    // Process the request and get the response components
    let (status_code, body, content_type) = match req.uri().path() {
        CONFIGURATION_PATH => {
            // /configuration
            // Exposes the node configuration
            configuration::handle_configuration_request(&node_config)
        },
        CONSENSUS_HEALTH_CHECK_PATH => {
            // /consensus_health_check
            // Exposes the consensus health check
            metrics::handle_consensus_health_check(&node_config).await
        },
        FORGE_METRICS_PATH => {
            // /forge_metrics
            // Exposes forge encoded metrics
            metrics::handle_forge_metrics()
        },
        IDENTITY_INFORMATION_PATH => {
            // /identity_information
            // Exposes the identity information of the node
            identity_information::handle_identity_information_request(&node_config)
        },
        INDEX_PATH => {
            // /
            // Exposes the index and list of available endpoints
            index::handle_index_request()
        },
        JSON_METRICS_PATH => {
            // /json_metrics
            // Exposes JSON encoded metrics
            metrics::handle_json_metrics_request()
        },
        METRICS_PATH => {
            // /metrics
            // Exposes text encoded metrics
            metrics::handle_metrics_request()
        },
        PEER_INFORMATION_PATH => {
            // /peer_information
            // Exposes the peer information
            peer_information::handle_peer_information_request(
                &node_config,
                aptos_data_client,
                peers_and_metadata,
            )
        },
        SYSTEM_INFORMATION_PATH => {
            // /system_information
            // Exposes the system and build information
            system_information::handle_system_information_request(node_config)
        },
        _ => {
            // Handle the invalid path
            (
                StatusCode::NOT_FOUND,
                Body::from(INVALID_ENDPOINT_MESSAGE),
                CONTENT_TYPE_TEXT.into(),
            )
        },
    };

    // Create a response builder
    let response_builder = Response::builder()
        .header(HEADER_CONTENT_TYPE, content_type)
        .status(status_code);

    // Build the response based on the request methods
    let response = match *req.method() {
        Method::HEAD => response_builder.body(Body::empty()), // Return only the headers
        Method::GET => response_builder.body(body),           // Include the response body
        _ => {
            // Invalid method found
            Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Body::empty())
        },
    };

    // Return the processed response
    Ok(response.unwrap_or_else(|error| {
        // Log the internal error
        debug!("Error encountered when generating response: {:?}", error);

        // Return a failure response
        let mut response = Response::new(Body::from(UNEXPECTED_ERROR_MESSAGE));
        *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        response
    }))
```

**File:** crates/crash-handler/src/lib.rs (L26-57)
```rust
pub fn setup_panic_handler() {
    panic::set_hook(Box::new(move |pi: &PanicHookInfo<'_>| {
        handle_panic(pi);
    }));
}

// Formats and logs panic information
fn handle_panic(panic_info: &PanicHookInfo<'_>) {
    // The Display formatter for a PanicHookInfo contains the message, payload and location.
    let details = format!("{}", panic_info);
    let backtrace = format!("{:#?}", Backtrace::new());

    let info = CrashInfo { details, backtrace };
    let crash_info = toml::to_string_pretty(&info).unwrap();
    error!("{}", crash_info);
    // TODO / HACK ALARM: Write crash info synchronously via eprintln! to ensure it is written before the process exits which error! doesn't guarantee.
    // This is a workaround until https://github.com/aptos-labs/aptos-core/issues/2038 is resolved.
    eprintln!("{}", crash_info);

    // Wait till the logs have been flushed
    aptos_logger::flush();

    // Do not kill the process if the panics happened at move-bytecode-verifier.
    // This is safe because the `state::get_state()` uses a thread_local for storing states. Thus the state can only be mutated to VERIFIER by the thread that's running the bytecode verifier.
    //
    // TODO: once `can_unwind` is stable, we should assert it. See https://github.com/rust-lang/rust/issues/92988.
    if state::get_state() == VMState::VERIFIER || state::get_state() == VMState::DESERIALIZER {
        return;
    }

    // Kill the process
    process::exit(12);
```

**File:** config/src/config/inspection_service_config.rs (L26-36)
```rust
impl Default for InspectionServiceConfig {
    fn default() -> InspectionServiceConfig {
        InspectionServiceConfig {
            address: "0.0.0.0".to_string(),
            port: 9101,
            expose_configuration: false,
            expose_identity_information: true,
            expose_peer_information: true,
            expose_system_information: true,
        }
    }
```
