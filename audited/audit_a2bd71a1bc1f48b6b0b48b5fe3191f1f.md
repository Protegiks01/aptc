# Audit Report

## Title
Sensitive Configuration Data Exposure Through Unsanitized Debug Logging in Indexer-GRPC Services

## Summary
The `setup_logging()` function in `ServerArgs::run()` does not implement any sanitization mechanisms for configuration values before logging. Multiple indexer-grpc services log configuration structs containing sensitive data (Redis passwords, API keys, authentication tokens, and internal paths) using Debug formatting, leading to credential exposure in JSON-formatted logs and stdout.

## Finding Description

The security vulnerability exists across multiple layers in the indexer-grpc framework:

**1. No Sanitization in setup_logging()**

The `setup_logging()` function only configures the tracing subscriber with JSON formatting but provides no mechanism to sanitize sensitive configuration values. [1](#0-0) 

**2. Redis Password Exposure via println!**

The data service logs Redis connection URLs with Debug formatting directly to stdout. Redis URLs commonly contain embedded credentials in the format `redis://username:password@host:port`. The `RedisUrl` type derives Debug without custom sanitization. [2](#0-1) [3](#0-2) 

**3. File Store Configuration Exposure via Structured Logs**

The GRPC manager service explicitly logs file store configuration using `info!` macro, which exposes internal paths like Google Cloud Storage service account key paths. [4](#0-3) 

**4. Authentication Token Exposure Risk**

Configuration structs derive Debug and contain sensitive authentication data that could be exposed through error messages or explicit logging. [5](#0-4) [6](#0-5) 

**Attack Path:**

1. Operator configures indexer-grpc services with Redis URL containing password: `redis://user:secretpass@redis.internal:6379`
2. Service starts and calls `ServerArgs::run()` which invokes `setup_logging()`
3. Service initialization logs configuration with Debug formatting
4. Redis password appears in cleartext in stdout and/or structured JSON logs
5. Attacker with log access (via log aggregation, monitoring systems, or compromised log storage) obtains credentials
6. Attacker uses credentials to access Redis, potentially poisoning cache data or accessing sensitive indexed blockchain data

## Impact Explanation

This vulnerability constitutes **Medium severity** per Aptos bug bounty criteria:

- **Information Disclosure**: Exposes authentication credentials (Redis passwords, API keys, auth tokens) and internal infrastructure details (service account key paths, internal addresses)
- **Credential Compromise**: Enables attackers to access backend services (Redis, GCS) used by indexer infrastructure
- **Indirect Impact**: While not directly affecting consensus, compromised indexer infrastructure could serve malicious data to dApps and users relying on indexer APIs

The issue affects operational security of indexer-grpc services which provide critical blockchain data access to the ecosystem.

## Likelihood Explanation

**High likelihood** of exploitation in production environments:

1. **Common Configuration Pattern**: Redis URLs with embedded passwords are standard practice and widely used
2. **Log Exposure Vectors**: 
   - Centralized log aggregation systems (Splunk, ELK, CloudWatch)
   - Container orchestration platform logs (Kubernetes)
   - Monitoring dashboards
   - Log file backups
   - Insider access
3. **Automatic Occurrence**: Vulnerability triggers automatically on service startup with no special conditions required
4. **Wide Surface**: Affects multiple services (data-service, manager, cache-worker, file-store)

## Recommendation

Implement custom Debug formatters that redact sensitive fields:

```rust
// In ecosystem/indexer-grpc/indexer-grpc-utils/src/types.rs
impl std::fmt::Debug for RedisUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let url = &self.0;
        let sanitized = format!(
            "redis://{}:[REDACTED]@{}:{}{}",
            url.username(),
            url.host_str().unwrap_or("[unknown]"),
            url.port().unwrap_or(6379),
            url.path()
        );
        write!(f, "{}", sanitized)
    }
}

// In ecosystem/indexer-grpc/indexer-grpc-data-service/src/config.rs
// Add custom Debug for IndexerGrpcDataServiceConfig
impl std::fmt::Debug for IndexerGrpcDataServiceConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IndexerGrpcDataServiceConfig")
            .field("data_service_grpc_tls_config", &self.data_service_grpc_tls_config)
            .field("data_service_grpc_non_tls_config", &self.data_service_grpc_non_tls_config)
            .field("whitelisted_auth_tokens", &"[REDACTED]")
            .field("redis_read_replica_address", &self.redis_read_replica_address)
            // ... other fields
            .finish()
    }
}
```

Additionally:
- Replace `println!` statements with proper logging macros
- Implement centralized config sanitization in `setup_logging()` or `load()`
- Add lint rules to detect Debug derives on security-sensitive config structs
- Document which config fields contain sensitive data

## Proof of Concept

```rust
// Create a test config file: test_config.yaml
// health_check_port: 8080
// server_config:
//   redis_read_replica_address: "redis://admin:supersecret123@redis.internal:6379/0"
//   file_store_config:
//     file_store_type: "LocalFileStore"
//     local_file_store_path: "/tmp/test"

// Run the indexer-grpc-data-service
// cargo run --bin aptos-indexer-grpc-data-service -- --config-path test_config.yaml

// Observe stdout output:
// >>>> Starting Redis connection: Url { scheme: "redis", cannot_be_a_base: false, 
//      username: "admin", password: Some("supersecret123"), host: Some(Domain("redis.internal")), 
//      port: Some(6379), path: "/0", query: None, fragment: None }

// The password "supersecret123" is exposed in cleartext in the logs.
```

**Notes:**

This vulnerability is limited to the indexer-grpc auxiliary services and does not directly impact consensus, Move VM execution, or core blockchain security. However, it represents a significant operational security risk for production deployments where indexer infrastructure credentials could be compromised through log access.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-server-framework/src/lib.rs (L170-193)
```rust
/// Set up logging for the server. By default we don't set a writer, in which case it
/// just logs to stdout. This can be overridden using the `make_writer` parameter.
/// This can be helpful for custom logging, e.g. logging to different files based on
/// the origin of the logging.
pub fn setup_logging(make_writer: Option<Box<dyn Fn() -> Box<dyn std::io::Write> + Send + Sync>>) {
    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();

    let subscriber = tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_target(false)
        .with_thread_names(true)
        .with_env_filter(env_filter);

    match make_writer {
        Some(w) => subscriber.with_writer(w).init(),
        None => subscriber.init(),
    }
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/config.rs (L48-60)
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IndexerGrpcDataServiceConfig {
    /// If given, we will run a server that uses TLS.
    pub data_service_grpc_tls_config: Option<TlsConfig>,
    /// If given, we will run a server that does not use TLS.
    pub data_service_grpc_non_tls_config: Option<NonTlsConfig>,
    /// The size of the response channel that response can be buffered.
    #[serde(default = "IndexerGrpcDataServiceConfig::default_data_service_response_channel_size")]
    pub data_service_response_channel_size: usize,
    /// Deprecated: a list of auth tokens that are allowed to access the service.
    #[serde(default)]
    pub whitelisted_auth_tokens: Vec<String>,
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/config.rs (L162-165)
```rust
        println!(
            ">>>> Starting Redis connection: {:?}",
            &self.redis_read_replica_address.0
        );
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/types.rs (L12-14)
```rust
/// A URL that only allows the redis:// scheme.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RedisUrl(pub Url);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/grpc_manager.rs (L44-47)
```rust
        info!(
            chain_id = chain_id,
            "FilestoreUploader is created, config: {:?}.", config.file_store_config
        );
```

**File:** ecosystem/indexer-grpc/indexer-transaction-generator/src/config.rs (L315-321)
```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionImporterPerNetworkConfig {
    /// The endpoint of the transaction stream.
    pub transaction_stream_endpoint: Url,
    /// The API key to use for the transaction stream if required.
    pub api_key: Option<String>,
    /// The version of the transaction to fetch and their output file names.
```
