# Audit Report

## Title
Redis Credential Leakage Through Error Messages and Logging in Indexer-gRPC Services

## Summary
The `RedisUrl` type in the indexer-grpc utilities does not sanitize credentials before being logged or included in error messages. This leads to plain-text Redis passwords being exposed in application logs, error outputs, and debug messages across multiple indexer-grpc services (data-service, cache-worker, file-store).

## Finding Description

The `RedisUrl` type is used throughout the indexer-grpc services to store Redis connection URLs that may contain embedded credentials in the format `redis://:password@host:port`. Unlike the codebase's handling of PostgreSQL URLs (which explicitly sanitize passwords before logging), `RedisUrl` lacks any credential sanitization mechanism. [1](#0-0) 

The type derives `Debug` without custom implementation and implements `Display` by directly printing the underlying URL: [2](#0-1) 

This results in credentials being exposed in multiple locations:

**1. Direct stdout logging during service startup:** [3](#0-2) 

**2. Error context when Redis connection fails:** [4](#0-3) 

**3. Cache worker error context:** [5](#0-4) 

**4. File store processor error contexts (two locations):** [6](#0-5) [7](#0-6) 

Additionally, when configuration deserialization fails due to invalid scheme validation, Figment's error reporting mechanism may include the full URL value along with the custom error message from the `Deserialize` implementation: [8](#0-7) 

The codebase demonstrates awareness of this security risk through explicit sanitization of PostgreSQL URIs: [9](#0-8) 

However, this pattern was not applied to `RedisUrl`.

## Impact Explanation

This is a **Low to Medium severity** information disclosure vulnerability per the Aptos bug bounty criteria:

- **Information Leak**: Redis credentials are exposed in plain text through logs and error messages
- **Downstream Impact**: Exposed credentials could enable unauthorized access to Redis instances, allowing attackers to:
  - Read cached blockchain indexing data
  - Corrupt the cache (if write permissions exist)
  - Cause denial of service by clearing the cache
  - Potentially use the compromised Redis instance as a pivot point

The vulnerability affects infrastructure services (indexer-grpc) rather than core consensus components, limiting its severity. However, compromised indexing infrastructure could impact data availability for applications relying on these services.

## Likelihood Explanation

**High Likelihood** - The vulnerability triggers in multiple common scenarios:

1. **Normal startup**: Credentials are logged to stdout every time the data-service starts (line 164 in config.rs)
2. **Connection failures**: Any Redis connectivity issue causes credentials to be logged in error context
3. **Configuration errors**: Invalid scheme in config files triggers deserialization errors that may include the full URL
4. **Log aggregation**: These logs are typically sent to centralized logging systems, increasing exposure surface

The likelihood is further increased because:
- No special attacker actions are required
- The leakage occurs during normal operations
- Log files are often accessible to operators, support staff, and monitoring systems
- Centralized logging systems may retain these credentials indefinitely

## Recommendation

Implement credential sanitization for `RedisUrl` following the same pattern used for PostgreSQL URIs:

**1. Add a custom `Debug` implementation:**
```rust
impl Debug for RedisUrl {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let sanitized = self.sanitized_url();
        f.debug_tuple("RedisUrl").field(&sanitized).finish()
    }
}
```

**2. Add a custom `Display` implementation that sanitizes:**
```rust
impl Display for RedisUrl {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.sanitized_url())
    }
}
```

**3. Add a private helper method:**
```rust
impl RedisUrl {
    fn sanitized_url(&self) -> String {
        let mut url = self.0.clone();
        if url.password().is_some() {
            url.set_password(Some("***")).unwrap();
        }
        url.to_string()
    }
}
```

**4. Remove the `Debug` derive** from the struct definition:
```rust
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct RedisUrl(pub Url);
```

This ensures credentials are masked with `***` in all logging, debug output, and error messages while preserving the actual credentials for establishing connections.

## Proof of Concept

**Setup:** Create a YAML configuration file with embedded Redis credentials:

```yaml
health_check_port: 8080
server_config:
  data_service_grpc_non_tls_config:
    data_service_grpc_listen_address: "0.0.0.0:50051"
  file_store_config:
    file_store_bucket_name: "test-bucket"
  redis_read_replica_address: "redis://:SuperSecretPassword123@redis.internal:6379"
```

**Trigger 1 - Normal startup:**
Start the indexer-grpc-data-service with this config. Observe stdout output includes:
```
>>>> Starting Redis connection: Url { scheme: "redis", ... password: Some("SuperSecretPassword123"), ... }
```

**Trigger 2 - Invalid scheme:**
Modify config to use invalid scheme:
```yaml
redis_read_replica_address: "redis-cluster://:SuperSecretPassword123@redis.internal:6379"
```

Attempting to load this config will produce a deserialization error that Figment reports with the full value visible in the error chain.

**Trigger 3 - Connection error:**
Use a valid config but ensure Redis is unreachable. The service will fail with error:
```
Failed to create redis client for redis://:SuperSecretPassword123@redis.internal:6379
```

All three scenarios demonstrate credential leakage to logs accessible by operators, monitoring systems, and potentially attackers with log access.

## Notes

This vulnerability demonstrates a systemic issue where secure coding patterns (URL sanitization) were applied inconsistently across the codebase. While PostgreSQL URIs are properly sanitized, Redis URLs are not, despite serving the same security-sensitive purpose. A comprehensive audit of all URL/credential handling throughout the codebase is recommended to identify and remediate similar patterns.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/types.rs (L13-14)
```rust
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RedisUrl(pub Url);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/types.rs (L28-41)
```rust
impl<'de> Deserialize<'de> for RedisUrl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let url = Url::deserialize(deserializer)?;
        if url.scheme() != "redis" {
            return Err(serde::de::Error::custom(format!(
                "Invalid scheme: {}",
                url.scheme()
            )));
        }
        Ok(Self(url))
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/types.rs (L58-61)
```rust
impl Display for RedisUrl {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/config.rs (L162-165)
```rust
        println!(
            ">>>> Starting Redis connection: {:?}",
            &self.redis_read_replica_address.0
        );
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/service.rs (L111-113)
```rust
                redis::Client::open(redis_address.0.clone()).with_context(|| {
                    format!("Failed to create redis client for {}", redis_address)
                })?,
```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L84-90)
```rust
        let redis_client = redis::Client::open(redis_main_instance_address.0.clone())
            .with_context(|| {
                format!(
                    "[Indexer Cache] Failed to create redis client for {}",
                    redis_main_instance_address
                )
            })?;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store/src/processor.rs (L44-49)
```rust
        let conn = redis::Client::open(redis_main_instance_address.0.clone())
            .with_context(|| {
                format!(
                    "Create redis client for {} failed",
                    redis_main_instance_address.0
                )
```

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store/src/processor.rs (L53-57)
```rust
            .with_context(|| {
                format!(
                    "Create redis connection to {} failed.",
                    redis_main_instance_address.0
                )
```

**File:** config/src/config/indexer_config.rs (L92-100)
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
```
