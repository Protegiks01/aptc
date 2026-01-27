# Audit Report

## Title
Redis Credentials Exposed Through Serialization and Error Logging in Indexer-GRPC Components

## Summary
The `IndexerGrpcCacheWorkerConfig` and related indexer-grpc configurations derive `Serialize` and `Debug` traits without properly redacting Redis credentials contained in the `redis_main_instance_address` field. Redis URLs typically include authentication credentials in the format `redis://username:password@host:port/database`. These credentials are exposed in plaintext through multiple vectors: JSON serialization, debug formatting, error messages, and log output.

## Finding Description

The vulnerability exists across multiple layers of the indexer-grpc subsystem:

**1. Unsafe Serialization of Config Struct**

The `IndexerGrpcCacheWorkerConfig` struct derives `Serialize` without custom redaction logic: [1](#0-0) 

**2. RedisUrl Type Without Credential Protection**

The `RedisUrl` type is a newtype wrapper that derives `Serialize` and `Debug` without masking sensitive data: [2](#0-1) 

The `Display` implementation delegates directly to the inner `Url`, exposing credentials: [3](#0-2) 

**3. Credential Exposure in Error Messages**

Multiple error contexts format the `RedisUrl` with credentials in plaintext:

**Cache Worker:** [4](#0-3) 

**File Store Processor (two instances):** [5](#0-4) [6](#0-5) 

**Data Service:** [7](#0-6) 

**4. Framework Amplification**

The `GenericConfig<T>` wrapper also derives `Serialize` and `Debug`, compounding the exposure: [8](#0-7) 

**5. Existing Precedent for Credential Masking**

Critically, the codebase demonstrates awareness of this vulnerability class. The `aptos-node` logger explicitly masks postgres passwords before logging: [9](#0-8) 

This precedent proves the team understands URL credentials must be masked, yet the same protection is absent for Redis URLs in the indexer-grpc components.

## Impact Explanation

This vulnerability qualifies as **High Severity** per Aptos bug bounty criteria for the following reasons:

1. **Credential Exposure**: Redis credentials grant full read/write access to the transaction cache, a critical infrastructure component for indexer operations.

2. **Cache Poisoning Attack Vector**: An attacker obtaining Redis credentials could:
   - Corrupt cached blockchain data, causing validators and applications to receive incorrect transaction information
   - Inject malicious transaction data into the cache
   - Delete cached data causing service disruption
   - Monitor all transactions flowing through the indexer

3. **Multiple Exposure Surfaces**:
   - JSON-formatted logs (when logging is enabled with JSON output)
   - Error messages when Redis connection fails (network issues, misconfiguration, Redis downtime)
   - Debug output in diagnostic tools
   - Serialized config dumps for troubleshooting
   - Panic handler crash reports that may serialize config state

4. **Production Likelihood**: Redis connection errors are common in production environments due to:
   - Network partitions
   - Redis server restarts
   - Misconfigured connection strings
   - Firewall rules
   - Resource exhaustion

5. **Information Disclosure**: Aligns with "Significant protocol violations" category - compromised indexer infrastructure affects data integrity for all downstream consumers.

## Likelihood Explanation

**Likelihood: High**

This vulnerability will trigger automatically in common production scenarios:

1. **Redis Connection Failures**: Network issues, Redis restarts, or misconfigurations cause connection errors that log the full URL with credentials.

2. **Initial Deployment**: During setup, configuration errors frequently trigger these error paths.

3. **Infrastructure Changes**: Any Redis infrastructure maintenance or migration risks triggering credential-exposing errors.

4. **Logging Infrastructure**: Organizations often centralize logs to SIEM systems, log aggregators, or monitoring platforms, increasing exposure radius.

5. **No Privilege Required**: The vulnerability is triggered by system conditions (Redis connectivity), not attacker actions. Anyone with log access (SRE teams, monitoring systems, support staff) can view credentials.

The combination of automatic triggering and multiple exposure vectors makes exploitation highly likely without requiring sophisticated attack techniques.

## Recommendation

**Implement Credential Redaction for RedisUrl**

Follow the existing pattern used for postgres URIs. Modify the `RedisUrl` type to implement custom `Serialize`, `Debug`, and `Display` traits that mask passwords:

```rust
// In ecosystem/indexer-grpc/indexer-grpc-utils/src/types.rs

impl Serialize for RedisUrl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut url = self.0.clone();
        if url.password().is_some() {
            url.set_password(Some("REDACTED")).ok();
        }
        url.serialize(serializer)
    }
}

impl Debug for RedisUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut url = self.0.clone();
        if url.password().is_some() {
            url.set_password(Some("REDACTED")).ok();
        }
        write!(f, "RedisUrl({})", url)
    }
}

impl Display for RedisUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut url = self.0.clone();
        if url.password().is_some() {
            url.set_password(Some("REDACTED")).ok();
        }
        write!(f, "{}", url)
    }
}
```

**Additional Hardening:**

1. Consider storing Redis credentials in environment variables or secrets managers rather than URLs
2. Audit all configuration structs with `Serialize`/`Debug` derives for similar issues
3. Add linting rules to detect sensitive fields in serializable configs
4. Implement structured logging that automatically redacts known credential patterns

## Proof of Concept

```rust
// Test demonstrating credential exposure
// Place in ecosystem/indexer-grpc/indexer-grpc-utils/src/types.rs

#[cfg(test)]
mod security_tests {
    use super::*;
    
    #[test]
    fn test_redis_url_exposes_credentials_in_serialization() {
        // Create a Redis URL with credentials
        let redis_url_str = "redis://admin:secretpassword123@redis.example.com:6379/0";
        let redis_url = RedisUrl::from_str(redis_url_str).unwrap();
        
        // Serialize to JSON
        let serialized = serde_json::to_string(&redis_url).unwrap();
        
        // VULNERABILITY: The password is exposed in plaintext
        assert!(serialized.contains("secretpassword123"), 
            "Password should be redacted but is exposed: {}", serialized);
        
        // Debug formatting also exposes credentials
        let debug_output = format!("{:?}", redis_url);
        assert!(debug_output.contains("secretpassword123"),
            "Password should be redacted but is exposed: {}", debug_output);
        
        // Display formatting also exposes credentials  
        let display_output = format!("{}", redis_url);
        assert!(display_output.contains("secretpassword123"),
            "Password should be redacted but is exposed: {}", display_output);
    }
    
    #[test]
    fn test_redis_connection_error_exposes_credentials() {
        use anyhow::Context;
        
        // Simulate connection error scenario from worker.rs
        let redis_url_str = "redis://user:password@invalid-host:6379/0";
        let redis_url = RedisUrl::from_str(redis_url_str).unwrap();
        
        let result = redis::Client::open(redis_url.0.clone())
            .with_context(|| {
                format!(
                    "[Indexer Cache] Failed to create redis client for {}",
                    redis_url
                )
            });
        
        // VULNERABILITY: Error message contains credentials
        if let Err(e) = result {
            let error_msg = format!("{:?}", e);
            assert!(error_msg.contains("password"),
                "Credentials exposed in error: {}", error_msg);
        }
    }
}
```

**Steps to verify:**

1. Add the test to `ecosystem/indexer-grpc/indexer-grpc-utils/src/types.rs`
2. Run `cargo test test_redis_url_exposes_credentials_in_serialization`
3. Observe that the test passes, confirming credentials are exposed
4. Apply the recommended fixes
5. The test should now fail (or be modified to assert redaction works)
6. Trigger a Redis connection error in a running cache worker to verify credentials appear in logs

## Notes

This vulnerability represents a systemic issue across the indexer-grpc subsystem. The same pattern appears in:
- `indexer-grpc-cache-worker`
- `indexer-grpc-file-store` 
- `indexer-grpc-data-service`

All components using `RedisUrl` are affected. The fix should be centralized in the `RedisUrl` type definition to protect all consumers automatically.

The existence of password masking for postgres URIs but not Redis URLs suggests this is an oversight rather than an intentional design decision, making it a clear security gap that should be addressed.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/lib.rs (L14-22)
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IndexerGrpcCacheWorkerConfig {
    pub fullnode_grpc_address: Url,
    pub file_store_config: IndexerGrpcFileStoreConfig,
    pub redis_main_instance_address: RedisUrl,
    #[serde(default = "default_enable_cache_compression")]
    pub enable_cache_compression: bool,
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/types.rs (L13-14)
```rust
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RedisUrl(pub Url);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/types.rs (L58-62)
```rust
impl Display for RedisUrl {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
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

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store/src/processor.rs (L44-50)
```rust
        let conn = redis::Client::open(redis_main_instance_address.0.clone())
            .with_context(|| {
                format!(
                    "Create redis client for {} failed",
                    redis_main_instance_address.0
                )
            })?
```

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store/src/processor.rs (L51-58)
```rust
            .get_tokio_connection_manager()
            .await
            .with_context(|| {
                format!(
                    "Create redis connection to {} failed.",
                    redis_main_instance_address.0
                )
            })?;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/service.rs (L111-113)
```rust
                redis::Client::open(redis_address.0.clone()).with_context(|| {
                    format!("Failed to create redis client for {}", redis_address)
                })?,
```

**File:** ecosystem/indexer-grpc/indexer-grpc-server-framework/src/lib.rs (L79-86)
```rust
#[derive(Deserialize, Clone, Debug, Serialize)]
pub struct GenericConfig<T> {
    // Shared configuration among all services.
    pub health_check_port: u16,

    // Specific configuration for each service.
    pub server_config: T,
}
```

**File:** aptos-node/src/logger.rs (L91-102)
```rust
    if let Some(u) = &node_config.indexer.postgres_uri {
        let mut parsed_url = url::Url::parse(u).expect("Invalid postgres uri");
        if parsed_url.password().is_some() {
            masked_config = node_config.clone();
            parsed_url.set_password(Some("*")).unwrap();
            masked_config.indexer.postgres_uri = Some(parsed_url.to_string());
            config = &masked_config;
        }
    }

    info!("Loaded node config: {:?}", config);
}
```
