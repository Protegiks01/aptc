# Audit Report

## Title
Redis URL Credentials and Infrastructure Disclosure via Display Trait in Indexer Components

## Summary
The `RedisUrl` type's `Display` trait implementation exposes complete Redis connection URLs including potential credentials, private IP addresses, database numbers, and internal hostnames when triggered in error messages during connection failures in indexer-grpc components. [1](#0-0) 

## Finding Description
The `RedisUrl` wrapper type implements the `Display` trait by directly outputting the inner `url::Url` object without any sanitization or masking of sensitive information. When Redis connection failures occur in production indexer services, this Display implementation is invoked via error context formatting, exposing the complete Redis URL in logs and error messages.

**Vulnerable Code Paths:**

1. **Cache Worker** - Connection failure exposes full Redis URL: [2](#0-1) 

2. **Data Service** - Service initialization failure exposes Redis URL: [3](#0-2) 

3. **File Store Processor** - Uses inner URL `.0` directly but still exposes credentials: [4](#0-3) 

**Security Context Violation:**

The codebase demonstrates explicit awareness of credential exposure risks and implements password masking for PostgreSQL URIs in other components: [5](#0-4) [6](#0-5) 

This inconsistency indicates the `RedisUrl` Display implementation violates established security practices within the codebase.

**Information Disclosed:**
- Private IP addresses or internal hostnames
- Port numbers
- Redis database numbers  
- Potentially embedded credentials if Redis URLs use the format `redis://username:password@host:port/db`

## Impact Explanation
This vulnerability falls under **Medium Severity** per Aptos bug bounty criteria for the following reasons:

1. **Information Disclosure Severity**: While categorized as an information leak, the exposure includes potential authentication credentials and detailed internal infrastructure topology that could facilitate more sophisticated attacks.

2. **Credential Exposure Risk**: Redis URLs can contain embedded credentials in the standard format `redis://[username[:password]@]host:port/database`. If operators configure Redis authentication via URL parameters (common practice), passwords are logged in cleartext.

3. **Infrastructure Reconnaissance**: Exposed private IP addresses, port numbers, and database identifiers provide attackers with detailed infrastructure mapping, reducing the effort required for targeted attacks against the indexer infrastructure.

4. **Trust Boundary Violation**: Log data may be accessible to:
   - Log aggregation systems with broader access controls
   - Monitoring dashboards  
   - Semi-trusted operational staff
   - External systems via log forwarding

While this does not directly impact consensus, state integrity, or funds, it represents a significant operational security risk for indexer infrastructure that processes and serves blockchain data to external consumers.

## Likelihood Explanation
**High Likelihood** of occurrence:

1. **Common Trigger Conditions**:
   - Network connectivity issues
   - Redis server restarts or maintenance
   - Misconfiguration during deployment
   - Authentication failures
   - Firewall rule changes

2. **Production Environment Exposure**: These errors occur in production indexer services that continuously process blockchain data, making Redis connection failures a realistic operational scenario.

3. **Multiple Vulnerable Code Paths**: Three separate components (cache worker, data service, file store processor) exhibit this vulnerability, multiplying exposure opportunities.

4. **Persistent Logging**: Error messages are typically logged to persistent storage and forwarded to centralized logging systems, extending the window of exposure.

## Recommendation
Implement credential masking in the `Display` trait implementation for `RedisUrl`, following the pattern established for PostgreSQL URIs elsewhere in the codebase:

```rust
impl Display for RedisUrl {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut masked_url = self.0.clone();
        if masked_url.password().is_some() {
            let _ = masked_url.set_password(Some("***"));
        }
        if masked_url.username() != "" {
            let _ = masked_url.set_username("***");
        }
        write!(f, "{}", masked_url)
    }
}
```

**Alternative approach** - Also implement a secure Debug trait:
```rust
impl Debug for RedisUrl {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut masked_url = self.0.clone();
        if masked_url.password().is_some() {
            let _ = masked_url.set_password(Some("***"));
        }
        if masked_url.username() != "" {
            let _ = masked_url.set_username("***");
        }
        f.debug_tuple("RedisUrl")
            .field(&masked_url.to_string())
            .finish()
    }
}
```

## Proof of Concept

```rust
// Add to ecosystem/indexer-grpc/indexer-grpc-utils/src/types.rs as a test

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redis_url_display_exposes_credentials() {
        // Simulate a Redis URL with embedded credentials
        let redis_url_str = "redis://admin:secretpassword123@10.0.1.50:6379/0";
        let redis_url: RedisUrl = redis_url_str.parse().expect("Valid Redis URL");
        
        // Simulate error message formatting
        let error_message = format!("Failed to connect to Redis: {}", redis_url);
        
        // Verify that credentials are exposed (this demonstrates the vulnerability)
        assert!(error_message.contains("secretpassword123"));
        assert!(error_message.contains("admin"));
        assert!(error_message.contains("10.0.1.50"));
        
        println!("VULNERABILITY DEMONSTRATED:");
        println!("Error message exposes: {}", error_message);
        println!("\nThis would appear in production logs, exposing:");
        println!("  - Username: admin");
        println!("  - Password: secretpassword123");
        println!("  - Private IP: 10.0.1.50");
        println!("  - Port: 6379");
        println!("  - Database: 0");
    }

    #[test]
    fn test_with_context_error_exposure() {
        use anyhow::Context;
        
        let redis_url_str = "redis://indexer:P@ssw0rd!@redis-internal.example.com:6379/2";
        let redis_url: RedisUrl = redis_url_str.parse().expect("Valid Redis URL");
        
        // Simulate the pattern used in worker.rs and service.rs
        let result: Result<(), anyhow::Error> = Err(anyhow::anyhow!("Connection refused"))
            .with_context(|| format!("Failed to create redis client for {}", redis_url));
        
        if let Err(e) = result {
            let error_string = format!("{:#}", e);
            println!("\nError chain exposes credentials:");
            println!("{}", error_string);
            
            // Verify exposure
            assert!(error_string.contains("P@ssw0rd!"));
            assert!(error_string.contains("redis-internal.example.com"));
        }
    }
}
```

**To run the PoC:**
```bash
cd ecosystem/indexer-grpc/indexer-grpc-utils
cargo test test_redis_url_display_exposes_credentials -- --nocapture
cargo test test_with_context_error_exposure -- --nocapture
```

## Notes

**Scope Context**: This vulnerability affects the indexer-grpc infrastructure components, not core consensus, Move VM, or state management systems. However, indexer services are production-critical infrastructure that serve blockchain data to external consumers and applications.

**Credential Usage**: While the current codebase examples show Redis connections without embedded credentials, the `RedisUrl` type explicitly supports and validates the `redis://` scheme which permits credential embedding per Redis URL specification. The vulnerability exists regardless of current deployment practices.

**Defense in Depth**: Even if current deployments don't use URL-embedded credentials, implementing proper credential masking follows defense-in-depth principles and aligns with security practices already established elsewhere in the codebase for PostgreSQL connections.

### Citations

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

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/service.rs (L111-113)
```rust
                redis::Client::open(redis_address.0.clone()).with_context(|| {
                    format!("Failed to create redis client for {}", redis_address)
                })?,
```

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store/src/processor.rs (L44-58)
```rust
        let conn = redis::Client::open(redis_main_instance_address.0.clone())
            .with_context(|| {
                format!(
                    "Create redis client for {} failed",
                    redis_main_instance_address.0
                )
            })?
            .get_tokio_connection_manager()
            .await
            .with_context(|| {
                format!(
                    "Create redis connection to {} failed.",
                    redis_main_instance_address.0
                )
            })?;
```

**File:** aptos-node/src/logger.rs (L91-98)
```rust
    if let Some(u) = &node_config.indexer.postgres_uri {
        let mut parsed_url = url::Url::parse(u).expect("Invalid postgres uri");
        if parsed_url.password().is_some() {
            masked_config = node_config.clone();
            parsed_url.set_password(Some("*")).unwrap();
            masked_config.indexer.postgres_uri = Some(parsed_url.to_string());
            config = &masked_config;
        }
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
