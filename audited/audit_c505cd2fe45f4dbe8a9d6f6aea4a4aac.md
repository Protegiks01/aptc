# Audit Report

## Title
Information Disclosure of Internal Network Topology Through Unsanitized Error Logging in Node Checker

## Summary
The `RetryableEndpointError` wrapping in the node-checker's `ApiIndexProvider` does not sanitize URLs before logging, potentially leaking internal IP addresses and network topology information when errors are logged. However, authentication tokens and stack traces are not exposed.

## Finding Description

The node-checker's `ApiIndexProvider` wraps REST client errors without sanitizing sensitive information: [1](#0-0) 

The error chain flows as follows:

1. `Client::get_index()` returns a `reqwest::Error` on failure
2. The error is converted to `RestError` which preserves the URL information: [2](#0-1) 

3. This is wrapped in `ProviderError::RetryableEndpointError` with the error message format: [3](#0-2) 

4. These errors are logged in the sync runner using the `{:#}` format specifier: [4](#0-3) 

When a `reqwest::Error` is displayed, it includes the full URL being accessed (e.g., "error sending request for url (http://192.168.1.100:8080/v1/)"), exposing internal IP addresses and port numbers.

**Security concerns addressed:**
- **Auth tokens**: NOT leaked - tokens are passed via Authorization header which `reqwest::Error` does not expose: [5](#0-4) 

- **Internal IPs**: LEAKED - URLs containing internal IPs are included in error messages without sanitization

- **Stack traces**: NOT leaked - the `{:#}` format only displays the error chain, not backtraces

## Impact Explanation

This vulnerability falls into the **Medium severity** category as stated in the security question. While it doesn't directly compromise consensus, funds, or network availability, it constitutes an information disclosure vulnerability that could aid network reconnaissance. 

If node-checker logs are sent to third-party logging services or accessible by unauthorized personnel, internal network topology (IP addresses, ports, API structure) would be exposed. However, this requires log access which limits the severity.

## Likelihood Explanation

The likelihood is **moderate** because:
- It only occurs when REST client errors happen during node health checks
- It requires the attacker to have access to node-checker logs
- It depends on deployment configuration (centralized logging, log retention)
- The node-checker is typically run in controlled environments by trusted operators

## Recommendation

Implement URL sanitization before logging errors. The fix should redact sensitive parts of URLs while preserving debugging utility:

```rust
// In ecosystem/node-checker/src/provider/api_index.rs
use anyhow::Result;

fn sanitize_url(url: &str) -> String {
    // Redact IP addresses and ports, keep path for debugging
    url.parse::<url::Url>()
        .map(|u| {
            let scheme = u.scheme();
            let path = u.path();
            format!("{}://<redacted>{}", scheme, path)
        })
        .unwrap_or_else(|_| "<invalid-url>".to_string())
}

async fn provide(&self) -> Result<Self::Output, ProviderError> {
    self.output_cache
        .get(
            self.client
                .get_index()
                .map_ok(|r| r.into_inner())
                .map_err(|e| {
                    let sanitized_msg = format!("Request failed: {}", sanitize_url(&e.to_string()));
                    ProviderError::RetryableEndpointError("/", anyhow::anyhow!(sanitized_msg))
                }),
        )
        .await
}
```

## Proof of Concept

```rust
// Test demonstrating URL leakage in error messages
#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::Client as ReqwestClient;
    
    #[tokio::test]
    async fn test_url_leakage_in_errors() {
        // Create a client pointing to an internal IP
        let client = aptos_rest_client::Client::new(
            "http://192.168.1.100:8080".parse().unwrap()
        );
        
        let provider = ApiIndexProvider::new(
            ApiIndexProviderConfig::default(),
            client,
        );
        
        // Trigger an error by connecting to non-existent host
        let result = provider.provide().await;
        
        // The error message will contain the internal IP
        match result {
            Err(e) => {
                let error_msg = format!("{:#}", e);
                // This assertion would pass, demonstrating the leak
                assert!(error_msg.contains("192.168.1.100"));
                println!("Error message leaks internal IP: {}", error_msg);
            },
            Ok(_) => panic!("Expected error"),
        }
    }
}
```

**Notes:**

The vulnerability is limited in scope because:
1. The node-checker is an operational diagnostic tool, not part of core blockchain consensus or execution
2. It requires access to logs, which should already be restricted
3. Auth tokens are properly protected (not exposed in error messages)
4. This is primarily a defense-in-depth concern rather than a critical exploit

The recommended fix implements URL sanitization to prevent accidental disclosure while maintaining debugging utility.

### Citations

**File:** ecosystem/node-checker/src/provider/api_index.rs (L55-64)
```rust
    async fn provide(&self) -> Result<Self::Output, ProviderError> {
        self.output_cache
            .get(
                self.client
                    .get_index()
                    .map_ok(|r| r.into_inner())
                    .map_err(|e| ProviderError::RetryableEndpointError("/", e.into())),
            )
            .await
    }
```

**File:** crates/aptos-rest-client/src/error.rs (L146-162)
```rust
#[derive(Debug, Error)]
pub enum RestError {
    #[error("API error {0}")]
    Api(AptosErrorResponse),
    #[error("BCS ser/de error {0}")]
    Bcs(bcs::Error),
    #[error("JSON er/de error {0}")]
    Json(serde_json::Error),
    #[error("URL Parse error {0}")]
    UrlParse(url::ParseError),
    #[error("Timeout waiting for transaction {0}")]
    Timeout(&'static str),
    #[error("Unknown error {0}")]
    Unknown(anyhow::Error),
    #[error("HTTP error {0}: {1}")]
    Http(StatusCode, reqwest::Error),
}
```

**File:** ecosystem/node-checker/src/provider/traits.rs (L28-38)
```rust
#[derive(Error, Debug)]
pub enum ProviderError {
    #[error("Something went wrong hitting endpoint {0}: {1:#}")]
    RetryableEndpointError(&'static str, #[source] anyhow::Error),

    #[error("Something went wrong hitting endpoint {0}: {1:#}")]
    NonRetryableEndpointError(&'static str, #[source] anyhow::Error),

    #[error("Something went wrong parsing the response from the node: {0:#}")]
    ParseError(#[from] anyhow::Error),
}
```

**File:** ecosystem/node-checker/src/runner/sync_runner.rs (L192-207)
```rust
                    if num_attempts < self.config.num_retries {
                        num_attempts += 1;
                        warn!(
                            "Checker failed with a retryable error: {:#}. Retrying in {} seconds.",
                            err, self.config.retry_delay_secs
                        );
                        tokio::time::sleep(Duration::from_secs(
                            self.config.retry_delay_secs.into(),
                        ))
                        .await;
                    } else {
                        error!(
                            "Checker failed with a retryable error too many times ({}): {:#}.",
                            self.config.num_retries, err
                        );
                        return Err(err);
```

**File:** crates/aptos-rest-client/src/client_builder.rs (L82-88)
```rust
    pub fn api_key(mut self, api_key: &str) -> Result<Self> {
        self.headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", api_key))?,
        );
        Ok(self)
    }
```
