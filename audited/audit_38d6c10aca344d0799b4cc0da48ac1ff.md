# Audit Report

## Title
Rosetta API Server Panic on Malformed Chain ID Header During Bootstrap

## Summary
The Aptos Rosetta API server performs an unchecked parse of the `X-APTOS-CHAIN-ID` HTTP header from the upstream REST API during bootstrap. If the upstream node returns a malformed or unparseable chain ID string, the server panics and crashes, causing a denial of service.

## Finding Description

During Rosetta server initialization in `bootstrap_async()`, the code retrieves ledger information from the configured upstream REST API endpoint and validates that the chain ID matches the expected value. However, the error handling uses `.expect()` which panics on any error, including parsing failures. [1](#0-0) 

The execution flow is as follows:

1. `bootstrap_async()` calls `client.get_ledger_information().await.expect(...)`
2. This invokes `get_index_bcs()` which makes an HTTP request to the root endpoint with BCS accept header
3. The response goes through `check_and_parse_bcs_response()` → `check_response()` → `parse_state()`
4. `parse_state()` calls `State::from_headers()` which attempts to parse HTTP headers including `X-APTOS-CHAIN-ID` [2](#0-1) 

The header parsing attempts to convert the string header value to a `u8`: [3](#0-2) 

If parsing fails (e.g., header contains "abc", "999", "-1", "", or any non-numeric string), `maybe_chain_id` becomes `None`. The function then fails with `anyhow::bail!()`: [4](#0-3) 

This error propagates back through the call chain and reaches the `.expect()` in `bootstrap_async()`, causing a panic that crashes the entire Rosetta server process.

**Attack Scenario:**
1. Attacker compromises or performs MITM attack on the upstream REST API node
2. Malicious node returns response with malformed `X-APTOS-CHAIN-ID` header (e.g., "invalid", "256", "-1")
3. Rosetta server attempts to parse the header during bootstrap
4. Parsing fails, error returned
5. `.expect()` panics with message "Should successfully get ledger information from Rest API on bootstap"
6. Rosetta server process terminates

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty criteria because it causes "API crashes". While this vulnerability doesn't affect blockchain consensus or validator operations, it prevents the Rosetta API service from starting, which impacts:

- Exchange integrations relying on Rosetta API
- Block explorers and analytics services
- Any external systems depending on Rosetta for blockchain data access

The crash occurs during bootstrap, making the service completely unavailable until the upstream node is fixed or reconfigured.

## Likelihood Explanation

The likelihood is **Medium-to-High** because:

**Prerequisites:**
- Attacker must compromise or MITM the configured upstream REST API endpoint
- Or the upstream node itself has a bug that produces malformed headers

**Feasibility:**
- Configuration errors or bugs in custom REST API implementations could trigger this accidentally
- Intentional attacks require network-level access or control over the upstream node
- No authentication or authorization bypass needed - just malformed response data

**Persistence:**
- The panic occurs at startup, so service remains down until configuration is changed
- Operators may not immediately identify the root cause from panic message alone

## Recommendation

Replace the `.expect()` call with proper error handling that logs the error and returns it gracefully, allowing the caller to handle startup failures without panicking:

```rust
pub async fn bootstrap_async(
    chain_id: ChainId,
    api_config: ApiConfig,
    rest_client: Option<aptos_rest_client::Client>,
    supported_currencies: HashSet<Currency>,
) -> anyhow::Result<JoinHandle<()>> {
    debug!("Starting up Rosetta server with {:?}", api_config);

    if let Some(ref client) = rest_client {
        let ledger_info = client
            .get_ledger_information()
            .await
            .context("Failed to get ledger information from Rest API on bootstrap")?;
        
        let upstream_chain_id = ledger_info.into_inner().chain_id;
        
        if chain_id.id() != upstream_chain_id {
            anyhow::bail!(
                "Chain ID mismatch: expected {}, got {} from upstream server",
                chain_id.id(),
                upstream_chain_id
            );
        }
    }
    
    // ... rest of function
}
```

Additionally, consider adding validation in `State::from_headers()` to provide more specific error messages when parsing fails:

```rust
let maybe_chain_id = headers
    .get(X_APTOS_CHAIN_ID)
    .and_then(|h| h.to_str().ok())
    .and_then(|s| s.parse::<u8>().map_err(|e| {
        eprintln!("Failed to parse chain_id header '{}': {}", s, e);
        e
    }).ok());
```

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use aptos_api_types::X_APTOS_CHAIN_ID;
    use reqwest::header::HeaderMap;
    
    #[test]
    fn test_malformed_chain_id_parsing() {
        let mut headers = HeaderMap::new();
        
        // Test various malformed chain ID values
        let malformed_values = vec![
            "abc",           // Non-numeric
            "999",           // Out of u8 range
            "-1",            // Negative
            "",              // Empty
            "1.5",           // Decimal
            "0xFF",          // Hex format
            "chain_id_123",  // Text with numbers
        ];
        
        for malformed in malformed_values {
            headers.insert(X_APTOS_CHAIN_ID, malformed.parse().unwrap());
            headers.insert("x-aptos-ledger-version", "1000".parse().unwrap());
            headers.insert("x-aptos-ledger-timestamp", "1000000".parse().unwrap());
            headers.insert("x-aptos-epoch", "1".parse().unwrap());
            headers.insert("x-aptos-ledger-oldest-version", "0".parse().unwrap());
            headers.insert("x-aptos-block-height", "100".parse().unwrap());
            headers.insert("x-aptos-oldest-block-height", "0".parse().unwrap());
            
            let result = State::from_headers(&headers);
            assert!(
                result.is_err(),
                "Should fail to parse malformed chain_id: {}",
                malformed
            );
        }
    }
}
```

To trigger the actual panic in integration testing, mock an HTTP server that returns malformed headers and configure the Rosetta server to use it during bootstrap.

## Notes

This vulnerability demonstrates a broader pattern where the Aptos Rosetta implementation trusts upstream REST API responses without defensive validation. While the REST API is typically a trusted component, defense-in-depth principles suggest that API bridges should handle malformed responses gracefully rather than panicking, especially during critical startup phases.

The panic occurs specifically because HTTP headers (which are strings) must be parsed, creating a trust boundary that isn't properly validated. The BCS response body itself uses binary deserialization which has its own error handling, but the HTTP header parsing introduces a separate failure mode.

### Citations

**File:** crates/aptos-rosetta/src/lib.rs (L125-136)
```rust
    if let Some(ref client) = rest_client {
        assert_eq!(
            chain_id.id(),
            client
                .get_ledger_information()
                .await
                .expect("Should successfully get ledger information from Rest API on bootstap")
                .into_inner()
                .chain_id,
            "Failed to match Rosetta chain Id to upstream server"
        );
    }
```

**File:** crates/aptos-rest-client/src/lib.rs (L1976-1978)
```rust
fn parse_state(response: &reqwest::Response) -> AptosResult<State> {
    Ok(State::from_headers(response.headers())?)
}
```

**File:** crates/aptos-rest-client/src/state.rs (L24-27)
```rust
        let maybe_chain_id = headers
            .get(X_APTOS_CHAIN_ID)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
```

**File:** crates/aptos-rest-client/src/state.rs (L87-98)
```rust
            anyhow::bail!(
                "Failed to build State from headers due to missing values in response. \
                Chain ID: {:?}, Version: {:?}, Timestamp: {:?}, Epoch: {:?}, \
                Oldest Ledger Version: {:?}, Block Height: {:?} Oldest Block Height: {:?}",
                maybe_chain_id,
                maybe_version,
                maybe_timestamp,
                maybe_epoch,
                maybe_oldest_ledger_version,
                maybe_block_height,
                maybe_oldest_block_height,
            )
```
