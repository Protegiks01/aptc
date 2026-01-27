# Audit Report

## Title
Rosetta Server Panic on Malformed Chain ID in REST API Response Headers

## Summary
The `bootstrap_async()` function in the Aptos Rosetta server crashes with a panic when the upstream REST API returns a malformed `chain_id` value in HTTP response headers. An attacker controlling the REST API endpoint or performing a man-in-the-middle attack can cause denial of service by sending chain_id values that fail to parse as a valid `u8`.

## Finding Description

The vulnerability exists in the initialization flow of the Rosetta API server. During bootstrap, the server validates that the configured chain ID matches the chain ID reported by the upstream REST API endpoint. [1](#0-0) 

The code calls `get_ledger_information()` with `.expect()`, which panics if the call returns an error. This call internally retrieves HTTP response headers and parses the chain_id as follows: [2](#0-1) 

The `parse()` method attempts to convert the header string to a `u8`. If the header contains malformed values such as:
- Non-numeric strings ("abc", "invalid")
- Numbers exceeding u8 range ("256", "999", "1000")
- Negative numbers ("-1")
- Empty strings ("")

The parse fails, returning `None`, which causes `State::from_headers()` to return an error: [3](#0-2) 

This error propagates through the call chain and triggers the panic via `.expect()` in `bootstrap_async()`.

**Attack Path:**
1. Attacker controls or compromises the REST API endpoint configured for the Rosetta server
2. Attacker configures malicious HTTP responses with malformed `X-Aptos-Chain-Id` headers (e.g., "abc", "999")
3. Rosetta server attempts to start and calls `bootstrap_async()`
4. Server panics during initialization, causing complete denial of service
5. Rosetta API remains unavailable until configuration is fixed

## Impact Explanation

This is a **Medium severity** denial of service vulnerability that prevents the Rosetta API server from starting. While it doesn't affect core blockchain consensus or validator operations, it does qualify as an "API crash" which falls under High severity in the Aptos bug bounty program. However, given the limited scope (only affects Rosetta service, not core blockchain) and the requirement for attacker to control the upstream REST API, Medium severity is appropriate.

The impact is limited to availability of the Rosetta API service, which is a separate interface layer and not critical to blockchain operation. However, for users relying on Rosetta API for blockchain interaction, this represents a complete service outage.

## Likelihood Explanation

The likelihood is **Medium** because it requires the attacker to:
1. Control or compromise the REST API endpoint that the Rosetta server connects to, OR
2. Perform a successful man-in-the-middle attack to modify HTTP headers

While these prerequisites are non-trivial, they are realistic attack scenarios:
- Misconfigured Rosetta servers pointing to untrusted REST APIs
- Compromised REST API servers  
- Network-level MITM attacks in insecure environments

The exploit itself is trivial once the attacker has the required position - simply return malformed headers in HTTP responses.

## Recommendation

Replace `.expect()` with proper error handling that logs the error and gracefully fails instead of panicking:

```rust
if let Some(ref client) = rest_client {
    let ledger_info = client
        .get_ledger_information()
        .await
        .context("Failed to get ledger information from Rest API during bootstrap")?;
    
    let upstream_chain_id = ledger_info.into_inner().chain_id;
    
    if chain_id.id() != upstream_chain_id {
        anyhow::bail!(
            "Chain ID mismatch: configured={}, upstream={}",
            chain_id.id(),
            upstream_chain_id
        );
    }
}
```

This change:
- Returns a proper error instead of panicking
- Provides clear error messages for troubleshooting
- Allows the runtime to handle the error gracefully
- Maintains the validation logic while improving error handling

## Proof of Concept

```rust
#[tokio::test]
async fn test_malformed_chain_id_causes_panic() {
    use mockito::Server;
    use aptos_types::chain_id::ChainId;
    use aptos_config::config::ApiConfig;
    use std::collections::HashSet;

    // Create a mock server
    let mut server = Server::new_async().await;
    
    // Mock the REST API endpoint with malformed chain_id header
    let _mock = server.mock("GET", "/")
        .with_status(200)
        .with_header("X-Aptos-Chain-Id", "malformed_string") // Invalid u8
        .with_header("X-Aptos-Ledger-Version", "1")
        .with_header("X-Aptos-Ledger-Timestamp", "1000000")
        .with_header("X-Aptos-Epoch", "1")
        .with_header("X-Aptos-Ledger-Oldest-Version", "0")
        .with_header("X-Aptos-Block-Height", "1")
        .with_header("X-Aptos-Oldest-Block-Height", "0")
        .with_header("Content-Type", "application/x.aptos.signed_transaction+bcs")
        .with_body(vec![]) // Empty BCS body
        .create_async()
        .await;

    // Create REST client pointing to mock server
    let rest_client = aptos_rest_client::Client::new(
        url::Url::parse(&server.url()).unwrap()
    );

    let chain_id = ChainId::new(1);
    let api_config = ApiConfig::default();
    
    // This should panic due to malformed chain_id
    let result = bootstrap_async(
        chain_id,
        api_config,
        Some(rest_client),
        HashSet::new()
    ).await;
    
    // The function panics before returning, so we never reach here
    // In a real scenario, this would crash the server
    assert!(result.is_err());
}
```

## Notes

This vulnerability specifically affects the Rosetta API service layer, not the core Aptos blockchain. The Rosetta API is an optional interface that provides standardized blockchain access following the Rosetta specification. While critical for users relying on this API, it does not impact consensus, validator operations, or core blockchain security. The root cause is improper error handling during initialization when validating chain ID consistency between the configured value and the upstream REST API response.

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
