# Audit Report

## Title
Missing Request Size Validation in Aptos Rosetta Client and Server Leading to Memory Exhaustion DoS

## Summary
The Aptos Rosetta API implementation lacks request size validation on both the client side (during JSON serialization) and server side (during request processing). This allows attackers to craft requests with arbitrarily large vectors of operations, signatures, or other data structures, causing memory exhaustion and denial of service.

## Finding Description

The vulnerability exists in two locations:

**Client-Side Issue:**
The `RosettaClient::make_call()` function serializes requests without any size validation before calling `serde_json::to_string()`. [1](#0-0) 

Multiple request types accept unbounded vectors that an attacker can populate with arbitrary data:
- `ConstructionCombineRequest` contains `signatures: Vec<Signature>` [2](#0-1) 
- `ConstructionPayloadsRequest` contains `operations: Vec<Operation>` and `public_keys: Option<Vec<PublicKey>>` [3](#0-2) 
- `ConstructionPreprocessRequest` contains `operations: Vec<Operation>` [4](#0-3) 

**Server-Side Issue:**
All Rosetta server routes use `warp::body::json()` without explicit content length limits. For example: [5](#0-4) 

The server's route configuration applies CORS, logging, and error recovery middleware, but notably lacks any size limit middleware: [6](#0-5) 

In contrast, the main Aptos API applies `PostSizeLimit` middleware with an 8MB default limit: [7](#0-6)  and [8](#0-7) 

The default content length limit is defined as 8MB: [9](#0-8) 

**Attack Scenario:**
1. Attacker crafts a `ConstructionCombineRequest` with 100,000 fake `Signature` objects
2. Each signature's `hex_bytes` field contains 128 characters (minimal Ed25519 signature)
3. Client calls `make_call()`, which allocates ~50MB+ for JSON serialization
4. Request is sent to Rosetta server
5. Server's `warp::body::json()` reads entire body into memory without size checks
6. Multiple concurrent requests cause OOM on both client and server

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program, specifically under "API crashes". The Rosetta API can be forced to crash through memory exhaustion, affecting:

1. **Block explorers and integrations** that depend on Rosetta for transaction construction
2. **Validator infrastructure** if they run Rosetta servers for operational tooling
3. **Service availability** for any downstream services

While not directly impacting consensus (as Rosetta is not part of the consensus protocol), the Rosetta API is an official Aptos component that requires protection. The vulnerability breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits."

## Likelihood Explanation

**Likelihood: High**

The attack requires no special privileges:
- Any network client can send HTTP POST requests to the Rosetta server
- Request construction is trivial (populate vectors with arbitrary data)
- Rosetta servers are typically publicly accessible for blockchain integration
- No authentication or rate limiting is enforced at the request size level
- The vulnerability is deterministic and reliable

## Recommendation

**Client-Side Fix:**
Add a size check before serialization in `make_call()`:

```rust
async fn make_call<'a, I: Serialize + Debug, O: DeserializeOwned>(
    &'a self,
    path: &'static str,
    request: &'a I,
) -> anyhow::Result<O> {
    let body = serde_json::to_string(request)?;
    
    // Validate request size (use 8MB limit consistent with main API)
    const MAX_REQUEST_SIZE: usize = 8 * 1024 * 1024;
    if body.len() > MAX_REQUEST_SIZE {
        return Err(anyhow!("Request body exceeds maximum size of {} bytes", MAX_REQUEST_SIZE));
    }
    
    let response = self
        .inner
        .post(self.address.join(path)?)
        .header(CONTENT_TYPE, JSON)
        .body(body)
        .send()
        .await?;
    // ... rest of function
}
```

**Server-Side Fix:**
Apply content length limit middleware to all routes. Modify `routes()` function to use warp's built-in size limiting:

```rust
pub fn routes(
    context: RosettaContext,
) -> impl Filter<Extract = (impl Reply,), Error = Infallible> + Clone {
    // Add content length limit to all POST routes
    const MAX_BODY_SIZE: u64 = 8 * 1024 * 1024; // 8MB
    
    account::routes(context.clone())
        .or(block::block_route(context.clone()))
        .or(construction::combine_route(context.clone()))
        // ... other routes
        .with(warp::body::content_length_limit(MAX_BODY_SIZE))
        .with(warp::cors()...)
        // ... rest of middleware
}
```

Alternatively, adapt the `PostSizeLimit` middleware used by the main API for use with warp.

## Proof of Concept

```rust
use aptos_rosetta::client::RosettaClient;
use aptos_rosetta::types::*;
use url::Url;

#[tokio::test]
async fn test_oversized_request_dos() {
    let client = RosettaClient::new(Url::parse("http://localhost:8082").unwrap());
    
    // Create malicious request with 100,000 signatures
    let mut signatures = Vec::new();
    for i in 0..100_000 {
        signatures.push(Signature {
            signing_payload: SigningPayload {
                account_identifier: AccountIdentifier::base_account(
                    AccountAddress::from_hex_literal("0x1").unwrap()
                ),
                hex_bytes: "a".repeat(128), // 128 byte hex string
                signature_type: Some(SignatureType::Ed25519),
            },
            public_key: PublicKey {
                hex_bytes: "b".repeat(64),
                curve_type: CurveType::Edwards25519,
            },
            signature_type: SignatureType::Ed25519,
            hex_bytes: "c".repeat(128),
        });
    }
    
    let request = ConstructionCombineRequest {
        network_identifier: NetworkIdentifier {
            blockchain: "aptos".to_string(),
            network: "testnet".to_string(),
        },
        unsigned_transaction: "d".repeat(1000),
        signatures,
    };
    
    // This will allocate ~50MB+ of memory for JSON serialization
    // and send it to the server, which will also allocate similar memory
    let result = client.combine(&request).await;
    
    // Expected: Should fail with size limit error
    // Actual: Succeeds in allocating massive memory, potentially causing OOM
    assert!(result.is_err());
}
```

## Notes

The vulnerability affects the Rosetta API specifically, which is separate from the core consensus infrastructure. However, as an official Aptos component used for blockchain integration and potentially run by validators for operational tooling, it requires proper resource limits. The fix should align with the 8MB default used by the main Aptos REST API to maintain consistency across the codebase.

### Citations

**File:** crates/aptos-rosetta/src/client.rs (L131-149)
```rust
    async fn make_call<'a, I: Serialize + Debug, O: DeserializeOwned>(
        &'a self,
        path: &'static str,
        request: &'a I,
    ) -> anyhow::Result<O> {
        let response = self
            .inner
            .post(self.address.join(path)?)
            .header(CONTENT_TYPE, JSON)
            .body(serde_json::to_string(request)?)
            .send()
            .await?;
        if !response.status().is_success() {
            let error: Error = response.json().await?;
            return Err(anyhow!("Failed API with: {:?}", error));
        }

        Ok(response.json().await?)
    }
```

**File:** crates/aptos-rosetta/src/types/requests.rs (L128-136)
```rust
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConstructionCombineRequest {
    /// Network identifier describing the blockchain and the chain id
    pub network_identifier: NetworkIdentifier,
    /// A hex encoded, BCS encoded, [`aptos_types::transaction::RawTransaction`]
    pub unsigned_transaction: String,
    /// Set of signatures with SigningPayloads to combine
    pub signatures: Vec<Signature>,
}
```

**File:** crates/aptos-rosetta/src/types/requests.rs (L307-319)
```rust
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConstructionPayloadsRequest {
    /// Network identifier describing the blockchain and the chain id
    pub network_identifier: NetworkIdentifier,
    /// The set of [`Operation`] that describes the [`InternalOperation`] to execute
    pub operations: Vec<Operation>,
    /// Required information for building a [`aptos_types::transaction::RawTransaction`]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ConstructionMetadata>,
    /// Public keys of those who will sign the eventual [`aptos_types::transaction::SignedTransaction`]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_keys: Option<Vec<PublicKey>>,
}
```

**File:** crates/aptos-rosetta/src/types/requests.rs (L338-346)
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ConstructionPreprocessRequest {
    /// Network identifier describing the blockchain and the chain id
    pub network_identifier: NetworkIdentifier,
    /// Operations that make up an `InternalOperation`
    pub operations: Vec<Operation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<PreprocessMetadata>,
}
```

**File:** crates/aptos-rosetta/src/construction.rs (L57-65)
```rust
pub fn combine_route(
    server_context: RosettaContext,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path!("construction" / "combine")
        .and(warp::post())
        .and(warp::body::json())
        .and(with_context(server_context))
        .and_then(handle_request(construction_combine))
}
```

**File:** crates/aptos-rosetta/src/lib.rs (L163-189)
```rust
/// Collection of all routes for the server
pub fn routes(
    context: RosettaContext,
) -> impl Filter<Extract = (impl Reply,), Error = Infallible> + Clone {
    account::routes(context.clone())
        .or(block::block_route(context.clone()))
        .or(construction::combine_route(context.clone()))
        .or(construction::derive_route(context.clone()))
        .or(construction::hash_route(context.clone()))
        .or(construction::metadata_route(context.clone()))
        .or(construction::parse_route(context.clone()))
        .or(construction::payloads_route(context.clone()))
        .or(construction::preprocess_route(context.clone()))
        .or(construction::submit_route(context.clone()))
        .or(network::list_route(context.clone()))
        .or(network::options_route(context.clone()))
        .or(network::status_route(context.clone()))
        .or(health_check_route(context))
        .with(
            warp::cors()
                .allow_any_origin()
                .allow_methods(vec![Method::GET, Method::POST])
                .allow_headers(vec![warp::http::header::CONTENT_TYPE]),
        )
        .with(logger())
        .recover(handle_rejection)
}
```

**File:** api/src/runtime.rs (L175-175)
```rust
    let size_limit = context.content_length_limit();
```

**File:** api/src/runtime.rs (L255-255)
```rust
            .with(PostSizeLimit::new(size_limit))
```

**File:** config/src/config/api_config.rs (L97-97)
```rust
const DEFAULT_REQUEST_CONTENT_LENGTH_LIMIT: u64 = 8 * 1024 * 1024; // 8 MB
```
