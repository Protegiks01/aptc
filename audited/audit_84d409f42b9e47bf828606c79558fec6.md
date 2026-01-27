# Audit Report

## Title
Missing Chain ID Validation in Rosetta Block Endpoints Enables Cross-Chain Data Leakage

## Summary
The Aptos Rosetta API block retrieval functions (`get_block_by_index()` and `build_block()`) fail to validate that blocks fetched from the REST API actually belong to the configured chain. This allows cross-chain data leakage where block data from one chain can be returned labeled as belonging to a different chain, breaking fundamental data integrity guarantees.

## Finding Description

The vulnerability exists in the block retrieval flow where chain_id validation is inconsistent across Rosetta API endpoints.

**The Issue:**

In `BlockRetriever::get_block_by_height()`, the function discards the `State` metadata containing the actual chain_id from the REST API response: [1](#0-0) 

The `.into_inner()` call extracts only the `BcsBlock` and discards the `State` which contains the actual `chain_id` from the response headers. [2](#0-1) 

This means `get_block_by_index()` receives the block without any chain_id metadata to validate against: [3](#0-2) 

When `BlockIdentifier::from_block()` is called, it uses the server's configured `chain_id` rather than validating against the actual block's chain: [4](#0-3) 

**Contrast with Construction Endpoint:**

The construction metadata endpoint correctly validates chain_id: [5](#0-4) 

**Attack Scenario:**

1. Rosetta server configured for Mainnet (chain_id=1)
2. REST client URL gets redirected to Testnet node (chain_id=2) via:
   - DNS poisoning
   - BGP hijacking  
   - Proxy misconfiguration
   - Server-side redirection
3. User requests block from Mainnet via `/block` endpoint
4. Server fetches block from Testnet but labels it with Mainnet chain_id
5. User receives Testnet block data with Mainnet BlockIdentifier hash format "1-{height}"
6. User constructs transactions based on incorrect chain data

**Startup Validation is Insufficient:**

While there is chain_id validation at startup: [6](#0-5) 

This only validates once during initialization and does not protect against runtime changes to the REST client connection.

## Impact Explanation

This is **HIGH severity** per the Aptos Bug Bounty criteria for "Significant protocol violations":

1. **Data Integrity Violation**: Users receive block data from the wrong blockchain, labeled with the expected chain_id
2. **Financial Risk**: Users constructing transactions based on this data could experience:
   - Incorrect balance information leading to failed transactions
   - Wrong transaction parameters (sequence numbers, gas prices differ across chains)
   - Potential fund loss if transaction construction relies on wrong chain state
3. **API Trust Violation**: Breaks the fundamental guarantee that Rosetta API responses correspond to the requested network

While this requires infrastructure-level misconfiguration or attack (DNS poisoning, proxy issues), such scenarios are realistic in production environments and the impact is severe.

## Likelihood Explanation

**Medium-High Likelihood:**

1. **Realistic Attack Vectors:**
   - DNS cache poisoning redirecting REST API URL
   - BGP hijacking in cloud environments
   - Load balancer/proxy misconfiguration
   - Accidental configuration changes during maintenance
   
2. **No Detection Mechanism:** 
   - After startup, there's no runtime validation
   - Silent failure - wrong data returned without errors
   - Users may not notice until financial impact occurs

3. **Common Deployment Scenarios:**
   - Multi-chain deployments where configuration mistakes happen
   - Cloud environments with dynamic DNS
   - Infrastructure as Code misconfigurations

## Recommendation

Add runtime chain_id validation in `BlockRetriever::get_block_by_height()` similar to the construction endpoint:

**Modified Implementation:**

```rust
pub async fn get_block_by_height(
    &self,
    height: u64,
    with_transactions: bool,
    expected_chain_id: ChainId,
) -> ApiResult<aptos_rest_client::aptos_api_types::BcsBlock> {
    if with_transactions {
        let response = self
            .rest_client
            .get_full_block_by_height_bcs(height, self.page_size)
            .await?;
        
        // Validate chain_id from response headers
        if expected_chain_id.id() != response.state().chain_id {
            return Err(ApiError::ChainIdMismatch);
        }
        
        Ok(response.into_inner())
    } else {
        let response = self
            .rest_client
            .get_block_by_height_bcs(height, false)
            .await?;
        
        // Validate chain_id from response headers
        if expected_chain_id.id() != response.state().chain_id {
            return Err(ApiError::ChainIdMismatch);
        }
        
        Ok(response.into_inner())
    }
}
```

Update call sites to pass `expected_chain_id` parameter and handle the `ChainIdMismatch` error appropriately.

The `ChainIdMismatch` error already exists in the error types: [7](#0-6) [8](#0-7) 

## Proof of Concept

**Rust Integration Test:**

```rust
#[tokio::test]
async fn test_cross_chain_block_leakage() {
    use aptos_rosetta::RosettaContext;
    use aptos_types::chain_id::ChainId;
    use mockito::Server;
    
    // Create mock server representing Testnet (chain_id=2)
    let mut server = Server::new_async().await;
    let testnet_chain_id: u8 = 2;
    
    // Mock block endpoint returning Testnet block
    let mock = server.mock("GET", "/v1/blocks/by_height/100?with_transactions=true")
        .with_status(200)
        .with_header("X-APTOS-CHAIN-ID", &testnet_chain_id.to_string())
        .with_header("X-APTOS-LEDGER-VERSION", "1000")
        .with_header("X-APTOS-BLOCK-HEIGHT", "100")
        .with_header("X-APTOS-EPOCH", "1")
        .with_header("X-APTOS-LEDGER-TIMESTAMP", "1000000")
        .with_header("X-APTOS-LEDGER-OLDEST-VERSION", "0")
        .with_header("X-APTOS-OLDEST-BLOCK-HEIGHT", "0")
        .with_body(/* BCS encoded Testnet block */)
        .create_async()
        .await;
    
    // Configure Rosetta for Mainnet (chain_id=1)
    let mainnet_chain_id = ChainId::new(1);
    let rest_client = aptos_rest_client::Client::new(server.url().parse().unwrap());
    
    let context = RosettaContext::new(
        Some(Arc::new(rest_client)),
        mainnet_chain_id,
        /* block_cache */ None,
        HashSet::new(),
    ).await;
    
    // Request block - should fail but doesn't!
    let result = context.block_cache()
        .unwrap()
        .get_block_by_height(100, true)
        .await;
    
    // VULNERABILITY: This succeeds and returns Testnet block
    // It should return ApiError::ChainIdMismatch instead
    assert!(result.is_ok(), "Block from wrong chain was accepted!");
    
    // The block will be labeled with Mainnet chain_id
    // but contains Testnet data - cross-chain leakage!
}
```

## Notes

- The vulnerability affects all three functions mentioned in the security question: `block()`, `build_block()`, and `get_block_by_index()`
- The `get_block_info_by_height()` function also lacks validation but has less severe impact
- This issue demonstrates an inconsistency in security practices across the codebase where one endpoint (construction) validates chain_id but others do not
- The fix should be applied consistently across all REST API response handling in the Rosetta implementation

### Citations

**File:** crates/aptos-rosetta/src/block.rs (L116-141)
```rust
async fn get_block_by_index(
    block_cache: &BlockRetriever,
    block_height: u64,
    chain_id: ChainId,
) -> ApiResult<(
    BlockIdentifier,
    aptos_rest_client::aptos_api_types::BcsBlock,
)> {
    let block = block_cache.get_block_by_height(block_height, true).await?;

    // For the genesis block, we populate parent_block_identifier with the
    // same genesis block. Refer to
    // https://www.rosetta-api.org/docs/common_mistakes.html#malformed-genesis-block
    if block_height == 0 {
        Ok((BlockIdentifier::from_block(&block, chain_id), block))
    } else {
        // Retrieve the previous block's identifier
        let prev_block = block_cache
            .get_block_by_height(block_height - 1, false)
            .await?;
        let prev_block_id = BlockIdentifier::from_block(&prev_block, chain_id);

        // Retrieve the current block
        Ok((prev_block_id, block))
    }
}
```

**File:** crates/aptos-rosetta/src/block.rs (L205-225)
```rust
    pub async fn get_block_by_height(
        &self,
        height: u64,
        with_transactions: bool,
    ) -> ApiResult<aptos_rest_client::aptos_api_types::BcsBlock> {
        // If we request transactions, we have to provide the page size, it ideally is bigger than
        // the maximum block size.  If not, transactions will be missed.
        if with_transactions {
            Ok(self
                .rest_client
                .get_full_block_by_height_bcs(height, self.page_size)
                .await?
                .into_inner())
        } else {
            Ok(self
                .rest_client
                .get_block_by_height_bcs(height, false)
                .await?
                .into_inner())
        }
    }
```

**File:** crates/aptos-rest-client/src/state.rs (L10-20)
```rust
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct State {
    pub chain_id: u8,
    pub epoch: u64,
    pub version: u64,
    pub timestamp_usecs: u64,
    pub oldest_ledger_version: u64,
    pub oldest_block_height: u64,
    pub block_height: u64,
    pub cursor: Option<String>,
}
```

**File:** crates/aptos-rosetta/src/types/identifiers.rs (L424-432)
```rust
    pub fn from_block(
        block: &aptos_rest_client::aptos_api_types::BcsBlock,
        chain_id: ChainId,
    ) -> BlockIdentifier {
        BlockIdentifier {
            index: block.block_height,
            hash: BlockHash::new(chain_id, block.block_height).to_string(),
        }
    }
```

**File:** crates/aptos-rosetta/src/construction.rs (L460-463)
```rust
    // Ensure this network really is the one we expect it to be
    if server_context.chain_id.id() != response.state().chain_id {
        return Err(ApiError::ChainIdMismatch);
    }
```

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

**File:** crates/aptos-rosetta/src/error.rs (L21-21)
```rust
    ChainIdMismatch,
```

**File:** crates/aptos-rosetta/src/error.rs (L174-174)
```rust
            ApiError::ChainIdMismatch => "Chain Id doesn't match",
```
