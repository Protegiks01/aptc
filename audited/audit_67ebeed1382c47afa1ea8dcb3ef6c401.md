# Audit Report

## Title
ChainId Validation Panic in Node Health Checker Allows Denial of Service Against Monitoring Tools

## Summary
The Node Health Checker (NHC) and several other client tools call `ChainId::new()` on untrusted API responses without validating that `chain_id != 0`. Since `ChainId::new()` uses `assert!(id > 0)`, a malicious node returning `chain_id: 0` causes a panic and crashes the checking tool.

## Finding Description

The `ChainId::new()` constructor enforces a strict invariant that chain ID must be non-zero [1](#0-0) , as chain ID 0 is reserved for accidental initialization [2](#0-1) .

However, the TPS checker in the Node Health Checker directly calls `ChainId::new(response.chain_id)` on the API response without validation [3](#0-2) . If a malicious or misconfigured target node returns `chain_id: 0` in its `IndexResponse` [4](#0-3) , the assertion fails and causes a panic.

**Attack Flow:**
1. Attacker runs a malicious node configured to return `{"chain_id": 0, ...}` in API responses
2. Node Health Checker queries the malicious node's index endpoint
3. API response is parsed into `IndexResponse` with `chain_id: 0`
4. `ChainId::new(0)` is called, triggering the assertion
5. Node Health Checker panics and crashes for that check

This same vulnerability exists in multiple locations:
- Transaction emitter cluster initialization [5](#0-4) 
- API tester [6](#0-5) 
- Telemetry service validator cache [7](#0-6) 
- Aptos CLI utilities [8](#0-7) 

## Impact Explanation

This is a **Low severity** issue per the Aptos bug bounty program classification for "Non-critical implementation bugs". The impact is limited to:

- **Denial of Service against monitoring tools**: A malicious node can crash the Node Health Checker
- **Denial of Service against client tooling**: Transaction emitters, CLI tools, and telemetry services can be crashed
- **No consensus impact**: Does not affect validator operation or blockchain consensus
- **No funds at risk**: Does not enable theft, minting, or freezing of funds
- **No blockchain availability impact**: Only affects off-chain monitoring and client tools

## Likelihood Explanation

**High likelihood** for this specific attack scenario:
- Trivial to exploit - attacker just needs to configure their node to return invalid data
- No authentication required - any node being monitored can be malicious
- No special privileges needed - works against public monitoring infrastructure
- Attack is undetectable until the crash occurs

## Recommendation

Replace panic-inducing `ChainId::new()` with validated construction when handling untrusted API responses:

```rust
// In ecosystem/node-checker/src/checker/tps.rs
let chain_id = match target_api_index_provider.provide().await {
    Ok(response) => {
        if response.chain_id == 0 {
            return Ok(vec![Self::build_result(
                "Invalid chain ID from your node".to_string(),
                0,
                "Your node returned chain_id 0, which is invalid. This may indicate a misconfiguration.".to_string(),
            )]);
        }
        ChainId::new(response.chain_id)
    },
    Err(err) => { /* existing error handling */ },
};
```

Apply similar validation to all other locations calling `ChainId::new()` on untrusted input.

Alternatively, introduce a `ChainId::try_new(id: u8) -> Result<ChainId>` method that returns an error instead of panicking, following the pattern used in `ChainId::from_str()` [9](#0-8) .

## Proof of Concept

```rust
// PoC: Malicious node returns chain_id: 0
use aptos_api_types::IndexResponse;
use aptos_sdk::types::chain_id::ChainId;

#[test]
#[should_panic(expected = "cannot have chain ID with 0")]
fn test_chain_id_zero_panic() {
    // Simulate API response from malicious node
    let malicious_response = IndexResponse {
        chain_id: 0,  // Invalid value
        epoch: 1.into(),
        ledger_version: 100.into(),
        oldest_ledger_version: 0.into(),
        ledger_timestamp: 1000.into(),
        node_role: aptos_config::config::RoleType::FullNode,
        oldest_block_height: 0.into(),
        block_height: 10.into(),
        git_hash: None,
    };
    
    // This panics - demonstrating the vulnerability
    let _ = ChainId::new(malicious_response.chain_id);
}
```

## Notes

While the vulnerability is real and exploitable, it only affects client-side monitoring and tooling infrastructure. The Aptos blockchain consensus, validator operations, and fund security remain unaffected. This represents a minor availability issue for operational tooling rather than a critical security vulnerability.

### Citations

**File:** types/src/chain_id.rs (L14-15)
```rust
    /// Users might accidentally initialize the ChainId field to 0, hence reserving ChainId 0 for accidental
    /// initialization.
```

**File:** types/src/chain_id.rs (L169-179)
```rust
impl FromStr for ChainId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        ensure!(!s.is_empty(), "Cannot create chain ID from empty string");
        NamedChain::str_to_chain_id(s).or_else(|_err| {
            let value = s.parse::<u8>()?;
            ensure!(value > 0, "cannot have chain ID with 0");
            Ok(ChainId::new(value))
        })
    }
```

**File:** types/src/chain_id.rs (L183-186)
```rust
    pub fn new(id: u8) -> Self {
        assert!(id > 0, "cannot have chain ID with 0");
        Self(id)
    }
```

**File:** ecosystem/node-checker/src/checker/tps.rs (L119-120)
```rust
        let chain_id = match target_api_index_provider.provide().await {
            Ok(response) => ChainId::new(response.chain_id),
```

**File:** api/types/src/index.rs (L14-18)
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, PoemObject, Serialize)]
pub struct IndexResponse {
    /// Chain ID of the current chain
    pub chain_id: u8,
    pub epoch: U64,
```

**File:** crates/transaction-emitter-lib/src/cluster.rs (L245-245)
```rust
    Ok(ChainId::new(max_chain_id))
```

**File:** crates/aptos-api-tester/src/tokenv1_client.rs (L28-28)
```rust
    Ok(ChainId::new(id))
```

**File:** crates/aptos-telemetry-service/src/validator_cache.rs (L102-102)
```rust
        let chain_id = ChainId::new(state.chain_id);
```

**File:** crates/aptos/src/common/utils.rs (L319-319)
```rust
    Ok(ChainId::new(state.chain_id))
```
