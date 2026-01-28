Based on my thorough validation of this security claim against the Aptos Core codebase, I can confirm this is a **VALID** vulnerability. Here is my assessment:

# Audit Report

## Title
Unhandled Panic in Rosetta Account Balance API Due to Invalid Fungible Asset Address

## Summary
The Rosetta API's account balance endpoint contains a critical error handling flaw where user-supplied fungible asset addresses are parsed using `.unwrap()`, causing the server to panic instead of returning proper error responses. This creates a trivially exploitable denial-of-service vector against the Rosetta API service.

## Finding Description

The vulnerability exists in the argument preparation phase when querying fungible asset balances. The code at line 335 uses `.unwrap()` on `AccountAddress::from_str()` when processing the `fa_address` field from user input: [1](#0-0) 

The `fa_address` originates from the `Currency.metadata.fa_address` field, which is defined as an optional string with no validation: [2](#0-1) 

This field is part of the `AccountBalanceRequest.currencies` parameter, deserialized directly from JSON: [3](#0-2) 

**Attack Path:**
1. Attacker sends POST to `/account/balance` with malformed JSON: `{"currencies": [{"symbol": "X", "decimals": 8, "metadata": {"fa_address": "invalid"}}]}`
2. Request deserialization succeeds (all fields are optional strings)
3. Code reaches line 335 and attempts `AccountAddress::from_str("invalid")`
4. Parse fails, `.unwrap()` panics
5. API handler task crashes

Notably, the codebase has a proper error handling helper function that should have been used: [4](#0-3) 

The error handling infrastructure exists and would properly convert parse errors to `ApiError::InvalidInput`: [5](#0-4) 

## Impact Explanation

This qualifies as **HIGH Severity** under the Aptos Bug Bounty framework's "API Crashes" category. The impact includes:

- **Service Disruption**: Repeated malicious requests can continuously crash Rosetta API handlers
- **Availability Loss**: Applications depending on Rosetta API for balance queries experience failures
- **Resource Exhaustion**: Crash-and-restart cycles consume system resources

While this does NOT affect core blockchain consensus, validator operations, or block production, the framework explicitly categorizes "API Crashes" affecting REST API availability as HIGH severity impacts.

## Likelihood Explanation

**Likelihood: HIGH**

- **Exploitability**: Trivial - requires only a single malformed HTTP POST request
- **Privilege Required**: None - endpoint is publicly accessible without authentication
- **Attack Complexity**: Minimal - standard HTTP client with JSON payload
- **Detection Difficulty**: Moderate - panics are logged but may be dismissed as client errors

Any attacker with network access can repeatedly crash the Rosetta API service with minimal effort and zero cost.

## Recommendation

Replace the vulnerable `.unwrap()` calls with proper error handling using the existing `str_to_account_address()` helper or equivalent error propagation:

```rust
vec![
    bcs::to_bytes(&owner_address)?,
    bcs::to_bytes(
        &AccountAddress::from_str(fa_address)
            .map_err(|_| ApiError::InvalidInput(Some("Invalid fungible asset address".to_string())))?
    )?,
]
```

Alternatively, validate the `fa_address` field during request deserialization before it reaches the processing logic.

## Proof of Concept

```bash
curl -X POST http://localhost:8080/account/balance \
  -H "Content-Type: application/json" \
  -d '{
    "network_identifier": {"blockchain": "aptos", "network": "mainnet"},
    "account_identifier": {"address": "0x1"},
    "currencies": [{
      "symbol": "FAKE",
      "decimals": 8,
      "metadata": {"fa_address": "invalid_address_format"}
    }]
  }'
```

This request will cause the Rosetta API server to panic with an `AccountAddressParseError` at the `.unwrap()` call.

## Notes

- The report correctly identifies that Move VM errors ARE properly handled through the error chain
- The vulnerability occurs BEFORE the Move function is called, in the argument preparation phase
- The Rosetta API is an auxiliary service, but API crashes are explicitly in-scope per the bug bounty framework
- A proper fix should use the existing `ApiError` infrastructure rather than panicking on invalid input

### Citations

**File:** crates/aptos-rosetta/src/account.rs (L333-336)
```rust
                    vec![
                        bcs::to_bytes(&owner_address).unwrap(),
                        bcs::to_bytes(&AccountAddress::from_str(fa_address).unwrap()).unwrap(),
                    ],
```

**File:** crates/aptos-rosetta/src/types/objects.rs (L177-185)
```rust
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct CurrencyMetadata {
    /// Move coin type e.g. 0x1::aptos_coin::AptosCoin
    #[serde(skip_serializing_if = "Option::is_none")]
    pub move_type: Option<String>,
    /// Fungible Asset Address e.g. 0xA
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fa_address: Option<String>,
}
```

**File:** crates/aptos-rosetta/src/types/requests.rs (L23-38)
```rust
/// Request for an account's currency balance either now, or historically
///
/// [API Spec](https://www.rosetta-api.org/docs/models/AccountBalanceRequest.html)
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AccountBalanceRequest {
    /// Network identifier describing the blockchain and the chain id
    pub network_identifier: NetworkIdentifier,
    /// Account identifier describing the account address
    pub account_identifier: AccountIdentifier,
    /// For historical balance lookups by either hash or version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_identifier: Option<PartialBlockIdentifier>,
    /// For filtering which currencies to show
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currencies: Option<Vec<Currency>>,
}
```

**File:** crates/aptos-rosetta/src/types/identifiers.rs (L218-222)
```rust
/// Converts a string to an account address with error handling
fn str_to_account_address(address: &str) -> Result<AccountAddress, ApiError> {
    AccountAddress::from_str(address)
        .map_err(|_| ApiError::InvalidInput(Some("Invalid account address".to_string())))
}
```

**File:** crates/aptos-rosetta/src/error.rs (L50-50)
```rust
    InvalidInput(Option<String>),
```
