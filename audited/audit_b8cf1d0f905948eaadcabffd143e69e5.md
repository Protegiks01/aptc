# Audit Report

## Title
Client-Side Memory Exhaustion via Unbounded Hex String Deserialization in REST Client

## Summary
The `deserialize_from_prefixed_hex_string` function in the Aptos REST client library lacks input length validation, allowing malicious or compromised servers to cause excessive memory allocation and CPU consumption on client infrastructure by sending extremely long hex strings in API responses.

## Finding Description
The vulnerability exists in the deserialization flow when clients parse account data from REST API responses. [1](#0-0) 

The function deserializes arbitrary-length strings without validation, then attempts to parse them as `AuthenticationKey` objects. During this process:

1. The full string is allocated in memory without length checks [2](#0-1) 

2. The string is passed to `AuthenticationKey::from_str()` which calls `hex::decode()` on the entire input [3](#0-2) 

3. Only after decoding the entire hex string does validation occur, checking that the result is exactly 32 bytes [4](#0-3) 

A malicious server can send responses with authentication keys containing millions of characters (e.g., `"0x" + 100MB of hex digits`), causing:
- **Memory allocation**: ~150MB per request (100MB string + 50MB decoded bytes)
- **CPU consumption**: Processing millions of characters through hex decoding
- **Resource exhaustion**: Multiple concurrent requests amplify the attack

This affects client infrastructure components that use the REST client library, including:
- Node-checker services (validator monitoring) [5](#0-4) 
- Telemetry services [6](#0-5) 
- CLI tools and transaction emitters

## Impact Explanation
**Classification: Does Not Meet Bounty Severity Threshold**

While this is a legitimate security vulnerability, it **does not meet the Aptos bug bounty severity criteria** because:

1. **Client-side impact only**: The vulnerability affects REST client infrastructure, not blockchain validator nodes or consensus participants
2. **No blockchain impact**: Does not affect consensus safety, transaction execution, state consistency, or fund security
3. **Infrastructure disruption**: Can cause DoS on monitoring/tooling infrastructure, but not on the blockchain network itself
4. **Out of scope**: Network-level DoS attacks are explicitly excluded from the bug bounty program

The server-side REST API properly validates and returns only legitimate 32-byte authentication keys. [7](#0-6) 

## Likelihood Explanation
**Low to Medium Likelihood**

Attack requires:
- Attacker to operate a malicious Aptos node OR compromise a legitimate node's REST API
- Client infrastructure to connect to this malicious endpoint
- Sustained attack to cause meaningful disruption given modern server memory capacity

Most production deployments connect to trusted node endpoints, reducing practical exploitability.

## Recommendation
Add length validation before hex decoding:

```rust
pub fn deserialize_from_prefixed_hex_string<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    <T as FromStr>::Err: std::fmt::Display,
{
    use serde::de::Error;
    
    const MAX_HEX_STRING_LENGTH: usize = 1024; // Reasonable limit
    
    let s = <String>::deserialize(deserializer)?;
    
    if s.len() > MAX_HEX_STRING_LENGTH {
        return Err(D::Error::custom(format!(
            "Hex string too long: {} characters (max: {})",
            s.len(), MAX_HEX_STRING_LENGTH
        )));
    }
    
    s.trim_start_matches("0x")
        .parse::<T>()
        .map_err(D::Error::custom)
}
```

## Proof of Concept
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use aptos_types::transaction::authenticator::AuthenticationKey;
    
    #[test]
    fn test_oversized_hex_string_memory_consumption() {
        // Create a JSON with 10MB hex string for authentication_key
        let malicious_json = format!(
            r#"{{"sequence_number":"0","authentication_key":"0x{}"}}"#,
            "a".repeat(10_000_000)
        );
        
        // Attempt to deserialize - will allocate ~15MB before failing
        let result: Result<Account, _> = serde_json::from_str(&malicious_json);
        
        // Should fail with WrongLengthError, but only after allocating memory
        assert!(result.is_err());
        
        // In a real attack, multiple concurrent requests could exhaust memory
    }
}
```

## Notes
This vulnerability represents a **client-side resource exhaustion issue** rather than a blockchain protocol vulnerability. While it should be fixed to harden infrastructure tools, it does not pose a direct threat to the Aptos blockchain's security guarantees around consensus, state integrity, or fund safety. The vulnerability exists in client deserialization code and requires clients to connect to malicious servers, placing it outside the core blockchain threat model focused on validator and consensus security.

### Citations

**File:** crates/aptos-rest-client/src/types.rs (L18-30)
```rust
pub fn deserialize_from_prefixed_hex_string<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    <T as FromStr>::Err: std::fmt::Display,
{
    use serde::de::Error;

    let s = <String>::deserialize(deserializer)?;
    s.trim_start_matches("0x")
        .parse::<T>()
        .map_err(D::Error::custom)
}
```

**File:** types/src/transaction/authenticator.rs (L974-981)
```rust
    fn try_from(bytes: &[u8]) -> std::result::Result<AuthenticationKey, CryptoMaterialError> {
        if bytes.len() != Self::LENGTH {
            return Err(CryptoMaterialError::WrongLengthError);
        }
        let mut addr = [0u8; Self::LENGTH];
        addr.copy_from_slice(bytes);
        Ok(AuthenticationKey(addr))
    }
```

**File:** types/src/transaction/authenticator.rs (L995-1003)
```rust
    fn from_str(s: &str) -> Result<Self> {
        ensure!(
            !s.is_empty(),
            "authentication key string should not be empty.",
        );
        let bytes_out = ::hex::decode(s)?;
        let key = AuthenticationKey::try_from(bytes_out.as_slice())?;
        Ok(key)
    }
```

**File:** ecosystem/node-checker/Cargo.toml (L21-21)
```text
aptos-rest-client = { workspace = true }
```

**File:** crates/aptos-telemetry-service/Cargo.toml (L25-25)
```text
aptos-rest-client = { workspace = true }
```

**File:** api/src/accounts.rs (L264-317)
```rust
    pub fn account(self, accept_type: &AcceptType) -> BasicResultWith404<AccountData> {
        // Retrieve the Account resource and convert it accordingly
        let state_value_opt = self.get_account_resource()?;

        let account_resource = if let Some(state_value) = &state_value_opt {
            let account_resource: AccountResource = bcs::from_bytes(state_value)
                .context("Internal error deserializing response from DB")
                .map_err(|err| {
                    BasicErrorWith404::internal_with_code(
                        err,
                        AptosErrorCode::InternalError,
                        &self.latest_ledger_info,
                    )
                })?;
            account_resource
        } else {
            let stateless_account_enabled = self
                .context
                .feature_enabled(
                    aptos_types::on_chain_config::FeatureFlag::DEFAULT_ACCOUNT_RESOURCE,
                )
                .context("Failed to check if stateless account is enabled")
                .map_err(|_| {
                    BasicErrorWith404::internal_with_code(
                        "Failed to check if stateless account is enabled",
                        AptosErrorCode::InternalError,
                        &self.latest_ledger_info,
                    )
                })?;
            if stateless_account_enabled {
                AccountResource::new_stateless(*self.address.inner())
            } else {
                Err(account_not_found(
                    self.address,
                    self.ledger_version,
                    &self.latest_ledger_info,
                ))?
            }
        };

        // Convert the AccountResource into the summary object AccountData
        match accept_type {
            AcceptType::Json => BasicResponse::try_from_json((
                account_resource.into(),
                &self.latest_ledger_info,
                BasicResponseStatus::Ok,
            )),
            AcceptType::Bcs => BasicResponse::try_from_encoded((
                state_value_opt.unwrap_or_else(|| bcs::to_bytes(&account_resource).unwrap()),
                &self.latest_ledger_info,
                BasicResponseStatus::Ok,
            )),
        }
    }
```
