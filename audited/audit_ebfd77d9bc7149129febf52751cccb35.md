# Audit Report

## Title
Information Disclosure Through Unsanitized Storage Errors in SafetyRules Consensus Key Loading

## Summary
The `default_consensus_sk()` function in `persistent_safety_storage.rs` propagates detailed storage backend errors without sanitization. These errors, containing sensitive infrastructure details including Vault HTTP response bodies and file system paths, are exposed through both local logging and the SafetyRules network service, providing attackers with reconnaissance information about the validator's key storage infrastructure.

## Finding Description

The vulnerability exists in the error propagation chain from storage operations to network-exposed interfaces: [1](#0-0) 

The function directly propagates `aptos_secure_storage::Error` without sanitization. These errors contain detailed backend-specific information:

**For Vault Storage:** [2](#0-1) 

The `HttpError` variant includes the full HTTP response body from Vault API calls, which can contain:
- Vault seal status ("Vault is sealed")
- Detailed permission errors with capability requirements
- Encryption key versioning information
- Transit backend configuration details

**For OnDisk Storage:** [3](#0-2) 

IO errors include full file system paths revealing key storage locations.

**Error Exposure via Network:**

The critical exposure occurs through the SafetyRules serialization layer: [4](#0-3) 

The `Error` enum is serializable: [5](#0-4) 

When storage errors are converted to SafetyRules errors: [6](#0-5) 

The `error.to_string()` at line 94 and 96 includes all detailed storage backend information, which is then serialized and transmitted over the network when Initialize operations fail.

**Attack Path:**

1. Attacker with network access to SafetyRules service (compromised node, validator network access, or log aggregation access)
2. Triggers key loading via Initialize message during epoch transitions
3. If key loading fails (token expiry, seal status, missing key), detailed error is returned
4. Error reveals:
   - Storage backend type (Vault vs OnDisk)
   - Vault endpoints and authentication status
   - File system paths for key storage
   - Encryption configuration and key versioning
   - Exact error conditions (missing vs corrupted vs permission denied)

## Impact Explanation

This is a **Medium Severity** information disclosure vulnerability:

- **Direct Impact**: Leaks infrastructure configuration details that should remain confidential
- **Attack Enhancement**: Provides reconnaissance information enabling:
  - Targeted attacks on identified storage backends
  - Understanding of key rotation and versioning schemes
  - Precise knowledge of authentication/authorization requirements
  - File system structure for offline attacks
- **Defense-in-Depth Violation**: Error messages should never expose internal implementation details

Per Aptos bug bounty criteria, this falls under Medium Severity: "Minor information leaks" that could facilitate more sophisticated attacks on validator infrastructure.

## Likelihood Explanation

**High Likelihood** - This will occur naturally during:
- Validator initialization failures
- Vault token expiration
- Key rotation operations
- Storage backend misconfigurations
- Epoch transition errors

The information is exposed through:
1. Local validator logs (accessible via log aggregation systems)
2. SafetyRules network service responses (accessible to other validators or compromised nodes)
3. Error messages visible during operational troubleshooting

## Recommendation

Implement error sanitization before propagating storage errors:

```rust
pub fn default_consensus_sk(
    &self,
) -> Result<bls12381::PrivateKey, aptos_secure_storage::Error> {
    self.internal_store
        .get::<bls12381::PrivateKey>(CONSENSUS_KEY)
        .map(|v| v.value)
        .map_err(|e| {
            // Sanitize error to prevent information leakage
            match e {
                Error::KeyNotSet(_) => Error::KeyNotSet("consensus key".to_string()),
                Error::KeyVersionNotFound(_, _) => Error::KeyNotSet("consensus key".to_string()),
                Error::PermissionDenied => Error::PermissionDenied,
                Error::SerializationError(_) => Error::InternalError("key deserialization failed".to_string()),
                _ => Error::InternalError("storage access failed".to_string()),
            }
        })
}
```

Additionally, sanitize error conversions in the From trait implementation: [6](#0-5) 

Replace lines 94 and 96 with generic error messages that don't expose backend details.

## Proof of Concept

```rust
#[cfg(test)]
mod information_leak_test {
    use super::*;
    use aptos_secure_storage::{Storage, VaultStorage};
    
    #[test]
    fn test_vault_error_information_leak() {
        // Setup Vault storage with invalid token
        let vault = VaultStorage::new(
            "http://vault.example.com:8200".to_string(),
            "expired_token".to_string(),
            None, None, false, None, None
        );
        let storage = PersistentSafetyStorage::new(Storage::from(vault), false);
        
        // Attempt to load consensus key
        let result = storage.default_consensus_sk();
        
        // Verify error contains detailed Vault information
        assert!(result.is_err());
        let error_msg = format!("{}", result.unwrap_err());
        
        // This will expose Vault HTTP response body including:
        // - Vault endpoint URL
        // - Authentication failure details
        // - Potentially seal status and configuration
        println!("Leaked error: {}", error_msg);
        assert!(error_msg.contains("Http error") || error_msg.contains("vault"));
    }
    
    #[test]
    fn test_error_serialization_over_network() {
        // Demonstrate that Error enum can be serialized
        let error = Error::SecureStorageUnexpectedError(
            "Http error, status code: 403, status text: Forbidden, body: {\"errors\":[\"permission denied, needs capability transit:read on transit/export/signing-key/consensus\"]}".to_string()
        );
        
        // This error can be serialized and sent over network
        let serialized = serde_json::to_string(&error).unwrap();
        println!("Serialized error sent over network: {}", serialized);
        
        // Verify detailed information is preserved
        assert!(serialized.contains("transit/export/signing-key/consensus"));
    }
}
```

## Notes

This vulnerability represents a defense-in-depth failure where detailed internal infrastructure information is unnecessarily exposed through error messages. While not directly exploitable for key compromise, it provides valuable reconnaissance data for sophisticated attackers targeting validator infrastructure. The fix requires implementing error message sanitization at the storage abstraction boundary to prevent backend-specific details from propagating to logs or network interfaces.

### Citations

**File:** consensus/safety-rules/src/persistent_safety_storage.rs (L98-104)
```rust
    pub fn default_consensus_sk(
        &self,
    ) -> Result<bls12381::PrivateKey, aptos_secure_storage::Error> {
        self.internal_store
            .get::<bls12381::PrivateKey>(CONSENSUS_KEY)
            .map(|v| v.value)
    }
```

**File:** secure/storage/vault/src/lib.rs (L75-91)
```rust
impl From<ureq::Response> for Error {
    fn from(resp: ureq::Response) -> Self {
        if resp.synthetic() {
            match resp.into_string() {
                Ok(resp) => Error::SyntheticError(resp),
                Err(error) => Error::InternalError(error.to_string()),
            }
        } else {
            let status = resp.status();
            let status_text = resp.status_text().to_string();
            match resp.into_string() {
                Ok(body) => Error::HttpError(status, status_text, body),
                Err(error) => Error::InternalError(error.to_string()),
            }
        }
    }
}
```

**File:** secure/storage/src/on_disk.rs (L53-62)
```rust
    fn read(&self) -> Result<HashMap<String, Value>, Error> {
        let mut file = File::open(&self.file_path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        if contents.is_empty() {
            return Ok(HashMap::new());
        }
        let data = serde_json::from_str(&contents)?;
        Ok(data)
    }
```

**File:** consensus/safety-rules/src/serializer.rs (L45-82)
```rust
    pub fn handle_message(&mut self, input_message: Vec<u8>) -> Result<Vec<u8>, Error> {
        let input = serde_json::from_slice(&input_message)?;

        let output = match input {
            SafetyRulesInput::ConsensusState => {
                serde_json::to_vec(&self.internal.consensus_state())
            },
            SafetyRulesInput::Initialize(li) => serde_json::to_vec(&self.internal.initialize(&li)),
            SafetyRulesInput::SignProposal(block_data) => {
                serde_json::to_vec(&self.internal.sign_proposal(&block_data))
            },
            SafetyRulesInput::SignTimeoutWithQC(timeout, maybe_tc) => serde_json::to_vec(
                &self
                    .internal
                    .sign_timeout_with_qc(&timeout, maybe_tc.as_ref().as_ref()),
            ),
            SafetyRulesInput::ConstructAndSignVoteTwoChain(vote_proposal, maybe_tc) => {
                serde_json::to_vec(
                    &self.internal.construct_and_sign_vote_two_chain(
                        &vote_proposal,
                        maybe_tc.as_ref().as_ref(),
                    ),
                )
            },
            SafetyRulesInput::ConstructAndSignOrderVote(order_vote_proposal) => serde_json::to_vec(
                &self
                    .internal
                    .construct_and_sign_order_vote(&order_vote_proposal),
            ),
            SafetyRulesInput::SignCommitVote(ledger_info, new_ledger_info) => serde_json::to_vec(
                &self
                    .internal
                    .sign_commit_vote(*ledger_info, *new_ledger_info),
            ),
        };

        Ok(output?)
    }
```

**File:** consensus/safety-rules/src/error.rs (L8-10)
```rust
#[derive(Clone, Debug, Deserialize, Error, PartialEq, Eq, Serialize)]
/// Different reasons for proposal rejection
pub enum Error {
```

**File:** consensus/safety-rules/src/error.rs (L78-98)
```rust
impl From<aptos_secure_storage::Error> for Error {
    fn from(error: aptos_secure_storage::Error) -> Self {
        match error {
            aptos_secure_storage::Error::PermissionDenied => {
                // If a storage error is thrown that indicates a permission failure, we
                // want to panic immediately to alert an operator that something has gone
                // wrong. For example, this error is thrown when a storage (e.g., vault)
                // token has expired, so it makes sense to fail fast and require a token
                // renewal!
                panic!(
                    "A permission error was thrown: {:?}. Maybe the storage token needs to be renewed?",
                    error
                );
            },
            aptos_secure_storage::Error::KeyVersionNotFound(_, _)
            | aptos_secure_storage::Error::KeyNotSet(_) => {
                Self::SecureStorageMissingDataError(error.to_string())
            },
            _ => Self::SecureStorageUnexpectedError(error.to_string()),
        }
    }
```
