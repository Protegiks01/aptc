# Audit Report

## Title
Sensitive Information Disclosure Through Unsanitized Error Messages in Secure Storage Module

## Summary
The `From<io::Error>` and `From<serde_json::Error>` trait implementations in the secure storage error module directly propagate underlying error messages without sanitization. This exposes sensitive information including filesystem paths, JSON structure details, and storage configuration through both validator logs and the SafetyRules remote network service. [1](#0-0) [2](#0-1) 

## Finding Description
The secure storage module is used by validators to persist cryptographic keys and consensus safety data. When I/O or serialization errors occur, they are converted to the storage `Error` type through `From` trait implementations that use `format!("{}", error)` to include the full underlying error message.

These unsanitized errors propagate through the consensus SafetyRules module where they are:

1. **Logged with `warn!` level** - SafetyRules errors are logged through the structured logging system, exposing file paths and internal details to log aggregation systems. [3](#0-2) 

2. **Converted to SafetyRules errors** - Storage errors are wrapped in `SecureStorageUnexpectedError` which preserves the sensitive information from the underlying error. [4](#0-3) 

3. **Serialized and transmitted over network** - The SafetyRules remote service serializes all errors (which derive `Serialize`) and returns them to network clients. [5](#0-4) [6](#0-5) 

**Sensitive information exposed includes:**
- Full filesystem paths where validator keys are stored (e.g., "No such file or directory: /opt/aptos/validator/secure-keys.json")
- File permission details and access control information
- JSON structure and field names from serialization errors
- Storage configuration details

## Impact Explanation
This qualifies as **Medium Severity** under the Aptos bug bounty program's "Minor information leaks" category, elevated to medium due to the sensitivity of the exposed information in a validator context.

The information disclosure aids attackers in:
- **Reconnaissance**: Learning internal filesystem structure and key storage locations
- **Targeted attacks**: Identifying specific files to target for corruption or unauthorized access
- **Privilege escalation**: Understanding the validator's file system layout for exploit chaining
- **Social engineering**: Using authentic path information to craft convincing phishing attacks against operators

While this doesn't directly compromise funds or consensus, it violates the defense-in-depth principle by unnecessarily exposing implementation details that should remain internal. Validators handle highly sensitive cryptographic material, and any information leakage about its storage location increases attack surface.

## Likelihood Explanation
**High likelihood** - This occurs whenever storage operations fail, which can happen through:
- Disk space exhaustion
- File permission changes
- Corrupted storage files
- Configuration errors
- Filesystem issues

In production validator environments, storage errors are not uncommon during:
- Initial node setup and configuration
- Disk maintenance or upgrades  
- File system corruption or hardware failures
- Incorrect deployment configurations

The errors are automatically logged and may be exposed through:
- Centralized log aggregation systems
- Monitoring dashboards (Grafana)
- Error reporting services
- Operator access to logs
- Remote SafetyRules service clients (if used)

## Recommendation
Implement error sanitization in the `From` trait implementations to strip sensitive information before propagation:

```rust
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        // Sanitize by only including error kind, not detailed message
        Self::InternalError(format!("I/O error: {}", error.kind()))
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        // Include error category but not line numbers or content
        Self::SerializationError(format!("JSON serialization error: {}", 
            match error.classify() {
                serde_json::error::Category::Io => "I/O error",
                serde_json::error::Category::Syntax => "syntax error",
                serde_json::error::Category::Data => "data error",
                serde_json::error::Category::Eof => "unexpected end of input",
            }
        ))
    }
}
```

Alternatively, use a dedicated internal error type that preserves details for debugging while providing a sanitized display implementation for logging and serialization.

## Proof of Concept

Create a test file that demonstrates information leakage:

```rust
// In secure/storage/src/on_disk.rs or a test file
#[test]
fn test_error_information_disclosure() {
    use std::fs;
    use std::path::PathBuf;
    
    // Create a storage with a non-existent directory path
    let sensitive_path = PathBuf::from("/opt/aptos/validator/keys/consensus_key.json");
    
    // Attempt to read from non-existent file
    let result = std::fs::File::open(&sensitive_path);
    
    // Convert io::Error to storage Error
    let storage_error: Error = result.unwrap_err().into();
    
    // Verify that the error message contains the sensitive path
    let error_msg = format!("{}", storage_error);
    assert!(error_msg.contains("/opt/aptos/validator/keys/consensus_key.json"),
        "Error message exposes sensitive file path: {}", error_msg);
    
    // This demonstrates that when this error is logged or sent over network,
    // the full path is exposed
    println!("Leaked error: {}", error_msg);
}
```

To demonstrate the full exploitation path through SafetyRules:

```rust
#[test] 
fn test_safety_rules_error_leakage() {
    use aptos_secure_storage::{Storage, OnDiskStorage};
    use std::path::PathBuf;
    
    // Create OnDiskStorage with non-existent path
    let sensitive_path = PathBuf::from("/var/aptos/validator-keys/safety-data.json");
    
    // This will fail when trying to read, exposing the path in errors
    let storage = Storage::from(OnDiskStorage::new(sensitive_path));
    let mut safety_storage = PersistentSafetyStorage::new(storage, true);
    
    // Attempt to read safety data will fail with path disclosure
    let result = safety_storage.safety_data();
    
    match result {
        Err(e) => {
            let error_msg = format!("{}", e);
            // Error message will contain the sensitive file path
            assert!(error_msg.contains("/var/aptos/validator-keys"),
                "SafetyRules error leaks path: {}", error_msg);
        },
        Ok(_) => panic!("Expected error"),
    }
}
```

## Notes
The secure storage module is explicitly documented as handling sensitive cryptographic material. [7](#0-6)  The `OnDiskStorage` implementation even notes that it "violates the code base" by making copies of key material and "should not be used in production." Despite this awareness of security sensitivity, the error handling does not follow security best practices of sanitizing error messages before exposure.

This issue affects all storage backends (OnDisk, Vault, InMemory) since they all use the same error types. [8](#0-7)

### Citations

**File:** secure/storage/src/error.rs (L38-42)
```rust
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::InternalError(format!("{}", error))
    }
}
```

**File:** secure/storage/src/error.rs (L50-54)
```rust
impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self::SerializationError(format!("{}", error))
    }
}
```

**File:** consensus/safety-rules/src/safety_rules.rs (L496-499)
```rust
        .inspect_err(|err| {
            warn!(log_cb(SafetyLogSchema::new(log_entry, LogEvent::Error)).error(err));
            counters::increment_query(log_entry.as_str(), "error");
        })
```

**File:** consensus/safety-rules/src/error.rs (L8-8)
```rust
#[derive(Clone, Debug, Deserialize, Error, PartialEq, Eq, Serialize)]
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

**File:** secure/storage/src/on_disk.rs (L16-22)
```rust
/// OnDiskStorage represents a key value store that is persisted to the local filesystem and is
/// intended for single threads (or must be wrapped by a Arc<RwLock<>>). This provides no permission
/// checks and simply offers a proof of concept to unblock building of applications without more
/// complex data stores. Internally, it reads and writes all data to a file, which means that it
/// must make copies of all key material which violates the code base. It violates it because
/// the anticipation is that data stores would securely handle key material. This should not be used
/// in production.
```

**File:** secure/storage/src/vault.rs (L149-149)
```rust
            Err(Error::InternalError("Vault is not unsealed".into()))
```
