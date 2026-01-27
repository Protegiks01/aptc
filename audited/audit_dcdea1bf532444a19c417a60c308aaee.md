# Audit Report

## Title
Consensus Validator DoS via Panic on Vault Token Expiration in SafetyRules Error Handling

## Summary
The SafetyRules error handling code intentionally panics when encountering `PermissionDenied` errors from secure storage, which occurs when Vault authentication tokens expire. This panic happens in the critical consensus voting path, causing validator crashes and potential network liveness failures when tokens naturally expire during operation.

## Finding Description

The vulnerability exists in the error conversion logic that transforms secure storage errors into SafetyRules errors. [1](#0-0) 

When validators use Vault as their secure storage backend for SafetyRules persistence, Vault tokens have time-to-live (TTL) limits and will eventually expire. When a Vault token expires, subsequent storage operations return HTTP 403 responses, which are converted to `PermissionDenied` errors. [2](#0-1) 

The critical issue is that this error occurs during consensus voting operations. When a validator receives a block proposal, it calls the voting path which accesses persistent storage multiple times to read and update safety data. [3](#0-2) 

The voting implementation in SafetyRules accesses storage at multiple critical points. [4](#0-3) 

All storage accesses use the `?` operator which invokes the `From` trait conversion, triggering the panic when tokens are expired. The storage access occurs through PersistentSafetyStorage which wraps the Vault backend. [5](#0-4) 

Token renewal is optional in Vault configuration and implemented as best-effort - if renewal fails, only an error is logged without preventing continued operation. [6](#0-5) 

Vault configuration explicitly allows optional token renewal. [7](#0-6) 

**Attack Path:**
1. Validator is configured with Vault backend for SafetyRules storage
2. Token renewal is not configured, misconfigured, or renewal fails
3. Vault token naturally expires after its TTL
4. Validator receives next block proposal and enters voting path
5. SafetyRules attempts to read safety_data from storage
6. Vault returns HTTP 403 (expired token)
7. Error conversion panics, crashing validator process
8. Validator is offline until operator manually renews token and restarts

This breaks the **Consensus Safety** invariant requirement for liveness, as validators cannot participate in consensus while crashed.

## Impact Explanation

**Severity: Medium to High**

This qualifies as **High Severity** under Aptos bug bounty criteria ("Validator node slowdowns" / "API crashes") with potential escalation to **Critical** if multiple validators crash simultaneously, causing "Total loss of liveness/network availability."

**Impact Quantification:**
- **Single Validator**: Immediate crash, unable to vote until manual intervention
- **Multiple Validators**: If several validators' tokens expire around the same time (common if deployed together), network could lose sufficient voting power
- **Consensus Liveness**: Each crashed validator reduces the network's ability to form quorums
- **Network Availability**: With enough simultaneous crashes (≥1/3 of validators), consensus can halt entirely

The severity escalates based on:
1. How many production validators use Vault backend (unknown)
2. Whether operators properly configure token renewal
3. Token TTL synchronization across validators

## Likelihood Explanation

**Likelihood: Medium to High**

**Factors Increasing Likelihood:**
1. **Natural Occurrence**: Token expiration is inevitable, not requiring attacker action
2. **Configuration Complexity**: Token renewal must be explicitly configured and maintained
3. **Silent Failure**: Token renewal failures only log errors, operators may not notice until crash
4. **Production Usage**: Vault is explicitly supported and likely used in production for key management
5. **Synchronized Deployments**: Validators deployed together likely have synchronized token expiration times

**Factors Decreasing Likelihood:**
1. **Requires Vault Backend**: Only affects validators using Vault (not on-disk or in-memory storage)
2. **Operator Control**: Well-configured infrastructure with proper monitoring prevents this
3. **Recoverable**: Operators can renew tokens and restart validators

**Realistic Scenario**: A validator operator deploys with Vault, configures initial token, but fails to set up `renew_ttl_secs` properly. Weeks later during normal operation, the token expires while processing a block proposal, instantly crashing the validator.

## Recommendation

**Fix: Return Error Instead of Panic**

Replace the panic with a proper error return that allows graceful degradation:

```rust
impl From<aptos_secure_storage::Error> for Error {
    fn from(error: aptos_secure_storage::Error) -> Self {
        match error {
            aptos_secure_storage::Error::PermissionDenied => {
                // Log the permission error prominently for operator alerting
                error!(
                    "Permission denied accessing secure storage: {:?}. \
                    Storage token may need renewal. Validator cannot participate in consensus.",
                    error
                );
                // Return an error instead of panicking to allow graceful handling
                Self::SecureStorageUnexpectedError(
                    "Permission denied - storage token may need renewal".to_string()
                )
            },
            aptos_secure_storage::Error::KeyVersionNotFound(_, _)
            | aptos_secure_storage::Error::KeyNotSet(_) => {
                Self::SecureStorageMissingDataError(error.to_string())
            },
            _ => Self::SecureStorageUnexpectedError(error.to_string()),
        }
    }
}
```

**Additional Recommendations:**
1. Implement health checks that detect token expiration before voting operations
2. Add metrics/alerts for token renewal failures
3. Make token renewal mandatory for Vault configurations with validation
4. Document token management requirements clearly for operators
5. Consider fail-safe mode where validator stops voting but doesn't crash

## Proof of Concept

```rust
// Test demonstrating the panic on PermissionDenied
// Location: consensus/safety-rules/src/tests/token_expiration_test.rs

#[cfg(test)]
mod token_expiration_dos_test {
    use crate::{
        Error, PersistentSafetyStorage, SafetyRules, TSafetyRules,
    };
    use aptos_secure_storage::{Error as StorageError, InMemoryStorage, Storage};
    use aptos_consensus_types::vote_proposal::VoteProposal;
    use aptos_types::validator_signer::ValidatorSigner;
    
    #[test]
    #[should_panic(expected = "A permission error was thrown")]
    fn test_permission_denied_causes_panic_during_voting() {
        // Setup: Create a mock storage that will return PermissionDenied
        struct FailingStorage;
        
        impl aptos_secure_storage::KVStorage for FailingStorage {
            fn available(&self) -> Result<(), StorageError> {
                Err(StorageError::PermissionDenied)
            }
            
            fn get<T: serde::de::DeserializeOwned>(
                &self, 
                _key: &str
            ) -> Result<aptos_secure_storage::GetResponse<T>, StorageError> {
                // Simulate expired token
                Err(StorageError::PermissionDenied)
            }
            
            fn set<T: serde::Serialize>(
                &mut self, 
                _key: &str, 
                _value: T
            ) -> Result<(), StorageError> {
                Err(StorageError::PermissionDenied)
            }
            
            #[cfg(any(test, feature = "testing"))]
            fn reset_and_clear(&mut self) -> Result<(), StorageError> {
                Ok(())
            }
        }
        
        // Create SafetyRules with the failing storage
        let storage = Storage::from(FailingStorage);
        let persistent_storage = PersistentSafetyStorage::new(storage, false);
        let mut safety_rules = SafetyRules::new(persistent_storage, true);
        
        // Create a vote proposal
        let signer = ValidatorSigner::from_int(0);
        let vote_proposal = test_utils::make_proposal_with_qc(
            1, 
            QuorumCert::certificate_for_genesis(),
            &signer,
        );
        
        // Attempt to vote - this will panic when accessing storage
        // In production, this panic crashes the validator
        let _result = safety_rules.construct_and_sign_vote_two_chain(
            &vote_proposal,
            None,
        );
        
        // This line is never reached due to panic
    }
}
```

**Reproduction Steps:**
1. Configure validator with Vault backend for SafetyRules
2. Set a short token TTL (e.g., 1 hour) without `renew_ttl_secs` configured
3. Start validator and wait for consensus participation
4. Wait for token to expire
5. Observe validator crash on next voting operation with panic message
6. Network loses one validator; repeat with multiple validators for consensus halt

**Notes**

The vulnerability is real and exploitable through natural operational conditions. While it doesn't require active attacker involvement, it represents a critical design flaw in consensus-critical error handling. The intentional panic for "fail-fast" operator alerting is inappropriate for production consensus software and violates availability guarantees. Validators using Vault without proper token management will experience crashes during normal operation, potentially causing network liveness failures.

### Citations

**File:** consensus/safety-rules/src/error.rs (L78-99)
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
}
```

**File:** secure/storage/src/error.rs (L56-64)
```rust
impl From<aptos_vault_client::Error> for Error {
    fn from(error: aptos_vault_client::Error) -> Self {
        match error {
            aptos_vault_client::Error::NotFound(_, key) => Self::KeyNotSet(key),
            aptos_vault_client::Error::HttpError(403, _, _) => Self::PermissionDenied,
            _ => Self::InternalError(format!("{}", error)),
        }
    }
}
```

**File:** consensus/src/round_manager.rs (L1519-1527)
```rust
        let vote_proposal = block_arc.vote_proposal();
        let vote_result = self.safety_rules.lock().construct_and_sign_vote_two_chain(
            &vote_proposal,
            self.block_store.highest_2chain_timeout_cert().as_deref(),
        );
        let vote = vote_result.context(format!(
            "[RoundManager] SafetyRules Rejected {}",
            block_arc.block()
        ))?;
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L53-95)
```rust
    pub(crate) fn guarded_construct_and_sign_vote_two_chain(
        &mut self,
        vote_proposal: &VoteProposal,
        timeout_cert: Option<&TwoChainTimeoutCertificate>,
    ) -> Result<Vote, Error> {
        // Exit early if we cannot sign
        self.signer()?;

        let vote_data = self.verify_proposal(vote_proposal)?;
        if let Some(tc) = timeout_cert {
            self.verify_tc(tc)?;
        }
        let proposed_block = vote_proposal.block();
        let mut safety_data = self.persistent_storage.safety_data()?;

        // if already voted on this round, send back the previous vote
        // note: this needs to happen after verifying the epoch as we just check the round here
        if let Some(vote) = safety_data.last_vote.clone() {
            if vote.vote_data().proposed().round() == proposed_block.round() {
                return Ok(vote);
            }
        }

        // Two voting rules
        self.verify_and_update_last_vote_round(
            proposed_block.block_data().round(),
            &mut safety_data,
        )?;
        self.safe_to_vote(proposed_block, timeout_cert)?;

        // Record 1-chain data
        self.observe_qc(proposed_block.quorum_cert(), &mut safety_data);
        // Construct and sign vote
        let author = self.signer()?.author();
        let ledger_info = self.construct_ledger_info_2chain(proposed_block, vote_data.hash())?;
        let signature = self.sign(&ledger_info)?;
        let vote = Vote::new_with_signature(vote_data, author, ledger_info, signature);

        safety_data.last_vote = Some(vote.clone());
        self.persistent_storage.set_safety_data(safety_data)?;

        Ok(vote)
    }
```

**File:** consensus/safety-rules/src/persistent_safety_storage.rs (L134-148)
```rust
    pub fn safety_data(&mut self) -> Result<SafetyData, Error> {
        if !self.enable_cached_safety_data {
            let _timer = counters::start_timer("get", SAFETY_DATA);
            return self.internal_store.get(SAFETY_DATA).map(|v| v.value)?;
        }

        if let Some(cached_safety_data) = self.cached_safety_data.clone() {
            Ok(cached_safety_data)
        } else {
            let _timer = counters::start_timer("get", SAFETY_DATA);
            let safety_data: SafetyData = self.internal_store.get(SAFETY_DATA).map(|v| v.value)?;
            self.cached_safety_data = Some(safety_data.clone());
            Ok(safety_data)
        }
    }
```

**File:** secure/storage/src/vault.rs (L68-84)
```rust
    // Made into an accessor so we can get auto-renewal
    fn client(&self) -> &Client {
        if self.renew_ttl_secs.is_some() {
            let now = self.time_service.now_secs();
            let next_renewal = self.next_renewal.load(Ordering::Relaxed);
            if now >= next_renewal {
                let result = self.client.renew_token_self(self.renew_ttl_secs);
                if let Ok(ttl) = result {
                    let next_renewal = now + (ttl as u64) / 2;
                    self.next_renewal.store(next_renewal, Ordering::Relaxed);
                } else if let Err(e) = result {
                    aptos_logger::error!("Unable to renew lease: {}", e.to_string());
                }
            }
        }
        &self.client
    }
```

**File:** config/src/config/secure_backend_config.rs (L51-74)
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VaultConfig {
    /// Optional SSL Certificate for the vault host, this is expected to be a full path.
    pub ca_certificate: Option<PathBuf>,
    /// A namespace is an optional portion of the path to a key stored within Vault. For example,
    /// a secret, S, without a namespace would be available in secret/data/S, with a namespace, N, it
    /// would be in secret/data/N/S.
    pub namespace: Option<String>,
    /// Vault leverages leases on many tokens, specify this to automatically have your lease
    /// renewed up to that many seconds more. If this is not specified, the lease will not
    /// automatically be renewed.
    pub renew_ttl_secs: Option<u32>,
    /// Vault's URL, note: only HTTP is currently supported.
    pub server: String,
    /// The authorization token for accessing secrets
    pub token: Token,
    /// Disable check-and-set when writing secrets to Vault
    pub disable_cas: Option<bool>,
    /// Timeout for new vault socket connections, in milliseconds.
    pub connection_timeout_ms: Option<u64>,
    /// Timeout for generic vault operations (e.g., reads and writes), in milliseconds.
    pub response_timeout_ms: Option<u64>,
}
```
