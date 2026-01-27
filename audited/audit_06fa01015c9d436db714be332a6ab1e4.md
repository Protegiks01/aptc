# Audit Report

## Title
Information Disclosure via Serialized Error Responses in SafetyRules RemoteService

## Summary
The SafetyRules RemoteService serializes and transmits detailed error messages containing sensitive internal consensus state information (epoch, rounds, QC data) to any connected TCP client without authentication, potentially enabling reconnaissance attacks against validators.

## Finding Description

The SafetyRules RemoteService exposes a critical information disclosure vulnerability through its error handling mechanism. When `SerializerService::handle_message()` processes requests from SafetyRules operations, it serializes the complete `Result<T, Error>` type—including error variants with sensitive data—and sends them back to clients. [1](#0-0) 

The error serialization occurs because:
1. SafetyRules methods return `Result<T, Error>` types
2. The entire Result is serialized via `serde_json::to_vec(&self.internal.consensus_state())`
3. When an error occurs, serde creates JSON: `{"Err": <error_details>}`
4. This JSON is transmitted to the client over the network [2](#0-1) 

The Error enum includes sensitive data in multiple variants: [3](#0-2) 

Critical examples include:
- `IncorrectEpoch(u64, u64)` - reveals current epoch
- `IncorrectLastVotedRound(u64, u64)` - reveals last voted round (critical consensus state)
- `IncorrectPreferredRound(u64, u64)` - reveals preferred round
- `NotSafeToVote(u64, u64, u64, u64)` - reveals QC round, TC round, HQC round
- `WaypointOutOfDate(u64, u64, u64, u64)` - reveals waypoint versions and epochs

The NetworkServer provides no authentication mechanism, accepting any TCP connection: [4](#0-3) 

**Attack Path:**
1. Attacker discovers RemoteService endpoint (if exposed)
2. Connects via TCP without authentication
3. Sends crafted SafetyRules requests designed to trigger specific errors
4. Receives serialized error responses containing internal consensus state
5. Analyzes leaked information for reconnaissance or timing attacks

## Impact Explanation

This issue is classified as **Low Severity** per Aptos bug bounty criteria: "Minor information leaks." While the leaked information includes consensus state details, there is:

- **No direct loss of funds** or consensus manipulation
- **No direct consensus safety violation** 
- **No validator manipulation** capability

The impact is further limited because: [5](#0-4) 

Mainnet validators are **required** to use `SafetyRulesService::Local`, not the RemoteService. The config sanitizer enforces this constraint. Only test networks or misconfigured validators would expose this attack surface.

## Likelihood Explanation

**Likelihood: Low**

The vulnerability requires:
1. A validator running with `SafetyRulesService::Process` (RemoteService) configuration
2. The RemoteService network endpoint being accessible to the attacker
3. Mainnet explicitly prohibits this configuration

However, the vulnerability could manifest in:
- Test networks (devnet, testnet) where RemoteService might be used
- Development/debugging scenarios
- Misconfigured validators violating deployment guidelines

## Recommendation

Implement error sanitization in the RemoteService to prevent internal state leakage:

```rust
// In serializer.rs
pub fn handle_message(&mut self, input_message: Vec<u8>) -> Result<Vec<u8>, Error> {
    let input = serde_json::from_slice(&input_message)?;
    
    let output = match input {
        SafetyRulesInput::ConsensusState => {
            // Sanitize errors before serialization
            sanitize_result(self.internal.consensus_state())
        },
        // ... other cases with sanitization
    };
    
    Ok(output?)
}

fn sanitize_result<T: Serialize>(result: Result<T, Error>) -> Result<Vec<u8>, serde_json::Error> {
    match result {
        Ok(value) => serde_json::to_vec(&Ok(value)),
        Err(error) => {
            // Return generic error without sensitive details
            let generic_error = "Operation failed";
            serde_json::to_vec(&Err::<T, &str>(generic_error))
        }
    }
}
```

Additionally, implement authentication for RemoteService connections using mutual TLS or token-based authentication at the NetworkServer level.

## Proof of Concept

```rust
#[test]
fn test_error_information_disclosure() {
    use std::net::TcpStream;
    use std::io::{Read, Write};
    
    // Setup: Start a RemoteService (in real scenario, connect to existing one)
    let server_addr = "127.0.0.1:6543".parse().unwrap();
    
    // Attacker connects
    let mut stream = TcpStream::connect(server_addr).unwrap();
    
    // Craft request that will trigger NotInitialized error
    let request = serde_json::json!("ConsensusState");
    let request_bytes = serde_json::to_vec(&request).unwrap();
    
    // Send length-prefixed message
    let len = (request_bytes.len() as u32).to_le_bytes();
    stream.write_all(&len).unwrap();
    stream.write_all(&request_bytes).unwrap();
    
    // Read response
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).unwrap();
    let response_len = u32::from_le_bytes(len_bytes) as usize;
    
    let mut response_bytes = vec![0u8; response_len];
    stream.read_exact(&mut response_bytes).unwrap();
    
    // Parse response - should contain serialized error with internal state
    let response: serde_json::Value = serde_json::from_slice(&response_bytes).unwrap();
    
    // Verify error contains sensitive information
    if let Some(err) = response.get("Err") {
        println!("Leaked error details: {:?}", err);
        // Error would contain internal state information
    }
}
```

---

**Notes:**
While this vulnerability represents a real information disclosure issue in the SafetyRules RemoteService implementation, its practical impact is significantly limited by deployment constraints. Mainnet validators cannot use RemoteService configuration, restricting the attack surface to test environments or misconfigured nodes. The leaked information does not directly enable consensus manipulation, fund theft, or network disruption. This assessment classifies the issue as **Low Severity** per the Aptos bug bounty program criteria.

### Citations

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

**File:** consensus/safety-rules/src/remote_service.rs (L47-55)
```rust
fn process_one_message(
    network_server: &mut NetworkServer,
    serializer_service: &mut SerializerService,
) -> Result<(), Error> {
    let request = network_server.read()?;
    let response = serializer_service.handle_message(request)?;
    network_server.write(&response)?;
    Ok(())
}
```

**File:** consensus/safety-rules/src/error.rs (L8-63)
```rust
#[derive(Clone, Debug, Deserialize, Error, PartialEq, Eq, Serialize)]
/// Different reasons for proposal rejection
pub enum Error {
    #[error("Provided epoch, {0}, does not match expected epoch, {1}")]
    IncorrectEpoch(u64, u64),
    #[error("block has next round that wraps around: {0}")]
    IncorrectRound(u64),
    #[error("Provided round, {0}, is incompatible with last voted round, {1}")]
    IncorrectLastVotedRound(u64, u64),
    #[error("Provided round, {0}, is incompatible with preferred round, {1}")]
    IncorrectPreferredRound(u64, u64),
    #[error("Unable to verify that the new tree extends the parent: {0}")]
    InvalidAccumulatorExtension(String),
    #[error("Invalid EpochChangeProof: {0}")]
    InvalidEpochChangeProof(String),
    #[error("Internal error: {0}")]
    InternalError(String),
    #[error("No next_epoch_state specified in the provided Ledger Info")]
    InvalidLedgerInfo,
    #[error("Invalid proposal: {0}")]
    InvalidProposal(String),
    #[error("Invalid QC: {0}")]
    InvalidQuorumCertificate(String),
    #[error("{0} is not set, SafetyRules is not initialized")]
    NotInitialized(String),
    #[error("Does not satisfy order vote rule. Block Round {0}, Highest Timeout Round {1}")]
    NotSafeForOrderVote(u64, u64),
    #[error("Data not found in secure storage: {0}")]
    SecureStorageMissingDataError(String),
    #[error("Unexpected error returned by secure storage: {0}")]
    SecureStorageUnexpectedError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Validator key not found: {0}")]
    ValidatorKeyNotFound(String),
    #[error("The validator is not in the validator set. Address not in set: {0}")]
    ValidatorNotInSet(String),
    #[error("Vote proposal missing expected signature")]
    VoteProposalSignatureNotFound,
    #[error("Does not satisfy 2-chain voting rule. Round {0}, Quorum round {1}, TC round {2},  HQC round in TC {3}")]
    NotSafeToVote(u64, u64, u64, u64),
    #[error("Does not satisfy 2-chain timeout rule. Round {0}, Quorum round {1}, TC round {2}, one-chain round {3}")]
    NotSafeToTimeout(u64, u64, u64, u64),
    #[error("Invalid TC: {0}")]
    InvalidTimeoutCertificate(String),
    #[error("Inconsistent Execution Result: Ordered BlockInfo doesn't match executed BlockInfo. Ordered: {0}, Executed: {1}")]
    InconsistentExecutionResult(String, String),
    #[error("Invalid Ordered LedgerInfoWithSignatures: Empty or at least one of executed_state_id, version, or epoch_state are not dummy value: {0}")]
    InvalidOrderedLedgerInfo(String),
    #[error("Waypoint out of date: Previous waypoint version {0}, updated version {1}, current epoch {2}, provided epoch {3}")]
    WaypointOutOfDate(u64, u64, u64, u64),
    #[error("Invalid Timeout: {0}")]
    InvalidTimeout(String),
    #[error("Incorrect 1-chain Quorum Certificate provided for signing order votes. Quorum Certificate: {0}, block id: {1}")]
    InvalidOneChainQuorumCertificate(HashValue, HashValue),
}
```

**File:** secure/net/src/lib.rs (L365-404)
```rust
    fn client(&mut self) -> Result<&mut NetworkStream, Error> {
        if self.stream.is_none() {
            self.increment_counter(Method::Connect, MethodResult::Query);
            info!(SecureNetLogSchema::new(
                &self.service,
                NetworkMode::Server,
                LogEvent::ConnectionAttempt,
            ));

            let listener = self.listener.as_mut().ok_or(Error::AlreadyShutdown)?;

            let (stream, stream_addr) = match listener.accept() {
                Ok(ok) => ok,
                Err(err) => {
                    self.increment_counter(Method::Connect, MethodResult::Failure);
                    let err = err.into();
                    warn!(SecureNetLogSchema::new(
                        &self.service,
                        NetworkMode::Server,
                        LogEvent::ConnectionSuccessful,
                    )
                    .error(&err));
                    return Err(err);
                },
            };

            self.increment_counter(Method::Connect, MethodResult::Success);
            info!(SecureNetLogSchema::new(
                &self.service,
                NetworkMode::Server,
                LogEvent::ConnectionSuccessful,
            )
            .remote_peer(&stream_addr));

            stream.set_nodelay(true)?;
            self.stream = Some(NetworkStream::new(stream, stream_addr, self.timeout_ms));
        }

        self.stream.as_mut().ok_or(Error::NoActiveStream)
    }
```

**File:** config/src/config/safety_rules_config.rs (L98-104)
```rust
            // Verify that the safety rules service is set to local for optimal performance
            if chain_id.is_mainnet() && !safety_rules_config.service.is_local() {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    format!("The safety rules service should be set to local in mainnet for optimal performance! Given config: {:?}", &safety_rules_config.service)
                ));
            }
```
