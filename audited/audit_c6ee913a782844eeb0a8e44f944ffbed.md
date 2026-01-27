# Audit Report

## Title
Unauthenticated Information Leakage of Validator Voting Behavior via Remote Safety Rules Service

## Summary
The `ConsensusState` struct exposes sensitive validator voting behavior through the unauthenticated remote safety rules service. When SafetyRules is configured in Process mode, the `consensus_state()` endpoint serializes and returns the complete `SafetyData` including the `last_vote` field, revealing detailed voting information to any attacker who can connect to the TCP service. [1](#0-0) 

## Finding Description

The vulnerability occurs through the following chain:

1. **ConsensusState Structure Contains Voting Data**: The `ConsensusState` struct contains a `SafetyData` field which includes `last_vote: Option<Vote>` that stores the validator's most recent vote. [2](#0-1) 

2. **No Serialization Filtering**: The `SafetyData` struct derives `Serialize` without any `#[serde(skip_serializing)]` attribute on the `last_vote` field, meaning when `ConsensusState` is serialized via `serde_json::to_vec()`, it includes the complete `Vote` struct with voting details, author identity, signatures, and ledger info. [3](#0-2) 

3. **Exposed via Unauthenticated Service**: The `TSafetyRules::consensus_state()` method returns the full `ConsensusState`. [4](#0-3) 

4. **Remote Service Serialization**: The `SerializerService` handles `SafetyRulesInput::ConsensusState` requests by serializing the entire `ConsensusState` to JSON. [5](#0-4) 

5. **Plain TCP Without Authentication**: The remote safety rules service uses `NetworkServer` which implements plain TCP communication with no authentication mechanism. [6](#0-5) 

An attacker who can connect to the remote safety rules service endpoint can send a `SafetyRulesInput::ConsensusState` message and receive the serialized response containing:
- The validator's last vote including the specific block voted for
- Validator identity and signature
- Current epoch, rounds (last_voted_round, preferred_round, one_chain_round)
- Validator set membership status
- Timeout information

## Impact Explanation

This is a **Low Severity** information leakage vulnerability per the Aptos bug bounty classification ("Minor information leaks - up to $1,000"). 

While it does not directly compromise consensus safety, fund security, or network availability, it exposes operational information that could aid attackers:

1. **Validator Reconnaissance**: Identify which nodes are active validators
2. **Voting Pattern Analysis**: Track validator voting behavior over time
3. **Consensus Timing Intelligence**: Determine consensus progress and timing
4. **Strategic Attack Planning**: Use leaked information to coordinate timing attacks

The severity is limited because:
- Mainnet validators are protected (config sanitizer requires Local mode) [7](#0-6) 
- Votes are broadcast to validators during normal consensus operation
- No direct consensus safety violation or fund loss
- Cannot forge or manipulate votes with this information

## Likelihood Explanation

**Low to Medium likelihood** depending on deployment configuration:

**Mitigating Factors:**
- Mainnet validators are required by the config sanitizer to use `SafetyRulesService::Local`, preventing remote service exposure
- The `Thread` service mode automatically binds to localhost only [8](#0-7) 

**Risk Scenarios:**
- Testnets or development networks using `SafetyRulesService::Process` mode
- Misconfigured validators that bypass sanitizer checks
- Process mode with publicly accessible network addresses [9](#0-8) 

The vulnerability requires the attacker to:
1. Identify a validator running SafetyRules in Process mode
2. Have network connectivity to the configured server address
3. Construct and send a `SafetyRulesInput::ConsensusState` message

## Recommendation

**Option 1 (Recommended): Exclude last_vote from serialization**
```rust
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize, Clone, Default)]
pub struct SafetyData {
    pub epoch: u64,
    pub last_voted_round: u64,
    pub preferred_round: u64,
    #[serde(default)]
    pub one_chain_round: u64,
    #[serde(skip_serializing)]  // Add this annotation
    pub last_vote: Option<Vote>,
    #[serde(default)]
    pub highest_timeout_round: u64,
}
```

**Option 2: Add authentication to remote service**
Implement mutual TLS or cryptographic authentication for the NetworkServer/NetworkClient to ensure only authorized consensus nodes can query consensus_state().

**Option 3: Create separate public/internal ConsensusState**
Define a `PublicConsensusState` that excludes sensitive fields for external queries, while keeping the full `ConsensusState` for internal use.

## Proof of Concept

```rust
// PoC: Unauthenticated query of validator voting behavior
// This demonstrates an attacker connecting to an exposed remote safety rules service

use aptos_safety_rules::serializer::SafetyRulesInput;
use aptos_secure_net::NetworkClient;
use std::net::SocketAddr;

fn exploit_consensus_state_leak(target_validator: SocketAddr) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Create network client to remote safety rules service (no auth required)
    let mut client = NetworkClient::new(
        "attacker".to_string(),
        target_validator,
        30_000,
    );
    
    // Craft request for consensus state
    let request = SafetyRulesInput::ConsensusState;
    let request_bytes = serde_json::to_vec(&request)?;
    
    // Send request to unauthenticated endpoint
    client.write(&request_bytes)?;
    
    // Receive serialized ConsensusState including last_vote details
    let response = client.read()?;
    
    // Parse response to extract sensitive voting information
    let consensus_state: serde_json::Value = serde_json::from_slice(&response)?;
    
    println!("Leaked validator state: {}", consensus_state);
    // Response contains:
    // - safety_data.last_vote (full Vote with block, author, signature)
    // - safety_data.epoch, last_voted_round, preferred_round
    // - in_validator_set (validator membership)
    // - waypoint
    
    Ok(response)
}
```

**Notes**

1. **Deployment Context**: This vulnerability only affects validators running SafetyRules in Process mode with an exposed network address. Mainnet production validators are protected by the configuration sanitizer requirement for Local mode.

2. **Information vs. Action**: While this exposes voting behavior, it does not allow vote manipulation, forgery, or direct consensus attacks. The leaked information is primarily useful for reconnaissance and timing analysis.

3. **Design Intent**: The comment in `consensus_state.rs` states "This does not include sensitive data like private keys," suggesting the intent was to provide monitoring/debugging data. However, voting behavior is operationally sensitive and should not be exposed without authentication.

4. **Broadcast vs. Query**: Although votes are broadcast during normal consensus operation, having a queryable endpoint accessible to non-validators expands the attack surface beyond the intended validator set.

### Citations

**File:** consensus/safety-rules/src/consensus_state.rs (L9-17)
```rust
/// Public representation of the internal state of SafetyRules for monitoring / debugging purposes.
/// This does not include sensitive data like private keys.
/// @TODO add hash of ledger info (waypoint)
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConsensusState {
    safety_data: SafetyData,
    waypoint: Waypoint,
    in_validator_set: bool,
}
```

**File:** consensus/consensus-types/src/safety_data.rs (L9-21)
```rust
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize, Clone, Default)]
pub struct SafetyData {
    pub epoch: u64,
    pub last_voted_round: u64,
    // highest 2-chain round, used for 3-chain
    pub preferred_round: u64,
    // highest 1-chain round, used for 2-chain
    #[serde(default)]
    pub one_chain_round: u64,
    pub last_vote: Option<Vote>,
    #[serde(default)]
    pub highest_timeout_round: u64,
}
```

**File:** consensus/consensus-types/src/vote.rs (L18-34)
```rust
/// Vote is the struct that is ultimately sent by the voter in response for
/// receiving a proposal.
/// Vote carries the `LedgerInfo` of a block that is going to be committed in case this vote
/// is gathers QuorumCertificate (see the detailed explanation in the comments of `LedgerInfo`).
#[derive(Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct Vote {
    /// The data of the vote.
    vote_data: VoteData,
    /// The identity of the voter.
    author: Author,
    /// LedgerInfo of a block that is going to be committed in case this vote gathers QC.
    ledger_info: LedgerInfo,
    /// Signature on the LedgerInfo along with a status on whether the signature is verified.
    signature: SignatureWithStatus,
    /// The 2-chain timeout and corresponding signature.
    two_chain_timeout: Option<(TwoChainTimeout, bls12381::Signature)>,
}
```

**File:** consensus/safety-rules/src/t_safety_rules.rs (L20-23)
```rust
pub trait TSafetyRules {
    /// Provides the internal state of SafetyRules for monitoring / debugging purposes. This does
    /// not include sensitive data like private keys.
    fn consensus_state(&mut self) -> Result<ConsensusState, Error>;
```

**File:** consensus/safety-rules/src/serializer.rs (L48-51)
```rust
        let output = match input {
            SafetyRulesInput::ConsensusState => {
                serde_json::to_vec(&self.internal.consensus_state())
            },
```

**File:** secure/net/src/lib.rs (L272-289)
```rust
pub struct NetworkServer {
    service: String,
    listener: Option<TcpListener>,
    stream: Option<NetworkStream>,
    /// Read, Write, Connect timeout in milliseconds.
    timeout_ms: u64,
}

impl NetworkServer {
    pub fn new(service: String, listen: SocketAddr, timeout_ms: u64) -> Self {
        let listener = TcpListener::bind(listen);
        Self {
            service,
            listener: Some(listener.unwrap()),
            stream: None,
            timeout_ms,
        }
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

**File:** consensus/safety-rules/src/thread.rs (L29-34)
```rust
    pub fn new(storage: PersistentSafetyStorage, timeout: u64) -> Self {
        let listen_port = utils::get_available_port();
        let listen_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_port);
        let server_addr = listen_addr;

        let child = thread::spawn(move || remote_service::execute(storage, listen_addr, timeout));
```

**File:** consensus/safety-rules/src/process.rs (L35-38)
```rust
    pub fn start(&mut self) {
        let data = self.data.take().expect("Unable to retrieve ProcessData");
        remote_service::execute(data.storage, data.server_addr, data.network_timeout);
    }
```
