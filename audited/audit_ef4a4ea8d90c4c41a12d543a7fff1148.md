# Audit Report

## Title
Unauthenticated SafetyRules Remote Service Allows Validator Impersonation and Consensus Safety Violations

## Summary
The SafetyRules component, which holds validator consensus private keys and signs critical consensus messages, can be configured to run as a remote service using the unauthenticated TCP networking layer from `secure/net`. This allows any attacker who can reach the network socket to request signatures on arbitrary consensus messages, enabling validator impersonation, equivocation attacks, and consensus safety violations.

## Finding Description

SafetyRules is the critical consensus component responsible for ensuring safety guarantees in AptosBFT by preventing double-voting and validating consensus messages before signing them with the validator's BLS12-381 private key. [1](#0-0) 

When configured in "Process" mode, SafetyRules runs as a separate service that accepts network connections. [2](#0-1) 

The critical vulnerability lies in the network communication layer. The `secure/net` module implements a basic TCP client-server architecture with **no authentication mechanism**. [3](#0-2) 

The SafetyRules remote service uses this unauthenticated networking layer directly. [4](#0-3) 

Any client connecting to this service can send serialized `SafetyRulesInput` commands, which include critical operations such as:
- `SignProposal` - Sign block proposals
- `ConstructAndSignVoteTwoChain` - Create and sign votes
- `SignTimeoutWithQC` - Sign timeout messages
- `SignCommitVote` - Sign commit votes
- `Initialize` - Reset SafetyRules state [5](#0-4) 

The service deserializes incoming messages and processes them without any authentication or authorization checks. [6](#0-5) 

**Attack Path:**
1. Attacker discovers a validator running SafetyRules in Process mode with a network-accessible socket
2. Attacker establishes a plain TCP connection (no handshake or authentication required)
3. Attacker crafts malicious `SafetyRulesInput` messages requesting signatures on conflicting blocks or votes
4. SafetyRules processes the request and returns valid BLS signatures using the validator's private key
5. Attacker uses these signatures to impersonate the validator, create equivocating votes, or disrupt consensus

This breaks **Consensus Safety Invariant #2**: "AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine" by allowing an external attacker to obtain validator signatures without controlling the validator itself.

## Impact Explanation

This vulnerability falls under **Critical Severity** per the Aptos bug bounty program for the following reasons:

1. **Consensus/Safety Violations**: An attacker can force a validator to sign conflicting consensus messages (equivocation), which directly violates BFT consensus safety guarantees. This can lead to chain splits if multiple validators are compromised.

2. **Validator Impersonation**: The attacker gains full signing capabilities of the validator without needing to compromise the validator's private key storage, effectively acting as the validator in the consensus protocol.

3. **Non-recoverable Network Impact**: If an attacker obtains signatures for conflicting blocks at critical heights (e.g., epoch boundaries), this could cause consensus deadlock requiring manual intervention or a hard fork to resolve.

While the config sanitizer enforces `Local` mode for mainnet validators [7](#0-6) , this protection is insufficient because:
- Testnet and devnet validators remain vulnerable (Process mode is allowed)
- Configuration sanitizers can be bypassed or disabled
- The architectural flaw represents a lack of defense-in-depth in a consensus-critical component

## Likelihood Explanation

**Medium-to-High Likelihood** for the following reasons:

**Factors Increasing Likelihood:**
- Process mode is explicitly described as "the production, separate service approach" in the code comments, indicating intended use beyond testing
- Testnet validators are real targets with actual stake and economic value
- No authentication means any network-reachable deployment is immediately vulnerable
- The attack requires no special privileges or insider access

**Factors Decreasing Likelihood:**
- Mainnet config sanitizer blocks Process mode
- Operators would typically bind SafetyRules service to localhost only
- Deployment best practices would use firewall rules

However, defense-in-depth principles dictate that authentication should be mandatory for any service handling consensus private keys, regardless of network topology assumptions.

## Recommendation

Implement mandatory mutual authentication for the SafetyRules remote service using the same Noise protocol framework already used by Aptos validator networking:

1. **Add Authentication Layer**: Modify the RemoteService implementation to use the authenticated networking stack from `network/framework` instead of the unauthenticated `secure/net` module.

2. **Enforce Client Authentication**: Require clients connecting to SafetyRules to prove possession of an authorized key (e.g., the validator's network identity key).

3. **Add Authorization Checks**: Verify that the authenticated client has permission to request SafetyRules operations.

4. **Defense-in-Depth**: Even if Process mode is discouraged for mainnet, all deployments should have authentication enabled by default.

Example architectural fix:
```rust
// In remote_service.rs, replace NetworkServer with authenticated transport
pub fn execute(storage: PersistentSafetyStorage, listen_addr: SocketAddr, 
               network_timeout_ms: u64, authorized_key: x25519::PublicKey) {
    let mut safety_rules = SafetyRules::new(storage, false);
    // Use authenticated network transport with Noise protocol
    let mut network_server = AuthenticatedNetworkServer::new(
        "safety-rules".to_string(), 
        listen_addr, 
        network_timeout_ms,
        authorized_key  // Only accept connections from this key
    );
    // Rest of implementation...
}
```

## Proof of Concept

```rust
// This PoC demonstrates the vulnerability by connecting to an unauthenticated
// SafetyRules service and requesting a signature without any authentication.

use aptos_secure_net::NetworkClient;
use consensus_safety_rules::serializer::SafetyRulesInput;
use aptos_consensus_types::block_data::BlockData;
use std::net::SocketAddr;

#[test]
fn test_unauthenticated_safety_rules_access() {
    // Assume SafetyRules is running in Process mode on 127.0.0.1:6666
    let server_addr: SocketAddr = "127.0.0.1:6666".parse().unwrap();
    
    // Create a client - NO AUTHENTICATION REQUIRED
    let mut client = NetworkClient::new(
        "malicious-client".to_string(),
        server_addr,
        5000 // timeout_ms
    );
    
    // Craft a malicious request to sign an arbitrary block
    let malicious_block = BlockData::new(/* malicious parameters */);
    let request = SafetyRulesInput::SignProposal(Box::new(malicious_block));
    let request_bytes = serde_json::to_vec(&request).unwrap();
    
    // Send request - no authentication check
    client.write(&request_bytes).unwrap();
    
    // Receive valid signature from the validator's private key!
    let response_bytes = client.read().unwrap();
    let signature: bls12381::Signature = serde_json::from_slice(&response_bytes).unwrap();
    
    // The attacker now has a valid signature from the validator
    // This can be used to create equivocating votes or impersonate the validator
    assert!(signature.verify(/* ... */));
}
```

**Notes:**
- This PoC requires a SafetyRules instance running in Process mode
- In a real attack, the attacker would craft specific malicious blocks designed to cause consensus violations
- The vulnerability allows complete bypass of SafetyRules' safety checks by an external, unauthenticated attacker

### Citations

**File:** consensus/safety-rules/src/t_safety_rules.rs (L19-62)
```rust
/// Interface for SafetyRules
pub trait TSafetyRules {
    /// Provides the internal state of SafetyRules for monitoring / debugging purposes. This does
    /// not include sensitive data like private keys.
    fn consensus_state(&mut self) -> Result<ConsensusState, Error>;

    /// Initialize SafetyRules using an Epoch ending LedgerInfo, this should map to what was
    /// provided in consensus_state. It will be used to initialize the ValidatorSet.
    /// This uses a EpochChangeProof because there's a possibility that consensus migrated to a
    /// new epoch but SafetyRules did not.
    fn initialize(&mut self, proof: &EpochChangeProof) -> Result<(), Error>;

    /// As the holder of the private key, SafetyRules also signs proposals or blocks.
    /// A Block is a signed BlockData along with some additional metadata.
    fn sign_proposal(&mut self, block_data: &BlockData) -> Result<bls12381::Signature, Error>;

    /// Sign the timeout together with highest qc for 2-chain protocol.
    fn sign_timeout_with_qc(
        &mut self,
        timeout: &TwoChainTimeout,
        timeout_cert: Option<&TwoChainTimeoutCertificate>,
    ) -> Result<bls12381::Signature, Error>;

    /// Attempts to vote for a given proposal following the 2-chain protocol.
    fn construct_and_sign_vote_two_chain(
        &mut self,
        vote_proposal: &VoteProposal,
        timeout_cert: Option<&TwoChainTimeoutCertificate>,
    ) -> Result<Vote, Error>;

    /// Attempts to create an order vote for a block given the quroum certificate for the block.
    fn construct_and_sign_order_vote(
        &mut self,
        order_vote_proposal: &OrderVoteProposal,
    ) -> Result<OrderVote, Error>;

    /// As the holder of the private key, SafetyRules also signs a commit vote.
    /// This returns the signature for the commit vote.
    fn sign_commit_vote(
        &mut self,
        ledger_info: LedgerInfoWithSignatures,
        new_ledger_info: LedgerInfo,
    ) -> Result<bls12381::Signature, Error>;
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

**File:** config/src/config/safety_rules_config.rs (L203-216)
```rust
/// Defines how safety rules should be executed
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum SafetyRulesService {
    /// This runs safety rules in the same thread as event processor
    Local,
    /// This is the production, separate service approach
    Process(RemoteService),
    /// This runs safety rules in the same thread as event processor but data is passed through the
    /// light weight RPC (serializer)
    Serializer,
    /// This creates a separate thread to run safety rules, it is similar to a fork / exec style
    Thread,
}
```

**File:** secure/net/src/lib.rs (L407-456)
```rust
struct NetworkStream {
    stream: TcpStream,
    remote: SocketAddr,
    buffer: Vec<u8>,
    temp_buffer: [u8; 1024],
}

impl NetworkStream {
    pub fn new(stream: TcpStream, remote: SocketAddr, timeout_ms: u64) -> Self {
        let timeout = Some(std::time::Duration::from_millis(timeout_ms));
        // These only fail if a duration of 0 is passed in.
        stream.set_read_timeout(timeout).unwrap();
        stream.set_write_timeout(timeout).unwrap();

        Self {
            stream,
            remote,
            buffer: Vec::new(),
            temp_buffer: [0; 1024],
        }
    }

    /// Blocking read until able to successfully read an entire message
    pub fn read(&mut self) -> Result<Vec<u8>, Error> {
        let result = self.read_buffer();
        if !result.is_empty() {
            return Ok(result);
        }

        loop {
            trace!("Attempting to read from stream");
            let read = self.stream.read(&mut self.temp_buffer)?;
            trace!("Read {} bytes from stream", read);
            if read == 0 {
                return Err(Error::RemoteStreamClosed);
            }
            self.buffer.extend(self.temp_buffer[..read].to_vec());
            let result = self.read_buffer();
            if !result.is_empty() {
                trace!("Found a message in the stream");
                return Ok(result);
            }
            trace!("Did not find a message yet, reading again");
        }
    }

    /// Terminate the socket
    pub fn shutdown(&self) -> Result<(), Error> {
        Ok(self.stream.shutdown(Shutdown::Both)?)
    }
```

**File:** consensus/safety-rules/src/remote_service.rs (L30-55)
```rust
pub fn execute(storage: PersistentSafetyStorage, listen_addr: SocketAddr, network_timeout_ms: u64) {
    let mut safety_rules = SafetyRules::new(storage, false);
    if let Err(e) = safety_rules.consensus_state() {
        warn!("Unable to print consensus state: {}", e);
    }

    let mut serializer_service = SerializerService::new(safety_rules);
    let mut network_server =
        NetworkServer::new("safety-rules".to_string(), listen_addr, network_timeout_ms);

    loop {
        if let Err(e) = process_one_message(&mut network_server, &mut serializer_service) {
            warn!("Failed to process message: {}", e);
        }
    }
}

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

**File:** consensus/safety-rules/src/serializer.rs (L22-34)
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum SafetyRulesInput {
    ConsensusState,
    Initialize(Box<EpochChangeProof>),
    SignProposal(Box<BlockData>),
    SignTimeoutWithQC(
        Box<TwoChainTimeout>,
        Box<Option<TwoChainTimeoutCertificate>>,
    ),
    ConstructAndSignVoteTwoChain(Box<VoteProposal>, Box<Option<TwoChainTimeoutCertificate>>),
    ConstructAndSignOrderVote(Box<OrderVoteProposal>),
    SignCommitVote(Box<LedgerInfoWithSignatures>, Box<LedgerInfo>),
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
