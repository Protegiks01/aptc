# Audit Report

## Title
Absence of Rate Limiting on Safety Rules Service Requests in Process/Thread Mode

## Summary
The safety rules service in Process/Thread mode lacks rate limiting on incoming `SafetyRulesInput` requests. While this creates a potential resource exhaustion vector, the practical exploitability is limited by architectural constraints and configuration requirements that prevent this from being a critical security vulnerability.

## Finding Description

The safety rules service, when running in Process or Thread mode, processes requests through an infinite loop without any rate limiting mechanism. [1](#0-0) 

The `execute()` function continuously calls `process_one_message()` which reads a request, processes it via `SerializerService.handle_message()`, and writes the response back: [2](#0-1) 

Each `SafetyRulesInput` request can trigger computationally expensive BLS signature operations: [3](#0-2) 

The processing logic handles these requests synchronously: [4](#0-3) 

The underlying `NetworkServer` provides no rate limiting—only a per-operation timeout: [5](#0-4) 

**However, there are critical architectural constraints:**

1. **Mainnet validators are required to use Local mode**, which eliminates this code path entirely: [6](#0-5) 

2. The safety rules service is only accessible to the local consensus module within the same validator node, not to external network peers.

3. The consensus module itself contains safety checks that provide natural rate limiting (e.g., round progression requirements): [7](#0-6) 

## Impact Explanation

**Theoretical Impact**: If exploited, this could cause validator node slowdown through CPU exhaustion from processing excessive signature requests and JSON deserialization.

**Practical Impact Limitations**:
- Only affects testnet/devnet deployments using Process/Thread mode
- Requires control over the consensus module (insider threat)
- Does not affect network consensus safety or other validators
- Mainnet is explicitly protected by configuration enforcement

This would rate as **Medium severity** per bug bounty criteria (validator slowdown), but only in non-production environments.

## Likelihood Explanation

**Low likelihood** for the following reasons:

1. **Configuration Enforcement**: Mainnet validators cannot use Process/Thread mode due to config sanitization
2. **Access Control**: Only the local consensus module can connect to the safety rules service
3. **Trust Model Violation**: Exploitation requires either:
   - A malicious consensus module (insider threat—validator operators are trusted per the security model)
   - A severe bug in consensus code causing request flooding (not a vulnerability per se)
4. **Natural Rate Limiting**: Safety rules checks (round progression, epoch verification) provide some inherent protection

## Recommendation

Despite the limited practical exploitability, implementing rate limiting would improve defense-in-depth for testnet/devnet deployments and protect against consensus module bugs.

**Recommended fix**: Add a token bucket rate limiter to the safety rules service:

```rust
// In remote_service.rs, add rate limiting using the existing aptos-rate-limiter crate
use aptos_rate_limiter::rate_limit::{TokenBucketRateLimiter, Bucket};

pub fn execute(storage: PersistentSafetyStorage, listen_addr: SocketAddr, network_timeout_ms: u64) {
    let mut safety_rules = SafetyRules::new(storage, false);
    let mut serializer_service = SerializerService::new(safety_rules);
    let mut network_server = NetworkServer::new("safety-rules".to_string(), listen_addr, network_timeout_ms);
    
    // Add rate limiter: 100 requests per second with burst of 10
    let rate_limiter = TokenBucketRateLimiter::new(
        Bucket::new(100, 100), // 100 tokens/sec capacity
        10, // burst size
    );
    
    loop {
        // Check rate limit before processing
        if rate_limiter.try_consume(1).is_err() {
            warn!("Rate limit exceeded for safety rules requests");
            thread::sleep(Duration::from_millis(100));
            continue;
        }
        
        if let Err(e) = process_one_message(&mut network_server, &mut serializer_service) {
            warn!("Failed to process message: {}", e);
        }
    }
}
```

## Proof of Concept

**Note**: This PoC demonstrates the absence of rate limiting but cannot demonstrate practical exploitation due to architectural constraints (requires local consensus module access).

```rust
// Test demonstrating lack of rate limiting (for testnet/devnet with Process mode)
#[test]
fn test_no_rate_limiting_on_safety_rules_requests() {
    use std::net::{TcpStream, SocketAddr};
    use std::io::Write;
    
    // Setup safety rules service in Process mode
    let server_addr: SocketAddr = "127.0.0.1:6666".parse().unwrap();
    // (Service setup code omitted for brevity)
    
    // Simulate rapid request flooding
    let mut stream = TcpStream::connect(server_addr).unwrap();
    let request = create_consensus_state_request(); // SafetyRulesInput::ConsensusState
    
    // Send 1000 requests rapidly - no rate limiting will prevent this
    for _ in 0..1000 {
        stream.write_all(&request).unwrap();
        // All requests are processed without rate limiting
    }
    
    // In a system with rate limiting, later requests would be rejected/delayed
    // Without it, all 1000 requests are processed, consuming CPU resources
}
```

---

**Validation Assessment**: This issue **FAILS** the validation criteria for a reportable vulnerability because:
- ❌ **Not exploitable by unprivileged attacker**: Requires control of the consensus module (insider threat)
- ❌ **Mainnet protection**: Config sanitizer enforces Local mode, eliminating this code path in production
- ⚠️ **Limited scope**: Only affects testnet/devnet, single validator, no network-wide impact

**Conclusion**: While rate limiting is absent and should be added for defense-in-depth, this does not constitute a concrete, exploitable vulnerability by unprivileged attackers under the current trust model and deployment constraints.

### Citations

**File:** consensus/safety-rules/src/remote_service.rs (L30-45)
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

**File:** consensus/safety-rules/src/safety_rules.rs (L346-370)
```rust
    fn guarded_sign_proposal(
        &mut self,
        block_data: &BlockData,
    ) -> Result<bls12381::Signature, Error> {
        self.signer()?;
        self.verify_author(block_data.author())?;

        let mut safety_data = self.persistent_storage.safety_data()?;
        self.verify_epoch(block_data.epoch(), &safety_data)?;

        if block_data.round() <= safety_data.last_voted_round {
            return Err(Error::InvalidProposal(format!(
                "Proposed round {} is not higher than last voted round {}",
                block_data.round(),
                safety_data.last_voted_round
            )));
        }

        self.verify_qc(block_data.quorum_cert())?;
        self.verify_and_update_preferred_round(block_data.quorum_cert(), &mut safety_data)?;
        // we don't persist the updated preferred round to save latency (it'd be updated upon voting)

        let signature = self.sign(block_data)?;
        Ok(signature)
    }
```
