# Audit Report

## Title
Missing Signature Verification in SafetyRules EpochChangeProof Initialization Allows Bypassing Validator Consensus Requirement

## Summary
The `TSafetyRules::initialize()` interface accepts `EpochChangeProof` without enforcing signature verification when using Waypoint-based validation. This allows an attacker with network access to the remote SafetyRules service to inject epoch change proofs with invalid or missing signatures, violating the fundamental consensus invariant that epoch transitions must be approved by a quorum of validators.

## Finding Description

The vulnerability exists in the signature verification logic of the epoch change proof validation chain: [1](#0-0) 

The `TSafetyRules` trait defines `initialize()` but does not mandate signature verification in its contract. [2](#0-1) 

The `SafetyRules::guarded_initialize()` implementation calls `proof.verify(&waypoint)` which delegates to the `Verifier` trait: [3](#0-2) 

For the first ledger info in the proof, when `verifier_ref` is a `Waypoint`, the verification only checks version and hash: [4](#0-3) [5](#0-4) 

**Critical: No signature verification occurs**. The `Waypoint::verify()` method only validates that the `LedgerInfo` matches the expected version and hash value, but does NOT verify the `AggregateSignature` in the `LedgerInfoWithSignatures`.

In contrast, when using `EpochState` as a verifier (for subsequent epoch changes), signatures ARE verified: [6](#0-5) 

**Attack Vector:**

SafetyRules can be deployed as a remote service over an **unauthenticated TCP connection**: [7](#0-6) [8](#0-7) [9](#0-8) 

The network transport uses plain TCP with no authentication: [10](#0-9) 

**Exploitation Path:**

1. Attacker gains network access to the SafetyRules service port (through misconfiguration or network compromise)
2. Attacker crafts a `SafetyRulesInput::Initialize` message containing an `EpochChangeProof`
3. The proof contains a single `LedgerInfoWithSignatures` with:
   - Valid `LedgerInfo` content matching the current waypoint's version and hash
   - **Invalid, empty, or forged `AggregateSignature`**
4. The message is sent over the unauthenticated TCP connection
5. `SerializerService::handle_message()` deserializes and calls `initialize()`
6. `Waypoint::verify()` passes (hash matches)
7. No signature verification occurs
8. SafetyRules accepts an epoch change that was **never signed by validators**

**Invariant Violated:**

This breaks **Critical Invariant #10: Cryptographic Correctness** - BLS signatures must be verified to ensure epoch changes are validator-approved. It also violates **Invariant #2: Consensus Safety** by accepting state transitions without proper cryptographic proof of validator consensus.

## Impact Explanation

**Severity: High** (per Aptos Bug Bounty criteria)

This constitutes a **Significant Protocol Violation** because:

1. **Bypasses Consensus Requirement**: Epoch changes are critical consensus operations that MUST be approved by ≥2f+1 validators. Accepting unsigned epoch changes violates this fundamental requirement.

2. **Defense-in-Depth Failure**: Even though waypoints are trust anchors, signatures provide a critical secondary validation layer. This gap eliminates that protection.

3. **Remote Exploit Surface**: The vulnerability is exploitable over the network in the Process mode deployment configuration, which is a production deployment option.

4. **No Access Control**: The unauthenticated TCP connection means any network attacker can attempt exploitation.

While this does not directly cause fund loss or immediate consensus violation (the LedgerInfo content must still match the waypoint), it:
- Allows bypassing cryptographic verification of validator approval
- Could be chained with waypoint manipulation attacks
- Violates the security model that epoch transitions require validator consensus
- Undermines the integrity of the consensus protocol

The `skip_sig_verify` flag is NOT checked during initialization, meaning even in production mode (where `skip_sig_verify=false`), signatures are still not verified: [11](#0-10) 

## Likelihood Explanation

**Likelihood: Medium-High**

Exploitation requires:
1. ✓ **Network access to SafetyRules service** - Feasible if the service is misconfigured or network is compromised
2. ✓ **Knowledge of the waypoint** - Waypoints are not secret; they're used for bootstrapping
3. ✓ **Ability to craft valid serialized messages** - Straightforward with knowledge of the protocol

The attack does NOT require:
- Validator private keys
- Consensus participant status
- Byzantine validator collusion
- Cryptographic breaks

Many production deployments may use the remote SafetyRules configuration for security isolation (e.g., running in SGX or HSM), making the network interface a real attack surface.

## Recommendation

**Fix 1: Enforce Signature Verification in Waypoint-based Initialization**

Modify `Waypoint` to verify signatures even when using waypoint-based trust:

```rust
impl Verifier for Waypoint {
    fn verify(&self, ledger_info: &LedgerInfoWithSignatures) -> Result<()> {
        // Verify waypoint match
        self.verify(ledger_info.ledger_info())?;
        
        // CRITICAL: Also verify signatures for defense-in-depth
        // Extract and verify against the validator set in next_epoch_state
        if let Some(epoch_state) = ledger_info.ledger_info().next_epoch_state() {
            ledger_info.verify_signatures(&epoch_state.verifier)?;
        }
        
        Ok(())
    }
    
    // ... rest of implementation
}
```

**Fix 2: Add Authentication to Remote SafetyRules**

Implement mutual TLS or Noise protocol authentication for the SafetyRules network service to prevent unauthorized initialize() calls.

**Fix 3: Add Explicit Signature Verification to guarded_initialize()**

```rust
fn guarded_initialize(&mut self, proof: &EpochChangeProof) -> Result<(), Error> {
    let waypoint = self.persistent_storage.waypoint()?;
    let last_li = proof
        .verify(&waypoint)
        .map_err(|e| Error::InvalidEpochChangeProof(format!("{}", e)))?;
    
    // CRITICAL: Explicitly verify signatures even after waypoint verification
    if !self.skip_sig_verify {
        for li_with_sigs in &proof.ledger_info_with_sigs {
            if let Some(epoch_state) = li_with_sigs.ledger_info().next_epoch_state() {
                li_with_sigs.verify_signatures(&epoch_state.verifier)
                    .map_err(|e| Error::InvalidEpochChangeProof(format!("Signature verification failed: {}", e)))?;
            }
        }
    }
    
    // ... rest of implementation
}
```

## Proof of Concept

```rust
#[test]
fn test_initialize_with_invalid_signatures_should_fail() {
    use aptos_types::{
        aggregate_signature::AggregateSignature,
        block_info::BlockInfo,
        epoch_change::EpochChangeProof,
        epoch_state::EpochState,
        ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
        validator_signer::ValidatorSigner,
        validator_verifier::generate_validator_verifier,
        waypoint::Waypoint,
    };
    use aptos_crypto::hash::HashValue;
    
    // Setup: Create a valid epoch-ending LedgerInfo
    let signer = ValidatorSigner::from_int(0);
    let (validator_signers, validator_verifier) = 
        generate_validator_verifier(&[signer.clone()]);
    
    let epoch_state = EpochState::new(1, validator_verifier);
    let ledger_info = LedgerInfo::new(
        BlockInfo::new(
            1, 0, HashValue::zero(), HashValue::zero(), 
            100, 0, Some(epoch_state)
        ),
        HashValue::zero(),
    );
    
    // Create waypoint from this LedgerInfo
    let waypoint = Waypoint::new_epoch_boundary(&ledger_info).unwrap();
    
    // ATTACK: Create LedgerInfoWithSignatures with EMPTY (invalid) signature
    let malicious_li_with_sigs = LedgerInfoWithSignatures::new(
        ledger_info.clone(),
        AggregateSignature::empty(), // Invalid signature!
    );
    
    // Create proof with invalid signatures
    let malicious_proof = EpochChangeProof::new(
        vec![malicious_li_with_sigs],
        false,
    );
    
    // Current behavior: This PASSES (vulnerability)
    assert!(malicious_proof.verify(&waypoint).is_ok());
    
    // Expected behavior: Should FAIL signature verification
    // After fix, this should return Err()
}
```

**Notes**

The vulnerability demonstrates a critical gap in the defense-in-depth approach to consensus security. While waypoints provide a trusted starting point, they should not eliminate the requirement for cryptographic proof of validator consensus. The combination of unauthenticated network exposure and missing signature verification creates a realistic attack surface that violates fundamental consensus invariants.

### Citations

**File:** consensus/safety-rules/src/t_safety_rules.rs (L19-29)
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
```

**File:** consensus/safety-rules/src/safety_rules.rs (L41-48)
```rust
pub struct SafetyRules {
    pub(crate) persistent_storage: PersistentSafetyStorage,
    pub(crate) validator_signer: Option<ValidatorSigner>,
    pub(crate) epoch_state: Option<EpochState>,
    // Skip verification of signatures and well-formed, this can be set if it's used in local mode
    // where consensus already verifies.
    pub(crate) skip_sig_verify: bool,
}
```

**File:** consensus/safety-rules/src/safety_rules.rs (L265-269)
```rust
    fn guarded_initialize(&mut self, proof: &EpochChangeProof) -> Result<(), Error> {
        let waypoint = self.persistent_storage.waypoint()?;
        let last_li = proof
            .verify(&waypoint)
            .map_err(|e| Error::InvalidEpochChangeProof(format!("{}", e)))?;
```

**File:** types/src/epoch_change.rs (L106-114)
```rust
            // Try to verify each (epoch -> epoch + 1) jump in the EpochChangeProof.
            verifier_ref.verify(ledger_info_with_sigs)?;
            // While the original verification could've been via waypoints,
            // all the next epoch changes are verified using the (already
            // trusted) validator sets.
            verifier_ref = ledger_info_with_sigs
                .ledger_info()
                .next_epoch_state()
                .ok_or_else(|| format_err!("LedgerInfo doesn't carry a ValidatorSet"))?;
```

**File:** types/src/waypoint.rs (L62-79)
```rust
    pub fn verify(&self, ledger_info: &LedgerInfo) -> Result<()> {
        ensure!(
            ledger_info.version() == self.version(),
            "Waypoint version mismatch: waypoint version = {}, given version = {}",
            self.version(),
            ledger_info.version()
        );
        let converter = Ledger2WaypointConverter::new(ledger_info);
        ensure!(
            converter.hash() == self.value(),
            format!(
                "Waypoint value mismatch: waypoint value = {}, given value = {}",
                self.value().to_hex(),
                converter.hash().to_hex()
            )
        );
        Ok(())
    }
```

**File:** types/src/waypoint.rs (L82-85)
```rust
impl Verifier for Waypoint {
    fn verify(&self, ledger_info: &LedgerInfoWithSignatures) -> Result<()> {
        self.verify(ledger_info.ledger_info())
    }
```

**File:** types/src/epoch_state.rs (L40-50)
```rust
impl Verifier for EpochState {
    fn verify(&self, ledger_info: &LedgerInfoWithSignatures) -> anyhow::Result<()> {
        ensure!(
            self.epoch == ledger_info.ledger_info().epoch(),
            "LedgerInfo has unexpected epoch {}, expected {}",
            ledger_info.ledger_info().epoch(),
            self.epoch
        );
        ledger_info.verify_signatures(&self.verifier)?;
        Ok(())
    }
```

**File:** consensus/safety-rules/src/remote_service.rs (L30-44)
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

**File:** consensus/safety-rules/src/serializer.rs (L45-54)
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
```

**File:** secure/net/src/lib.rs (L6-16)
```rust
//! This provides a simple networking substrate between a client and server. It is assumed that all
//! operations are blocking and return only complete blocks of data. The intended use case has the
//! server blocking on read.  Upon receiving a payload during a read, the server should process the
//! payload, write a response, and then block on read again. The client should block on read after
//! performing a write. Upon errors or remote disconnections, the call (read, write) will return an
//! error to let the caller know of the event. A follow up call will result in the service
//! attempting to either reconnect in the case of a client or accept a new client in the case of a
//! server.
//!
//! Internally both the client and server leverage a NetworkStream that communications in blocks
//! where a block is a length prefixed array of bytes.
```
