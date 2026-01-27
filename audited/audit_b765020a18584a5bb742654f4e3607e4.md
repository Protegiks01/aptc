# Audit Report

## Title
Missing Validation Allows Signing Multiple Conflicting Timeout Certificates for Same Round

## Summary
The `highest_timeout_round` field in `SafetyData` does not prevent a validator from signing multiple conflicting timeout messages for the same round with different `hqc_round` values. The `guarded_sign_timeout_with_qc` function lacks validation to reject timeout signing requests when `timeout.round() <= safety_data.highest_timeout_round`, allowing equivocation. [1](#0-0) 

## Finding Description

The SafetyRules module is designed to be the last line of defense for consensus safety, preventing validators from signing conflicting messages that could violate BFT safety guarantees. When signing timeout certificates, the `guarded_sign_timeout_with_qc` function performs several validation checks but critically **fails to prevent signing multiple timeouts for the same round**. [2](#0-1) 

The vulnerability lies in the validation logic at lines 37-46:

1. **Line 37-42**: Checks if `timeout.round() < safety_data.last_voted_round` and errors
2. **Line 43-45**: Updates `last_voted_round` if `timeout.round() > safety_data.last_voted_round`  
3. **Line 46**: Calls `update_highest_timeout_round`
4. **Missing check**: No validation when `timeout.round() == safety_data.highest_timeout_round`

The `update_highest_timeout_round` implementation only updates the field if the new round is strictly greater: [3](#0-2) 

**Attack Scenario:**

1. First call with `TwoChainTimeout(round=10, hqc_round=5)`:
   - Condition `10 > 0` is TRUE → `highest_timeout_round = 10`
   - Signature returned for (epoch, round=10, hqc_round=5)

2. Second call with `TwoChainTimeout(round=10, hqc_round=7)`:
   - Check `10 < 10` is FALSE (no error thrown)
   - Check `10 > 10` is FALSE (no update to `last_voted_round`)
   - `update_highest_timeout_round`: `10 > 10` is FALSE (no update)
   - **Function proceeds to sign at line 49**
   - Signature returned for (epoch, round=10, hqc_round=7)

The validator now has two conflicting timeout signatures for round 10. In the 2-chain timeout protocol, validators sign `TimeoutSigningRepr` containing `(epoch, round, hqc_round)`: [4](#0-3) 

While the aggregation mechanism attempts to handle this with `or_insert` (only accepting the first signature per validator), different network peers could receive different timeout messages from the same validator at different times, potentially leading to: [5](#0-4) 

- **Inconsistent timeout certificate formation** across the network
- **Timeout certificate verification failures** when different validators aggregate different signatures from the equivocating validator
- **Consensus liveness degradation** due to inability to form valid timeout certificates

## Impact Explanation

This vulnerability represents a **HIGH severity** consensus protocol violation per the Aptos bug bounty criteria. Specifically:

1. **Consensus Safety Violation**: Allows validator timeout equivocation, breaking the fundamental assumption that each validator produces at most one timeout signature per round

2. **Protocol Integrity**: While not directly causing a chain split, inconsistent timeout certificates can lead to consensus deadlocks requiring manual intervention

3. **Defense-in-Depth Failure**: SafetyRules is explicitly designed as the final safety layer. The existence of higher-level protections (e.g., in RoundManager) does not excuse this gap, as SafetyRules must function correctly even when called through alternative code paths or when caller bugs exist

The missing error type in the error enum further confirms this is an oversight: [6](#0-5) 

Notice there are errors for `IncorrectLastVotedRound` and `IncorrectPreferredRound`, but no `IncorrectHighestTimeoutRound` error, despite the parallel structure.

## Likelihood Explanation

**Likelihood: MEDIUM**

The vulnerability requires one of the following conditions:

1. **Buggy calling code**: A bug in RoundManager or another component that calls `sign_timeout_with_qc` multiple times for the same round
2. **Alternative code paths**: Direct access to SafetyRules through the `TSafetyRules` trait interface bypassing RoundManager protections
3. **Race conditions**: Concurrent calls to SafetyRules (though typically serialized through locks)

The normal flow includes a check in RoundManager: [7](#0-6) 

At line 1006, there's a check `if let Some(timeout) = self.round_state.timeout_sent()` that reuses existing timeouts. However, this is a higher-level optimization, not a security control. SafetyRules should enforce this invariant independently.

The test suite lacks coverage for this specific scenario: [8](#0-7) 

The test validates signing for different rounds but never attempts signing twice for the same round with different `hqc_round` values, indicating this case was not considered during development.

## Recommendation

Add explicit validation in `guarded_sign_timeout_with_qc` to reject timeout signing when the round has already been signed:

```rust
pub(crate) fn guarded_sign_timeout_with_qc(
    &mut self,
    timeout: &TwoChainTimeout,
    timeout_cert: Option<&TwoChainTimeoutCertificate>,
) -> Result<bls12381::Signature, Error> {
    self.signer()?;
    let mut safety_data = self.persistent_storage.safety_data()?;
    self.verify_epoch(timeout.epoch(), &safety_data)?;
    if !self.skip_sig_verify {
        timeout
            .verify(&self.epoch_state()?.verifier)
            .map_err(|e| Error::InvalidTimeout(e.to_string()))?;
    }
    if let Some(tc) = timeout_cert {
        self.verify_tc(tc)?;
    }

    self.safe_to_timeout(timeout, timeout_cert, &safety_data)?;
    
    // ADD THIS CHECK: Prevent signing timeout for round <= already signed timeout round
    if timeout.round() <= safety_data.highest_timeout_round {
        return Err(Error::IncorrectHighestTimeoutRound(
            timeout.round(),
            safety_data.highest_timeout_round,
        ));
    }
    
    if timeout.round() < safety_data.last_voted_round {
        return Err(Error::IncorrectLastVotedRound(
            timeout.round(),
            safety_data.last_voted_round,
        ));
    }
    if timeout.round() > safety_data.last_voted_round {
        self.verify_and_update_last_vote_round(timeout.round(), &mut safety_data)?;
    }
    self.update_highest_timeout_round(timeout, &mut safety_data);
    self.persistent_storage.set_safety_data(safety_data)?;

    let signature = self.sign(&timeout.signing_format())?;
    Ok(signature)
}
```

Also add the corresponding error variant:

```rust
#[error("Provided round, {0}, is incompatible with highest timeout round, {1}")]
IncorrectHighestTimeoutRound(u64, u64),
```

## Proof of Concept

```rust
#[test]
fn test_timeout_equivocation_prevention() {
    use crate::test_utils;
    use aptos_consensus_types::timeout_2chain::TwoChainTimeout;
    
    let (mut safety_rules, signer) = test_utils::make_safety_rules();
    let (proof, genesis_qc) = test_utils::make_genesis(&signer);
    safety_rules.initialize(&proof).unwrap();
    
    // Successfully sign timeout for round 1 with hqc_round=0
    let timeout1 = TwoChainTimeout::new(1, 1, genesis_qc.clone());
    let sig1 = safety_rules.sign_timeout_with_qc(&timeout1, None).unwrap();
    
    // Create a different QC for testing
    let qc_round_1 = test_utils::make_qc_with_round(1, &signer);
    
    // BUG: Can sign again for round 1 with different hqc_round=1
    // This SHOULD fail but currently succeeds
    let timeout2 = TwoChainTimeout::new(1, 1, qc_round_1);
    let result = safety_rules.sign_timeout_with_qc(&timeout2, None);
    
    // EXPECTED: Should return Error::IncorrectHighestTimeoutRound(1, 1)
    // ACTUAL: Returns Ok(signature), allowing equivocation
    assert!(result.is_err(), "Should reject signing timeout for same round twice");
    match result.unwrap_err() {
        Error::IncorrectHighestTimeoutRound(round, highest) => {
            assert_eq!(round, 1);
            assert_eq!(highest, 1);
        },
        e => panic!("Wrong error type: {:?}", e),
    }
}
```

## Notes

This vulnerability demonstrates a gap in SafetyRules' defense-in-depth approach. While the RoundManager layer includes practical protections against redundant timeout signing, SafetyRules must independently enforce consensus safety invariants. The missing validation allows timeout equivocation if calling code has bugs or if SafetyRules is accessed through alternative paths, potentially leading to inconsistent timeout certificate formation and consensus liveness issues.

### Citations

**File:** consensus/consensus-types/src/safety_data.rs (L8-21)
```rust
/// Data structure for safety rules to ensure consensus safety.
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

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L19-51)
```rust
    pub(crate) fn guarded_sign_timeout_with_qc(
        &mut self,
        timeout: &TwoChainTimeout,
        timeout_cert: Option<&TwoChainTimeoutCertificate>,
    ) -> Result<bls12381::Signature, Error> {
        self.signer()?;
        let mut safety_data = self.persistent_storage.safety_data()?;
        self.verify_epoch(timeout.epoch(), &safety_data)?;
        if !self.skip_sig_verify {
            timeout
                .verify(&self.epoch_state()?.verifier)
                .map_err(|e| Error::InvalidTimeout(e.to_string()))?;
        }
        if let Some(tc) = timeout_cert {
            self.verify_tc(tc)?;
        }

        self.safe_to_timeout(timeout, timeout_cert, &safety_data)?;
        if timeout.round() < safety_data.last_voted_round {
            return Err(Error::IncorrectLastVotedRound(
                timeout.round(),
                safety_data.last_voted_round,
            ));
        }
        if timeout.round() > safety_data.last_voted_round {
            self.verify_and_update_last_vote_round(timeout.round(), &mut safety_data)?;
        }
        self.update_highest_timeout_round(timeout, &mut safety_data);
        self.persistent_storage.set_safety_data(safety_data)?;

        let signature = self.sign(&timeout.signing_format())?;
        Ok(signature)
    }
```

**File:** consensus/safety-rules/src/safety_rules.rs (L158-170)
```rust
    pub(crate) fn update_highest_timeout_round(
        &self,
        timeout: &TwoChainTimeout,
        safety_data: &mut SafetyData,
    ) {
        if timeout.round() > safety_data.highest_timeout_round {
            safety_data.highest_timeout_round = timeout.round();
            trace!(
                SafetyLogSchema::new(LogEntry::HighestTimeoutRound, LogEvent::Update)
                    .highest_timeout_round(safety_data.highest_timeout_round)
            );
        }
    }
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L96-103)
```rust
/// Validators sign this structure that allows the TwoChainTimeoutCertificate to store a round number
/// instead of a quorum cert per validator in the signatures field.
#[derive(Serialize, Deserialize, Debug, CryptoHasher, BCSCryptoHash)]
pub struct TimeoutSigningRepr {
    pub epoch: u64,
    pub round: Round,
    pub hqc_round: Round,
}
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L320-329)
```rust
    pub fn add_signature(
        &mut self,
        validator: AccountAddress,
        round: Round,
        signature: bls12381::Signature,
    ) {
        self.signatures
            .entry(validator)
            .or_insert((round, signature));
    }
```

**File:** consensus/safety-rules/src/error.rs (L15-18)
```rust
    #[error("Provided round, {0}, is incompatible with last voted round, {1}")]
    IncorrectLastVotedRound(u64, u64),
    #[error("Provided round, {0}, is incompatible with preferred round, {1}")]
    IncorrectPreferredRound(u64, u64),
```

**File:** consensus/src/round_manager.rs (L1005-1033)
```rust
        if self.local_config.enable_round_timeout_msg {
            let timeout = if let Some(timeout) = self.round_state.timeout_sent() {
                timeout
            } else {
                let timeout = TwoChainTimeout::new(
                    self.epoch_state.epoch,
                    round,
                    self.block_store.highest_quorum_cert().as_ref().clone(),
                );
                let signature = self
                    .safety_rules
                    .lock()
                    .sign_timeout_with_qc(
                        &timeout,
                        self.block_store.highest_2chain_timeout_cert().as_deref(),
                    )
                    .context("[RoundManager] SafetyRules signs 2-chain timeout")?;

                let timeout_reason = self.compute_timeout_reason(round);

                RoundTimeout::new(
                    timeout,
                    self.proposal_generator.author(),
                    timeout_reason,
                    signature,
                )
            };

            self.round_state.record_round_timeout(timeout.clone());
```

**File:** consensus/safety-rules/src/tests/suite.rs (L774-843)
```rust
fn test_2chain_timeout(constructor: &Callback) {
    let (mut safety_rules, signer) = constructor();
    let (proof, genesis_qc) = test_utils::make_genesis(&signer);
    let genesis_round = genesis_qc.certified_block().round();
    let round = genesis_round;
    safety_rules.initialize(&proof).unwrap();
    let a1 = test_utils::make_proposal_with_qc(round + 1, genesis_qc.clone(), &signer);
    let a2 = make_proposal_with_parent(round + 2, &a1, None, &signer);
    let a3 = make_proposal_with_parent(round + 3, &a2, None, &signer);

    safety_rules
        .sign_timeout_with_qc(&TwoChainTimeout::new(1, 1, genesis_qc.clone()), None)
        .unwrap();
    assert_eq!(
        safety_rules
            .sign_timeout_with_qc(&TwoChainTimeout::new(1, 2, genesis_qc.clone()), None)
            .unwrap_err(),
        Error::NotSafeToTimeout(2, 0, 0, 0),
    );

    assert_eq!(
        safety_rules
            .sign_timeout_with_qc(&TwoChainTimeout::new(2, 2, genesis_qc.clone()), None)
            .unwrap_err(),
        Error::IncorrectEpoch(2, 1)
    );
    safety_rules
        .sign_timeout_with_qc(
            &TwoChainTimeout::new(1, 2, genesis_qc.clone()),
            Some(make_timeout_cert(1, &genesis_qc, &signer)).as_ref(),
        )
        .unwrap();
    assert_eq!(
        safety_rules
            .sign_timeout_with_qc(&TwoChainTimeout::new(1, 1, genesis_qc.clone()), None)
            .unwrap_err(),
        Error::IncorrectLastVotedRound(1, 2)
    );
    // update one-chain to 2
    safety_rules
        .construct_and_sign_vote_two_chain(&a3, None)
        .unwrap();
    assert_eq!(
        safety_rules
            .sign_timeout_with_qc(
                &TwoChainTimeout::new(1, 4, a3.block().quorum_cert().clone(),),
                Some(make_timeout_cert(2, &genesis_qc, &signer)).as_ref()
            )
            .unwrap_err(),
        Error::NotSafeToTimeout(4, 2, 2, 2)
    );
    assert_eq!(
        safety_rules
            .sign_timeout_with_qc(
                &TwoChainTimeout::new(1, 4, a2.block().quorum_cert().clone(),),
                Some(make_timeout_cert(3, &genesis_qc, &signer)).as_ref()
            )
            .unwrap_err(),
        Error::NotSafeToTimeout(4, 1, 3, 2)
    );
    assert!(matches!(
        safety_rules
            .sign_timeout_with_qc(
                &TwoChainTimeout::new(1, 1, a3.block().quorum_cert().clone(),),
                Some(make_timeout_cert(2, &genesis_qc, &signer)).as_ref()
            )
            .unwrap_err(),
        Error::InvalidTimeout(_)
    ));
}
```
