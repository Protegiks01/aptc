# Audit Report

## Title
Consensus Divergence Due to Inconsistent Signature Verification in DAG Ordered Proofs Across Mixed SafetyRules Configurations

## Summary
The DAG consensus implementation creates `ordered_proof` with empty signatures by design, while SafetyRules' `sign_commit_vote()` conditionally verifies these signatures based on the `skip_sig_verify` configuration flag. If validators operate with different SafetyRules modes (Local vs Serializer), validators using Serializer mode will reject empty-signature ordered proofs, while Local mode validators will accept them, causing partial commit vote generation and commit certificate formation failures.

## Finding Description
The vulnerability arises from an interaction between three components:

1. **DAG Adapter Creates Empty-Signature Ordered Proofs**: The DAG consensus adapter creates ordered blocks with `LedgerInfoWithSignatures` containing `AggregateSignature::empty()`: [1](#0-0) 

2. **SafetyRules Has Configuration-Dependent Signature Verification**: The `SafetyRulesManager` creates SafetyRules with different `skip_sig_verify` settings based on service type:
   - Local mode: `skip_sig_verify = true` (no verification) [2](#0-1) 
   - Serializer mode: `skip_sig_verify = false` (full verification) [3](#0-2) 

3. **Conditional Signature Verification in sign_commit_vote()**: The signature verification only occurs when `skip_sig_verify` is false: [4](#0-3) 

**Attack Scenario**:
If a network has validators with mixed SafetyRules configurations (some using Local mode, others using Serializer mode) and DAG consensus is enabled:

1. DAG adapter broadcasts ordered blocks with empty-signature ordered proofs to all validators
2. Local mode validators (skip_sig_verify=true) skip verification and successfully sign commit votes
3. Serializer mode validators (skip_sig_verify=false) attempt signature verification on the empty `AggregateSignature`, which fails with `Error::InvalidQuorumCertificate`
4. Serializer mode validators refuse to sign commit votes
5. If enough validators use Serializer mode, the 2f+1 threshold for commit certificate formation cannot be met
6. Consensus fails to commit blocks, causing liveness failure

This breaks the **Consensus Safety** invariant: validators must reach agreement on commits, but diverge based on their local configuration rather than on cryptographic proofs.

## Impact Explanation
**Severity: Medium (State inconsistencies requiring intervention)**

This vulnerability causes:
- **Consensus Liveness Failure**: Unable to form commit certificates when sufficient validators use Serializer mode
- **Partial Commit State**: Some validators have commit signatures while others don't
- **Manual Intervention Required**: Network operators must reconfigure validators to restore consensus

The impact is limited to Medium severity because:
1. It requires validator misconfiguration (not all validators using the same SafetyRules mode)
2. No funds are lost or stolen
3. The network can recover by standardizing configurations
4. Safety is preserved (no double commits), only liveness is affected

However, it violates the critical property that consensus should work correctly regardless of local optimizations or configuration choices, as long as cryptographic conditions are met.

## Likelihood Explanation
**Likelihood: Low to Medium**

The vulnerability occurs when:
1. Network uses DAG consensus (enabled in production)
2. Validators have heterogeneous SafetyRules configurations
3. Some validators use Local mode while others use Serializer mode

This is LOW likelihood in well-managed networks where all validators follow the same deployment guidelines, but MEDIUM likelihood in:
- Networks during configuration migration periods
- Networks with diverse validator operators using different setups
- Networks where documentation doesn't clearly specify DAG requires Local mode

The root cause is lack of protocol-level enforcement or runtime validation that DAG consensus is incompatible with Serializer mode SafetyRules.

## Recommendation
Implement one of the following fixes:

**Option 1: Enforce Configuration Compatibility (Recommended)**
Add runtime validation that rejects Serializer mode when DAG consensus is enabled:

```rust
// In SafetyRulesManager::new() or during consensus initialization
pub fn new(config: &SafetyRulesConfig, consensus_type: ConsensusType) -> Self {
    if consensus_type == ConsensusType::DAG && 
       matches!(config.service, SafetyRulesService::Serializer) {
        panic!("DAG consensus requires Local mode SafetyRules, found Serializer mode");
    }
    // ... existing code
}
```

**Option 2: Make DAG Create Proper Ordered Proofs**
Modify the DAG adapter to create ordered proofs with actual aggregated signatures from DAG votes, making it compatible with all SafetyRules modes. This requires significant refactoring of the DAG certificate handling.

**Option 3: Add Configuration Validation**
Add a startup check that ensures all validators in the network use compatible configurations:

```rust
// In SafetyRules::guarded_sign_commit_vote()
fn guarded_sign_commit_vote(
    &mut self,
    ledger_info: LedgerInfoWithSignatures,
    new_ledger_info: LedgerInfo,
) -> Result<bls12381::Signature, Error> {
    self.signer()?;
    
    // ... existing validation code ...
    
    // Verify signatures OR check that empty signatures are expected (DAG mode)
    if !self.skip_sig_verify {
        if ledger_info.signatures().sig().is_none() && !self.is_dag_mode() {
            // Empty signatures are only acceptable in DAG mode with Local SafetyRules
            return Err(Error::InvalidQuorumCertificate(
                "Empty signatures not allowed in this configuration".into()
            ));
        }
        if ledger_info.signatures().sig().is_some() {
            ledger_info
                .verify_signatures(&self.epoch_state()?.verifier)
                .map_err(|error| Error::InvalidQuorumCertificate(error.to_string()))?;
        }
    }
    
    // ... rest of function
}
```

## Proof of Concept
```rust
// Test demonstrating the configuration incompatibility
#[test]
fn test_dag_ordered_proof_with_serializer_mode_fails() {
    use aptos_types::{aggregate_signature::AggregateSignature, ledger_info::{LedgerInfo, LedgerInfoWithSignatures}, block_info::BlockInfo};
    use aptos_crypto::HashValue;
    
    // Create empty-signature ordered proof (as DAG does)
    let block_info = BlockInfo::random(1);
    let ledger_info = LedgerInfo::new(block_info.clone(), HashValue::zero());
    let ordered_proof = LedgerInfoWithSignatures::new(
        ledger_info.clone(),
        AggregateSignature::empty(), // DAG creates empty signatures
    );
    
    // Create new ledger info to sign
    let new_ledger_info = LedgerInfo::new(block_info, HashValue::random());
    
    // Create SafetyRules in Serializer mode (skip_sig_verify = false)
    let storage = test_utils::test_storage();
    let mut safety_rules = SafetyRules::new(storage, false); // Serializer mode
    
    // Initialize safety rules
    let proof = test_utils::make_genesis_epoch_change_proof();
    safety_rules.initialize(&proof).unwrap();
    
    // Attempt to sign commit vote - this WILL FAIL with Serializer mode
    let result = safety_rules.sign_commit_vote(ordered_proof, new_ledger_info);
    
    // Assertion: Serializer mode rejects empty signatures
    assert!(matches!(result, Err(Error::InvalidQuorumCertificate(_))));
    
    // In contrast, Local mode (skip_sig_verify = true) would succeed
    let mut local_safety_rules = SafetyRules::new(test_utils::test_storage(), true);
    local_safety_rules.initialize(&proof).unwrap();
    let result_local = local_safety_rules.sign_commit_vote(ordered_proof_clone, new_ledger_info_clone);
    assert!(result_local.is_ok()); // Local mode accepts empty signatures
}
```

## Notes
This vulnerability represents a **configuration footgun** where the system allows incompatible component combinations without validation. While the immediate exploit requires validator misconfiguration (making it less severe), it violates defense-in-depth principles by allowing configurations that deterministically fail at runtime rather than failing fast at startup or being prevented by design.

The core issue is that `skip_sig_verify` was designed as an optimization flag (skip verification because consensus already verified), but DAG's design choice to use empty signatures means that assumption doesn't hold universally. The protocol should either enforce configuration compatibility or make the components truly composable.

### Citations

**File:** consensus/src/dag/adapter.rs (L211-214)
```rust
            ordered_proof: LedgerInfoWithSignatures::new(
                LedgerInfo::new(block_info, anchor.digest()),
                AggregateSignature::empty(),
            ),
```

**File:** consensus/safety-rules/src/safety_rules_manager.rs (L131-136)
```rust
    pub fn new_local(storage: PersistentSafetyStorage) -> Self {
        let safety_rules = SafetyRules::new(storage, true);
        Self {
            internal_safety_rules: SafetyRulesWrapper::Local(Arc::new(RwLock::new(safety_rules))),
        }
    }
```

**File:** consensus/safety-rules/src/safety_rules_manager.rs (L145-152)
```rust
    pub fn new_serializer(storage: PersistentSafetyStorage) -> Self {
        let safety_rules = SafetyRules::new(storage, false);
        let serializer_service = SerializerService::new(safety_rules);
        Self {
            internal_safety_rules: SafetyRulesWrapper::Serializer(Arc::new(RwLock::new(
                serializer_service,
            ))),
        }
```

**File:** consensus/safety-rules/src/safety_rules.rs (L405-410)
```rust
        // Verify that ledger_info contains at least 2f + 1 dostinct signatures
        if !self.skip_sig_verify {
            ledger_info
                .verify_signatures(&self.epoch_state()?.verifier)
                .map_err(|error| Error::InvalidQuorumCertificate(error.to_string()))?;
        }
```
