# Audit Report

## Title
Stale One-Chain Round Values in Order Vote Processing Enable Consensus Safety Violations

## Summary
The `guarded_construct_and_sign_order_vote()` function in the 2-chain consensus protocol calls `observe_qc()` to update `one_chain_round` before performing safety validation. If the subsequent `safe_for_order_vote()` check fails, the function returns an error without persisting the updated state, creating a stale `one_chain_round` value that violates timeout safety invariants.

## Finding Description

In Aptos's 2-chain BFT consensus implementation, validators must maintain accurate tracking of the highest 1-chain round they've observed via the `one_chain_round` field in `SafetyData`. This value is critical for timeout safety checks that prevent validators from signing timeouts with outdated quorum certificates.

**The Vulnerability:**

The order of operations in `guarded_construct_and_sign_order_vote()` is flawed: [1](#0-0) 

At line 108, `observe_qc()` updates `one_chain_round` in the mutable `safety_data` reference: [2](#0-1) 

However, the safety check `safe_for_order_vote()` occurs AFTER this update at line 110: [3](#0-2) 

If `safe_for_order_vote()` fails (when `block.round() <= highest_timeout_round`), the function returns an error before line 117 where `set_safety_data()` would persist the updated state. The in-memory update to `one_chain_round` is discarded.

**Contrast with Correct Implementation:**

The regular voting path performs safety checks BEFORE observing the QC: [4](#0-3) 

Line 81 calls `safe_to_vote()` before line 84 calls `observe_qc()`, ensuring QC observation only happens for proposals that pass safety validation.

**Attack Scenario:**

1. **Initial State:** Validator has `one_chain_round = 1`, `highest_timeout_round = 4` (after signing a timeout)

2. **Trigger:** Network delivers OrderVoteProposal for round 3 with a valid QC certifying round 3
   - Line 108: `observe_qc()` updates `one_chain_round` to 3 in memory
   - Line 110: `safe_for_order_vote(3)` checks: `3 > 4`? NO → Returns error
   - Function exits; `one_chain_round` remains 1 in persistent storage

3. **Exploitation:** Validator receives timeout request for round 5 with QC at round 2
   - Loads `safety_data` with stale `one_chain_round = 1`
   - `safe_to_timeout()` validates: `qc_round(2) >= one_chain_round(1)`? YES [5](#0-4) 
   
   - Validator signs timeout with QC at round 2

4. **Safety Violation:** Validator signed a timeout with QC at round 2 despite having observed and cryptographically verified a QC at round 3. This violates the monotonicity requirement that validators should never sign messages acknowledging only older QCs than they've observed.

## Impact Explanation

This vulnerability violates a fundamental protocol invariant in the 2-chain BFT consensus implementation. The `qc_round >= one_chain_round` check in `safe_to_timeout()` exists specifically to prevent validators from signing timeouts with outdated quorum certificates, ensuring monotonicity in the validator's view of the chain.

**Severity Assessment:**

Per Aptos bug bounty criteria, this constitutes a **protocol violation affecting consensus behavior**:

- **Protocol Invariant Violation**: The explicit safety check `qc_round >= one_chain_round` can be bypassed due to stale state
- **Consensus Impact**: Validators may sign timeout messages that violate 2-chain BFT safety properties
- **Potential for Byzantine Exploitation**: While the bug can trigger naturally, Byzantine actors could deliberately exploit this to construct conflicting timeout certificates or cause consensus disagreements

The impact aligns with "Significant protocol violations" criteria. While the report claims HIGH severity, the concrete demonstration of critical safety failures (double-spending or chain splits) would be required to definitively confirm HIGH vs MEDIUM classification.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

The vulnerability can be triggered in normal network operation without Byzantine behavior:

**Triggering Conditions:**
1. Validator has previously signed a timeout (setting `highest_timeout_round = N`)
2. Network delivers OrderVoteProposal for block at round R where `R ≤ N`
3. The QC in this proposal has `certified_block().round() > one_chain_round`
4. Validator later receives timeout request with QC round between the old and new `one_chain_round` values

**Natural Occurrence:**
- Network asynchrony causes out-of-order message delivery
- Validators experience network partitions during view changes
- Timeout certificates are generated while some validators observe higher QCs
- No Byzantine behavior required to trigger the stale state

## Recommendation

**Fix:** Reorder operations to perform safety validation BEFORE updating state, consistent with the regular voting implementation.

Modified `guarded_construct_and_sign_order_vote()`:

```rust
pub(crate) fn guarded_construct_and_sign_order_vote(
    &mut self,
    order_vote_proposal: &OrderVoteProposal,
) -> Result<OrderVote, Error> {
    self.signer()?;
    self.verify_order_vote_proposal(order_vote_proposal)?;
    let proposed_block = order_vote_proposal.block();
    let mut safety_data = self.persistent_storage.safety_data()?;

    // Perform safety check BEFORE observing QC
    self.safe_for_order_vote(proposed_block, &safety_data)?;
    
    // Only update state if safety check passed
    self.observe_qc(order_vote_proposal.quorum_cert(), &mut safety_data);
    
    let author = self.signer()?.author();
    let ledger_info =
        LedgerInfo::new(order_vote_proposal.block_info().clone(), HashValue::zero());
    let signature = self.sign(&ledger_info)?;
    let order_vote = OrderVote::new_with_signature(author, ledger_info.clone(), signature);
    self.persistent_storage.set_safety_data(safety_data)?;
    Ok(order_vote)
}
```

## Proof of Concept

A complete PoC would require extending the existing test suite at `consensus/safety-rules/src/tests/suite.rs` to add a test case demonstrating the stale state scenario:

```rust
fn test_order_vote_stale_one_chain_round(safety_rules: &Callback) {
    let (mut safety_rules, signer) = safety_rules();
    let (proof, genesis_qc) = test_utils::make_genesis(&signer);
    
    // Setup: Create proposals and timeout to set highest_timeout_round = 4
    // Trigger: Deliver OrderVoteProposal for round 3 with QC at round 3
    //          (should fail safe_for_order_vote but observe QC)
    // Verify: Later timeout request with QC at round 2 incorrectly succeeds
    //         when one_chain_round should be 3, not 1
}
```

## Notes

**Validation Status:**
- ✅ Code evidence verified through direct inspection of source files
- ✅ Vulnerability exists in current codebase
- ✅ Triggering scenario is realistic under network asynchrony
- ✅ Violates explicitly checked protocol invariant
- ⚠️ Concrete PoC code not provided (recommended for complete validation)
- ⚠️ Direct demonstration of critical safety failure (double-spending/chain split) not shown

**Key Evidence:**
- Ordering bug confirmed: `observe_qc()` (line 108) before `safe_for_order_vote()` (line 110)
- Correct pattern exists in regular voting: safety check before state update
- SafetyData field `one_chain_round` defined at line 17 in safety_data.rs: [6](#0-5) 

**Severity Consideration:**
The classification between HIGH and MEDIUM severity depends on whether this protocol violation can be leveraged for critical consensus failures. The explicit safety check in the codebase suggests the protocol designers consider this important for consensus safety, supporting the higher severity assessment.

### Citations

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L77-84)
```rust
        self.verify_and_update_last_vote_round(
            proposed_block.block_data().round(),
            &mut safety_data,
        )?;
        self.safe_to_vote(proposed_block, timeout_cert)?;

        // Record 1-chain data
        self.observe_qc(proposed_block.quorum_cert(), &mut safety_data);
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L97-119)
```rust
    pub(crate) fn guarded_construct_and_sign_order_vote(
        &mut self,
        order_vote_proposal: &OrderVoteProposal,
    ) -> Result<OrderVote, Error> {
        // Exit early if we cannot sign
        self.signer()?;
        self.verify_order_vote_proposal(order_vote_proposal)?;
        let proposed_block = order_vote_proposal.block();
        let mut safety_data = self.persistent_storage.safety_data()?;

        // Record 1-chain data
        self.observe_qc(order_vote_proposal.quorum_cert(), &mut safety_data);

        self.safe_for_order_vote(proposed_block, &safety_data)?;
        // Construct and sign order vote
        let author = self.signer()?.author();
        let ledger_info =
            LedgerInfo::new(order_vote_proposal.block_info().clone(), HashValue::zero());
        let signature = self.sign(&ledger_info)?;
        let order_vote = OrderVote::new_with_signature(author, ledger_info.clone(), signature);
        self.persistent_storage.set_safety_data(safety_data)?;
        Ok(order_vote)
    }
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L124-145)
```rust
    fn safe_to_timeout(
        &self,
        timeout: &TwoChainTimeout,
        maybe_tc: Option<&TwoChainTimeoutCertificate>,
        safety_data: &SafetyData,
    ) -> Result<(), Error> {
        let round = timeout.round();
        let qc_round = timeout.hqc_round();
        let tc_round = maybe_tc.map_or(0, |tc| tc.round());
        if (round == next_round(qc_round)? || round == next_round(tc_round)?)
            && qc_round >= safety_data.one_chain_round
        {
            Ok(())
        } else {
            Err(Error::NotSafeToTimeout(
                round,
                qc_round,
                tc_round,
                safety_data.one_chain_round,
            ))
        }
    }
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L168-178)
```rust
    fn safe_for_order_vote(&self, block: &Block, safety_data: &SafetyData) -> Result<(), Error> {
        let round = block.round();
        if round > safety_data.highest_timeout_round {
            Ok(())
        } else {
            Err(Error::NotSafeForOrderVote(
                round,
                safety_data.highest_timeout_round,
            ))
        }
    }
```

**File:** consensus/safety-rules/src/safety_rules.rs (L135-145)
```rust
    pub(crate) fn observe_qc(&self, qc: &QuorumCert, safety_data: &mut SafetyData) -> bool {
        let mut updated = false;
        let one_chain = qc.certified_block().round();
        let two_chain = qc.parent_block().round();
        if one_chain > safety_data.one_chain_round {
            safety_data.one_chain_round = one_chain;
            trace!(
                SafetyLogSchema::new(LogEntry::OneChainRound, LogEvent::Update)
                    .preferred_round(safety_data.one_chain_round)
            );
            updated = true;
```

**File:** consensus/consensus-types/src/safety_data.rs (L15-17)
```rust
    // highest 1-chain round, used for 2-chain
    #[serde(default)]
    pub one_chain_round: u64,
```
