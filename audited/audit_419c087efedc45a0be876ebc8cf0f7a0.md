# Audit Report

## Title
OptQuorumStore Exclude Authors Bypass - Byzantine Leader Can Ignore Validator Exclusion Mechanism

## Summary
Byzantine leaders can bypass the `exclude_authors` exclusion mechanism when creating OptQuorumStore proposals, allowing them to include batches from validators that should be excluded due to past failures. The proposal verification process does not validate that the leader respected the `exclude_authors` constraint, enabling protocol violations and potential performance degradation.

## Finding Description

The OptQuorumStore (OptQS) protocol includes an exclusion mechanism to avoid including batches from validators who have recently caused payload availability failures. This mechanism works through the `exclude_authors` HashSet in `OptQSPayloadPullParams`. [1](#0-0) 

The exclusion set is populated by tracking `PayloadUnavailable` timeout failures through `ExponentialWindowFailureTracker`, which computes the set of authors to exclude based on recent failure history: [2](#0-1) 

When an honest leader creates an OptQS proposal, they retrieve the exclusion parameters via the `opt_qs_payload_param_provider`: [3](#0-2) [4](#0-3) 

The `exclude_authors` set is then passed through the payload pull parameters and used to filter which validators' batches are included during batch pulling: [5](#0-4) 

**The Critical Flaw:** When validators receive and verify an OptQS proposal, the verification only checks that batch authors are valid validators, but does NOT verify that the proposal respected the `exclude_authors` constraint: [6](#0-5) 

This verification is called during OptProposalMsg verification: [7](#0-6)  specifically at the payload verification step: [8](#0-7) 

**Attack Scenario:**
1. Byzantine validator V_B has been causing problems (slow responses, intermittent failures)
2. Honest validators track this and include V_B in their local `exclude_authors` sets
3. V_B (or a colluding validator) becomes the leader for round R through normal leader rotation
4. When creating the OptQS proposal, V_B can manually construct an `OptQuorumStorePayload` using the public constructor: [9](#0-8) 
5. V_B ignores its own failure tracker and includes batches from problematic validators (including itself)
6. Honest validators receive the proposal and verify it via `OptProposalMsg.verify()`
7. Verification only checks that authors are valid validators - passes ✓
8. No check that the leader respected `exclude_authors` constraint
9. Proposal is accepted and problematic batches are executed

## Impact Explanation

This vulnerability has **HIGH** severity impact per the Aptos bug bounty program, falling under the "Validator Node Slowdowns" category:

1. **Validator Node Slowdowns**: Byzantine leaders can include batches with resource-intensive transactions from validators that honest nodes have identified as problematic, causing performance degradation across all validators executing the block

2. **Protocol Defense Mechanism Bypass**: The OptQS exclusion mechanism is designed as a critical defense against problematic validators. Bypassing it undermines the protocol's fault tolerance guarantees and allows Byzantine validators to continue degrading network performance even after being identified

3. **Resource Exhaustion**: Malicious batches can waste computational resources, network bandwidth, and execution time

4. **Degraded Network Performance**: If problematic batches consistently cause delays, they impact the network's ability to maintain optimal performance

While this does not directly break consensus safety (execution remains deterministic and all validators execute the same transactions), it violates the protocol's intended defense mechanisms and enables Byzantine validators to degrade network performance systematically.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

Required conditions:
- Byzantine validator (or colluding validator) must become leader (happens naturally through leader election rotation)
- Byzantine validator has been tracked as problematic by honest validators  
- Byzantine validator has available batches to include

The attack is straightforward to execute once a Byzantine validator becomes leader. Given Aptos' rotating leader election, Byzantine validators will periodically have the opportunity to propose blocks. The lack of verification makes exploitation trivial for any Byzantine leader - they simply construct an `OptQuorumStorePayload` directly instead of using the standard batch pulling mechanism with exclusion filtering.

## Recommendation

Add verification that the proposal respected the `exclude_authors` constraint. However, this is challenging because:

1. Each honest validator maintains its own local `exclude_authors` set based on its observed failure history
2. Different validators may have different exclusion sets due to network conditions
3. The leader's exclusion set may legitimately differ from other validators

Potential solutions:

**Option 1: Consensus on Exclusion Set**
- Include the `exclude_authors` set (or its hash) in the proposal
- Validators verify that included batches don't violate the declared exclusion set
- Validators can reject proposals with unreasonable exclusion sets based on their own tracking

**Option 2: Mandatory Exclusion Reporting**
- Validators gossip their exclusion sets periodically
- Proposals must respect exclusion sets reported by >2/3 of validators
- Provides decentralized enforcement of exclusion mechanism

**Option 3: Economic Penalties**
- Don't prevent the bypass, but add accountability
- Track which leaders include batches from problematic validators
- Apply reputation penalties or stake slashing for repeated violations

## Proof of Concept

A complete PoC would require:
1. Setting up a test network with Byzantine validator
2. Triggering `PayloadUnavailable` failures to populate `exclude_authors`
3. Having the Byzantine validator become leader
4. Constructing an `OptQuorumStorePayload` that violates exclusions
5. Demonstrating the proposal passes verification

The core vulnerability can be demonstrated by examining the code paths:
- Honest leaders filter via `pull_internal()` which checks `!exclude_authors.contains(author)`
- Byzantine leaders can call `OptQuorumStorePayload::new()` directly with arbitrary batches
- Verification via `verify_opt_batches()` only checks `authors.contains_key(&batch.author())`

## Notes

This vulnerability represents a gap between the protocol's intended defense mechanism and its enforcement. While the `exclude_authors` mechanism is designed to protect against problematic validators, the lack of verification allows Byzantine leaders to ignore it completely. The impact is limited to performance degradation rather than consensus safety violations, but it undermines an important fault tolerance mechanism in the OptQuorumStore protocol.

The secondary claim about availability vs. validity tracking is also valid - the mechanism only tracks `PayloadUnavailable` failures: [10](#0-9)  A Byzantine validator could provide batches that are available but contain problematic transactions, which would not trigger exclusion.

### Citations

**File:** consensus/consensus-types/src/payload_pull_params.rs (L11-14)
```rust
pub struct OptQSPayloadPullParams {
    pub exclude_authors: HashSet<Author>,
    pub minimum_batch_age_usecs: u64,
}
```

**File:** consensus/src/liveness/proposal_status_tracker.rs (L80-98)
```rust
    fn get_exclude_authors(&self) -> HashSet<Author> {
        let mut exclude_authors = HashSet::new();

        let limit = self.window;
        for round_reason in self.past_round_statuses.iter().rev().take(limit) {
            if let NewRoundReason::Timeout(RoundTimeoutReason::PayloadUnavailable {
                missing_authors,
            }) = round_reason
            {
                for author_idx in missing_authors.iter_ones() {
                    if let Some(author) = self.ordered_authors.get(author_idx) {
                        exclude_authors.insert(*author);
                    }
                }
            }
        }

        exclude_authors
    }
```

**File:** consensus/src/liveness/proposal_generator.rs (L501-501)
```rust
        let maybe_optqs_payload_pull_params = self.opt_qs_payload_param_provider.get_params();
```

**File:** consensus/src/liveness/proposal_generator.rs (L696-696)
```rust
        let maybe_optqs_payload_pull_params = self.opt_qs_payload_param_provider.get_params();
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L596-600)
```rust
        for (_, batches) in self
            .author_to_batches
            .iter()
            .filter(|(author, _)| !exclude_authors.contains(author))
        {
```

**File:** consensus/consensus-types/src/common.rs (L558-572)
```rust
    pub fn verify_opt_batches<T: TBatchInfo>(
        verifier: &ValidatorVerifier,
        opt_batches: &OptBatches<T>,
    ) -> anyhow::Result<()> {
        let authors = verifier.address_to_validator_index();
        for batch in &opt_batches.batch_summary {
            ensure!(
                authors.contains_key(&batch.author()),
                "Invalid author {} for batch {}",
                batch.author(),
                batch.digest()
            );
        }
        Ok(())
    }
```

**File:** consensus/consensus-types/src/common.rs (L598-607)
```rust
            (true, Payload::OptQuorumStore(OptQuorumStorePayload::V1(p))) => {
                let proof_with_data = p.proof_with_data();
                Self::verify_with_cache(&proof_with_data.batch_summary, verifier, proof_cache)?;
                Self::verify_inline_batches(
                    p.inline_batches()
                        .iter()
                        .map(|batch| (batch.info(), batch.transactions())),
                )?;
                Self::verify_opt_batches(verifier, p.opt_batches())?;
                Ok(())
```

**File:** consensus/consensus-types/src/opt_proposal_msg.rs (L96-123)
```rust
    pub fn verify(
        &self,
        sender: Author,
        validator: &ValidatorVerifier,
        proof_cache: &ProofCache,
        quorum_store_enabled: bool,
    ) -> Result<()> {
        ensure!(
            self.proposer() == sender,
            "OptProposal author {:?} doesn't match sender {:?}",
            self.proposer(),
            sender
        );

        let (payload_verify_result, qc_verify_result) = rayon::join(
            || {
                self.block_data()
                    .payload()
                    .verify(validator, proof_cache, quorum_store_enabled)
            },
            || self.block_data().grandparent_qc().verify(validator),
        );
        payload_verify_result?;
        qc_verify_result?;

        // Note that we postpone the verification of SyncInfo until it's being used.
        self.verify_well_formed()
    }
```

**File:** consensus/consensus-types/src/payload.rs (L418-430)
```rust
    pub fn new(
        inline_batches: InlineBatches<BatchInfo>,
        opt_batches: OptBatches<BatchInfo>,
        proofs: ProofBatches<BatchInfo>,
        execution_limits: PayloadExecutionLimit,
    ) -> Self {
        Self::V1(OptQuorumStorePayloadV1 {
            inline_batches,
            opt_batches,
            proofs,
            execution_limits,
        })
    }
```
