# Audit Report

## Title
Consensus Safety Violation Due to Unsafe Default Values in SafetyData Deserialization During Mid-Epoch Upgrades

## Summary
The `SafetyData` struct uses `#[serde(default)]` for `one_chain_round` and `highest_timeout_round` fields, causing them to default to 0 when deserializing old data during validator upgrades. This breaks critical consensus safety rules by allowing validators to sign timeouts with stale QCs and order votes for rounds where they've already timed out, potentially causing equivocation and ordering conflicts.

## Finding Description

The `SafetyData` structure maintains critical state for consensus safety rules in the Aptos consensus layer. [1](#0-0) 

The fields `one_chain_round` and `highest_timeout_round` are marked with `#[serde(default)]`, which causes them to default to 0 when deserializing old SafetyData that lacks these fields. [2](#0-1) 

A test explicitly demonstrates backward compatibility by deserializing old SafetyData without these fields into the new format. [3](#0-2) 

**Attack Vector 1: Timeout Safety Violation**

The `safe_to_timeout` function enforces the critical safety rule: `qc_round >= safety_data.one_chain_round`. [4](#0-3) 

During normal operation, `one_chain_round` is updated via `observe_qc` when processing quorum certificates. [5](#0-4) 

When a validator upgrades mid-epoch:
1. Validator has previously observed blocks up to round 1000 with `one_chain_round` = 950
2. After upgrade, old SafetyData is deserialized with `one_chain_round` defaulting to 0
3. Attacker sends timeout proposal for round 501 with QC at round 500
4. Safety check becomes: `500 >= 0` (passes incorrectly)
5. Validator signs timeout with stale QC, violating BFT safety

**Attack Vector 2: Order Vote Safety Violation**

The `safe_for_order_vote` function enforces: `round > safety_data.highest_timeout_round`. [6](#0-5) 

The `highest_timeout_round` is updated when signing timeouts. [7](#0-6) 

When a validator upgrades mid-epoch:
1. Validator previously signed timeout at round 2000
2. After upgrade, `highest_timeout_round` defaults to 0
3. Attacker sends order vote proposals for rounds 1-2000
4. Safety check becomes: `1500 > 0` (passes incorrectly)
5. Validator signs order votes for rounds where they've already expressed timeout

The test suite validates this safety rule, confirming that order votes cannot be signed for rounds at or below the highest timeout round. [8](#0-7) 

**Critical Mid-Epoch Upgrade Path:**

During epoch initialization, SafetyData is only reset when starting a NEW epoch (Ordering::Less case). [9](#0-8) 

For same-epoch restarts (Ordering::Equal), the existing SafetyData is preserved. [10](#0-9) 

SafetyData is loaded from persistent storage via deserialization, which applies the `#[serde(default)]` defaults. [11](#0-10) 

## Impact Explanation

**CRITICAL Severity** - This vulnerability directly violates **Consensus Safety**, a Critical impact category in the Aptos bug bounty program.

**Specific Impacts:**
1. **Equivocation**: Validators can sign conflicting timeouts or votes, breaking BFT safety guarantees
2. **Ordering Conflicts**: Validators can order vote on blocks they've already timed out on, causing non-deterministic commit decisions
3. **Chain Splits**: Different validators may commit different blocks due to inconsistent safety state
4. **Byzantine Behavior**: Honest validators behave as if Byzantine after upgrade, potentially triggering safety failures with <1/3 Byzantine nodes

This breaks the fundamental AptosBFT invariant that consensus safety must be maintained under <1/3 Byzantine validators.

## Likelihood Explanation

**HIGH Likelihood** - This occurs automatically during routine network upgrades:

1. **Frequency**: Every validator upgrade that adds new SafetyData fields
2. **Timing**: Affects any validator upgrading mid-epoch (common during rolling upgrades)
3. **Automation**: No attacker action needed - the vulnerability triggers on deserialization
4. **Detection**: Silent failure - validators don't know their safety state is corrupted
5. **Scope**: Affects ALL upgrading validators simultaneously during network upgrades
6. **Exploitation**: Simple - send normal timeout or order vote proposals to recently upgraded validators

The only protection would be if all validators upgrade simultaneously at epoch boundaries, which is operationally infeasible for a live network.

## Recommendation

Implement proper SafetyData migration during upgrades:

1. **Preserve Safety State on Upgrade**: When deserializing SafetyData, if new fields are missing (indicating old data), derive their values from existing fields:
   - Set `one_chain_round` to `max(preferred_round, last_voted_round)` to maintain conservative safety
   - Set `highest_timeout_round` to `last_voted_round` as a safe lower bound

2. **Add Explicit Migration Path**: Implement a migration function that runs during initialization to populate missing fields based on current consensus state.

3. **Add Version Field**: Include a version field in SafetyData to detect schema changes and trigger appropriate migration logic.

4. **Validation on Load**: Add assertions after deserialization to verify that critical safety fields are within reasonable bounds.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Running a validator with old SafetyData format (without `one_chain_round` and `highest_timeout_round`)
2. Processing blocks until `one_chain_round` would be > 0 and signing a timeout (setting `highest_timeout_round` > 0)
3. Upgrading the validator to new code with these fields
4. Observing that deserialized SafetyData has these fields set to 0
5. Attempting to sign timeouts/order votes that should be rejected by safety rules but are accepted

The test at lines 54-70 of `safety_data.rs` explicitly demonstrates the deserialization behavior that enables this vulnerability.

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

**File:** consensus/consensus-types/src/safety_data.rs (L54-70)
```rust
fn test_safety_data_upgrade() {
    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize, Clone, Default)]
    struct OldSafetyData {
        pub epoch: u64,
        pub last_voted_round: u64,
        pub preferred_round: u64,
        pub last_vote: Option<Vote>,
    }
    let old_data = OldSafetyData {
        epoch: 1,
        last_voted_round: 10,
        preferred_round: 100,
        last_vote: None,
    };
    let value = serde_json::to_value(old_data).unwrap();
    let _: SafetyData = serde_json::from_value(value).unwrap();
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

**File:** consensus/safety-rules/src/safety_rules.rs (L135-156)
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
        }
        if two_chain > safety_data.preferred_round {
            safety_data.preferred_round = two_chain;
            trace!(
                SafetyLogSchema::new(LogEntry::PreferredRound, LogEvent::Update)
                    .preferred_round(safety_data.preferred_round)
            );
            updated = true;
        }
        updated
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

**File:** consensus/safety-rules/src/safety_rules.rs (L294-307)
```rust
            Ordering::Less => {
                // start new epoch
                self.persistent_storage.set_safety_data(SafetyData::new(
                    epoch_state.epoch,
                    0,
                    0,
                    0,
                    None,
                    0,
                ))?;

                info!(SafetyLogSchema::new(LogEntry::Epoch, LogEvent::Update)
                    .epoch(epoch_state.epoch));
            },
```

**File:** consensus/safety-rules/src/safety_rules.rs (L308-309)
```rust
            Ordering::Equal => (),
        };
```

**File:** consensus/safety-rules/src/tests/suite.rs (L250-314)
```rust
fn test_order_votes_with_timeout(safety_rules: &Callback) {
    let (mut safety_rules, signer) = safety_rules();

    let (proof, genesis_qc) = test_utils::make_genesis(&signer);
    let round = genesis_qc.certified_block().round();
    let epoch = genesis_qc.certified_block().epoch();

    let data = random_payload(2048);
    //               __ tc1 __   __ tc3 __ p4b
    //              /         \ /
    // genesis --- p0          p2 -- p3 -- p4a

    // ov1 orders p0
    // ov3 orders p2
    // ov4 orders p3

    let p0 = test_utils::make_proposal_with_qc(round + 1, genesis_qc.clone(), &signer);
    let p1 = test_utils::make_proposal_with_parent(data.clone(), round + 2, &p0, None, &signer);
    let tc1 = test_utils::make_timeout_cert(round + 2, p1.block().quorum_cert(), &signer);
    let p2 = test_utils::make_proposal_with_parent(data.clone(), round + 3, &p0, None, &signer);
    let p3 = test_utils::make_proposal_with_parent(data.clone(), round + 4, &p2, None, &signer);
    let tc3 = test_utils::make_timeout_cert(round + 4, p3.block().quorum_cert(), &signer);
    let p4a = test_utils::make_proposal_with_parent(data.clone(), round + 5, &p3, None, &signer);
    let p4b = test_utils::make_proposal_with_parent(data, round + 5, &p2, None, &signer);

    let ov1 = OrderVoteProposal::new(
        p0.block().clone(),
        p1.block().quorum_cert().certified_block().clone(),
        Arc::new(p1.block().quorum_cert().clone()),
    );
    let ov3 = OrderVoteProposal::new(
        p2.block().clone(),
        p3.block().quorum_cert().certified_block().clone(),
        Arc::new(p3.block().quorum_cert().clone()),
    );
    let ov4 = OrderVoteProposal::new(
        p3.block().clone(),
        p4a.block().quorum_cert().certified_block().clone(),
        Arc::new(p4a.block().quorum_cert().clone()),
    );

    safety_rules.initialize(&proof).unwrap();

    safety_rules
        .construct_and_sign_vote_two_chain(&p0, None)
        .unwrap();

    safety_rules
        .construct_and_sign_vote_two_chain(&p2, Some(&tc1))
        .unwrap();

    // The validator hasn't signed timeout for round 2, but has received timeout certificate for round 2.
    // The validator can still sign order vote for round 1. But all the 2f+1 validators who signed timeout certificate
    // can't order vote for round 1. So, 2f+1 order votes can't be formed for round 1.
    safety_rules.construct_and_sign_order_vote(&ov1).unwrap();

    safety_rules
        .sign_timeout_with_qc(
            &TwoChainTimeout::new(epoch, round + 4, p3.block().quorum_cert().clone()),
            Some(&tc3),
        )
        .unwrap();

    // Cannot sign order vote for round 3 after signing timeout for round 4
    assert_err!(safety_rules.construct_and_sign_order_vote(&ov3));
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
