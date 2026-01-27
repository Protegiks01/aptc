# Audit Report

## Title
Consensus Strategy Exposure Through Unrestricted Trace-Level Logging Configuration

## Summary
The logging filter system lacks hard-coded protections to prevent trace-level logging of consensus-critical modules. While enabled through operator configuration (RUST_LOG environment variable), this could expose Byzantine validator voting strategies, round states, and internal consensus decisions through log files.

## Finding Description

The `Filter::enabled()` function in the logging system has **no hard-coded security controls** to prevent trace-level logging of consensus-critical modules, regardless of configuration: [1](#0-0) 

The function simply matches module paths against directives and permits any log level, including `Trace`. Consensus code extensively logs sensitive information at trace level:

**Safety Rules exposes internal voting state:** [2](#0-1) 

**Full consensus state including validator identity:** [3](#0-2) 

**Round state with all validators' pending votes:** [4](#0-3) 

**Actual usage logging full round state in consensus manager:** [5](#0-4) 

**PendingVotes Display exposes all validator vote activity:** [6](#0-5) 

The RUST_LOG environment variable is configurable in deployments: [7](#0-6) 

With default value: [8](#0-7) 

## Impact Explanation

**Severity Assessment: Medium** (fails Critical severity due to requiring privileged access)

While this violates the principle that validator voting strategies should remain private until broadcast, exploitation requires:
- Operator access to modify RUST_LOG configuration, OR
- System access to read validator log files

This is an **operational security/configuration issue** rather than a code vulnerability exploitable by unprivileged external attackers. An operator setting `RUST_LOG=consensus=trace` (even accidentally for debugging) would expose:
- Real-time voting decisions and timing
- Which validators voted for which blocks  
- Internal consensus round progression
- Validator identities correlated with vote patterns

This information could theoretically aid Byzantine coordination but requires insider access or compromised infrastructure.

## Likelihood Explanation

**Likelihood: Low** - Requires privileged access

Exploitation requires one of:
1. **Malicious operator** with deployment configuration access
2. **Compromised logging infrastructure** with log read access
3. **Accidental misconfiguration** by operators during debugging

This is NOT exploitable by external attackers without first compromising validator infrastructure or having insider access, which violates the trust model requirement that validators operators are trusted roles.

## Recommendation

Implement hard-coded security controls in the logging filter to prevent trace-level logging of consensus-critical modules:

```rust
impl Filter {
    pub fn enabled(&self, metadata: &Metadata) -> bool {
        // Hard-coded protection: Never allow trace logging for consensus modules
        if metadata.level() == Level::Trace {
            let consensus_critical_modules = [
                "consensus::safety_rules",
                "consensus::round_manager", 
                "consensus::liveness",
                "consensus::pending_votes",
            ];
            
            for critical_module in &consensus_critical_modules {
                if metadata.module_path().starts_with(critical_module) {
                    return false;
                }
            }
        }
        
        // Existing filter logic
        for directive in self.directives.iter().rev() {
            match &directive.name {
                Some(name) if !metadata.module_path().starts_with(name) => {},
                Some(..) | None => return LevelFilter::from(metadata.level()) <= directive.level,
            }
        }
        false
    }
}
```

Additionally, add configuration validation and warnings in deployment templates.

## Proof of Concept

This vulnerability cannot be demonstrated through a standard Move test or Rust unit test as it requires actual deployment configuration and log access. However, reproduction steps would be:

1. Deploy validator with `RUST_LOG=consensus::safety_rules=trace`
2. Monitor validator logs during consensus rounds
3. Observe exposed voting rounds, preferences, and validator identities in log output
4. Correlate timing information with network messages to identify voting strategies

**Note**: This scenario requires operator-level access to configure RUST_LOG and read logs, making it an **insider threat** rather than an external attack vector.

---

## Notes

This finding represents a **missing security hardening** rather than an exploitable code vulnerability. It fails the validation criterion "Exploitable by unprivileged attacker (no validator insider access required)" as it requires either:
- Deployment configuration privileges (to set RUST_LOG)
- System access (to read log files)

Per the Aptos bug bounty guidelines and trust model, this is a **configuration security concern** for validator operators but not a vulnerability exploitable by external attackers. The lack of hard-coded protections is a design limitation that should be addressed through defense-in-depth principles, but does not constitute an exploitable security flaw under the strict validation criteria provided.

### Citations

**File:** crates/aptos-logger/src/filter.rs (L136-145)
```rust
    pub fn enabled(&self, metadata: &Metadata) -> bool {
        // Search for the longest match, the vector is assumed to be pre-sorted.
        for directive in self.directives.iter().rev() {
            match &directive.name {
                Some(name) if !metadata.module_path().starts_with(name) => {},
                Some(..) | None => return LevelFilter::from(metadata.level()) <= directive.level,
            }
        }
        false
    }
```

**File:** consensus/safety-rules/src/safety_rules.rs (L226-229)
```rust
        trace!(
            SafetyLogSchema::new(LogEntry::LastVotedRound, LogEvent::Update)
                .last_voted_round(safety_data.last_voted_round)
        );
```

**File:** consensus/safety-rules/src/safety_rules.rs (L251-256)
```rust
        trace!(SafetyLogSchema::new(LogEntry::State, LogEvent::Update)
            .author(self.persistent_storage.author()?)
            .epoch(safety_data.epoch)
            .last_voted_round(safety_data.last_voted_round)
            .preferred_round(safety_data.preferred_round)
            .waypoint(waypoint));
```

**File:** consensus/src/liveness/round_state.rs (L178-186)
```rust
impl<'a> RoundStateLogSchema<'a> {
    pub fn new(state: &'a RoundState) -> Self {
        Self {
            round: Some(state.current_round),
            highest_ordered_round: Some(state.highest_ordered_round),
            pending_votes: Some(&state.pending_votes),
            self_vote: state.vote_sent.as_ref(),
        }
    }
```

**File:** consensus/src/round_manager.rs (L2086-2088)
```rust
                    match result {
                        Ok(_) => trace!(RoundStateLogSchema::new(round_state)),
                        Err(e) => {
```

**File:** consensus/src/pending_votes.rs (L522-550)
```rust
impl fmt::Display for PendingVotes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PendingVotes: [")?;

        for (li_digest, (_, status)) in self.li_digest_to_votes.iter() {
            match status {
                VoteStatus::EnoughVotes(_li) => {
                    write!(f, "LI {} has aggregated QC", li_digest)?;
                },
                VoteStatus::NotEnoughVotes(sig_aggregator) => {
                    write!(
                        f,
                        "LI {} has {} verified votes, {} unverified votes",
                        li_digest,
                        sig_aggregator.verified_voters().count(),
                        sig_aggregator.unverified_voters().count(),
                    )?;
                },
            }
        }

        // collect timeout votes
        let timeout_votes = self
            .maybe_2chain_timeout_votes
            .as_ref()
            .map(|votes| votes.partial_2chain_tc.signers().collect::<Vec<_>>());

        if let Some(authors) = timeout_votes {
            write!(f, "{} timeout {:?}", authors.len(), authors)?;
```

**File:** terraform/helm/aptos-node/templates/validator.yaml (L163-164)
```yaml
        - name: RUST_LOG
          value: {{ .rust_log }}
```

**File:** terraform/helm/aptos-node/values.yaml (L82-82)
```yaml
  rust_log: info
```
