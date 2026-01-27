# Audit Report

## Title
Configuration Sanitizer Bypass Enables Consensus Safety Violations Through In-Memory Storage

## Summary
The `skip_config_sanitizer` flag bypasses all configuration validation, allowing mainnet validators to use non-persistent in-memory storage for consensus safety data. This enables double voting after node restarts, violating BFT consensus safety guarantees.

## Finding Description

The vulnerability exists in the configuration validation system. When `skip_config_sanitizer=true` is set, the node startup process skips all safety checks for consensus configuration. [1](#0-0) 

This bypass prevents the execution of `SafetyRulesConfig::sanitize()`, which contains critical mainnet validation checks: [2](#0-1) 

The validation normally prevents mainnet validators from using `InMemoryStorage` for consensus safety data. According to the secure storage documentation, `InMemoryStorage` provides no persistence: [3](#0-2) 

The `SafetyData` structure contains `last_voted_round`, which is the critical field preventing double voting: [4](#0-3) 

The first voting rule enforces that validators cannot vote twice in the same round: [5](#0-4) 

**Attack Scenario:**
1. Validator operator sets `skip_config_sanitizer: true` in node configuration
2. Sets `safety_rules.backend: in_memory_storage` 
3. Validator operates normally, voting in rounds 1-100
4. Node crashes or is restarted
5. Since `InMemoryStorage` is non-persistent, `last_voted_round` resets to 0
6. On restart, the validator can vote again in rounds 1-100
7. This creates equivocating votes (double voting) violating consensus safety

## Impact Explanation

**Severity: Critical** - This qualifies under the Aptos Bug Bounty program's Critical category for "Consensus/Safety violations."

The impact includes:
- **Double Voting**: Validators can vote multiple times for different blocks in the same round
- **Equivocation Detection**: Other validators will detect conflicting votes from the same validator
- **Byzantine Threshold**: If multiple validators exploit this, reaching >1/3 Byzantine threshold could cause chain splits
- **Safety Violation**: Directly violates AptosBFT's core guarantee of preventing double-spending under <1/3 Byzantine validators

## Likelihood Explanation

**Likelihood: Low-Medium**

Requirements for exploitation:
- Validator operator access (privileged role)
- Ability to modify node configuration files
- Ability to restart the validator node
- Knowledge of the bypass mechanism

While this requires insider access (validator operator), it represents a significant configuration weakness that:
- Could be exploited by compromised validator operators
- Could occur accidentally through misconfiguration
- Bypasses fundamental safety mechanisms
- Has no runtime detection until equivocation occurs

## Recommendation

**Primary Fix:** Remove the `skip_config_sanitizer` option entirely, or restrict it to non-production environments only.

**Alternative Fix:** If the flag must exist for testing, add explicit safeguards:

```rust
impl ConfigSanitizer for NodeConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        // For mainnet, NEVER allow skipping sanitization
        if let Some(chain_id) = chain_id {
            if chain_id.is_mainnet() && node_config.node_startup.skip_config_sanitizer {
                return Err(Error::ConfigSanitizerFailed(
                    "NodeConfig".to_string(),
                    "skip_config_sanitizer cannot be enabled on mainnet!".to_string(),
                ));
            }
        }
        
        // If config sanitization is disabled (only for non-mainnet), don't do anything
        if node_config.node_startup.skip_config_sanitizer {
            return Ok(());
        }
        
        // ... rest of sanitization logic
    }
}
```

**Additional Hardening:** Add runtime validation in SafetyRules to detect storage backend type and refuse to operate with InMemoryStorage on mainnet.

## Proof of Concept

Create a malicious validator configuration file (`validator_config.yaml`):

```yaml
base:
  role: validator

node_startup:
  skip_config_sanitizer: true  # Bypass all validation
  
consensus:
  safety_rules:
    backend:
      type: in_memory_storage  # Non-persistent storage
    service:
      type: local
      
# ... rest of validator config
```

**Exploitation Steps:**

1. Deploy validator with the above configuration on mainnet
2. Validator participates in consensus, votes in rounds 1-100
3. Restart the validator node (simulating crash or maintenance)
4. Since `InMemoryStorage` is used, `last_voted_round` is lost and resets to 0
5. Validator can now construct and sign votes for rounds 1-100 again
6. Other validators receive conflicting votes and detect equivocation
7. If >1/3 validators are compromised this way, consensus safety is violated

**Detection:**
Monitor validator metrics for `last_voted_round` resets after restarts. Check for `EquivocateVote` events in consensus logs.

**Notes**

This vulnerability requires validator operator access, which is typically a trusted role. However, it represents a critical weakness in the configuration system that bypasses fundamental consensus safety mechanisms. The vulnerability could be exploited through:

- Compromised validator operator credentials
- Accidental misconfiguration during deployment
- Malicious insider with validator access
- Automated deployment scripts using unsafe defaults

The core issue is that the configuration system allows disabling all safety checks, including those protecting consensus safety invariants. This violates defense-in-depth principles and creates a single point of failure in the security architecture.

### Citations

**File:** config/src/config/config_sanitizer.rs (L44-48)
```rust
    ) -> Result<(), Error> {
        // If config sanitization is disabled, don't do anything!
        if node_config.node_startup.skip_config_sanitizer {
            return Ok(());
        }
```

**File:** config/src/config/safety_rules_config.rs (L86-96)
```rust
            // Verify that the secure backend is appropriate for mainnet validators
            if chain_id.is_mainnet()
                && node_type.is_validator()
                && safety_rules_config.backend.is_in_memory()
            {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "The secure backend should not be set to in memory storage in mainnet!"
                        .to_string(),
                ));
            }
```

**File:** secure/storage/README.md (L34-36)
```markdown
- `InMemory`: The InMemory secure storage implementation provides a simple in-memory storage
engine. This engine should only be used for testing, as it does not offer any persistence, or
security (i.e., data is simply held in DRAM and may be lost on a crash, or restart).
```

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

**File:** consensus/safety-rules/src/safety_rules.rs (L212-232)
```rust
    /// First voting rule
    pub(crate) fn verify_and_update_last_vote_round(
        &self,
        round: Round,
        safety_data: &mut SafetyData,
    ) -> Result<(), Error> {
        if round <= safety_data.last_voted_round {
            return Err(Error::IncorrectLastVotedRound(
                round,
                safety_data.last_voted_round,
            ));
        }

        safety_data.last_voted_round = round;
        trace!(
            SafetyLogSchema::new(LogEntry::LastVotedRound, LogEvent::Update)
                .last_voted_round(safety_data.last_voted_round)
        );

        Ok(())
    }
```
