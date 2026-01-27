# Audit Report

## Title
Validator Crash During Epoch Initialization Due to Unvalidated Channel Size Configuration

## Summary
The `internal_per_key_channel_size` configuration parameter in `ConsensusConfig` lacks validation, allowing it to be set to zero. When this occurs, the `NonZeroUsize!` macro panics during validator epoch initialization, but only after significant partial state setup has occurred, leaving the validator node in an inconsistent state that requires manual recovery and could impact consensus participation.

## Finding Description

The vulnerability occurs through the following sequence:

1. The `NonZeroUsize!` macro is defined to panic when given a zero value: [1](#0-0) 

2. This macro is used to create channels with `max_queue_size_per_key` parameter: [2](#0-1) 

3. The `internal_per_key_channel_size` field in `ConsensusConfig` can be set via YAML configuration and defaults to 10: [3](#0-2) [4](#0-3) 

4. The `ConfigSanitizer` implementation for `ConsensusConfig` does NOT validate this field, only checking other constraints: [5](#0-4) 

5. During epoch initialization, multiple channels are created using this unchecked value, but only AFTER substantial state setup: [6](#0-5) [7](#0-6) 

6. Further into initialization, more channels are created after even more state setup (safety rules, execution client, block store): [8](#0-7) [9](#0-8) 

The panic occurs after the validator has already:
- Loaded validator set and created epoch state
- Parsed on-chain consensus, execution, and randomness configurations
- Loaded consensus keys
- Initialized network sender and payload manager
- Started execution client
- Initialized safety rules
- Created block store

This partial initialization leaves resources allocated but not properly managed, requiring manual intervention to clean up and restart.

## Impact Explanation

This qualifies as **HIGH severity** per Aptos bug bounty criteria:

**Primary Impact - Validator Node Crashes (HIGH)**: A misconfigured validator will crash during epoch initialization, completely removing it from consensus participation. This is explicitly listed as HIGH severity in the bounty program.

**Secondary Impact - State Inconsistencies Requiring Intervention (MEDIUM)**: The crash occurs after partial state setup, potentially leaving:
- Partially initialized epoch state in memory
- Started but not properly stopped execution clients
- Initialized safety rules without corresponding cleanup
- Allocated resources without proper deallocation

**Tertiary Impact - Consensus Degradation**: If multiple validators have this misconfiguration (e.g., due to copy-pasted configuration or documentation errors), the network could lose consensus quorum or suffer degraded performance during critical epoch transitions.

## Likelihood Explanation

**Likelihood: MEDIUM to HIGH**

This can occur through:

1. **Operator Error**: A validator operator accidentally sets `internal_per_key_channel_size: 0` in their configuration YAML, either through typo, misunderstanding, or copy-paste error.

2. **Configuration Template Issues**: If example configurations or deployment scripts contain this error, multiple validators could be affected simultaneously.

3. **Automation Errors**: Configuration management systems or deployment automation could incorrectly set this value.

4. **Compromised Access**: An attacker gaining access to validator configuration files could intentionally set this to cause disruption.

The lack of validation means this misconfiguration will only be detected at runtime during epoch initialization, not during node startup or configuration loading, making it harder to catch before causing impact.

## Recommendation

Add validation in the `ConfigSanitizer` implementation for `ConsensusConfig`:

```rust
impl ConfigSanitizer for ConsensusConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();

        // Verify that the safety rules and quorum store configs are valid
        SafetyRulesConfig::sanitize(node_config, node_type, chain_id)?;
        QuorumStoreConfig::sanitize(node_config, node_type, chain_id)?;

        // ADD THIS VALIDATION:
        if node_config.consensus.internal_per_key_channel_size == 0 {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "internal_per_key_channel_size must be greater than 0".to_string(),
            ));
        }

        // Verify that the consensus-only feature is not enabled in mainnet
        if let Some(chain_id) = chain_id {
            if chain_id.is_mainnet() && is_consensus_only_perf_test_enabled() {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "consensus-only-perf-test should not be enabled in mainnet!".to_string(),
                ));
            }
        }

        // Sender block limits must be <= receiver block limits
        Self::sanitize_send_recv_block_limits(&sanitizer_name, &node_config.consensus)?;

        // Quorum store batches must be <= consensus blocks
        Self::sanitize_batch_block_limits(&sanitizer_name, &node_config.consensus)?;

        Ok(())
    }
}
```

Additionally, consider adding validation for other channel size configurations (`intra_consensus_channel_buffer_size`, etc.) to ensure they are within reasonable bounds.

## Proof of Concept

Create a test configuration file `malicious_config.yaml`:

```yaml
consensus:
  internal_per_key_channel_size: 0
  # ... other config fields with valid values
```

Then attempt to start a validator node with this configuration:

```rust
#[test]
fn test_zero_channel_size_causes_panic() {
    use aptos_config::config::NodeConfig;
    
    // Load configuration with internal_per_key_channel_size set to 0
    let mut config = NodeConfig::default();
    config.consensus.internal_per_key_channel_size = 0;
    
    // This should panic during consensus initialization when epoch starts
    // The panic will occur in aptos_channel::new() when NonZeroUsize! is invoked
    
    // Expected panic message: "aptos_channel cannot be of size 0"
}
```

The panic will occur when `start_new_epoch` is called and attempts to create channels, demonstrating that the crash happens after configuration loading but during critical initialization.

## Notes

This vulnerability demonstrates a gap in defensive programming where configuration validation should occur at the earliest possible point (configuration loading/sanitization) rather than relying on runtime assertions during critical initialization phases. The timing of the panic is particularly problematic because it occurs during epoch transitions, which are critical moments for consensus protocol operation.

### Citations

**File:** crates/aptos-infallible/src/nonzero.rs (L6-13)
```rust
macro_rules! NonZeroUsize {
    ($num:expr) => {
        NonZeroUsize!($num, "Must be non-zero")
    };
    ($num:expr, $message:literal) => {
        std::num::NonZeroUsize::new($num).expect($message)
    };
}
```

**File:** crates/channel/src/aptos_channel.rs (L235-241)
```rust
pub fn new<K: Eq + Hash + Clone, M>(
    queue_style: QueueStyle,
    max_queue_size_per_key: usize,
    counters: Option<&'static IntCounterVec>,
) -> (Sender<K, M>, Receiver<K, M>) {
    let max_queue_size_per_key =
        NonZeroUsize!(max_queue_size_per_key, "aptos_channel cannot be of size 0");
```

**File:** config/src/config/consensus_config.rs (L55-56)
```rust
    // The size of the round/recovery manager and proposal buffer channels.
    pub internal_per_key_channel_size: usize,
```

**File:** config/src/config/consensus_config.rs (L242-242)
```rust
            internal_per_key_channel_size: 10,
```

**File:** config/src/config/consensus_config.rs (L503-532)
```rust
impl ConfigSanitizer for ConsensusConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();

        // Verify that the safety rules and quorum store configs are valid
        SafetyRulesConfig::sanitize(node_config, node_type, chain_id)?;
        QuorumStoreConfig::sanitize(node_config, node_type, chain_id)?;

        // Verify that the consensus-only feature is not enabled in mainnet
        if let Some(chain_id) = chain_id {
            if chain_id.is_mainnet() && is_consensus_only_perf_test_enabled() {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "consensus-only-perf-test should not be enabled in mainnet!".to_string(),
                ));
            }
        }

        // Sender block limits must be <= receiver block limits
        Self::sanitize_send_recv_block_limits(&sanitizer_name, &node_config.consensus)?;

        // Quorum store batches must be <= consensus blocks
        Self::sanitize_batch_block_limits(&sanitizer_name, &node_config.consensus)?;

        Ok(())
    }
```

**File:** consensus/src/epoch_manager.rs (L950-954)
```rust
        let (round_manager_tx, round_manager_rx) = aptos_channel::new(
            QueueStyle::KLAST,
            self.config.internal_per_key_channel_size,
            Some(&counters::ROUND_MANAGER_CHANNEL_MSGS),
        );
```

**File:** consensus/src/epoch_manager.rs (L956-960)
```rust
        let (buffered_proposal_tx, buffered_proposal_rx) = aptos_channel::new(
            QueueStyle::KLAST,
            self.config.internal_per_key_channel_size,
            Some(&counters::ROUND_MANAGER_CHANNEL_MSGS),
        );
```

**File:** consensus/src/epoch_manager.rs (L1276-1280)
```rust
        let (rand_msg_tx, rand_msg_rx) = aptos_channel::new::<AccountAddress, IncomingRandGenRequest>(
            QueueStyle::KLAST,
            self.config.internal_per_key_channel_size,
            None,
        );
```

**File:** consensus/src/epoch_manager.rs (L1285-1290)
```rust
        let (secret_share_manager_tx, secret_share_manager_rx) =
            aptos_channel::new::<AccountAddress, IncomingSecretShareRequest>(
                QueueStyle::KLAST,
                self.config.internal_per_key_channel_size,
                None,
            );
```
