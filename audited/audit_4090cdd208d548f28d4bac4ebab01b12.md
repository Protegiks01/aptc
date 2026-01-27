# Audit Report

## Title
Consensus Safety Violation: Validators Can Start with Default Configs When On-Chain Config Fetching Fails

## Summary
During node bootstrap, if `notify_initial_configs()` successfully sends a config notification but individual on-chain configs (like `OnChainConsensusConfig` or `OnChainExecutionConfig`) fail to load later, the validator starts consensus with default/fallback configurations instead of failing. This allows different validators to run with mismatched consensus parameters, violating consensus safety.

## Finding Description

The vulnerability exists in the interaction between the lazy config loading mechanism in `DbBackedOnChainConfig` and the error handling in consensus epoch initialization.

**Attack Path:**

1. During node startup, `notify_initial_configs()` creates a `DbBackedOnChainConfig` lazy provider and succeeds if `ConfigurationResource` exists in storage. [1](#0-0) 

2. The node passes initialization and state sync completes successfully. [2](#0-1) 

3. When consensus starts a new epoch, it calls `start_new_epoch()` which attempts to fetch individual configs lazily via `payload.get()`. [3](#0-2) 

4. **Critical Flaw**: If fetching `OnChainConsensusConfig` or `OnChainExecutionConfig` fails (e.g., due to partial database corruption, state sync bug, or race conditions), consensus merely logs warnings and uses default configs instead of failing.

5. This creates a consensus split scenario where:
   - Validators with complete databases use the actual on-chain configs
   - Validators with incomplete/corrupted databases use default configs
   - Different consensus parameters (timeouts, quorum store settings, execution configs) across validators
   - Violation of deterministic execution invariant

**Root Cause:**
The `DbBackedOnChainConfig` provider defers config fetching until access time, and the epoch manager treats missing configs as non-fatal errors with default fallbacks. [4](#0-3) 

## Impact Explanation

**Critical Severity** - This vulnerability enables consensus safety violations:

1. **Consensus Parameter Divergence**: Different validators operate with different consensus configs (proposer election type, timeouts, quorum store settings), breaking the fundamental assumption that all validators follow the same protocol rules.

2. **Execution Divergence**: Different `OnChainExecutionConfig` values cause validators to execute blocks differently (transaction shuffling, gas limits, deduplication), potentially producing different state roots for identical blocks.

3. **Liveness Failures**: Mismatched timeout configurations can prevent quorum formation.

4. **Safety Violations**: If defaults differ significantly from on-chain configs (e.g., different proposer election mechanisms), validators may accept/reject different blocks, leading to chain splits under Byzantine conditions.

This violates **Critical Invariant #1 (Deterministic Execution)** and **Critical Invariant #2 (Consensus Safety)**, qualifying for Critical severity under the bug bounty program's "Consensus/Safety violations" category.

## Likelihood Explanation

**Medium-High Likelihood:**

Scenarios triggering this vulnerability:
1. **Partial Database Corruption**: Disk failures affecting specific state keys while leaving `ConfigurationResource` intact
2. **State Sync Bugs**: Edge cases where state sync marks completion but hasn't downloaded all config resources
3. **Race Conditions**: Epoch transitions occurring before all configs are persisted
4. **Rollback/Recovery**: Node restart from backup with incomplete state
5. **Storage Backend Issues**: RocksDB corruption affecting specific key ranges

While not trivially exploitable, these are realistic operational scenarios that don't require attacker access to validator infrastructure. The vulnerability can be triggered by environmental factors (hardware failures, software bugs) affecting any validator in the network.

## Recommendation

**Immediate Fix**: Fail fast if critical configs cannot be loaded during epoch initialization.

```rust
async fn start_new_epoch(&mut self, payload: OnChainConfigPayload<P>) {
    let validator_set: ValidatorSet = payload
        .get()
        .expect("failed to get ValidatorSet from payload");
    
    // CHANGE: Make these REQUIRED, not optional with defaults
    let onchain_consensus_config: OnChainConsensusConfig = payload
        .get()
        .expect("Failed to get OnChainConsensusConfig - cannot start epoch safely");
    
    let onchain_execution_config: OnChainExecutionConfig = payload
        .get()
        .expect("Failed to get OnChainExecutionConfig - cannot start epoch safely");
    
    // Remove unwrap_or_default fallback logic
    let consensus_config = onchain_consensus_config;  // No fallback
    let execution_config = onchain_execution_config;  // No fallback
    
    // Continue with epoch initialization...
}
```

**Alternative Approach**: Eagerly validate all required configs in `notify_initial_configs()` before sending notifications:

```rust
fn notify_initial_configs(&mut self, version: Version) -> Result<(), Error> {
    // Validate all critical configs exist BEFORE notifying subscribers
    let configs = self.read_on_chain_configs(version)?;
    
    // Eagerly validate required configs exist and are readable
    let _ = configs.get::<ValidatorSet>()
        .map_err(|e| Error::UnexpectedErrorEncountered(format!("Missing ValidatorSet: {}", e)))?;
    let _ = configs.get::<OnChainConsensusConfig>()
        .map_err(|e| Error::UnexpectedErrorEncountered(format!("Missing OnChainConsensusConfig: {}", e)))?;
    let _ = configs.get::<OnChainExecutionConfig>()
        .map_err(|e| Error::UnexpectedErrorEncountered(format!("Missing OnChainExecutionConfig: {}", e)))?;
    
    // Only notify if validation succeeds
    self.notify_reconfiguration_subscribers(version)
}
```

## Proof of Concept

```rust
// Reproduction scenario (conceptual - requires integration test setup):

#[tokio::test]
async fn test_consensus_starts_with_default_configs_on_missing_onchain_config() {
    // 1. Setup a validator node with corrupted database
    //    - ConfigurationResource exists
    //    - OnChainConsensusConfig is missing/corrupted
    let mut corrupted_db = setup_test_db_with_partial_corruption();
    
    // 2. Start the node - notify_initial_configs() succeeds
    let event_service = EventSubscriptionService::new(Arc::new(RwLock::new(corrupted_db)));
    let result = event_service.notify_initial_configs(version);
    assert!(result.is_ok()); // Passes because ConfigurationResource exists
    
    // 3. Consensus starts new epoch
    let mut epoch_manager = setup_epoch_manager(event_service);
    let payload = get_reconfig_notification_payload();
    
    // 4. Attempt to get OnChainConsensusConfig
    let consensus_config_result = payload.get::<OnChainConsensusConfig>();
    assert!(consensus_config_result.is_err()); // Config fetch fails
    
    // 5. Current code falls back to default - VULNERABILITY
    // Validator uses OnChainConsensusConfig::default() instead of actual config
    // Other validators with healthy databases use real on-chain config
    // => Consensus divergence!
}
```

**Notes:**
- The vulnerability requires validators to have inconsistent database states (some with all configs, others missing specific configs)
- The lazy loading pattern in `DbBackedOnChainConfig` defers validation too late in the startup process
- The `unwrap_or_default()` pattern explicitly allows silent fallback to default configurations
- This is particularly dangerous because the node appears to start successfully while operating with incorrect parameters

### Citations

**File:** state-sync/inter-component/event-notifications/src/lib.rs (L281-307)
```rust
    fn read_on_chain_configs(
        &self,
        version: Version,
    ) -> Result<OnChainConfigPayload<DbBackedOnChainConfig>, Error> {
        let db_state_view = &self
            .storage
            .read()
            .reader
            .state_view_at_version(Some(version))
            .map_err(|error| {
                Error::UnexpectedErrorEncountered(format!(
                    "Failed to create account state view {:?}",
                    error
                ))
            })?;
        let epoch = ConfigurationResource::fetch_config(&db_state_view)
            .ok_or_else(|| {
                Error::UnexpectedErrorEncountered("Configuration resource does not exist!".into())
            })?
            .epoch();

        // Return the new on-chain config payload (containing all found configs at this version).
        Ok(OnChainConfigPayload::new(
            epoch,
            DbBackedOnChainConfig::new(self.storage.read().reader.clone(), version),
        ))
    }
```

**File:** state-sync/inter-component/event-notifications/src/lib.rs (L398-412)
```rust
    fn get<T: OnChainConfig>(&self) -> Result<T> {
        let bytes = self
            .reader
            .get_state_value_by_version(&StateKey::on_chain_config::<T>()?, self.version)?
            .ok_or_else(|| {
                anyhow!(
                    "no config {} found in aptos root account state",
                    T::CONFIG_ID
                )
            })?
            .bytes()
            .clone();

        T::deserialize_into_config(&bytes)
    }
```

**File:** state-sync/state-sync-driver/src/driver_factory.rs (L103-118)
```rust
        match storage.reader.get_latest_state_checkpoint_version() {
            Ok(Some(synced_version)) => {
                if let Err(error) =
                    event_subscription_service.notify_initial_configs(synced_version)
                {
                    panic!(
                        "Failed to notify subscribers of initial on-chain configs: {:?}",
                        error
                    )
                }
            },
            Ok(None) => {
                panic!("Latest state checkpoint version not found.")
            },
            Err(error) => panic!("Failed to fetch the initial synced version: {:?}", error),
        }
```

**File:** consensus/src/epoch_manager.rs (L1164-1203)
```rust
    async fn start_new_epoch(&mut self, payload: OnChainConfigPayload<P>) {
        let validator_set: ValidatorSet = payload
            .get()
            .expect("failed to get ValidatorSet from payload");
        let mut verifier: ValidatorVerifier = (&validator_set).into();
        verifier.set_optimistic_sig_verification_flag(self.config.optimistic_sig_verification);

        let epoch_state = Arc::new(EpochState {
            epoch: payload.epoch(),
            verifier: verifier.into(),
        });

        self.epoch_state = Some(epoch_state.clone());

        let onchain_consensus_config: anyhow::Result<OnChainConsensusConfig> = payload.get();
        let onchain_execution_config: anyhow::Result<OnChainExecutionConfig> = payload.get();
        let onchain_randomness_config_seq_num: anyhow::Result<RandomnessConfigSeqNum> =
            payload.get();
        let randomness_config_move_struct: anyhow::Result<RandomnessConfigMoveStruct> =
            payload.get();
        let onchain_jwk_consensus_config: anyhow::Result<OnChainJWKConsensusConfig> = payload.get();
        let dkg_state = payload.get::<DKGState>();

        if let Err(error) = &onchain_consensus_config {
            warn!("Failed to read on-chain consensus config {}", error);
        }

        if let Err(error) = &onchain_execution_config {
            warn!("Failed to read on-chain execution config {}", error);
        }

        if let Err(error) = &randomness_config_move_struct {
            warn!("Failed to read on-chain randomness config {}", error);
        }

        self.epoch_state = Some(epoch_state.clone());

        let consensus_config = onchain_consensus_config.unwrap_or_default();
        let execution_config = onchain_execution_config
            .unwrap_or_else(|_| OnChainExecutionConfig::default_if_missing());
```
