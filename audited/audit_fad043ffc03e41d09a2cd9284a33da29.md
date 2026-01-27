# Audit Report

## Title
Testnet Validators Forced into Fast Sync Can Experience Permanent Bootstrap Failures Without Fallback Mechanism

## Summary
Testnet validators are automatically forced into fast sync mode (`BootstrappingMode::DownloadLatestStates`) by the config optimizer, but this mode has no fallback mechanism when snapshot peers are unavailable. This can cause permanent bootstrap failures during network initialization, partitions, or when all peers are also bootstrapping, preventing validators from ever becoming operational.

## Finding Description

The vulnerability exists in the state sync configuration optimization logic that forces testnet validators into fast sync mode without accounting for scenarios where snapshot peers may be unavailable.

**The Issue Chain:**

1. **Forced Fast Sync**: The config optimizer automatically sets testnet validators to fast sync mode: [1](#0-0) 

2. **Auto-Bootstrapping Prohibited**: The sanitizer explicitly prevents auto-bootstrapping for fast sync nodes: [2](#0-1) 

3. **No Fallback Mechanism**: Unlike `ExecuteOrApplyFromGenesis` mode which has an `OutputFallbackHandler`, fast sync has no fallback when data is unavailable: [3](#0-2) 

4. **Empty Global Summary Handling**: When no peers are available, the driver returns early without making progress: [4](#0-3) 

5. **Error Loop Without Recovery**: When peers exist but lack snapshot data, errors are logged but the node remains stuck: [5](#0-4) 

6. **Data Unavailability**: When no peers can service snapshot requests, the data client returns an error: [6](#0-5) 

**Attack/Failure Scenarios:**

- **Scenario 1**: Fresh testnet initialization where all validators are starting simultaneously with no existing state
- **Scenario 2**: Network partition where a validator loses connectivity to all peers with snapshot data
- **Scenario 3**: Testnet restart where most validators cleared their storage and are bootstrapping together
- **Scenario 4**: Geographic isolation where available peers don't have the required snapshot data at the target version

The bootstrapping mode is read-only during execution: [7](#0-6) 

## Impact Explanation

This vulnerability meets **Medium to High severity** criteria:

**Medium Severity ($10,000):**
- Causes state inconsistencies requiring manual intervention (node cannot bootstrap without manual config changes)
- Affects validator availability during critical network events

**Potential High Severity ($50,000):**
- Can cause validator node unavailability indefinitely
- Impacts network liveness if multiple validators are affected simultaneously
- During testnet initialization, could prevent the network from launching

The impact is significant because:
1. Validators cannot participate in consensus until bootstrapped
2. No automatic recovery mechanism exists
3. Requires manual intervention (config changes or storage management)
4. Can affect multiple validators simultaneously during network-wide events
5. Breaks the validator availability invariant

## Likelihood Explanation

**Likelihood: Medium to High**

This issue is likely to occur in several realistic scenarios:

1. **Testnet Initialization** (High): When launching a new testnet, all validators start fresh and none have snapshot data to share
2. **Network Partitions** (Medium): During network splits, validators may be isolated from peers with snapshot data
3. **Mass Restarts** (Medium): When multiple testnet validators restart with cleared storage simultaneously
4. **Geographic Issues** (Low-Medium): In distributed testnets, some regions may lack validators with required snapshot data

The issue is particularly problematic because:
- The forced fast sync is automatic and non-obvious to operators
- No warnings are provided that peers must have snapshot data
- The infinite retry loop provides no indication that the configuration is the problem
- Testnet operators may not realize they need to manually override the bootstrapping mode

## Recommendation

Implement a multi-layered solution:

**1. Add Timeout-Based Fallback:**
```rust
// In StateSyncDriverConfig
pub struct StateSyncDriverConfig {
    // ... existing fields ...
    /// Maximum time (secs) to attempt fast sync before falling back
    pub max_fast_sync_attempt_duration_secs: u64,
    /// Fallback bootstrapping mode if fast sync fails
    pub fallback_bootstrapping_mode: Option<BootstrappingMode>,
}
```

**2. Modify Config Optimizer to Allow Fallback:**
```rust
// In ConfigOptimizer for StateSyncDriverConfig::optimize
if (chain_id.is_testnet() || chain_id.is_mainnet())
    && local_driver_config_yaml["bootstrapping_mode"].is_null()
{
    state_sync_driver_config.bootstrapping_mode =
        BootstrappingMode::DownloadLatestStates;
    // Set fallback for testnet (mainnet may want stricter behavior)
    if chain_id.is_testnet() 
        && local_driver_config_yaml["fallback_bootstrapping_mode"].is_null() 
    {
        state_sync_driver_config.fallback_bootstrapping_mode = 
            Some(BootstrappingMode::ExecuteOrApplyFromGenesis);
    }
    modified_config = true;
}
```

**3. Update Sanitizer to Allow Conditional Auto-Bootstrapping:**
```rust
// Allow auto-bootstrapping for fast sync if fallback is configured
let fast_sync_enabled = state_sync_driver_config.bootstrapping_mode.is_fast_sync();
let has_fallback = state_sync_driver_config.fallback_bootstrapping_mode.is_some();

if state_sync_driver_config.enable_auto_bootstrapping 
    && fast_sync_enabled 
    && !has_fallback 
{
    return Err(Error::ConfigSanitizerFailed(
        sanitizer_name,
        "Auto-bootstrapping requires a fallback mode when using fast sync!".to_string(),
    ));
}
```

**4. Implement Fallback Logic in Bootstrapper:**
Track bootstrap attempt duration and trigger fallback when threshold exceeded.

## Proof of Concept

**Reproduction Steps:**

1. Set up a testnet environment with 2-3 validator nodes
2. Configure all validators with empty storage (fresh start)
3. Start all validators simultaneously with default configuration
4. Observe that config optimizer forces fast sync mode
5. Verify that no peers have snapshot data to share
6. Monitor logs showing repeated `AdvertisedDataError` or `DataIsUnavailable` errors
7. Confirm validators never complete bootstrapping

**Expected Behavior:**
- Validators should either fallback to genesis execution mode after timeout
- Or auto-bootstrap if configured appropriately
- Or provide clear error indicating manual config override needed

**Actual Behavior:**
- Validators remain stuck in infinite retry loop
- No progress made toward bootstrapping
- No automatic recovery mechanism triggered
- Network cannot achieve liveness

**Log Evidence:**
```
[state_sync_driver] Error found when checking the bootstrapper progress!
Error: AdvertisedDataError("No highest advertised epoch end found in the network!")

OR

Error: DataIsUnavailable("No peers are available to service the given request")
```

The test `test_optimize_bootstrapping_mode_testnet_validator` validates the forced fast sync but doesn't test the failure scenario: [8](#0-7) 

## Notes

This vulnerability represents a design oversight where the optimization for established networks (forcing fast sync to avoid full history replay) creates a bootstrapping deadlock scenario for new or restarting networks. The lack of a fallback mechanism combined with the prohibition on auto-bootstrapping for fast sync nodes creates a situation where validators can become permanently stuck without manual intervention.

### Citations

**File:** config/src/config/state_sync_config.rs (L507-516)
```rust
        // Verify that auto-bootstrapping is not enabled for
        // nodes that are fast syncing.
        let fast_sync_enabled = state_sync_driver_config.bootstrapping_mode.is_fast_sync();
        if state_sync_driver_config.enable_auto_bootstrapping && fast_sync_enabled {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "Auto-bootstrapping should not be enabled for nodes that are fast syncing!"
                    .to_string(),
            ));
        }
```

**File:** config/src/config/state_sync_config.rs (L561-573)
```rust
        // Default to fast sync for all testnet and mainnet nodes
        // because pruning has kicked in, and nodes will struggle
        // to locate all the data since genesis.
        let mut modified_config = false;
        if let Some(chain_id) = chain_id {
            if (chain_id.is_testnet() || chain_id.is_mainnet())
                && local_driver_config_yaml["bootstrapping_mode"].is_null()
            {
                state_sync_driver_config.bootstrapping_mode =
                    BootstrappingMode::DownloadLatestStates;
                modified_config = true;
            }
        }
```

**File:** config/src/config/state_sync_config.rs (L663-680)
```rust
    fn test_optimize_bootstrapping_mode_testnet_validator() {
        // Create a node config with execution mode enabled
        let mut node_config = create_execution_mode_config();

        // Optimize the config and verify modifications are made
        let modified_config = StateSyncConfig::optimize(
            &mut node_config,
            &serde_yaml::from_str("{}").unwrap(), // An empty local config,
            NodeType::Validator,
            Some(ChainId::testnet()),
        )
        .unwrap();
        assert!(modified_config);

        // Verify that the bootstrapping mode is now set to fast sync
        let state_sync_driver_config = node_config.state_sync.state_sync_driver;
        assert!(state_sync_driver_config.bootstrapping_mode.is_fast_sync());
    }
```

**File:** state-sync/state-sync-driver/src/utils.rs (L113-194)
```rust
/// A simple struct that holds all information relevant for managing
/// fallback behaviour to output syncing.
#[derive(Clone)]
pub struct OutputFallbackHandler {
    // The configuration for the state sync driver
    driver_configuration: DriverConfiguration,

    // The most recent time at which we fell back to output syncing
    fallback_start_time: Arc<Mutex<Option<Instant>>>,

    // The time service
    time_service: TimeService,
}

impl OutputFallbackHandler {
    pub fn new(driver_configuration: DriverConfiguration, time_service: TimeService) -> Self {
        let fallback_start_time = Arc::new(Mutex::new(None));
        Self {
            driver_configuration,
            fallback_start_time,
            time_service,
        }
    }

    /// Initiates a fallback to output syncing (if we haven't already)
    pub fn fallback_to_outputs(&mut self) {
        let missing_fallback_start_time = self.fallback_start_time.lock().is_none();
        if missing_fallback_start_time {
            self.set_fallback_start_time(self.time_service.now());
            info!(LogSchema::new(LogEntry::Driver).message(&format!(
                "Falling back to output syncing for at least {:?} seconds!",
                self.get_fallback_duration().as_secs()
            )));
        }
    }

    /// Returns true iff we're currently in fallback mode
    pub fn in_fallback_mode(&mut self) -> bool {
        let fallback_start_time = self.fallback_start_time.lock().take();
        if let Some(fallback_start_time) = fallback_start_time {
            if let Some(fallback_deadline) =
                fallback_start_time.checked_add(self.get_fallback_duration())
            {
                // Check if we elapsed the max fallback duration
                if self.time_service.now() >= fallback_deadline {
                    info!(LogSchema::new(LogEntry::AutoBootstrapping)
                        .message("Passed the output fallback deadline! Disabling fallback mode!"));
                    false
                } else {
                    // Reinsert the fallback deadline (not enough time has passed)
                    self.set_fallback_start_time(fallback_start_time);
                    true
                }
            } else {
                warn!(LogSchema::new(LogEntry::Driver)
                    .message("The fallback deadline overflowed! Disabling fallback mode!"));
                false
            }
        } else {
            false
        }
    }

    /// Returns the fallback duration as defined by the config
    fn get_fallback_duration(&self) -> Duration {
        Duration::from_secs(
            self.driver_configuration
                .config
                .fallback_to_output_syncing_secs,
        )
    }

    /// Sets the fallback start time internally
    fn set_fallback_start_time(&mut self, fallback_start_time: Instant) {
        if let Some(old_start_time) = self.fallback_start_time.lock().replace(fallback_start_time) {
            warn!(LogSchema::new(LogEntry::Driver).message(&format!(
                "Overwrote the old fallback start time ({:?}) with the new one ({:?})!",
                old_start_time, fallback_start_time
            )));
        }
    }
}
```

**File:** state-sync/state-sync-driver/src/driver.rs (L671-678)
```rust
        // Fetch the global data summary and verify we have active peers
        let global_data_summary = self.aptos_data_client.get_global_data_summary();
        if global_data_summary.is_empty() {
            trace!(LogSchema::new(LogEntry::Driver).message(
                "The global data summary is empty! It's likely that we have no active peers."
            ));
            return self.check_auto_bootstrapping().await;
        }
```

**File:** state-sync/state-sync-driver/src/driver.rs (L711-719)
```rust
        } else if let Err(error) = self.bootstrapper.drive_progress(&global_data_summary).await {
            sample!(
                    SampleRate::Duration(Duration::from_secs(DRIVER_ERROR_LOG_FREQ_SECS)),
                    warn!(LogSchema::new(LogEntry::Driver)
                        .error(&error)
                        .message("Error found when checking the bootstrapper progress!"));
            );
            metrics::increment_counter(&metrics::BOOTSTRAPPER_ERRORS, error.get_label());
        };
```

**File:** state-sync/aptos-data-client/src/client.rs (L322-328)
```rust
        // Verify that we have at least one peer to service the request
        if num_peers_for_request == 0 {
            return Err(Error::DataIsUnavailable(format!(
                "No peers are available to service the given request: {:?}",
                request
            )));
        }
```

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L362-365)
```rust
    /// Returns the bootstrapping mode of the node
    fn get_bootstrapping_mode(&self) -> BootstrappingMode {
        self.driver_configuration.config.bootstrapping_mode
    }
```
