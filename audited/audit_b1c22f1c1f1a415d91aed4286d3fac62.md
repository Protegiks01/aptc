# Audit Report

## Title
Consensus Observer Crashes on Startup with Zero-Duration Interval Configuration

## Summary
Setting `progress_check_interval_ms` to 0 in the consensus observer configuration causes an immediate panic when the consensus observer starts, crashing validator fullnodes and public fullnodes. The configuration system lacks validation to prevent zero-duration intervals, violating the availability invariant. [1](#0-0) 

## Finding Description
The consensus observer configuration allows all timeout and interval fields to be set to 0 without validation. When `progress_check_interval_ms` is set to 0, the consensus observer's `start()` method creates a tokio interval with zero duration, which triggers an immediate panic.

The vulnerable code path:

1. Configuration is loaded with `progress_check_interval_ms = 0` [2](#0-1) 

2. The consensus observer starts and creates an interval stream using the configuration value [3](#0-2) 

3. The tokio `interval()` function is called with `Duration::from_millis(0)`, which equals `Duration::ZERO` [4](#0-3) 

4. Tokio's interval implementation panics when given a zero duration (similar assertion exists in aptos-time-service) [5](#0-4) 

Additionally, setting the timeout fields to 0 creates operational failure even without a panic:
- `network_request_timeout_ms = 0`: All RPC subscription requests timeout immediately [6](#0-5) 

- `max_subscription_timeout_ms = 0`: Active subscriptions timeout on the first health check [7](#0-6) 

- `max_subscription_sync_timeout_ms = 0`: Database sync progress checks fail immediately [8](#0-7) 

## Impact Explanation
This vulnerability meets **High Severity** criteria per the Aptos bug bounty program:

1. **Validator node slowdowns / API crashes**: Nodes with consensus observer enabled (validators and fullnodes) crash on startup and cannot serve API requests or participate in consensus observation.

2. **Availability Impact**: 
   - Validator fullnodes become unavailable, preventing users from querying blockchain state
   - Public fullnodes fail to start, reducing network availability
   - Continuous restart loops if automated restart is configured

3. **Network-Wide Impact Potential**: If multiple node operators inadvertently use zero-timeout configuration (e.g., from a misconfigured deployment template), this could cause widespread node failures.

The configuration system currently enables consensus observer automatically on validators and validator fullnodes without validating timeout values: [9](#0-8) 

## Likelihood Explanation
**Moderate Likelihood**:

1. **Configuration Error Scenario**: Node operators might set timeouts to 0 thinking it means "no timeout" or "infinite timeout," when it actually means "zero duration."

2. **Template Propagation**: If deployment templates or example configurations contain zero values, multiple operators could deploy misconfigured nodes.

3. **No Validation**: The configuration system accepts 0 without warning or error, making it easy to introduce accidentally.

4. **Auto-Enable Risk**: The optimizer automatically enables consensus observer on validators and VFNs, so misconfigured timeout values immediately affect production nodes.

## Recommendation
Add validation to reject zero-duration timeout and interval configurations in `ConsensusObserverConfig`:

```rust
impl ConsensusObserverConfig {
    pub fn validate(&self) -> Result<(), String> {
        // Validate timeout fields
        if self.network_request_timeout_ms == 0 {
            return Err("network_request_timeout_ms must be greater than 0".to_string());
        }
        if self.max_subscription_timeout_ms == 0 {
            return Err("max_subscription_timeout_ms must be greater than 0".to_string());
        }
        if self.max_subscription_sync_timeout_ms == 0 {
            return Err("max_subscription_sync_timeout_ms must be greater than 0".to_string());
        }
        
        // Validate interval fields
        if self.progress_check_interval_ms == 0 {
            return Err("progress_check_interval_ms must be greater than 0".to_string());
        }
        if self.garbage_collection_interval_ms == 0 {
            return Err("garbage_collection_interval_ms must be greater than 0".to_string());
        }
        if self.subscription_peer_change_interval_ms == 0 {
            return Err("subscription_peer_change_interval_ms must be greater than 0".to_string());
        }
        if self.subscription_refresh_interval_ms == 0 {
            return Err("subscription_refresh_interval_ms must be greater than 0".to_string());
        }
        
        // Validate duration fields
        if self.observer_fallback_duration_ms == 0 {
            return Err("observer_fallback_duration_ms must be greater than 0".to_string());
        }
        if self.observer_fallback_startup_period_ms == 0 {
            return Err("observer_fallback_startup_period_ms must be greater than 0".to_string());
        }
        if self.observer_fallback_progress_threshold_ms == 0 {
            return Err("observer_fallback_progress_threshold_ms must be greater than 0".to_string());
        }
        if self.observer_fallback_sync_lag_threshold_ms == 0 {
            return Err("observer_fallback_sync_lag_threshold_ms must be greater than 0".to_string());
        }
        
        Ok(())
    }
}
```

Call this validation during node startup before initializing the consensus observer.

## Proof of Concept
**Configuration file** (`node.yaml`):
```yaml
consensus_observer:
  observer_enabled: true
  publisher_enabled: true
  progress_check_interval_ms: 0  # This will cause panic
  network_request_timeout_ms: 0
  max_subscription_timeout_ms: 0
  max_subscription_sync_timeout_ms: 0
```

**Expected behavior**:
1. Start an Aptos fullnode with this configuration
2. The node will panic during consensus observer initialization with an assertion failure about "period must be non-zero"
3. The node process terminates and cannot start successfully

**Stack trace location**:
- Entry point: `consensus_observer.rs:1116` where `IntervalStream::new(interval(Duration::from_millis(0)))` is called
- Panic source: tokio's interval implementation when validating duration > 0

## Notes
This vulnerability affects consensus observer availability but does not impact consensus safety or validator operations directly. However, it breaks the availability invariant for nodes running consensus observer and could cause operational issues if deployed across multiple nodes simultaneously.

### Citations

**File:** config/src/config/consensus_observer_config.rs (L32-61)
```rust
    pub network_request_timeout_ms: u64,

    /// Interval (in milliseconds) to garbage collect peer state
    pub garbage_collection_interval_ms: u64,
    /// Maximum number of blocks to keep in memory (e.g., pending blocks, ordered blocks, etc.)
    pub max_num_pending_blocks: u64,
    /// Interval (in milliseconds) to check progress of the consensus observer
    pub progress_check_interval_ms: u64,

    /// The maximum number of concurrent subscriptions
    pub max_concurrent_subscriptions: u64,
    /// Maximum timeout (in milliseconds) we'll wait for the synced version to
    /// increase before terminating the active subscription.
    pub max_subscription_sync_timeout_ms: u64,
    /// Maximum message timeout (in milliseconds) for active subscriptions
    pub max_subscription_timeout_ms: u64,
    /// Interval (in milliseconds) to check for subscription related peer changes
    pub subscription_peer_change_interval_ms: u64,
    /// Interval (in milliseconds) to refresh the subscription
    pub subscription_refresh_interval_ms: u64,

    /// Duration (in milliseconds) to require state sync to synchronize when in fallback mode
    pub observer_fallback_duration_ms: u64,
    /// Duration (in milliseconds) we'll wait on startup before considering fallback mode
    pub observer_fallback_startup_period_ms: u64,
    /// Duration (in milliseconds) we'll wait for syncing progress before entering fallback mode
    pub observer_fallback_progress_threshold_ms: u64,
    /// Duration (in milliseconds) of acceptable sync lag before entering fallback mode
    pub observer_fallback_sync_lag_threshold_ms: u64,
}
```

**File:** config/src/config/consensus_observer_config.rs (L63-84)
```rust
impl Default for ConsensusObserverConfig {
    fn default() -> Self {
        Self {
            observer_enabled: false,
            publisher_enabled: false,
            max_network_channel_size: 1000,
            max_parallel_serialization_tasks: num_cpus::get(), // Default to the number of CPUs
            network_request_timeout_ms: 5_000,                 // 5 seconds
            garbage_collection_interval_ms: 60_000,            // 60 seconds
            max_num_pending_blocks: 150, // 150 blocks (sufficient for existing production networks)
            progress_check_interval_ms: 5_000, // 5 seconds
            max_concurrent_subscriptions: 2, // 2 streams should be sufficient
            max_subscription_sync_timeout_ms: 15_000, // 15 seconds
            max_subscription_timeout_ms: 15_000, // 15 seconds
            subscription_peer_change_interval_ms: 180_000, // 3 minutes
            subscription_refresh_interval_ms: 600_000, // 10 minutes
            observer_fallback_duration_ms: 600_000, // 10 minutes
            observer_fallback_startup_period_ms: 60_000, // 60 seconds
            observer_fallback_progress_threshold_ms: 10_000, // 10 seconds
            observer_fallback_sync_lag_threshold_ms: 15_000, // 15 seconds
        }
    }
```

**File:** config/src/config/consensus_observer_config.rs (L94-155)
```rust
impl ConfigOptimizer for ConsensusObserverConfig {
    fn optimize(
        node_config: &mut NodeConfig,
        local_config_yaml: &Value,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<bool, Error> {
        let consensus_observer_config = &mut node_config.consensus_observer;
        let local_observer_config_yaml = &local_config_yaml["consensus_observer"];

        // Check if the observer configs are manually set in the local config.
        // If they are, we don't want to override them.
        let observer_manually_set = !local_observer_config_yaml["observer_enabled"].is_null();
        let publisher_manually_set = !local_observer_config_yaml["publisher_enabled"].is_null();

        // Enable the consensus observer and publisher based on the node type
        let mut modified_config = false;
        match node_type {
            NodeType::Validator => {
                if ENABLE_ON_VALIDATORS && !publisher_manually_set {
                    // Only enable the publisher for validators
                    consensus_observer_config.publisher_enabled = true;
                    modified_config = true;
                }
            },
            NodeType::ValidatorFullnode => {
                if ENABLE_ON_VALIDATOR_FULLNODES
                    && !observer_manually_set
                    && !publisher_manually_set
                {
                    // Enable both the observer and the publisher for VFNs
                    consensus_observer_config.observer_enabled = true;
                    consensus_observer_config.publisher_enabled = true;
                    modified_config = true;
                }
            },
            NodeType::PublicFullnode => {
                if ENABLE_ON_PUBLIC_FULLNODES && !observer_manually_set && !publisher_manually_set {
                    // Enable both the observer and the publisher for PFNs
                    consensus_observer_config.observer_enabled = true;
                    consensus_observer_config.publisher_enabled = true;
                    modified_config = true;
                }
            },
        }

        // Optimize the max number of pending blocks to accommodate increased block rates.
        // Note: we currently only do this for test networks (e.g., devnet).
        if let Some(chain_id) = chain_id {
            if local_observer_config_yaml["max_num_pending_blocks"].is_null()
                && !chain_id.is_testnet()
                && !chain_id.is_mainnet()
            {
                consensus_observer_config.max_num_pending_blocks =
                    MAX_NUM_PENDING_BLOCKS_FOR_TEST_NETWORKS;
                modified_config = true;
            }
        }

        Ok(modified_config)
    }
}
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L63-64)
```rust
use tokio::{sync::mpsc::UnboundedSender, time::interval};
use tokio_stream::wrappers::IntervalStream;
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L1115-1119)
```rust
        // Create a progress check ticker
        let mut progress_check_interval = IntervalStream::new(interval(Duration::from_millis(
            consensus_observer_config.progress_check_interval_ms,
        )))
        .fuse();
```

**File:** crates/aptos-time-service/src/interval.rs (L30-34)
```rust
    pub fn new(delay: Sleep, period: Duration) -> Self {
        assert!(period > ZERO_DURATION, "`period` must be non-zero.");

        Self { delay, period }
    }
```

**File:** consensus/src/consensus_observer/observer/subscription_utils.rs (L136-140)
```rust
        let subscription_request = ConsensusObserverRequest::Subscribe;
        let request_timeout_ms = consensus_observer_config.network_request_timeout_ms;
        let response = consensus_observer_client
            .send_rpc_request_to_peer(&potential_peer, subscription_request, request_timeout_ms)
            .await;
```

**File:** consensus/src/consensus_observer/observer/subscription.rs (L166-182)
```rust
    fn check_subscription_timeout(&self) -> Result<(), Error> {
        // Calculate the duration since the last message
        let time_now = self.time_service.now();
        let duration_since_last_message = time_now.duration_since(self.last_message_receive_time);

        // Check if the subscription has timed out
        if duration_since_last_message
            > Duration::from_millis(self.consensus_observer_config.max_subscription_timeout_ms)
        {
            return Err(Error::SubscriptionTimeout(format!(
                "Subscription to peer: {} has timed out! No message received for: {:?}",
                self.peer_network_id, duration_since_last_message
            )));
        }

        Ok(())
    }
```

**File:** consensus/src/consensus_observer/observer/subscription.rs (L185-222)
```rust
    fn check_syncing_progress(&mut self) -> Result<(), Error> {
        // Get the current time and synced version from storage
        let time_now = self.time_service.now();
        let current_synced_version =
            self.db_reader
                .get_latest_ledger_info_version()
                .map_err(|error| {
                    Error::UnexpectedError(format!(
                        "Failed to read highest synced version: {:?}",
                        error
                    ))
                })?;

        // Verify that the synced version is increasing appropriately
        let (highest_synced_version, highest_version_timestamp) =
            self.highest_synced_version_and_time;
        if current_synced_version <= highest_synced_version {
            // The synced version hasn't increased. Check if we should terminate
            // the subscription based on the last time the highest synced version was seen.
            let duration_since_highest_seen = time_now.duration_since(highest_version_timestamp);
            let timeout_duration = Duration::from_millis(
                self.consensus_observer_config
                    .max_subscription_sync_timeout_ms,
            );
            if duration_since_highest_seen > timeout_duration {
                return Err(Error::SubscriptionProgressStopped(format!(
                    "The DB is not making sync progress! Highest synced version: {}, elapsed: {:?}",
                    highest_synced_version, duration_since_highest_seen
                )));
            }
            return Ok(()); // We haven't timed out yet
        }

        // Update the highest synced version and time
        self.highest_synced_version_and_time = (current_synced_version, time_now);

        Ok(())
    }
```
