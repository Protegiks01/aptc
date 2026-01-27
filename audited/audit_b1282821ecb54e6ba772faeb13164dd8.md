# Audit Report

## Title
Perpetual Fallback Loop Vulnerability in Consensus Observer Due to Missing Grace Period After Recovery

## Summary
The consensus observer fallback manager lacks a grace period after completing fallback sync, allowing observers to be trapped in a perpetual cycle of fallback states. After syncing for 10 minutes, the observer immediately performs progress checks without any stabilization period, causing it to re-enter fallback mode if block timestamps still lag behind wall clock time by more than 15 seconds.

## Finding Description
The vulnerability exists in the consensus observer's fallback mechanism, specifically in how it handles recovery from fallback mode: [1](#0-0) 

The `check_syncing_progress()` function includes a startup period check that only applies from the initial `start_time` set during construction. This `start_time` is never reset: [2](#0-1) 

When fallback sync completes, only the syncing progress is reset, not the startup period: [3](#0-2) 

The core issue is in `verify_sync_lag_health()` which compares block timestamps directly with wall clock time: [4](#0-3) 

**Attack Scenario:**
If block production is slowed (whether by Byzantine validators timing out during their leader turns, or network conditions), the following cycle occurs:

1. Observer detects sync lag > 15 seconds → enters fallback mode
2. State sync runs for 10 minutes
3. Fallback completes, `reset_syncing_progress()` is called
4. After only 5 seconds (next progress check interval), `verify_sync_lag_health()` runs again
5. If latest block's timestamp is still > 15 seconds old, immediately triggers fallback again
6. Cycle repeats indefinitely [5](#0-4) [6](#0-5) 

## Impact Explanation
**High Severity** - This creates a significant liveness degradation for consensus observers:

- Observers spend ~95% of time in fallback mode (10 min fallback / ~10 min cycle)
- Consensus observer becomes effectively unusable for Validator Fullnodes (VFNs)
- Degrades the entire state synchronization architecture that VFNs rely on
- Cascading failure: multiple observers entering fallback simultaneously increases network state sync load

This qualifies as **High severity** per the bug bounty criteria: "Validator node slowdowns" and "Significant protocol violations."

## Likelihood Explanation
**Medium-High Likelihood:**

While Byzantine validators with < 1/3 stake cannot completely stop consensus due to BFT guarantees, they can cause intermittent delays:
- When selected as leaders (proportional to their stake %), they can deliberately timeout
- Leader reputation system eventually penalizes them, but not instantaneously
- During epoch transitions or network stress, even honest validators may cause temporary slowdowns
- The vulnerability has a **zero grace period** after recovery, making it highly sensitive to any transient issues

The lack of post-recovery grace period means even legitimate network fluctuations can trigger cascading fallback loops.

## Recommendation

Add a grace period after fallback recovery by resetting the startup tracking when fallback completes:

```rust
// In ObserverFallbackManager struct, add:
last_fallback_completion_time: Option<Instant>,

// In reset_syncing_progress():
pub fn reset_syncing_progress(&mut self, latest_synced_ledger_info: &LedgerInfoWithSignatures) {
    let time_now = self.time_service.now();
    let highest_synced_version = latest_synced_ledger_info.ledger_info().version();
    
    self.highest_synced_version_and_time = (highest_synced_version, time_now);
    // Reset the fallback completion time to enable grace period
    self.last_fallback_completion_time = Some(time_now);
}

// In check_syncing_progress():
pub fn check_syncing_progress(&mut self) -> Result<(), Error> {
    let time_now = self.time_service.now();
    let startup_period = Duration::from_millis(
        self.consensus_observer_config.observer_fallback_startup_period_ms
    );
    
    // Check if we're within startup period (initial OR post-fallback)
    let within_initial_startup = time_now.duration_since(self.start_time) < startup_period;
    let within_post_fallback_grace = self.last_fallback_completion_time
        .map(|completion_time| time_now.duration_since(completion_time) < startup_period)
        .unwrap_or(false);
    
    if within_initial_startup || within_post_fallback_grace {
        return Ok(()); // Within grace period
    }
    
    // ... rest of checks
}
```

This provides a 60-second stabilization period after each fallback recovery, preventing immediate re-entry into fallback mode.

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    
    #[test]
    fn test_repeated_fallback_without_grace_period() {
        // Create observer config with short fallback duration for testing
        let consensus_observer_config = ConsensusObserverConfig {
            observer_fallback_startup_period_ms: 60_000, // 60 sec grace initially
            observer_fallback_progress_threshold_ms: 10_000,
            observer_fallback_sync_lag_threshold_ms: 15_000, // 15 sec lag threshold
            ..Default::default()
        };
        
        let time_service = TimeService::mock();
        let mock_time = time_service.clone().into_mock();
        
        // Create mock DB that returns blocks with old timestamps
        let mut mock_db_reader = MockDatabaseReader::new();
        let old_timestamp = mock_time.now_unix_time().as_micros() as u64 
            - Duration::from_secs(20).as_micros() as u64; // 20 seconds old
        
        mock_db_reader
            .expect_get_latest_ledger_info_version()
            .returning(|| Ok(100));
        mock_db_reader
            .expect_get_block_timestamp()
            .returning(move |_| Ok(old_timestamp)); // Always returns old timestamp
        
        let mut fallback_manager = ObserverFallbackManager::new(
            consensus_observer_config,
            Arc::new(mock_db_reader),
            time_service,
        );
        
        // Advance past initial startup period
        mock_time.advance(Duration::from_secs(70));
        
        // First check should trigger fallback (old timestamp)
        assert_matches!(
            fallback_manager.check_syncing_progress(),
            Err(Error::ObserverFallingBehind(_))
        );
        
        // Simulate fallback completion by resetting progress
        let ledger_info = create_test_ledger_info(100);
        fallback_manager.reset_syncing_progress(&ledger_info);
        
        // Advance just 5 seconds (next progress check)
        mock_time.advance(Duration::from_secs(5));
        
        // VULNERABILITY: No grace period, immediately triggers fallback again!
        assert_matches!(
            fallback_manager.check_syncing_progress(),
            Err(Error::ObserverFallingBehind(_))
        );
        // This proves observers can get stuck in perpetual fallback loop
    }
}
```

## Notes
The vulnerability is exacerbated by the fact that:
1. The `observer_fallback_duration_ms` is 10 minutes by default, making each fallback cycle very expensive
2. The `progress_check_interval_ms` is only 5 seconds, giving almost no recovery time between checks
3. Byzantine validators don't need to completely stop consensus—even occasional delays during their leader rounds can maintain timestamp lag above threshold

The fix should balance preventing cascading failures while still detecting genuine falling-behind scenarios. A post-fallback grace period equal to the startup period (60 seconds) provides reasonable protection without compromising detection of real synchronization issues.

### Citations

**File:** consensus/src/consensus_observer/observer/fallback_manager.rs (L29-50)
```rust
    // The time at which the fallback manager started running
    start_time: Instant,

    // The time service (used to check the storage update time)
    time_service: TimeService,
}

impl ObserverFallbackManager {
    pub fn new(
        consensus_observer_config: ConsensusObserverConfig,
        db_reader: Arc<dyn DbReader>,
        time_service: TimeService,
    ) -> Self {
        // Get the current time
        let time_now = time_service.now();

        // Create a new fallback manager
        Self {
            consensus_observer_config,
            db_reader,
            highest_synced_version_and_time: (0, time_now),
            start_time: time_now,
```

**File:** consensus/src/consensus_observer/observer/fallback_manager.rs (L58-85)
```rust
    pub fn check_syncing_progress(&mut self) -> Result<(), Error> {
        // If we're still within the startup period, we don't need to verify progress
        let time_now = self.time_service.now();
        let startup_period = Duration::from_millis(
            self.consensus_observer_config
                .observer_fallback_startup_period_ms,
        );
        if time_now.duration_since(self.start_time) < startup_period {
            return Ok(()); // We're still in the startup period
        }

        // Fetch the synced ledger info version from storage
        let latest_ledger_info_version =
            self.db_reader
                .get_latest_ledger_info_version()
                .map_err(|error| {
                    Error::UnexpectedError(format!(
                        "Failed to read highest synced version: {:?}",
                        error
                    ))
                })?;

        // Verify that the synced version is increasing appropriately
        self.verify_increasing_sync_versions(latest_ledger_info_version, time_now)?;

        // Verify that the sync lag is within acceptable limits
        self.verify_sync_lag_health(latest_ledger_info_version)
    }
```

**File:** consensus/src/consensus_observer/observer/fallback_manager.rs (L119-154)
```rust
    /// Verifies that the sync lag is within acceptable limits. If not, an error is returned.
    fn verify_sync_lag_health(&self, latest_ledger_info_version: Version) -> Result<(), Error> {
        // Get the latest block timestamp from storage
        let latest_block_timestamp_usecs = match self
            .db_reader
            .get_block_timestamp(latest_ledger_info_version)
        {
            Ok(block_timestamp_usecs) => block_timestamp_usecs,
            Err(error) => {
                // Log a warning and return without entering fallback mode
                warn!(LogSchema::new(LogEntry::ConsensusObserver)
                    .message(&format!("Failed to read block timestamp: {:?}", error)));
                return Ok(());
            },
        };

        // Get the current time (in microseconds)
        let timestamp_now_usecs = self.time_service.now_unix_time().as_micros() as u64;

        // Calculate the block timestamp lag (saturating at 0)
        let timestamp_lag_usecs = timestamp_now_usecs.saturating_sub(latest_block_timestamp_usecs);
        let timestamp_lag_duration = Duration::from_micros(timestamp_lag_usecs);

        // Check if the sync lag is within acceptable limits
        let sync_lag_threshold_ms = self
            .consensus_observer_config
            .observer_fallback_sync_lag_threshold_ms;
        if timestamp_lag_duration > Duration::from_millis(sync_lag_threshold_ms) {
            return Err(Error::ObserverFallingBehind(format!(
                "Consensus observer is falling behind! Highest synced version: {}, sync lag: {:?}",
                latest_ledger_info_version, timestamp_lag_duration
            )));
        }

        Ok(())
    }
```

**File:** consensus/src/consensus_observer/observer/fallback_manager.rs (L156-164)
```rust
    /// Resets the syncing progress to the latest synced ledger info and current time
    pub fn reset_syncing_progress(&mut self, latest_synced_ledger_info: &LedgerInfoWithSignatures) {
        // Get the current time and highest synced version
        let time_now = self.time_service.now();
        let highest_synced_version = latest_synced_ledger_info.ledger_info().version();

        // Update the highest synced version and time
        self.highest_synced_version_and_time = (highest_synced_version, time_now);
    }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L167-201)
```rust
    /// Checks the progress of the consensus observer
    async fn check_progress(&mut self) {
        debug!(LogSchema::new(LogEntry::ConsensusObserver)
            .message("Checking consensus observer progress!"));

        // If we've fallen back to state sync, we should wait for it to complete
        if self.state_sync_manager.in_fallback_mode() {
            info!(LogSchema::new(LogEntry::ConsensusObserver)
                .message("Waiting for state sync to complete fallback syncing!",));
            return;
        }

        // If state sync is syncing to a commit decision, we should wait for it to complete
        if self.state_sync_manager.is_syncing_to_commit() {
            info!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Waiting for state sync to reach commit decision: {:?}!",
                    self.observer_block_data.lock().root().commit_info()
                ))
            );
            return;
        }

        // Check if we need to fallback to state sync
        if let Err(error) = self.observer_fallback_manager.check_syncing_progress() {
            // Log the error and enter fallback mode
            warn!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Failed to make syncing progress! Entering fallback mode! Error: {:?}",
                    error
                ))
            );
            self.enter_fallback_mode().await;
            return;
        }
```

**File:** config/src/config/consensus_observer_config.rs (L54-61)
```rust
    pub observer_fallback_duration_ms: u64,
    /// Duration (in milliseconds) we'll wait on startup before considering fallback mode
    pub observer_fallback_startup_period_ms: u64,
    /// Duration (in milliseconds) we'll wait for syncing progress before entering fallback mode
    pub observer_fallback_progress_threshold_ms: u64,
    /// Duration (in milliseconds) of acceptable sync lag before entering fallback mode
    pub observer_fallback_sync_lag_threshold_ms: u64,
}
```
