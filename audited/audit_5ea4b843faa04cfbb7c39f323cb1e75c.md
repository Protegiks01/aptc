# Audit Report

## Title
DKG Session Loss Due to Silent Error Handling in Epoch Manager State Deserialization

## Summary
The DKG epoch manager silently defaults to an empty state when DKGState deserialization fails, causing validators that restart during an active DKG session to lose track of in-progress DKG work and fail to resume participation. This can lead to network liveness failures if multiple validators experience storage issues simultaneously.

## Finding Description

In `dkg/src/epoch_manager.rs`, the `start_new_epoch()` function reads the on-chain DKGState to check if there's an in-progress DKG session that should be resumed: [1](#0-0) 

The `unwrap_or_default()` pattern silently masks any deserialization failures. When `payload.get::<DKGState>()` fails, it returns a default state with `in_progress: None` and `last_completed: None`: [2](#0-1) 

The `in_progress_session` variable (which becomes `None`) is then passed to `DKGManager::run()`: [3](#0-2) 

When DKGManager receives `None` for an in-progress session, it skips resumption: [4](#0-3) 

The validator will wait for a new DKGStartEvent, but since DKG was already started on-chain, no new event will be emitted: [5](#0-4) 

**Attack Scenario:**
1. DKG session starts on-chain for epoch N+1 during epoch N
2. Validator experiences storage issues (corruption, transient database errors) and restarts
3. During restart, `DbBackedOnChainConfig::get()` fails when reading DKGState: [6](#0-5) 

4. The error is silently suppressed by `unwrap_or_default()`, returning empty state
5. Validator doesn't resume DKG participation
6. If enough validators (>1/3) experience similar issues, DKG cannot reach quorum
7. Network gets stuck - cannot complete DKG, cannot progress to next epoch

## Impact Explanation

**Severity: Medium (Availability/Liveness Issue)**

This is **NOT** a Critical or High severity security vulnerability because:
- It requires node infrastructure failures (storage corruption, database errors), not attacker actions
- An unprivileged attacker cannot directly cause DKGState deserialization failures
- It's not exploitable without node-level access or infrastructure compromise

However, it represents a **Medium severity** operational resilience issue:
- Can cause network liveness degradation if multiple validators fail simultaneously
- Requires manual intervention (restarting affected validators or clearing incomplete sessions)
- Violates defensive programming principles by silently hiding critical errors

## Likelihood Explanation

**Likelihood: Low to Medium**

The likelihood depends on infrastructure quality:
- **Low** in production with robust storage systems
- **Medium** during network stress, hardware failures, or database maintenance
- Validators with poor storage reliability are more susceptible
- Simultaneous failures across multiple validators required for network impact

## Recommendation

Replace `unwrap_or_default()` with explicit error handling that logs failures and either retries or fails loudly:

```rust
let dkg_state_result = payload.get::<DKGState>();
let in_progress_session = match dkg_state_result {
    Ok(DKGState { in_progress, .. }) => in_progress,
    Err(e) => {
        error!(
            epoch = epoch_state.epoch,
            error = %e,
            "Failed to deserialize DKGState - DKG resumption may fail. \
             Consider manual intervention if DKG is in progress."
        );
        // Could also implement retry logic here
        None
    }
};
```

Alternatively, follow the pattern used in consensus epoch manager which propagates errors properly: [7](#0-6) [8](#0-7) 

## Proof of Concept

This is a defensive programming issue rather than an exploitable vulnerability. A PoC would require:

1. Setting up a validator node
2. Starting a DKG session
3. Injecting storage failures during node restart
4. Observing that the validator doesn't resume DKG

Since this requires infrastructure manipulation rather than protocol exploitation, it falls outside the scope of a traditional security PoC.

---

**Notes:**
While this is a real code quality issue that could impact network reliability, it does **not** constitute an exploitable security vulnerability per the bug bounty criteria. It's an operational resilience concern that should be addressed through better error handling and monitoring, but lacks the attacker-controllable exploit path required for a security finding.

### Citations

**File:** dkg/src/epoch_manager.rs (L202-205)
```rust
            let DKGState {
                in_progress: in_progress_session,
                ..
            } = payload.get::<DKGState>().unwrap_or_default();
```

**File:** dkg/src/epoch_manager.rs (L253-258)
```rust
            tokio::spawn(dkg_manager.run(
                in_progress_session,
                dkg_start_event_rx,
                dkg_rpc_msg_rx,
                dkg_manager_close_rx,
            ));
```

**File:** types/src/dkg/mod.rs (L141-145)
```rust
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DKGState {
    pub last_completed: Option<DKGSessionState>,
    pub in_progress: Option<DKGSessionState>,
}
```

**File:** dkg/src/dkg_manager/mod.rs (L140-162)
```rust
        if let Some(session_state) = in_progress_session {
            let DKGSessionState {
                start_time_us,
                metadata,
                ..
            } = session_state;

            if metadata.dealer_epoch == self.epoch_state.epoch {
                info!(
                    epoch = self.epoch_state.epoch,
                    "Found unfinished and current DKG session. Continuing it."
                );
                if let Err(e) = self.setup_deal_broadcast(start_time_us, &metadata).await {
                    error!(epoch = self.epoch_state.epoch, "dkg resumption failed: {e}");
                }
            } else {
                info!(
                    cur_epoch = self.epoch_state.epoch,
                    dealer_epoch = metadata.dealer_epoch,
                    "Found unfinished but stale DKG session. Ignoring it."
                );
            }
        }
```

**File:** aptos-move/framework/aptos-framework/sources/dkg.move (L59-85)
```text
    /// Mark on-chain DKG state as in-progress. Notify validators to start DKG.
    /// Abort if a DKG is already in progress.
    public(friend) fun start(
        dealer_epoch: u64,
        randomness_config: RandomnessConfig,
        dealer_validator_set: vector<ValidatorConsensusInfo>,
        target_validator_set: vector<ValidatorConsensusInfo>,
    ) acquires DKGState {
        let dkg_state = borrow_global_mut<DKGState>(@aptos_framework);
        let new_session_metadata = DKGSessionMetadata {
            dealer_epoch,
            randomness_config,
            dealer_validator_set,
            target_validator_set,
        };
        let start_time_us = timestamp::now_microseconds();
        dkg_state.in_progress = std::option::some(DKGSessionState {
            metadata: new_session_metadata,
            start_time_us,
            transcript: vector[],
        });

        emit(DKGStartEvent {
            start_time_us,
            session_metadata: new_session_metadata,
        });
    }
```

**File:** state-sync/inter-component/event-notifications/src/lib.rs (L397-412)
```rust
impl OnChainConfigProvider for DbBackedOnChainConfig {
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

**File:** consensus/src/epoch_manager.rs (L1039-1039)
```rust
        let dkg_state = maybe_dkg_state.map_err(NoRandomnessReason::DKGStateResourceMissing)?;
```

**File:** consensus/src/epoch_manager.rs (L1185-1186)
```rust
        let dkg_state = payload.get::<DKGState>();

```
