# Audit Report

## Title
Timeout Task Resource Leak During RoundState Destruction in Consensus Layer

## Summary
The `RoundState` struct in the consensus liveness module does not implement the `Drop` trait, causing timeout tasks to continue running after the `RoundState` is dropped during epoch transitions. While spawned tasks are not properly aborted, the security impact is mitigated by round validation checks that filter out stale timeout messages.

## Finding Description

When `RoundState` is dropped (typically during epoch transitions when `EpochManager::shutdown_current_processor()` is called), any active timeout task associated with the `abort_handle` field continues executing because the `AbortHandle` is dropped without calling `abort()`. [1](#0-0) 

The `RoundState` struct stores an `Option<AbortHandle>` but does not implement `Drop`. When a new round starts, the previous timeout handle is properly aborted: [2](#0-1) 

However, when `RoundState` itself is destroyed, no such cleanup occurs. The timeout task, spawned by `ClockTimeService::run_after()`, wraps the actual work in an `Abortable` future: [3](#0-2) 

According to the `futures` crate semantics, simply dropping an `AbortHandle` does not cancel the associated task—only calling `abort()` does. Other parts of the codebase recognize this pattern and use `DropGuard` to ensure automatic abort on drop: [4](#0-3) 

**Exploitation Path:**
1. During normal operation, `RoundState` has an active timeout task scheduled
2. `EpochManager::shutdown_current_processor()` initiates epoch transition
3. `RoundManager` receives close signal and drops, which drops `RoundState`
4. The `abort_handle` is dropped without calling `abort()`
5. The timeout task continues running and eventually sends a stale round number
6. `EpochManager::process_local_timeout()` receives the message
7. The message is forwarded to the new epoch's `RoundManager`

**Mitigation Check:**
The critical security protection is in `RoundState::process_local_timeout()`: [5](#0-4) 

This function checks if the received round matches the current round. Stale timeouts from previous epochs are rejected and have no effect on consensus.

## Impact Explanation

**Actual Impact: Low/Non-Security**

While this is a resource management bug, it does **not** meet the Medium severity threshold ($10,000) for the Aptos bug bounty program:

- **No Consensus Impact**: Stale timeout messages are filtered by round validation checks
- **No Safety Violation**: Cannot cause different validators to commit different blocks
- **Minimal Resource Leak**: Spawned tasks are lightweight (sleep + single channel send)
- **Temporary**: Tasks complete after timeout duration and are garbage collected
- **No Funds at Risk**: Cannot lead to theft, minting, or freezing of funds

The only observable effects are:
1. Unnecessary CPU/memory usage for the duration of the timeout
2. Warning logs if timeout fires between epoch shutdown and new epoch start [6](#0-5) 

## Likelihood Explanation

**Occurrence: High, Impact: Negligible**

This issue occurs during every epoch transition when:
- `RoundState` has an active timeout (very common)
- The timeout hasn't fired yet when shutdown occurs
- The epoch transition completes before the timeout expires

Epoch transitions happen regularly in the Aptos network, making this technically frequent. However, the mitigated impact means there's no exploitable security vulnerability.

## Recommendation

Implement the `Drop` trait for `RoundState` to properly abort pending timeout tasks:

```rust
impl Drop for RoundState {
    fn drop(&mut self) {
        if let Some(handle) = self.abort_handle.take() {
            handle.abort();
        }
    }
}
```

Alternatively, wrap the `AbortHandle` in a `DropGuard` to ensure automatic cleanup:

```rust
use aptos_reliable_broadcast::DropGuard;

pub struct RoundState {
    // ... other fields ...
    abort_handle: Option<DropGuard>,
}
```

## Proof of Concept

This is a passive resource management issue rather than an exploitable vulnerability. The bug manifests during normal epoch transitions and cannot be triggered by external attackers. A test demonstrating the issue would show:

```rust
#[tokio::test]
async fn test_round_state_timeout_leak() {
    let (timeout_tx, mut timeout_rx) = aptos_channels::new_test(10);
    let time_service = Arc::new(ClockTimeService::new(tokio::runtime::Handle::current()));
    
    {
        let mut round_state = RoundState::new(
            Box::new(ExponentialTimeInterval::fixed(Duration::from_millis(100))),
            time_service,
            timeout_tx,
        );
        round_state.process_certificates(/* setup new round */);
        // RoundState dropped here without aborting timeout
    }
    
    // Timeout task still runs and sends message
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(timeout_rx.next().await.is_some()); // Message received despite RoundState dropped
}
```

However, this demonstrates a code quality issue, not a security vulnerability meeting bug bounty criteria.

---

**Notes:**

After thorough analysis, this issue is better classified as a **resource management bug** rather than a security vulnerability. While the `abort_handle` lifecycle is improperly managed, the consensus protocol has defense-in-depth checks that prevent stale timeout messages from causing any consensus impact. The spawned tasks are lightweight and short-lived, resulting in negligible resource consumption. This does not meet the Medium severity threshold requiring "state inconsistencies requiring intervention" or "limited funds loss."

### Citations

**File:** consensus/src/liveness/round_state.rs (L165-166)
```rust
    abort_handle: Option<AbortHandle>,
}
```

**File:** consensus/src/liveness/round_state.rs (L233-241)
```rust
    pub fn process_local_timeout(&mut self, round: Round) -> bool {
        if round != self.current_round {
            return false;
        }
        warn!(round = round, "Local timeout");
        counters::TIMEOUT_COUNT.inc();
        self.setup_timeout(1);
        true
    }
```

**File:** consensus/src/liveness/round_state.rs (L347-352)
```rust
        let abort_handle = self
            .time_service
            .run_after(timeout, SendTask::make(timeout_sender, self.current_round));
        if let Some(handle) = self.abort_handle.replace(abort_handle) {
            handle.abort();
        }
```

**File:** consensus/src/util/time_service.rs (L114-125)
```rust
    fn run_after(&self, timeout: Duration, mut t: Box<dyn ScheduledTask>) -> AbortHandle {
        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        let task = Abortable::new(
            async move {
                sleep(timeout).await;
                t.run().await;
            },
            abort_registration,
        );
        self.executor.spawn(task);
        abort_handle
    }
```

**File:** crates/reliable-broadcast/src/lib.rs (L222-236)
```rust
pub struct DropGuard {
    abort_handle: AbortHandle,
}

impl DropGuard {
    pub fn new(abort_handle: AbortHandle) -> Self {
        Self { abort_handle }
    }
}

impl Drop for DropGuard {
    fn drop(&mut self) {
        self.abort_handle.abort();
    }
}
```

**File:** consensus/src/epoch_manager.rs (L1897-1903)
```rust
        let Some(sender) = self.round_manager_tx.as_mut() else {
            warn!(
                "Received local timeout for round {} without Round Manager",
                round
            );
            return;
        };
```
