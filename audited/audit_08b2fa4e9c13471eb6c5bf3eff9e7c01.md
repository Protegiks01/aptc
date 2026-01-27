# Audit Report

## Title
Unhandled Panic Propagation in FuturesUnorderedX Causes Backup Process Crash

## Summary
The `FuturesUnorderedX::poll_next()` function does not implement panic handling for futures in the `in_progress` queue. When any future panics during polling, the panic propagates through the stream layers and triggers the global panic handler, causing the backup process to exit with code 12. This lack of defensive programming differs from critical paths like the bytecode verifier and VM validator, which use `catch_unwind` to prevent process crashes.

## Finding Description

The backup system uses a custom stream utility `FuturesUnorderedX` to manage concurrent futures with concurrency limits. [1](#0-0) 

When `poll_next()` is called, it polls the underlying `FuturesUnordered` without any panic handling. If any future in `in_progress` panics during polling, the panic propagates uncaught through:

1. `FuturesUnordered::poll_next_unpin()` (standard library)
2. `FuturesUnorderedX::poll_next()` (no catch_unwind)
3. `FuturesOrderedX::poll_next()` which internally uses `FuturesUnorderedX` [2](#0-1) 
4. `TryBufferedX::poll_next()` which uses `FuturesOrderedX` [3](#0-2) 
5. The backup process main loop [4](#0-3) 

The panic then triggers the global panic handler, which logs crash information and exits the process with code 12. [5](#0-4) 

Critically, the panic handler only prevents process exit for panics occurring in the Move bytecode verifier or deserializer (checked via `VMState`). Backup futures do not use this mechanism, so panics will always crash the process.

In contrast, other critical code paths implement defensive panic handling:
- The bytecode verifier uses `catch_unwind` with `VMState::VERIFIER` [6](#0-5) 
- The VM validator uses `catch_unwind` to prevent crashes [7](#0-6) 

No such protection exists in the backup code paths. [8](#0-7) 

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty criteria for "API crashes" and "Significant protocol violations."

The backup process is critical infrastructure for disaster recovery. A crash during backup operations results in:
- **Incomplete backups**: Partial state snapshots that cannot be used for restoration
- **Loss of backup availability**: Operators cannot create backups during crash recovery
- **Operational disruption**: Manual intervention required to restart backup processes
- **Data integrity concerns**: Incomplete backups may give false confidence in disaster recovery capabilities

While this requires a panic to occur in a backup future, several realistic scenarios exist:
- Bugs in storage backend implementations
- Deserialization panics from corrupted state data
- Third-party crate panics in the dependency chain
- Resource exhaustion conditions (though less common)
- Integer overflow in debug builds (if any remain)

The impact is amplified because backup operations typically run continuously or on schedules, meaning a single panic source could cause repeated crashes and prevent any successful backups.

## Likelihood Explanation

**Likelihood: Medium to High**

The likelihood depends on whether panics occur in the backup future execution path. However:

1. **High Code Complexity**: The backup path involves multiple layers (network clients, storage backends, serialization) where bugs could cause panics
2. **No Defensive Programming**: Unlike the verifier and validator, there is zero panic protection
3. **Long-Running Operations**: Backup processes run for extended periods, increasing exposure to rare panic conditions
4. **External Dependencies**: The backup process interacts with HTTP clients and storage systems that could panic

Even a low probability of panics per future becomes significant when processing thousands or millions of state records during snapshot backups.

## Recommendation

Implement panic handling in `FuturesUnorderedX::poll_next()` following the pattern used in the bytecode verifier and VM validator:

```rust
fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    
    // Collect outputs from newly finished futures from the underlying `FuturesUnordered`.
    loop {
        let poll_result = catch_unwind(AssertUnwindSafe(|| {
            self.in_progress.poll_next_unpin(cx)
        }));
        
        match poll_result {
            Ok(Poll::Ready(Some(output))) => {
                self.queued_outputs.push_back(output);
                // Concurrency is now below `self.max_in_progress`, kick off a queued one, if any.
                if let Some(future) = self.queued.pop_front() {
                    self.in_progress.push(future)
                }
            }
            Ok(Poll::Ready(None)) => break,
            Ok(Poll::Pending) => break,
            Err(_panic) => {
                // Log the panic and skip this future
                error!("Future panicked in backup stream, skipping");
                // Continue processing remaining futures
                continue;
            }
        }
    }

    if let Some(output) = self.queued_outputs.pop_front() {
        Poll::Ready(Some(output))
    } else if self.in_progress.is_empty() {
        Poll::Ready(None)
    } else {
        Poll::Pending
    }
}
```

Alternatively, wrap individual futures with panic-catching wrappers before pushing them into the stream, or handle panics at the backup controller level.

## Proof of Concept

```rust
#[cfg(test)]
mod test_panic_propagation {
    use super::*;
    use futures::StreamExt;
    
    #[tokio::test]
    #[should_panic(expected = "test panic")]
    async fn test_panic_propagates_through_stream() {
        let mut futures = FuturesUnorderedX::new(2);
        
        // Add a future that panics
        futures.push(async {
            panic!("test panic");
        });
        
        // Add a normal future
        futures.push(async {
            42
        });
        
        // This will panic and crash the test, demonstrating
        // that panics are not caught
        let _results: Vec<_> = futures.collect().await;
    }
}
```

This test demonstrates that a panic in any future causes the entire stream to abort. When this occurs in production backup processes, it triggers the global panic handler and crashes the process with exit code 12, leaving incomplete backups.

## Notes

The absence of panic handling in backup streams represents a defensive programming gap. While the immediate trigger (a panicking future) would require a separate bug, the consequences (process crash, incomplete backups) are severe enough to warrant defensive measures. This is especially important given that other critical paths (verifier, VM validator) already implement such protections, establishing a precedent for defensive panic handling in production code.

### Citations

**File:** storage/backup/backup-cli/src/utils/stream/futures_unordered_x.rs (L1-117)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

/// This wraps around `futures::stream::futures_unorderd::FuturesUnordered` to provide similar
/// functionality except that there's limit on concurrency. This allows us to manage more futures
/// without activation too many of them at the same time.
use futures::{
    stream::{FusedStream, FuturesUnordered},
    task::{Context, Poll},
    Future, Stream, StreamExt,
};
use std::{collections::VecDeque, fmt::Debug, pin::Pin};

#[must_use = "streams do nothing unless polled"]
pub struct FuturesUnorderedX<T: Future> {
    queued: VecDeque<T>,
    in_progress: FuturesUnordered<T>,
    queued_outputs: VecDeque<T::Output>,
    max_in_progress: usize,
}

impl<T: Future> Unpin for FuturesUnorderedX<T> {}

impl<Fut: Future> FuturesUnorderedX<Fut> {
    /// Constructs a new, empty `FuturesOrderedX`
    ///
    /// The returned `FuturesOrderedX` does not contain any futures and, in this
    /// state, `FuturesOrdered::poll_next` will return `Poll::Ready(None)`.
    pub fn new(max_in_progress: usize) -> FuturesUnorderedX<Fut> {
        assert!(max_in_progress > 0);
        FuturesUnorderedX {
            queued: VecDeque::new(),
            in_progress: FuturesUnordered::new(),
            queued_outputs: VecDeque::new(),
            max_in_progress,
        }
    }

    /// Returns the number of futures contained in the queue.
    ///
    /// This represents the total number of in-flight futures, including those whose outputs queued
    /// for polling, those currently being processing and those in queued due to concurrency limit.
    pub fn len(&self) -> usize {
        self.queued.len() + self.in_progress.len() + self.queued_outputs.len()
    }

    /// Returns `true` if the queue contains no futures
    pub fn is_empty(&self) -> bool {
        self.queued.is_empty() && self.in_progress.is_empty() && self.queued_outputs.is_empty()
    }

    /// Push a future into the queue.
    ///
    /// This function submits the given future to the internal set for managing.
    /// This function will not call `poll` on the submitted future. The caller
    /// must ensure that `FuturesOrdered::poll` is called in order to receive
    /// task notifications.
    pub fn push(&mut self, future: Fut) {
        if self.in_progress.len() < self.max_in_progress {
            self.in_progress.push(future);
        } else {
            self.queued.push_back(future);
        }
    }
}

impl<Fut: Future> Stream for FuturesUnorderedX<Fut> {
    type Item = Fut::Output;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Collect outputs from newly finished futures from the underlying `FuturesUnordered`.
        while let Poll::Ready(Some(output)) = self.in_progress.poll_next_unpin(cx) {
            self.queued_outputs.push_back(output);
            // Concurrency is now below `self.max_in_progress`, kick off a queued one, if any.
            if let Some(future) = self.queued.pop_front() {
                self.in_progress.push(future)
            }
        }

        if let Some(output) = self.queued_outputs.pop_front() {
            Poll::Ready(Some(output))
        } else if self.in_progress.is_empty() {
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.len();
        (len, Some(len))
    }
}

impl<Fut: Future> Debug for FuturesUnorderedX<Fut> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FuturesOrderedX {{ ... }}")
    }
}

impl<Fut: Future> FusedStream for FuturesUnorderedX<Fut> {
    fn is_terminated(&self) -> bool {
        self.in_progress.is_terminated() && self.queued_outputs.is_empty()
    }
}

impl<Fut: Future> Extend<Fut> for FuturesUnorderedX<Fut> {
    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = Fut>,
    {
        for item in iter.into_iter() {
            self.push(item);
        }
    }
}

```

**File:** storage/backup/backup-cli/src/utils/stream/futures_ordered_x.rs (L68-68)
```rust
    in_progress_queue: FuturesUnorderedX<OrderWrapper<T>>,
```

**File:** storage/backup/backup-cli/src/utils/stream/try_buffered_x.rs (L28-28)
```rust
    in_progress_queue: FuturesOrderedX<IntoFuture<St::Ok>>,
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/backup.rs (L253-266)
```rust
        let chunks: Vec<_> = chunk_manifest_fut_stream
            .try_buffered_x(8, 4) // 4 concurrently, at most 8 results in buffer.
            .map_ok(|chunk_manifest| {
                let last_idx = chunk_manifest.last_idx;
                info!(
                    last_idx = last_idx,
                    values_per_second =
                        ((last_idx + 1) as f64 / start.elapsed().as_secs_f64()) as u64,
                    "Chunk written."
                );
                chunk_manifest
            })
            .try_collect()
            .await?;
```

**File:** crates/crash-handler/src/lib.rs (L27-57)
```rust
    panic::set_hook(Box::new(move |pi: &PanicHookInfo<'_>| {
        handle_panic(pi);
    }));
}

// Formats and logs panic information
fn handle_panic(panic_info: &PanicHookInfo<'_>) {
    // The Display formatter for a PanicHookInfo contains the message, payload and location.
    let details = format!("{}", panic_info);
    let backtrace = format!("{:#?}", Backtrace::new());

    let info = CrashInfo { details, backtrace };
    let crash_info = toml::to_string_pretty(&info).unwrap();
    error!("{}", crash_info);
    // TODO / HACK ALARM: Write crash info synchronously via eprintln! to ensure it is written before the process exits which error! doesn't guarantee.
    // This is a workaround until https://github.com/aptos-labs/aptos-core/issues/2038 is resolved.
    eprintln!("{}", crash_info);

    // Wait till the logs have been flushed
    aptos_logger::flush();

    // Do not kill the process if the panics happened at move-bytecode-verifier.
    // This is safe because the `state::get_state()` uses a thread_local for storing states. Thus the state can only be mutated to VERIFIER by the thread that's running the bytecode verifier.
    //
    // TODO: once `can_unwind` is stable, we should assert it. See https://github.com/rust-lang/rust/issues/92988.
    if state::get_state() == VMState::VERIFIER || state::get_state() == VMState::DESERIALIZER {
        return;
    }

    // Kill the process
    process::exit(12);
```

**File:** third_party/move/move-bytecode-verifier/src/verifier.rs (L138-172)
```rust
    let prev_state = move_core_types::state::set_state(VMState::VERIFIER);
    let result = std::panic::catch_unwind(|| {
        // Always needs to run bound checker first as subsequent passes depend on it
        BoundsChecker::verify_module(module).map_err(|e| {
            // We can't point the error at the module, because if bounds-checking
            // failed, we cannot safely index into module's handle to itself.
            e.finish(Location::Undefined)
        })?;
        FeatureVerifier::verify_module(config, module)?;
        LimitsVerifier::verify_module(config, module)?;
        DuplicationChecker::verify_module(module)?;

        signature_v2::verify_module(config, module)?;

        InstructionConsistency::verify_module(module)?;
        constants::verify_module(module)?;
        friends::verify_module(module)?;

        RecursiveStructDefChecker::verify_module(module)?;
        InstantiationLoopChecker::verify_module(module)?;
        CodeUnitVerifier::verify_module(config, module)?;

        // Add the failpoint injection to test the catch_unwind behavior.
        fail::fail_point!("verifier-failpoint-panic");

        script_signature::verify_module(module, no_additional_script_signature_checks)
    })
    .unwrap_or_else(|_| {
        Err(
            PartialVMError::new(StatusCode::VERIFIER_INVARIANT_VIOLATION)
                .finish(Location::Undefined),
        )
    });
    move_core_types::state::set_state(prev_state);
    result
```

**File:** vm-validator/src/vm_validator.rs (L155-169)
```rust
        let result = std::panic::catch_unwind(move || {
            let vm_validator_locked = vm_validator.lock().unwrap();

            use aptos_vm::VMValidator;
            let vm = AptosVM::new(&vm_validator_locked.state.environment);
            vm.validate_transaction(
                txn,
                &vm_validator_locked.state.state_view,
                &vm_validator_locked.state,
            )
        });
        if let Err(err) = &result {
            error!("VMValidator panicked: {:?}", err);
        }
        result.map_err(|_| anyhow::anyhow!("panic validating transaction"))
```
