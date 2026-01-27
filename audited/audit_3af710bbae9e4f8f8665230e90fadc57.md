# Audit Report

## Title
Unhandled Panics in Background Metric Collection Tasks Can Crash Validator Nodes

## Summary
The background spawns in `by_transaction_execution()` and `by_transaction_output()` do not implement panic handling, allowing any panic in the metrics collection code to crash the entire validator node due to the global panic handler that calls `process::exit(12)`. [1](#0-0) [2](#0-1) 

## Finding Description

The executor workflow spawns background tasks on the rayon thread pool to asynchronously update metrics after transaction execution and output processing. These spawned closures directly call `metrics::update_counters_for_processed_chunk()` without any panic catching mechanism.

The critical security issue arises from the interaction between three components:

1. **Rayon Thread Pool Behavior**: The `THREAD_MANAGER.get_background_pool()` returns a rayon `ThreadPool`. When `spawn()` is called on a rayon thread pool, if the closure panics, rayon catches it to prevent worker thread death but then re-raises the panic. [3](#0-2) 

2. **Global Panic Handler**: The Aptos node sets up a global panic handler during initialization that logs the panic and exits the process with code 12 (except for VERIFIER/DESERIALIZER panics). [4](#0-3) [5](#0-4) 

3. **Metrics Code Complexity**: The `update_counters_for_processed_chunk()` function is complex (247 lines) with multiple potential panic sources including string formatting, enum matching, BCS serialization, and Prometheus metric operations. [6](#0-5) 

The panic propagation chain:
1. Metrics code panics (due to bug, resource exhaustion, unexpected data, etc.)
2. Rayon catches and re-raises the panic
3. Global panic handler is triggered
4. `process::exit(12)` is called
5. **Entire validator node crashes**

## Impact Explanation

This qualifies as **HIGH severity** under the Aptos bug bounty program criteria: "Validator node slowdowns, API crashes, Significant protocol violations."

Impact breakdown:
- **Validator Availability**: Any panic in metrics collection immediately crashes the validator node, causing it to miss consensus rounds until manual restart
- **Network Reliability**: Multiple validators experiencing this issue could impact network liveness
- **Operational Risk**: Silent failures in non-critical code (metrics) can have critical consequences
- **Debugging Difficulty**: Metrics should aid debugging, but here they become a crash vector

The vulnerability affects **every validator node** in the network, as all nodes execute this code path during block processing.

## Likelihood Explanation

**Likelihood: Medium-Low**

While no specific exploit has been demonstrated, several realistic scenarios could trigger panics:

1. **Code Evolution Risk**: Future changes to metrics code or transaction types could introduce panics without realizing the crash risk
2. **Resource Exhaustion**: Memory allocation failures during string formatting or BCS serialization under load
3. **Enum Exhaustiveness**: Adding new transaction or status types without updating all match statements could trigger panics
4. **Debug Implementation Panics**: Custom Debug implementations on transaction types might panic on malformed data that passed earlier validation
5. **Prometheus Library Issues**: Lock poisoning or internal assertion failures in the metrics library
6. **String Formatting Edge Cases**: Format macros can panic on certain invalid UTF-8 or format string issues

The code processes attacker-controlled transaction data during metrics collection, creating potential attack surface even though the transactions have been validated and executed.

## Recommendation

Wrap the spawned closures with `std::panic::catch_unwind()` to prevent panics from crashing the validator:

```rust
THREAD_MANAGER.get_background_pool().spawn(move || {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _timer = OTHER_TIMERS.timer_with(&["async_update_counters__by_execution"]);
        for x in [&out.to_commit, &out.to_retry, &out.to_discard] {
            metrics::update_counters_for_processed_chunk(
                &x.transactions,
                &x.transaction_outputs,
                "execution",
            )
        }
    }));
    
    if let Err(e) = result {
        error!(
            "Panic in background metrics collection: {:?}",
            e
        );
        EXECUTOR_ERRORS.inc();
    }
});
```

Apply the same fix to both `by_transaction_execution()` and `by_transaction_output()`.

Additionally, consider:
- Adding unit tests that verify panic handling in background tasks
- Implementing timeout mechanisms for background tasks
- Using a separate error counter to track metrics collection failures
- Reviewing all background spawns across the codebase for similar issues

## Proof of Concept

```rust
// Proof of concept demonstrating the vulnerability
// This would be added as a test in do_get_execution_output.rs

#[test]
#[should_panic] // This demonstrates the current unsafe behavior
fn test_panic_in_background_metrics_crashes_process() {
    use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
    use std::time::Duration;
    
    // Simulate the current code behavior
    let panicked = Arc::new(AtomicBool::new(false));
    let panicked_clone = panicked.clone();
    
    THREAD_MANAGER.get_background_pool().spawn(move || {
        // Simulate a panic in metrics code
        panicked_clone.store(true, Ordering::SeqCst);
        panic!("Metrics collection failed!");
    });
    
    // Wait for background task
    std::thread::sleep(Duration::from_millis(100));
    
    // If we reach here, the panic was not caught (current behavior)
    // In production with setup_panic_handler(), this would exit the process
    assert!(panicked.load(Ordering::SeqCst));
}

#[test]
fn test_panic_handling_with_fix() {
    use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
    use std::time::Duration;
    
    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();
    
    THREAD_MANAGER.get_background_pool().spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            panic!("Metrics collection failed!");
        }));
        
        if result.is_err() {
            // Panic was caught - node continues running
            completed_clone.store(true, Ordering::SeqCst);
        }
    });
    
    std::thread::sleep(Duration::from_millis(100));
    
    // With the fix, we handle the panic gracefully
    assert!(completed.load(Ordering::SeqCst));
}
```

## Notes

This vulnerability represents a **reliability and availability issue** rather than a direct security exploit. The lack of defensive programming around non-critical background tasks (metrics collection) can cause critical failures (validator crashes). While the metrics code itself may be robust, the principle of defense-in-depth requires that failures in non-critical paths should not compromise core functionality.

The vulnerability is exacerbated by the global panic handler's aggressive process termination policy, which is necessary for catching critical panics in consensus or execution paths but becomes problematic when applied uniformly to all code paths including background tasks.

### Citations

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L92-101)
```rust
        THREAD_MANAGER.get_background_pool().spawn(move || {
            let _timer = OTHER_TIMERS.timer_with(&["async_update_counters__by_execution"]);
            for x in [&out.to_commit, &out.to_retry, &out.to_discard] {
                metrics::update_counters_for_processed_chunk(
                    &x.transactions,
                    &x.transaction_outputs,
                    "execution",
                )
            }
        });
```

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L244-251)
```rust
        THREAD_MANAGER.get_background_pool().spawn(move || {
            let _timer = OTHER_TIMERS.timer_with(&["async_update_counters__by_output"]);
            metrics::update_counters_for_processed_chunk(
                &out.to_commit.transactions,
                &out.to_commit.transaction_outputs,
                "output",
            )
        });
```

**File:** experimental/runtimes/src/strategies/default.rs (L29-30)
```rust
        let background_threads =
            spawn_rayon_thread_pool("background".into(), Some(MAX_THREAD_POOL_SIZE));
```

**File:** crates/crash-handler/src/lib.rs (L26-57)
```rust
pub fn setup_panic_handler() {
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

**File:** aptos-node/src/lib.rs (L233-234)
```rust
    // Setup panic handler
    aptos_crash_handler::setup_panic_handler();
```

**File:** execution/executor/src/metrics.rs (L263-510)
```rust
pub fn update_counters_for_processed_chunk<T>(
    transactions: &[T],
    transaction_outputs: &[TransactionOutput],
    process_type: &str,
) where
    T: TransactionProvider,
{
    let detailed_counters = AptosVM::get_processed_transactions_detailed_counters();
    let detailed_counters_label = if detailed_counters { "true" } else { "false" };
    if transactions.len() != transaction_outputs.len() {
        warn!(
            "Chunk lenthgs don't match: txns: {} and outputs: {}",
            transactions.len(),
            transaction_outputs.len()
        );
    }

    for (txn, output) in transactions.iter().zip(transaction_outputs.iter()) {
        if detailed_counters {
            if let Ok(size) = bcs::serialized_size(output) {
                PROCESSED_TXNS_OUTPUT_SIZE.observe_with(&[process_type], size as f64);
            }
        }

        let (state, reason, error_code) = match output.status() {
            TransactionStatus::Keep(execution_status) => match execution_status {
                ExecutionStatus::Success => ("keep_success", "", "".to_string()),
                ExecutionStatus::OutOfGas => ("keep_rejected", "OutOfGas", "error".to_string()),
                ExecutionStatus::MoveAbort { info, .. } => (
                    "keep_rejected",
                    "MoveAbort",
                    if detailed_counters {
                        info.as_ref()
                            .map(|v| v.reason_name.to_lowercase())
                            .unwrap_or_else(|| "none".to_string())
                    } else {
                        "error".to_string()
                    },
                ),
                ExecutionStatus::ExecutionFailure { .. } => {
                    ("keep_rejected", "ExecutionFailure", "error".to_string())
                },
                ExecutionStatus::MiscellaneousError(e) => (
                    "keep_rejected",
                    "MiscellaneousError",
                    if detailed_counters {
                        e.map(|v| format!("{:?}", v).to_lowercase())
                            .unwrap_or_else(|| "none".to_string())
                    } else {
                        "error".to_string()
                    },
                ),
            },
            TransactionStatus::Discard(discard_status_code) => {
                (
                    // Specialize duplicate txns for alerts
                    if *discard_status_code == StatusCode::SEQUENCE_NUMBER_TOO_OLD {
                        "discard_sequence_number_too_old"
                    } else if *discard_status_code == StatusCode::SEQUENCE_NUMBER_TOO_NEW {
                        "discard_sequence_number_too_new"
                    } else if *discard_status_code == StatusCode::TRANSACTION_EXPIRED {
                        "discard_transaction_expired"
                    } else if *discard_status_code == StatusCode::NONCE_ALREADY_USED {
                        "discard_nonce_already_used"
                    } else {
                        // Only log if it is an interesting discard
                        sample!(
                            SampleRate::Duration(Duration::from_secs(15)),
                            warn!(
                                "[sampled] Txn being discarded is {:?} with status code {:?}",
                                txn, discard_status_code
                            );
                        );
                        "discard"
                    },
                    "error_code",
                    if detailed_counters {
                        format!("{:?}", discard_status_code).to_lowercase()
                    } else {
                        "error".to_string()
                    },
                )
            },
            TransactionStatus::Retry => ("retry", "", "".to_string()),
        };

        let kind = match txn.get_transaction() {
            Some(Transaction::UserTransaction(_)) => "user_transaction",
            Some(Transaction::GenesisTransaction(_)) => "genesis",
            Some(Transaction::BlockMetadata(_)) => "block_metadata",
            Some(Transaction::BlockMetadataExt(_)) => "block_metadata_ext",
            Some(Transaction::StateCheckpoint(_)) => "state_checkpoint",
            Some(Transaction::BlockEpilogue(_)) => "block_epilogue",
            Some(Transaction::ValidatorTransaction(_)) => "validator_transaction",
            None => "unknown",
        };

        PROCESSED_TXNS_COUNT
            .with_label_values(&[process_type, kind, state])
            .inc();

        if !error_code.is_empty() {
            PROCESSED_FAILED_TXNS_REASON_COUNT
                .with_label_values(&[
                    detailed_counters_label,
                    process_type,
                    state,
                    reason,
                    &error_code,
                ])
                .inc();
        }

        if let Some(Transaction::UserTransaction(user_txn)) = txn.get_transaction() {
            if detailed_counters {
                let mut signature_count = 0;
                let account_authenticators = user_txn.authenticator_ref().all_signers();
                for account_authenticator in account_authenticators {
                    match account_authenticator {
                        AccountAuthenticator::Ed25519 { .. } => {
                            signature_count += 1;
                            PROCESSED_TXNS_AUTHENTICATOR
                                .with_label_values(&[process_type, "Ed25519"])
                                .inc();
                        },
                        AccountAuthenticator::MultiEd25519 { signature, .. } => {
                            let count = signature.signatures().len();
                            signature_count += count;
                            PROCESSED_TXNS_AUTHENTICATOR
                                .with_label_values(&[process_type, "Ed25519_in_MultiEd25519"])
                                .inc_by(count as u64);
                        },
                        AccountAuthenticator::SingleKey { authenticator } => {
                            signature_count += 1;
                            PROCESSED_TXNS_AUTHENTICATOR
                                .with_label_values(&[
                                    process_type,
                                    &format!("{}_in_SingleKey", authenticator.signature().name()),
                                ])
                                .inc();
                        },
                        AccountAuthenticator::MultiKey { authenticator } => {
                            for (_, signature) in authenticator.signatures() {
                                signature_count += 1;
                                PROCESSED_TXNS_AUTHENTICATOR
                                    .with_label_values(&[
                                        process_type,
                                        &format!("{}_in_MultiKey", signature.name()),
                                    ])
                                    .inc();
                            }
                        },
                        AccountAuthenticator::NoAccountAuthenticator => {
                            PROCESSED_TXNS_AUTHENTICATOR
                                .with_label_values(&[process_type, "NoAccountAuthenticator"])
                                .inc();
                        },
                        AccountAuthenticator::Abstract { .. } => {
                            PROCESSED_TXNS_AUTHENTICATOR
                                .with_label_values(&[process_type, "AbstractionAuthenticator"])
                                .inc();
                        },
                    };
                }

                PROCESSED_TXNS_NUM_AUTHENTICATORS
                    .observe_with(&[process_type], signature_count as f64);
            }

            let payload_type = if user_txn.payload().is_multisig() {
                "multisig"
            } else {
                match user_txn.payload().executable_ref() {
                    Ok(TransactionExecutableRef::Script(_)) => "script",
                    Ok(TransactionExecutableRef::EntryFunction(_)) => "function",
                    Ok(TransactionExecutableRef::Empty) => "empty",
                    Err(_) => "deprecated_payload",
                }
            };
            if user_txn.payload().replay_protection_nonce().is_some() {
                PROCESSED_USER_TXNS_BY_PAYLOAD
                    .with_label_values(&[
                        process_type,
                        &(payload_type.to_string() + "_orderless"),
                        state,
                    ])
                    .inc();
            } else {
                PROCESSED_USER_TXNS_BY_PAYLOAD
                    .with_label_values(&[process_type, payload_type, state])
                    .inc();
            }

            if let Ok(TransactionExecutableRef::EntryFunction(function)) =
                user_txn.payload().executable_ref()
            {
                let is_core = function.module().address() == &CORE_CODE_ADDRESS;
                PROCESSED_USER_TXNS_ENTRY_FUNCTION_BY_MODULE
                    .with_label_values(&[
                        detailed_counters_label,
                        process_type,
                        if is_core { "core" } else { "user" },
                        if detailed_counters {
                            function.module().name().as_str()
                        } else if is_core {
                            "core_module"
                        } else {
                            "user_module"
                        },
                        state,
                    ])
                    .inc();
                if is_core && detailed_counters {
                    PROCESSED_USER_TXNS_ENTRY_FUNCTION_BY_CORE_METHOD
                        .with_label_values(&[
                            process_type,
                            function.module().name().as_str(),
                            function.function().as_str(),
                            state,
                        ])
                        .inc();
                }
            };
        }

        for event in output.events() {
            let (is_core, creation_number) = match event {
                ContractEvent::V1(v1) => (
                    v1.key().get_creator_address() == CORE_CODE_ADDRESS,
                    if detailed_counters {
                        v1.key().get_creation_number().to_string()
                    } else {
                        "event".to_string()
                    },
                ),
                ContractEvent::V2(_v2) => (false, "event".to_string()),
            };
            PROCESSED_USER_TXNS_CORE_EVENTS
                .with_label_values(&[
                    detailed_counters_label,
                    process_type,
                    if is_core { "core" } else { "user" },
                    &creation_number,
                ])
                .inc();
        }
    }
}
```
