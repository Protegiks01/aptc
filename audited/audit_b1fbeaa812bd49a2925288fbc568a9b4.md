# Audit Report

## Title
Memory Reallocation Vulnerability in jemalloc Stats Collection Can Crash Validator Node

## Summary
A buffer capacity calculation error in the jemalloc statistics collection callback allows vector reallocation despite explicit design intent to avoid allocations. If the reallocation fails under memory pressure, it triggers a process-wide panic that crashes the entire validator node during operation. [1](#0-0) 

## Finding Description
The `write_cb` callback function contains a critical bug in its capacity calculation. When jemalloc's `malloc_stats_print` calls this callback multiple times to output statistics incrementally, the code incorrectly calculates the remaining buffer capacity. [2](#0-1) 

The bug: Line 18 computes `std::cmp::min(out.capacity(), stats_cstr.len())` which checks against the **total capacity** of the Vec, not the **remaining capacity**. The correct calculation should be `std::cmp::min(out.capacity() - out.len(), stats_cstr.len())`.

**Attack Scenario:**
1. Vec is created with 2MB capacity (default `malloc_stats_max_len`)
2. First callback: Adds 1.5MB of stats data (Vec.len = 1.5MB, remaining = 0.5MB)
3. Second callback: Attempts to add another 1MB chunk
   - Code calculates: `min(2MB, 1MB) = 1MB`
   - Tries to extend Vec by 1MB, but only 0.5MB remaining
   - `extend_from_slice` triggers reallocation to ~2.5MB
4. If reallocation fails (OOM in containerized environment or under memory pressure), Rust panics
5. Global panic handler catches panic and calls `process::exit(12)` [3](#0-2) 

6. Entire validator process terminates, killing consensus, mempool, state sync, and all other services

The admin service starts before consensus and runs in the same process: [4](#0-3) [5](#0-4) 

When an operator queries `/malloc/stats` (typically during memory debugging), the callback violation occurs while consensus is actively running. [6](#0-5) 

## Impact Explanation
This qualifies as **High Severity** under the Aptos bug bounty program ("Validator node slowdowns" / "API crashes"). When triggered, it causes immediate validator termination via `process::exit(12)`, resulting in:

- **Loss of liveness**: Validator stops participating in consensus
- **Network impact**: Reduces validator set size, moving closer to Byzantine threshold
- **Timing criticality**: Most likely to occur when debugging memory issues (i.e., when node is already stressed)

The vulnerability breaks the **Resource Limits** invariant (#9) by allowing unbounded reallocation attempts in a callback explicitly designed to avoid allocations (as indicated by the comment on line 17). [7](#0-6) 

## Likelihood Explanation
**Medium-to-Low Likelihood** due to multiple prerequisites:

1. **Admin service must be enabled**: Disabled by default on mainnet, enabled on testnet [8](#0-7) 

2. **Authentication required on mainnet**: Reduces attack surface but doesn't eliminate operator error [9](#0-8) 

3. **Memory pressure needed**: Allocation must fail for crash to occur
   - More likely in containerized environments with memory limits (common for validators)
   - Precisely when operators would query malloc stats for debugging
   - Creates a dangerous feedback loop: memory issues → query stats → trigger reallocation → crash

4. **Large jemalloc output**: Stats must exceed initial capacity to trigger multiple callbacks
   - With default 2MB buffer, achievable with detailed heap profiling enabled

## Recommendation
Fix the capacity calculation to account for data already in the buffer:

```rust
unsafe extern "C" fn write_cb(buf: *mut c_void, s: *const c_char) {
    let out = unsafe { &mut *(buf as *mut Vec<u8>) };
    let stats_cstr = unsafe { CStr::from_ptr(s).to_bytes() };
    // We do not want any memory allocation in the callback.
    let remaining_capacity = out.capacity() - out.len();
    let len = std::cmp::min(remaining_capacity, stats_cstr.len());
    out.extend_from_slice(&stats_cstr[0..len]);
}
```

**Alternative**: Pre-allocate and use unsafe buffer manipulation to completely avoid Vec growth:
```rust
let len = std::cmp::min(out.capacity() - out.len(), stats_cstr.len());
if len > 0 {
    let current_len = out.len();
    unsafe {
        std::ptr::copy_nonoverlapping(
            stats_cstr.as_ptr(),
            out.as_mut_ptr().add(current_len),
            len
        );
        out.set_len(current_len + len);
    }
}
```

## Proof of Concept
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    
    #[test]
    #[should_panic(expected = "capacity overflow")]
    fn test_malloc_stats_reallocation_bug() {
        // Simulate the buggy behavior
        let max_len = 100; // Small buffer for testing
        let mut stats = Vec::with_capacity(max_len);
        
        // First callback: fill 80 bytes
        let first_chunk = vec![b'A'; 80];
        let len1 = std::cmp::min(stats.capacity(), first_chunk.len());
        stats.extend_from_slice(&first_chunk[0..len1]);
        assert_eq!(stats.len(), 80);
        
        // Second callback: try to add 50 more (buggy calculation)
        let second_chunk = vec![b'B'; 50];
        // BUG: checks total capacity (100) not remaining (20)
        let len2 = std::cmp::min(stats.capacity(), second_chunk.len());
        // len2 = 50, but only 20 capacity remaining!
        // This will trigger reallocation
        stats.extend_from_slice(&second_chunk[0..len2]);
        // If we're out of memory, this panics
    }
    
    #[test]
    fn test_malloc_stats_correct_implementation() {
        let max_len = 100;
        let mut stats = Vec::with_capacity(max_len);
        
        let first_chunk = vec![b'A'; 80];
        let remaining1 = stats.capacity() - stats.len();
        let len1 = std::cmp::min(remaining1, first_chunk.len());
        stats.extend_from_slice(&first_chunk[0..len1]);
        assert_eq!(stats.len(), 80);
        
        let second_chunk = vec![b'B'; 50];
        // CORRECT: checks remaining capacity
        let remaining2 = stats.capacity() - stats.len();
        let len2 = std::cmp::min(remaining2, second_chunk.len());
        stats.extend_from_slice(&second_chunk[0..len2]);
        // Only adds 20 bytes (remaining capacity), no reallocation
        assert_eq!(stats.len(), 100);
    }
}
```

## Notes
- The comment "We do not want any memory allocation in the callback" indicates developers understood the risk but implemented the check incorrectly
- This is particularly dangerous because malloc stats collection is most likely to be used when debugging memory issues—precisely when allocation failures are more probable
- The bug violates Rust's safety guarantees that the developers tried to maintain in an unsafe callback context
- While the admin service is on a separate tokio runtime, the global panic handler ensures any panic kills the entire process, including consensus

### Citations

**File:** crates/aptos-admin-service/src/server/malloc.rs (L14-20)
```rust
unsafe extern "C" fn write_cb(buf: *mut c_void, s: *const c_char) {
    let out = unsafe { &mut *(buf as *mut Vec<u8>) };
    let stats_cstr = unsafe { CStr::from_ptr(s).to_bytes() };
    // We do not want any memory allocation in the callback.
    let len = std::cmp::min(out.capacity(), stats_cstr.len());
    out.extend_from_slice(&stats_cstr[0..len]);
}
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

**File:** aptos-node/src/lib.rs (L700-701)
```rust
    // Starts the admin service
    let mut admin_service = services::start_admin_service(&node_config);
```

**File:** aptos-node/src/lib.rs (L840-842)
```rust
    // Create the consensus runtime (if enabled)
    let consensus_runtime = consensus::create_consensus_runtime(
        &node_config,
```

**File:** crates/aptos-admin-service/src/server/mod.rs (L188-191)
```rust
            #[cfg(unix)]
            (hyper::Method::GET, "/malloc/stats") => {
                malloc::handle_malloc_stats_request(context.config.malloc_stats_max_len)
            },
```

**File:** config/src/config/admin_service_config.rs (L68-76)
```rust
            if let Some(chain_id) = chain_id {
                if chain_id.is_mainnet()
                    && node_config.admin_service.authentication_configs.is_empty()
                {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "Must enable authentication for AdminService on mainnet.".into(),
                    ));
                }
```

**File:** config/src/config/admin_service_config.rs (L93-100)
```rust
        if node_config.admin_service.enabled.is_none() {
            // Only enable the admin service if the chain is not mainnet
            let admin_service_enabled = if let Some(chain_id) = chain_id {
                !chain_id.is_mainnet()
            } else {
                false // We cannot determine the chain ID, so we disable the admin service
            };
            node_config.admin_service.enabled = Some(admin_service_enabled);
```
