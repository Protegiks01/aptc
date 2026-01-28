# Audit Report

## Title
Memory Reallocation in jemalloc Callback Causes Validator Node Crash and Undefined Behavior

## Summary
The `write_cb` callback function in the malloc stats endpoint incorrectly calculates available buffer space, leading to memory reallocation during jemalloc's `malloc_stats_print` execution. This violates jemalloc's callback contract and can cause validator node crashes, deadlocks, or undefined behavior affecting node availability.

## Finding Description

The vulnerability exists in the `write_cb` callback function used by `malloc_stats_print`. [1](#0-0) 

The bug occurs on line 18 where the code calculates `let len = std::cmp::min(out.capacity(), stats_cstr.len());` using the **total capacity** of the Vec instead of the **remaining capacity**. The correct calculation should be `let len = std::cmp::min(out.capacity() - out.len(), stats_cstr.len());` to determine available space.

When `malloc_stats_print` calls this callback multiple times (which it does to output stats in chunks), the accumulated data can exceed the pre-allocated capacity. [2](#0-1) 

**Exploitation Scenario:**
1. Initial state: Vec allocated with 2MB capacity [3](#0-2) 
2. First callback adds 1.5MB of data, `out.len()` becomes 1.5MB
3. Second callback calculates `len = min(2MB, 1MB)` without considering the 1.5MB already written
4. Total becomes 2.5MB > 2MB capacity, triggering reallocation
5. Reallocation calls jemalloc while inside jemalloc's own callback

This violates the explicit contract stated in the code comment. [4](#0-3) 

The consequences include:
- **Reentrancy hazard**: Calling malloc during malloc_stats_print
- **Deadlock risk**: If jemalloc holds internal locks during callback execution
- **Memory corruption**: If jemalloc's internal state becomes inconsistent
- **Undefined behavior**: Violating jemalloc's API contract

The endpoint is accessible via the admin service. [5](#0-4) 

Jemalloc profiling is enabled on validator nodes. [6](#0-5) 

## Impact Explanation

**High Severity** - Validator Node Crashes per Aptos bug bounty criteria (up to $50,000).

This vulnerability can cause:
1. **Validator node crashes** - Undefined behavior or segfaults during callback execution when memory corruption occurs
2. **Validator node hangs** - Deadlock if jemalloc attempts to acquire locks it already holds during the callback
3. **Memory corruption** - Inconsistent allocator state affecting node stability

The impact is severe because:
- On **testnet/devnet**: Admin service is enabled by default with no authentication configured [7](#0-6) , making this readily exploitable
- On **mainnet**: Requires authentication [8](#0-7)  but if admin service is exposed and credentials are compromised, this becomes exploitable
- **Availability impact**: Crashing validators affects network participation and consensus performance

This directly maps to the HIGH severity category "Validator Node Slowdowns/Crashes" in the Aptos bug bounty program.

## Likelihood Explanation

**High Likelihood** on testnet/devnet, **Medium Likelihood** on mainnet.

**Triggering Conditions:**
1. Admin service must be enabled (automatic on testnet/devnet) [9](#0-8) 
2. Attacker must access `/malloc/stats` endpoint via HTTP GET
3. Jemalloc stats output must exceed 2MB during callback sequence

**Feasibility:**
With profiling enabled (`prof:true`) [6](#0-5)  and a busy validator processing transactions, jemalloc stats can accumulate beyond 2MB due to:
- Allocation backtraces from profiling
- Arena statistics
- Per-thread allocation data
- Multiple callback invocations accumulating data

The vulnerability is triggerable because the bug occurs when cumulative callback writes exceed capacity, not just when total output exceeds 2MB. An attacker simply needs to make HTTP GET requests to the admin service endpoint during periods of high memory activity.

## Recommendation

Fix the capacity calculation in the `write_cb` callback function to account for data already written:

```rust
let len = std::cmp::min(out.capacity() - out.len(), stats_cstr.len());
```

This ensures that `extend_from_slice` never attempts to add more data than the remaining capacity, preventing reallocation during the callback.

Additionally, consider:
1. Adding an assertion to verify no reallocation occurs
2. Increasing the default buffer size if profiling output regularly exceeds 2MB
3. Truncating output rather than allowing potential reallocation

## Proof of Concept

To reproduce this vulnerability:

1. Deploy a validator node with the admin service enabled (default on testnet/devnet)
2. Ensure jemalloc profiling is active (enabled by default in aptos-node)
3. Generate significant allocation activity (e.g., process transactions)
4. Send an HTTP GET request to `http://<admin-service-address>:9102/malloc/stats`
5. If malloc stats exceed 2MB across multiple callback invocations, the bug triggers
6. Observe undefined behavior: potential crash, deadlock, or memory corruption

The vulnerability is deterministic when the cumulative callback data exceeds the pre-allocated 2MB capacity.

## Notes

This is a clear violation of jemalloc's API contract. The comment explicitly states "We do not want any memory allocation in the callback," yet the implementation allows reallocation through `extend_from_slice` when capacity is exceeded. The bug is subtle because it only manifests when jemalloc makes multiple callback invocations that cumulatively exceed capacity, not when a single callback exceeds capacity.

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

**File:** crates/aptos-admin-service/src/server/malloc.rs (L22-34)
```rust
fn get_jemalloc_stats_string(max_len: usize) -> anyhow::Result<String> {
    let _ = jemalloc_ctl::epoch::advance();

    let mut stats = Vec::with_capacity(max_len);
    unsafe {
        jemalloc_sys::malloc_stats_print(
            Some(write_cb),
            &mut stats as *mut _ as *mut c_void,
            std::ptr::null(),
        );
    }
    Ok(String::from_utf8(stats)?)
}
```

**File:** config/src/config/admin_service_config.rs (L48-48)
```rust
            malloc_stats_max_len: 2 * 1024 * 1024,
```

**File:** config/src/config/admin_service_config.rs (L67-78)
```rust
        if node_config.admin_service.enabled == Some(true) {
            if let Some(chain_id) = chain_id {
                if chain_id.is_mainnet()
                    && node_config.admin_service.authentication_configs.is_empty()
                {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "Must enable authentication for AdminService on mainnet.".into(),
                    ));
                }
            }
        }
```

**File:** config/src/config/admin_service_config.rs (L93-103)
```rust
        if node_config.admin_service.enabled.is_none() {
            // Only enable the admin service if the chain is not mainnet
            let admin_service_enabled = if let Some(chain_id) = chain_id {
                !chain_id.is_mainnet()
            } else {
                false // We cannot determine the chain ID, so we disable the admin service
            };
            node_config.admin_service.enabled = Some(admin_service_enabled);

            modified_config = true; // The config was modified
        }
```

**File:** crates/aptos-admin-service/src/server/mod.rs (L189-191)
```rust
            (hyper::Method::GET, "/malloc/stats") => {
                malloc::handle_malloc_stats_request(context.config.malloc_stats_max_len)
            },
```

**File:** aptos-node/src/main.rs (L19-19)
```rust
pub static mut malloc_conf: *const c_char = c"prof:true,lg_prof_sample:23".as_ptr().cast();
```
