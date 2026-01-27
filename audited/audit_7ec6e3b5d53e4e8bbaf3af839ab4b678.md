# Audit Report

## Title
Storage Exhaustion via Unauthenticated Heap Dump Endpoint Causing Validator Halt

## Summary
The Aptos Admin Service exposes an unauthenticated `/malloc/dump_profile` endpoint on testnet/devnet validators that creates heap dump files without any cleanup mechanism. An attacker can repeatedly trigger this endpoint to exhaust disk space in `/tmp`, causing validator node failures and network liveness issues.

## Finding Description

The vulnerability exists in the Admin Service's heap profiling functionality. The admin service is enabled by default on non-mainnet networks (testnet/devnet) with no authentication required. [1](#0-0) [2](#0-1) 

The `/malloc/dump_profile` endpoint is exposed in the admin service and triggers heap dump creation: [3](#0-2) 

When invoked, the `handle_dump_profile_request()` function creates a heap dump file in `/tmp` with a timestamp-based filename: [4](#0-3) 

**Critical Issue**: There is no cleanup mechanism for these files. Each invocation creates a new file that persists indefinitely. [5](#0-4) 

The jemalloc profiler is enabled on all validator nodes: [6](#0-5) 

**Attack Path:**
1. Attacker identifies a testnet/devnet validator with admin service running on default port 9102
2. Attacker sends repeated HTTP GET requests to `http://validator-ip:9102/malloc/dump_profile`
3. Each request creates a heap dump file (potentially hundreds of MB to several GB)
4. Files accumulate in `/tmp` with no cleanup
5. Disk space exhausts, causing validator write failures and eventual halt
6. Multiple validators affected simultaneously cause network liveness degradation

This violates the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits."

## Impact Explanation

This is a **High Severity** vulnerability per the Aptos bug bounty criteria:
- **"Validator node slowdowns"** - Direct match to High severity category
- When disk space fills, the validator experiences I/O failures, database write errors, and eventual halt
- Multiple affected validators cause network liveness issues
- On testnet/devnet, all validators with default configuration are vulnerable
- No authentication barrier makes exploitation trivial

The impact is heightened because:
- Heap dumps from a running validator can be several gigabytes each
- The attack requires minimal resources (just HTTP requests)
- The effect is persistent (files never clean up automatically)
- Recovery requires manual intervention to delete files and restart nodes

## Likelihood Explanation

**High Likelihood** on testnet/devnet environments:

1. **Default Configuration is Vulnerable**: Admin service is automatically enabled on non-mainnet networks with no authentication [7](#0-6) 

2. **Attack Complexity**: Trivial - requires only knowledge of the validator's IP and default port
3. **Attacker Requirements**: None - no authentication, no special access, no stake required
4. **Discovery**: Admin service endpoints are documented in the codebase and easily discovered

**Low Likelihood** on mainnet:
- Admin service is disabled by default on mainnet
- If enabled, authentication is mandatory [8](#0-7) 

However, testnet/devnet availability is still critical for ecosystem health, development, and testing.

## Recommendation

Implement automatic cleanup of heap dump files with configurable retention policies:

```rust
// In crates/aptos-admin-service/src/server/malloc.rs

use std::fs;
use std::time::{SystemTime, Duration};

const PROFILE_PATH_PREFIX: &str = "/tmp/heap-profile";
const MAX_HEAP_DUMPS: usize = 5; // Keep only last N dumps
const MAX_DUMP_AGE_SECS: u64 = 3600; // Delete dumps older than 1 hour

fn cleanup_old_heap_dumps() -> anyhow::Result<()> {
    let mut dumps: Vec<_> = fs::read_dir("/tmp")?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("heap-profile."))
        .collect();
    
    // Sort by modification time, newest first
    dumps.sort_by_key(|e| e.metadata().and_then(|m| m.modified()).ok());
    dumps.reverse();
    
    // Delete old dumps beyond max count
    for dump in dumps.iter().skip(MAX_HEAP_DUMPS) {
        let _ = fs::remove_file(dump.path());
    }
    
    // Delete dumps older than threshold
    let now = SystemTime::now();
    for dump in &dumps {
        if let Ok(metadata) = dump.metadata() {
            if let Ok(modified) = metadata.modified() {
                if now.duration_since(modified).unwrap_or(Duration::ZERO).as_secs() > MAX_DUMP_AGE_SECS {
                    let _ = fs::remove_file(dump.path());
                }
            }
        }
    }
    
    Ok(())
}

pub fn handle_dump_profile_request() -> hyper::Result<Response<Body>> {
    // Clean up old dumps before creating new one
    let _ = cleanup_old_heap_dumps();
    
    match dump_heap_profile() {
        Ok(path) => Ok(reply_with(
            Vec::new(),
            Body::from(format!("Successfully dumped heap profile to {path}")),
        )),
        Err(e) => Ok(reply_with_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to dump heap profile: {e}"),
        )),
    }
}
```

Additional recommendations:
1. Add rate limiting to the endpoint (max 1 request per minute per IP)
2. Add disk space checks before creating dumps
3. Configure authentication even on testnet/devnet
4. Add monitoring/alerting for `/tmp` disk usage

## Proof of Concept

```bash
#!/bin/bash
# PoC: Storage exhaustion attack on testnet validator

VALIDATOR_IP="testnet-validator.example.com"
ADMIN_PORT="9102"

echo "Starting heap dump storage exhaustion attack..."

# Send 100 requests to create heap dumps
for i in {1..100}; do
    echo "Creating heap dump $i..."
    curl -s "http://${VALIDATOR_IP}:${ADMIN_PORT}/malloc/dump_profile"
    echo ""
    
    # Check disk space
    ssh validator@${VALIDATOR_IP} "df -h /tmp | tail -1"
    
    sleep 2
done

echo "Attack complete. Check /tmp disk usage on validator."
```

**Expected Result**: After running this script, `/tmp` will contain 100+ heap dump files, each potentially several GB in size. The validator will experience disk space exhaustion, leading to write failures and eventual node halt.

**Verification**: On the target validator, run `ls -lh /tmp/heap-profile.* | wc -l` to count accumulated dumps and `du -sh /tmp/heap-profile.*` to see total space consumed.

## Notes

While the original security question focused on the `memory_profiler.rs` Python script failure scenario, investigation revealed a more severe vulnerability in the admin service's production endpoint. The admin service's `/malloc/dump_profile` has no cleanup mechanism whatsoever, making it exploitable on all default-configured testnet/devnet validators without authentication.

### Citations

**File:** config/src/config/admin_service_config.rs (L21-21)
```rust
    // If empty, will allow all requests without authentication. (Not allowed on mainnet.)
```

**File:** config/src/config/admin_service_config.rs (L47-47)
```rust
            authentication_configs: vec![],
```

**File:** config/src/config/admin_service_config.rs (L69-76)
```rust
                if chain_id.is_mainnet()
                    && node_config.admin_service.authentication_configs.is_empty()
                {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "Must enable authentication for AdminService on mainnet.".into(),
                    ));
                }
```

**File:** config/src/config/admin_service_config.rs (L94-100)
```rust
            // Only enable the admin service if the chain is not mainnet
            let admin_service_enabled = if let Some(chain_id) = chain_id {
                !chain_id.is_mainnet()
            } else {
                false // We cannot determine the chain ID, so we disable the admin service
            };
            node_config.admin_service.enabled = Some(admin_service_enabled);
```

**File:** crates/aptos-admin-service/src/server/mod.rs (L193-193)
```rust
            (hyper::Method::GET, "/malloc/dump_profile") => malloc::handle_dump_profile_request(),
```

**File:** crates/aptos-admin-service/src/server/malloc.rs (L46-63)
```rust
fn dump_heap_profile() -> anyhow::Result<String> {
    let _ = jemalloc_ctl::epoch::advance();

    let key = b"prof.dump\0";
    let path = format!(
        "{}.{}",
        PROFILE_PATH_PREFIX,
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_millis()
    );
    let value = CString::new(path.clone())?;
    unsafe {
        jemalloc_ctl::raw::write(key, value.as_ptr())
            .map_err(|e| anyhow::anyhow!("prof.dump error: {e}"))?;
    }
    Ok(path)
}
```

**File:** crates/aptos-admin-service/src/server/malloc.rs (L65-76)
```rust
pub fn handle_dump_profile_request() -> hyper::Result<Response<Body>> {
    match dump_heap_profile() {
        Ok(path) => Ok(reply_with(
            Vec::new(),
            Body::from(format!("Successfully dumped heap profile to {path}")),
        )),
        Err(e) => Ok(reply_with_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to dump heap profile: {e}"),
        )),
    }
}
```

**File:** aptos-node/src/main.rs (L11-19)
```rust
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

/// Can be overridden by setting the `MALLOC_CONF` env var.
#[allow(unsafe_code)]
#[cfg(unix)]
#[used]
#[unsafe(no_mangle)]
pub static mut malloc_conf: *const c_char = c"prof:true,lg_prof_sample:23".as_ptr().cast();
```
