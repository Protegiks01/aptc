# Audit Report

## Title
Unvalidated CPU Profiling Frequency Parameter Enables Resource Exhaustion Attack on Validator Nodes

## Summary
The Admin Service's `/profilez` endpoint accepts a `frequency` parameter without validation, allowing attackers to specify extreme values (e.g., 1,000,000 Hz or negative values) that cause excessive CPU profiling overhead, potentially degrading consensus performance on testnet/devnet validator nodes where the admin service is enabled by default. [1](#0-0) 

## Finding Description

The CPU profiling endpoint parses the frequency parameter as an `i32` without any range validation. This unvalidated frequency is then passed directly to `pprof::ProfilerGuard::new(frequency)` to control the profiling sampling rate. [2](#0-1) 

The admin service exposes this endpoint at `/profilez` on port 9102 and is automatically enabled on non-mainnet chains (testnet/devnet) without requiring authentication by default. [3](#0-2) [4](#0-3) 

**Attack Scenario:**
1. Attacker identifies a testnet/devnet validator with admin service exposed (default enabled, but port exposure depends on deployment configuration)
2. Attacker sends: `GET /profilez?frequency=1000000&seconds=600` (1 MHz sampling for 10 minutes)
3. The profiler interrupts execution 1 million times per second to capture stack traces
4. CPU resources are consumed by profiling overhead rather than consensus operations
5. Validator experiences performance degradation during critical consensus rounds

**Invariant Violated:**
This breaks the **Resource Limits** invariant (#9): "All operations must respect gas, storage, and computational limits." The profiling operation lacks proper resource bounds, allowing unrestricted CPU consumption.

## Impact Explanation

This qualifies as **High Severity** ("Validator node slowdowns" - up to $50,000) with the following impacts:

1. **Consensus Performance Degradation**: Excessive profiling overhead consumes CPU cycles needed for block validation, voting, and state computation, potentially causing validators to miss consensus rounds or slow down block processing.

2. **Resource Exhaustion**: At sampling frequencies orders of magnitude above reasonable values (99-100 Hz default), the profiler can consume significant CPU resources through signal handling and stack trace collection.

3. **Attack Surface**: While the admin service is disabled on mainnet by default, it is auto-enabled on testnet/devnet where validators may be less security-hardened. If node operators expose the admin port (non-default but possible), the attack surface is real. [5](#0-4) 

The authentication requirement on mainnet provides some protection, but authentication is not required on testnet/devnet where the service is enabled by default. [6](#0-5) 

## Likelihood Explanation

**Likelihood: Medium** on testnet/devnet deployments where:
- Admin service is enabled by default (auto-configured for non-mainnet)
- Authentication may not be configured
- Node operators may expose the admin port for debugging purposes

**Likelihood: Low** on mainnet due to:
- Admin service disabled by default
- Authentication required if enabled
- Port typically not externally exposed in production Helm configurations [7](#0-6) 

However, the **lack of validation is a clear defensive programming failure** that should be fixed regardless of deployment configuration.

## Recommendation

Implement strict validation on the frequency parameter to ensure it falls within a safe operational range:

```rust
let frequency: i32 = match query_pairs.get("frequency") {
    Some(val) => match val.parse() {
        Ok(val) => {
            // Validate frequency is within safe range (1-1000 Hz)
            if val < 1 || val > 1000 {
                return Ok(reply_with_status(
                    StatusCode::BAD_REQUEST,
                    format!("Frequency must be between 1 and 1000 Hz, got: {}", val),
                ));
            }
            val
        },
        Err(err) => return Ok(reply_with_status(StatusCode::BAD_REQUEST, err.to_string())),
    },
    None => 99,
};
```

Additionally, implement rate limiting on profiling requests to prevent rapid successive attacks, and consider requiring authentication even on testnet/devnet deployments.

## Proof of Concept

```bash
#!/bin/bash
# PoC: Send malicious profiling request to validator admin service
# Assumes admin service is accessible (testnet/devnet with exposed port)

TARGET_HOST="validator.testnet.aptos.dev"  # Example testnet validator
ADMIN_PORT="9102"

# Attack 1: Extremely high frequency (1 MHz sampling)
curl -v "http://${TARGET_HOST}:${ADMIN_PORT}/profilez?frequency=1000000&seconds=300"

# Attack 2: Negative frequency (may cause panic in some code paths)
curl -v "http://${TARGET_HOST}:${ADMIN_PORT}/profilez?frequency=-1&seconds=60"

# Attack 3: Zero frequency (undefined behavior)
curl -v "http://${TARGET_HOST}:${ADMIN_PORT}/profilez?frequency=0&seconds=60"

# Monitor validator performance metrics during attack:
# - Check consensus round times
# - Monitor CPU usage on validator node
# - Observe any missed proposals or votes
```

**Expected Result:** The validator node experiences increased CPU usage and potential performance degradation during the profiling period, with no rejection of the invalid frequency values.

**Note:** This PoC requires the admin service to be accessible, which depends on deployment configuration. The vulnerability exists in the code regardless of deployment configuration.

---

## Notes

While this vulnerability has limited exploitability on mainnet (service disabled by default), it represents a clear defensive programming failure that violates resource limit invariants. The automatic enablement on testnet/devnet combined with potential misconfigurations (exposed admin port, no authentication) creates a realistic attack surface for validator node performance degradation. The fix is straightforward and should be implemented as defense-in-depth hardening.

### Citations

**File:** crates/aptos-system-utils/src/profiling.rs (L31-37)
```rust
    let frequency: i32 = match query_pairs.get("frequency") {
        Some(val) => match val.parse() {
            Ok(val) => val,
            Err(err) => return Ok(reply_with_status(StatusCode::BAD_REQUEST, err.to_string())),
        },
        None => 99,
    };
```

**File:** crates/aptos-system-utils/src/profiling.rs (L95-96)
```rust
    let guard = pprof::ProfilerGuard::new(frequency)
        .map_err(|e| anyhow!("Failed to start cpu profiling: {e:?}."))?;
```

**File:** crates/aptos-admin-service/src/server/mod.rs (L154-157)
```rust
        let mut authenticated = false;
        if context.config.authentication_configs.is_empty() {
            authenticated = true;
        } else {
```

**File:** crates/aptos-admin-service/src/server/mod.rs (L185-185)
```rust
            (hyper::Method::GET, "/profilez") => handle_cpu_profiling_request(req).await,
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

**File:** terraform/helm/aptos-node/values.yaml (L159-159)
```yaml
    enableAdminPort: false
```
