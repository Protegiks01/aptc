# Audit Report

## Title
Mainnet Validators Expose Detailed System Information Enabling OS Fingerprinting and Targeted Exploits

## Summary
The inspection service's `expose_system_information` field defaults to `true` and lacks sanitizer enforcement for mainnet validators, allowing detailed system, build, and hardware information to be exposed when the metrics port is enabled for monitoring. This enables attackers to perform OS fingerprinting, version detection, and vulnerability mapping for targeted exploits.

## Finding Description
The `InspectionServiceConfig` has an inconsistent security posture for mainnet validators. While the sanitizer explicitly prevents mainnet validators from exposing node configuration [1](#0-0) , it performs NO similar check for `expose_system_information`, `expose_identity_information`, or `expose_peer_information`.

The default value for `expose_system_information` is `true` [2](#0-1) , and the config optimizer only modifies settings for non-mainnet nodes, leaving mainnet validators with insecure defaults [3](#0-2) .

When exposed, the `/system_information` endpoint reveals:
- **OS details**: Exact kernel version, OS name, and OS version enabling CVE mapping [4](#0-3) 
- **Build information**: Git commit hash, Rust version, cargo version, build profile, enabling code-specific exploit development [5](#0-4) 
- **Hardware fingerprinting**: CPU brand, vendor ID, memory configuration for resource exhaustion attacks [6](#0-5) 
- **Network topology**: Hostname potentially revealing infrastructure layout [7](#0-6) 

The inspection service binds to all interfaces by default (`0.0.0.0:9101`) [8](#0-7)  and routes through HAProxy when exposed [9](#0-8) .

**Attack Scenario:**
1. Validator operator enables `enableMetricsPort: true` for monitoring (configurable in Kubernetes) [10](#0-9) 
2. Attacker queries `http://<validator-ip>:9101/system_information`
3. Attacker obtains exact OS version (e.g., "Ubuntu 22.04.3 LTS", kernel "5.15.0-89")
4. Attacker obtains exact git commit hash and Rust version
5. Attacker maps known CVEs to the specific versions
6. Attacker develops targeted exploit for the validator's environment

## Impact Explanation
This vulnerability falls under **Medium Severity** ("Minor information leaks") per the Aptos bug bounty program, but with elevated risk due to its targeting potential:

- **Information Disclosure**: Exposes detailed technical information about validator infrastructure
- **Attack Surface Expansion**: Enables precise targeting of known vulnerabilities in specific OS/kernel/Rust versions
- **No Direct Fund Loss**: Does not directly cause fund theft or consensus failure
- **Defense Circumvention**: Allows attackers to bypass traditional security-through-obscurity defenses

The impact is amplified because validators are high-value targets securing the blockchain's consensus mechanism. A targeted exploit developed using this fingerprinting could lead to validator compromise, which could then escalate to consensus attacks if multiple validators are affected.

## Likelihood Explanation
**Likelihood: Medium**

The vulnerability becomes exploitable when:
1. **Monitoring Requirements**: Operators enabling metrics for Prometheus/monitoring (common operational practice)
2. **No Explicit Guidance**: Absence of security documentation warning about this exposure
3. **Default Insecure**: Unlike `expose_configuration`, no sanitizer prevents this on mainnet
4. **Operator Assumption**: Operators may assume "metrics" are safe to expose publicly

**Mitigating Factors:**
- Default Kubernetes deployment has `enableMetricsPort: false` [10](#0-9) 
- Docker Compose binds to localhost by default [11](#0-10) 
- NetworkPolicy can restrict access (though disabled by default)

However, the inconsistency in the sanitizer suggests this was an oversight rather than intentional design, indicating real-world mainnet validators may have this exposure enabled.

## Recommendation
Add sanitizer enforcement for mainnet validators to match the security posture for `expose_configuration`:

```rust
impl ConfigSanitizer for InspectionServiceConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let inspection_service_config = &node_config.inspection_service;

        // Verify that mainnet validators do not expose sensitive endpoints
        if let Some(chain_id) = chain_id {
            if node_type.is_validator() && chain_id.is_mainnet() {
                if inspection_service_config.expose_configuration {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "Mainnet validators should not expose the node configuration!".to_string(),
                    ));
                }
                
                // ADD THIS CHECK:
                if inspection_service_config.expose_system_information {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "Mainnet validators should not expose system information!".to_string(),
                    ));
                }
                
                // OPTIONALLY ADD:
                if inspection_service_config.expose_identity_information {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "Mainnet validators should not expose identity information!".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }
}
```

Additionally:
1. Change the default for mainnet validators to `expose_system_information: false`
2. Add security documentation warning operators about the risks of exposing metrics publicly
3. Consider implementing IP whitelisting for the inspection service on mainnet validators

## Proof of Concept
```bash
#!/bin/bash
# PoC: Query system information from a validator with exposed metrics port

VALIDATOR_IP="<validator-public-ip>"
METRICS_PORT="9101"

echo "Attempting to fingerprint validator at ${VALIDATOR_IP}:${METRICS_PORT}"
echo ""

# Query system information endpoint
curl -s "http://${VALIDATOR_IP}:${METRICS_PORT}/system_information" | jq '.'

# Expected output (if exposed):
# {
#   "cpu_brand": "Intel(R) Xeon(R) CPU @ 2.20GHz",
#   "cpu_vendor_id": "GenuineIntel",
#   "system_kernel_version": "5.15.0-89-generic",
#   "system_os_version": "Ubuntu 22.04.3 LTS",
#   "build_commit_hash": "abc123def456...",
#   "build_rust_version": "rustc 1.75.0",
#   ...
# }

echo ""
echo "Attacker can now:"
echo "1. Map OS version to known CVEs (e.g., kernel vulnerabilities)"
echo "2. Identify exact code version for targeted exploits"
echo "3. Tailor resource exhaustion attacks to hardware specs"
echo "4. Use hostname for network topology reconnaissance"
```

## Notes
The inconsistency between sanitizer enforcement for `expose_configuration` versus `expose_system_information` strongly suggests this is a security oversight rather than intentional design. The build and system information exposed contains sufficient detail for sophisticated attackers to develop targeted exploits, particularly when combined with publicly known CVE databases and code vulnerability trackers. While default deployments have some protections, the lack of explicit enforcement creates risk when operators enable monitoring without understanding the security implications.

### Citations

**File:** config/src/config/inspection_service_config.rs (L26-36)
```rust
impl Default for InspectionServiceConfig {
    fn default() -> InspectionServiceConfig {
        InspectionServiceConfig {
            address: "0.0.0.0".to_string(),
            port: 9101,
            expose_configuration: false,
            expose_identity_information: true,
            expose_peer_information: true,
            expose_system_information: true,
        }
    }
```

**File:** config/src/config/inspection_service_config.rs (L54-64)
```rust
        // Verify that mainnet validators do not expose the configuration
        if let Some(chain_id) = chain_id {
            if node_type.is_validator()
                && chain_id.is_mainnet()
                && inspection_service_config.expose_configuration
            {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "Mainnet validators should not expose the node configuration!".to_string(),
                ));
            }
```

**File:** config/src/config/inspection_service_config.rs (L71-109)
```rust
impl ConfigOptimizer for InspectionServiceConfig {
    fn optimize(
        node_config: &mut NodeConfig,
        local_config_yaml: &Value,
        _node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<bool, Error> {
        let inspection_service_config = &mut node_config.inspection_service;
        let local_inspection_config_yaml = &local_config_yaml["inspection_service"];

        // Enable all endpoints for non-mainnet nodes (to aid debugging)
        let mut modified_config = false;
        if let Some(chain_id) = chain_id {
            if !chain_id.is_mainnet() {
                if local_inspection_config_yaml["expose_configuration"].is_null() {
                    inspection_service_config.expose_configuration = true;
                    modified_config = true;
                }

                if local_inspection_config_yaml["expose_identity_information"].is_null() {
                    inspection_service_config.expose_identity_information = true;
                    modified_config = true;
                }

                if local_inspection_config_yaml["expose_peer_information"].is_null() {
                    inspection_service_config.expose_peer_information = true;
                    modified_config = true;
                }

                if local_inspection_config_yaml["expose_system_information"].is_null() {
                    inspection_service_config.expose_system_information = true;
                    modified_config = true;
                }
            }
        }

        Ok(modified_config)
    }
}
```

**File:** crates/aptos-telemetry/src/system_information.rs (L70-93)
```rust
/// Collects the cpu info and appends it to the given map
fn collect_cpu_info(
    system_information: &mut BTreeMap<String, String>,
    system: &Lazy<Mutex<System>>,
) {
    // Collect the number of CPUs and cores
    let system_lock = system.lock();
    let cpus = system_lock.cpus();
    system_information.insert(CPU_COUNT.into(), cpus.len().to_string());
    utils::insert_optional_value(
        system_information,
        CPU_CORE_COUNT,
        system_lock
            .physical_core_count()
            .map(|count| count.to_string()),
    );

    // Collect the overall CPU info
    let global_cpu = system_lock.global_cpu_info();
    system_information.insert(CPU_BRAND.into(), global_cpu.brand().into());
    system_information.insert(CPU_FREQUENCY.into(), global_cpu.frequency().to_string());
    system_information.insert(CPU_NAME.into(), global_cpu.name().into());
    system_information.insert(CPU_VENDOR_ID.into(), global_cpu.vendor_id().into());
}
```

**File:** crates/aptos-telemetry/src/system_information.rs (L152-173)
```rust
/// Collects the sys info and appends it to the given map
fn collect_sys_info(
    system_information: &mut BTreeMap<String, String>,
    system: &Lazy<Mutex<System>>,
) {
    utils::insert_optional_value(
        system_information,
        SYSTEM_HOST_NAME,
        system.lock().host_name(),
    );
    utils::insert_optional_value(
        system_information,
        SYSTEM_KERNEL_VERSION,
        system.lock().kernel_version(),
    );
    utils::insert_optional_value(system_information, SYSTEM_NAME, system.lock().name());
    utils::insert_optional_value(
        system_information,
        SYSTEM_OS_VERSION,
        system.lock().long_os_version(),
    );
}
```

**File:** crates/aptos-build-info/src/lib.rs (L59-105)
```rust
pub fn get_build_information() -> BTreeMap<String, String> {
    shadow!(build);

    let mut build_information = BTreeMap::new();

    // Get Git metadata from shadow_rs crate.
    // This is applicable for native builds where the cargo has
    // access to the .git directory.
    build_information.insert(BUILD_BRANCH.into(), build::BRANCH.into());
    build_information.insert(BUILD_CARGO_VERSION.into(), build::CARGO_VERSION.into());
    build_information.insert(BUILD_CLEAN_CHECKOUT.into(), build::GIT_CLEAN.to_string());
    build_information.insert(BUILD_COMMIT_HASH.into(), build::COMMIT_HASH.into());
    build_information.insert(BUILD_TAG.into(), build::TAG.into());
    build_information.insert(BUILD_TIME.into(), build::BUILD_TIME.into());
    build_information.insert(BUILD_OS.into(), build::BUILD_OS.into());
    build_information.insert(BUILD_RUST_CHANNEL.into(), build::RUST_CHANNEL.into());
    build_information.insert(BUILD_RUST_VERSION.into(), build::RUST_VERSION.into());

    // Compilation information
    build_information.insert(BUILD_IS_RELEASE_BUILD.into(), is_release().to_string());
    build_information.insert(BUILD_PROFILE_NAME.into(), get_build_profile_name());
    build_information.insert(
        BUILD_USING_TOKIO_UNSTABLE.into(),
        std::env!("USING_TOKIO_UNSTABLE").to_string(),
    );

    // Get Git metadata from environment variables set during build-time.
    // This is applicable for docker based builds  where the cargo cannot
    // access the .git directory, or to override shadow_rs provided info.
    if let Ok(git_sha) = std::env::var("GIT_SHA") {
        build_information.insert(BUILD_COMMIT_HASH.into(), git_sha);
    }

    if let Ok(git_branch) = std::env::var("GIT_BRANCH") {
        build_information.insert(BUILD_BRANCH.into(), git_branch);
    }

    if let Ok(git_tag) = std::env::var("GIT_TAG") {
        build_information.insert(BUILD_TAG.into(), git_tag);
    }

    if let Ok(build_date) = std::env::var("BUILD_DATE") {
        build_information.insert(BUILD_TIME.into(), build_date);
    }

    build_information
}
```

**File:** terraform/helm/aptos-node/files/haproxy.cfg (L92-108)
```text
## Specify the validator metrics frontend
frontend validator-metrics
    mode http
    option httplog
    bind :9102
    default_backend validator-metrics

    # Deny requests from blocked IPs
    tcp-request connection reject if { src -n -f /usr/local/etc/haproxy/blocked.ips }

    ## Add the forwarded header
    http-request add-header Forwarded "for=%ci"

## Specify the validator metrics backend
backend validator-metrics
    mode http
    server {{ include "aptos-validator.fullname" $ }}-{{ $.Values.i }}-validator {{ include "aptos-validator.fullname" $ }}-{{ $.Values.i }}-validator:9101
```

**File:** terraform/helm/aptos-node/values.yaml (L156-157)
```yaml
    # -- Enable the metrics port on the validator
    enableMetricsPort: false
```

**File:** docker/compose/aptos-node/docker-compose.yaml (L32-32)
```yaml
      - "127.0.0.1:9101:9101"
```
