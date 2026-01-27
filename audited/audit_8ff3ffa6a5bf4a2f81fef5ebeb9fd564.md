# Audit Report

## Title
ConfigSanitizer Fails to Restrict System Information Exposure on Mainnet Validators

## Summary
The `ConfigSanitizer` implementation for `InspectionServiceConfig` only validates that mainnet validators do not expose the configuration endpoint (`expose_configuration`), but fails to check whether `expose_system_information` is enabled. Since `expose_system_information` defaults to `true`, mainnet validators will expose sensitive system information (CPU specs, memory, disk, OS version, hostname) unless explicitly disabled, enabling attackers to fingerprint validators and plan targeted attacks.

## Finding Description
The `InspectionServiceConfig::sanitize()` function implements validation logic to prevent mainnet validators from exposing sensitive information. However, this validation is incomplete. [1](#0-0) 

The sanitizer only checks if `expose_configuration` is enabled for mainnet validators, but completely ignores the other sensitive endpoints: `expose_system_information`, `expose_identity_information`, and `expose_peer_information`.

The default configuration explicitly sets `expose_system_information` to `true`: [2](#0-1) 

When the system information endpoint is enabled, it exposes highly sensitive information about the validator node's hardware and operating system: [3](#0-2) 

This information includes:
- CPU brand, count, cores, frequency, vendor ID
- Disk available space, file system type, total space
- Memory available, total, and used
- System hostname, kernel version, OS version [4](#0-3) 

**Attack Path:**
1. Attacker identifies mainnet validator nodes (through public validator addresses or network scanning)
2. Attacker connects to the inspection service port (default 9101)
3. Attacker sends GET request to `/system_information` endpoint
4. Since the sanitizer doesn't enforce disabling this endpoint and it defaults to `true`, the validator returns sensitive system information
5. Attacker uses this information to:
   - Fingerprint and uniquely identify validators
   - Discover exploitable OS/kernel vulnerabilities
   - Plan resource exhaustion attacks based on known hardware limits
   - Correlate validator identities across network changes
   - Identify validators running on cloud providers vs. bare metal

The endpoint handler checks the configuration flag but provides no protection if the operator didn't explicitly disable it: [5](#0-4) 

## Impact Explanation
This vulnerability qualifies as **High Severity** under the Aptos bug bounty program for the following reasons:

1. **Validator Node Security Risk**: Exposing detailed system information enables targeted attacks against mainnet validators, potentially leading to "Validator node slowdowns" or "API crashes" (High severity criteria).

2. **Information Disclosure**: Attackers can systematically collect hardware fingerprints of all mainnet validators, creating a database for future targeted attacks.

3. **Attack Surface Expansion**: Knowledge of specific OS versions and kernel versions allows attackers to exploit known CVEs, potentially achieving remote code execution on validator nodes (which would be Critical severity).

4. **Operational Security Violation**: The existence of a `ConfigSanitizer` that checks `expose_configuration` demonstrates that developers understood the risk of exposing sensitive information on mainnet validators, but the incomplete implementation creates a false sense of security.

## Likelihood Explanation
The likelihood of exploitation is **HIGH**:

1. **Default Configuration**: `expose_system_information` defaults to `true`, meaning any validator operator who doesn't explicitly disable it is vulnerable.

2. **Lack of Awareness**: The sanitizer only checks `expose_configuration`, giving operators false confidence that all sensitive endpoints are properly protected.

3. **No Documentation**: The provided configuration examples don't explicitly set `expose_system_information: false` for mainnet validators.

4. **Easy Discovery**: The inspection service runs on a known default port (9101) and the endpoint path is predictable (`/system_information`).

5. **Zero Prerequisites**: Any external attacker can exploit this - no authentication, no special permissions, no validator insider access required.

## Recommendation
The `ConfigSanitizer` should enforce that **all** potentially sensitive inspection service endpoints are disabled for mainnet validators, not just `expose_configuration`.

**Recommended Fix:**

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
                
                if inspection_service_config.expose_system_information {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "Mainnet validators should not expose system information!".to_string(),
                    ));
                }
                
                if inspection_service_config.expose_identity_information {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "Mainnet validators should not expose identity information!".to_string(),
                    ));
                }
                
                if inspection_service_config.expose_peer_information {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "Mainnet validators should not expose peer information!".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }
}
```

Additionally, the default configuration for `expose_system_information` should be changed to `false` to follow the secure-by-default principle.

## Proof of Concept

**Step 1:** Start a mainnet validator with default configuration (or any configuration that doesn't explicitly set `expose_system_information: false`)

**Step 2:** Execute the following HTTP request:

```bash
curl http://VALIDATOR_IP:9101/system_information
```

**Expected Result (Current Behavior):** The endpoint returns a JSON response containing:
```json
{
  "cpu_brand": "Intel(R) Xeon(R) CPU @ 2.50GHz",
  "cpu_count": "8",
  "cpu_core_count": "4",
  "cpu_frequency": "2500",
  "memory_total": "16777216000",
  "memory_available": "8388608000",
  "disk_total_space": "1000000000000",
  "system_host_name": "validator-node-01",
  "system_kernel_version": "5.15.0-1023-gcp",
  "system_os_version": "Ubuntu 22.04.2 LTS",
  ...
}
```

**Expected Result (After Fix):** The endpoint returns HTTP 403 Forbidden with error message due to ConfigSanitizer validation failure during node startup.

**Rust Test Case:**

```rust
#[test]
fn test_sanitize_system_info_mainnet() {
    // Create an inspection service config with system information endpoint enabled
    let node_config = NodeConfig {
        inspection_service: InspectionServiceConfig {
            expose_system_information: true,
            ..Default::default()
        },
        ..Default::default()
    };

    // Verify that sanitization fails for mainnet validators
    let error = InspectionServiceConfig::sanitize(
        &node_config,
        NodeType::Validator,
        Some(ChainId::mainnet()),
    )
    .unwrap_err();
    assert!(matches!(error, Error::ConfigSanitizerFailed(_, _)));
}
```

## Notes
This vulnerability represents a significant operational security gap. While the inspection service endpoints can be individually disabled, the lack of enforcement at the configuration level means that mainnet validators operating with default or partially-configured settings are exposing sensitive information that could be leveraged in multi-stage attacks. The incomplete implementation of the `ConfigSanitizer` creates a false sense of security, as operators may assume that all sensitive endpoints are properly validated when in fact only `expose_configuration` is checked.

### Citations

**File:** config/src/config/inspection_service_config.rs (L26-37)
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
}
```

**File:** config/src/config/inspection_service_config.rs (L45-68)
```rust
impl ConfigSanitizer for InspectionServiceConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let inspection_service_config = &node_config.inspection_service;

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
        }

        Ok(())
    }
```

**File:** crates/aptos-telemetry/src/system_information.rs (L14-33)
```rust
/// System information keys
const CPU_BRAND: &str = "cpu_brand";
const CPU_COUNT: &str = "cpu_count";
const CPU_CORE_COUNT: &str = "cpu_core_count";
const CPU_FREQUENCY: &str = "cpu_frequency";
const CPU_NAME: &str = "cpu_name";
const CPU_VENDOR_ID: &str = "cpu_vendor_id";
const DISK_AVAILABLE_SPACE: &str = "disk_available_space";
const DISK_COUNT: &str = "disk_count";
const DISK_FILE_SYSTEM: &str = "disk_file_system";
const DISK_NAME: &str = "disk_name";
const DISK_TOTAL_SPACE: &str = "disk_total_space";
const DISK_TYPE: &str = "disk_type";
const MEMORY_AVAILABLE: &str = "memory_available";
const MEMORY_TOTAL: &str = "memory_total";
const MEMORY_USED: &str = "memory_used";
const SYSTEM_HOST_NAME: &str = "system_host_name";
const SYSTEM_KERNEL_VERSION: &str = "system_kernel_version";
const SYSTEM_NAME: &str = "system_name";
const SYSTEM_OS_VERSION: &str = "system_os_version";
```

**File:** crates/aptos-telemetry/src/system_information.rs (L51-68)
```rust
pub fn get_system_information() -> BTreeMap<String, String> {
    let mut system_information: BTreeMap<String, String> = BTreeMap::new();
    collect_system_info(&mut system_information);
    system_information
}

/// Collects the system info and appends it to the given map
pub(crate) fn collect_system_info(system_information: &mut BTreeMap<String, String>) {
    // Note: this might be expensive, so it shouldn't be done often
    GLOBAL_SYSTEM.lock().refresh_system();
    GLOBAL_SYSTEM.lock().refresh_disks();

    // Collect relevant and available system information
    collect_cpu_info(system_information, &GLOBAL_SYSTEM);
    collect_disk_info(system_information, &GLOBAL_SYSTEM);
    collect_memory_info(system_information, &GLOBAL_SYSTEM);
    collect_sys_info(system_information, &GLOBAL_SYSTEM);
}
```

**File:** crates/aptos-inspection-service/src/server/system_information.rs (L14-29)
```rust
pub fn handle_system_information_request(node_config: NodeConfig) -> (StatusCode, Body, String) {
    // Only return system information if the endpoint is enabled
    if node_config.inspection_service.expose_system_information {
        (
            StatusCode::OK,
            Body::from(get_system_information_json()),
            CONTENT_TYPE_JSON.into(),
        )
    } else {
        (
            StatusCode::FORBIDDEN,
            Body::from(SYS_INFO_DISABLED_MESSAGE),
            CONTENT_TYPE_TEXT.into(),
        )
    }
}
```
