# Audit Report

## Title
Mainnet Validators Can Accidentally Expose System Information Due to Insecure Default Configuration and Missing Sanitizer Check

## Summary
The `InspectionServiceConfig` has `expose_system_information: true` by default, but the `ConfigSanitizer` does not enforce that mainnet validators disable this endpoint. This creates an inconsistency where mainnet validators are protected from exposing configuration data but not system information. When validators enable the metrics port for monitoring purposes, they inadvertently expose sensitive system details including hostname, hardware specifications, OS version, and build commit hash to the public internet. [1](#0-0) 

## Finding Description

The vulnerability stems from three design flaws working in combination:

**Flaw 1: Insecure Default Configuration**

The `InspectionServiceConfig::default()` implementation sets `expose_system_information: true`, meaning validators must explicitly disable this to prevent exposure. [2](#0-1) 

**Flaw 2: Incomplete Sanitizer Logic**

The `ConfigSanitizer::sanitize()` implementation checks that mainnet validators do not expose configuration data but fails to check system information exposure: [3](#0-2) 

This creates an inconsistency where `expose_configuration` is explicitly protected for mainnet validators, but `expose_system_information` is not, despite exposing similarly sensitive data.

**Flaw 3: Common Deployment Pattern Enables Exposure**

When validators enable the metrics port for legitimate monitoring (setting `enableMetricsPort: true`), the inspection service becomes publicly accessible through the LoadBalancer: [4](#0-3) 

The HAProxy configuration exposes the internal inspection service port 9101 as external port 9102: [5](#0-4) 

**Attack Scenario:**

1. Validator operator enables metrics port for Prometheus monitoring by setting `enableMetricsPort: true`
2. Validator uses default node configuration without explicitly setting `expose_system_information: false`
3. Inspection service exposes `/system_information` endpoint with default `expose_system_information: true`
4. Attacker sends HTTP GET to `http://validator-ip:9101/system_information`
5. Service returns detailed system information because the check passes: [6](#0-5) 

**Sensitive Information Exposed:**

The `get_system_information()` function collects and returns:
- CPU brand, count, cores, frequency, vendor
- Disk available space, filesystem, total space, type
- Memory available, total, used
- **System hostname** (reveals internal network naming)
- Kernel version (enables CVE identification)
- OS name and version (enables exploit targeting)
- Build commit hash (reveals exact code version) [7](#0-6) 

## Impact Explanation

This vulnerability represents a **defense-in-depth failure** with Medium severity impact for the following reasons:

1. **Facilitates Targeted Attacks**: Knowing the exact OS/kernel version and build commit allows attackers to identify applicable CVEs and known vulnerabilities in that specific code version.

2. **Infrastructure Reconnaissance**: Hostname disclosure reveals internal naming conventions, helping attackers map the network topology and identify high-value targets.

3. **Hardware Fingerprinting**: CPU and memory specifications enable attackers to craft resource exhaustion attacks optimized for the specific hardware configuration.

4. **Configuration Inconsistency**: The sanitizer's explicit protection of `expose_configuration` but not `expose_system_information` indicates that information exposure on mainnet validators was considered a security concern, making this omission a genuine oversight rather than an intentional design choice.

According to Aptos bug bounty guidelines, this qualifies as **Medium Severity** because while it's primarily information disclosure (typically Low), it significantly aids more serious attacks and represents a protocol-level misconfiguration affecting validator security posture.

## Likelihood Explanation

The likelihood is **Medium to High** because:

1. **Common Operational Practice**: Validators commonly enable metrics ports for monitoring infrastructure (Prometheus, Grafana, etc.), making `enableMetricsPort: true` a standard configuration.

2. **Default Configs Don't Include Inspection Service**: None of the example validator configurations include an `inspection_service` section, meaning they rely on defaults: [8](#0-7) 

3. **No Warning or Guidance**: There's no documentation warning validators to disable system information exposure when enabling metrics, unlike the explicit sanitizer error for configuration exposure.

4. **Validator Count**: This affects all mainnet validators who enable metrics without explicitly disabling system information exposure.

## Recommendation

**Immediate Fix: Add Sanitizer Check**

Add a check for `expose_system_information` in the `ConfigSanitizer::sanitize()` method, mirroring the existing check for `expose_configuration`:

```rust
// In config/src/config/inspection_service_config.rs, around line 65
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
            }
        }

        Ok(())
    }
}
```

**Defense-in-Depth: Change Default to False**

For maximum security, change the default value to `false`:

```rust
impl Default for InspectionServiceConfig {
    fn default() -> InspectionServiceConfig {
        InspectionServiceConfig {
            address: "0.0.0.0".to_string(),
            port: 9101,
            expose_configuration: false,
            expose_identity_information: false,  // Consider this too
            expose_peer_information: false,       // Consider this too
            expose_system_information: false,     // CHANGE FROM true
        }
    }
}
```

## Proof of Concept

**Setup:**
1. Deploy a validator with `enableMetricsPort: true` and default inspection service config
2. The validator will have `expose_system_information: true` by default

**Exploitation:**
```bash
# Query the system information endpoint
curl http://<validator-ip>:9101/system_information

# Expected response (JSON with system details):
{
  "cpu_brand": "Intel Core i9-9900K",
  "cpu_count": "16",
  "cpu_core_count": "8",
  "memory_total": "67108864000",
  "system_host_name": "aptos-validator-prod-01",
  "system_kernel_version": "5.15.0-1030-gcp",
  "system_name": "Linux",
  "build_commit_hash": "abc123def456..."
  // ... additional sensitive details
}
```

**Rust Test to Verify Sanitizer Gap:**
```rust
#[test]
fn test_sanitize_mainnet_system_information_exposure() {
    // Create a config with system information exposure enabled
    let node_config = NodeConfig {
        inspection_service: InspectionServiceConfig {
            expose_system_information: true,  // This should be rejected for mainnet validators
            ..Default::default()
        },
        ..Default::default()
    };

    // Attempt to sanitize - THIS CURRENTLY PASSES BUT SHOULD FAIL
    let result = InspectionServiceConfig::sanitize(
        &node_config,
        NodeType::Validator,
        Some(ChainId::mainnet()),
    );
    
    // This assertion FAILS with current code (no error returned)
    // but SHOULD PASS with the fix (error returned)
    assert!(result.is_err(), "Mainnet validators should not be allowed to expose system information");
}
```

## Notes

This vulnerability represents a **configuration security gap** rather than a critical consensus or funds-at-risk issue. However, it's significant because:

1. It demonstrates incomplete security hardening for mainnet validators
2. The exposed information directly facilitates reconnaissance for more serious attacks
3. The inconsistency in the sanitizer logic suggests this protection was simply overlooked
4. The fix is trivial but important for validator operational security

The default Helm configuration has `enableMetricsPort: false`, which provides some protection, but validators commonly enable this for operational monitoring, making the vulnerability practically exploitable.

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

**File:** terraform/helm/aptos-node/templates/haproxy.yaml (L39-43)
```yaml
  {{- if $.Values.service.validator.enableMetricsPort }}
  - name: metrics
    port: 9101
    targetPort: 9102
  {{- end }}
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

**File:** terraform/helm/aptos-node/files/configs/validator-base.yaml (L1-48)
```yaml
###
### This is the base validator NodeConfig to work with this helm chart
### Additional overrides to the NodeConfig can be specified via .Values.validator.config or .Values.overrideNodeConfig
###
base:
  role: validator
  waypoint:
    from_file: /opt/aptos/genesis/waypoint.txt

consensus:
  safety_rules:
    service:
      type: "local"
    backend:
      type: "on_disk_storage"
      path: secure-data.json
      namespace: ~
    initial_safety_rules_config:
      from_file:
        waypoint:
          from_file: /opt/aptos/genesis/waypoint.txt
        identity_blob_path: /opt/aptos/genesis/validator-identity.yaml

execution:
  genesis_file_location: /opt/aptos/genesis/genesis.blob

full_node_networks:
  - network_id:
      private: "vfn"
    listen_address: "/ip4/0.0.0.0/tcp/6181"
    identity:
      type: "from_config"
      key: "b0f405a3e75516763c43a2ae1d70423699f34cd68fa9f8c6bb2d67aa87d0af69"
      peer_id: "00000000000000000000000000000000d58bc7bb154b38039bc9096ce04e1237"

storage:
  rocksdb_configs:
    enable_storage_sharding: true

api:
  enabled: true
  address: "0.0.0.0:8080"

validator_network:
  discovery_method: "onchain"
  identity:
    type: "from_file"
    path: /opt/aptos/genesis/validator-identity.yaml
```
