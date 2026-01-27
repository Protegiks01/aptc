# Audit Report

## Title
Panic-Induced Validator Crash from Invalid AdminService Address Configuration

## Summary
The AdminService initialization code contains explicit panic calls when parsing the configured address, allowing an invalid `admin_service.address` value in the node configuration to crash validators during startup or reconfiguration. No validation exists during config loading to prevent invalid address values from reaching this panic point.

## Finding Description

The `AdminServiceConfig` struct accepts an arbitrary string for the `address` field with no validation during deserialization or sanitization. [1](#0-0) 

The `ConfigSanitizer` implementation for `AdminServiceConfig` only validates authentication requirements for mainnet but performs no validation of the address format. [2](#0-1) 

During node startup, the admin service is started early in the initialization process. [3](#0-2) 

The `AdminService::new()` constructor attempts to parse the configured address string into a `SocketAddr`, containing two explicit panic points:

1. **Panic on resolution failure**: If `to_socket_addrs()` fails to parse/resolve the address, it explicitly calls `panic!()` [4](#0-3) 

2. **Panic on empty iterator**: If resolution succeeds but returns no addresses, `.next().unwrap()` panics [5](#0-4) 

**Attack Scenario:**
1. Attacker modifies validator config file (e.g., through compromised deployment automation, config management system, or social engineering)
2. Sets `admin_service.address` to invalid value: `"invalid.hostname.local"`, `"999.999.999.999"`, `"not-an-ip"`, or empty string
3. Config loads successfully (no validation during deserialization)
4. During startup, `AdminService::new()` is called
5. Address parsing fails, triggering panic and crashing the validator immediately

## Impact Explanation

**Severity: HIGH** (Validator node crashes)

This vulnerability enables denial-of-service attacks against validators:

- **Complete startup failure**: Validators cannot start with invalid AdminService address configuration
- **Crash during reconfiguration**: If configs are hot-reloaded, validators crash immediately
- **No graceful degradation**: The panic provides no error recovery mechanism
- **Operational disruption**: Requires manual intervention to identify and fix the config issue

While the AdminService itself is not consensus-critical, preventing a validator from starting at all impacts network availability and liveness. Multiple misconfigured validators could degrade network performance or, in extreme cases, threaten consensus if validator participation drops below required thresholds.

Per Aptos bug bounty criteria, this qualifies as **High Severity** due to causing validator node crashes and operational disruption.

## Likelihood Explanation

**Likelihood: MEDIUM**

The vulnerability requires an attacker to modify the validator's configuration file, which typically requires some level of access to the validator's deployment infrastructure. However:

- **Configuration systems**: Automated deployment tools, config management (Ansible, Terraform), or CI/CD pipelines could be compromised
- **Human error**: Legitimate operators may accidentally introduce invalid addresses during configuration updates
- **Supply chain**: Compromised config templates or deployment scripts could inject invalid values
- **Insider threats**: Malicious operators with config access can trivially exploit this

Once an invalid value is in the config, the crash is deterministic and guaranteed.

## Recommendation

Add validation for the `address` field during config sanitization to reject invalid address formats before they reach the runtime initialization code:

```rust
impl ConfigSanitizer for AdminServiceConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();

        // Validate address format if enabled
        if node_config.admin_service.enabled == Some(true) {
            // Validate that address can be resolved
            let test_addr = (
                node_config.admin_service.address.as_str(),
                node_config.admin_service.port,
            );
            
            test_addr.to_socket_addrs().map_err(|e| {
                Error::ConfigSanitizerFailed(
                    sanitizer_name.clone(),
                    format!(
                        "Invalid admin_service address '{}:{}': {}",
                        node_config.admin_service.address,
                        node_config.admin_service.port,
                        e
                    ),
                )
            })?;

            // Check mainnet authentication requirement
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

        Ok(())
    }
}
```

Additionally, replace the panic in `AdminService::new()` with proper error handling:

```rust
let address: SocketAddr = (service_address.as_str(), service_port)
    .to_socket_addrs()
    .map_err(|e| anyhow::anyhow!(
        "Failed to parse admin service address {}:{}: {}",
        service_address, service_port, e
    ))?
    .next()
    .ok_or_else(|| anyhow::anyhow!(
        "No socket addresses resolved for admin service {}:{}",
        service_address, service_port
    ))?;
```

## Proof of Concept

**Setup:**
1. Create a validator config file with invalid AdminService address:

```yaml
base:
  role: "validator"
  # ... other base config

admin_service:
  enabled: true
  address: "invalid.hostname.that.does.not.resolve.anywhere.local"
  port: 9102
  authentication_configs: []
  malloc_stats_max_len: 2097152

# ... rest of config
```

2. Attempt to start the validator node:

```bash
cargo run --bin aptos-node -- -f /path/to/invalid-config.yaml
```

**Expected Result:**
The validator crashes with a panic:
```
thread 'admin' panicked at 'Failed to parse invalid.hostname.that.does.not.resolve.anywhere.local:9102 as address'
```

**Alternative PoC with invalid IP:**

```yaml
admin_service:
  enabled: true
  address: "999.999.999.999"  # Invalid IP address
  port: 9102
```

This will similarly cause the validator to panic during startup at the address parsing stage.

## Notes

While the `malloc_stats_max_len` parameter was also mentioned in the security question, its usage is safe. The malloc stats handler properly uses `std::cmp::min` to prevent buffer overflows, and setting it to 0 simply truncates output rather than causing a crash. [6](#0-5) 

The primary vulnerability is the unvalidated address field combined with panic-based error handling in the runtime initialization code.

### Citations

**File:** config/src/config/admin_service_config.rs (L17-24)
```rust
pub struct AdminServiceConfig {
    pub enabled: Option<bool>,
    pub address: String,
    pub port: u16,
    // If empty, will allow all requests without authentication. (Not allowed on mainnet.)
    pub authentication_configs: Vec<AuthenticationConfig>,
    pub malloc_stats_max_len: usize,
}
```

**File:** config/src/config/admin_service_config.rs (L59-82)
```rust
impl ConfigSanitizer for AdminServiceConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();

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

        Ok(())
    }
}
```

**File:** aptos-node/src/lib.rs (L700-701)
```rust
    // Starts the admin service
    let mut admin_service = services::start_admin_service(&node_config);
```

**File:** crates/aptos-admin-service/src/server/mod.rs (L78-85)
```rust
        let address: SocketAddr = (service_address.as_str(), service_port)
            .to_socket_addrs()
            .unwrap_or_else(|_| {
                panic!(
                    "Failed to parse {}:{} as address",
                    service_address, service_port
                )
            })
```

**File:** crates/aptos-admin-service/src/server/mod.rs (L86-87)
```rust
            .next()
            .unwrap();
```

**File:** crates/aptos-admin-service/src/server/malloc.rs (L18-19)
```rust
    let len = std::cmp::min(out.capacity(), stats_cstr.len());
    out.extend_from_slice(&stats_cstr[0..len]);
```
