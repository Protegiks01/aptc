# Audit Report

## Title
Missing Authentication in Inspection Service Configuration Endpoint Enables Unauthorized Information Disclosure

## Summary
The `handle_configuration_request()` function in the Aptos Inspection Service lacks any authentication mechanism, creating an architectural inconsistency with the Admin Service which enforces authentication for similar sensitive endpoints. This allows unauthenticated network attackers to retrieve node configuration data when the endpoint is enabled.

## Finding Description

The inspection service's configuration endpoint exposes the entire `NodeConfig` structure without validating authentication tokens or API keys. [1](#0-0) 

The function only checks if the `expose_configuration` flag is enabled but performs no authentication validation whatsoever. The service binds to `0.0.0.0` by default, making it accessible from all network interfaces. [2](#0-1) 

In contrast, the Admin Service implements proper authentication for similar debugging endpoints. It enforces passcode-based authentication and prevents unauthenticated access on mainnet. [3](#0-2) 

The Admin Service configuration explicitly requires authentication on mainnet. [4](#0-3) 

While the configuration uses debug formatting to protect private keys via `SilentDebug`, it still exposes extensive operational information including network topology, peer addresses, storage configurations, consensus settings, and internal parameters. [5](#0-4) 

## Impact Explanation

This issue constitutes **information disclosure** but does **not** meet High severity criteria per the Aptos Bug Bounty program. According to the bounty guidelines, this falls under **Low Severity** ("Minor information leaks") rather than High Severity which requires "Validator node slowdowns," "API crashes," or "Significant protocol violations."

The leaked configuration data enables reconnaissance for potential attacks but does not directly cause:
- Loss of funds or consensus violations (Critical)
- Validator slowdowns or API crashes (High)  
- State inconsistencies or fund manipulation (Medium)

The mainnet protection via `ConfigSanitizer` prevents validators from exposing this endpoint, limiting the attack surface. [6](#0-5) 

## Likelihood Explanation

**Moderate likelihood** on non-mainnet deployments where the endpoint is auto-enabled. **Low likelihood** on mainnet where validators cannot enable it.

The `ConfigOptimizer` automatically enables all inspection endpoints on non-mainnet networks, creating exposure on testnets and development networks. [7](#0-6) 

Exploitation requires:
1. Node operator manually enables `expose_configuration` (against best practices) OR running on non-mainnet
2. Firewall rules don't restrict port 9101 access
3. Attacker has network access to the inspection service port

## Recommendation

Implement authentication for the inspection service consistent with the Admin Service design:

1. Add `authentication_configs` field to `InspectionServiceConfig` 
2. Implement authentication validation in the request handler before serving sensitive endpoints
3. Enforce authentication on mainnet via `ConfigSanitizer` when sensitive endpoints are enabled
4. Consider requiring authentication for all endpoints that expose internal state, not just configuration

Reference the Admin Service implementation as a template for proper authentication. [8](#0-7) 

## Proof of Concept

```bash
# On a node with expose_configuration=true (e.g., testnet node)
curl http://<node_ip>:9101/configuration

# Returns full NodeConfig in debug format including:
# - Network addresses and peer information
# - Storage and database configurations  
# - Consensus parameters
# - API settings and feature flags
# No authentication required
```

---

**Notes:**

While this represents a valid security concern regarding architectural inconsistency between inspection and admin services, the actual severity per Aptos Bug Bounty criteria is **Low** (Minor information leak), not High. The issue does not break any of the 10 critical invariants (deterministic execution, consensus safety, Move VM safety, etc.) and does not directly threaten funds, consensus, or availability. Mainnet validators are protected by configuration sanitization that prevents enabling this endpoint.

### Citations

**File:** crates/aptos-inspection-service/src/server/configuration.rs (L13-29)
```rust
pub fn handle_configuration_request(node_config: &NodeConfig) -> (StatusCode, Body, String) {
    // Only return configuration if the endpoint is enabled
    let (status_code, body) = if node_config.inspection_service.expose_configuration {
        // We format the configuration using debug formatting. This is important to
        // prevent secret/private keys from being serialized and leaked (i.e.,
        // all secret keys are marked with SilentDisplay and SilentDebug).
        let encoded_configuration = format!("{:?}", node_config);
        (StatusCode::OK, Body::from(encoded_configuration))
    } else {
        (
            StatusCode::FORBIDDEN,
            Body::from(CONFIGURATION_DISABLED_MESSAGE),
        )
    };

    (status_code, body, CONTENT_TYPE_TEXT.into())
}
```

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

**File:** config/src/config/inspection_service_config.rs (L45-69)
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

**File:** crates/aptos-admin-service/src/server/mod.rs (L154-181)
```rust
        let mut authenticated = false;
        if context.config.authentication_configs.is_empty() {
            authenticated = true;
        } else {
            for authentication_config in &context.config.authentication_configs {
                match authentication_config {
                    AuthenticationConfig::PasscodeSha256(passcode_sha256) => {
                        let query = req.uri().query().unwrap_or("");
                        let query_pairs: HashMap<_, _> =
                            url::form_urlencoded::parse(query.as_bytes()).collect();
                        let passcode: Option<String> =
                            query_pairs.get("passcode").map(|p| p.to_string());
                        if let Some(passcode) = passcode {
                            if sha256::digest(passcode) == *passcode_sha256 {
                                authenticated = true;
                            }
                        }
                    },
                }
            }
        };

        if !authenticated {
            return Ok(reply_with_status(
                StatusCode::NETWORK_AUTHENTICATION_REQUIRED,
                format!("{} endpoint requires authentication.", req.uri().path()),
            ));
        }
```

**File:** config/src/config/admin_service_config.rs (L15-39)
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdminServiceConfig {
    pub enabled: Option<bool>,
    pub address: String,
    pub port: u16,
    // If empty, will allow all requests without authentication. (Not allowed on mainnet.)
    pub authentication_configs: Vec<AuthenticationConfig>,
    pub malloc_stats_max_len: usize,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationConfig {
    // This will allow authentication through query parameter.
    // e.g. `/profilez?passcode=abc`.
    //
    // To calculate sha256, use sha256sum tool, or other online tools.
    //
    // e.g.
    //
    // printf abc |sha256sum
    PasscodeSha256(String),
    // TODO(grao): Add SSL support if necessary.
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
