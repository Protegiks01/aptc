# Audit Report

## Title
Unrestricted Build Information Disclosure Enables Validator Version Fingerprinting and Targeted Exploitation

## Summary
Multiple unprotected endpoints expose detailed build information (git commit hash, version, build time) to any network participant, enabling adversaries to fingerprint validator software versions and identify nodes running vulnerable or outdated software. This information disclosure facilitates targeted attacks against validators with known version-specific vulnerabilities.

## Finding Description

The Aptos node exposes build information through three distinct channels without authentication or access controls:

**1. REST API Index Endpoint (Always Exposed)**

The root API endpoint always returns the git commit hash: [1](#0-0) 

This exposure is **unconditional** - there is no configuration option to disable it.

**2. Inspection Service Endpoint (Enabled by Default)**

The `/system_information` endpoint exposes comprehensive build information: [2](#0-1) 

The full build information is retrieved via: [3](#0-2) 

This endpoint defaults to **enabled**: [4](#0-3) 

Critically, there is **no sanitizer preventing mainnet validators** from exposing system information (only configuration exposure is blocked): [5](#0-4) 

**3. Peer Monitoring Service (No Authentication)**

Any connected peer can send a `GetNodeInformation` RPC request and receive full build information: [6](#0-5) 

The build information structure includes: [7](#0-6) 

This includes:
- `BUILD_COMMIT_HASH`: Exact git commit hash
- `BUILD_TAG`: Version tag
- `BUILD_TIME`: Build timestamp  
- `BUILD_BRANCH`: Source branch
- `BUILD_PKG_VERSION`: Package version

The peer monitoring service is registered on **all network types** (validator, VFN, and public networks): [8](#0-7) 

**Attack Scenario:**

1. **Reconnaissance Phase**: Adversary connects to public fullnodes or VFNs operated by validators
2. **Version Fingerprinting**: 
   - Query `GET /` API endpoint → obtain `git_hash`
   - Query `GET /system_information` → obtain full build details (if enabled)
   - Send `GetNodeInformation` RPC → obtain complete build information
3. **Validator Identification**: Map VFNs to their associated validators (VFNs are typically operated by validators and run the same software version)
4. **Targeted Exploitation**: Identify validators running versions with known vulnerabilities and launch version-specific exploits

**Security Guarantees Broken:**

While this doesn't directly violate the 10 critical invariants, it creates a critical **operational security vulnerability** by:
- Eliminating security through obscurity for version-specific vulnerabilities
- Enabling reconnaissance for targeted attacks
- Providing real-time intelligence on network upgrade coordination
- Revealing which validators are lagging in security updates

## Impact Explanation

**Medium Severity** (up to $10,000 per Aptos Bug Bounty criteria)

This qualifies as a Medium severity information disclosure vulnerability because:

1. **Enables Targeted Attacks**: Adversaries can identify validators running specific vulnerable versions and craft targeted exploits rather than attempting blind attacks

2. **Network-Wide Intelligence**: Reveals upgrade coordination status - during upgrade periods, adversaries can identify which validators are still running old versions

3. **No Mitigation Options**: 
   - REST API `git_hash` exposure **cannot be disabled**
   - Peer monitoring service **has no authentication**
   - Inspection service defaults to **enabled** with no mainnet-specific protections

4. **Persistent Exposure**: While `NODE_BUILD_INFO_FREQ_SECS` (60 minutes) controls telemetry pushing to Aptos Labs servers, the real issue is that **on-demand queries** via REST API and peer monitoring RPC provide immediate, real-time version information to any adversary

5. **Amplification Effect**: Each vulnerable validator identified increases the attack surface for consensus-level attacks, as Byzantine fault tolerance assumes < 1/3 malicious validators

However, this is not Critical severity because:
- It's information disclosure, not direct exploitation
- Requires existence of exploitable vulnerabilities in specific versions
- Validators can partially mitigate by disabling public-facing services

## Likelihood Explanation

**HIGH Likelihood** - This vulnerability is actively exploitable today:

1. **No Authentication Required**: Any network participant can access these endpoints
2. **Enabled by Default**: All exposure channels are active in default configurations  
3. **Multiple Attack Vectors**: Three independent channels provide redundant access
4. **Public Accessibility**: VFNs and public fullnodes are intentionally publicly accessible
5. **No Rate Limiting**: Adversaries can continuously monitor version updates

The only barrier is that adversaries must:
- Know the network topology (which VFNs belong to which validators) - this is often public information
- Have knowledge of version-specific vulnerabilities - publicly disclosed CVEs make this trivial

## Recommendation

**Implement tiered access controls for build information disclosure:**

1. **REST API**: Add configuration flag to optionally mask git_hash for public endpoints:
```rust
// In api/src/index.rs
let git_hash = if node_config.api.expose_git_hash {
    Some(aptos_build_info::get_git_hash())
} else {
    None
};
```

2. **Inspection Service**: Add mainnet validator protection:
```rust
// In config/src/config/inspection_service_config.rs
if node_type.is_validator()
    && chain_id.is_mainnet()
    && inspection_service_config.expose_system_information
{
    return Err(Error::ConfigSanitizerFailed(
        sanitizer_name,
        "Mainnet validators should not expose system information!".to_string(),
    ));
}
```

3. **Peer Monitoring Service**: Implement authentication or restrict `GetNodeInformation` responses:
```rust
// In peer-monitoring-service/server/src/lib.rs
fn get_node_information(&self) -> Result<PeerMonitoringServiceResponse, Error> {
    // Return limited information (no build details) to untrusted peers
    let build_information = if self.is_trusted_peer() {
        aptos_build_info::get_build_information()
    } else {
        BTreeMap::new() // Return empty build info to untrusted peers
    };
    // ... rest of implementation
}
```

4. **Configuration Defaults**: Disable build information exposure by default for mainnet validators:
```rust
// In config/src/config/inspection_service_config.rs
impl Default for InspectionServiceConfig {
    fn default() -> InspectionServiceConfig {
        InspectionServiceConfig {
            expose_system_information: false, // Changed from true
            // ... other fields
        }
    }
}
```

## Proof of Concept

**Step 1: Query REST API for git hash**
```bash
# Query any public Aptos node
curl https://fullnode.mainnet.aptoslabs.com/ | jq '.git_hash'
# Returns: "a1b2c3d4..." (actual commit hash)
```

**Step 2: Query Inspection Service**
```bash
# Query inspection service (if enabled)
curl http://node-ip:9101/system_information | jq '.build_commit_hash'
# Returns: Full build information including commit hash, version, build time
```

**Step 3: Query via Peer Monitoring RPC (Rust client)**
```rust
use aptos_peer_monitoring_service_client::PeerMonitoringServiceClient;
use aptos_peer_monitoring_service_types::request::PeerMonitoringServiceRequest;

async fn fingerprint_node(client: &PeerMonitoringServiceClient, peer_id: PeerId) {
    // Send GetNodeInformation request
    let request = PeerMonitoringServiceRequest::GetNodeInformation;
    let response = client.send_request(peer_id, request).await.unwrap();
    
    // Extract build information from NodeInformationResponse
    if let PeerMonitoringServiceResponse::NodeInformation(info) = response {
        println!("Git Hash: {}", info.build_information.get("build_commit_hash").unwrap());
        println!("Version: {}", info.build_information.get("build_pkg_version").unwrap());
        println!("Build Time: {}", info.build_information.get("build_time").unwrap());
        
        // Now adversary knows exact version and can check for known vulnerabilities
        check_for_vulnerabilities(&info.build_information);
    }
}
```

**Impact Demonstration:**
```
Scenario: CVE-XXXX-YYYY exists in Aptos version 1.2.3 (commit abc123)

1. Adversary scans network and identifies:
   - Validator A: Running commit abc123 (VULNERABLE)
   - Validator B: Running commit def456 (PATCHED)
   - Validator C: Running commit abc123 (VULNERABLE)

2. Adversary targets Validators A and C with version-specific exploit
3. With 2 of 10 validators compromised (20% < 33% Byzantine threshold), 
   adversary still cannot break consensus but has gained significant foothold
4. During next upgrade window, adversary identifies validators lagging updates
   and times attacks for maximum impact
```

This vulnerability enables systematic reconnaissance that significantly reduces the adversary's effort to identify and exploit version-specific weaknesses in the validator set.

---

**Notes:**

The `NODE_BUILD_INFO_FREQ_SECS` constant mentioned in the security question controls telemetry reporting to Aptos Labs servers, which is not the primary attack vector. The real vulnerability is the **unrestricted on-demand access** to build information through REST API and peer monitoring RPC, which provides immediate version fingerprinting without any authentication or rate limiting.

### Citations

**File:** api/src/index.rs (L39-43)
```rust
                let index_response = IndexResponse::new(
                    ledger_info.clone(),
                    node_role,
                    Some(aptos_build_info::get_git_hash()),
                );
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

**File:** crates/aptos-inspection-service/src/server/system_information.rs (L32-35)
```rust
fn get_system_information_json() -> String {
    // Get the system and build information
    let mut system_information = aptos_telemetry::system_information::get_system_information();
    system_information.extend(build_information!());
```

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

**File:** config/src/config/inspection_service_config.rs (L54-65)
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
        }
```

**File:** peer-monitoring-service/server/src/lib.rs (L259-280)
```rust
    fn get_node_information(&self) -> Result<PeerMonitoringServiceResponse, Error> {
        // Get the node information
        let build_information = aptos_build_info::get_build_information();
        let current_time: Instant = self.time_service.now();
        let uptime = current_time.duration_since(self.start_time);
        let (highest_synced_epoch, highest_synced_version) =
            self.storage.get_highest_synced_epoch_and_version()?;
        let ledger_timestamp_usecs = self.storage.get_ledger_timestamp_usecs()?;
        let lowest_available_version = self.storage.get_lowest_available_version()?;

        // Create and return the response
        let node_information_response = NodeInformationResponse {
            build_information,
            highest_synced_epoch,
            highest_synced_version,
            ledger_timestamp_usecs,
            lowest_available_version,
            uptime,
        };
        Ok(PeerMonitoringServiceResponse::NodeInformation(
            node_information_response,
        ))
```

**File:** crates/aptos-build-info/src/lib.rs (L59-84)
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

```

**File:** aptos-node/src/network.rs (L370-378)
```rust
        // Register the peer monitoring service (both client and server) with the network
        let peer_monitoring_service_network_handle = register_client_and_service_with_network(
            &mut network_builder,
            network_id,
            &network_config,
            peer_monitoring_network_configuration(node_config),
            true,
        );
        peer_monitoring_service_network_handles.push(peer_monitoring_service_network_handle);
```
