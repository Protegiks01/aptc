# Audit Report

## Title
Aptos Node Checker API Exposed to Public Network Without Authentication Enabling Information Disclosure and DoS Attacks

## Summary
The aptos-node-checker server binds to all network interfaces (0.0.0.0) by default without any authentication, rate limiting, or access control mechanisms. This exposes the node health checking API to the public network, allowing unauthorized users to query sensitive node information, use the service as a scanning proxy, and potentially launch resource exhaustion attacks.

## Finding Description
The node-checker service is invoked via `server::run_cmd()` in the main binary. [1](#0-0) 

This function ultimately calls the `run()` function which binds the server to a configurable address and port. [2](#0-1) 

The critical security issue lies in the default configuration for `listen_address`, which is set to **"0.0.0.0"** (all network interfaces) rather than "127.0.0.1" (localhost only). [3](#0-2) 

This default binding exposes two unauthenticated API endpoints to the public network:

1. **`/check` endpoint** - Allows anyone to run health checks against arbitrary target nodes by specifying a node URL and baseline configuration. [4](#0-3) 

2. **`/configurations` endpoint** - Exposes all available baseline configurations. [5](#0-4) 

The service implements only CORS middleware with no authentication, authorization, or rate limiting mechanisms. [6](#0-5) 

**Comparison with Security-Critical Services:**

In contrast, security-critical services like the Consensus Safety Rules explicitly bind to localhost only to prevent unauthorized access. [7](#0-6) 

**Attack Scenarios:**

1. **Information Disclosure**: An attacker discovers a publicly exposed node-checker instance and queries the `/check` endpoint to gather detailed health metrics, API availability, and configuration information about validator nodes in the network.

2. **Scanning Proxy**: An attacker uses the public node-checker as a proxy to scan other nodes, hiding their real IP address while conducting reconnaissance.

3. **Resource Exhaustion**: Without rate limiting, an attacker floods the API with thousands of concurrent requests to `/check`, causing the service to exhaust CPU, memory, or network resources, leading to API crashes or denial of service.

4. **Network Topology Mapping**: An attacker enumerates all baseline configurations via `/configurations` to understand the network's validator architecture and identify potential targets.

## Impact Explanation
This vulnerability qualifies as **High Severity** according to Aptos Bug Bounty criteria:

- **API crashes**: Unlimited unauthenticated requests can exhaust system resources, causing the node-checker service to crash or become unresponsive.
- **Information disclosure**: Sensitive validator node health data, metrics endpoints, and network configuration details are exposed to unauthorized parties.
- **Reconnaissance enablement**: Attackers can use the exposed API to map the validator network and identify weak or misconfigured nodes for further attacks.

While the node-checker is not a core consensus component, its exposure can facilitate attacks against validator infrastructure and violates the **Access Control** security invariant by allowing unrestricted access to diagnostic capabilities that should be restricted to authorized operators.

## Likelihood Explanation
**Likelihood: High**

This vulnerability is highly likely to be exploited because:

1. **Default configuration is insecure**: Operators who run the node-checker with default settings automatically expose it to the public network.
2. **No authentication required**: Any network client can access the API endpoints without credentials.
3. **Well-documented API**: The OpenAPI specification is publicly available, making it easy for attackers to discover and exploit exposed instances.
4. **Discovery is trivial**: Automated scanners can easily identify exposed node-checker instances on the default port (20121).
5. **Low attacker skill requirement**: Exploiting this requires only basic HTTP client knowledge.

## Recommendation
Implement the following security controls:

1. **Change default binding to localhost**:
   ```rust
   #[clap(long, default_value = "127.0.0.1")]
   pub listen_address: String,
   ```

2. **Add authentication middleware**: Implement API key or token-based authentication to restrict access to authorized operators.

3. **Implement rate limiting**: Add request rate limiting per client IP to prevent resource exhaustion attacks.

4. **Add security documentation**: Document the security implications of binding to 0.0.0.0 and recommend using reverse proxies with authentication for production deployments.

5. **Consider IP allowlisting**: Allow operators to configure an allowlist of trusted IP addresses or CIDR ranges.

**Fixed code for `ecosystem/node-checker/src/server/common.rs`**:
```rust
#[derive(Clone, Debug, Parser)]
pub struct ServerArgs {
    /// What address to listen on, e.g. localhost or 0.0.0.0
    /// SECURITY: Defaults to localhost. Only bind to 0.0.0.0 if behind a secured reverse proxy.
    #[clap(long, default_value = "127.0.0.1")]
    pub listen_address: String,
    // ... rest of fields
}
```

## Proof of Concept

**Setup:**
1. Deploy node-checker with default configuration:
   ```bash
   cargo run -p aptos-node-checker -- server run \
     --baseline-config-paths ./baseline.yaml
   ```

2. From a remote machine, enumerate configurations:
   ```bash
   curl http://TARGET_IP:20121/configurations
   ```

3. Query health of arbitrary target nodes:
   ```bash
   curl "http://TARGET_IP:20121/check?baseline_configuration_id=devnet_fullnode&node_url=http://victim-node.example.com"
   ```

4. Launch resource exhaustion attack:
   ```bash
   for i in {1..10000}; do
     curl "http://TARGET_IP:20121/check?baseline_configuration_id=devnet_fullnode&node_url=http://example.com" &
   done
   ```

**Expected Result**: 
- Step 2-3 succeed, exposing sensitive information
- Step 4 causes high CPU/memory usage, potential API crash

**Reproduction Steps:**
1. Start node-checker service with default settings
2. Verify it binds to 0.0.0.0:20121 by checking `netstat -tlnp | grep 20121`
3. Access the API from any external IP address without authentication
4. Observe successful unauthorized access to node health checking capabilities

## Notes
This vulnerability represents a fundamental security design flaw where a diagnostic tool defaults to insecure network exposure. While operators could configure firewall rules or use reverse proxies to mitigate this issue, the principle of secure defaults dictates that services should bind to localhost unless explicitly configured otherwise. The contrast with the Safety Rules service—which explicitly binds to localhost for security—demonstrates that the Aptos codebase already follows this pattern for security-critical components, but the node-checker was not implemented with the same security considerations.

### Citations

**File:** ecosystem/node-checker/src/bin/aptos-node-checker.rs (L34-35)
```rust
        Command::Server(args) => server::run_cmd(args).await,
        Command::Configuration(args) => configuration::run_cmd(args).await,
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

**File:** ecosystem/node-checker/src/server/common.rs (L13-15)
```rust
    /// What address to listen on, e.g. localhost or 0.0.0.0
    #[clap(long, default_value = "0.0.0.0")]
    pub listen_address: String,
```

**File:** ecosystem/node-checker/src/server/api.rs (L29-45)
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
    ) -> poem::Result<Json<CheckSummary>> {
```

**File:** ecosystem/node-checker/src/server/api.rs (L114-126)
```rust
    #[oai(path = "/configurations", method = "get")]
    async fn configurations(&self) -> Json<Vec<ConfigurationDescriptor>> {
        Json(
            self.baseline_configurations
                .0
                .iter()
                .map(|(k, v)| ConfigurationDescriptor {
                    id: k.clone(),
                    pretty_name: v.configuration.configuration_name.clone(),
                })
                .collect(),
        )
    }
```

**File:** consensus/safety-rules/src/thread.rs (L30-32)
```rust
        let listen_port = utils::get_available_port();
        let listen_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_port);
        let server_addr = listen_addr;
```
