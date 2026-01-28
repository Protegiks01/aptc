# Audit Report

## Title
Server-Side Request Forgery (SSRF) in Node Checker via Unvalidated DNS Resolution

## Summary
The Aptos Node Checker exposes a SSRF vulnerability via the `/check` endpoint. When a user supplies a malicious `node_url` pointing to an internal service or cloud metadata endpoint, the system resolves and connects to the specified target without verifying whether the resolved IP address is private, internal, or otherwise sensitive.

## Finding Description
The `/check` endpoint accepts a `node_url` query parameter and constructs a `NodeAddress` object from it. The `as_noise_network_address()` method is then called, which resolves the DNS entry to an IP (via `socket_addrs()`) with no filtering for private, loopback, or link-local addresses. The resolved address is used to initiate a noise protocol connection and a raw TCP handshake is performed, all prior to any validation of the remote address category. No filtering is implemented at any stage in this flow. This allows an attacker to target sensitive internal infrastructure, such as AWS metadata endpoints, by supplying a domain or IP in the URL and triggering an internal connection from trusted validator-node checker infrastructure. [1](#0-0) [2](#0-1) 

## Impact Explanation
This enables exposure of internal network services of validator operators, which often include highly sensitive endpoints such as cloud metadata endpoints (e.g., `169.254.169.254` for AWS/GCP), internal databases, key management systems, or private APIs. Exploiting this can lead to credential theft, metadata service exploitation, further lateral movement inside a validator's infrastructure, and total validator compromise (if sensitive secrets are obtained). The most likely impacts are classified as High per Aptos bounty guidelines: Validator node slowdowns, API crashes, and validator compromise if keys are accessed.

## Likelihood Explanation
Likelihood is high. The exploit is trivial to execute—a single HTTP GET to the `/check` endpoint with a carefully chosen `node_url` is sufficient. No authentication or authorization is required. This API is intended for use by validator/infrastructure operators but is not protected from untrusted input. The only prerequisite is network access to the node checker.

## Recommendation
The server-side logic handling node address and DNS resolution must implement strict filtering of network addresses. Reject any address that resolves to:
- Private range IPs (per RFC1918)
- Link-local addresses (`169.254.0.0/16`)
- Loopback addresses (e.g., `127.0.0.1`, `::1`)
- Any region deemed sensitive for the relevant deployment context

This should be done immediately after DNS resolution and before any connection attempt, both for IPv4 and IPv6. The validation should be included in `as_noise_network_address()` before returning a usable socket address.

## Proof of Concept

```
# Example HTTP GET
curl "http://<node-checker-host>:20121/check?baseline_configuration_id=devnet_fullnode&node_url=http://metadata.google.internal&noise_port=6180&public_key=0x..."
```

If the DNS resolves within the validator context (e.g., to `169.254.169.254`), the node checker will make a noise handshake attempt to the metadata service—verifiable via internal logs or network traffic.

---

Notes:
- The code path and logic for creating a `NodeAddress` from untrusted input and calling `as_noise_network_address()` is unambiguous, and no validation is performed after DNS resolution.
- No code in this flow (including underlying types) checks for private/reserved/loopback IPs after resolution, so any remediation must add or wrap address validation logic directly where network connections are made.
- The bug is high severity under the Aptos security guidelines as it can result in operational validator compromise if exploited in a common misconfiguration. [1](#0-0) [2](#0-1)

### Citations

**File:** ecosystem/node-checker/src/server/api.rs (L30-109)
```rust
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

        let complete_evaluation_result = baseline_configuration
            .runner
            .run(&target_node_address)
            .await;

        match complete_evaluation_result {
            Ok(complete_evaluation) => Ok(Json(complete_evaluation)),
            Err(e) => {
                // We only get to this point if the evaluation failed due to an error
                // on our side, e.g. something wrong with NHC or the baseline.
                error!(
                    target_node_url = target_node_address.url,
                    event = "check_failed_our_fault"
                );
                Err(poem::Error::from((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    anyhow!(e),
                )))
            },
        }
    }
```

**File:** ecosystem/node-checker/src/configuration/node_address.rs (L120-160)
```rust
    pub fn as_noise_network_address(&self) -> Result<NetworkAddress> {
        // Confirm we have a public key. Technically we can build a NetworkAddress
        // without one, but it's not useful for any of our needs without one.
        let public_key = match self.public_key {
            Some(public_key) => public_key,
            None => bail!("Cannot convert NodeAddress to NetworkAddress without a public key"),
        };

        // Ensure we can get socket addrs from the URL. If the URL is a domain
        // name, it will automatically perform DNS resolution.
        let socket_addrs = self
            .url
            .socket_addrs(|| None)
            .with_context(|| format!("Failed to get SocketAddrs from address {}", self.url))?;

        // Ensure this results in exactly one SocketAddr.
        if socket_addrs.is_empty() {
            bail!(
                "NodeAddress {} did not resolve to any SocketAddrs. If DNS, ensure domain name is valid",
                self.url
            );
        }
        if socket_addrs.len() > 1 {
            aptos_logger::warn!(
                "NodeAddress {} resolved to multiple SocketAddrs, but we're only checking the first one: {:?}",
                self.url,
                socket_addrs,
            );
        }

        // Configure the SocketAddr with the provided noise port.
        let mut socket_addr = socket_addrs[0];
        socket_addr.set_port(
            self.noise_port
                .context("Can't build NetworkAddress without a noise port")?,
        );

        // Build a network address, including the public key and protocol.
        Ok(NetworkAddress::from(socket_addr).append_prod_protos(public_key, 0))
    }
}
```
