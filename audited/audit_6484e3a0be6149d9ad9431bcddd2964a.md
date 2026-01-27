# Audit Report

## Title
HTTP Redirect Following Vulnerability in JWK Consensus Configuration Allows Malicious JWK Injection

## Summary
The JWK consensus system blindly follows HTTP redirects when fetching OpenID configuration and JWK keys from OIDC provider `config_url` endpoints. This allows attackers to redirect validators to malicious JWK servers through open redirects, URL shorteners, or domain takeovers, potentially compromising keyless account security.

## Finding Description

The JWK fetching mechanism in the Aptos consensus layer uses the `reqwest` HTTP client with default settings that automatically follow HTTP redirects without validation or restrictions. [1](#0-0) 

When governance configures an OIDC provider with a `config_url`, validators periodically fetch JWK keys from this URL. The system accepts any string as a valid `config_url` without validation: [2](#0-1) 

The JWKObserver spawns background tasks that call these fetch functions: [3](#0-2) 

**Attack Scenario:**

1. Attacker identifies or creates a legitimate-looking `config_url` that performs HTTP redirects (e.g., through open redirect vulnerabilities, URL shorteners, or domain takeovers)
2. Through governance proposal (requires social engineering or finding trusted domains with open redirects), the malicious `config_url` is approved
3. Validators fetch from the `config_url` using `reqwest::Client::new()` which follows up to 10 redirects by default
4. The URL redirects to an attacker-controlled server serving malicious JWK keys
5. Validators broadcast their observations of these malicious JWKs
6. When quorum is reached, the malicious JWKs are committed on-chain via validator transaction
7. These JWKs are then used to verify keyless account signatures: [4](#0-3) 

8. Attacker can forge JWT signatures using private keys corresponding to the malicious JWKs, impersonating keyless accounts

**Invariant Violations:**
- **Deterministic Execution**: If redirect chains are time-sensitive or geo-dependent, different validators may fetch different final JWK sets, breaking consensus determinism
- **Cryptographic Correctness**: Malicious JWKs undermine the security of keyless account signature verification

## Impact Explanation

**Severity: High** (up to $50,000 per Aptos Bug Bounty guidelines)

While the ultimate impact could be Critical (loss of funds through keyless account compromise), the attack requires:
1. Governance approval of a malicious or vulnerable `config_url`
2. OR exploitation of open redirect vulnerabilities in trusted domains

The vulnerability enables:
- **Keyless Account Compromise**: Attackers can forge JWT signatures for keyless accounts, executing unauthorized transactions
- **Consensus Manipulation**: Malicious JWKs become part of the chain state through quorum consensus
- **Fund Theft**: Compromised keyless accounts can have their funds stolen
- **Protocol Integrity Violation**: The JWK consensus mechanism's trustworthiness is undermined

However, this falls under "Significant protocol violations" (High severity) rather than direct fund loss (Critical) due to the governance prerequisite.

## Likelihood Explanation

**Likelihood: Medium**

The attack requires either:

1. **Open Redirect Exploitation** (Medium likelihood):
   - Open redirect vulnerabilities are common in web applications
   - An attacker could propose a `config_url` like: `https://trusted-provider.com/redirect?url=https://attacker.com/.well-known/openid-configuration`
   - Governance voters may approve URLs from trusted domains without inspecting redirect behavior

2. **Domain Takeover** (Low likelihood):
   - Expired domains from legitimate OIDC providers could be re-registered
   - Already-approved config_urls would start redirecting to attacker-controlled servers

3. **Infrastructure Compromise** (Low likelihood):
   - A legitimate OIDC provider's infrastructure could be compromised
   - The attacker adds redirects without needing new governance approval

The lack of any redirect validation or HTTPS enforcement creates multiple attack vectors. While governance provides some protection, it's not a sufficient security control against redirect-based attacks.

## Recommendation

Implement strict redirect policies and URL validation:

```rust
// In crates/jwk-utils/src/lib.rs
pub async fn fetch_jwks_uri_from_openid_config(config_url: &str) -> Result<String> {
    // 1. Validate URL scheme is HTTPS
    let parsed_url = Url::parse(config_url)
        .map_err(|e| anyhow!("Invalid config_url: {}", e))?;
    
    if parsed_url.scheme() != "https" {
        return Err(anyhow!("config_url must use HTTPS scheme"));
    }
    
    // 2. Configure client with no redirects
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()?;
    
    let response = client.get(config_url).send().await?;
    
    // 3. Reject any redirect responses
    if response.status().is_redirection() {
        return Err(anyhow!(
            "config_url returned redirect status {}, redirects are not allowed",
            response.status()
        ));
    }
    
    let OpenIDConfiguration { jwks_uri, .. } = response.json().await?;
    
    // 4. Validate jwks_uri is also HTTPS and from same domain
    let jwks_url = Url::parse(&jwks_uri)?;
    if jwks_url.scheme() != "https" {
        return Err(anyhow!("jwks_uri must use HTTPS scheme"));
    }
    
    // Optional: Enforce same domain restriction
    if jwks_url.host() != parsed_url.host() {
        return Err(anyhow!(
            "jwks_uri domain must match config_url domain for security"
        ));
    }
    
    Ok(jwks_uri)
}
```

Additionally, add URL validation in the Move contract:

```move
// In aptos-move/framework/aptos-framework/sources/configs/jwk_consensus_config.move
public fun new_oidc_provider(name: String, config_url: String): OIDCProvider {
    // Validate HTTPS scheme (basic check)
    assert!(
        string::index_of(&config_url, &utf8(b"https://")) == 0,
        error::invalid_argument(EINVALID_CONFIG_URL)
    );
    OIDCProvider { name, config_url }
}
```

## Proof of Concept

```rust
// Test demonstrating redirect following vulnerability
// Place in crates/jwk-utils/tests/redirect_test.rs

use aptos_jwk_utils::{fetch_jwks_uri_from_openid_config, fetch_jwks_from_jwks_uri};
use hyper::{Body, Request, Response, Server, StatusCode};
use hyper::service::{make_service_fn, service_fn};
use std::convert::Infallible;
use std::net::SocketAddr;

#[tokio::test]
async fn test_redirect_following_vulnerability() {
    // Setup malicious redirect server
    let redirect_addr = SocketAddr::from(([127, 0, 0, 1], 8081));
    let malicious_addr = SocketAddr::from(([127, 0, 0, 1], 8082));
    
    // Server 1: Redirects to malicious server
    let redirect_svc = make_service_fn(|_| async {
        Ok::<_, Infallible>(service_fn(|_req: Request<Body>| async {
            let redirect_url = "http://127.0.0.1:8082/.well-known/openid-configuration";
            Ok::<_, Infallible>(
                Response::builder()
                    .status(StatusCode::MOVED_PERMANENTLY)
                    .header("Location", redirect_url)
                    .body(Body::empty())
                    .unwrap()
            )
        }))
    });
    
    // Server 2: Malicious JWK server
    let malicious_svc = make_service_fn(|_| async {
        Ok::<_, Infallible>(service_fn(|_req: Request<Body>| async {
            let malicious_config = r#"{"issuer": "https://evil.com", "jwks_uri": "http://127.0.0.1:8082/jwks"}"#;
            Ok::<_, Infallible>(
                Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/json")
                    .body(Body::from(malicious_config))
                    .unwrap()
            )
        }))
    });
    
    // Spawn servers
    tokio::spawn(Server::bind(&redirect_addr).serve(redirect_svc));
    tokio::spawn(Server::bind(&malicious_addr).serve(malicious_svc));
    
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    
    // Attempt to fetch - this will follow the redirect!
    let result = fetch_jwks_uri_from_openid_config("http://127.0.0.1:8081/.well-known/openid-configuration").await;
    
    // VULNERABILITY: The fetch succeeds by following redirects to malicious server
    assert!(result.is_ok(), "Redirect was followed to malicious server");
    let jwks_uri = result.unwrap();
    assert!(jwks_uri.contains("127.0.0.1:8082"), "Fetched from malicious server after redirect");
}
```

## Notes

This vulnerability represents a **defense-in-depth failure**. While governance provides one layer of protection, the system should not blindly trust HTTP behavior from potentially compromised or malicious endpoints. The lack of redirect validation creates multiple attack vectors:

1. **Open Redirect Chaining**: Attackers can chain open redirects across multiple trusted domains to obscure the final malicious destination
2. **Protocol Downgrade**: HTTPS URLs can redirect to HTTP, enabling man-in-the-middle attacks
3. **Time-of-Check-Time-of-Use**: A URL approved by governance could start redirecting after approval
4. **Geo-Based Redirects**: CDNs or load balancers might redirect different validators to different endpoints, breaking consensus determinism

The recommended fix enforces:
- HTTPS-only communication
- No redirect following (Policy::none())
- Domain validation between config_url and jwks_uri
- Explicit rejection of redirect status codes

This provides multiple layers of security against redirect-based attacks while maintaining the system's ability to fetch legitimate JWK configurations.

### Citations

**File:** crates/jwk-utils/src/lib.rs (L40-44)
```rust
pub async fn fetch_jwks_uri_from_openid_config(config_url: &str) -> Result<String> {
    let client = reqwest::Client::new();
    let OpenIDConfiguration { jwks_uri, .. } = client.get(config_url).send().await?.json().await?;
    Ok(jwks_uri)
}
```

**File:** aptos-move/framework/aptos-framework/sources/configs/jwk_consensus_config.move (L104-107)
```text
    /// Construct an `OIDCProvider` object.
    public fun new_oidc_provider(name: String, config_url: String): OIDCProvider {
        OIDCProvider { name, config_url }
    }
```

**File:** crates/aptos-jwk-consensus/src/jwk_observer.rs (L102-110)
```rust
async fn fetch_jwks(open_id_config_url: &str, my_addr: Option<AccountAddress>) -> Result<Vec<JWK>> {
    let jwks_uri = fetch_jwks_uri_from_openid_config(open_id_config_url)
        .await
        .map_err(|e| anyhow!("fetch_jwks failed with open-id config request: {e}"))?;
    let jwks = fetch_jwks_from_jwks_uri(my_addr, jwks_uri.as_str())
        .await
        .map_err(|e| anyhow!("fetch_jwks failed with jwks uri request: {e}"))?;
    Ok(jwks)
}
```

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L112-149)
```rust
fn get_jwk_for_authenticator(
    jwks: &AllProvidersJWKs,
    pk: &KeylessPublicKey,
    sig: &KeylessSignature,
) -> Result<JWK, VMStatus> {
    let jwt_header = sig
        .parse_jwt_header()
        .map_err(|_| invalid_signature!("Failed to parse JWT header"))?;

    let jwk_move_struct = jwks.get_jwk(&pk.iss_val, &jwt_header.kid).map_err(|_| {
        invalid_signature!(format!(
            "JWK for {} with KID {} was not found",
            pk.iss_val, jwt_header.kid
        ))
    })?;

    let jwk = JWK::try_from(jwk_move_struct)
        .map_err(|_| invalid_signature!("Could not unpack Any in JWK Move struct"))?;

    match &jwk {
        JWK::RSA(rsa_jwk) => {
            if rsa_jwk.alg != jwt_header.alg {
                return Err(invalid_signature!(format!(
                    "JWK alg ({}) does not match JWT header's alg ({})",
                    rsa_jwk.alg, jwt_header.alg
                )));
            }
        },
        JWK::Unsupported(jwk) => {
            return Err(invalid_signature!(format!(
                "JWK with KID {} and hex-encoded payload {} is not supported",
                jwt_header.kid,
                hex::encode(&jwk.payload)
            )))
        },
    }

    Ok(jwk)
```
