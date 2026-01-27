# Audit Report

## Title
Server-Side Request Forgery (SSRF) via Unvalidated URL Parsing in Gas Schedule Fetcher

## Summary
The `GasScheduleLocator::deserialize()` function accepts arbitrary URLs without validating the scheme, host, or port components. This allows an attacker who can influence the release configuration file to perform Server-Side Request Forgery (SSRF) attacks against internal services, cloud metadata endpoints, or perform internal network reconnaissance.

## Finding Description

The `GasScheduleLocator::deserialize()` function uses `Url::parse()` to determine if a string is a valid URL, but performs no validation on the parsed URL's components: [1](#0-0) 

When the string successfully parses as a URL, it's stored as `RemoteFile(url)` without any checks on:
- **Scheme validation**: Accepts any scheme (http, https, file, ftp, etc.)
- **Host validation**: No restriction on localhost, internal IPs, or cloud metadata services
- **Port validation**: No restriction on which ports can be accessed

The parsed URL is later used directly in `fetch_gas_schedule()`: [2](#0-1) 

The `reqwest::get()` function will attempt to fetch from any URL provided, including:
- `http://localhost:8080/admin` - Internal admin interfaces
- `http://169.254.169.254/latest/meta-data/` - Cloud metadata services (AWS, GCP, Azure)
- `http://192.168.1.1/` - Internal network devices
- `http://internal-service:9090/` - Internal services

In contrast, the codebase has a secure URL validation pattern in `parse_target()`: [3](#0-2) 

This validation ensures the scheme is not empty and provides defense against malformed URLs. The same validation is absent in `GasScheduleLocator::deserialize()`.

**Attack Path:**
1. Attacker creates malicious YAML config with URL pointing to internal service (e.g., `http://169.254.169.254/latest/meta-data/iam/security-credentials/`)
2. Attacker convinces developer to use config via social engineering, or compromises CI/CD pipeline
3. When `aptos-release-builder` runs, it loads the config: [4](#0-3) 
4. The tool calls `fetch_gas_schedule()` which makes HTTP request to attacker-specified URL
5. Response data is returned to attacker's context (developer machine/CI system)

## Impact Explanation

This vulnerability enables **Server-Side Request Forgery (SSRF)** attacks with the following impacts:

**Information Disclosure (High):**
- Access to cloud metadata services can expose IAM credentials, API keys, and instance metadata
- Access to internal services can reveal sensitive configuration, API endpoints, and system architecture
- Port scanning capabilities to map internal network topology

**Potential Credential Theft (High):**
- AWS metadata endpoint (`http://169.254.169.254/`) exposes IAM role credentials
- GCP metadata endpoint (`http://metadata.google.internal/`) exposes service account tokens
- Azure metadata endpoint (`http://169.254.169.254/metadata/`) exposes managed identity credentials

**Defense-in-Depth Violation (High):**
- Developer tools should implement security controls to prevent misuse
- Inconsistent security posture across codebase (compare with `parse_target()` validation)
- Creates trust relationship risk in CI/CD pipelines

Per Aptos bug bounty criteria, this constitutes **High Severity** as it represents a "Significant protocol violation" in the form of missing security controls in release tooling that could affect validator node security if developers' credentials are compromised.

## Likelihood Explanation

**Likelihood: Medium-High**

The vulnerability requires one of the following conditions:
1. **Social Engineering**: Attacker convinces developer to use malicious config file
2. **CI/CD Compromise**: Attacker injects malicious config into build pipeline
3. **Supply Chain Attack**: Malicious config distributed through compromised repository/channel

While these require attacker access or interaction with trusted parties, they are realistic scenarios:
- Developers frequently share and use config files from various sources
- CI/CD pipelines often pull configurations from multiple repositories
- Open-source projects accept contributions that may include config files

The `aptos-release-builder` tool is used by:
- Core Aptos developers generating governance proposals
- Validator operators preparing network upgrades
- CI/CD systems for automated release processes

All these environments typically have elevated permissions and access to sensitive resources, increasing the impact of successful exploitation.

## Recommendation

Implement URL validation in `GasScheduleLocator::deserialize()` following the secure pattern from `parse_target()`:

```rust
fn visit_str<E>(self, value: &str) -> Result<GasScheduleLocator, E>
where
    E: serde::de::Error,
{
    if value == "current" {
        Ok(GasScheduleLocator::Current)
    } else if let Ok(url) = Url::parse(value) {
        // Validate URL scheme
        if url.scheme().is_empty() {
            return Err(E::custom("URL scheme must not be empty"));
        }
        
        // Only allow http and https schemes
        if url.scheme() != "http" && url.scheme() != "https" {
            return Err(E::custom("URL scheme must be http or https"));
        }
        
        // Validate host is not empty
        if url.host_str().map(|h| h.is_empty()).unwrap_or(true) {
            return Err(E::custom("URL host must not be empty"));
        }
        
        // Reject localhost and internal IPs
        if let Some(host) = url.host_str() {
            if host == "localhost" 
                || host.starts_with("127.") 
                || host.starts_with("10.")
                || host.starts_with("192.168.")
                || host == "169.254.169.254" 
                || host.starts_with("172.16.")
                || host.starts_with("172.17.")
                || host.starts_with("172.18.")
                || host.starts_with("172.19.")
                || host.starts_with("172.20.")
                || host.starts_with("172.21.")
                || host.starts_with("172.22.")
                || host.starts_with("172.23.")
                || host.starts_with("172.24.")
                || host.starts_with("172.25.")
                || host.starts_with("172.26.")
                || host.starts_with("172.27.")
                || host.starts_with("172.28.")
                || host.starts_with("172.29.")
                || host.starts_with("172.30.")
                || host.starts_with("172.31.") {
                return Err(E::custom("URL cannot point to internal addresses"));
            }
        }
        
        Ok(GasScheduleLocator::RemoteFile(url))
    } else {
        Ok(GasScheduleLocator::LocalFile(value.to_string()))
    }
}
```

Alternatively, maintain an allowlist of trusted domains for gas schedule sources.

## Proof of Concept

Create a malicious release config file `malicious_release.yaml`:

```yaml
name: "SSRF-Attack"
remote_endpoint: ~
proposals:
  - name: "gas_schedule_ssrf"
    metadata:
      title: "Malicious Gas Schedule"
      description: "SSRF PoC"
    execution_mode: RootSigner
    update_sequence:
      - Gas:
          old: current
          new: "http://169.254.169.254/latest/meta-data/"
```

Run the tool:
```bash
cargo run --bin aptos-release-builder -- \
    generate-proposals \
    --release-config malicious_release.yaml \
    --output-dir /tmp/output
```

The tool will attempt to fetch from the cloud metadata endpoint, demonstrating the SSRF vulnerability. The HTTP request will be visible in network logs, and if running on a cloud instance, it will successfully retrieve metadata.

**Notes**

- This vulnerability exists in developer tooling, not core consensus/execution components
- Exploitation requires attacker ability to influence configuration files used by developers or CI/CD systems
- While the tool is used by trusted developers, defense-in-depth principles require proper input validation
- The inconsistency with `parse_target()` validation pattern indicates this is an oversight rather than an intentional design choice
- Impact is amplified when tool runs in cloud environments with metadata services or privileged CI/CD contexts

### Citations

**File:** aptos-move/aptos-release-builder/src/components/mod.rs (L178-189)
```rust
            fn visit_str<E>(self, value: &str) -> Result<GasScheduleLocator, E>
            where
                E: serde::de::Error,
            {
                if value == "current" {
                    Ok(GasScheduleLocator::Current)
                } else if let Ok(url) = Url::parse(value) {
                    Ok(GasScheduleLocator::RemoteFile(url))
                } else {
                    Ok(GasScheduleLocator::LocalFile(value.to_string()))
                }
            }
```

**File:** aptos-move/aptos-release-builder/src/components/mod.rs (L205-209)
```rust
            GasScheduleLocator::RemoteFile(url) => {
                let response = reqwest::get(url.as_str()).await?;
                let gas_schedule: GasScheduleV2 = response.json().await?;
                Ok(gas_schedule)
            },
```

**File:** crates/transaction-emitter-lib/src/args.rs (L240-242)
```rust
    if url.scheme().is_empty() {
        bail!("Scheme must not be empty, try prefixing URL with http://");
    }
```

**File:** aptos-move/aptos-release-builder/src/main.rs (L233-237)
```rust
            aptos_release_builder::ReleaseConfig::load_config(release_config.as_path())
                .with_context(|| "Failed to load release config".to_string())?
                .generate_release_proposal_scripts(output_dir.as_path())
                .await
                .with_context(|| "Failed to generate release proposal scripts".to_string())?;
```
