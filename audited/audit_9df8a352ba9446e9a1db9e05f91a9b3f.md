# Audit Report

## Title
Local Testnet Faucet Network Interface Exposure Through Misconfiguration

## Summary
The local testnet faucet's `bind_to` parameter and related configuration options can be misconfigured to expose the faucet to external networks (0.0.0.0), allowing unrestricted access to mint unlimited test tokens without authentication or rate limiting.

## Finding Description

The faucet binding behavior is controlled through multiple code paths with insufficient restrictions:

**1. Primary Entry Point - `aptos node run-local-testnet`:** [1](#0-0) 

The `bind_to` address can be explicitly set to 0.0.0.0 via the `--bind-to` flag, or automatically defaults to 0.0.0.0 when running inside a container. This address is passed to `FaucetManager::new()`: [2](#0-1) 

**2. Faucet Configuration:** [3](#0-2) 

The `bind_to` parameter is converted to a string and passed to `RunConfig::build_for_cli()`, which creates a faucet with **no security controls**: [4](#0-3) 

**3. No Amount Restrictions:** [5](#0-4) 

The transaction submission configuration has no maximum amount limits, allowing unlimited minting per request.

**4. Alternative Exposure via `run-simple`:** [6](#0-5) 

The `run-simple` command defaults to binding on 0.0.0.0, exposing any faucet started with this command to all network interfaces by default.

**5. Network Binding:** [7](#0-6) 

The server binds directly to the configured listen_address without additional network interface validation.

## Impact Explanation

While this affects a **development tool** (local testnet faucet) rather than production blockchain infrastructure, the misconfiguration poses security risks in the following scenarios:

1. **Development Environment Exposure**: Developers accidentally running `--bind-to 0.0.0.0` expose their local testnet faucet to their entire network
2. **Container Deployments**: Automatic 0.0.0.0 binding in containers may expose faucets unintentionally
3. **Shared Networks**: In corporate or shared development environments, exposed faucets allow any network peer to drain test accounts

However, this does **NOT** meet the Aptos bug bounty severity criteria because:
- It only affects **test/development environments**, not production networks
- No real funds at risk (only test tokens)
- No impact on consensus, validator operations, or mainnet
- Not part of the core blockchain protocol

This is better classified as a **security hardening recommendation** rather than a critical vulnerability.

## Likelihood Explanation

**Moderate likelihood** of misconfiguration:
- Default behavior is safe (127.0.0.1) when not in containers
- Requires explicit `--bind-to 0.0.0.0` flag or container deployment
- `run-simple` command defaults to 0.0.0.0 (higher risk)

However, **low security impact** because:
- Limited to development/testing contexts
- No real monetary value at risk
- Documented as a local testing tool

## Recommendation

While this is a development tool issue, security hardening is recommended:

1. **Add explicit warnings** when binding to 0.0.0.0:
```rust
if bind_to == Ipv4Addr::new(0, 0, 0, 0) {
    eprintln!("WARNING: Faucet is binding to 0.0.0.0 (all network interfaces).");
    eprintln!("This exposes the faucet to your entire network without authentication.");
    eprintln!("Only use this in trusted environments or containers.");
}
```

2. **Change `run-simple` default** to 127.0.0.1:
```rust
#[clap(long, default_value = "127.0.0.1")]
pub listen_address: String,
```

3. **Add amount limits** even for local testing:
```rust
Some(1_000_000_000_000), // maximum_amount: 10,000 APT
```

4. **Documentation**: Clearly document the security implications of network binding options.

## Proof of Concept

```bash
# Start local testnet with exposed faucet
aptos node run-local-testnet --bind-to 0.0.0.0 --force-restart --assume-yes

# From any machine on the network, drain unlimited tokens
curl -X POST "http://<victim-ip>:8081/mint?amount=999999999999999&address=0xATTACKER_ADDRESS"

# Repeat without limits
for i in {1..1000}; do
    curl -X POST "http://<victim-ip>:8081/mint?amount=999999999999999&address=0xATTACKER_ADDRESS"
done
```

## Notes

**This issue does NOT qualify as a valid vulnerability** under the strict Aptos bug bounty criteria because:

1. **Scope Limitation**: The local testnet faucet is a development utility, not a production blockchain component
2. **No Real Funds**: Only affects test tokens with no monetary value  
3. **No Protocol Impact**: Does not affect consensus, state management, or core blockchain operations
4. **Documented Purpose**: Explicitly designed and documented as a local testing tool

The finding represents a **security best practice concern** for development environments rather than an exploitable vulnerability in the Aptos blockchain protocol itself. The impact is limited to test token drainage in development contexts, which does not meet the Critical, High, or Medium severity thresholds defined in the bug bounty program.

**Classification: Security Hardening Recommendation (Development Tooling)**

### Citations

**File:** crates/aptos/src/node/local_testnet/mod.rs (L274-284)
```rust
        let bind_to = match self.bind_to {
            Some(bind_to) => bind_to,
            None => {
                if running_inside_container {
                    Ipv4Addr::new(0, 0, 0, 0)
                } else {
                    Ipv4Addr::new(127, 0, 0, 1)
                }
            },
        };
        info!("Binding host services to {}", bind_to);
```

**File:** crates/aptos/src/node/local_testnet/mod.rs (L295-303)
```rust
            let faucet_manager = FaucetManager::new(
                &self,
                node_health_checkers.clone(),
                bind_to,
                test_dir.clone(),
                node_manager.get_node_api_url(),
            )
            .context("Failed to build faucet service manager")?;
            managers.push(Box::new(faucet_manager));
```

**File:** crates/aptos/src/node/local_testnet/faucet.rs (L48-66)
```rust
    pub fn new(
        args: &RunLocalnet,
        prerequisite_health_checkers: HashSet<HealthChecker>,
        bind_to: Ipv4Addr,
        test_dir: PathBuf,
        node_api_url: Url,
    ) -> Result<Self> {
        Ok(Self {
            config: RunConfig::build_for_cli(
                node_api_url.clone(),
                bind_to.to_string(),
                args.faucet_args.faucet_port,
                FunderKeyEnum::KeyFile(test_dir.join("mint.key")),
                args.faucet_args.do_not_delegate,
                None,
            ),
            prerequisite_health_checkers,
        })
    }
```

**File:** crates/aptos-faucet/core/src/server/run.rs (L195-199)
```rust
        let listener = TcpListener::bind((
            self.server_config.listen_address.clone(),
            self.server_config.listen_port,
        ))
        .await?;
```

**File:** crates/aptos-faucet/core/src/server/run.rs (L276-277)
```rust
            bypasser_configs: vec![],
            checker_configs: vec![],
```

**File:** crates/aptos-faucet/core/src/server/run.rs (L286-287)
```rust
                    None,    // maximum_amount
                    None,    // maximum_amount_with_bypass
```

**File:** crates/aptos-faucet/core/src/server/run.rs (L359-360)
```rust
    #[clap(long, default_value = "0.0.0.0")]
    pub listen_address: String,
```
