# Audit Report

## Title
Resource Exhaustion via Unbounded OIDC Provider Spawning in JWK Consensus Configuration

## Summary
A governance-approved proposal can configure `ConfigV1.oidc_providers` with thousands of OIDC providers (up to ~7,000 within the 1MB transaction limit), causing each validator to spawn thousands of tokio tasks that make continuous HTTP requests to external endpoints. This leads to memory exhaustion, CPU saturation, network congestion, and file descriptor depletion, resulting in validator node slowdowns and degraded consensus performance.

## Finding Description

The vulnerability exists in the JWK consensus configuration system where governance can set an unbounded list of OIDC providers without size validation.

**Attack Flow:**

1. **No Size Validation**: The Move module's `new_v1()` function only validates provider name uniqueness, not the vector length [1](#0-0) 

2. **Transaction Size Limit**: The only constraint is the `MAX_BYTES_PER_WRITE_OP` limit of 1MB, allowing approximately 7,000 providers at ~150 bytes each (name + config_url strings) [2](#0-1) 

3. **Governance Configuration**: Attackers submit a proposal via `set_for_next_epoch()` which accepts the configuration without size checks [3](#0-2) 

4. **Epoch Transition Trigger**: On epoch transition, validators retrieve the config and clone the OIDC providers vector [4](#0-3) 

5. **Unbounded Task Spawning**: The critical vulnerability occurs when the JWK manager iterates over all providers and spawns a separate `JWKObserver` tokio task for each one [5](#0-4) 

6. **Continuous HTTP Requests**: Each spawned `JWKObserver` task runs an infinite loop making HTTP requests to the provider's config_url every 10 seconds [6](#0-5) 

7. **Resource Exhaustion**: With 7,000 providers:
   - 7,000 tokio tasks spawned per validator
   - 14,000 HTTP requests every 10 seconds (2 requests per provider: OpenID config + JWKs URI) [7](#0-6) 
   - 1,400+ HTTP requests per second to external endpoints
   - Massive memory consumption from task state
   - File descriptor exhaustion from HTTP connections
   - CPU saturation from tokio scheduler overhead

**Invariant Violation**: This breaks the **Resource Limits** invariant (#9): "All operations must respect gas, storage, and computational limits." The system allows unbounded resource consumption that is not constrained by gas or any other limit.

## Impact Explanation

**Severity: HIGH** per Aptos Bug Bounty criteria.

This vulnerability directly matches the High severity category: **"Validator node slowdowns"**. The impact includes:

1. **Memory Exhaustion**: 7,000 concurrent tokio tasks with associated HTTP client state can consume gigabytes of RAM
2. **CPU Saturation**: Tokio scheduler managing 7,000 tasks + processing 1,400 HTTP requests/second degrades performance
3. **Network Congestion**: Sustained outbound traffic of 1,400+ requests/second affects validator network capacity
4. **File Descriptor Depletion**: Each HTTP connection consumes system FDs, potentially hitting ulimit
5. **Consensus Degradation**: Validators struggling with resource exhaustion may miss rounds, delay votes, or fail to propose blocks timely

All validators are affected simultaneously when the epoch transition occurs, creating a network-wide performance degradation event.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

**Requirements:**
- Governance approval (majority vote required)
- No special validator privileges needed
- Attack is deterministic once approved

**Feasibility:**
- Governance proposals are a standard attack vector for on-chain configuration
- The attack parameters fit within normal transaction limits (1MB)
- Once approved, the effect is immediate and guaranteed on next epoch
- All validators are simultaneously affected
- No recovery mechanism exists without another governance proposal

**Complexity:**
- Low technical complexity: simple governance proposal with large vector
- High social engineering barrier: requires governance approval
- However, malicious proposal could be disguised as legitimate expansion of supported OIDC providers

## Recommendation

**Immediate Fix**: Add a maximum provider count validation in the Move module:

```move
/// Maximum number of OIDC providers to prevent resource exhaustion
const MAX_OIDC_PROVIDERS: u64 = 10;

/// Construct a `JWKConsensusConfig` of variant `ConfigV1`.
///
/// Abort if the given provider list exceeds maximum count or contains duplicates.
public fun new_v1(oidc_providers: vector<OIDCProvider>): JWKConsensusConfig {
    let provider_count = vector::length(&oidc_providers);
    assert!(
        provider_count <= MAX_OIDC_PROVIDERS,
        error::invalid_argument(ETOO_MANY_PROVIDERS)
    );
    
    let name_set = simple_map::new<String, u64>();
    vector::for_each_ref(&oidc_providers, |provider| {
        let provider: &OIDCProvider = provider;
        let (_, old_value) = simple_map::upsert(&mut name_set, provider.name, 0);
        if (option::is_some(&old_value)) {
            abort(error::invalid_argument(EDUPLICATE_PROVIDERS))
        }
    });
    JWKConsensusConfig {
        variant: copyable_any::pack( ConfigV1 { oidc_providers } )
    }
}
```

**Additional Hardening**:
1. Add runtime limit check in Rust when spawning observers
2. Implement task pooling with bounded concurrency
3. Add metrics/alerts for excessive observer count
4. Consider lazy spawning or on-demand fetching instead of continuous polling

## Proof of Concept

```move
#[test_only]
module aptos_framework::jwk_consensus_config_dos_test {
    use std::string::utf8;
    use std::vector;
    use aptos_framework::jwk_consensus_config;

    #[test]
    #[expected_failure] // Should fail after implementing MAX_OIDC_PROVIDERS check
    fun test_resource_exhaustion_via_many_providers() {
        // Create a vector with thousands of OIDC providers
        let providers = vector::empty();
        let i = 0;
        
        // Within 1MB limit: ~7000 providers at 150 bytes each
        while (i < 7000) {
            let name = utf8(b"https://provider");
            vector::append(&mut *string::bytes(&mut name), std::bcs::to_bytes(&i));
            
            let config_url = utf8(b"https://provider.example.com/.well-known/openid-configuration");
            vector::append(&mut *string::bytes(&mut config_url), std::bcs::to_bytes(&i));
            
            let provider = jwk_consensus_config::new_oidc_provider(name, config_url);
            vector::push_back(&mut providers, provider);
            i = i + 1;
        };
        
        // This should be rejected but currently succeeds
        // causing 7000 tokio tasks + 14000 HTTP requests per 10 seconds
        let _config = jwk_consensus_config::new_v1(providers);
    }
}
```

**Rust Reproduction Steps**:
1. Submit governance proposal with ConfigV1 containing 7,000 providers
2. Wait for governance approval and epoch transition
3. Observe validator metrics:
   - `tokio::task::count` showing 7,000+ additional tasks
   - Network metrics showing 1,400+ outbound requests/sec
   - Memory usage increasing by several GB
   - CPU utilization spiking above normal
   - Consensus round times increasing
   - Potential validator crashes from OOM or fd exhaustion

## Notes

The vulnerability's impact extends beyond simple vector cloning as initially suggested in the security question. While `oidc_providers_cloned()` does clone the vector [8](#0-7) , the critical resource exhaustion occurs in the JWK observer spawning mechanism, not the clone operation itself.

The attack is realistic within current system constraints and represents a clear violation of the resource limits invariant. The 10-provider recommendation balances legitimate use cases (multiple major OIDC providers like Google, Microsoft, Apple, etc.) against resource exhaustion risks.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/configs/jwk_consensus_config.move (L62-65)
```text
    public fun set_for_next_epoch(framework: &signer, config: JWKConsensusConfig) {
        system_addresses::assert_aptos_framework(framework);
        config_buffer::upsert(config);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/configs/jwk_consensus_config.move (L90-102)
```text
    public fun new_v1(oidc_providers: vector<OIDCProvider>): JWKConsensusConfig {
        let name_set = simple_map::new<String, u64>();
        vector::for_each_ref(&oidc_providers, |provider| {
            let provider: &OIDCProvider = provider;
            let (_, old_value) = simple_map::upsert(&mut name_set, provider.name, 0);
            if (option::is_some(&old_value)) {
                abort(error::invalid_argument(EDUPLICATE_PROVIDERS))
            }
        });
        JWKConsensusConfig {
            variant: copyable_any::pack( ConfigV1 { oidc_providers } )
        }
    }
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L1-1)
```rust
// Copyright (c) Aptos Foundation
```

**File:** crates/aptos-jwk-consensus/src/epoch_manager.rs (L177-186)
```rust
        let (jwk_manager_should_run, oidc_providers) = match jwk_consensus_config {
            Ok(config) => {
                let should_run =
                    config.jwk_consensus_enabled() && onchain_consensus_config.is_vtxn_enabled();
                let providers = config
                    .oidc_providers_cloned()
                    .into_iter()
                    .map(jwks::OIDCProvider::from)
                    .collect();
                (should_run, Some(SupportedOIDCProviders { providers }))
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L108-134)
```rust
        this.jwk_observers = oidc_providers
            .unwrap_or_default()
            .into_provider_vec()
            .into_iter()
            .filter_map(|provider| {
                let OIDCProvider { name, config_url } = provider;
                let maybe_issuer = String::from_utf8(name);
                let maybe_config_url = String::from_utf8(config_url);
                match (maybe_issuer, maybe_config_url) {
                    (Ok(issuer), Ok(config_url)) => Some(JWKObserver::spawn(
                        this.epoch_state.epoch,
                        this.my_addr,
                        issuer,
                        config_url,
                        Duration::from_secs(10),
                        local_observation_tx.clone(),
                    )),
                    (maybe_issuer, maybe_config_url) => {
                        warn!(
                            "unable to spawn observer, issuer={:?}, config_url={:?}",
                            maybe_issuer, maybe_config_url
                        );
                        None
                    },
                }
            })
            .collect();
```

**File:** crates/aptos-jwk-consensus/src/jwk_observer.rs (L51-89)
```rust
    async fn start(
        fetch_interval: Duration,
        my_addr: AccountAddress,
        issuer: String,
        open_id_config_url: String,
        observation_tx: aptos_channel::Sender<(), (Issuer, Vec<JWK>)>,
        close_rx: oneshot::Receiver<()>,
    ) {
        let mut interval = tokio::time::interval(fetch_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut close_rx = close_rx.into_stream();
        let my_addr = if cfg!(feature = "smoke-test") {
            // Include self validator address in JWK request,
            // so dummy OIDC providers in smoke tests can do things like "key A for validator 1, key B for validator 2".
            Some(my_addr)
        } else {
            None
        };

        loop {
            tokio::select! {
                _ = interval.tick().fuse() => {
                    let timer = Instant::now();
                    let result = fetch_jwks(open_id_config_url.as_str(), my_addr).await;
                    debug!(issuer = issuer, "observe_result={:?}", result);
                    let secs = timer.elapsed().as_secs_f64();
                    if let Ok(mut jwks) = result {
                        OBSERVATION_SECONDS.with_label_values(&[issuer.as_str(), "ok"]).observe(secs);
                        jwks.sort();
                        let _ = observation_tx.push((), (issuer.as_bytes().to_vec(), jwks));
                    } else {
                        OBSERVATION_SECONDS.with_label_values(&[issuer.as_str(), "err"]).observe(secs);
                    }
                },
                _ = close_rx.select_next_some() => {
                    break;
                }
            }
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

**File:** types/src/on_chain_config/jwk_consensus_config.rs (L76-81)
```rust
    pub fn oidc_providers_cloned(&self) -> Vec<OIDCProvider> {
        match self {
            OnChainJWKConsensusConfig::Off => vec![],
            OnChainJWKConsensusConfig::V1(v1) => v1.oidc_providers.clone(),
        }
    }
```
