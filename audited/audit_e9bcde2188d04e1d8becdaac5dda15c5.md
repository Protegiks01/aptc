# Audit Report

## Title
JWK Observer Lifecycle Race Condition Enables Governance Bypass

## Summary
The JWK consensus system maintains a fixed set of observers per epoch that cannot be modified during runtime. When governance removes an issuer mid-epoch via `remove_issuer_from_observed_jwks()`, the corresponding observer continues running and immediately recreates the removed state, completely bypassing the governance action until the next epoch boundary.

## Finding Description

The JWK consensus manager maintains two critical data structures with mismatched lifecycles:

1. **`jwk_observers: Vec<JWKObserver>`** - Spawned once per epoch, cannot be modified
2. **`states_by_issuer: HashMap<Issuer, PerProviderState>`** - Can change mid-epoch via on-chain events [1](#0-0) 

Observers are created from on-chain configuration at epoch start: [2](#0-1) 

They run independently in separate tokio tasks, periodically fetching JWKs: [3](#0-2) 

When governance calls `remove_issuer_from_observed_jwks()` to remove a compromised OIDC provider: [4](#0-3) 

This emits an `ObservedJWKsUpdated` event that triggers `reset_with_on_chain_state()`: [5](#0-4) 

The state reset removes the issuer from `states_by_issuer`: [6](#0-5) 

**The Race Condition:** The observer for the removed issuer continues running. When it sends a new observation, `process_new_observation()` recreates the state using `.or_default()`: [7](#0-6) 

The default state has `on_chain: None`, causing version calculation to return 0: [8](#0-7) 

A new observation with version 1 is created, reaches quorum, and passes validator transaction validation: [9](#0-8) 

The validation treats it as a new issuer (version 0 → 1), allowing the removed issuer to be immediately re-added to on-chain state, completely bypassing governance's removal action.

## Impact Explanation

This vulnerability breaks the **Governance Integrity** invariant. It constitutes a **Medium to High severity** issue:

**Medium Severity Factors:**
- Governance decisions can be bypassed until next epoch
- Security incident response is delayed (cannot immediately remove compromised OIDC providers)
- Resource waste as validators continue processing unwanted issuers

**Potential High Severity:**
- If a compromised OIDC provider is discovered, governance cannot immediately stop its JWKs from being used
- The system continues accepting authentication tokens from the compromised provider
- Could lead to unauthorized access if the provider's keys are compromised

The issue meets **Medium Severity** criteria per the bug bounty program: "State inconsistencies requiring intervention" and governance bypass requiring epoch-level recovery.

## Likelihood Explanation

**Likelihood: High**

This occurs automatically whenever governance attempts to remove an issuer mid-epoch:
- No special attacker actions required beyond normal governance
- The race condition is deterministic: observers always continue running
- Affects all validators simultaneously
- Reproducible with standard governance operations

The issue manifests during legitimate operational scenarios:
- Emergency removal of compromised OIDC providers
- Decommissioning deprecated authentication providers
- Security incident response

## Recommendation

**Solution 1: Dynamic Observer Management**

Add observer lifecycle management to `IssuerLevelConsensusManager`:

```rust
// In jwk_manager/mod.rs
pub fn update_observers(&mut self, new_providers: Vec<OIDCProvider>) {
    // Stop observers for removed issuers
    let new_issuer_set: HashSet<Issuer> = new_providers.iter()
        .map(|p| p.name.clone()).collect();
    
    let mut observers_to_keep = Vec::new();
    let mut observers_to_stop = Vec::new();
    
    for observer in std::mem::take(&mut self.jwk_observers) {
        if new_issuer_set.contains(&observer.issuer()) {
            observers_to_keep.push(observer);
        } else {
            observers_to_stop.push(observer);
        }
    }
    
    // Shutdown removed observers
    tokio::spawn(async move {
        join_all(observers_to_stop.into_iter()
            .map(JWKObserver::shutdown)).await;
    });
    
    // Start new observers
    for provider in new_providers {
        if !observers_to_keep.iter()
            .any(|o| o.issuer() == provider.name) {
            observers_to_keep.push(JWKObserver::spawn(/* ... */));
        }
    }
    
    self.jwk_observers = observers_to_keep;
}
```

Call this method in `reset_with_on_chain_state()` when issuer changes are detected.

**Solution 2: Observer Validation**

Prevent state recreation for issuers not in the supported list:

```rust
pub fn process_new_observation(
    &mut self,
    issuer: Issuer,
    jwks: Vec<JWKMoveStruct>,
) -> Result<()> {
    // Check if issuer is in supported list before processing
    if !self.is_supported_issuer(&issuer) {
        debug!("Ignoring observation for unsupported issuer: {:?}", issuer);
        return Ok(());
    }
    
    let state = self.states_by_issuer.entry(issuer.clone()).or_default();
    // ... rest of processing
}
```

**Solution 3: Epoch-Only Changes (Recommended)**

Document and enforce that issuer list changes only take effect at epoch boundaries, ensuring observers are always synchronized with state. Update governance documentation to reflect this constraint.

## Proof of Concept

```rust
#[tokio::test]
async fn test_observer_governance_bypass() {
    // Setup: Create JWK manager with 2 issuers
    let mut manager = create_test_manager(vec![
        issuer("https://provider-a.com"),
        issuer("https://provider-b.com"),
    ]).await;
    
    // Initial state: both issuers have observers running
    assert_eq!(manager.jwk_observers.len(), 2);
    assert!(manager.states_by_issuer.contains_key(b"https://provider-a.com"));
    assert!(manager.states_by_issuer.contains_key(b"https://provider-b.com"));
    
    // Simulate governance removing provider-b
    let new_on_chain_state = AllProvidersJWKs {
        entries: vec![
            ProviderJWKs {
                issuer: b"https://provider-a.com".to_vec(),
                version: 1,
                jwks: vec![],
            }
            // provider-b is removed
        ]
    };
    
    manager.reset_with_on_chain_state(new_on_chain_state).unwrap();
    
    // After reset: provider-b state is removed
    assert!(!manager.states_by_issuer.contains_key(b"https://provider-b.com"));
    
    // But observer for provider-b still exists!
    assert_eq!(manager.jwk_observers.len(), 2);
    
    // Simulate observer sending new observation
    let new_jwks = vec![create_test_jwk("key1")];
    manager.process_new_observation(
        b"https://provider-b.com".to_vec(),
        new_jwks.clone()
    ).unwrap();
    
    // BUG: State for provider-b is recreated!
    assert!(manager.states_by_issuer.contains_key(b"https://provider-b.com"));
    
    // Consensus starts for removed issuer
    let state = manager.states_by_issuer.get(b"https://provider-b.com").unwrap();
    assert!(matches!(state.consensus_state, ConsensusState::InProgress { .. }));
    
    // This bypasses governance's removal decision
}
```

## Notes

This vulnerability demonstrates a fundamental design issue where observer lifecycle management is decoupled from consensus state management. The system correctly implements epoch-based resets, but mid-epoch state changes through governance actions create unexpected race conditions.

The issue is particularly concerning for security incident response, where immediate removal of compromised OIDC providers is critical. The current implementation delays such removals until the next epoch boundary, potentially leaving the system vulnerable during that window.

The root cause is the immutability of the `jwk_observers` vector after epoch initialization, combined with the dynamic nature of on-chain state changes triggered by governance actions.

### Citations

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L61-61)
```rust
    jwk_observers: Vec<JWKObserver>,
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

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L140-143)
```rust
                jwk_updated = jwk_updated_rx.select_next_some() => {
                    let ObservedJWKsUpdated { jwks, .. } = jwk_updated;
                    this.reset_with_on_chain_state(jwks)
                },
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L194-195)
```rust
        let state = self.states_by_issuer.entry(issuer.clone()).or_default();
        state.observed = Some(jwks.clone());
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L252-253)
```rust
        self.states_by_issuer
            .retain(|issuer, _| onchain_issuer_set.contains(issuer));
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L377-381)
```rust
    pub fn on_chain_version(&self) -> u64 {
        self.on_chain
            .as_ref()
            .map_or(0, |provider_jwks| provider_jwks.version)
    }
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

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L510-520)
```text
    public fun remove_issuer_from_observed_jwks(fx: &signer, issuer: vector<u8>): Option<ProviderJWKs> acquires ObservedJWKs, PatchedJWKs, Patches {
        system_addresses::assert_aptos_framework(fx);
        let observed_jwks = borrow_global_mut<ObservedJWKs>(@aptos_framework);
        let old_value = remove_issuer(&mut observed_jwks.jwks, issuer);

        let epoch = reconfiguration::current_epoch();
        emit(ObservedJWKsUpdated { epoch, jwks: observed_jwks.jwks });
        regenerate_patched_jwks();

        old_value
    }
```

**File:** aptos-move/aptos-vm/src/validator_txns/jwk.rs (L117-130)
```rust
        let on_chain = jwks_by_issuer
            .entry(issuer.clone())
            .or_insert_with(|| ProviderJWKs::new(issuer));
        let verifier = ValidatorVerifier::from(&validator_set);

        let QuorumCertifiedUpdate {
            update: observed,
            multi_sig,
        } = update;

        // Check version.
        if on_chain.version + 1 != observed.version {
            return Err(Expected(IncorrectVersion));
        }
```
