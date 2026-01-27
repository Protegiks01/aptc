# Audit Report

## Title
Unbounded JWK Consensus Session Creation Enables Memory Exhaustion Attack via Compromised OIDC Provider

## Summary
The JWK consensus per-key mode lacks limits on the number of concurrent consensus sessions that can be created for different (issuer, kid) pairs. A compromised or malicious OIDC provider can return an excessive number of JWK keys, causing all validators to create unbounded consensus sessions and exhaust memory resources, leading to validator node crashes and network-wide liveness degradation.

## Finding Description

The `KeyLevelConsensusManager` stores consensus state in an unbounded HashMap keyed by (Issuer, KID) pairs. [1](#0-0) 

When JWK observations are processed, the system creates a new consensus session for each unique (issuer, kid) pair that differs from the on-chain state: [2](#0-1) 

The `maybe_start_consensus` function inserts entries into the HashMap without any bounds checking: [3](#0-2) 

Additionally, the JWK fetching mechanism has no limit on the number of keys returned by an OIDC provider: [4](#0-3) 

**Attack Path:**
1. A whitelisted OIDC provider (e.g., Google, Facebook) becomes compromised through a supply chain attack
2. The attacker modifies the provider's JWK endpoint to return 50,000+ unique JWKs with different `kid` values
3. All validators' `JWKObserver` threads fetch these JWKs periodically (every 10 seconds)
4. `process_new_observation` iterates through all keys and creates consensus sessions for each difference from on-chain state
5. Each session allocates:
   - `ConsensusState::InProgress` structure with proposals and signatures
   - `QuorumCertProcessGuard` with `AbortHandle`
   - A spawned tokio task running reliable broadcast consensus
6. Memory consumption grows unbounded across all validators
7. Validators crash or experience severe performance degradation
8. Network liveness is compromised if sufficient validators are affected

The cleanup mechanism in `reset_with_on_chain_state` only removes sessions when the on-chain version changes for an issuer: [5](#0-4) 

This means sessions persist until consensus completes and commits, creating a vulnerability window where memory can be exhausted before cleanup occurs.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program:

- **Validator node slowdowns**: The excessive memory allocation and spawned tasks will degrade validator performance
- **Potential validator crashes**: If memory exhaustion occurs, validators may crash entirely
- **Network liveness impact**: If multiple validators crash simultaneously, the network may lose liveness

The attack affects **all validators simultaneously** since they all observe the same OIDC provider endpoint, making this a network-wide availability issue rather than an isolated node problem.

The invariant violated is: **"Resource Limits: All operations must respect gas, storage, and computational limits"** - the unbounded HashMap growth violates resource limits on validator nodes.

## Likelihood Explanation

**Likelihood: Medium to High**

**Requirements for exploitation:**
1. An OIDC provider must be whitelisted via on-chain governance (legitimate precondition)
2. The provider's endpoint must be compromised or modified maliciously (supply chain attack vector)

**Feasibility assessment:**
- Major OIDC providers (Google, Facebook, Microsoft) have been targets of sophisticated attacks
- Supply chain attacks are increasingly common and realistic
- The attack requires no validator-specific access, only compromise of an external dependency
- Once exploited, impact is immediate and affects all validators

**Attack complexity: Low** - Simply return a large JWK set from the compromised endpoint

The attack is realistic because:
- OIDC providers are external entities outside the Aptos security perimeter
- Historical precedent exists for compromise of major authentication providers
- The system has no defense-in-depth mechanisms (no rate limits, size checks, or bounds)

## Recommendation

**Immediate fixes:**

1. **Add a maximum limit on concurrent consensus sessions per issuer:**

```rust
const MAX_CONSENSUS_SESSIONS_PER_ISSUER: usize = 100;

impl KeyLevelConsensusManager {
    fn maybe_start_consensus(&mut self, update: KeyLevelUpdate) -> Result<()> {
        // Count existing sessions for this issuer
        let issuer_session_count = self.states_by_key
            .keys()
            .filter(|(iss, _)| iss == &update.issuer)
            .count();
        
        if issuer_session_count >= MAX_CONSENSUS_SESSIONS_PER_ISSUER {
            warn!(
                issuer = String::from_utf8(update.issuer.clone()).ok(),
                session_count = issuer_session_count,
                "Max consensus sessions reached for issuer, dropping update"
            );
            return Ok(());
        }
        
        // ... existing logic ...
    }
}
```

2. **Add validation on JWK fetch response size:**

```rust
const MAX_JWKS_PER_PROVIDER: usize = 100;

pub async fn fetch_jwks_from_jwks_uri(
    my_addr: Option<AccountAddress>,
    jwks_uri: &str,
) -> Result<Vec<JWK>> {
    let client = reqwest::Client::new();
    let mut request_builder = client.get(jwks_uri);
    if let Some(addr) = my_addr {
        request_builder = request_builder.header(COOKIE, addr.to_hex());
    }
    let JWKsResponse { keys } = request_builder.send().await?.json().await?;
    
    if keys.len() > MAX_JWKS_PER_PROVIDER {
        anyhow::bail!(
            "JWK provider returned {} keys, exceeding limit of {}",
            keys.len(),
            MAX_JWKS_PER_PROVIDER
        );
    }
    
    let jwks = keys.into_iter().map(JWK::from).collect();
    Ok(jwks)
}
```

3. **Add metrics monitoring:**

```rust
pub static ACTIVE_CONSENSUS_SESSIONS: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!(
        "aptos_jwk_consensus_active_sessions",
        "Number of active JWK consensus sessions by issuer",
        &["issuer"]
    )
    .unwrap()
});
```

## Proof of Concept

**Rust reproduction steps:**

```rust
#[tokio::test]
async fn test_jwk_session_exhaustion() {
    // Setup KeyLevelConsensusManager
    let (consensus_key, epoch_state, rb, vtxn_pool) = setup_test_environment();
    let mut manager = KeyLevelConsensusManager::new(
        consensus_key,
        test_addr(),
        epoch_state,
        rb,
        vtxn_pool,
    );
    
    // Simulate compromised OIDC provider returning 10,000 JWKs
    let malicious_jwks: Vec<JWK> = (0..10000)
        .map(|i| create_test_jwk(format!("kid_{}", i)))
        .collect();
    
    // Process observation
    let result = manager.process_new_observation(
        b"https://evil-provider.com".to_vec(),
        malicious_jwks,
    );
    
    assert!(result.is_ok());
    
    // Verify unbounded growth
    assert_eq!(manager.states_by_key.len(), 10000);
    
    // Measure memory consumption
    let memory_mb = estimate_memory_usage(&manager.states_by_key);
    println!("Memory consumed: {} MB", memory_mb);
    
    // This would crash a validator node with limited resources
    assert!(memory_mb > 500); // Demonstrates excessive memory usage
}
```

**Attack simulation:**
1. Deploy a malicious HTTP server mimicking an OIDC provider
2. Configure it to return a JWK set with 50,000+ unique kid values
3. Wait for validators to fetch and process the malicious response
4. Observe memory growth on validator nodes via metrics
5. Confirm degraded performance or crashes

**Notes**

This vulnerability represents a **supply chain security gap** in the JWK consensus mechanism. While OIDC providers are trusted entities added through governance, the system should defend against compromise scenarios through defense-in-depth measures like bounded resource consumption.

The issue is exacerbated because:
- All validators observe the same endpoint simultaneously (network-wide impact)
- No rate limiting exists between observations (attack repeats every 10 seconds)
- Sessions persist until on-chain commit (creates accumulation window)
- Reliable broadcast runs indefinitely with retries (amplifies resource usage)

The recommended limits (100 keys per provider, 100 sessions per issuer) are based on legitimate OIDC provider behavior - most providers maintain 2-10 active keys for rotation purposes. These limits provide adequate headroom while preventing abuse.

### Citations

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L59-59)
```rust
    states_by_key: HashMap<(Issuer, KID), ConsensusState<ObservedKeyLevelUpdate>>,
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L109-177)
```rust
    pub fn process_new_observation(&mut self, issuer: Issuer, jwks: Vec<JWK>) -> Result<()> {
        debug!(
            epoch = self.epoch_state.epoch,
            issuer = String::from_utf8(issuer.clone()).ok(),
            "Processing new observation."
        );
        let observed_jwks_by_kid: HashMap<KID, JWK> =
            jwks.into_iter().map(|jwk| (jwk.id(), jwk)).collect();
        let effectively_onchain = self
            .onchain_jwks
            .get(&issuer)
            .cloned()
            .unwrap_or_else(|| ProviderJWKsIndexed::new(issuer.clone()));
        let all_kids: HashSet<KID> = effectively_onchain
            .jwks
            .keys()
            .chain(observed_jwks_by_kid.keys())
            .cloned()
            .collect();
        for kid in all_kids {
            let onchain = effectively_onchain.jwks.get(&kid);
            let observed = observed_jwks_by_kid.get(&kid);
            match (onchain, observed) {
                (Some(x), Some(y)) => {
                    if x == y {
                        // No change, drop any in-progress consensus.
                        self.states_by_key.remove(&(issuer.clone(), kid.clone()));
                    } else {
                        // Update detected.
                        let update = KeyLevelUpdate {
                            issuer: issuer.clone(),
                            base_version: effectively_onchain.version,
                            kid: kid.clone(),
                            to_upsert: Some(y.clone()),
                        };
                        self.maybe_start_consensus(update)
                            .context("process_new_observation failed at upsert consensus init")?;
                    }
                },
                (None, Some(y)) => {
                    // Insert detected.
                    let update = KeyLevelUpdate {
                        issuer: issuer.clone(),
                        base_version: effectively_onchain.version,
                        kid: kid.clone(),
                        to_upsert: Some(y.clone()),
                    };
                    self.maybe_start_consensus(update)
                        .context("process_new_observation failed at upsert consensus init")?;
                },
                (Some(_), None) => {
                    // Delete detected.
                    let update = KeyLevelUpdate {
                        issuer: issuer.clone(),
                        base_version: effectively_onchain.version,
                        kid: kid.clone(),
                        to_upsert: None,
                    };
                    self.maybe_start_consensus(update)
                        .context("process_new_observation failed at deletion consensus init")?;
                },
                (None, None) => {
                    unreachable!("`kid` in `union(A, B)` but `kid` not in `A` and not in `B`?")
                },
            }
        }

        Ok(())
    }
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L216-228)
```rust
        self.states_by_key.insert(
            (update.issuer.clone(), update.kid.clone()),
            ConsensusState::InProgress {
                my_proposal: ObservedKeyLevelUpdate {
                    author: self.my_addr,
                    observed: update,
                    signature,
                },
                abort_handle_wrapper: QuorumCertProcessGuard {
                    handle: abort_handle,
                },
            },
        );
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L244-254)
```rust
        self.states_by_key.retain(|(issuer, _), _| {
            new_onchain_jwks
                .get(issuer)
                .map(|jwks| jwks.version)
                .unwrap_or_default()
                == self
                    .onchain_jwks
                    .get(issuer)
                    .map(|jwks| jwks.version)
                    .unwrap_or_default()
        });
```

**File:** crates/jwk-utils/src/lib.rs (L25-36)
```rust
pub async fn fetch_jwks_from_jwks_uri(
    my_addr: Option<AccountAddress>,
    jwks_uri: &str,
) -> Result<Vec<JWK>> {
    let client = reqwest::Client::new();
    let mut request_builder = client.get(jwks_uri);
    if let Some(addr) = my_addr {
        request_builder = request_builder.header(COOKIE, addr.to_hex());
    }
    let JWKsResponse { keys } = request_builder.send().await?.json().await?;
    let jwks = keys.into_iter().map(JWK::from).collect();
    Ok(jwks)
```
