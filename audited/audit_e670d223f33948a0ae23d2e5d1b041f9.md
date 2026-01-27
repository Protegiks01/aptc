# Audit Report

## Title
Unbounded Topic Enumeration in Validator Transaction Pool via Malicious JWK Key IDs

## Summary
The validator transaction pool's `seq_nums_by_topic` HashMap lacks a limit on unique topics. When JWK consensus operates in per-key mode, each unique `(issuer, kid)` pair creates a distinct topic. A malicious or compromised OIDC provider could serve thousands of JWKs with unique Key IDs, causing all validators to simultaneously enumerate topics and exhaust memory, leading to performance degradation and potential denial of service.

## Finding Description
The `PoolStateInner` struct maintains an unbounded `HashMap<Topic, u64>` that maps topics to sequence numbers: [1](#0-0) 

When JWK consensus is enabled in per-key mode, topics are created with the structure `Topic::JWK_CONSENSUS_PER_KEY_MODE { issuer, kid }`: [2](#0-1) 

Both `Issuer` and `KID` are defined as unbounded byte vectors: [3](#0-2) 

The JWK consensus manager processes all observed keys and creates topics for each unique `(issuer, kid)` pair: [4](#0-3) 

The observation process fetches all JWKs from the OIDC provider's endpoint without any size limits: [5](#0-4) 

**Attack Path:**
1. Governance adds an OIDC provider to `SupportedOIDCProviders` (or an existing legitimate provider is compromised)
2. The malicious provider's JWKS endpoint serves thousands/millions of JWKs with unique KIDs
3. All validators observe this endpoint via `JWKObserver`
4. `KeyLevelConsensusManager::process_new_observation()` processes each key
5. For each unique `(issuer, kid)`, a new topic is inserted into `seq_nums_by_topic`
6. The HashMap grows unbounded, consuming memory and degrading performance across all validators simultaneously

The only limit is on federated JWKs (2 KiB), but no limit exists for validator-observed JWKs: [6](#0-5) 

## Impact Explanation
This qualifies as **Medium Severity** under the Aptos bug bounty program criteria:
- **Validator node slowdowns**: Memory exhaustion and HashMap performance degradation would slow down all validators simultaneously
- **State inconsistencies requiring intervention**: The issue would require manual intervention to remove the malicious OIDC provider via governance

The impact is network-wide because all validators observe the same OIDC providers and would experience the same resource exhaustion. This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits."

## Likelihood Explanation
The likelihood is **Medium to Low** because the attack requires:
1. **Governance approval** to add a malicious OIDC provider to `SupportedOIDCProviders`, OR
2. **Compromise of a legitimate OIDC provider** already approved by governance

While governance is controlled by stake-weighted voting and requires broad consensus, the risk of a compromised legitimate provider (e.g., through supply chain attacks or security breaches) makes this a realistic threat vector. Real-world OIDC providers typically maintain 2-10 active keys, so thousands of KIDs would be anomalous and detectable, but could cause significant damage before mitigation.

## Recommendation
Implement a maximum limit on the number of JWKs per issuer in the observation and validation logic:

```rust
// In jwks.move, add a constant
const MAX_JWKS_PER_ISSUER: u64 = 100;

// In upsert_into_observed_jwks, validate the size
assert!(
    vector::length(&proposed_provider_jwks.jwks) <= MAX_JWKS_PER_ISSUER,
    error::invalid_argument(ETOO_MANY_JWKS_PER_ISSUER)
);
```

Additionally, add validation in the Rust observation code:

```rust
// In jwk_observer.rs
const MAX_JWKS_PER_ISSUER: usize = 100;

async fn fetch_jwks(...) -> Result<Vec<JWK>> {
    let jwks = fetch_jwks_from_jwks_uri(...).await?;
    ensure!(
        jwks.len() <= MAX_JWKS_PER_ISSUER,
        "JWKS count exceeds maximum limit of {}", MAX_JWKS_PER_ISSUER
    );
    Ok(jwks)
}
```

This prevents the HashMap from growing beyond reasonable bounds while still supporting legitimate use cases.

## Proof of Concept

```rust
#[test]
fn test_topic_enumeration_attack() {
    use crate::{VTxnPoolState, Topic};
    use aptos_types::validator_txn::ValidatorTransaction;
    use aptos_types::jwks::{QuorumCertifiedUpdate, ProviderJWKs, issuer_from_str};
    use std::sync::Arc;
    
    let pool = VTxnPoolState::default();
    let issuer = issuer_from_str("https://malicious.provider.com");
    
    // Simulate attacker creating many unique KIDs
    let mut guards = vec![];
    for i in 0..10000 {
        let kid = format!("malicious_kid_{}", i).as_bytes().to_vec();
        let topic = Topic::JWK_CONSENSUS_PER_KEY_MODE {
            issuer: issuer.clone(),
            kid,
        };
        
        let update = QuorumCertifiedUpdate {
            update: ProviderJWKs::new(issuer.clone()),
            multi_sig: aptos_types::aggregate_signature::AggregateSignature::empty(),
        };
        let txn = ValidatorTransaction::ObservedJWKUpdate(update);
        
        let guard = pool.put(topic, Arc::new(txn), None);
        guards.push(guard);
    }
    
    // At this point, seq_nums_by_topic contains 10,000 unique topics
    // Memory usage and HashMap performance are degraded
    println!("Successfully enumerated 10,000 unique topics");
}
```

## Notes
The vulnerability exists because JWK observation trusts external OIDC providers to serve reasonable numbers of keys. While governance controls which providers are trusted, once approved, there's no protection against a provider serving malicious data. The per-key consensus mode amplifies this issue by creating a unique topic for every key, rather than a single topic per issuer as in the per-issuer mode.

### Citations

**File:** crates/validator-transaction-pool/src/lib.rs (L114-124)
```rust
pub struct PoolStateInner {
    /// Incremented every time a txn is pushed in. The txn gets the old value as its sequence number.
    next_seq_num: u64,

    /// Track Topic -> seq_num mapping.
    /// We allow only 1 txn per topic and this index helps find the old txn when adding a new one for the same topic.
    seq_nums_by_topic: HashMap<Topic, u64>,

    /// Txns ordered by their sequence numbers (i.e. time they entered the pool).
    txn_queue: BTreeMap<u64, PoolItem>,
}
```

**File:** types/src/validator_txn.rs (L55-64)
```rust
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[allow(non_camel_case_types)]
pub enum Topic {
    DKG,
    JWK_CONSENSUS(jwks::Issuer),
    JWK_CONSENSUS_PER_KEY_MODE {
        issuer: jwks::Issuer,
        kid: jwks::KID,
    },
}
```

**File:** types/src/jwks/mod.rs (L36-38)
```rust
pub type Issuer = Vec<u8>;
/// Type for JWK Key ID.
pub type KID = Vec<u8>;
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L336-341)
```rust
                let topic = Topic::JWK_CONSENSUS_PER_KEY_MODE {
                    issuer: issuer.clone(),
                    kid: kid.clone(),
                };
                let txn = ValidatorTransaction::ObservedJWKUpdate(issuer_level_repr.clone());
                let vtxn_guard = self.vtxn_pool.put(topic, Arc::new(txn), None);
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

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L31-33)
```text
    /// We limit the size of a `PatchedJWKs` resource installed by a dapp owner for federated keyless accounts.
    /// Note: If too large, validators waste work reading it for invalid TXN signatures.
    const MAX_FEDERATED_JWKS_SIZE_BYTES: u64 = 2 * 1024; // 2 KiB
```
