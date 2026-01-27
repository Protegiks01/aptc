# Audit Report

## Title
Time-of-Check-to-Time-of-Use (TOCTOU) Authorization Bypass in Telemetry Service JWT Validation

## Summary
The `authorize_jwt` function validates JWT tokens by checking the embedded NodeType against an allowed roles list and verifying epoch/expiration, but does **not** re-validate that the NodeType still matches the node's current role in the validator set. This creates a TOCTOU window where a demoted or removed node can continue using a privileged JWT (valid for up to 60 minutes) to submit metrics to trusted backends, bypassing authorization controls.

## Finding Description
The telemetry service uses a two-phase authentication and authorization flow that creates a critical TOCTOU vulnerability:

**Authentication Phase (Time-of-Check):**
When a node authenticates via the `/auth` endpoint, the server determines the node's role by looking it up in the cached validator set and creates a JWT embedding this NodeType. [1](#0-0) 

The JWT is created with a 60-minute expiration and includes the NodeType determined at authentication time. [2](#0-1) 

**Authorization Phase (Time-of-Use):**
When the JWT is later used to submit metrics, the `authorize_jwt` function only validates: (1) JWT signature validity, (2) NodeType is in the allowed roles list, (3) epoch matches current epoch, and (4) token hasn't time-expired. [3](#0-2) 

**Critical Gap:** The authorization function fetches the current epoch from the validator set but does **not** re-validate the NodeType against the node's current role. [4](#0-3) 

**Attack Scenario:**
1. Node A authenticates as Validator at epoch 100 → receives JWT with `{node_type: Validator, epoch: 100, exp: T0+60min}`
2. Within the same epoch (before epoch 101), Node A is removed from the validator set or demoted
3. The `PeerSetCacheUpdater` periodically updates the cached validator set from on-chain state [5](#0-4) 
4. Node A continues using its JWT to submit metrics; `authorize_jwt` accepts it because epoch still matches (100==100) and token hasn't time-expired
5. Based on the stale NodeType in the JWT, Node A's metrics are routed to the privileged `ingest_metrics_client` instead of `untrusted_ingest_metrics_clients` [6](#0-5) 

This violates the Access Control invariant: authorization should reflect the node's **current** role, not its role at authentication time.

## Impact Explanation
This is a **High Severity** vulnerability per Aptos bug bounty criteria because it constitutes a "Significant protocol violation" - specifically an authorization bypass that allows demoted or removed nodes to maintain privileged access.

**Concrete Impact:**
- Demoted/removed validators can submit metrics to trusted backends for up to 60 minutes after demotion
- Unknown/untrusted nodes that briefly gained Validator status can continue accessing privileged infrastructure
- Could pollute trusted metrics with data from compromised or malicious nodes
- Violates the principle of least privilege and separation of trust domains

While this doesn't directly affect consensus or fund security, it represents a critical authorization control failure in the telemetry infrastructure.

## Likelihood Explanation
This vulnerability has **Medium-to-High Likelihood** of exploitation:

**Favorable Conditions:**
- Validator sets regularly change due to key rotations, performance issues, or governance decisions
- The 60-minute JWT validity window is substantial
- Epoch changes may not coincide with validator set updates (changes can occur within the same epoch)
- The periodic cache update mechanism creates inherent staleness windows [7](#0-6) 

**Required Steps:**
1. Node obtains valid JWT with privileged NodeType (requires initial authentication)
2. Node's role changes within the same epoch or before JWT expires
3. Node continues using JWT to access privileged backends

The attack requires no special privileges beyond initial authentication capability, making it accessible to any node that was once privileged.

## Recommendation
Re-validate the NodeType against the current validator set during JWT authorization:

```rust
pub async fn authorize_jwt(
    token: String,
    context: Context,
    allow_roles: Vec<NodeType>,
) -> anyhow::Result<Claims, Rejection> {
    let decoded: TokenData<Claims> = context.jwt_service().decode(&token).map_err(|e| {
        error!("unable to authorize jwt token: {}", e);
        reject::custom(ServiceError::unauthorized(
            JwtAuthError::InvalidAuthToken.into(),
        ))
    })?;
    let claims = decoded.claims;

    // Get current validator set and epoch
    let (current_epoch, peer_set) = match context.peers().validators().read().get(&claims.chain_id) {
        Some((epoch, peer_set)) => (*epoch, peer_set.clone()),
        None => {
            return Err(reject::custom(ServiceError::unauthorized(
                JwtAuthError::ExpiredAuthToken.into(),
            )));
        },
    };

    // RE-VALIDATE: Determine current NodeType based on current validator set
    let current_node_type = match peer_set.get(&claims.peer_id) {
        Some(peer) if peer.role == PeerRole::Validator => NodeType::Validator,
        Some(peer) if peer.role == PeerRole::ValidatorFullNode => NodeType::ValidatorFullNode,
        _ => {
            // Check VFN and public fullnode caches similarly
            // Default to Unknown types if not found
            NodeType::UnknownValidator // or appropriate unknown type
        }
    };

    // Verify NodeType hasn't changed
    if current_node_type != claims.node_type {
        return Err(reject::custom(ServiceError::forbidden(
            JwtAuthError::AccessDenied.into(),
        )));
    }

    if !allow_roles.contains(&claims.node_type) {
        return Err(reject::custom(ServiceError::forbidden(
            JwtAuthError::AccessDenied.into(),
        )));
    }

    if claims.epoch == current_epoch && claims.exp > Utc::now().timestamp() as usize {
        Ok(claims)
    } else {
        Err(reject::custom(ServiceError::unauthorized(
            JwtAuthError::ExpiredAuthToken.into(),
        )))
    }
}
```

This ensures that even if a JWT is cryptographically valid and within its time window, it will be rejected if the node's role has changed since issuance.

## Proof of Concept

```rust
#[cfg(test)]
mod toctou_attack_test {
    use super::*;
    use crate::tests::test_context;
    use aptos_types::{chain_id::ChainId, PeerId};
    use aptos_config::config::{Peer, PeerRole, PeerSet};
    use std::collections::HashMap;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_jwt_authorization_bypass_via_role_change() {
        let mut test_context = test_context::new_test_context().await;
        let peer_id = PeerId::random();
        let chain_id = ChainId::new(25);
        
        // Step 1: Node is initially a Validator
        {
            let mut peer_set = PeerSet::new();
            peer_set.insert(peer_id, Peer {
                role: PeerRole::Validator,
                addresses: vec![],
                keys: Default::default(),
            });
            test_context
                .inner
                .peers()
                .validators()
                .write()
                .insert(chain_id, (10, peer_set));
        }
        
        // Step 2: Node authenticates and gets JWT with NodeType::Validator
        let token = create_jwt_token(
            test_context.inner.jwt_service(),
            chain_id,
            peer_id,
            NodeType::Validator,
            10,
            Uuid::default(),
        )
        .unwrap();
        
        // Step 3: Node is removed from validator set (demoted/removed)
        {
            let empty_peer_set = PeerSet::new();
            test_context
                .inner
                .peers()
                .validators()
                .write()
                .insert(chain_id, (10, empty_peer_set)); // Same epoch!
        }
        
        // Step 4: Node tries to use JWT - SHOULD BE REJECTED but currently ACCEPTS
        let result = authorize_jwt(
            token,
            test_context.inner.clone(),
            vec![NodeType::Validator],
        )
        .await;
        
        // VULNERABILITY: This passes when it should fail
        assert!(result.is_ok(), "Authorization bypass: demoted node can still use privileged JWT");
        
        // The node can now submit metrics to trusted backend despite being removed
        // from the validator set, violating authorization controls
    }
}
```

**Notes:**
The vulnerability exists because the JWT validation logic trusts the NodeType embedded in the JWT token without re-verifying it against the current state of the validator set. While the epoch check provides some protection, validator set changes can occur within the same epoch (due to key rotations, removals, etc.), and the 60-minute JWT validity window creates a substantial exploitation window. This represents a fundamental TOCTOU flaw in the authorization architecture.

### Citations

**File:** crates/aptos-telemetry-service/src/auth.rs (L116-135)
```rust
    let node_type = match peer_role {
        PeerRole::Validator => NodeType::Validator,
        PeerRole::ValidatorFullNode => NodeType::ValidatorFullNode,
        PeerRole::Unknown => match body.role_type {
            RoleType::Validator => NodeType::UnknownValidator,
            RoleType::FullNode => context
                .peers()
                .public_fullnodes()
                .get(&body.chain_id)
                .and_then(|peer_set| {
                    if peer_set.contains_key(&body.peer_id) {
                        Some(NodeType::PublicFullNode)
                    } else {
                        None
                    }
                })
                .unwrap_or(NodeType::UnknownFullNode),
        },
        _ => NodeType::Unknown,
    };
```

**File:** crates/aptos-telemetry-service/src/jwt_auth.rs (L18-42)
```rust
pub fn create_jwt_token(
    jwt_service: &JsonWebTokenService,
    chain_id: ChainId,
    peer_id: PeerId,
    node_type: NodeType,
    epoch: u64,
    uuid: Uuid,
) -> Result<String, Error> {
    let issued = Utc::now().timestamp();
    let expiration = Utc::now()
        .checked_add_signed(chrono::Duration::minutes(60))
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        chain_id,
        peer_id,
        node_type,
        epoch,
        exp: expiration as usize,
        iat: issued as usize,
        run_uuid: uuid,
    };
    jwt_service.encode(claims)
}
```

**File:** crates/aptos-telemetry-service/src/jwt_auth.rs (L44-79)
```rust
pub async fn authorize_jwt(
    token: String,
    context: Context,
    allow_roles: Vec<NodeType>,
) -> anyhow::Result<Claims, Rejection> {
    let decoded: TokenData<Claims> = context.jwt_service().decode(&token).map_err(|e| {
        error!("unable to authorize jwt token: {}", e);
        reject::custom(ServiceError::unauthorized(
            JwtAuthError::InvalidAuthToken.into(),
        ))
    })?;
    let claims = decoded.claims;

    let current_epoch = match context.peers().validators().read().get(&claims.chain_id) {
        Some(info) => info.0,
        None => {
            return Err(reject::custom(ServiceError::unauthorized(
                JwtAuthError::ExpiredAuthToken.into(),
            )));
        },
    };

    if !allow_roles.contains(&claims.node_type) {
        return Err(reject::custom(ServiceError::forbidden(
            JwtAuthError::AccessDenied.into(),
        )));
    }

    if claims.epoch == current_epoch && claims.exp > Utc::now().timestamp() as usize {
        Ok(claims)
    } else {
        Err(reject::custom(ServiceError::unauthorized(
            JwtAuthError::ExpiredAuthToken.into(),
        )))
    }
}
```

**File:** crates/aptos-telemetry-service/src/validator_cache.rs (L51-59)
```rust
    pub fn run(self) {
        let mut interval = time::interval(self.update_interval);
        tokio::spawn(async move {
            loop {
                self.update().await;
                interval.tick().await;
            }
        });
    }
```

**File:** crates/aptos-telemetry-service/src/validator_cache.rs (L86-90)
```rust
    async fn update_for_chain(
        &self,
        chain_name: &ChainCommonName,
        url: &str,
    ) -> Result<(), ValidatorCacheUpdateError> {
```

**File:** crates/aptos-telemetry-service/src/prometheus_push_metrics.rs (L80-85)
```rust
    let client = match claims.node_type {
        NodeType::UnknownValidator | NodeType::UnknownFullNode => {
            &context.metrics_client().untrusted_ingest_metrics_clients
        },
        _ => &context.metrics_client().ingest_metrics_client,
    };
```
