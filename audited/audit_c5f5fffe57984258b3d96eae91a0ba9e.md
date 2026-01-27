# Audit Report

## Title
JWT Replay Attack: Removed Validators Can Continue Submitting Metrics to Trusted Backend via Unexpired Tokens

## Summary
The Aptos telemetry service's JWT validation logic fails to re-verify that a node's role in the validator set remains valid. After a validator is removed from the validator set, they can continue using previously-issued JWT tokens (valid for 60 minutes) to submit metrics as a trusted validator, bypassing authorization state changes and accessing privileged metrics infrastructure.

## Finding Description

The vulnerability exists in the JWT authorization flow across multiple components:

**JWT Token Creation:** When a node authenticates, the system determines their role by checking the current validator set. [1](#0-0)  The determined `node_type` is embedded in a JWT with 60-minute expiration. [2](#0-1) 

**JWT Token Validation:** The critical flaw occurs in the `authorize_jwt` function. [3](#0-2)  The validation checks only three conditions: (1) epoch matches current epoch, (2) token hasn't expired, and (3) claimed node_type is in allowed roles. [4](#0-3) 

**The Missing Check:** The validator never re-queries the current validator set to verify that the `peer_id` in the JWT still holds the claimed `node_type`. When a validator is removed from the validator set (via slashing, unstaking, or governance action), the validator cache is updated with the new set. [5](#0-4)  However, JWTs issued before the removal remain cryptographically valid and pass all authorization checks.

**Impact on Metrics Routing:** The system routes metrics differently based on node type. [6](#0-5)  Trusted nodes (Validator, ValidatorFullNode, PublicFullNode) route to `ingest_metrics_client`, while untrusted nodes route to `untrusted_ingest_metrics_clients`. A removed validator with a valid JWT continues accessing the trusted metrics backend.

**Attack Scenario:**
1. Validator V authenticates at epoch N, receives JWT: `{peer_id: V, node_type: Validator, epoch: N, exp: T+60min}`
2. Within the same epoch, validator V is removed from the validator set (slashing/unstaking)
3. Validator cache updates with new set (still epoch N, but V no longer present)
4. V continues submitting metrics using the JWT for up to 60 minutes
5. Validation passes because: epoch matches (N==N), token not expired, NodeType::Validator is allowed
6. Metrics are routed to trusted backend and labeled as coming from a validator

## Impact Explanation

This vulnerability represents a **High severity** authorization bypass with multiple security implications:

**Trust Boundary Violation:** The system's security model assumes removed validators immediately lose access to privileged infrastructure. This assumption is violated for up to 60 minutes per token, allowing potentially malicious or compromised nodes to continue accessing trusted systems.

**Metrics Integrity Compromise:** Operational monitoring and alerting systems rely on the distinction between trusted and untrusted metrics sources. Polluted metrics from removed validators can:
- Mislead operators about network health
- Trigger false alerts or mask real issues  
- Corrupt historical metrics data used for capacity planning
- Violate compliance requirements for audit trails

**Denial of Service Potential:** A removed validator could flood the trusted metrics backend with excessive data, potentially causing:
- Storage exhaustion in metrics databases
- API slowdowns or crashes (meeting High severity criteria)
- Degraded monitoring for legitimate validators

**Attack Amplification:** If multiple validators are removed simultaneously (e.g., during a security incident or governance action), each retains 60-minute access windows, amplifying the potential for coordinated abuse.

Per Aptos bug bounty criteria, this qualifies as High severity due to "significant protocol violations" in the authorization model and potential for "API crashes" or "validator node slowdowns" through metrics system abuse.

## Likelihood Explanation

**High Likelihood** of exploitation:

**Common Triggering Events:** Validators are regularly removed from validator sets through:
- Governance-initiated removals
- Performance-based ejections
- Voluntary unstaking
- Slashing for malicious behavior

**Low Attack Complexity:** Exploitation requires only:
- Previously obtained valid JWT (normal operation)
- Knowledge that removal occurred
- Standard HTTP client to continue submitting metrics

**No Special Privileges Required:** The attack doesn't require ongoing validator status—only historical authentication. Any node that was ever a validator can exploit this window.

**Observable Window:** The 60-minute validity period provides ample time for attackers to notice their removal and deliberately abuse the remaining token lifetime.

**Incentive for Malicious Actors:** Validators removed for malicious behavior have direct incentive to disrupt monitoring infrastructure during their remaining access window.

## Recommendation

Implement real-time validator set membership verification during JWT validation:

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

    // Fetch current validator set for the chain
    let validator_cache = context.peers().validators().read();
    let (current_epoch, peer_set) = match validator_cache.get(&claims.chain_id) {
        Some(info) => info,
        None => {
            return Err(reject::custom(ServiceError::unauthorized(
                JwtAuthError::ExpiredAuthToken.into(),
            )));
        },
    };

    // Verify epoch matches
    if claims.epoch != *current_epoch {
        return Err(reject::custom(ServiceError::unauthorized(
            JwtAuthError::ExpiredAuthToken.into(),
        )));
    }

    // Verify token not expired
    if claims.exp <= Utc::now().timestamp() as usize {
        return Err(reject::custom(ServiceError::unauthorized(
            JwtAuthError::ExpiredAuthToken.into(),
        )));
    }

    // **NEW CHECK**: Re-verify the peer_id's current role matches claimed node_type
    let current_role = match peer_set.get(&claims.peer_id) {
        Some(peer) => {
            // Peer found in validator set - determine their current role
            match claims.node_type {
                NodeType::Validator => {
                    if peer.role == PeerRole::Validator {
                        Some(NodeType::Validator)
                    } else {
                        None // Role mismatch
                    }
                },
                NodeType::ValidatorFullNode => {
                    // Also check VFN cache if needed
                    let vfn_cache = context.peers().validator_fullnodes().read();
                    if let Some((_, vfn_set)) = vfn_cache.get(&claims.chain_id) {
                        if vfn_set.contains_key(&claims.peer_id) {
                            Some(NodeType::ValidatorFullNode)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                },
                _ => None,
            }
        },
        None => {
            // Peer not in validator set
            match claims.node_type {
                NodeType::Validator | NodeType::ValidatorFullNode => {
                    // Claimed to be trusted validator but not in set
                    return Err(reject::custom(ServiceError::forbidden(
                        JwtAuthError::AccessDenied.into(),
                    )));
                },
                _ => Some(claims.node_type.clone()), // Allow untrusted roles
            }
        },
    };

    // Verify the current role matches claimed role
    match current_role {
        Some(role) if role == claims.node_type && allow_roles.contains(&role) => {
            Ok(claims)
        },
        _ => {
            Err(reject::custom(ServiceError::forbidden(
                JwtAuthError::AccessDenied.into(),
            )))
        },
    }
}
```

**Additional Mitigations:**
1. Reduce JWT expiration from 60 minutes to 5-10 minutes to minimize attack window
2. Implement token revocation list for explicitly invalidated tokens
3. Add epoch transition event handlers to proactively invalidate tokens when validator sets change
4. Log and alert on authorization failures that indicate removed validators attempting access

## Proof of Concept

```rust
#[cfg(test)]
mod exploit_test {
    use super::*;
    use crate::tests::test_context;
    use aptos_types::{chain_id::ChainId, PeerId};
    use std::collections::HashMap;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_removed_validator_jwt_replay() {
        // Setup: Create test context with validator in set
        let test_context = test_context::new_test_context().await;
        let peer_id = PeerId::random();
        let chain_id = ChainId::new(25);
        
        // Step 1: Add validator to validator set at epoch 10
        {
            let mut peer_set = HashMap::new();
            peer_set.insert(
                peer_id,
                Peer::from_addrs(
                    PeerRole::Validator,
                    vec![NetworkAddress::from_str("/ip4/127.0.0.1/tcp/6180").unwrap()]
                )
            );
            test_context
                .inner
                .peers()
                .validators()
                .write()
                .insert(chain_id, (10, peer_set));
        }
        
        // Step 2: Validator authenticates and gets JWT
        let token = create_jwt_token(
            test_context.inner.jwt_service(),
            chain_id,
            peer_id,
            NodeType::Validator,
            10,
            Uuid::new_v4(),
        )
        .unwrap();
        
        // Step 3: Validator is removed from set (same epoch)
        {
            test_context
                .inner
                .peers()
                .validators()
                .write()
                .insert(chain_id, (10, HashMap::new())); // Empty peer set
        }
        
        // Step 4: EXPLOIT - Removed validator uses JWT to submit metrics
        let result = authorize_jwt(
            token.clone(),
            test_context.inner.clone(),
            vec![NodeType::Validator]
        ).await;
        
        // BUG: This should fail but succeeds!
        assert!(result.is_ok(), "VULNERABILITY: Removed validator JWT still accepted");
        
        // Step 5: Verify metrics would be routed to trusted backend
        let claims = result.unwrap();
        assert_eq!(claims.node_type, NodeType::Validator);
        // In handle_metrics_ingest, this routes to ingest_metrics_client (trusted)
        // instead of untrusted_ingest_metrics_clients
    }
}
```

**Notes**

The vulnerability stems from a fundamental architectural decision to embed authorization state (node role) in stateless JWTs rather than performing real-time authorization checks. While JWTs provide scalability benefits, they require careful handling of state changes. The telemetry service's validator cache is already updated in real-time, but the JWT validation logic fails to leverage this current state, creating a 60-minute authorization bypass window whenever validator set membership changes.

### Citations

**File:** crates/aptos-telemetry-service/src/auth.rs (L72-114)
```rust
    let (epoch, peer_role) = match cache.read().get(&body.chain_id) {
        Some((epoch, peer_set)) => {
            match peer_set.get(&body.peer_id) {
                Some(peer) => {
                    let remote_public_key = &remote_public_key;
                    if !peer.keys.contains(remote_public_key) {
                        warn!("peer found in peer set but public_key is not found. request body: {}, role_type: {}, peer_id: {}, received public_key: {}", body.chain_id, body.role_type, body.peer_id, remote_public_key);
                        return Err(reject::custom(ServiceError::forbidden(
                            ServiceErrorCode::AuthError(
                                AuthError::PeerPublicKeyNotFound,
                                body.chain_id,
                            ),
                        )));
                    }
                    Ok((*epoch, peer.role))
                },
                None => {
                    // if not, verify that their peerid is constructed correctly from their public key
                    let derived_remote_peer_id =
                        aptos_types::account_address::from_identity_public_key(remote_public_key);
                    if derived_remote_peer_id != body.peer_id {
                        return Err(reject::custom(ServiceError::forbidden(
                            ServiceErrorCode::AuthError(
                                AuthError::PublicKeyMismatch,
                                body.chain_id,
                            ),
                        )));
                    } else {
                        Ok((*epoch, PeerRole::Unknown))
                    }
                },
            }
        },
        None => {
            warn!(
                "Validator set unavailable for Chain ID {}. Rejecting request.",
                body.chain_id
            );
            Err(reject::custom(ServiceError::unauthorized(
                ServiceErrorCode::AuthError(AuthError::ValidatorSetUnavailable, body.chain_id),
            )))
        },
    }?;
```

**File:** crates/aptos-telemetry-service/src/jwt_auth.rs (L26-30)
```rust
    let issued = Utc::now().timestamp();
    let expiration = Utc::now()
        .checked_add_signed(chrono::Duration::minutes(60))
        .expect("valid timestamp")
        .timestamp();
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

**File:** crates/aptos-telemetry-service/src/validator_cache.rs (L176-176)
```rust
            validator_cache.insert(chain_id, (state.epoch, validator_peers));
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
