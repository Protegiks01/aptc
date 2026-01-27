# Audit Report

## Title
TOCTOU Race Condition in Telemetry Service JWT Authentication During Epoch Transitions

## Summary
A Time-Of-Check-Time-Of-Use (TOCTOU) race condition exists between JWT token creation and validation in the telemetry service. When epoch transitions occur, tokens created with epoch N become immediately invalid when the validator cache updates to epoch N+1, causing authentication failures during epoch boundaries.

## Finding Description

The telemetry service uses JWT tokens for authenticating validator nodes submitting metrics and logs. The authentication flow has a critical TOCTOU vulnerability:

**Token Creation Flow:**
1. When a node authenticates via `handle_auth()`, the current epoch is read from the validator cache [1](#0-0) 
2. A JWT token is created with this epoch value [2](#0-1) 
3. The JWT encoding happens in `create_jwt_token()` which embeds the epoch in the Claims structure [3](#0-2) 

**Token Validation Flow:**
1. When the token is later used, `authorize_jwt()` reads the current epoch from the validator cache [4](#0-3) 
2. Strict validation requires exact epoch match [5](#0-4) 

**The Race Condition:**
Between token creation and validation, a background `PeerSetCacheUpdater` periodically updates the validator cache with the latest on-chain ValidatorSet [6](#0-5) . The cache stores `(epoch, peerset)` tuples [7](#0-6) . When an epoch transition occurs on-chain:

1. Node receives token with epoch N at time T0
2. Epoch transition happens on-chain at time T1
3. Background updater updates cache to epoch N+1 at time T2
4. Node attempts to use token at time T3
5. Validation fails: `claims.epoch (N) != current_epoch (N+1)`
6. Token is rejected as expired despite being within its 60-minute validity window [8](#0-7) 

**No Grace Period:** The code has no overlap or grace period mechanism - tokens from the previous epoch are immediately invalid once the cache updates.

## Impact Explanation

**Severity: Medium** (up to $10,000 per Aptos Bug Bounty criteria)

This vulnerability causes state inconsistencies in the telemetry authentication system requiring operational intervention:

1. **Authentication Service Degradation**: During each epoch transition (which occurs regularly on Aptos), all validators holding tokens from the previous epoch experience authentication failures
2. **Telemetry Gaps**: Validators cannot submit metrics or logs during the transition window, creating monitoring blind spots during critical epoch changes
3. **Cascading Re-authentication Load**: Mass authentication failures trigger simultaneous re-authentication attempts by all affected validators, potentially overwhelming the telemetry service
4. **Operational Impact**: While this doesn't affect consensus or blockchain state directly, it disrupts critical operational monitoring during epoch transitions - precisely when observability is most needed

This qualifies as Medium severity under "State inconsistencies requiring intervention" - the telemetry service authentication state becomes inconsistent with the on-chain epoch state, requiring nodes to re-authenticate.

## Likelihood Explanation

**Likelihood: High - Occurs Naturally**

This vulnerability triggers automatically during every epoch transition without requiring any attacker action:

1. **Frequent Occurrence**: Epoch transitions happen regularly on Aptos networks
2. **Wide Window**: The TOCTOU window spans from token creation to token use, which can be seconds to minutes
3. **Guaranteed Hit**: Any node that receives a token shortly before an epoch transition will experience this issue
4. **No Mitigation**: The code has no defensive mechanisms (grace periods, epoch overlap, etc.)

The vulnerability is deterministic and requires no special conditions beyond normal network operation during epoch transitions.

## Recommendation

Implement a grace period mechanism to allow tokens from the previous epoch to remain valid for a short transition window:

```rust
// In authorize_jwt() function
let current_epoch = match context.peers().validators().read().get(&claims.chain_id) {
    Some(info) => info.0,
    None => {
        return Err(reject::custom(ServiceError::unauthorized(
            JwtAuthError::ExpiredAuthToken.into(),
        )));
    },
};

// Allow tokens from current epoch OR previous epoch (grace period)
let epoch_valid = claims.epoch == current_epoch || 
                  claims.epoch + 1 == current_epoch;

if !allow_roles.contains(&claims.node_type) {
    return Err(reject::custom(ServiceError::forbidden(
        JwtAuthError::AccessDenied.into(),
    )));
}

if epoch_valid && claims.exp > Utc::now().timestamp() as usize {
    Ok(claims)
} else {
    Err(reject::custom(ServiceError::unauthorized(
        JwtAuthError::ExpiredAuthToken.into(),
    )))
}
```

This allows tokens from both the current epoch and the immediately previous epoch to be valid, providing a grace period during epoch transitions.

## Proof of Concept

```rust
#[cfg(test)]
mod toctou_epoch_test {
    use super::*;
    use crate::types::auth::Claims;
    use crate::types::common::NodeType;
    use aptos_types::{chain_id::ChainId, PeerId};
    use std::collections::HashMap;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_epoch_transition_invalidates_token() {
        // Setup test context
        let test_context = test_context::new_test_context().await;
        let chain_id = ChainId::new(25);
        let peer_id = PeerId::random();
        
        // Initialize validator cache with epoch 10
        {
            test_context
                .inner
                .peers()
                .validators()
                .write()
                .insert(chain_id, (10, HashMap::new()));
        }
        
        // Create token with epoch 10
        let token = create_jwt_token(
            test_context.inner.jwt_service(),
            chain_id,
            peer_id,
            NodeType::Validator,
            10, // epoch 10
            Uuid::default(),
        )
        .unwrap();
        
        // Token is valid with epoch 10
        let result = authorize_jwt(
            token.clone(),
            test_context.inner.clone(),
            vec![NodeType::Validator]
        ).await;
        assert!(result.is_ok());
        
        // Simulate epoch transition - update cache to epoch 11
        {
            test_context
                .inner
                .peers()
                .validators()
                .write()
                .insert(chain_id, (11, HashMap::new()));
        }
        
        // Same token now fails validation (TOCTOU vulnerability)
        let result = authorize_jwt(
            token,
            test_context.inner,
            vec![NodeType::Validator]
        ).await;
        
        // Token is rejected despite being within expiration time
        assert!(result.is_err());
        // This demonstrates the TOCTOU race condition
    }
}
```

## Notes

This vulnerability specifically affects the telemetry service authentication subsystem, not the core consensus or transaction processing layers. While the impact is limited to operational monitoring capabilities, the authentication failures during epoch transitions represent a genuine security concern for maintaining observability during critical blockchain state changes.

### Citations

**File:** crates/aptos-telemetry-service/src/auth.rs (L72-72)
```rust
    let (epoch, peer_role) = match cache.read().get(&body.chain_id) {
```

**File:** crates/aptos-telemetry-service/src/auth.rs (L137-144)
```rust
    let token = create_jwt_token(
        context.jwt_service(),
        body.chain_id,
        body.peer_id,
        node_type,
        epoch,
        body.run_uuid,
    )
```

**File:** crates/aptos-telemetry-service/src/jwt_auth.rs (L26-30)
```rust
    let issued = Utc::now().timestamp();
    let expiration = Utc::now()
        .checked_add_signed(chrono::Duration::minutes(60))
        .expect("valid timestamp")
        .timestamp();
```

**File:** crates/aptos-telemetry-service/src/jwt_auth.rs (L32-41)
```rust
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
```

**File:** crates/aptos-telemetry-service/src/jwt_auth.rs (L57-64)
```rust
    let current_epoch = match context.peers().validators().read().get(&claims.chain_id) {
        Some(info) => info.0,
        None => {
            return Err(reject::custom(ServiceError::unauthorized(
                JwtAuthError::ExpiredAuthToken.into(),
            )));
        },
    };
```

**File:** crates/aptos-telemetry-service/src/jwt_auth.rs (L72-78)
```rust
    if claims.epoch == current_epoch && claims.exp > Utc::now().timestamp() as usize {
        Ok(claims)
    } else {
        Err(reject::custom(ServiceError::unauthorized(
            JwtAuthError::ExpiredAuthToken.into(),
        )))
    }
```

**File:** crates/aptos-telemetry-service/src/validator_cache.rs (L176-176)
```rust
            validator_cache.insert(chain_id, (state.epoch, validator_peers));
```

**File:** crates/aptos-telemetry-service/src/types/mod.rs (L17-17)
```rust
    pub type EpochedPeerStore = HashMap<ChainId, (EpochNum, PeerSet)>;
```
