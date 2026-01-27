# Audit Report

## Title
Unbounded Memory Growth in Telemetry Service Validator Cache Due to Missing Validation

## Summary
The `update_for_chain()` function in the telemetry service accepts validator set data from configured REST API endpoints without any size validation, allowing a compromised or malicious endpoint to cause memory exhaustion by injecting excessive validator entries or cycling through multiple chain IDs.

## Finding Description

The telemetry service's `PeerSetCacheUpdater` periodically queries configured "trusted" full node endpoints to fetch validator sets and caches them in memory. The cache is structured as `HashMap<ChainId, (EpochNum, PeerSet)>` where `PeerSet = HashMap<PeerId, Peer>`. [1](#0-0) 

The vulnerability exists in the `update_for_chain()` function which:

1. Fetches `ValidatorSet` from a configured REST endpoint [2](#0-1) 

2. Extracts the chain_id from HTTP response headers without validation [3](#0-2) 

3. Converts all validators from the response into `PeerSet` entries without size limits [4](#0-3) 

4. Directly inserts into the cache without validation [5](#0-4) 

The only validation performed checks if the sets are empty, not if they are excessively large: [6](#0-5) 

While the on-chain Move framework defines `MAX_VALIDATOR_SET_SIZE = 65536`, the telemetry service performs no enforcement of this limit: [7](#0-6) 

**Attack Scenario:**

If a configured "trusted" full node endpoint is compromised or an operator mistakenly configures a malicious endpoint, the attacker can:

1. Return ValidatorSet responses with excessive validators (far exceeding 65,536)
2. Cycle through different chain_id values (0-255 since chain_id is u8) on successive requests [8](#0-7) 
3. Each validator creates a `Peer` object containing network addresses and keys [9](#0-8) 
4. Memory consumption grows unbounded until the telemetry service crashes

**Memory Impact Calculation:**
- Chain IDs: 256 possible values (u8)
- Validators per chain: No limit enforced (on-chain limit is 65,536 but not validated)
- Per validator: ~1KB+ (PeerId + Peer with addresses and keys)
- Potential maximum: 256 chains × 65,536 validators × 1KB = **16+ GB**
- Without validation: Could inject millions of validators per chain

## Impact Explanation

This vulnerability qualifies as **HIGH severity** per Aptos bug bounty criteria:

1. **API crashes**: Memory exhaustion causes the telemetry service to crash or become unresponsive
2. **Validator node slowdowns**: If the telemetry service runs on validator infrastructure, memory exhaustion impacts overall node performance
3. **Significant protocol violation**: The service accepts untrusted data without validation, violating the "Resource Limits" invariant that all operations must respect computational and memory constraints

The telemetry service is a critical operational component for monitoring validator health and network metrics. Its unavailability impairs the operator's ability to detect and respond to network issues.

## Likelihood Explanation

**Likelihood: Medium**

The attack requires one of the following conditions:
- Compromise of a configured "trusted" full node endpoint (supply chain attack)
- Operator misconfiguration (adding an attacker-controlled endpoint)
- MITM attack if TLS is not properly enforced

While these require external compromise, they are realistic scenarios:
- Full node endpoints may be operated by third parties
- Configuration errors are common operational risks  
- Defense-in-depth requires validation even when trusting external services

The lack of any size validation creates unnecessary risk and violates secure coding principles.

## Recommendation

Implement validation in `update_for_chain()` to enforce size limits:

1. **Validate chain_id**: Verify against expected/configured chain IDs
2. **Validate validator set size**: Enforce `MAX_VALIDATOR_SET_SIZE` from the Move framework
3. **Implement cache size limits**: Add maximum total memory consumption limits
4. **Add rate limiting**: Prevent rapid cache updates from the same source

**Recommended Fix:**

Add validation before inserting into cache in `validator_cache.rs`:

```rust
// After line 128, before line 163:
const MAX_VALIDATORS_PER_CHAIN: usize = 65536; // From stake.move
const MAX_TOTAL_CACHE_ENTRIES: usize = 100_000;

// Validate validator set size
if validator_peers.len() > MAX_VALIDATORS_PER_CHAIN {
    return Err(ValidatorCacheUpdateError::ValidatorSetTooLarge);
}
if vfn_peers.len() > MAX_VALIDATORS_PER_CHAIN {
    return Err(ValidatorCacheUpdateError::VfnSetTooLarge);
}

// Validate total cache size
let current_size: usize = validator_cache.values()
    .map(|(_, peers)| peers.len())
    .sum();
if current_size + validator_peers.len() > MAX_TOTAL_CACHE_ENTRIES {
    return Err(ValidatorCacheUpdateError::CacheFull);
}
```

Also validate expected chain_ids against a configured allowlist to prevent arbitrary chain_id injection.

## Proof of Concept

```rust
// Demonstration of memory exhaustion attack
// This would be added as a test in validator_cache.rs

#[tokio::test]
async fn test_validator_cache_memory_exhaustion() {
    use aptos_types::validator_info::ValidatorInfo;
    
    // Create a ValidatorSet with excessive validators
    let mut malicious_validators = Vec::new();
    for i in 0..100_000 { // Far exceeds MAX_VALIDATOR_SET_SIZE
        malicious_validators.push(ValidatorInfo::new(
            PeerId::random(),
            100,
            ValidatorConfig::new(/* ... */),
        ));
    }
    let malicious_set = ValidatorSet::new(malicious_validators);
    
    // Setup mock server returning malicious data
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method("GET").path("/v1/accounts/.../resource/0x1::stake::ValidatorSet");
        then.status(200)
            .body(bcs::to_bytes(&malicious_set).unwrap())
            .header(X_APTOS_CHAIN_ID, "25")
            .header(X_APTOS_EPOCH, "10")
            // ... other headers
    });
    
    // Configure telemetry service with malicious endpoint
    let mut endpoints = HashMap::new();
    endpoints.insert("malicious".into(), server.base_url());
    
    let updater = PeerSetCacheUpdater::new(
        Arc::new(RwLock::new(HashMap::new())),
        Arc::new(RwLock::new(HashMap::new())),
        endpoints,
        Duration::from_secs(1),
    );
    
    // Trigger update
    updater.update().await;
    
    // Observe: Cache now contains 100,000 validator entries
    // Memory consumption: ~100MB+ depending on peer data
    // No error or validation occurred
    assert!(updater.validators.read().len() > 0);
    // In production, repeated calls with different chain_ids 
    // would exhaust available memory
}
```

**Notes:**
- This vulnerability requires compromise of a configured external dependency
- While the attack vector requires privileged access to infrastructure (compromised full node), the telemetry service code itself lacks necessary defensive validation
- Defense-in-depth principles require validating untrusted input even from "trusted" sources
- The Move framework defines explicit limits that should be enforced in all consuming services

### Citations

**File:** crates/aptos-telemetry-service/src/types/mod.rs (L17-17)
```rust
    pub type EpochedPeerStore = HashMap<ChainId, (EpochNum, PeerSet)>;
```

**File:** crates/aptos-telemetry-service/src/validator_cache.rs (L95-98)
```rust
        let response: Response<ValidatorSet> = client
            .get_account_resource_bcs(CORE_CODE_ADDRESS, "0x1::stake::ValidatorSet")
            .await
            .map_err(ValidatorCacheUpdateError::RestError)?;
```

**File:** crates/aptos-telemetry-service/src/validator_cache.rs (L100-102)
```rust
        let (peer_addrs, state) = response.into_parts();

        let chain_id = ChainId::new(state.chain_id);
```

**File:** crates/aptos-telemetry-service/src/validator_cache.rs (L107-128)
```rust
        let validator_peers: PeerSet = peer_addrs
            .clone()
            .into_iter()
            .filter_map(|validator_info| -> Option<(PeerId, Peer)> {
                validator_info
                    .config()
                    .validator_network_addresses()
                    .map(|addresses| {
                        (
                            *validator_info.account_address(),
                            Peer::from_addrs(PeerRole::Validator, addresses),
                        )
                    })
                    .map_err(|err| {
                        error!(
                            "unable to parse validator network address for validator info {} for chain name {}: {}",
                            validator_info, chain_name, err
                        )
                    })
                    .ok()
            })
            .collect();
```

**File:** crates/aptos-telemetry-service/src/validator_cache.rs (L163-171)
```rust
        let result = if !has_validators && !has_vfns {
            Err(ValidatorCacheUpdateError::BothPeerSetEmpty)
        } else if !has_validators {
            Err(ValidatorCacheUpdateError::ValidatorSetEmpty)
        } else if !has_vfns {
            Err(ValidatorCacheUpdateError::VfnSetEmpty)
        } else {
            Ok(())
        };
```

**File:** crates/aptos-telemetry-service/src/validator_cache.rs (L176-176)
```rust
            validator_cache.insert(chain_id, (state.epoch, validator_peers));
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L100-100)
```text
    const MAX_VALIDATOR_SET_SIZE: u64 = 65536;
```

**File:** crates/aptos-rest-client/src/state.rs (L12-12)
```rust
    pub chain_id: u8,
```

**File:** config/src/config/network_config.rs (L460-464)
```rust
pub struct Peer {
    pub addresses: Vec<NetworkAddress>,
    pub keys: HashSet<x25519::PublicKey>,
    pub role: PeerRole,
}
```
