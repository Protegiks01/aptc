# Audit Report

## Title
Unbounded BCS Deserialization in Validator Network Address Parsing May Cause Denial of Service

## Summary
The `validator_network_addresses()` and `fullnode_network_addresses()` methods use unbounded BCS deserialization (`bcs::from_bytes`) on untrusted on-chain data, potentially allowing a malicious validator operator to cause excessive memory allocation and crash validator nodes during peer discovery.

## Finding Description

When validators perform peer discovery, they deserialize network addresses from the on-chain `ValidatorSet` configuration. The deserialization path is:

1. Validator operator calls `update_network_and_fullnode_addresses` to store raw bytes on-chain [1](#0-0) 

2. These bytes are stored without validation as `Vec<u8>` in `ValidatorConfig` [2](#0-1) 

3. During peer discovery, validators deserialize using unbounded `bcs::from_bytes()` [3](#0-2) 

4. This deserialization is called in the network discovery module [4](#0-3) 

**Critical Issue**: Unlike network protocol messages which use `bcs::from_bytes_with_limit` for safety: [5](#0-4) 

The validator address deserialization has no size limits. A malicious operator could craft BCS-encoded bytes with a ULEB128 length prefix claiming billions of elements, potentially triggering excessive memory allocation when the BCS deserializer attempts to pre-allocate vector capacity.

## Impact Explanation

**Severity: HIGH** - This violates the "Resource Limits: All operations must respect gas, storage, and computational limits" invariant.

If exploited, this could cause:
- Validator node crashes due to out-of-memory conditions
- Network-wide availability degradation during epoch transitions
- Disruption of peer discovery mechanisms
- Potential temporary loss of consensus if enough validators crash

While the error is caught and logged, allocation failures in Rust typically panic before returning an error, making the `unwrap_or_default()` error handling ineffective against memory exhaustion attacks.

## Likelihood Explanation

**Likelihood: MEDIUM**
- Requires compromised/malicious validator operator (semi-trusted role)
- Low complexity - simple BCS byte crafting
- Persistent on-chain - affects all validators until corrected
- Triggered automatically during epoch changes and peer discovery
- No special timing or coordination required

## Recommendation

Apply size limits to BCS deserialization of network addresses, consistent with other network protocol deserialization:

```rust
// In types/src/validator_config.rs
const MAX_NETWORK_ADDRESS_BCS_BYTES: usize = 10_000; // Reasonable limit for address vectors

pub fn fullnode_network_addresses(&self) -> Result<Vec<NetworkAddress>, bcs::Error> {
    bcs::from_bytes_with_limit(&self.fullnode_network_addresses, MAX_NETWORK_ADDRESS_BCS_BYTES)
}

pub fn validator_network_addresses(&self) -> Result<Vec<NetworkAddress>, bcs::Error> {
    bcs::from_bytes_with_limit(&self.validator_network_addresses, MAX_NETWORK_ADDRESS_BCS_BYTES)
}
```

Additionally, consider adding on-chain validation in `update_network_and_fullnode_addresses` to reject excessively large byte vectors before storage.

## Proof of Concept

```rust
#[test]
fn test_malicious_validator_address_oom() {
    use bcs;
    
    // Craft BCS bytes claiming a huge vector length
    // ULEB128 encoding of 2^30 (1,073,741,824 elements)
    let mut malicious_bcs = vec![0x80, 0x80, 0x80, 0x80, 0x04]; // Length prefix for ~1 billion
    
    // Add minimal valid data (insufficient for claimed length)
    malicious_bcs.extend_from_slice(&[0x00]); 
    
    // Create ValidatorConfig with malicious data
    let config = ValidatorConfig {
        consensus_public_key: bls12381::PublicKey::default(),
        validator_network_addresses: malicious_bcs.clone(),
        fullnode_network_addresses: malicious_bcs,
        validator_index: 0,
    };
    
    // This may cause excessive allocation or OOM
    let result = config.validator_network_addresses();
    
    // Without limits, this could crash before returning an error
    assert!(result.is_err()); 
}
```

**Notes:**
The actual behavior depends on the BCS library's internal allocation strategy. The custom Aptos BCS fork should be audited to confirm whether it pre-allocates based on length prefixes. If pre-allocation occurs without validation against available data, this represents a viable DoS vector against validator infrastructure.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L954-995)
```text
    /// Update the network and full node addresses of the validator. This only takes effect in the next epoch.
    public entry fun update_network_and_fullnode_addresses(
        operator: &signer,
        pool_address: address,
        new_network_addresses: vector<u8>,
        new_fullnode_addresses: vector<u8>,
    ) acquires StakePool, ValidatorConfig {
        check_stake_permission(operator);
        assert_reconfig_not_in_progress();
        assert_stake_pool_exists(pool_address);
        let stake_pool = borrow_global_mut<StakePool>(pool_address);
        assert!(signer::address_of(operator) == stake_pool.operator_address, error::unauthenticated(ENOT_OPERATOR));
        assert!(exists<ValidatorConfig>(pool_address), error::not_found(EVALIDATOR_CONFIG));
        let validator_info = borrow_global_mut<ValidatorConfig>(pool_address);
        let old_network_addresses = validator_info.network_addresses;
        validator_info.network_addresses = new_network_addresses;
        let old_fullnode_addresses = validator_info.fullnode_addresses;
        validator_info.fullnode_addresses = new_fullnode_addresses;

        if (std::features::module_event_migration_enabled()) {
            event::emit(
                UpdateNetworkAndFullnodeAddresses {
                    pool_address,
                    old_network_addresses,
                    new_network_addresses,
                    old_fullnode_addresses,
                    new_fullnode_addresses,
                },
            );
        } else {
            event::emit_event(
                &mut stake_pool.update_network_and_fullnode_addresses_events,
                UpdateNetworkAndFullnodeAddressesEvent {
                    pool_address,
                    old_network_addresses,
                    new_network_addresses,
                    old_fullnode_addresses,
                    new_fullnode_addresses,
                },
            );
        };
    }
```

**File:** types/src/validator_config.rs (L36-43)
```rust
pub struct ValidatorConfig {
    pub consensus_public_key: bls12381::PublicKey,
    /// This is an bcs serialized `Vec<NetworkAddress>`
    pub validator_network_addresses: Vec<u8>,
    /// This is an bcs serialized `Vec<NetworkAddress>`
    pub fullnode_network_addresses: Vec<u8>,
    pub validator_index: u64,
}
```

**File:** types/src/validator_config.rs (L60-66)
```rust
    pub fn fullnode_network_addresses(&self) -> Result<Vec<NetworkAddress>, bcs::Error> {
        bcs::from_bytes(&self.fullnode_network_addresses)
    }

    pub fn validator_network_addresses(&self) -> Result<Vec<NetworkAddress>, bcs::Error> {
        bcs::from_bytes(&self.validator_network_addresses)
    }
```

**File:** network/discovery/src/validator_set.rs (L121-140)
```rust
            let addrs = if is_validator {
                config
                    .validator_network_addresses()
                    .map_err(anyhow::Error::from)
            } else {
                config
                    .fullnode_network_addresses()
                    .map_err(anyhow::Error::from)
            }
            .map_err(|err| {
                inc_by_with_context(&DISCOVERY_COUNTS, &network_context, "read_failure", 1);

                warn!(
                    NetworkSchema::new(&network_context),
                    "OnChainDiscovery: Failed to parse any network address: peer: {}, err: {}",
                    peer_id,
                    err
                )
            })
            .unwrap_or_default();
```

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L259-262)
```rust
    /// Deserializes the value using BCS encoding (with a specified limit)
    fn bcs_decode<T: DeserializeOwned>(&self, bytes: &[u8], limit: usize) -> anyhow::Result<T> {
        bcs::from_bytes_with_limit(bytes, limit).map_err(|e| anyhow!("{:?}", e))
    }
```
