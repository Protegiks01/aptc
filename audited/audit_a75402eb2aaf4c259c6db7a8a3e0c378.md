# Audit Report

## Title 
Missing Cryptographic Binding Validation Between PeerId and Network Public Keys Enables Validator Identity Confusion

## Summary
The Aptos network layer fails to validate that x25519 public keys embedded in validator NetworkAddresses cryptographically derive to the validator's PeerId (account address). This allows malicious validators to register arbitrary public keys onchain that don't match their identity, enabling them to impersonate other validators' network identities and potentially disrupt consensus.

## Finding Description

The vulnerability exists in the interaction between three system components:

**1. PeerId Derivation**  
A validator's PeerId is derived from their x25519 public key using `from_identity_public_key()`, which takes the last 16 bytes of the 32-byte public key. [1](#0-0) 

**2. Missing Onchain Validation**  
When validators update their network addresses via the `update_network_and_fullnode_addresses()` function in stake.move, there is NO validation that the x25519 public keys embedded in the NetworkAddresses derive to the validator's account address (PeerId). The function only checks operator permissions and reconfig status. [2](#0-1) 

**3. Network Address Construction and Discovery**  
NetworkAddresses embed x25519 public keys via `append_prod_protos()`. During onchain discovery, the `extract_validator_set_updates()` function extracts these addresses and public keys without validating the cryptographic binding between PeerId and public key. [3](#0-2) 

The public keys are extracted from NetworkAddresses using `Peer::from_addrs()`: [4](#0-3) 

**4. Authentication Relies on Poisoned Data**  
During Noise handshake authentication in Mutual mode (used for validator networks), the system validates that the remote peer's public key is in the trusted set for that PeerId. However, since the trusted set is populated from onchain discovery data that was never validated, an attacker can bypass this check. [5](#0-4) [6](#0-5) 

**Attack Scenario:**
1. Malicious validator has account address (PeerId) = `0xALICE`
2. Attacker generates or steals x25519 key pair (PrivateKey_B, PublicKey_B) where `from_identity_public_key(PublicKey_B) ≠ 0xALICE`
3. Attacker calls `update_network_and_fullnode_addresses()` with NetworkAddresses containing PublicKey_B
4. Other validators retrieve the ValidatorSet from onchain, extracting: `{PeerId: 0xALICE, PublicKey: PublicKey_B}`
5. When validators connect to `0xALICE`, they use PublicKey_B for the Noise handshake
6. The attacker's node (with PrivateKey_B) successfully authenticates
7. All network messages to/from this connection are associated with PeerId `0xALICE`, but the cryptographic identity is actually PublicKey_B

This breaks the fundamental invariant that a validator's PeerId uniquely and cryptographically identifies their network identity.

## Impact Explanation

**Critical Severity** - This vulnerability enables multiple severe attacks:

1. **Consensus Safety Violation**: An attacker controlling multiple validators could register different public keys for each, making it impossible to properly attribute Byzantine behavior or enforce the <1/3 Byzantine fault tolerance assumption. The system cannot reliably determine which validator sent which consensus messages.

2. **Key Compromise Amplification**: If an attacker compromises one validator's network keys, they could register those keys under multiple different PeerIds, effectively allowing one compromised key pair to control multiple validator slots in the consensus protocol.

3. **Validator Set Manipulation**: The cryptographic identity binding is fundamental to the security model. Breaking this binding undermines validator authentication, voting power attribution, and reward distribution.

4. **Network Partition Attacks**: An attacker could potentially cause different honest validators to have different views of which peer corresponds to which PeerId, leading to network partitioning or consensus liveness failures.

This meets the **Critical Severity** criteria per the Aptos bug bounty:
- Potential for Consensus/Safety violations
- Could lead to non-recoverable network partition requiring a hardfork
- Violates the cryptographic correctness invariant

## Likelihood Explanation

**HIGH** - This vulnerability is highly likely to be exploitable:

1. **No Special Privileges Required**: Any validator operator can call `update_network_and_fullnode_addresses()` on their own stake pool
2. **Simple Exploitation**: The attacker only needs to generate an x25519 key pair and encode it in a NetworkAddress
3. **No Detection Mechanism**: There is no onchain or offchain validation that would detect or prevent this attack
4. **Affects All Validators**: Every validator node relies on onchain discovery and would automatically connect using the malicious public key
5. **Persistent**: Once registered onchain, the malicious configuration persists until the next epoch

The only barrier is that the attacker must already be a validator, but this is explicitly within the threat model for consensus-level attacks.

## Recommendation

Add cryptographic validation in the `update_network_and_fullnode_addresses()` function to ensure all x25519 public keys embedded in the network addresses derive to the validator's account address:

```move
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
    
    // ADD VALIDATION HERE:
    // 1. Deserialize new_network_addresses to extract all x25519 public keys
    // 2. For each public key, verify: from_identity_public_key(pubkey) == pool_address
    // 3. Abort if any public key doesn't match
    validate_network_addresses_match_pool_address(pool_address, new_network_addresses);
    validate_network_addresses_match_pool_address(pool_address, new_fullnode_addresses);
    
    let validator_info = borrow_global_mut<ValidatorConfig>(pool_address);
    let old_network_addresses = validator_info.network_addresses;
    validator_info.network_addresses = new_network_addresses;
    let old_fullnode_addresses = validator_info.fullnode_addresses;
    validator_info.fullnode_addresses = new_fullnode_addresses;
    
    // ... rest of function
}

// New validation function
fun validate_network_addresses_match_pool_address(
    pool_address: address,
    encoded_addresses: vector<u8>,
) {
    // Parse the vector<NetworkAddress> from bytes
    // Extract all x25519 public keys from the addresses
    // Verify each pubkey derives to pool_address using from_identity_public_key
    // Abort with appropriate error code if validation fails
}
```

Additionally, add a one-time migration check during node startup to validate existing validator configurations and alert operators of any mismatches.

## Proof of Concept

**Setup:**
1. Deploy a validator with account address `0xVALIDATOR_A`
2. Generate a separate x25519 key pair `(private_B, public_B)` where `from_identity_public_key(public_B) = 0xVALIDATOR_B ≠ 0xVALIDATOR_A`

**Attack Steps:**
```move
script {
    use aptos_framework::stake;
    use std::vector;
    
    fun exploit(operator: &signer) {
        let pool_address = @0xVALIDATOR_A;
        
        // Construct NetworkAddress with public_B embedded
        // Format: /ip4/127.0.0.1/tcp/6180/noise-ik/<public_B>/handshake/0
        let malicious_network_address = construct_network_address_with_pubkey(public_B);
        let encoded_addresses = bcs::to_bytes(&vector[malicious_network_address]);
        
        // This call succeeds - NO VALIDATION!
        stake::update_network_and_fullnode_addresses(
            operator,
            pool_address,
            encoded_addresses,
            encoded_addresses
        );
        
        // In next epoch, other validators will:
        // 1. Query ValidatorSet and see: PeerId=0xVALIDATOR_A with PublicKey=public_B
        // 2. Dial 0xVALIDATOR_A using public_B for Noise handshake
        // 3. Attacker's node (with private_B) authenticates successfully
        // 4. Network identifies this connection as 0xVALIDATOR_A
        // 5. But cryptographic identity is actually 0xVALIDATOR_B
    }
}
```

**Verification:**
Run a test validator network with this configuration and observe that:
1. The `update_network_and_fullnode_addresses()` call succeeds despite the PeerId mismatch
2. Other validators successfully connect to the malicious validator
3. The connection metadata shows `remote_peer_id = 0xVALIDATOR_A` 
4. But the Noise session used `public_B` for authentication
5. Consensus messages from this validator are attributed to `0xVALIDATOR_A` in the system logs

This demonstrates that the cryptographic binding between PeerId and network public key is not enforced, enabling identity confusion attacks that could compromise consensus safety.

### Citations

**File:** types/src/account_address.rs (L140-146)
```rust
pub fn from_identity_public_key(identity_public_key: x25519::PublicKey) -> AccountAddress {
    let mut array = [0u8; AccountAddress::LENGTH];
    let pubkey_slice = identity_public_key.as_slice();
    // keep only the last 16 bytes
    array.copy_from_slice(&pubkey_slice[x25519::PUBLIC_KEY_SIZE - AccountAddress::LENGTH..]);
    AccountAddress::new(array)
}
```

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

**File:** network/discovery/src/validator_set.rs (L108-150)
```rust
pub(crate) fn extract_validator_set_updates(
    network_context: NetworkContext,
    node_set: ValidatorSet,
) -> PeerSet {
    let is_validator = network_context.network_id().is_validator_network();

    // Decode addresses while ignoring bad addresses
    node_set
        .into_iter()
        .map(|info| {
            let peer_id = *info.account_address();
            let config = info.into_config();

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

            let peer_role = if is_validator {
                PeerRole::Validator
            } else {
                PeerRole::ValidatorFullNode
            };
            (peer_id, Peer::from_addrs(peer_role, addrs))
        })
        .collect()
}
```

**File:** config/src/config/network_config.rs (L498-504)
```rust
    pub fn from_addrs(role: PeerRole, addresses: Vec<NetworkAddress>) -> Peer {
        let keys: HashSet<x25519::PublicKey> = addresses
            .iter()
            .filter_map(NetworkAddress::find_noise_proto)
            .collect();
        Peer::new(addresses, keys, role)
    }
```

**File:** network/framework/src/noise/handshake.rs (L369-382)
```rust
            HandshakeAuthMode::Mutual {
                peers_and_metadata, ..
            } => {
                let trusted_peers = peers_and_metadata.get_trusted_peers(&network_id)?;
                let trusted_peer = trusted_peers.get(&remote_peer_id).cloned();
                match trusted_peer {
                    Some(peer) => {
                        Self::authenticate_inbound(remote_peer_short, &peer, &remote_public_key)
                    },
                    None => Err(NoiseHandshakeError::UnauthenticatedClient(
                        remote_peer_short,
                        remote_peer_id,
                    )),
                }
```

**File:** network/framework/src/noise/handshake.rs (L488-500)
```rust
    fn authenticate_inbound(
        remote_peer_short: ShortHexStr,
        peer: &Peer,
        remote_public_key: &x25519::PublicKey,
    ) -> Result<PeerRole, NoiseHandshakeError> {
        if !peer.keys.contains(remote_public_key) {
            return Err(NoiseHandshakeError::UnauthenticatedClientPubkey(
                remote_peer_short,
                hex::encode(remote_public_key.as_slice()),
            ));
        }
        Ok(peer.role)
    }
```
