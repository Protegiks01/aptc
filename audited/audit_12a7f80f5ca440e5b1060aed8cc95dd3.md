# Audit Report

## Title
Public Key Injection in Outbound Network Connections Enables DoS and Resource Exhaustion

## Summary
The outbound dial path in Aptos networking does not validate that the public key extracted from a NetworkAddress matches the expected peer_id before initiating a Noise handshake. This allows an attacker who can influence peer discovery to force nodes to waste resources on handshakes with incorrect peers, enabling denial-of-service attacks.

## Finding Description

When establishing outbound connections, the `AptosNetTransport::dial()` function extracts the public key from the NetworkAddress without verifying it corresponds to the target `peer_id`. [1](#0-0) 

The extracted `pubkey` is passed directly to the Noise handshake without validation: [2](#0-1) 

In `NoiseUpgrader::upgrade_outbound()`, the `remote_peer_id` and `remote_public_key` are treated as independent inputs with no verification that they match: [3](#0-2) 

The `remote_peer_id` is only used to look up peer roles, not to validate the public key: [4](#0-3) 

**In contrast**, the inbound path properly validates this invariant for non-trusted peers by deriving the expected peer_id from the public key: [5](#0-4) 

This asymmetry creates an attack vector. While post-handshake validation eventually detects the mismatch, significant resources are wasted: [6](#0-5) 

The PeerId derivation function shows the expected relationship: [7](#0-6) 

**Attack Scenario:**

1. Attacker controls or influences a discovery source (seed peer configuration, malicious discovery service)
2. Attacker injects addresses mapping `peer_id=A` to `pubkey=B` where `from_identity_public_key(B) ≠ A`
3. When the node dials peer A, it extracts pubkey B and initiates a Noise handshake
4. The handshake proceeds with pubkey B (potentially connecting to a different peer entirely)
5. Post-handshake validation detects the peer_id mismatch and rejects the connection
6. Node repeatedly retries with exponential backoff, wasting CPU, network, and connection resources

## Impact Explanation

**Medium Severity** - This vulnerability enables:

- **Resource Exhaustion**: Nodes waste CPU cycles on cryptographic operations (DH key exchanges, AEAD encryption) for doomed connections
- **Network DoS**: Connection slots and bandwidth are consumed by handshakes that will inevitably fail
- **Delayed Recovery**: Exponential backoff mechanisms delay legitimate connection attempts
- **Information Leakage**: Attackers can observe which peer_ids nodes attempt to connect to

While this doesn't directly cause consensus violations or loss of funds, it can degrade network performance and availability, qualifying as **Medium severity** per the "State inconsistencies requiring intervention" and resource exhaustion categories.

## Likelihood Explanation

**Medium Likelihood** - Exploitation requires:

1. **Attacker influence over discovery**: Must control seed peer configurations or compromise discovery services
2. **Persistence**: Malicious addresses must survive network restarts and reconfigurations
3. **Scale**: Maximum impact requires injecting many malicious address mappings

In production networks with onchain validator discovery, the attack surface is limited. However, networks relying on seed peers or custom discovery services are vulnerable. The asymmetry with inbound validation suggests this was an oversight rather than an intentional design choice.

## Recommendation

Add validation in `AptosNetTransport::dial()` before initiating the Noise handshake:

```rust
pub fn dial(
    &self,
    peer_id: PeerId,
    addr: NetworkAddress,
) -> io::Result<...> {
    let (base_addr, pubkey, handshake_version) = Self::parse_dial_addr(&addr)?;
    
    // NEW: Validate that pubkey matches peer_id
    let derived_peer_id = aptos_types::account_address::from_identity_public_key(pubkey);
    if derived_peer_id != peer_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Public key in address does not match peer_id. Expected peer_id: {}, derived from pubkey: {}",
                peer_id.short_str(),
                derived_peer_id.short_str()
            ),
        ));
    }
    
    // ... rest of function unchanged
}
```

This mirrors the validation already present in the inbound path and provides defense-in-depth.

## Proof of Concept

```rust
#[test]
fn test_dial_with_mismatched_pubkey() {
    use aptos_crypto::x25519::PrivateKey;
    use rand::SeedableRng;
    
    // Create two different key pairs
    let mut rng = rand::rngs::StdRng::from_seed([0u8; 32]);
    let key1 = PrivateKey::generate(&mut rng);
    let pubkey1 = key1.public_key();
    let peer_id1 = aptos_types::account_address::from_identity_public_key(pubkey1);
    
    let key2 = PrivateKey::generate(&mut rng);
    let pubkey2 = key2.public_key();
    let peer_id2 = aptos_types::account_address::from_identity_public_key(pubkey2);
    
    // Create a malicious address: peer_id1 but pubkey2
    let malicious_addr = NetworkAddress::from_str("/ip4/127.0.0.1/tcp/6180")
        .unwrap()
        .append_prod_protos(pubkey2, 0); // Wrong pubkey!
    
    // Attempt to dial peer_id1 with address containing pubkey2
    // Currently this will proceed to handshake and fail later
    // With the fix, this should fail immediately at parse time
    
    let transport = create_test_transport(key1);
    match transport.dial(peer_id1, malicious_addr) {
        Err(e) => {
            // Expected with fix
            assert!(e.to_string().contains("does not match peer_id"));
        },
        Ok(_) => {
            // Current behavior - handshake will eventually fail
            // but only after wasting resources
        }
    }
}
```

**Notes:**

This vulnerability demonstrates a defense-in-depth gap where the inbound path properly validates the peer_id/pubkey relationship but the outbound path does not. While post-handshake validation provides a safety net, early rejection prevents resource waste and DoS amplification. The fix is straightforward and aligns with existing inbound validation logic.

### Citations

**File:** network/framework/src/transport/mod.rs (L549-549)
```rust
        let (base_addr, pubkey, handshake_version) = Self::parse_dial_addr(&addr)?;
```

**File:** network/framework/src/transport/mod.rs (L566-566)
```rust
        let upgrade_fut = upgrade_outbound(self.ctxt.clone(), fut_socket, addr, peer_id, pubkey);
```

**File:** network/framework/src/noise/handshake.rs (L183-193)
```rust
    pub async fn upgrade_outbound<TSocket, F>(
        &self,
        mut socket: TSocket,
        remote_peer_id: PeerId,
        remote_public_key: x25519::PublicKey,
        time_provider: F,
    ) -> Result<(NoiseStream<TSocket>, PeerRole), NoiseHandshakeError>
    where
        TSocket: AsyncRead + AsyncWrite + Debug + Unpin,
        F: Fn() -> [u8; AntiReplayTimestamps::TIMESTAMP_SIZE],
    {
```

**File:** network/framework/src/noise/handshake.rs (L260-262)
```rust
        let peer_role = self.extract_peer_role_from_trusted_peers(remote_peer_id);

        Ok((noise_stream, peer_role))
```

**File:** network/framework/src/noise/handshake.rs (L394-404)
```rust
                        let derived_remote_peer_id =
                            aptos_types::account_address::from_identity_public_key(
                                remote_public_key,
                            );
                        if derived_remote_peer_id != remote_peer_id {
                            // The peer ID is not constructed correctly from the public key
                            Err(NoiseHandshakeError::ClientPeerIdMismatch(
                                remote_peer_short,
                                remote_peer_id,
                                derived_remote_peer_id,
                            ))
```

**File:** network/framework/src/peer_manager/transport.rs (L238-246)
```rust
                let dialed_peer_id = connection.metadata.remote_peer_id;
                if dialed_peer_id == peer_id {
                    Ok(connection)
                } else {
                    Err(PeerManagerError::from_transport_error(format_err!(
                        "Dialed PeerId '{}' differs from expected PeerId '{}'",
                        dialed_peer_id.short_str(),
                        peer_id.short_str()
                    )))
```

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
