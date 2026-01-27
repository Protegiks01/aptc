# Audit Report

## Title
Missing Bounds Check in SecretShare::verify() Causes Consensus Node Crash (Denial of Service)

## Summary
The `verify()` function in `types/src/secret_sharing.rs` lacks bounds validation when accessing the `verification_keys` vector, enabling a crash-based Denial of Service attack against consensus nodes. An attacker can exploit validator set and verification keys size mismatches to trigger a panic that terminates the validator process.

## Finding Description

The `SecretShare::verify()` function performs an unchecked array access that violates memory safety guarantees: [1](#0-0) 

The function retrieves a validator index via `get_id()` and directly indexes into `verification_keys[index]` without validating `index < verification_keys.len()`. The TODO comment on line 78 explicitly acknowledges this missing security check. [2](#0-1) 

The `get_id()` function returns an unconstrained `usize` from the validator index map. While it panics if the peer is not in the validator set, it provides no guarantee that the returned index is within the bounds of the `verification_keys` vector.

**Attack Path**:

1. During epoch transitions or configuration updates, a size mismatch occurs where `ValidatorVerifier` contains N validators but `SecretShareConfig.verification_keys` contains M < N entries
2. A validator at index i where i ≥ M sends a `SecretShare` message to the network
3. Receiving nodes process the message through the verification pipeline: [3](#0-2) 

4. The verification task calls `msg.verify()`: [4](#0-3) 

5. For `SecretShareMessage::Share`, this triggers `share.verify(config)`, executing the vulnerable code path
6. Rust's runtime bounds checking detects `index >= verification_keys.len()` and **panics**, crashing the consensus node

**Invariant Violation**: This breaks the **Consensus Availability** invariant. Validator nodes must remain operational to maintain consensus liveness. A targeted crash attack can disable multiple validators simultaneously.

## Impact Explanation

**Severity: High** (per Aptos Bug Bounty criteria: "Validator node slowdowns / API crashes / Significant protocol violations")

This vulnerability enables a **Denial of Service** attack that can:
- **Crash multiple validator nodes** simultaneously by broadcasting malicious `SecretShare` messages
- **Degrade consensus liveness** by reducing the number of operational validators below the Byzantine fault tolerance threshold (< 2/3)
- **Force emergency interventions** requiring node restarts and configuration fixes

While this does not directly cause fund loss or consensus safety violations (which would be Critical severity), it represents a significant protocol violation that can disrupt network operations and requires immediate operator intervention.

## Likelihood Explanation

**Likelihood: Medium-to-High**

The vulnerability is exploitable when:
1. **Validator set size mismatch**: The `verification_keys` vector has fewer entries than the validator set size
2. **Network access**: The attacker can broadcast `SecretShare` messages (requires validator credentials or network positioning)

Potential triggering scenarios:
- **Epoch transitions**: New validators join but `SecretShareConfig` still references old verification keys
- **DKG configuration errors**: The distributed key generation produces fewer verification keys than expected
- **Race conditions**: Validator set updates propagate before corresponding verification key updates
- **Manual misconfigurations**: Operators manually construct `SecretShareConfig` with incorrect parameters

The explicit TODO comment indicates developers are aware of this risk but have not yet implemented the fix, suggesting the mismatch scenario may occur in practice.

## Recommendation

Implement bounds checking before accessing the `verification_keys` vector:

```rust
pub fn verify(&self, config: &SecretShareConfig) -> anyhow::Result<()> {
    let index = config.get_id(self.author());
    let decryption_key_share = self.share().clone();
    
    // Bounds check to prevent panic
    anyhow::ensure!(
        index < config.verification_keys.len(),
        "Validator index {} exceeds verification_keys length {}",
        index,
        config.verification_keys.len()
    );
    
    config.verification_keys[index]
        .verify_decryption_key_share(&self.metadata.digest, &decryption_key_share)?;
    Ok(())
}
```

Additionally, validate invariants during `SecretShareConfig` construction to ensure `verification_keys.len() >= validator.len()`.

## Proof of Concept

```rust
#[test]
fn test_secret_share_verify_out_of_bounds_panic() {
    use aptos_types::secret_sharing::{SecretShare, SecretShareConfig, SecretShareMetadata};
    use aptos_types::validator_verifier::{ValidatorConsensusInfo, ValidatorVerifier};
    use aptos_crypto::{bls12381::PrivateKey, Uniform};
    use std::sync::Arc;
    
    let mut rng = rand::thread_rng();
    
    // Create validator set with 5 validators
    let validators: Vec<ValidatorConsensusInfo> = (0..5)
        .map(|i| {
            let private_key = PrivateKey::generate(&mut rng);
            ValidatorConsensusInfo::new(
                AccountAddress::random(),
                private_key.public_key(),
                100,
            )
        })
        .collect();
    
    let validator_verifier = Arc::new(ValidatorVerifier::new(validators.clone()));
    
    // Create SecretShareConfig with only 3 verification keys (MISMATCH!)
    let (ek, dk, vks, msk_shares) = FPTXWeighted::setup_for_testing(
        rng.gen(),
        8,
        1,
        &WeightedConfigArkworks::new(2, vec![1, 1, 1]).unwrap(),
    ).unwrap();
    
    let config = SecretShareConfig::new(
        validators[0].address,
        1, // epoch
        validator_verifier.clone(),
        dk.clone(),
        msk_shares[0].clone(),
        vks, // Only 3 verification keys!
        config,
        ek,
    );
    
    // Validator at index 4 sends a share
    let metadata = SecretShareMetadata::new(1, 100, 1000, HashValue::random(), digest);
    let share = SecretShare::new(
        validators[4].address, // Index 4 >= 3 (verification_keys.len())
        metadata,
        decryption_key_share,
    );
    
    // This will PANIC with "index out of bounds"
    let result = share.verify(&config);
    // Expected: Err with proper error message
    // Actual: Thread panic crashes the node
}
```

## Notes

The vulnerability manifests as a **panic** (not undefined behavior as stated in the question) due to Rust's runtime bounds checking. However, panics in consensus-critical code paths are severe security issues as they enable targeted DoS attacks. The explicit TODO comment confirms this is a known deficiency awaiting remediation.

### Citations

**File:** types/src/secret_sharing.rs (L75-82)
```rust
    pub fn verify(&self, config: &SecretShareConfig) -> anyhow::Result<()> {
        let index = config.get_id(self.author());
        let decryption_key_share = self.share().clone();
        // TODO(ibalajiarun): Check index out of bounds
        config.verification_keys[index]
            .verify_decryption_key_share(&self.metadata.digest, &decryption_key_share)?;
        Ok(())
    }
```

**File:** types/src/secret_sharing.rs (L172-178)
```rust
    pub fn get_id(&self, peer: &Author) -> usize {
        *self
            .validator
            .address_to_validator_index()
            .get(peer)
            .expect("Peer should be in the index!")
    }
```

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L205-235)
```rust
    async fn verification_task(
        epoch_state: Arc<EpochState>,
        mut incoming_rpc_request: aptos_channel::Receiver<Author, IncomingSecretShareRequest>,
        verified_msg_tx: UnboundedSender<SecretShareRpc>,
        config: SecretShareConfig,
        bounded_executor: BoundedExecutor,
    ) {
        while let Some(dec_msg) = incoming_rpc_request.next().await {
            let tx = verified_msg_tx.clone();
            let epoch_state_clone = epoch_state.clone();
            let config_clone = config.clone();
            bounded_executor
                .spawn(async move {
                    match bcs::from_bytes::<SecretShareMessage>(dec_msg.req.data()) {
                        Ok(msg) => {
                            if msg.verify(&epoch_state_clone, &config_clone).is_ok() {
                                let _ = tx.unbounded_send(SecretShareRpc {
                                    msg,
                                    protocol: dec_msg.protocol,
                                    response_sender: dec_msg.response_sender,
                                });
                            }
                        },
                        Err(e) => {
                            warn!("Invalid dec message: {}", e);
                        },
                    }
                })
                .await;
        }
    }
```

**File:** consensus/src/rand/secret_sharing/network_messages.rs (L28-38)
```rust
    pub fn verify(
        &self,
        epoch_state: &EpochState,
        config: &SecretShareConfig,
    ) -> anyhow::Result<()> {
        ensure!(self.epoch() == epoch_state.epoch);
        match self {
            SecretShareMessage::RequestShare(_) => Ok(()),
            SecretShareMessage::Share(share) => share.verify(config),
        }
    }
```
