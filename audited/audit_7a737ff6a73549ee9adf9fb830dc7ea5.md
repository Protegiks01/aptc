# Audit Report

## Title
Guaranteed Panic in Secret Share Aggregation Due to Empty Weight HashMap

## Summary
The secret sharing implementation contains a critical implementation bug where `get_peer_weights()` returns an empty HashMap while `get_peer_weight()` returns hardcoded value 1. When `add_self_share()` is called, it attempts to lookup author weights from the empty HashMap, causing an immediate panic that would crash all validator nodes if the secret sharing feature were enabled.

## Finding Description

The `SecretShareConfig` struct has two methods for retrieving peer weights: [1](#0-0) 

The `get_peer_weight()` method returns a hardcoded value of 1 for any peer, while `get_peer_weights()` returns a reference to the `weights` field, which is initialized as an empty HashMap: [2](#0-1) 

When processing secret shares, the `SecretShareStore` uses these methods inconsistently:

1. In `add_share()`, it calls `get_peer_weight()` to get individual share weights (returns 1): [3](#0-2) 

2. In `add_self_share()`, it calls `get_peer_weights()` to get all weights (returns empty HashMap): [4](#0-3) 

The empty HashMap is then passed to `add_share_with_metadata()`, which attempts to lookup the author's weight: [5](#0-4) 

At line 162-164, the code performs `share_weights.get(share.author()).expect("Author must exist in weights")` on an empty HashMap, causing an immediate panic. Additionally, the `retain()` method called at line 168 also expects weights to exist: [6](#0-5) 

This causes a guaranteed panic when any validator attempts to process its own secret share.

## Impact Explanation

**Severity: HIGH** (if feature were enabled)

This bug would cause **total loss of network liveness** if the secret sharing feature were activated. Every validator node would crash immediately when attempting to process its own secret share during consensus, resulting in:

- Complete network halt (all validators crash simultaneously)
- Loss of block production and transaction processing
- Requires emergency hotfix deployment to restore network

However, **the feature is currently disabled** in production code: [7](#0-6) 

At line 549, `None` is passed as the `secret_sharing_config`, meaning the `SecretShareManager` is not instantiated.

## Likelihood Explanation

**Current Likelihood: Not Applicable** - The secret sharing feature is currently disabled in production.

**Future Likelihood (if enabled): Certain** - If the feature were enabled through configuration or governance, this bug would trigger with 100% probability on every block that requires secret share processing. The panic would affect all validators simultaneously.

This is **not an exploitable vulnerability** in the traditional security sense because:
1. No external attacker can trigger this behavior
2. It requires the feature to be enabled through privileged operations (governance/deployment)
3. Once enabled, it manifests automatically without attacker interaction
4. All validators are equally affected (not a targeted attack)

This is a **latent implementation bug** that would become a deployment blocker if the feature were activated, rather than an exploitable security vulnerability.

## Recommendation

The `SecretShareConfig` implementation is incomplete. The `weights` HashMap should be properly populated during initialization based on the validator set. Two approaches:

**Option 1: Populate weights during construction**
```rust
pub fn new(
    author: Author,
    epoch: u64,
    validator: Arc<ValidatorVerifier>,
    digest_key: DigestKey,
    msk_share: MasterSecretKeyShare,
    verification_keys: Vec<VerificationKey>,
    config: <FPTXWeighted as BatchThresholdEncryption>::ThresholdConfig,
    encryption_key: EncryptionKey,
) -> Self {
    let weights: HashMap<Author, u64> = validator
        .get_ordered_account_addresses_iter()
        .map(|addr| (addr, validator.get_voting_power(addr).unwrap()))
        .collect();
    
    Self {
        _author: author,
        _epoch: epoch,
        validator,
        digest_key,
        msk_share,
        verification_keys,
        config,
        encryption_key,
        weights,
    }
}

pub fn get_peer_weight(&self, peer: &Author) -> u64 {
    *self.weights.get(peer).expect("Peer must exist in weights")
}
```

**Option 2: Use the same weight source consistently**
Make both methods use the validator verifier's voting power directly:
```rust
pub fn get_peer_weight(&self, peer: &Author) -> u64 {
    self.validator.get_voting_power(peer).unwrap_or(0)
}

pub fn get_peer_weights(&self) -> HashMap<Author, u64> {
    self.validator
        .get_ordered_account_addresses_iter()
        .map(|addr| (addr, self.validator.get_voting_power(addr).unwrap_or(0)))
        .collect()
}
```

## Proof of Concept

This Rust unit test demonstrates the panic:

```rust
#[test]
#[should_panic(expected = "Author must exist in weights")]
fn test_add_self_share_panics_with_empty_weights() {
    use aptos_types::secret_sharing::*;
    use aptos_consensus_types::common::Author;
    use std::sync::Arc;
    
    // Create a SecretShareConfig with empty weights
    let validator = Arc::new(create_test_validator_verifier());
    let config = SecretShareConfig::new(
        Author::random(),
        1,
        validator,
        create_test_digest_key(),
        create_test_msk_share(),
        vec![],
        create_test_threshold_config(),
        create_test_encryption_key(),
    );
    
    // Create SecretShareStore
    let (tx, _rx) = unbounded();
    let mut store = SecretShareStore::new(1, Author::random(), config, tx);
    
    // Create a self share
    let self_share = create_test_secret_share();
    
    // This will panic because get_peer_weights() returns empty HashMap
    store.add_self_share(self_share).expect("Should panic before reaching here");
}
```

---

## Notes

**Answer to Original Question**: Yes, `get_peer_weight()` and `get_peer_weights()` return inconsistent values, but this is not due to validator set changes—it's a fundamental implementation bug where one returns hardcoded 1 and the other returns an empty HashMap. This inconsistency causes an immediate panic regardless of validator set state.

**Current Status**: This is a latent bug in disabled code, not an actively exploitable vulnerability. While the impact would be severe (HIGH) if activated, it does not meet the criteria for an exploitable security vulnerability because:
- No unprivileged attacker can trigger it
- Requires privileged action to enable the feature
- Affects all nodes equally (self-inflicted DoS)
- Is more accurately classified as a "deployment blocker" than a security vulnerability

The code requires completion before the secret sharing feature can be safely enabled in production.

### Citations

**File:** types/src/secret_sharing.rs (L145-169)
```rust
    weights: HashMap<Author, u64>,
}

impl SecretShareConfig {
    pub fn new(
        author: Author,
        epoch: u64,
        validator: Arc<ValidatorVerifier>,
        digest_key: DigestKey,
        msk_share: MasterSecretKeyShare,
        verification_keys: Vec<VerificationKey>,
        config: <FPTXWeighted as BatchThresholdEncryption>::ThresholdConfig,
        encryption_key: EncryptionKey,
    ) -> Self {
        Self {
            _author: author,
            _epoch: epoch,
            validator,
            digest_key,
            msk_share,
            verification_keys,
            config,
            encryption_key,
            weights: HashMap::new(),
        }
```

**File:** types/src/secret_sharing.rs (L196-202)
```rust
    pub fn get_peer_weight(&self, _peer: &Author) -> u64 {
        1
    }

    pub fn get_peer_weights(&self) -> &HashMap<Author, u64> {
        &self.weights
    }
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L74-81)
```rust
    fn retain(&mut self, metadata: &SecretShareMetadata, weights: &HashMap<Author, u64>) {
        self.shares.retain(|_, share| share.metadata == *metadata);
        self.total_weight = self
            .shares
            .keys()
            .map(|author| weights.get(author).expect("Author must exist for weight"))
            .sum();
    }
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L156-182)
```rust
    fn add_share_with_metadata(
        &mut self,
        share: SecretShare,
        share_weights: &HashMap<Author, u64>,
    ) -> anyhow::Result<()> {
        let item = std::mem::replace(self, Self::new(Author::ONE));
        let share_weight = *share_weights
            .get(share.author())
            .expect("Author must exist in weights");
        let new_item = match item {
            SecretShareItem::PendingMetadata(mut share_aggregator) => {
                let metadata = share.metadata.clone();
                share_aggregator.retain(share.metadata(), share_weights);
                share_aggregator.add_share(share, share_weight);
                SecretShareItem::PendingDecision {
                    metadata,
                    share_aggregator,
                }
            },
            SecretShareItem::PendingDecision { .. } => {
                bail!("Cannot add self share in PendingDecision state");
            },
            SecretShareItem::Decided { .. } => return Ok(()),
        };
        let _ = std::mem::replace(self, new_item);
        Ok(())
    }
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L237-257)
```rust
    pub fn add_self_share(&mut self, share: SecretShare) -> anyhow::Result<()> {
        assert!(
            self.self_author == share.author,
            "Only self shares can be added with metadata"
        );
        let peer_weights = self.secret_share_config.get_peer_weights();
        let metadata = share.metadata();
        ensure!(metadata.epoch == self.epoch, "Share from different epoch");
        ensure!(
            metadata.round <= self.highest_known_round + FUTURE_ROUNDS_TO_ACCEPT,
            "Share from future round"
        );

        let item = self
            .secret_share_map
            .entry(metadata.round)
            .or_insert_with(|| SecretShareItem::new(self.self_author));
        item.add_share_with_metadata(share, peer_weights)?;
        item.try_aggregate(&self.secret_share_config, self.decision_tx.clone());
        Ok(())
    }
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L259-275)
```rust
    pub fn add_share(&mut self, share: SecretShare) -> anyhow::Result<bool> {
        let weight = self.secret_share_config.get_peer_weight(share.author());
        let metadata = share.metadata();
        ensure!(metadata.epoch == self.epoch, "Share from different epoch");
        ensure!(
            metadata.round <= self.highest_known_round + FUTURE_ROUNDS_TO_ACCEPT,
            "Share from future round"
        );

        let item = self
            .secret_share_map
            .entry(metadata.round)
            .or_insert_with(|| SecretShareItem::new(self.self_author));
        item.add_share(share, weight)?;
        item.try_aggregate(&self.secret_share_config, self.decision_tx.clone());
        Ok(item.has_decision())
    }
```

**File:** consensus/src/pipeline/execution_client.rs (L543-558)
```rust
        let maybe_rand_msg_tx = self.spawn_decoupled_execution(
            maybe_consensus_key,
            commit_signer_provider,
            epoch_state.clone(),
            rand_config,
            fast_rand_config,
            None,
            onchain_consensus_config,
            rand_msg_rx,
            secret_sharing_msg_rx,
            highest_committed_round,
            self.consensus_config.enable_pre_commit,
            self.consensus_observer_config,
            self.consensus_publisher.clone(),
            network_sender.clone(),
        );
```
