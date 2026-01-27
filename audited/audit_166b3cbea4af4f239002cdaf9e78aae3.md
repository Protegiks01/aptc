# Audit Report

## Title
Economic Security Violation: Secret Sharing Treats All Validators Equally Regardless of Stake

## Summary
The secret sharing threshold mechanism ignores validator stake and treats all validators with equal weight, fundamentally breaking the economic security model where reconstruction should require a threshold of stake, not merely a threshold of validator count.

## Finding Description

The `SecretShareConfig::get_peer_weight()` function returns a hardcoded constant value of 1 for all validators, completely ignoring their actual voting power (stake). [1](#0-0) 

This weight is used during secret share aggregation to determine whether enough shares have been collected to reconstruct decryption keys. [2](#0-1)  The aggregator accumulates weights and checks against the threshold. [3](#0-2) [4](#0-3) 

**The Critical Flaw:**

The system uses a `WeightedConfigArkworks` that is designed to support stake-weighted thresholds. [5](#0-4)  This weighted configuration has the infrastructure to track individual player weights. [6](#0-5) 

Furthermore, validator stake information IS available through the `ValidatorVerifier` which is stored in the config. [7](#0-6)  The `ValidatorVerifier` provides voting power for each validator. [8](#0-7) 

However, instead of using this available weight information, the implementation returns constant 1, making the system vulnerable to low-stake validator attacks.

**Attack Scenario:**

Consider a validator set with 10 validators having stakes: `[100, 100, 100, 100, 100, 1, 1, 1, 1, 1]` (total stake = 505).

In a correctly implemented stake-weighted system:
- Threshold should be ~337 stake units (2/3 of total)
- Attacker controlling 5 small validators (stake 5) + 2 large validators (stake 200) = total stake 205
- This represents only 40% of total stake and should be INSUFFICIENT

With the current bug treating all validators as weight 1:
- Threshold becomes validator count-based instead of stake-based  
- The same attacker with 7 validators (regardless of their combined stake) could potentially meet count-based thresholds
- Economic security assumption violated: threshold can be met without sufficient stake representation

This breaks **Critical Invariant #5: "Governance Integrity: Voting power must be correctly calculated from stake"** by extension to the secret sharing subsystem, which should also respect stake-based security thresholds.

## Impact Explanation

**HIGH Severity** - This constitutes a significant protocol violation per the Aptos bug bounty criteria.

The vulnerability violates the fundamental economic security model of the blockchain:

1. **Economic Security Model Violation**: Proof-of-Stake systems rely on the assumption that security thresholds are based on economic stake, not validator count. This makes Sybil attacks (creating many low-stake validators) more viable.

2. **Secret Sharing Subsystem Compromise**: The secret sharing mechanism is used for batch encryption in the consensus pipeline. [9](#0-8)  If decryption keys can be reconstructed with insufficient stake, it could lead to premature information disclosure or consensus inconsistencies.

3. **Inconsistency with Randomness Generation**: The randomness generation path (`RandConfig`) correctly implements stake-weighted thresholds. [10](#0-9)  This inconsistency between subsystems is a design flaw.

While not reaching CRITICAL severity (which requires consensus safety violations or fund loss), this is a significant economic security violation that undermines the stake-based security model.

## Likelihood Explanation

**MODERATE Likelihood:**

The vulnerability is currently present in the codebase with a TODO comment acknowledging it needs fixing. [11](#0-10) 

Exploitation requirements:
- Attacker must operate multiple validator nodes (feasible by staking across multiple accounts)
- The secret sharing feature must be actively used in the network
- Attacker needs sufficient validator count to meet thresholds (easier with equal weights than with stake-based weights)

The likelihood is reduced by:
- It may be a known issue marked for future implementation
- Requires running validator infrastructure
- Limited to secret sharing subsystem rather than core consensus

## Recommendation

**Fix:** Modify `SecretShareConfig::get_peer_weight()` to return actual validator stake instead of constant 1.

The implementation should leverage the existing `ValidatorVerifier` to retrieve voting power:

```rust
pub fn get_peer_weight(&self, peer: &Author) -> u64 {
    self.validator
        .get_voting_power(peer)
        .unwrap_or(0)
}
```

Alternatively, populate the `weights` HashMap during construction and use it:

```rust
pub fn get_peer_weight(&self, peer: &Author) -> u64 {
    *self.weights.get(peer).unwrap_or(&0)
}
```

Additionally, ensure the `WeightedConfigArkworks` is initialized with actual validator stakes rather than uniform weights, and populate the `weights` field during `SecretShareConfig::new()` construction.

## Proof of Concept

The vulnerability can be demonstrated by examining the code flow:

1. **Validator stakes are available** via `ValidatorVerifier::get_voting_power()` [12](#0-11) 

2. **Weight infrastructure exists** in `WeightedConfig::get_player_weight()` [13](#0-12) 

3. **But implementation ignores it** - returns constant 1 [1](#0-0) 

4. **Used in critical aggregation logic** where threshold checks happen [4](#0-3) 

A concrete test would create a validator set with heterogeneous stakes and verify that low-stake validators can inappropriately meet reconstruction thresholds due to equal weight treatment.

## Notes

The comment indicating "This is temporary and meant to change in future PRs" [14](#0-13)  suggests this may be a known limitation. However, if the secret sharing functionality is actively deployed without stake-based weighting, it represents an active economic security vulnerability that should be addressed with high priority.

The randomness generation subsystem (`RandConfig`) correctly implements weighted configurations, demonstrating that the necessary infrastructure exists and has been properly implemented elsewhere in the codebase. [15](#0-14)

### Citations

**File:** types/src/secret_sharing.rs (L134-134)
```rust
/// This is temporary and meant to change in future PRs
```

**File:** types/src/secret_sharing.rs (L139-139)
```rust
    validator: Arc<ValidatorVerifier>,
```

**File:** types/src/secret_sharing.rs (L143-143)
```rust
    config: <FPTXWeighted as BatchThresholdEncryption>::ThresholdConfig,
```

**File:** types/src/secret_sharing.rs (L196-198)
```rust
    pub fn get_peer_weight(&self, _peer: &Author) -> u64 {
        1
    }
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L32-35)
```rust
    pub fn add_share(&mut self, share: SecretShare, weight: u64) {
        if self.shares.insert(share.author, share).is_none() {
            self.total_weight += weight;
        }
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L44-46)
```rust
        if self.total_weight < secret_share_config.threshold() {
            return Either::Left(self);
        }
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L260-260)
```rust
        let weight = self.secret_share_config.get_peer_weight(share.author());
```

**File:** crates/aptos-crypto/src/weighted_config.rs (L46-46)
```rust
    weights: Vec<usize>,
```

**File:** crates/aptos-crypto/src/weighted_config.rs (L163-165)
```rust
    pub fn get_player_weight(&self, player: &Player) -> usize {
        self.weights[player.id]
    }
```

**File:** types/src/validator_verifier.rs (L75-75)
```rust
    pub voting_power: u64,
```

**File:** types/src/validator_verifier.rs (L503-507)
```rust
    pub fn get_voting_power(&self, author: &AccountAddress) -> Option<u64> {
        self.address_to_validator_index
            .get(author)
            .map(|index| self.validator_infos[*index].voting_power)
    }
```

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L48-63)
```rust
pub struct SecretShareManager {
    author: Author,
    epoch_state: Arc<EpochState>,
    stop: bool,
    config: SecretShareConfig,
    reliable_broadcast: Arc<ReliableBroadcast<SecretShareMessage, ExponentialBackoff>>,
    network_sender: Arc<NetworkSender>,

    // local channel received from dec_store
    decision_rx: Receiver<SecretSharedKey>,
    // downstream channels
    outgoing_blocks: Sender<OrderedBlocks>,
    // local state
    secret_share_store: Arc<Mutex<SecretShareStore>>,
    block_queue: BlockQueue,
}
```

**File:** consensus/src/rand/rand_gen/types.rs (L590-590)
```rust
    wconfig: WeightedConfigBlstrs,
```

**File:** consensus/src/rand/rand_gen/types.rs (L676-681)
```rust
    pub fn get_peer_weight(&self, peer: &Author) -> u64 {
        let player = Player {
            id: self.get_id(peer),
        };
        self.wconfig.get_player_weight(&player) as u64
    }
```

**File:** consensus/src/rand/secret_sharing/types.rs (L99-102)
```rust
    pub fn get_peer_weight(&self, _peer: &Author) -> u64 {
        // daniel todo: use weighted config
        1
    }
```
