# Audit Report

## Title
Unbounded BCS Deserialization in Secret Share Messages Enables Validator DoS Attack

## Summary
The `from_network_message()` function in the secret sharing consensus component performs unbounded BCS deserialization of network messages, allowing malicious validators to send oversized payloads that consume excessive CPU and memory resources before validation occurs, causing denial-of-service on victim validator nodes.

## Finding Description

The vulnerability exists in a two-layer deserialization process for secret sharing consensus messages:

**First Layer (Protocol):** The network protocol layer deserializes `ConsensusMsg::SecretShareMsg` with recursion limits [1](#0-0)  applied via `bcs::from_bytes_with_limit()` [2](#0-1) .

**Second Layer (Application):** The application layer then deserializes the inner message data WITHOUT limits [3](#0-2)  and again in the verification task [4](#0-3) .

The recursion limit only constrains nesting depth at the protocol layer, not vector sizes. The inner `SecretShareMessage` type contains a `Vec<BIBEDecryptionKeyShareValue>` field [5](#0-4)  where each element is a BLS12-381 G1 curve point requiring expensive deserialization and validation.

**Attack Vector:**
1. Malicious validator crafts `SecretShare` with ~1.3 million curve points (within 64 MiB network limit [6](#0-5) )
2. Message passes network size checks and protocol-layer deserialization
3. Application-layer deserialization allocates memory and performs CPU-intensive curve point validation for all elements
4. Only AFTER full deserialization does verification check vector size and reject it [7](#0-6) 

This violates the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits."

## Impact Explanation

This is a **High severity** issue per Aptos bug bounty criteria:

**Validator node slowdowns:** Each malicious message forces the victim validator to:
- Allocate up to 64 MiB of memory for oversized vectors
- Execute expensive BLS curve point deserialization operations for millions of elements
- Consume bounded executor task slots [8](#0-7) 

**Consensus performance degradation:** Sustained attacks from one or more compromised validators can:
- Exhaust CPU resources on victim nodes
- Delay block processing and voting
- Reduce network throughput
- Impact consensus liveness

The bounded executor provides limited protection as it only caps concurrent tasks, not per-task resource consumption. Multiple attack messages can saturate available executor slots with expensive deserialization operations.

## Likelihood Explanation

**Likelihood: Medium-High**

**Requirements:**
- Attacker must be an authenticated validator on the validator network [9](#0-8)  (mutual authentication enabled)
- OR compromise a validator's network credentials

**Attack Complexity: Low**
- Trivial to craft: modify legitimate `SecretShare` with oversized vector
- Network layer accepts messages up to 64 MiB
- No pre-deserialization validation exists
- Verification only checks size AFTER expensive deserialization completes

**Realistic Scenario:**
- Compromised validator node
- Malicious validator operator
- Software bug in validator's secret share generation logic

Expected vector size is proportional to validator weights (typically hundreds to low thousands of virtual players for weighted secret sharing [10](#0-9) ), making 1.3 million element vectors clearly malicious.

## Recommendation

**Immediate Fix:** Apply BCS deserialization size limits at the application layer:

```rust
// In consensus/src/rand/secret_sharing/network_messages.rs, line 53:
fn from_network_message(msg: ConsensusMsg) -> anyhow::Result<Self> {
    match msg {
        ConsensusMsg::SecretShareMsg(msg) => {
            // Use RECURSION_LIMIT consistent with protocol layer
            const MAX_DESERIALIZATION_SIZE: usize = 64; // or higher if needed
            Ok(bcs::from_bytes_with_limit(&msg.data, MAX_DESERIALIZATION_SIZE)?)
        },
        _ => bail!("unexpected consensus message type {:?}", msg),
    }
}

// In consensus/src/rand/secret_sharing/secret_share_manager.rs, line 218:
match bcs::from_bytes_with_limit::<SecretShareMessage>(
    dec_msg.req.data(), 
    RECURSION_LIMIT // Import from network protocol constants
) {
    // ... existing logic
}
```

**Additional Hardening:**
1. Add pre-deserialization size validation based on expected validator set size
2. Implement maximum vector length checks for `Vec<BIBEDecryptionKeyShareValue>` tied to actual weighted configuration
3. Consider rate-limiting secret share message processing per peer
4. Add monitoring/alerting for oversized secret share messages

## Proof of Concept

```rust
// PoC demonstrating the vulnerability
use consensus::rand::secret_sharing::network_messages::{
    SecretShareMessage, SecretShareNetworkMessage
};
use types::secret_sharing::{SecretShare, SecretShareMetadata};
use aptos_crypto::hash::HashValue;

#[test]
fn test_oversized_secret_share_dos() {
    // Craft malicious SecretShare with oversized vector
    let malicious_share = SecretShare {
        author: AccountAddress::random(),
        metadata: SecretShareMetadata::default(),
        share: (
            Player::new(0),
            // Create vector with 1 million elements (within 64 MiB limit)
            // Each BIBEDecryptionKeyShareValue is ~48 bytes (compressed G1 point)
            vec![BIBEDecryptionKeyShareValue::default(); 1_000_000]
        ),
    };
    
    let malicious_msg = SecretShareMessage::Share(malicious_share);
    
    // Serialize to network message
    let data = bcs::to_bytes(&malicious_msg).unwrap();
    let network_msg = SecretShareNetworkMessage::new(1, data);
    
    // This will consume significant CPU/memory deserializing 1M curve points
    // BEFORE verification rejects it
    let start = std::time::Instant::now();
    match bcs::from_bytes::<SecretShareMessage>(&network_msg.data()) {
        Ok(msg) => {
            // Verification would fail here with size mismatch
            // But deserialization already completed
            println!("Deserialization took: {:?}", start.elapsed());
        }
        Err(e) => println!("Error: {}", e),
    }
}
```

**Notes:**
- The vulnerability requires validator network access, limiting the attacker pool to validators or those who compromise validator credentials
- Impact is validator performance degradation rather than consensus safety violation
- The issue stems from mismatched validation layers: protocol-level limits don't protect against application-layer resource exhaustion
- Similar pattern should be audited elsewhere in consensus message handling

### Citations

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L39-39)
```rust
pub const RECURSION_LIMIT: usize = 64;
```

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L260-262)
```rust
    fn bcs_decode<T: DeserializeOwned>(&self, bytes: &[u8], limit: usize) -> anyhow::Result<T> {
        bcs::from_bytes_with_limit(bytes, limit).map_err(|e| anyhow!("{:?}", e))
    }
```

**File:** consensus/src/rand/secret_sharing/network_messages.rs (L53-53)
```rust
            ConsensusMsg::SecretShareMsg(msg) => Ok(bcs::from_bytes(&msg.data)?),
```

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L216-217)
```rust
            bounded_executor
                .spawn(async move {
```

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L218-218)
```rust
                    match bcs::from_bytes::<SecretShareMessage>(dec_msg.req.data()) {
```

**File:** types/src/secret_sharing.rs (L60-64)
```rust
pub struct SecretShare {
    pub author: Author,
    pub metadata: SecretShareMetadata,
    pub share: SecretKeyShare,
}
```

**File:** config/src/config/network_config.rs (L50-50)
```rust
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; /* 64 MiB */
```

**File:** config/src/config/network_config.rs (L136-136)
```rust
        let mutual_authentication = network_id.is_validator_network();
```

**File:** crates/aptos-batch-encryption/src/schemes/fptx_weighted.rs (L154-156)
```rust
        (self.vks_g2.len() == dk_share.1.len())
            .then_some(())
            .ok_or(BatchEncryptionError::DecryptionKeyVerifyError)?;
```

**File:** crates/aptos-crypto/src/weighted_config.rs (L38-54)
```rust
#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, Eq)]
pub struct WeightedConfig<TC: ThresholdConfig> {
    /// A weighted config is a $w$-out-of-$W$ threshold config, where $w$ is the minimum weight
    /// needed to reconstruct the secret and $W$ is the total weight.
    tc: TC,
    /// The total number of players in the protocol.
    num_players: usize,
    /// Each player's weight
    weights: Vec<usize>,
    /// Player's starting index `a` in a vector of all `W` shares, such that this player owns shares
    /// `W[a, a + weight[player])`. Useful during weighted secret reconstruction.
    starting_index: Vec<usize>,
    /// The maximum weight of any player.
    max_weight: usize,
    /// The minimum weight of any player.
    min_weight: usize,
}
```
