# Audit Report

## Title
Memory Exhaustion DoS via Unbounded BitVec Allocation in RoundTimeout Deserialization

## Summary
A malicious validator can cause out-of-memory conditions on other validators by sending `RoundTimeoutMsg` messages with maliciously crafted `PayloadUnavailable` reasons containing extremely large BitVec allocations. The vulnerability exists because memory allocation occurs before size validation during deserialization, and the `reason` field is not covered by cryptographic signatures.

## Finding Description

The `PayloadUnavailable` variant in `RoundTimeoutReason` contains a `missing_authors` BitVec field that represents which validator authors' batches are missing. [1](#0-0) 

The critical vulnerability exists in BitVec deserialization where memory allocation occurs before size validation. The deserializer first allocates the full Vec<u8> based on the BCS length prefix, then checks if the size exceeds MAX_BUCKETS. [2](#0-1) 

The attack is possible because the `reason` field in `RoundTimeout` is not covered by the cryptographic signature. The signature verification only validates the `TwoChainTimeout` object via `signing_format()`, which excludes the reason field. [3](#0-2) 

The `TimeoutSigningRepr` structure that gets signed only includes epoch, round, and hqc_round - not the reason field. [4](#0-3) 

**Attack Path:**
1. Malicious validator creates a valid `TwoChainTimeout` and signs it properly using SafetyRules [5](#0-4) 
2. Attaches a `PayloadUnavailable` reason with a BitVec claiming 50MB+ size (under the 64MB network limit) [6](#0-5) 
3. Broadcasts `RoundTimeoutMsg` to other validators [7](#0-6) 
4. Receiving validators deserialize via `ConsensusMsg` enum during network message processing [8](#0-7) 
5. BitVec allocation occurs during automatic Serde deserialization before the MAX_BUCKETS validation executes
6. Although deserialization fails after allocation, repeated messages cause memory exhaustion

The MAX_BUCKETS limit is only 8192 bytes, but the network allows messages up to 64MB, creating a massive allocation window. [9](#0-8) 

## Impact Explanation

This qualifies as **Medium to High Severity** under the Aptos bug bounty program:

**Validator Node Slowdowns/Crashes (High)**: Repeated exploitation causes memory exhaustion leading to validator unavailability through resource exhaustion, which aligns with the bounty category "DoS through resource exhaustion."

**Consensus Liveness Impact**: If multiple validators are simultaneously targeted, the network may experience temporary liveness failures, though this doesn't constitute permanent network halting.

**State Inconsistencies**: Validators crashing mid-round may require manual intervention to restore proper operation.

The impact is limited to availability rather than safety violations (no fund theft, no consensus corruption), and requires a malicious validator within the 1/3 Byzantine assumption. This distinguishes it from Critical severity issues while still representing a significant protocol vulnerability.

## Likelihood Explanation

**Likelihood: Medium**

**Prerequisites:**
- Requires a malicious or compromised validator node (within BFT threat model)
- Attacker must have validator network access to broadcast consensus messages

**Feasibility:**
- Attack is straightforward - craft a valid `TwoChainTimeout` signature, then attach arbitrary `reason` field with large BitVec
- No complex timing or race conditions required
- Can be executed repeatedly for sustained impact
- Multiple validators can be targeted simultaneously

The attack exploits a legitimate protocol message flow where validators broadcast timeout messages during normal consensus operation. Since the signature doesn't cover the `reason` field, any validator can attach malicious data without detection until deserialization attempts allocation.

## Recommendation

**Immediate Fix:**
1. Include the `reason` field in the `TimeoutSigningRepr` structure so that signatures cover all RoundTimeout fields
2. Implement pre-deserialization size validation for BitVec fields before memory allocation
3. Add maximum size limits for the `reason` field variants

**Implementation Approach:**
```rust
// In timeout_2chain.rs - Update TimeoutSigningRepr to include reason hash
#[derive(Serialize, Deserialize, Debug, CryptoHasher, BCSCryptoHash)]
pub struct TimeoutSigningRepr {
    pub epoch: u64,
    pub round: Round,
    pub hqc_round: Round,
    pub reason_hash: HashValue, // Add cryptographic binding to reason
}

// In aptos-bitvec/src/lib.rs - Add early size validation
impl<'de> Deserialize<'de> for BitVec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Validate size BEFORE allocation
        let length = deserializer.deserialize_bytes(ByteVisitor)?;
        if length > MAX_BUCKETS {
            return Err(D::Error::custom(format!("BitVec too long: {}", length)));
        }
        // Then proceed with allocation
    }
}
```

## Proof of Concept

The vulnerability can be demonstrated by constructing a RoundTimeoutMsg with an oversized BitVec:

```rust
// Proof of concept (conceptual - requires validator keys)
let timeout = TwoChainTimeout::new(epoch, round, hqc);
let signature = signer.sign(&timeout.signing_format()).unwrap();

// Create malicious reason with huge BitVec
let mut malicious_bitvec = BitVec::default();
// Craft a serialized BitVec with 50MB claimed size in BCS encoding
let malicious_bytes = create_malicious_bcs_bitvec(50_000_000);

let round_timeout = RoundTimeout::new(
    timeout,
    author,
    RoundTimeoutReason::PayloadUnavailable { 
        missing_authors: deserialize_from_malicious_bytes(malicious_bytes) 
    },
    signature, // Valid signature - doesn't cover reason field
);

// Broadcast to other validators
network.broadcast_round_timeout(RoundTimeoutMsg::new(round_timeout, sync_info)).await;

// Receiving validators will allocate 50MB during deserialization
// Repeated messages cause memory exhaustion
```

The attack succeeds because signature verification passes (reason not covered) while deserialization allocates memory before validation.

## Notes

This vulnerability represents a **protocol-level bug** rather than a pure network DoS attack. It exploits two specific implementation flaws:
1. Incomplete signature coverage (architectural issue)
2. Allocation-before-validation pattern (implementation issue)

The vulnerability is within the Byzantine fault tolerance threat model (malicious validator < 1/3) and affects in-scope consensus layer components. While similar to resource exhaustion attacks, this is a specific protocol vulnerability requiring detailed knowledge of the consensus message structure, distinguishing it from generic network flooding attacks that are out of scope.

### Citations

**File:** consensus/consensus-types/src/round_timeout.rs (L17-22)
```rust
pub enum RoundTimeoutReason {
    Unknown,
    ProposalNotReceived,
    PayloadUnavailable { missing_authors: BitVec },
    NoQC,
}
```

**File:** consensus/consensus-types/src/round_timeout.rs (L97-107)
```rust
    pub fn verify(&self, validator: &ValidatorVerifier) -> anyhow::Result<()> {
        self.timeout.verify(validator)?;
        validator
            .verify(
                self.author(),
                &self.timeout.signing_format(),
                &self.signature,
            )
            .context("Failed to verify 2-chain timeout signature")?;
        Ok(())
    }
```

**File:** crates/aptos-bitvec/src/lib.rs (L20-20)
```rust
const MAX_BUCKETS: usize = 8192;
```

**File:** crates/aptos-bitvec/src/lib.rs (L235-252)
```rust
impl<'de> Deserialize<'de> for BitVec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename = "BitVec")]
        struct RawData {
            #[serde(with = "serde_bytes")]
            inner: Vec<u8>,
        }
        let v = RawData::deserialize(deserializer)?.inner;
        if v.len() > MAX_BUCKETS {
            return Err(D::Error::custom(format!("BitVec too long: {}", v.len())));
        }
        Ok(BitVec { inner: v })
    }
}
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L98-103)
```rust
#[derive(Serialize, Deserialize, Debug, CryptoHasher, BCSCryptoHash)]
pub struct TimeoutSigningRepr {
    pub epoch: u64,
    pub round: Round,
    pub hqc_round: Round,
}
```

**File:** consensus/src/round_manager.rs (L1009-1021)
```rust
                let timeout = TwoChainTimeout::new(
                    self.epoch_state.epoch,
                    round,
                    self.block_store.highest_quorum_cert().as_ref().clone(),
                );
                let signature = self
                    .safety_rules
                    .lock()
                    .sign_timeout_with_qc(
                        &timeout,
                        self.block_store.highest_2chain_timeout_cert().as_deref(),
                    )
                    .context("[RoundManager] SafetyRules signs 2-chain timeout")?;
```

**File:** consensus/src/round_manager.rs (L1034-1037)
```rust
            let round_timeout_msg = RoundTimeoutMsg::new(timeout, self.block_store.sync_info());
            self.network
                .broadcast_round_timeout(round_timeout_msg)
                .await;
```

**File:** config/src/config/network_config.rs (L50-50)
```rust
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; /* 64 MiB */
```

**File:** consensus/src/network_interface.rs (L91-91)
```rust
    RoundTimeoutMsg(Box<RoundTimeoutMsg>),
```
