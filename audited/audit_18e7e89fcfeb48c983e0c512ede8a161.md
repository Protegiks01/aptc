# Audit Report

## Title
No Migration Path for DealtPubKey Format Changes in DKG Protocol Upgrades

## Summary
The DKG (Distributed Key Generation) system stores transcript data on-chain containing `DealtPubKey` structures, but lacks versioning or migration mechanisms. Any future change to the `DealtPubKey` format would break deserialization of existing on-chain DKG state, potentially causing randomness generation failures and requiring a hardfork.

## Finding Description
The `DealtPubKey` structure is serialized as part of DKG transcripts and stored persistently on-chain in the `DKGState` resource. When validators start a new epoch, they must deserialize these transcripts to extract secret shares for randomness generation. [1](#0-0) 

The transcript is stored on-chain as raw bytes: [2](#0-1) 

When a new epoch begins, validators deserialize the previous epoch's transcript using hardcoded type information: [3](#0-2) 

The transcript type is fixed via type aliases with no versioning: [4](#0-3) [5](#0-4) 

The `DealtPubKey` uses BCS serialization without version fields: [6](#0-5) [7](#0-6) 

**The Problem:** If the `DealtPubKey` format needs to change (e.g., different group element type, modified serialization), the following occurs:
1. Old transcripts stored in `DKGState.last_completed.transcript` cannot be deserialized with the new type
2. `bcs::from_bytes` will fail at epoch transition
3. Validators cannot extract secret shares for randomness generation
4. Network randomness functionality breaks

This violates the **State Consistency** invariant: existing on-chain state becomes unreadable after a protocol upgrade.

## Impact Explanation
This qualifies as **Medium Severity** under the Aptos bug bounty criteria:
- **State inconsistencies requiring intervention**: The lack of migration path would cause validators to fail deserializing DKG state, requiring coordinated intervention (potentially a hardfork) to recover.
- Not **Critical** because it doesn't enable theft or consensus violation by an attacker—it's a protocol upgrade safety issue.

The impact affects:
- All validators attempting to start randomness generation in a new epoch
- Network randomness availability
- Requires coordination between all nodes to upgrade

## Likelihood Explanation
**Likelihood: Medium to High during protocol upgrades**

This issue WILL occur if:
1. Aptos decides to upgrade the DKG cryptographic scheme (e.g., switching curve implementations)
2. Performance optimizations require changing the `DealtPubKey` representation
3. Security improvements necessitate format changes

The likelihood depends on:
- Future protocol evolution needs (cryptographic agility is common in blockchain protocols)
- The existence of `weighted_transcriptv2.rs` suggests versioning was considered but not fully implemented
- No current migration framework exists [8](#0-7) 

## Recommendation

**Implement versioned transcript serialization:**

1. **Add version enum wrapper:**
```rust
// In types/src/dkg/mod.rs
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum VersionedTranscript {
    V1(pvss::das::WeightedTranscript),
    // Future versions can be added here
    // V2(NewTranscriptType),
}

impl VersionedTranscript {
    pub fn current_version(&self) -> u32 {
        match self {
            VersionedTranscript::V1(_) => 1,
        }
    }
}
```

2. **Update deserialization to handle multiple versions:**
```rust
// In consensus/src/epoch_manager.rs
let transcript = match try_deserialize_versioned(&dkg_session.transcript) {
    Ok(VersionedTranscript::V1(t)) => t,
    // Future: migrate from old versions
    Err(e) => return Err(NoRandomnessReason::TranscriptDeserializationError(e)),
};
```

3. **Add migration logic for epoch transitions:**
    - Store version metadata in `DKGSessionState`
    - Implement conversion functions between transcript versions
    - Allow validators to operate with mixed versions during transition periods

4. **Alternative: Store DealtPubKey separately:**
Store the final dealt public key separately from the full transcript to enable independent versioning.

## Proof of Concept

**Scenario demonstrating the breaking change:**

```rust
// Step 1: Simulate current state - transcript stored on-chain
use aptos_types::dkg::{DefaultDKG, DKGTrait};
use bcs;

// Current epoch: Store a transcript with G2Projective DealtPubKey
let current_transcript: <DefaultDKG as DKGTrait>::Transcript = /* ... */;
let serialized = bcs::to_bytes(&current_transcript).unwrap();
// This gets stored in DKGState.last_completed.transcript

// Step 2: Protocol upgrade - change DealtPubKey to use different group
// Hypothetically, if we changed:
// pub type WTrx = pvss::chunky::WeightedTranscriptV2<ark_bls12_381::Bls12_381>;
// The DealtPubKey type changes from G2Projective to E::G2Affine

// Step 3: Next epoch starts, try to deserialize old transcript
// This will FAIL because the types don't match:
let result = bcs::from_bytes::<NewTranscriptType>(&serialized);
// Result: Err(DeserializationError) - breaking randomness generation

assert!(result.is_err()); // Demonstrates the incompatibility
```

**Test case showing deserialization failure:**
```rust
#[test]
fn test_transcript_format_incompatibility() {
    // Serialize with V1 format
    let v1_transcript = create_v1_transcript();
    let bytes = bcs::to_bytes(&v1_transcript).unwrap();
    
    // Try to deserialize as V2 format (if it existed)
    // This would fail, breaking epoch transitions
    let result = bcs::from_bytes::<HypotheticalV2Transcript>(&bytes);
    assert!(result.is_err(), "Old transcript cannot be read with new format");
}
```

## Notes

While this is not an actively exploitable vulnerability by an attacker, it represents a **protocol safety concern** that would cause network disruption during legitimate upgrades. The Aptos team should implement versioning before needing to change the `DealtPubKey` format.

The existence of `weighted_transcriptv2.rs` with a different domain separation tag suggests awareness of versioning needs, but this hasn't been integrated into the type system or on-chain storage format. [9](#0-8)

### Citations

**File:** crates/aptos-dkg/src/pvss/dealt_pub_key.rs (L17-21)
```rust
        #[derive(DeserializeKey, Clone, Debug, SerializeKey, PartialEq, Eq)]
        pub struct DealtPubKey {
            /// A group element $g_1^a \in G$, where $G$ is $G_1$, $G_2$ or $G_T$
            g_a: $GTProjective,
        }
```

**File:** crates/aptos-dkg/src/pvss/dealt_pub_key.rs (L32-34)
```rust
            pub fn to_bytes(&self) -> [u8; DEALT_PK_NUM_BYTES] {
                self.g_a.to_compressed()
            }
```

**File:** crates/aptos-dkg/src/pvss/dealt_pub_key.rs (L49-55)
```rust
        impl TryFrom<&[u8]> for DealtPubKey {
            type Error = CryptoMaterialError;

            fn try_from(bytes: &[u8]) -> std::result::Result<DealtPubKey, Self::Error> {
                $gt_proj_from_bytes(bytes).map(|g_a| DealtPubKey { g_a })
            }
        }
```

**File:** aptos-move/framework/aptos-framework/sources/dkg.move (L31-37)
```text
    /// The input and output of a DKG session.
    /// The validator set of epoch `x` works together for an DKG output for the target validator set of epoch `x+1`.
    struct DKGSessionState has copy, store, drop {
        metadata: DKGSessionMetadata,
        start_time_us: u64,
        transcript: vector<u8>,
    }
```

**File:** consensus/src/epoch_manager.rs (L1056-1059)
```rust
        let transcript = bcs::from_bytes::<<DefaultDKG as DKGTrait>::Transcript>(
            dkg_session.transcript.as_slice(),
        )
        .map_err(NoRandomnessReason::TranscriptDeserializationError)?;
```

**File:** types/src/dkg/real_dkg/mod.rs (L38-41)
```rust
pub type WTrx = pvss::das::WeightedTranscript;
pub type DkgPP = <WTrx as Transcript>::PublicParameters;
pub type SSConfig = <WTrx as Transcript>::SecretSharingConfig;
pub type EncPK = <WTrx as Transcript>::EncryptPubKey;
```

**File:** types/src/dkg/mod.rs (L237-237)
```rust
pub type DefaultDKG = RealDKG;
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcriptv2.rs (L55-57)
```rust
/// Domain-separation tag (DST) used to ensure that all cryptographic hashes and
/// transcript operations within the protocol are uniquely namespaced
pub const DST: &[u8; 42] = b"APTOS_WEIGHTED_CHUNKY_FIELD_PVSS_v2_FS_DST";
```
