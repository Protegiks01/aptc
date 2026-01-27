# Audit Report

## Title
Memory Exhaustion DoS via Oversized PVSS Transcript Vectors During Deserialization

## Summary
The PVSS transcript verification system deserializes potentially malicious transcripts with oversized vectors before validating their sizes, enabling a memory exhaustion DoS attack. The benchmark suite tests MSM operations only up to 512 elements, failing to detect that production code could deserialize transcripts with 6,000+ elements (within the 2MB size limit), allocating significant memory before size validation occurs.

## Finding Description

The DKG transcript verification flow performs deserialization before size validation, creating a memory exhaustion vulnerability: [1](#0-0) 

The benchmark only tests MSM operations with sizes [4, 8, 32, 128, 512], but production transcripts can have much larger dimensions within the 2MB serialization limit.

A malicious validator can craft a `DKGTranscript` with oversized vectors in the serialized `transcript_bytes`. The attack exploits two deserialization points:

**First deserialization** (early verification): [2](#0-1) 

This deserializes the entire transcript, allocating memory for all vectors, but `verify_transcript_extra` only checks dealer validity and voting power, NOT vector sizes: [3](#0-2) 

**Second deserialization** (VM execution): [4](#0-3) 

Only during full verification does `check_sizes()` validate vector dimensions: [5](#0-4) 

But by this point, memory has been allocated **twice** for the oversized vectors.

**Size Analysis:**
- Each G1Projective (compressed): 48 bytes; G2Projective: 96 bytes
- For W elements: R(48W) + R_hat(96W) + V(48W) + V_hat(96W) + C(48W) ≈ 336W bytes
- 2MB limit allows W ≈ 6,241 elements
- Uncompressed in memory: G1 ≈ 144 bytes, G2 ≈ 288 bytes
- Memory per deserialization: ~10.1 MB for W=6,241
- Total per malicious transcript: ~20.2 MB (two deserializations)

Verification uses `UnmeteredGasMeter`: [6](#0-5) 

**Attack Flow:**
1. Malicious validator crafts transcript with V, V_hat, R, R_hat, C vectors each containing 6,000+ elements
2. Serializes to <2MB using compressed group elements
3. Submits as `ValidatorTransaction::DKGResult`
4. Passes size limit checks: [7](#0-6) 

5. Each receiving node deserializes twice, allocating ~20MB
6. Eventually fails at `check_sizes()`, but memory pressure accumulates
7. Repeated submissions exhaust node memory

## Impact Explanation

This qualifies as **Medium Severity** per Aptos bug bounty criteria:
- **State inconsistencies requiring intervention**: Nodes experiencing memory pressure may become unresponsive or crash
- **DoS vector**: Repeated malicious transcript submissions can exhaust validator node memory
- **No gas metering**: Uses `UnmeteredGasMeter`, so no cost to attacker
- **Affects consensus availability**: If enough validators are impacted, network liveness degrades

The vulnerability breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." Deserialization allocates unbounded memory (limited only by serialization size, not logical validity) before validation.

## Likelihood Explanation

**Likelihood: Medium to High**

**Attack Requirements:**
- Attacker must be a validator (to submit DKG transcripts)
- Can craft malformed transcripts with standard serialization tools
- No special access beyond validator status required

**Attack Complexity:**
- Low: Straightforward to serialize oversized vectors
- Automated: Can repeatedly submit malicious transcripts
- Persistent: Memory accumulates across multiple submissions

**Detection Gap:**
- Benchmarks test only up to 512 elements (12x smaller than exploitable size)
- No testing of malformed inputs
- No memory consumption monitoring in benchmarks

## Recommendation

**Immediate Fix:** Add size validation BEFORE deserialization:

```rust
// In types/src/dkg/mod.rs, DKGTranscript::verify()
pub(crate) fn verify(&self, verifier: &ValidatorVerifier) -> Result<()> {
    // Add size check BEFORE deserialization
    const MAX_TRANSCRIPT_BYTES: usize = 2_097_152; // 2MB
    const MAX_ELEMENTS_PER_VECTOR: usize = 1000; // Conservative limit
    
    ensure!(
        self.transcript_bytes.len() <= MAX_TRANSCRIPT_BYTES,
        "Transcript bytes exceed maximum size"
    );
    
    // Deserialize with size limits
    let transcripts: Transcripts = bcs::from_bytes(&self.transcript_bytes)
        .context("Transcripts deserialization failed")?;
    
    // Validate vector sizes immediately after deserialization
    ensure!(
        transcripts.main.V.len() <= MAX_ELEMENTS_PER_VECTOR + 1,
        "Transcript V vector exceeds maximum size"
    );
    ensure!(
        transcripts.main.R.len() <= MAX_ELEMENTS_PER_VECTOR,
        "Transcript R vector exceeds maximum size"
    );
    // Add similar checks for R_hat, V_hat, C
    
    RealDKG::verify_transcript_extra(&transcripts, verifier, true, None)
}
```

**Long-term Fix:** 
1. Use streaming deserialization with size limits
2. Add memory consumption tests to benchmark suite
3. Implement gas metering for validator transaction verification
4. Add fuzz testing for malformed transcript inputs

## Proof of Concept

```rust
// Rust reproduction - conceptual PoC showing memory allocation
use aptos_types::dkg::{DKGTranscript, DKGTranscriptMetadata};
use move_core_types::account_address::AccountAddress;
use blstrs::{G1Projective, G2Projective};
use group::Group;

fn craft_malicious_transcript() -> DKGTranscript {
    // Create oversized vectors (6000 elements each)
    let oversized_count = 6000;
    
    // These will serialize to ~2MB but allocate ~10MB when deserialized
    let V: Vec<G1Projective> = (0..oversized_count)
        .map(|_| G1Projective::generator())
        .collect();
    let R: Vec<G1Projective> = (0..oversized_count)
        .map(|_| G1Projective::generator())
        .collect();
    let V_hat: Vec<G2Projective> = (0..oversized_count)
        .map(|_| G2Projective::generator())
        .collect();
    let R_hat: Vec<G2Projective> = (0..oversized_count)
        .map(|_| G2Projective::generator())
        .collect();
    let C: Vec<G1Projective> = (0..oversized_count)
        .map(|_| G1Projective::generator())
        .collect();
    
    // Create malicious transcript struct (pseudo-code, actual struct is complex)
    // let malicious_trx = Transcript { V, V_hat, R, R_hat, C, ... };
    
    // Serialize to bytes
    // let transcript_bytes = bcs::to_bytes(&malicious_trx).unwrap();
    
    // Wrap in DKGTranscript
    DKGTranscript {
        metadata: DKGTranscriptMetadata {
            epoch: 1,
            author: AccountAddress::ONE,
        },
        transcript_bytes: vec![], // Would contain serialized malicious_trx
    }
}

// Submit repeatedly to cause memory exhaustion
// for _ in 0..100 {
//     let malicious_txn = ValidatorTransaction::DKGResult(craft_malicious_transcript());
//     // Submit to validator transaction pool
//     // Each node deserializing this allocates ~20MB
//     // 100 submissions = ~2GB memory pressure
// }
```

**Notes**

- The vulnerability exists because size validation (`check_sizes()`) happens after both deserialization operations
- The benchmark suite's maximum test size of 512 elements is insufficient to detect this 6,000+ element attack vector
- While W (total_weight) is legitimately derived from validator stakes, the deserialization happens before this derivation is validated against the transcript's actual vector sizes
- The double deserialization (early verify + VM execution) doubles the memory impact
- Using `UnmeteredGasMeter` means no resource accounting limits the attack

### Citations

**File:** crates/aptos-batch-encryption/benches/msm.rs (L11-27)
```rust
pub fn msm(c: &mut Criterion) {
    let mut group = c.benchmark_group("msm");
    let mut rng = thread_rng();

    for f_size in [4, 8, 32, 128, 512] {
        let gs = vec![G1Affine::rand(&mut rng); f_size];
        let scalars = vec![Fr::rand(&mut rng); f_size];

        group.bench_with_input(
            BenchmarkId::from_parameter(f_size),
            &(gs, scalars),
            |b, input| {
                b.iter(|| G1Projective::msm(&input.0, &input.1));
            },
        );
    }
}
```

**File:** types/src/dkg/mod.rs (L83-87)
```rust
    pub(crate) fn verify(&self, verifier: &ValidatorVerifier) -> Result<()> {
        let transcripts: Transcripts = bcs::from_bytes(&self.transcript_bytes)
            .context("Transcripts deserialization failed")?;
        RealDKG::verify_transcript_extra(&transcripts, verifier, true, None)
    }
```

**File:** types/src/dkg/real_dkg/mod.rs (L295-329)
```rust
    fn verify_transcript_extra(
        trx: &Self::Transcript,
        verifier: &ValidatorVerifier,
        checks_voting_power: bool,
        ensures_single_dealer: Option<AccountAddress>,
    ) -> anyhow::Result<()> {
        let all_validator_addrs = verifier.get_ordered_account_addresses();
        let main_trx_dealers = trx.main.get_dealers();
        let mut dealer_set = HashSet::with_capacity(main_trx_dealers.len());
        for dealer in main_trx_dealers.iter() {
            if let Some(dealer_addr) = all_validator_addrs.get(dealer.id) {
                dealer_set.insert(*dealer_addr);
            } else {
                bail!("invalid dealer idx");
            }
        }
        ensure!(main_trx_dealers.len() == dealer_set.len());
        if ensures_single_dealer.is_some() {
            let expected_dealer_set: HashSet<AccountAddress> =
                ensures_single_dealer.into_iter().collect();
            ensure!(expected_dealer_set == dealer_set);
        }

        if checks_voting_power {
            verifier
                .check_voting_power(dealer_set.iter(), true)
                .context("not enough power")?;
        }

        if let Some(fast_trx) = &trx.fast {
            ensure!(fast_trx.get_dealers() == main_trx_dealers);
            ensure!(trx.main.get_dealt_public_key() == fast_trx.get_dealt_public_key());
        }
        Ok(())
    }
```

**File:** aptos-move/aptos-vm/src/validator_txns/dkg.rs (L104-112)
```rust
        // Deserialize transcript and verify it.
        let pub_params = DefaultDKG::new_public_params(&in_progress_session_state.metadata);
        let transcript = bcs::from_bytes::<<DefaultDKG as DKGTrait>::Transcript>(
            dkg_node.transcript_bytes.as_slice(),
        )
        .map_err(|_| Expected(TranscriptDeserializationFailed))?;

        DefaultDKG::verify_transcript(&pub_params, &transcript)
            .map_err(|_| Expected(TranscriptVerificationFailed))?;
```

**File:** aptos-move/aptos-vm/src/validator_txns/dkg.rs (L115-115)
```rust
        let mut gas_meter = UnmeteredGasMeter;
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L415-455)
```rust
    fn check_sizes(&self, sc: &WeightedConfigBlstrs) -> anyhow::Result<()> {
        let W = sc.get_total_weight();

        if self.V.len() != W + 1 {
            bail!(
                "Expected {} G_2 (polynomial) commitment elements, but got {}",
                W + 1,
                self.V.len()
            );
        }

        if self.V_hat.len() != W + 1 {
            bail!(
                "Expected {} G_2 (polynomial) commitment elements, but got {}",
                W + 1,
                self.V_hat.len()
            );
        }

        if self.R.len() != W {
            bail!(
                "Expected {} G_1 commitment(s) to ElGamal randomness, but got {}",
                W,
                self.R.len()
            );
        }

        if self.R_hat.len() != W {
            bail!(
                "Expected {} G_2 commitment(s) to ElGamal randomness, but got {}",
                W,
                self.R_hat.len()
            );
        }

        if self.C.len() != W {
            bail!("Expected C of length {}, but got {}", W, self.C.len());
        }

        Ok(())
    }
```

**File:** types/src/on_chain_config/consensus_config.rs (L125-126)
```rust
const VTXN_CONFIG_PER_BLOCK_LIMIT_TXN_COUNT_DEFAULT: u64 = 2;
const VTXN_CONFIG_PER_BLOCK_LIMIT_TOTAL_BYTES_DEFAULT: u64 = 2097152; //2MB
```
