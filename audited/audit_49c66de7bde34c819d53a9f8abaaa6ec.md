# Audit Report

## Title
Chunked ElGamal Homomorphism: Bounded Discrete Log Causes Decryption Failure on Over-Aggregation

## Summary
The chunked ElGamal homomorphism in the PVSS implementation is mathematically sound at the cryptographic level (H(x+y) = H(x) + H(y) holds), but decryption relies on discrete logarithm computation with a bounded search range. When aggregating more transcripts than the configured `max_aggregation` parameter, chunk values can exceed the discrete log range bound, causing decryption to panic and potentially leading to denial of service.

## Finding Description
The chunked ElGamal encryption scheme splits plaintexts into chunks and encrypts each chunk separately using the homomorphic formula: [1](#0-0) 

The homomorphism is mathematically correct - adding encrypted chunks produces the encryption of the sum. However, decryption uses the Baby-Step Giant-Step (BSGS) discrete logarithm algorithm with a bounded search range: [2](#0-1) 

The search range is determined by `get_dlog_range_bound()`: [3](#0-2) 

This range is `1 << (ell + log2(max_aggregation))`, designed to accommodate up to `max_aggregation` transcript aggregations.

The critical issue is in the transcript aggregation logic: [4](#0-3) 

The `aggregate_with` function adds ciphertexts component-wise without checking if the number of aggregations exceeds `max_aggregation`. If chunk values exceed the dlog range bound, the discrete log computation fails: [5](#0-4) 

This returns `None`, which propagates up and causes a panic: [6](#0-5) 

## Impact Explanation
**Severity: High** - This issue can cause validator node crashes and service disruption through denial of service.

While the homomorphism is mathematically sound, the practical implementation has a bounded decodability range. If misconfigured (low `max_aggregation`) or if more transcripts are aggregated than expected, the system panics rather than gracefully handling the error.

The default configuration exposes this risk: [7](#0-6) 

Though marked for testing, if production code inadvertently uses insufficient `max_aggregation` values, or if the number of validator transcripts exceeds expectations, decryption will fail catastrophically with a panic.

## Likelihood Explanation
**Likelihood: Low to Medium**

This vulnerability requires:
1. Misconfiguration of `max_aggregation` parameter to be lower than actual aggregation count, OR
2. Unexpected number of validator transcripts exceeding the configured limit

However, the lack of runtime validation means there's no defensive check to prevent this scenario. The code assumes correct configuration without enforcement, violating defensive programming principles for consensus-critical systems.

## Recommendation
Add runtime validation to prevent over-aggregation:

```rust
fn aggregate_with(&mut self, sc: &SecretSharingConfig<E>, other: &Self) -> anyhow::Result<()> {
    // Track aggregation count in Subtranscript
    self.aggregation_count += 1;
    
    // Validate against max_aggregation from public parameters
    if self.aggregation_count > pp.max_aggregation {
        bail!("Aggregation count {} exceeds max_aggregation {}", 
              self.aggregation_count, pp.max_aggregation);
    }
    
    // Existing aggregation logic...
}
```

Additionally, replace `.expect()` with proper error handling:

```rust
let chunk_values: Vec<_> = bsgs::dlog_vec(pp.G.into_group(), &exp_chunks, &table, pp.get_dlog_range_bound())
    .ok_or_else(|| anyhow!("Discrete log failed - chunk value exceeds range bound"))?
    .into_iter()
    .map(|x| C::ScalarField::from(x))
    .collect();
```

## Proof of Concept
```rust
#[test]
#[should_panic(expected = "BSGS dlog failed")]
fn test_over_aggregation_causes_panic() {
    use ark_bn254::Bn254;
    
    // Create public parameters with max_aggregation = 2
    let pp = PublicParameters::<Bn254>::new(10, 16, 2, &mut thread_rng());
    let sc = WeightedConfig::new(2, vec![1, 1]).unwrap();
    
    // Create 3 transcripts (exceeds max_aggregation = 2)
    let trx1 = Transcript::deal(&sc, &pp, ...);
    let trx2 = Transcript::deal(&sc, &pp, ...);
    let trx3 = Transcript::deal(&sc, &pp, ...);
    
    // Aggregate all three
    let mut aggregated = trx1.subtrs.clone();
    aggregated.aggregate_with(&sc, &trx2.subtrs).unwrap();
    aggregated.aggregate_with(&sc, &trx3.subtrs).unwrap();
    
    // Attempt decryption - will panic due to chunk overflow
    aggregated.decrypt_own_share(&sc, &player, &dk, &pp); // PANICS
}
```

**Note**: While this represents a design limitation with potential DoS impact, exploiting it requires either misconfiguration or validator-level access to submit multiple transcripts. The mathematical homomorphism property H(x+y) = H(x) + H(y) holds correctly at the cryptographic level; the limitation is in the bounded decoding capability, which is accounted for by the `max_aggregation` parameter when properly configured.

### Citations

**File:** crates/aptos-dkg/src/pvss/chunky/chunked_elgamal.rs (L27-42)
```rust
/// Formally, given:
/// - `G_1, H_1` ∈ G₁ (group generators)
/// - `ek_i` ∈ G₁ (encryption keys)
/// - `z_i,j` ∈ Scalar<E> (from plaintext scalars `z_i`, each chunked into a vector z_i,j)
/// - `r_j` ∈ Scalar<E> (randomness for `j` in a vector of chunks z_i,j)
///
/// The homomorphism maps input `[z_i,j]` and randomness `[r_j]` to
/// the following codomain elements:
///
/// ```text
/// C_i,j = G_1 * z_i,j + ek_i * r_j
/// R_j  = H_1 * r_j
/// ```
///
/// The `C_i,j` represent "chunked" homomorphic encryptions of the plaintexts,
/// and `R_j` carry the corresponding randomness contributions.
```

**File:** crates/aptos-dkg/src/pvss/chunky/chunked_elgamal.rs (L336-339)
```rust
        let chunk_values: Vec<_> =
            bsgs::dlog_vec(pp.G.into_group(), &exp_chunks, &table, 1 << radix_exponent)
                .expect("dlog_vec failed")
                .into_iter()
```

**File:** crates/aptos-dkg/src/pvss/chunky/public_parameters.rs (L115-117)
```rust
    pub(crate) fn get_dlog_range_bound(&self) -> u32 {
        1u32 << (self.ell as u32 + log2(self.max_aggregation))
    }
```

**File:** crates/aptos-dkg/src/pvss/chunky/public_parameters.rs (L218-223)
```rust
impl<E: Pairing> Default for PublicParameters<E> {
    // This is only used for testing and benchmarking
    fn default() -> Self {
        let mut rng = thread_rng();
        Self::new(1, DEFAULT_ELL_FOR_TESTING, 1, &mut rng)
    }
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L357-363)
```rust
            let dealt_chunked_secret_key_share = bsgs::dlog_vec(
                pp.pp_elgamal.G.into_group(),
                &dealt_encrypted_secret_key_share_chunks,
                &pp.table,
                pp.get_dlog_range_bound(),
            )
            .expect("BSGS dlog failed");
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L387-416)
```rust
    fn aggregate_with(&mut self, sc: &SecretSharingConfig<E>, other: &Self) -> anyhow::Result<()> {
        debug_assert_eq!(self.Cs.len(), sc.get_total_num_players());
        debug_assert_eq!(self.Vs.len(), sc.get_total_num_players());
        debug_assert_eq!(self.Cs.len(), other.Cs.len());
        debug_assert_eq!(self.Rs.len(), other.Rs.len());
        debug_assert_eq!(self.Vs.len(), other.Vs.len());

        // Aggregate the V0s
        self.V0 += other.V0;

        for i in 0..sc.get_total_num_players() {
            for j in 0..self.Vs[i].len() {
                // Aggregate the V_{i,j}s
                self.Vs[i][j] += other.Vs[i][j];
                for k in 0..self.Cs[i][j].len() {
                    // Aggregate the C_{i,j,k}s
                    self.Cs[i][j][k] += other.Cs[i][j][k];
                }
            }
        }

        for j in 0..self.Rs.len() {
            for (R_jk, other_R_jk) in self.Rs[j].iter_mut().zip(&other.Rs[j]) {
                // Aggregate the R_{j,k}s
                *R_jk += other_R_jk;
            }
        }

        Ok(())
    }
```

**File:** crates/aptos-dkg/src/dlog/bsgs.rs (L35-46)
```rust
    for i in 0..n {
        let mut buf = vec![0u8; byte_size];
        gamma.serialize_compressed(&mut buf[..]).unwrap();

        if let Some(&j) = baby_table.get(&buf) {
            return Some(i * m + j);
        }

        gamma += G_neg_m;
    }

    None
```
