# Audit Report

## Title
DKG Verification Panic Causes Validator Node Crash Due to Unhandled Projection Dimension Mismatch

## Summary
A malicious DKG transcript with deliberately malformed proof witness dimensions can trigger an assertion failure during sigma protocol verification, causing all validator nodes to crash and halt the network. The vulnerability stems from lack of graceful error handling in the projection function path combined with a global panic handler that terminates the process.

## Finding Description

The vulnerability exists in the DKG (Distributed Key Generation) sigma protocol verification flow, specifically in how `LiftHomomorphism` handles projection functions that produce semantically invalid values.

**Attack Flow:**

1. A malicious validator creates a DKGTranscript containing a sigma protocol proof (SoK) where `proof.z` is a `HkzgWeightedElgamalWitness` with malformed `chunked_plaintexts` dimensions (e.g., extra chunks beyond the configured maximum). The validator constructs this by serializing arbitrary bytes into the `transcript_bytes` field. [1](#0-0) 

2. During verification, the validator transaction is processed in `process_dkg_result_inner()` which deserializes and calls verification. [2](#0-1) 

3. The PVSS verification calls `trx.main.verify()` which constructs a `WeightedHomomorphism` and invokes the sigma protocol `verify()` method. [3](#0-2) [4](#0-3) 

4. The sigma protocol's `verify()` method calls `msm_terms_for_verify()`, which in turn calls `self.msm_terms(&proof.z)` to compute MSM terms from the proof witness. [5](#0-4) [6](#0-5) 

5. For `LiftHomomorphism`, the `msm_terms()` implementation calls the projection function without error handling, then delegates to the underlying homomorphism. [7](#0-6) 

6. The projection function flattens the malformed `chunked_plaintexts` by prepending a zero and chaining all nested vectors, producing a `Witness` with excessive `values.len()`. [8](#0-7) 

7. When `CommitmentHomomorphism::msm_terms()` receives this witness, the assertion `assert!(self.msm_basis.len() >= input.values.len())` **fails and panics**. [9](#0-8) 

8. The global panic handler executes, checks the thread-local `VMState`, and since it is not `VERIFIER` or `DESERIALIZER` during DKG verification, calls `process::exit(12)`, **terminating the entire validator process**. [10](#0-9) 

**Root Cause:**

The projection function is defined as a non-fallible function pointer `fn(&LargerDomain) -> H::Domain` with no mechanism to return errors. [11](#0-10)  When it produces semantically invalid output (wrong dimensions), downstream code uses `assert!()` instead of returning a `Result`, causing panics that crash the validator. The panic occurs before any error handling can catch it, and the VMState protection mechanism (designed for Move bytecode verification/deserialization) is not active during DKG verification. [12](#0-11) 

## Impact Explanation

**Severity: HIGH**

This vulnerability enables a **network-wide liveness failure**:

- **Validator Node Crashes**: All honest validators attempting to verify the malicious DKG transcript will crash simultaneously when they hit the identical assertion failure
- **Consensus Halted**: The network cannot make progress without functioning validators  
- **Byzantine Fault Tolerance Violation**: AptosBFT is designed to tolerate < 1/3 Byzantine validators, but this allows a **single malicious validator** to halt the entire network
- **Deterministic Execution Broken**: Instead of all validators deterministically rejecting an invalid proof with an error, they all deterministically **crash**, violating consensus invariants

Per Aptos bug bounty criteria for HIGH severity: "Validator Node Crashes" that affect consensus operations. While not quite reaching "total loss of liveness" (Critical severity, which requires non-recoverable state), this causes temporary but complete network halt requiring manual validator restart and potential intervention to exclude the malicious transaction.

## Likelihood Explanation

**Likelihood: HIGH**

- **Low Complexity**: Attack requires only crafting a DKG transcript with modified proof witness dimensions - no cryptographic forgery needed, just arbitrary BCS-serialized bytes
- **Minimal Privileges**: Any validator participating in DKG can submit transcripts; no majority stake or collusion required
- **Reliable Trigger**: The panic is deterministic - all validators will crash on the same malformed input at the exact same code location
- **No Detection**: The malformed transcript passes BCS deserialization checks and basic structural validation, only failing during the sigma protocol MSM computation
- **High Impact**: Complete network halt affecting all validators simultaneously

## Recommendation

Replace the assertion with proper error handling:

1. **Change projection signature** to return `Result<H::Domain, Error>` or use a trait with fallible methods
2. **Replace `assert!()` with conditional check** in `CommitmentHomomorphism::msm_terms()` that returns an error instead of panicking
3. **Add dimension validation** before projection to catch malformed witnesses early
4. **Consider setting VMState** during DKG verification to prevent process exit on panic (though proper error handling is preferred)

Example fix for the assertion:
```rust
// Instead of:
assert!(self.msm_basis.len() >= input.values.len(), ...);

// Use:
if self.msm_basis.len() < input.values.len() {
    return Err(anyhow::anyhow!(
        "Not enough Lagrange basis elements for univariate hiding KZG: required {}, got {}",
        input.values.len(),
        self.msm_basis.len()
    ));
}
```

## Proof of Concept

The vulnerability can be triggered by constructing a malicious DKG transcript with excessive `chunked_plaintexts` dimensions in the sigma protocol proof witness. When any validator attempts to verify this transcript during block execution, they will hit the assertion failure in `CommitmentHomomorphism::msm_terms()` and crash with `process::exit(12)`.

A complete PoC would require:
1. Creating a properly structured DKGTranscript with valid metadata and epoch
2. Serializing a PVSS transcript with a sigma proof where `proof.z.chunked_plaintexts` has more chunks than `msm_basis.len() - 1` (accounting for the prepended zero in the projection)
3. Submitting this as a ValidatorTransaction during DKG phase
4. Observing that all validators crash deterministically when processing this transaction

The attack path is fully traceable through the codebase and requires no special conditions beyond being an active validator during DKG.

### Citations

**File:** types/src/dkg/mod.rs (L49-71)
```rust
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DKGTranscript {
    pub metadata: DKGTranscriptMetadata,
    #[serde(with = "serde_bytes")]
    pub transcript_bytes: Vec<u8>,
}

impl Debug for DKGTranscript {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DKGTranscript")
            .field("metadata", &self.metadata)
            .field("transcript_bytes_len", &self.transcript_bytes.len())
            .finish()
    }
}

impl DKGTranscript {
    pub fn new(epoch: u64, author: AccountAddress, transcript_bytes: Vec<u8>) -> Self {
        Self {
            metadata: DKGTranscriptMetadata { epoch, author },
            transcript_bytes,
        }
    }
```

**File:** aptos-move/aptos-vm/src/validator_txns/dkg.rs (L83-112)
```rust
    fn process_dkg_result_inner(
        &self,
        resolver: &impl AptosMoveResolver,
        module_storage: &impl AptosModuleStorage,
        log_context: &AdapterLogSchema,
        session_id: SessionId,
        dkg_node: DKGTranscript,
    ) -> Result<(VMStatus, VMOutput), ExecutionFailure> {
        let dkg_state =
            OnChainConfig::fetch_config(resolver).ok_or(Expected(MissingResourceDKGState))?;
        let config_resource = ConfigurationResource::fetch_config(resolver)
            .ok_or(Expected(MissingResourceConfiguration))?;
        let DKGState { in_progress, .. } = dkg_state;
        let in_progress_session_state =
            in_progress.ok_or(Expected(MissingResourceInprogressDKGSession))?;

        // Check epoch number.
        if dkg_node.metadata.epoch != config_resource.epoch() {
            return Err(Expected(EpochNotCurrent));
        }

        // Deserialize transcript and verify it.
        let pub_params = DefaultDKG::new_public_params(&in_progress_session_state.metadata);
        let transcript = bcs::from_bytes::<<DefaultDKG as DKGTrait>::Transcript>(
            dkg_node.transcript_bytes.as_slice(),
        )
        .map_err(|_| Expected(TranscriptDeserializationFailed))?;

        DefaultDKG::verify_transcript(&pub_params, &transcript)
            .map_err(|_| Expected(TranscriptVerificationFailed))?;
```

**File:** types/src/dkg/real_dkg/mod.rs (L332-374)
```rust
    fn verify_transcript(
        params: &Self::PublicParams,
        trx: &Self::Transcript,
    ) -> anyhow::Result<()> {
        // Verify dealer indices are valid.
        let dealers = trx
            .main
            .get_dealers()
            .iter()
            .map(|player| player.id)
            .collect::<Vec<usize>>();
        let num_validators = params.session_metadata.dealer_validator_set.len();
        ensure!(
            dealers.iter().all(|id| *id < num_validators),
            "real_dkg::verify_transcript failed with invalid dealer index."
        );

        let all_eks = params.pvss_config.eks.clone();

        let addresses = params.verifier.get_ordered_account_addresses();
        let dealers_addresses = dealers
            .iter()
            .filter_map(|&pos| addresses.get(pos))
            .cloned()
            .collect::<Vec<_>>();

        let spks = dealers_addresses
            .iter()
            .filter_map(|author| params.verifier.get_public_key(author))
            .collect::<Vec<_>>();

        let aux = dealers_addresses
            .iter()
            .map(|address| (params.pvss_config.epoch, address))
            .collect::<Vec<_>>();

        trx.main.verify(
            &params.pvss_config.wconfig,
            &params.pvss_config.pp,
            &spks,
            &all_eks,
            &aux,
        )?;
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L172-190)
```rust
            let hom = hkzg_chunked_elgamal::WeightedHomomorphism::<E>::new(
                lagr_g1,
                pp.pk_range_proof.ck_S.xi_1,
                &pp.pp_elgamal,
                &eks_inner,
            );
            if let Err(err) = hom.verify(
                &TupleCodomainShape(
                    self.sharing_proof.range_proof_commitment.clone(),
                    chunked_elgamal::WeightedCodomainShape {
                        chunks: self.subtrs.Cs.clone(),
                        randomness: self.subtrs.Rs.clone(),
                    },
                ),
                &self.sharing_proof.SoK,
                &sok_cntxt,
            ) {
                bail!("PoK verification failed: {:?}", err);
            }
```

**File:** crates/aptos-dkg/src/sigma_protocol/traits.rs (L52-71)
```rust
    fn verify<Ct: Serialize, H>(
        &self,
        public_statement: &Self::Codomain,
        proof: &Proof<C::ScalarField, H>, // Would like to set &Proof<E, Self>, but that ties the lifetime of H to that of Self, but we'd like it to be eg static
        cntxt: &Ct,
    ) -> anyhow::Result<()>
    where
        H: homomorphism::Trait<Domain = Self::Domain, Codomain = Self::Codomain>, // need this because `H` is technically different from `Self` due to lifetime changes
    {
        let msm_terms = self.msm_terms_for_verify::<_, H>(
            public_statement,
            proof,
            cntxt,
        );

        let msm_result = Self::msm_eval(msm_terms);
        ensure!(msm_result == C::ZERO); // or MsmOutput::zero()

        Ok(())
    }
```

**File:** crates/aptos-dkg/src/sigma_protocol/traits.rs (L104-124)
```rust
    fn msm_terms_for_verify<Ct: Serialize, H>(
        &self,
        public_statement: &Self::Codomain,
        proof: &Proof<C::ScalarField, H>,
        cntxt: &Ct,
    ) -> Self::MsmInput
    where
        H: homomorphism::Trait<Domain = Self::Domain, Codomain = Self::Codomain>, // Need this because the lifetime was changed
    {
        let prover_first_message = match &proof.first_proof_item {
            FirstProofItem::Commitment(A) => A,
            FirstProofItem::Challenge(_) => {
                panic!("Missing implementation - expected commitment, not challenge")
            },
        };

        let number_of_beta_powers = public_statement.clone().into_iter().count(); // TODO: maybe pass the into_iter version in merge_msm_terms?

        let (c, powers_of_beta) = self.compute_verifier_challenges(public_statement, prover_first_message, cntxt, number_of_beta_powers);

        let msm_terms_for_prover_response = self.msm_terms(&proof.z);
```

**File:** crates/aptos-dkg/src/sigma_protocol/homomorphism/fixed_base_msms.rs (L111-114)
```rust
    fn msm_terms(&self, input: &Self::Domain) -> Self::CodomainShape<Self::MsmInput> {
        let projected = (self.projection)(input);
        self.hom.msm_terms(&projected)
    }
```

**File:** crates/aptos-dkg/src/pvss/chunky/hkzg_chunked_elgamal.rs (L204-218)
```rust
            projection: |dom: &HkzgWeightedElgamalWitness<E::ScalarField>| {
                let HkzgWeightedElgamalWitness {
                    hkzg_randomness,
                    chunked_plaintexts,
                    ..
                } = dom;
                let flattened_chunked_plaintexts: Vec<Scalar<E::ScalarField>> =
                    std::iter::once(Scalar(E::ScalarField::ZERO))
                        .chain(chunked_plaintexts.iter().flatten().flatten().cloned())
                        .collect();
                univariate_hiding_kzg::Witness::<E::ScalarField> {
                    hiding_randomness: hkzg_randomness.clone(),
                    values: flattened_chunked_plaintexts,
                }
            },
```

**File:** crates/aptos-dkg/src/pcs/univariate_hiding_kzg.rs (L351-357)
```rust
    fn msm_terms(&self, input: &Self::Domain) -> Self::CodomainShape<Self::MsmInput> {
        assert!(
            self.msm_basis.len() >= input.values.len(),
            "Not enough Lagrange basis elements for univariate hiding KZG: required {}, got {}",
            input.values.len(),
            self.msm_basis.len()
        );
```

**File:** crates/crash-handler/src/lib.rs (L27-57)
```rust
    panic::set_hook(Box::new(move |pi: &PanicHookInfo<'_>| {
        handle_panic(pi);
    }));
}

// Formats and logs panic information
fn handle_panic(panic_info: &PanicHookInfo<'_>) {
    // The Display formatter for a PanicHookInfo contains the message, payload and location.
    let details = format!("{}", panic_info);
    let backtrace = format!("{:#?}", Backtrace::new());

    let info = CrashInfo { details, backtrace };
    let crash_info = toml::to_string_pretty(&info).unwrap();
    error!("{}", crash_info);
    // TODO / HACK ALARM: Write crash info synchronously via eprintln! to ensure it is written before the process exits which error! doesn't guarantee.
    // This is a workaround until https://github.com/aptos-labs/aptos-core/issues/2038 is resolved.
    eprintln!("{}", crash_info);

    // Wait till the logs have been flushed
    aptos_logger::flush();

    // Do not kill the process if the panics happened at move-bytecode-verifier.
    // This is safe because the `state::get_state()` uses a thread_local for storing states. Thus the state can only be mutated to VERIFIER by the thread that's running the bytecode verifier.
    //
    // TODO: once `can_unwind` is stable, we should assert it. See https://github.com/rust-lang/rust/issues/92988.
    if state::get_state() == VMState::VERIFIER || state::get_state() == VMState::DESERIALIZER {
        return;
    }

    // Kill the process
    process::exit(12);
```

**File:** crates/aptos-dkg/src/sigma_protocol/homomorphism/mod.rs (L29-56)
```rust
/// `LiftHomomorphism` adapts a homomorphism `H` defined on some `Domain`
/// so that it can act on a larger `LargerDomain` by precomposing `H`
/// with a natural projection map `π`, which should also be a homomorphism.
///
/// In other words, given:
/// - a homomorphism `h: Domain -> Codomain`
/// - another homomorphism `π: LargerDomain -> Domain`
///
/// `LiftHomomorphism` represents the composed homomorphism:
/// `h ∘ π : LargerDomain -> Codomain`.
///
/// # Example
///
/// A common case is when `LargerDomain` is a Cartesian product type like `X × Y`
/// and the projection is `(x, y) ↦ x`. Then `LiftHomomorphism`
/// lets `h` act on the first component of the pair, so `(h ∘ π)(x,y) = h(x)`.
///
/// Naturally this method immediately extends to composing arbitrary homomorphisms,
/// but we don't need that formalism for now. We are not deriving Eq here because
/// function pointer comparisons do not seem useful in this context.
#[derive(Debug, Clone)]
pub struct LiftHomomorphism<H, LargerDomain>
where
    H: Trait,
{
    pub hom: H,
    pub projection: fn(&LargerDomain) -> H::Domain,
}
```

**File:** third_party/move/move-core/types/src/state.rs (L1-25)
```rust
// Copyright (c) The Diem Core Contributors
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

use std::cell::RefCell;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VMState {
    DESERIALIZER,
    VERIFIER,
    RUNTIME,
    OTHER,
}

thread_local! {
    static STATE: RefCell<VMState> = const { RefCell::new(VMState::OTHER) };
}

pub fn set_state(state: VMState) -> VMState {
    STATE.with(|s| s.replace(state))
}

pub fn get_state() -> VMState {
    STATE.with(|s| *s.borrow())
}
```
