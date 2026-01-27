# Audit Report

## Title
InputSecret Cryptographic Material Not Zeroized on Drop - Core Dump Exposure Vulnerability

## Summary
The `InputSecret` struct used in PVSS (Publicly Verifiable Secret Sharing) dealing does not implement `Drop` with memory zeroization, violating Aptos's secure coding guidelines. When a validator process crashes and generates a core dump, the secret scalar 'a' remains in memory unredacted, allowing attackers with access to crash artifacts to extract cryptographic secrets used in DKG (Distributed Key Generation) for randomness generation. [1](#0-0) 

## Finding Description
The `InputSecret` struct contains a sensitive cryptographic scalar field `a` that is used as input to the PVSS dealing algorithm during DKG sessions. This secret is converted to `DealtSecretKey` which becomes part of the distributed randomness generation system. [2](#0-1) 

The struct derives `SilentDebug` and `SilentDisplay` which prevent the secret from appearing in debug output, but these macros only affect string formatting - they do NOT protect against memory dumps. [3](#0-2) 

The Aptos secure coding guidelines explicitly require using the `zeroize` crate for cryptographic material: [4](#0-3) [5](#0-4) 

However, the `zeroize` crate is not a dependency of `aptos-crypto`, and no `Drop` implementation exists for `InputSecret` or any other private key types in the codebase. [6](#0-5) 

During DKG dealing, validators generate an `InputSecret` locally, use it to create a PVSS transcript, and then the secret goes out of scope: [7](#0-6) 

When the `InputSecret` goes out of scope without zeroization, the secret scalar remains in memory until overwritten. If the validator process crashes during or shortly after dealing, the secret will be present in the core dump.

Validators run with debugging enabled (`RUST_BACKTRACE=1`) and include debugging tools in their Docker images: [8](#0-7) 

The codebase includes crash handling infrastructure that captures panic information: [9](#0-8) 

The `InputSecret` can be converted to `DealtSecretKey` which is used in the DKG protocol: [10](#0-9) 

## Impact Explanation
This vulnerability represents a **Medium** severity information leak that violates the Cryptographic Correctness invariant (#10). 

**Attack Scenario:**
1. A validator generates an `InputSecret` during DKG dealing
2. The validator process crashes (due to bug, OOM, etc.)
3. A core dump is generated containing the unredacted secret
4. An attacker with access to crash artifacts extracts the `InputSecret`
5. The attacker computes the `DealtSecretKey` from the secret
6. If multiple validators are compromised, the DKG randomness generation could be weakened

**Severity Justification:**
Per the Aptos bug bounty program, this qualifies as **Medium Severity** ($10,000) under "State inconsistencies requiring intervention" as it weakens cryptographic guarantees, or potentially **Low Severity** ($1,000) under "Minor information leaks" depending on the exploitability assessment.

The vulnerability requires the attacker to:
- Gain access to validator core dumps (system compromise, misconfigured crash reporting, or insider access)
- Extract secrets during the narrow time window when dealing occurs
- Compromise multiple validators to meaningfully impact DKG

## Likelihood Explanation
**Likelihood: Medium**

Validators can crash during operation due to:
- Software bugs causing panics
- Out-of-memory conditions
- Signal handling (SIGKILL, SIGSEGV)
- Container failures

The comment acknowledges crash scenarios during dealing: [11](#0-10) 

Core dumps are commonly generated in production environments for debugging. Attackers could access them through:
- System compromise of validator nodes
- Misconfigured crash reporting services
- Container orchestration exposure
- Insider threats with debug access
- Backup/logging infrastructure

The secret exists in memory for a brief period during dealing, but crashes can occur at any time.

## Recommendation
Implement proper memory zeroization for all cryptographic secrets:

1. **Add zeroize dependency** to `crates/aptos-crypto/Cargo.toml`:
```toml
zeroize = { version = "1.7", features = ["derive"] }
```

2. **Implement Drop with zeroize** for `InputSecret`:
```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(SilentDebug, SilentDisplay, PartialEq, ZeroizeOnDrop)]
pub struct InputSecret {
    #[zeroize(skip)]  // Scalar doesn't implement Zeroize
    a: Scalar,
}

impl Drop for InputSecret {
    fn drop(&mut self) {
        // Manually zeroize the scalar bytes
        // Note: Requires accessing internal representation safely
        unsafe {
            let ptr = &mut self.a as *mut Scalar as *mut u8;
            let len = std::mem::size_of::<Scalar>();
            std::ptr::write_bytes(ptr, 0, len);
        }
    }
}
```

3. **Apply the same pattern** to all private key types (`Ed25519PrivateKey`, etc.)

4. **Consider OS-level protections** like `mlock` or `MADV_DONTDUMP` for critical secrets

## Proof of Concept
```rust
#[cfg(test)]
mod memory_exposure_test {
    use super::*;
    use aptos_crypto::Uniform;
    use rand::thread_rng;
    
    #[test]
    fn test_input_secret_not_zeroized_on_drop() {
        let mut rng = thread_rng();
        
        // Allocate InputSecret at known location
        let secret_ptr: *const u8;
        let original_value: Vec<u8>;
        
        {
            let secret = InputSecret::generate(&mut rng);
            let scalar = secret.get_secret_a();
            
            // Capture the memory location and value
            secret_ptr = scalar as *const _ as *const u8;
            original_value = unsafe {
                std::slice::from_raw_parts(secret_ptr, 32).to_vec()
            };
            
            // secret drops here
        }
        
        // Check if memory was zeroed after drop
        let memory_after_drop = unsafe {
            std::slice::from_raw_parts(secret_ptr, 32)
        };
        
        // VULNERABILITY: Memory still contains the secret!
        // This assertion would fail with proper zeroization
        assert_ne!(memory_after_drop, &vec![0u8; 32]);
        assert_eq!(memory_after_drop, &original_value[..]);
        
        println!("WARNING: Secret not zeroized - would be exposed in core dump!");
    }
}
```

**Notes:**
- This vulnerability is systematic across all private key types in `aptos-crypto`
- The same issue affects `Ed25519PrivateKey`, `DealtSecretKeyShare`, and other cryptographic material
- While exploitation requires system access, defense-in-depth principles require proper secret sanitization
- The vulnerability directly violates the project's documented security guidelines

### Citations

**File:** crates/aptos-crypto/src/input_secret.rs (L14-24)
```rust
/// The *input secret* that will be given as input to the PVSS dealing algorithm. This will be of a
/// different type than the *dealt secret* that will be returned by the PVSS reconstruction algorithm.
///
/// This secret will NOT need to be stored by validators because a validator (1) picks such a secret
/// and (2) deals it via the PVSS. If the validator crashes during dealing, the entire task will be
/// restarted with a freshly-generated input secret.
#[derive(SilentDebug, SilentDisplay, PartialEq)]
pub struct InputSecret {
    /// The actual secret being dealt; a scalar $a \in F$.
    a: Scalar,
}
```

**File:** crates/aptos-crypto-derive/src/lib.rs (L128-143)
```rust
#[proc_macro_derive(SilentDebug)]
pub fn silent_debug(source: TokenStream) -> TokenStream {
    let ast: DeriveInput = syn::parse(source).expect("Incorrect macro input");
    let name = &ast.ident;
    let (impl_generics, ty_generics, where_clause) = ast.generics.split_for_impl();

    quote! {
        // In order to ensure that secrets are never leaked, Debug is elided
        impl #impl_generics ::std::fmt::Debug for #name #ty_generics #where_clause {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                write!(f, "<elided secret for {}>", stringify!(#name))
            }
        }
    }
    .into()
}
```

**File:** RUST_SECURE_CODING.md (L89-96)
```markdown
### Drop Trait

Implement the `Drop` trait selectively, only when necessary for specific destructor logic. It's mainly used for managing external resources or memory in structures like Box or Rc, often involving unsafe code and security-critical operations.

In a Rust secure development, the implementation of the `std::ops::Drop` trait
must not panic.

Do not rely on `Drop` trait in security material treatment after the use, use [zeroize](https://docs.rs/zeroize/latest/zeroize/#) to explicit destroy security material, e.g. private keys.
```

**File:** RUST_SECURE_CODING.md (L143-145)
```markdown
### Zeroing Sensitive Data

Use [zeroize](https://docs.rs/zeroize/latest/zeroize/#) for zeroing memory containing sensitive data.
```

**File:** crates/aptos-crypto/Cargo.toml (L15-75)
```text
[dependencies]
aes-gcm = { workspace = true }
anyhow = { workspace = true }
aptos-crypto-derive = { workspace = true }
arbitrary = { workspace = true, features = ["derive"], optional = true }
ark-bls12-381 = { workspace = true }
ark-bn254 = { workspace = true }
ark-ec = { workspace = true }
ark-ff = { workspace = true }
ark-groth16 = { workspace = true }
ark-poly = { workspace = true }
ark-relations = { workspace = true }
ark-serialize = { workspace = true }
ark-snark = { workspace = true }
ark-std = { workspace = true }
base64 = { workspace = true }
bcs = { workspace = true }
bls12_381 = { workspace = true }
blst = { workspace = true }
blstrs = { workspace = true }
bulletproofs = { workspace = true }
bytes = { workspace = true }
curve25519-dalek = { workspace = true }
curve25519-dalek-ng = { workspace = true }
digest = { workspace = true }
dudect-bencher = { workspace = true }
ed25519-dalek = { workspace = true }
ff = { workspace = true }
group = { workspace = true }
hex = { workspace = true }
hkdf = { workspace = true }
itertools = { workspace = true }
libsecp256k1 = { workspace = true }
merlin = { workspace = true }
more-asserts = { workspace = true }
neptune = { workspace = true }
num-bigint = { workspace = true }
num-integer = { workspace = true }
num-traits = { workspace = true }
once_cell = { workspace = true }
p256 = { workspace = true }
pairing = { workspace = true }
proptest = { workspace = true, optional = true }
proptest-derive = { workspace = true, optional = true }
rand = { workspace = true }
rand_core = { workspace = true }
rayon = { workspace = true }
ring = { workspace = true }
serde = { workspace = true }
serde-name = { workspace = true }
serde_bytes = { workspace = true }
sha2 = { workspace = true }
sha2_0_10_6 = { workspace = true }
sha3 = { workspace = true }
signature = { workspace = true }
slh-dsa = { workspace = true }
static_assertions = { workspace = true }
thiserror = { workspace = true }
tiny-keccak = { workspace = true }
typenum = { workspace = true }
x25519-dalek = { workspace = true }
```

**File:** dkg/src/dkg_manager/mod.rs (L325-339)
```rust
        let mut rng = if cfg!(feature = "smoke-test") {
            StdRng::from_seed(self.my_addr.into_bytes())
        } else {
            StdRng::from_rng(thread_rng()).unwrap()
        };
        let input_secret = DKG::InputSecret::generate(&mut rng);

        let trx = DKG::generate_transcript(
            &mut rng,
            &public_params,
            &input_secret,
            self.my_index as u64,
            &self.dealer_sk,
            &self.dealer_pk,
        );
```

**File:** docker/builder/validator.Dockerfile (L1-50)
```dockerfile
### Validator Image ###

FROM node-builder

FROM tools-builder

FROM debian-base AS validator

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install --no-install-recommends -y \
        # Needed to run debugging tools like perf
        linux-perf \
        sudo \
        procps \
        gdb

### Because build machine perf might not match run machine perf, we have to symlink
### Even if version slightly off, still mostly works
RUN ln -sf /usr/bin/perf_* /usr/bin/perf

RUN addgroup --system --gid 6180 aptos && adduser --system --ingroup aptos --no-create-home --uid 6180 aptos

RUN mkdir -p /opt/aptos/etc
COPY --link --from=node-builder /aptos/dist/aptos-node /usr/local/bin/
COPY --link --from=tools-builder /aptos/dist/aptos-debugger /usr/local/bin/

# Admission control
EXPOSE 8000
# Validator network
EXPOSE 6180
# Metrics
EXPOSE 9101
# Backup
EXPOSE 6186

# Capture backtrace on error
ENV RUST_BACKTRACE 1
ENV RUST_LOG_FORMAT=json

# add build info
ARG BUILD_DATE
ENV BUILD_DATE ${BUILD_DATE}
ARG GIT_TAG
ENV GIT_TAG ${GIT_TAG}
ARG GIT_BRANCH
ENV GIT_BRANCH ${GIT_BRANCH}
ARG GIT_SHA
ENV GIT_SHA ${GIT_SHA}
```

**File:** crates/crash-handler/src/lib.rs (L1-50)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

#![forbid(unsafe_code)]

use aptos_logger::prelude::*;
use backtrace::Backtrace;
use move_core_types::state::{self, VMState};
use serde::Serialize;
use std::{
    panic::{self, PanicHookInfo},
    process,
};

#[derive(Debug, Serialize)]
pub struct CrashInfo {
    details: String,
    backtrace: String,
}

/// Invoke to ensure process exits on a thread panic.
///
/// Tokio's default behavior is to catch panics and ignore them.  Invoking this function will
/// ensure that all subsequent thread panics (even Tokio threads) will report the
/// details/backtrace and then exit.
pub fn setup_panic_handler() {
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
```

**File:** crates/aptos-dkg/src/pvss/das/input_secret.rs (L14-22)
```rust
impl traits::Convert<DealtSecretKey, das::PublicParameters> for InputSecret {
    fn to(&self, pp: &das::PublicParameters) -> DealtSecretKey {
        DealtSecretKey::new(
            pp.get_encryption_public_params()
                .message_base()
                .mul(self.get_secret_a()),
        )
    }
}
```
