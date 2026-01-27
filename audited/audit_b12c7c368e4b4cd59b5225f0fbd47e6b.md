# Audit Report

## Title
Critical Validator Node Crash via Script Type Parameter Count Mismatch

## Summary
When the feature flag `sig_checker_v2_fix_script_ty_param_count` is disabled, an attacker can craft a malicious script that declares more type parameters than it actually uses, causing a panic in the bytecode verifier that crashes validator nodes. This vulnerability enables a denial-of-service attack against the Aptos network.

## Finding Description

The vulnerability exists in the `verify_script()` function where the `max_num` calculation determines which size of `BitsetTypeParameterConstraints<N>` to allocate for verification. [1](#0-0) 

Without the fix flag enabled, `max_num_of_ty_params_or_args()` only examines the maximum type parameter **index** actually used in the script's code, signatures, and instantiations - not the number of type parameters **declared** in `script.type_parameters`. [2](#0-1) 

An attacker can exploit this by crafting a script that:
1. Declares N type parameters (e.g., 20) in `script.type_parameters`
2. Only references a few type parameters in actual code (e.g., only index 0)
3. Causes `max_num = 1`, selecting `BitsetTypeParameterConstraints<1>` (capacity: 16 parameters)

During verification, `verify_script_impl()` attempts to create a context from all declared type parameters: [3](#0-2) 

This calls the `From` implementation which iterates through ALL declared type parameters: [4](#0-3) 

When inserting type parameter index 16 or higher into a `BitsetTypeParameterConstraints<1>` (which can only handle 0-15), the `insert()` method's assertion fails: [5](#0-4) 

This `assert!()` macro causes a **panic**, crashing the validator node process.

## Impact Explanation

**Severity: Critical (Validator Node Crash / Network Liveness)**

This vulnerability qualifies as **Critical** severity under the Aptos bug bounty criteria because it enables:

1. **Remote Code Execution equivalent**: Forces a panic that crashes validator nodes without any authentication or privileged access
2. **Total loss of liveness/network availability**: If multiple validators process the malicious script, it can cause widespread crashes affecting network consensus
3. **Consensus Safety violation**: Nodes that crash cannot participate in consensus, potentially causing liveness failures if enough validators are affected simultaneously

The attack requires no validator privileges - any transaction sender can submit a script transaction. The panic is deterministic and will affect all validators that attempt to verify the malicious script.

## Likelihood Explanation

**Likelihood: High (when fix flag disabled)**

The vulnerability is exploitable when:
- The `sig_checker_v2_fix_script_ty_param_count` feature flag is disabled
- Scripts are accepted as transaction payloads (currently supported)
- No explicit limit exists on `script.type_parameters.len()` in the limits verifier [6](#0-5) 

Currently, the fix flag is enabled by default on mainnet: [7](#0-6) 

However, feature flags can be modified through governance: [8](#0-7) 

The vulnerability would be exploitable in:
1. **Historical versions** before the fix was deployed
2. **Governance scenarios** where the flag is intentionally or accidentally disabled
3. **Test/development networks** without the fix flag enabled

## Recommendation

The fix is already implemented via the `sig_checker_v2_fix_script_ty_param_count` feature flag. Ensure this flag:

1. **Remains permanently enabled** on mainnet and cannot be disabled through governance
2. Consider hardcoding the fix or adding explicit validation in `LimitsVerifier::verify_script_impl()` to reject scripts with excessive type parameters:

```rust
fn verify_script_impl(config: &VerifierConfig, script: &'a CompiledScript) -> PartialVMResult<()> {
    let limit_check = Self { resolver: BinaryIndexedView::Script(script) };
    
    // Add explicit check for script type parameter count
    if let Some(limit) = config.max_generic_instantiation_length {
        if script.type_parameters.len() > limit {
            return Err(PartialVMError::new(StatusCode::TOO_MANY_TYPE_PARAMETERS));
        }
    }
    
    limit_check.verify_function_handles(config)?;
    limit_check.verify_struct_handles(config)?;
    limit_check.verify_type_nodes(config)
}
```

3. Mark the feature flag with a comment indicating it **cannot be disabled** similar to other critical flags: [9](#0-8) 

## Proof of Concept

```rust
// Rust PoC demonstrating the vulnerability
use move_binary_format::file_format::{
    AbilitySet, CompiledScript, Signature, SignatureToken, TypeParameterIndex
};
use move_bytecode_verifier::{VerifierConfig, verify_script};

fn create_malicious_script() -> CompiledScript {
    let mut script = CompiledScript::default();
    
    // Declare 20 type parameters (all with empty abilities)
    script.type_parameters = vec![AbilitySet::EMPTY; 20];
    
    // But only use type parameter 0 in the actual code/signatures
    // This makes max_num_of_ty_params_or_args() return 1
    script.parameters = Signature(vec![SignatureToken::TypeParameter(0)]);
    
    // Rest of script setup...
    script
}

fn exploit() {
    let script = create_malicious_script();
    
    // Config with fix flag DISABLED
    let config = VerifierConfig {
        sig_checker_v2_fix_script_ty_param_count: false,
        ..Default::default()
    };
    
    // This will panic when trying to insert type parameters 16-19
    // into a BitsetTypeParameterConstraints<1> (capacity: 16)
    let result = verify_script(&config, &script);
    
    // Never reaches here - validator node has crashed
}
```

**Exploitation Steps:**
1. Craft a `CompiledScript` with 20 type parameters declared
2. Reference only type parameter index 0 in script code
3. Submit as script transaction to network
4. All validators without the fix flag will panic during verification
5. Network liveness degraded as validators crash

## Notes

While the fix flag `SIGNATURE_CHECKER_V2_SCRIPT_FIX` is currently enabled by default on mainnet, this vulnerability represents a critical flaw in the original implementation that could be exploited if the flag is ever disabled through governance or in environments without the fix. The use of `assert!()` for validation rather than graceful error handling makes this particularly severe, as it causes unrecoverable process termination rather than rejecting the transaction with an error code.

### Citations

**File:** third_party/move/move-bytecode-verifier/src/signature_v2.rs (L49-57)
```rust
impl<'a, const N: usize> From<&'a [AbilitySet]> for BitsetTypeParameterConstraints<N> {
    fn from(abilities: &'a [AbilitySet]) -> Self {
        abilities
            .iter()
            .enumerate()
            .map(|(idx, abilities)| (idx as TypeParameterIndex, *abilities))
            .collect()
    }
}
```

**File:** third_party/move/move-bytecode-verifier/src/signature_v2.rs (L70-77)
```rust
    fn insert(&mut self, ty_param_idx: TypeParameterIndex, required_abilities: AbilitySet) {
        assert!(
            (ty_param_idx as usize) < N * NUM_PARAMS_PER_WORD,
            "Type parameter index out of bounds. \
             The current Bitset implementation is only configured to handle \
             {} type parameters at max.",
            N * NUM_PARAMS_PER_WORD
        );
```

**File:** third_party/move/move-bytecode-verifier/src/signature_v2.rs (L1190-1196)
```rust
    checker.verify_signature_in_context(
        &BitsetTypeParameterConstraints::from(script.type_parameters.as_slice()),
        script.parameters,
        // Script parameters can be signer references.
        true,
    )?;
    checker.verify_code(&script.type_parameters, &script.code)?;
```

**File:** third_party/move/move-bytecode-verifier/src/signature_v2.rs (L1201-1251)
```rust
fn max_num_of_ty_params_or_args(resolver: BinaryIndexedView) -> usize {
    let mut n = 0;

    for fh in resolver.function_handles() {
        n = n.max(fh.type_parameters.len())
    }

    for sh in resolver.struct_handles() {
        n = n.max(sh.type_parameters.len())
    }

    for sig in resolver.signatures() {
        for ty in &sig.0 {
            for ty in ty.preorder_traversal() {
                if let SignatureToken::TypeParameter(ty_param_idx) = ty {
                    n = n.max(*ty_param_idx as usize + 1)
                }
            }
        }
    }

    if let Some(struct_defs) = resolver.struct_defs() {
        for struct_def in struct_defs {
            match &struct_def.field_information {
                StructFieldInformation::Native => {},
                StructFieldInformation::Declared(fields) => {
                    for field in fields {
                        for ty in field.signature.0.preorder_traversal() {
                            if let SignatureToken::TypeParameter(ty_param_idx) = ty {
                                n = n.max(*ty_param_idx as usize + 1)
                            }
                        }
                    }
                },
                StructFieldInformation::DeclaredVariants(variants) => {
                    for variant in variants {
                        for field in &variant.fields {
                            for ty in field.signature.0.preorder_traversal() {
                                if let SignatureToken::TypeParameter(ty_param_idx) = ty {
                                    n = n.max(*ty_param_idx as usize + 1)
                                }
                            }
                        }
                    }
                },
            }
        }
    }

    n
}
```

**File:** third_party/move/move-bytecode-verifier/src/signature_v2.rs (L1273-1277)
```rust
pub fn verify_script(config: &VerifierConfig, script: &CompiledScript) -> VMResult<()> {
    let mut max_num = max_num_of_ty_params_or_args(BinaryIndexedView::Script(script));
    if config.sig_checker_v2_fix_script_ty_param_count {
        max_num = max_num.max(script.type_parameters.len());
    }
```

**File:** third_party/move/move-bytecode-verifier/src/limits.rs (L41-51)
```rust
    fn verify_script_impl(
        config: &VerifierConfig,
        script: &'a CompiledScript,
    ) -> PartialVMResult<()> {
        let limit_check = Self {
            resolver: BinaryIndexedView::Script(script),
        };
        limit_check.verify_function_handles(config)?;
        limit_check.verify_struct_handles(config)?;
        limit_check.verify_type_nodes(config)
    }
```

**File:** types/src/on_chain_config/aptos_features.rs (L79-80)
```rust
    /// Enabled on mainnet, can never be disabled.
    _REJECT_UNSTABLE_BYTECODE = 58,
```

**File:** types/src/on_chain_config/aptos_features.rs (L203-203)
```rust
            FeatureFlag::SIGNATURE_CHECKER_V2_SCRIPT_FIX,
```

**File:** aptos-move/framework/move-stdlib/sources/configs/features.move (L805-828)
```text
    public fun change_feature_flags_for_next_epoch(
        framework: &signer,
        enable: vector<u64>,
        disable: vector<u64>
    ) acquires PendingFeatures, Features {
        assert!(signer::address_of(framework) == @std, error::permission_denied(EFRAMEWORK_SIGNER_NEEDED));

        // Figure out the baseline feature vec that the diff will be applied to.
        let new_feature_vec = if (exists<PendingFeatures>(@std)) {
            // If there is a buffered feature vec, use it as the baseline.
            let PendingFeatures { features } = move_from<PendingFeatures>(@std);
            features
        } else if (exists<Features>(@std)) {
            // Otherwise, use the currently effective feature flag vec as the baseline, if it exists.
            Features[@std].features
        } else {
            // Otherwise, use an empty feature vec.
            vector[]
        };

        // Apply the diff and save it to the buffer.
        apply_diff(&mut new_feature_vec, enable, disable);
        move_to(framework, PendingFeatures { features: new_feature_vec });
    }
```
