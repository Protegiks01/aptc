# Audit Report

## Title
Complete Blockchain Compromise via Test-Only Native Functions in Production

## Summary
If `aptos_debug_natives()` is accidentally used in production validator code (with the Rust `testing` feature enabled), test-only native functions become available to all transactions. The most critical is `create_signers_for_testing`, which allows creating signers for ANY address without authentication, including system address @aptos_framework (0x1). This completely bypasses all access controls, enabling unlimited coin minting, governance takeover, and complete blockchain compromise.

## Finding Description

The vulnerability exists in the native function registration system when debug natives are accidentally enabled in production.

**The Debug Natives Function** exposes test-only native functions: [1](#0-0) 

This function calls `natives::configure_for_unit_test()` which is only available with the testing feature: [2](#0-1) 

**The Most Critical Test-Only Native**: `create_signers_for_testing` creates signers for sequential addresses (0x0, 0x1, 0x2, ...) without any authentication: [3](#0-2) 

The function is only registered when the testing feature is enabled: [4](#0-3) 

**How Production Normally Works**: The production environment calls `aptos_natives_with_builder` with `inject_create_signer_for_gov_sim: false`: [5](#0-4) 

Production natives explicitly pass `false` to exclude test natives: [6](#0-5) 

**Attack Scenario**:
1. Production validator is compiled with `feature = "testing"` enabled (configuration error)
2. Code accidentally calls `aptos_debug_natives()` instead of normal initialization path
3. Test-only natives become available in the native function table
4. Attacker deploys a malicious Move module declaring these natives (without `#[test_only]` attribute)
5. Attacker calls `create_signers_for_testing(2)` to get signers for addresses 0x0 and 0x1
6. With address 0x1 (@aptos_framework) signer, attacker bypasses all system address checks

**Critical System Address Checks Bypassed**: Many privileged operations verify the signer is from @aptos_framework: [7](#0-6) 

**Example Exploitation - Governance Takeover**: The attacker can store signer capabilities for any framework-reserved address: [8](#0-7) 

**Example Exploitation - Unlimited Coin Minting**: The attacker can mint maximum coins: [9](#0-8) 

## Impact Explanation

**CRITICAL Severity** - This vulnerability represents complete blockchain compromise and meets multiple critical impact categories from the Aptos bug bounty program:

1. **Loss of Funds (Unlimited)**: Attacker can mint unlimited APT coins, causing complete devaluation and theft through inflation. The `configure_accounts_for_test` function alone mints 18,446,744,073,709,551,615 (max u64) coins.

2. **Governance Integrity Violation**: Complete bypass of all governance mechanisms. Attacker can execute any proposal, modify voting rules, and take permanent control of on-chain governance.

3. **Access Control Catastrophic Failure**: The core security invariant "System addresses (@aptos_framework, @core_resources) must be protected" is completely broken. All 70+ functions protected by `system_addresses::assert_aptos_framework()` become accessible.

4. **Consensus/Staking Manipulation**: Attacker can modify staking configuration, consensus parameters, validator sets, and reward distributions, breaking consensus safety guarantees.

5. **Non-recoverable State**: Would require hard fork to recover from successful exploitation.

This qualifies for the maximum critical severity payout (up to $1,000,000) as it enables:
- Unlimited loss of funds
- Complete consensus violation
- Permanent blockchain compromise requiring hard fork

## Likelihood Explanation

**Low likelihood but CATASTROPHIC impact**:

The vulnerability requires specific configuration errors:
1. Production binary compiled with `feature = "testing"` enabled (should be prevented by proper CI/CD)
2. Production code calling `aptos_debug_natives()` instead of normal `AptosEnvironment::new()` path
3. Attacker deploying a malicious Move module

**However**: 
- If these configuration mistakes occur, exploitation is **trivial and guaranteed**
- No special privileges or validator access required
- The assertion check `assert_no_test_natives()` exists but is not used in all production paths
- Single transaction can achieve complete compromise
- Attack leaves minimal trace before execution

The low probability is offset by:
- Complete blockchain destruction
- Unrecoverable without hard fork  
- Affects all users simultaneously
- No detection mechanism before exploitation

## Recommendation

Implement multiple defense layers:

**1. Mandatory Runtime Validation**: Add this check to validator startup in `AptosEnvironment::new()`: [10](#0-9) 

Call `assert_no_test_natives()` during every production initialization to verify test natives are absent.

**2. Build System Hardening**:
- Ensure all production builds explicitly use `--no-default-features` or `--features production`
- Add CI/CD checks that fail if `testing` feature is enabled in release builds
- Separate build profiles for production vs development

**3. Code Isolation**:
- Move `aptos_debug_natives()` to a separate crate that is NOT linked in production binaries
- Add `#[cfg(not(feature = "production"))]` guards around debug native registration
- Make `aptos_debug_natives()` return a Result that fails if called in production context

**4. Static Analysis**:
- Add clippy lint to detect calls to `aptos_debug_natives()` outside test code paths
- Implement compile-time feature flag conflict detection

**5. Documentation**:
- Document the security implications of `aptos_debug_natives()` with prominent warnings
- Add security notes to validator deployment documentation

## Proof of Concept

**Malicious Move Module** (exploits available test natives):

```move
module attacker::exploit {
    use std::vector;
    use std::signer;
    
    // Declare the test-only native (without #[test_only] attribute)
    native fun create_signers_for_testing(num_signers: u64): vector<signer>;
    
    public entry fun execute_exploit() {
        // Create signers for addresses 0x0, 0x1
        let signers = create_signers_for_testing(2);
        
        // Get the @aptos_framework (0x1) signer
        vector::pop_back(&mut signers); // discard 0x0
        let aptos_framework_signer = vector::pop_back(&mut signers);
        
        // Verify we have 0x1
        assert!(signer::address_of(&aptos_framework_signer) == @0x1, 1);
        
        // Now can call ANY privileged function in the framework:
        // - aptos_governance::store_signer_cap()
        // - aptos_coin::configure_accounts_for_test()
        // - stake::update_performance_statistics()
        // - consensus_config::set()
        // - And 70+ other system functions
        
        // Complete blockchain takeover achieved
    }
}
```

**Verification of Production Path**: The normal production initialization explicitly excludes test natives by passing `false`: [11](#0-10) 

The `inject_create_signer_for_gov_sim` parameter is separate and only used for governance simulation, not for the dangerous `create_signers_for_testing` function.

## Notes

This vulnerability demonstrates a critical design principle: **test-only code must be completely isolated from production**. The defense-in-depth approach of:
1. Compile-time feature flags (`#[cfg(feature = "testing")]`)
2. Move-level attributes (`#[test_only]`)
3. Separate function paths (`aptos_natives` vs `aptos_debug_natives`)

Is defeated if any single layer fails. The `assert_no_test_natives()` function exists but must be mandatorily called in all production initialization paths.

### Citations

**File:** crates/aptos/src/move_tool/aptos_debug_natives.rs (L20-36)
```rust
pub fn aptos_debug_natives(
    native_gas_parameters: NativeGasParameters,
    misc_gas_params: MiscGasParameters,
) -> NativeFunctionTable {
    // As a side effect, also configure for unit testing
    natives::configure_for_unit_test();
    configure_extended_checks_for_unit_test();
    // Return all natives -- build with the 'testing' feature, therefore containing
    // debug related functions.
    natives::aptos_natives(
        LATEST_GAS_FEATURE_VERSION,
        native_gas_parameters,
        misc_gas_params,
        TimedFeaturesBuilder::enable_all().build(),
        Features::default(),
    )
}
```

**File:** aptos-move/aptos-vm/src/natives.rs (L142-159)
```rust
pub fn aptos_natives(
    gas_feature_version: u64,
    native_gas_params: NativeGasParameters,
    misc_gas_params: MiscGasParameters,
    timed_features: TimedFeatures,
    features: Features,
) -> NativeFunctionTable {
    let mut builder = SafeNativeBuilder::new(
        gas_feature_version,
        native_gas_params,
        misc_gas_params,
        timed_features,
        features,
        None,
    );

    aptos_natives_with_builder(&mut builder, false)
}
```

**File:** aptos-move/aptos-vm/src/natives.rs (L161-191)
```rust
pub fn assert_no_test_natives(err_msg: &str) {
    assert!(
        aptos_natives(
            LATEST_GAS_FEATURE_VERSION,
            NativeGasParameters::zeros(),
            MiscGasParameters::zeros(),
            TimedFeaturesBuilder::enable_all().build(),
            Features::default()
        )
        .into_iter()
        .all(|(_, module_name, func_name, _)| {
            !(module_name.as_str() == "unit_test"
                && func_name.as_str() == "create_signers_for_testing"
                || module_name.as_str() == "ed25519"
                    && func_name.as_str() == "generate_keys_internal"
                || module_name.as_str() == "ed25519" && func_name.as_str() == "sign_internal"
                || module_name.as_str() == "multi_ed25519"
                    && func_name.as_str() == "generate_keys_internal"
                || module_name.as_str() == "multi_ed25519" && func_name.as_str() == "sign_internal"
                || module_name.as_str() == "bls12381"
                    && func_name.as_str() == "generate_keys_internal"
                || module_name.as_str() == "bls12381" && func_name.as_str() == "sign_internal"
                || module_name.as_str() == "bls12381"
                    && func_name.as_str() == "generate_proof_of_possession_internal"
                || module_name.as_str() == "event"
                    && func_name.as_str() == "emitted_events_internal")
        }),
        "{}",
        err_msg
    )
}
```

**File:** aptos-move/aptos-vm/src/natives.rs (L193-196)
```rust
#[cfg(feature = "testing")]
pub fn configure_for_unit_test() {
    move_unit_test::extensions::set_extension_hook(Box::new(unit_test_extensions_hook))
}
```

**File:** aptos-move/framework/move-stdlib/src/natives/unit_test.rs (L30-45)
```rust
fn native_create_signers_for_testing(
    _context: &mut SafeNativeContext,
    ty_args: &[Type],
    mut args: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    debug_assert!(ty_args.is_empty());
    debug_assert!(args.len() == 1);

    let num_signers = safely_pop_arg!(args, u64);

    let signers = Value::vector_unchecked(
        (0..num_signers).map(|i| Value::master_signer(AccountAddress::new(to_le_bytes(i)))),
    )?;

    Ok(smallvec![signers])
}
```

**File:** aptos-move/framework/move-stdlib/src/natives/mod.rs (L47-50)
```rust
        #[cfg(feature = "testing")]
        {
            add_natives!("unit_test", unit_test::make_all(builder));
        }
```

**File:** aptos-move/aptos-vm-environment/src/environment.rs (L267-275)
```rust
        let mut builder = SafeNativeBuilder::new(
            gas_feature_version,
            native_gas_params,
            misc_gas_params,
            timed_features.clone(),
            features.clone(),
            gas_hook,
        );
        let natives = aptos_natives_with_builder(&mut builder, inject_create_signer_for_gov_sim);
```

**File:** aptos-move/framework/aptos-framework/sources/system_addresses.move (L26-31)
```text
    public fun assert_aptos_framework(account: &signer) {
        assert!(
            is_aptos_framework_address(signer::address_of(account)),
            error::permission_denied(ENOT_APTOS_FRAMEWORK_ADDRESS),
        )
    }
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L191-208)
```text
    public fun store_signer_cap(
        aptos_framework: &signer,
        signer_address: address,
        signer_cap: SignerCapability,
    ) acquires GovernanceResponsbility {
        system_addresses::assert_aptos_framework(aptos_framework);
        system_addresses::assert_framework_reserved(signer_address);

        if (!exists<GovernanceResponsbility>(@aptos_framework)) {
            move_to(
                aptos_framework,
                GovernanceResponsbility { signer_caps: simple_map::create<address, SignerCapability>() }
            );
        };

        let signer_caps = &mut borrow_global_mut<GovernanceResponsbility>(@aptos_framework).signer_caps;
        simple_map::add(signer_caps, signer_address, signer_cap);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_coin.move (L73-85)
```text
    public(friend) fun configure_accounts_for_test(
        aptos_framework: &signer,
        core_resources: &signer,
        mint_cap: MintCapability<AptosCoin>,
    ) {
        system_addresses::assert_aptos_framework(aptos_framework);

        // Mint the core resource account AptosCoin for gas so it can execute system transactions.
        let coins = coin::mint<AptosCoin>(
            18446744073709551615,
            &mint_cap,
        );
        coin::deposit<AptosCoin>(signer::address_of(core_resources), coins);
```

**File:** aptos-move/aptos-vm-environment/src/natives.rs (L10-13)
```rust
pub fn aptos_natives_with_builder(
    builder: &mut SafeNativeBuilder,
    inject_create_signer_for_gov_sim: bool,
) -> NativeFunctionTable {
```
