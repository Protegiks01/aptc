# Audit Report

## Title
Genesis Groth16 Verification Key Lacks Circuit Correctness Validation

## Summary
The genesis initialization process accepts an arbitrary Groth16 verification key through `keyless_groth16_vk_override` without validating that it corresponds to the correct keyless authentication circuit. While the Move validation function `validate_groth16_vk()` exists, it is never called during genesis, and there is no check to ensure the VK matches the expected circuit parameters.

## Finding Description

During genesis initialization in `fetch_genesis_info()`, a Groth16 verification key can be provided via the `Layout` configuration file's `keyless_groth16_vk_override` field. [1](#0-0) 

This verification key is passed to the genesis configuration and eventually stored on-chain via the `update_groth16_verification_key()` Move function. [2](#0-1) 

The Move module contains a validation function `validate_groth16_vk()` that checks if the VK contains valid BN254 elliptic curve points. [3](#0-2) 

However, this validation function is **never called** during genesis. The `update_groth16_verification_key()` function only checks that the caller is `@aptos_framework` and that execution is during genesis, but performs no cryptographic validation of the VK itself. [4](#0-3) 

Furthermore, there is no validation that the provided VK corresponds to the correct keyless authentication circuit. The codebase contains a test VK in `prepared_vk_for_testing()`, but no production validation ensures the genesis VK matches expected circuit parameters. [5](#0-4) 

**Attack Scenario (for non-mainnet deployments):**

If an attacker gains control over the genesis Layout configuration (e.g., for a testnet or private deployment), they could:
1. Generate a new Groth16 circuit with known trapdoor/proving keys
2. Set `keyless_groth16_vk_override` to the VK for their malicious circuit
3. The malicious VK is stored on-chain without validation
4. Generate valid ZK proofs for arbitrary user identities using their proving key
5. Submit keyless transactions impersonating any user, stealing funds

The keyless signature verification logic would accept these forged proofs because they verify correctly against the attacker's VK. [6](#0-5) 

**Mainnet Protection:** 

For mainnet genesis, the code explicitly sets `keyless_groth16_vk: None`, preventing this attack path on the production network. [7](#0-6) 

## Impact Explanation

**Severity: Critical** (for affected testnets/private chains) - This vulnerability allows complete compromise of keyless account security, enabling:
- **Loss of Funds**: Attacker can forge signatures for any keyless account and steal all funds
- **Authentication Bypass**: Complete breakdown of keyless account authentication guarantees
- **No Recovery**: Without a hard fork to replace the VK, the chain remains permanently vulnerable

This breaks the **Cryptographic Correctness** invariant: "BLS signatures, VRF, and hash operations must be secure" - extended to ZK proof verification.

**Scope Limitation**: Mainnet is protected since the VK is explicitly set to None. However, testnets, devnets, and private Aptos chains using the override are vulnerable.

## Likelihood Explanation

**Mainnet: Not Applicable** - Code explicitly sets VK to None, preventing the attack.

**Testnets/Private Chains: Medium**
- Requires attacker to control or compromise the genesis Layout file
- Layout file is typically controlled by trusted network operators
- Attack requires insider access or compromise of genesis git repository
- However, for development/test environments, security may be relaxed

**Exploitability**: High once genesis access is obtained - no complex timing or race conditions required.

The Trust Model specifies that "Aptos core developers, validator operators, governance participants" are trusted, making this primarily an insider threat scenario or a supply chain attack (compromised genesis repository).

## Recommendation

**Immediate Mitigation:**
1. **Call validation function**: Modify `update_groth16_verification_key()` to call `validate_groth16_vk()` before storing:

```move
public fun update_groth16_verification_key(fx: &signer, vk: Groth16VerificationKey) {
    system_addresses::assert_aptos_framework(fx);
    chain_status::assert_genesis();
    validate_groth16_vk(&vk);  // Add validation
    move_to(fx, vk);
}
```

2. **Add circuit correctness validation**: Create a function that checks the VK hash against expected values:

```rust
// In genesis/mod.rs or vm-genesis/src/lib.rs
fn validate_vk_matches_circuit(vk: &Groth16VerificationKey) -> Result<(), CliError> {
    let vk_hash = vk.hash();
    const EXPECTED_VK_HASH: &str = "..."; // Hash of correct production VK
    if vk_hash != EXPECTED_VK_HASH {
        return Err(CliError::UnexpectedError(
            "Groth16 VK does not match expected circuit".to_string()
        ));
    }
    Ok(())
}
```

3. **Governance-only updates**: For post-genesis VK updates, the existing `set_groth16_verification_key_for_next_epoch()` requires governance, which provides proper authorization. The warning comment acknowledges the risk. [8](#0-7) 

4. **Document genesis security**: Add clear documentation that genesis Layout files must be protected with the same security level as validator keys.

## Proof of Concept

```rust
// Testnet genesis exploitation PoC (conceptual - requires genesis setup access)

// Step 1: Attacker generates malicious circuit and VK
// (Using external tools like circom/snarkjs with custom circuit)
let malicious_circuit = generate_custom_groth16_circuit();
let (malicious_vk, malicious_proving_key) = malicious_circuit.setup();

// Step 2: Create Layout file with malicious VK
let layout = Layout {
    // ... other fields ...
    keyless_groth16_vk_override: Some(malicious_vk),
};

// Step 3: Run genesis with this Layout
// The VK is stored on-chain without validation

// Step 4: Later, generate forged proof
let fake_identity = KeylessPublicKey {
    iss_val: "https://accounts.google.com",
    id_commitment: target_user_commitment,
};

let forged_proof = malicious_circuit.prove(
    &malicious_proving_key,
    fake_identity.as_public_inputs()
);

// Step 5: Submit transaction with forged proof
let tx = create_keyless_transaction(
    fake_identity,
    forged_proof, // Verifies against malicious VK
    transfer_funds_to_attacker()
);

// Transaction is accepted, funds stolen
```

**Note:** This PoC requires controlling the genesis process. The vulnerability is real but requires privileged access to genesis configuration, making it primarily relevant for testnets or supply chain attacks on genesis repositories.

## Notes

- **Mainnet is NOT vulnerable**: The explicit `keyless_groth16_vk: None` setting in `fetch_mainnet_genesis_info()` prevents this attack on production networks.
- **Existing validation exists but is unused**: The `validate_groth16_vk()` function in the Move module performs point validation but is never invoked during genesis.
- **No circuit correctness check**: Even if point validation were called, there's no verification that the VK corresponds to the legitimate keyless authentication circuit rather than an attacker-controlled circuit.
- **Training wheels don't help**: Training wheels signatures protect against certain ZKP issues but cannot detect a completely different VK for a different circuit.
- **Governance updates are safer**: Post-genesis VK updates via `set_groth16_verification_key_for_next_epoch()` require governance approval, providing proper authorization controls.

### Citations

**File:** crates/aptos/src/genesis/mod.rs (L264-264)
```rust
            keyless_groth16_vk: None,
```

**File:** crates/aptos/src/genesis/mod.rs (L309-309)
```rust
            keyless_groth16_vk: layout.keyless_groth16_vk_override.clone(),
```

**File:** aptos-move/vm-genesis/src/lib.rs (L930-942)
```rust
    if vk.is_some() {
        exec_function(
            session,
            module_storage,
            traversal_context,
            KEYLESS_ACCOUNT_MODULE_NAME,
            "update_groth16_verification_key",
            vec![],
            serialize_values(&vec![
                MoveValue::Signer(CORE_CODE_ADDRESS),
                vk.unwrap().as_move_value(),
            ]),
        );
```

**File:** aptos-move/framework/aptos-framework/sources/keyless_account.move (L183-192)
```text
    fun validate_groth16_vk(vk: &Groth16VerificationKey) {
        // Could be leveraged to speed up the VM deserialization of the VK by 2x, since it can assume the points are valid.
        assert!(option::is_some(&crypto_algebra::deserialize<bn254_algebra::G1, bn254_algebra::FormatG1Compr>(&vk.alpha_g1)), E_INVALID_BN254_G1_SERIALIZATION);
        assert!(option::is_some(&crypto_algebra::deserialize<bn254_algebra::G2, bn254_algebra::FormatG2Compr>(&vk.beta_g2)), E_INVALID_BN254_G2_SERIALIZATION);
        assert!(option::is_some(&crypto_algebra::deserialize<bn254_algebra::G2, bn254_algebra::FormatG2Compr>(&vk.gamma_g2)), E_INVALID_BN254_G2_SERIALIZATION);
        assert!(option::is_some(&crypto_algebra::deserialize<bn254_algebra::G2, bn254_algebra::FormatG2Compr>(&vk.delta_g2)), E_INVALID_BN254_G2_SERIALIZATION);
        for (i in 0..vector::length(&vk.gamma_abc_g1)) {
            assert!(option::is_some(&crypto_algebra::deserialize<bn254_algebra::G1, bn254_algebra::FormatG1Compr>(vector::borrow(&vk.gamma_abc_g1, i))), E_INVALID_BN254_G1_SERIALIZATION);
        };
    }
```

**File:** aptos-move/framework/aptos-framework/sources/keyless_account.move (L198-203)
```text
    public fun update_groth16_verification_key(fx: &signer, vk: Groth16VerificationKey) {
        system_addresses::assert_aptos_framework(fx);
        chain_status::assert_genesis();
        // There should not be a previous resource set here.
        move_to(fx, vk);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/keyless_account.move (L262-262)
```text
    /// WARNING: If a malicious key is set, this would lead to stolen funds.
```

**File:** types/src/keyless/circuit_constants.rs (L30-99)
```rust
pub fn prepared_vk_for_testing() -> PreparedVerifyingKey<Bn254> {
    // Convert the projective points to affine.
    let alpha_g1 = g1_projective_str_to_affine(
        "20491192805390485299153009773594534940189261866228447918068658471970481763042",
        "9383485363053290200918347156157836566562967994039712273449902621266178545958",
    )
    .unwrap();

    let beta_g2 = g2_projective_str_to_affine(
        [
            "6375614351688725206403948262868962793625744043794305715222011528459656738731",
            "4252822878758300859123897981450591353533073413197771768651442665752259397132",
        ],
        [
            "10505242626370262277552901082094356697409835680220590971873171140371331206856",
            "21847035105528745403288232691147584728191162732299865338377159692350059136679",
        ],
    )
    .unwrap();

    let gamma_g2 = g2_projective_str_to_affine(
        [
            "10857046999023057135944570762232829481370756359578518086990519993285655852781",
            "11559732032986387107991004021392285783925812861821192530917403151452391805634",
        ],
        [
            "8495653923123431417604973247489272438418190587263600148770280649306958101930",
            "4082367875863433681332203403145435568316851327593401208105741076214120093531",
        ],
    )
    .unwrap();

    let delta_g2 = g2_projective_str_to_affine(
        [
            "6309950375468367434079888575625734658722834850554198467265341412057133512289",
            "290788916745604303732014379515714703987358626088033030814233237684691015915",
        ],
        [
            "18062633083579661887564610476476551517623934510295133920710347041696656037149",
            "18531177357310703535722548657431805690263733685063962985389260695754645724386",
        ],
    )
    .unwrap();

    let mut gamma_abc_g1 = Vec::new();
    for points in [
        g1_projective_str_to_affine(
            "3314139460766150258181182511839382093976747705712051605578952681462625768062",
            "15177929890957116336235565528373348502554233971408496072173139426537995658198",
        )
        .unwrap(),
        g1_projective_str_to_affine(
            "11040819149070528816396253292991080175919431363817777522273571096667537087166",
            "13976660124609527451731647657081915019685631850685519260597009755390746148997",
        )
        .unwrap(),
    ] {
        gamma_abc_g1.push(points);
    }

    let vk = VerifyingKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1,
    };

    PreparedVerifyingKey::from(vk)
}
```

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L347-347)
```rust
                        let result = zksig.verify_groth16_proof(public_inputs_hash, pvk.unwrap());
```
