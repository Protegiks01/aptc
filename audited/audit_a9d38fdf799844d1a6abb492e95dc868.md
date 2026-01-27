# Audit Report

## Title
Insufficient Validation of Initial JWKs During Genesis Allows Insertion of Malicious Keys

## Summary
The genesis initialization process accepts arbitrary JWKs without validation, allowing malicious or compromised JWKs to be permanently embedded in the blockchain from genesis. While JWKs themselves do not expire in the protocol design, the complete absence of validation enables unauthorized keyless account access if an attacker controls the genesis configuration.

## Finding Description

The vulnerability exists in the genesis initialization flow where `initial_jwks` are processed without any content validation: [1](#0-0) 

The `Layout` struct accepts arbitrary JWKs through the `initial_jwks` field. These are passed through the genesis configuration without validation: [2](#0-1) 

The `generate_genesis_txn()` function passes these JWKs directly to the VM genesis encoder: [3](#0-2) 

In the genesis validation function, **no validation of `initial_jwks` occurs**: [4](#0-3) 

The JWKs are then installed directly via `initialize_keyless_accounts()`: [5](#0-4) 

The `set_patches()` Move function only validates the signer, not the JWK content: [6](#0-5) 

During transaction validation, these unchecked JWKs are used to verify keyless account signatures: [7](#0-6) 

**Note on JWK Expiry:** JWKs in the Aptos protocol do not have expiry fields: [8](#0-7) 

The RSA_JWK struct contains only cryptographic parameters (`kid`, `kty`, `alg`, `e`, `n`) with no temporal constraints. Expiry is tracked separately in ephemeral signatures, not in the JWKs themselves.

## Impact Explanation

**Critical Severity Assessment:**

However, this vulnerability **fails the exploitability requirement** for bug bounty eligibility. The attack requires compromising the genesis configuration process, which is controlled by trusted Aptos core developers/foundation members. This is an **insider threat scenario** explicitly excluded from the trust model:

- Genesis configuration is a **one-time trusted setup** process
- Only Aptos core team members can modify genesis layout files
- Unprivileged external attackers cannot inject malicious JWKs without compromising trusted parties

While the technical impact would be Critical (unauthorized access to all keyless accounts using the malicious issuer), the **operational reality** is that this requires social engineering or insider compromise of the genesis ceremony itself.

## Likelihood Explanation

**Likelihood: Very Low (for unprivileged attackers)**

The attack is not feasible for unprivileged attackers because:

1. **Genesis is a trusted ceremony** - Only authorized Aptos team members participate
2. **Genesis happens once** - Cannot be repeated or exploited post-launch
3. **Multiple review checkpoints** - Genesis configuration undergoes peer review
4. **Requires insider access** - Must compromise a genesis ceremony participant

For an insider with malicious intent, likelihood increases but remains out of scope per the stated trust model.

## Recommendation

Despite being out of scope for unprivileged attackers, defense-in-depth measures are recommended:

1. **Add JWK validation during genesis**:
   - Verify JWK cryptographic parameters are well-formed
   - Cross-reference against known OIDC provider endpoints
   - Require multi-party approval for non-standard JWKs

2. **Implement cryptographic verification**:
   - Verify RSA modulus size constraints
   - Validate base64 encoding of JWK components
   - Ensure algorithm parameters match expected values

3. **Add genesis audit logging**:
   - Log all initial_jwks with cryptographic hashes
   - Require explicit acknowledgment of non-empty initial_jwks
   - Include JWK fingerprints in genesis waypoint

## Proof of Concept

This PoC demonstrates that malicious JWKs can be technically inserted if genesis access is obtained (operational exploit not shown):

```yaml
# In genesis layout.yaml (requires genesis ceremony access)
initial_jwks:
  - issuer: "https://malicious-oidc.example.com"
    jwk:
      variant:
        type_name: "0x1::jwks::RSA_JWK"
        data:
          kid: "malicious-key-001"
          kty: "RSA"
          alg: "RS256"
          e: "AQAB"
          n: "yWPl8gQhE..." # Attacker-controlled RSA public key
```

Once in genesis, the attacker with the corresponding private key can forge JWT signatures for keyless accounts using this issuer.

---

**FINAL ASSESSMENT:** While technically valid as a code weakness, this vulnerability **does not meet bug bounty criteria** because it requires compromising trusted genesis ceremony participants. It represents an **operational security concern** rather than an exploitable protocol vulnerability by unprivileged attackers.

Per the trust model: "Do **not** assume these actors behave maliciously unless the question explicitly explores insider threats." Since insider threats are not explicitly in scope, this should be treated as an operational hardening recommendation rather than a critical vulnerability.

### Citations

**File:** crates/aptos-genesis/src/config.rs (L84-85)
```rust
    #[serde(default)]
    pub initial_jwks: Vec<IssuerJWK>,
```

**File:** crates/aptos-genesis/src/lib.rs (L81-81)
```rust
    pub initial_jwks: Vec<IssuerJWK>,
```

**File:** crates/aptos-genesis/src/lib.rs (L136-166)
```rust
    fn generate_genesis_txn(&self) -> Transaction {
        aptos_vm_genesis::encode_genesis_transaction(
            self.root_key.clone(),
            &self.validators,
            &self.framework,
            self.chain_id,
            &aptos_vm_genesis::GenesisConfiguration {
                allow_new_validators: self.allow_new_validators,
                epoch_duration_secs: self.epoch_duration_secs,
                is_test: true,
                min_stake: self.min_stake,
                min_voting_threshold: self.min_voting_threshold,
                max_stake: self.max_stake,
                recurring_lockup_duration_secs: self.recurring_lockup_duration_secs,
                required_proposer_stake: self.required_proposer_stake,
                rewards_apy_percentage: self.rewards_apy_percentage,
                voting_duration_secs: self.voting_duration_secs,
                voting_power_increase_limit: self.voting_power_increase_limit,
                employee_vesting_start: 1663456089,
                employee_vesting_period_duration: 5 * 60, // 5 minutes
                initial_features_override: self.initial_features_override.clone(),
                randomness_config_override: self.randomness_config_override.clone(),
                jwk_consensus_config_override: self.jwk_consensus_config_override.clone(),
                initial_jwks: self.initial_jwks.clone(),
                keyless_groth16_vk: self.keyless_groth16_vk.clone(),
            },
            &self.consensus_config,
            &self.execution_config,
            &self.gas_schedule,
        )
    }
```

**File:** aptos-move/vm-genesis/src/lib.rs (L405-439)
```rust
fn validate_genesis_config(genesis_config: &GenesisConfiguration) {
    assert!(
        genesis_config.min_stake <= genesis_config.max_stake,
        "Min stake must be smaller than or equal to max stake"
    );
    assert!(
        genesis_config.epoch_duration_secs > 0,
        "Epoch duration must be > 0"
    );
    assert!(
        genesis_config.recurring_lockup_duration_secs > 0,
        "Recurring lockup duration must be > 0"
    );
    assert!(
        genesis_config.recurring_lockup_duration_secs >= genesis_config.epoch_duration_secs,
        "Recurring lockup duration must be at least as long as epoch duration"
    );
    assert!(
        genesis_config.rewards_apy_percentage > 0 && genesis_config.rewards_apy_percentage < 100,
        "Rewards APY must be > 0% and < 100%"
    );
    assert!(
        genesis_config.voting_duration_secs > 0,
        "On-chain voting duration must be > 0"
    );
    assert!(
        genesis_config.voting_duration_secs < genesis_config.recurring_lockup_duration_secs,
        "Voting duration must be strictly smaller than recurring lockup"
    );
    assert!(
        genesis_config.voting_power_increase_limit > 0
            && genesis_config.voting_power_increase_limit <= 50,
        "voting_power_increase_limit must be > 0 and <= 50"
    );
}
```

**File:** aptos-move/vm-genesis/src/lib.rs (L908-976)
```rust
fn initialize_keyless_accounts(
    session: &mut SessionExt<impl AptosMoveResolver>,
    module_storage: &impl AptosModuleStorage,
    traversal_context: &mut TraversalContext,
    chain_id: ChainId,
    mut initial_jwks: Vec<IssuerJWK>,
    vk: Option<Groth16VerificationKey>,
) {
    let config = keyless::Configuration::new_for_devnet();
    exec_function(
        session,
        module_storage,
        traversal_context,
        KEYLESS_ACCOUNT_MODULE_NAME,
        "update_configuration",
        vec![],
        serialize_values(&vec![
            MoveValue::Signer(CORE_CODE_ADDRESS),
            config.as_move_value(),
        ]),
    );

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
    }
    if !chain_id.is_mainnet() {
        let additional_jwk_patch = IssuerJWK {
            issuer: get_sample_iss(),
            jwk: JWK::RSA(secure_test_rsa_jwk()),
        };
        initial_jwks.insert(0, additional_jwk_patch);

        let jwk_patches: Vec<PatchJWKMoveStruct> = initial_jwks
            .into_iter()
            .map(|issuer_jwk| {
                let IssuerJWK { issuer, jwk } = issuer_jwk;
                let upsert_patch = PatchUpsertJWK {
                    issuer,
                    jwk: JWKMoveStruct::from(jwk),
                };
                PatchJWKMoveStruct::from(upsert_patch)
            })
            .collect();

        exec_function(
            session,
            module_storage,
            traversal_context,
            JWKS_MODULE_NAME,
            "set_patches",
            vec![],
            serialize_values(&vec![
                MoveValue::Signer(CORE_CODE_ADDRESS),
                jwk_patches.as_move_value(),
            ]),
        );
    }
}
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L379-383)
```text
    public fun set_patches(fx: &signer, patches: vector<Patch>) acquires Patches, PatchedJWKs, ObservedJWKs {
        system_addresses::assert_aptos_framework(fx);
        borrow_global_mut<Patches>(@aptos_framework).patches = patches;
        regenerate_patched_jwks();
    }
```

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L220-260)
```rust
    let patched_jwks = get_jwks_onchain(resolver)?;

    let training_wheels_pk = match &config.training_wheels_pubkey {
        None => None,
        // This takes ~4.4 microseconds, so we are not too concerned about speed here.
        // (Run `cargo bench -- ed25519/pk_deserialize` in `crates/aptos-crypto`.)
        Some(bytes) => Some(EphemeralPublicKey::ed25519(
            Ed25519PublicKey::try_from(bytes.as_slice()).map_err(|_| {
                // println!("[aptos-vm][groth16] On chain TW PK is invalid");

                invalid_signature!("The training wheels PK set on chain is not a valid PK")
            })?,
        )),
    };

    for (pk, sig) in authenticators {
        // Try looking up the jwk in 0x1.
        let jwk = match get_jwk_for_authenticator(&patched_jwks.jwks, pk.inner_keyless_pk(), sig) {
            // 1: If found in 0x1, then we consider that the ground truth & we are done.
            Ok(jwk) => jwk,
            // 2: If not found in 0x1, we check the Keyless PK type.
            Err(e) => {
                match pk {
                    // 2.a: If this is a federated keyless account; look in `jwk_addr` for JWKs
                    AnyKeylessPublicKey::Federated(fed_pk) => {
                        let federated_jwks =
                            get_federated_jwks_onchain(resolver, &fed_pk.jwk_addr, module_storage)
                                .map_err(|_| {
                                    invalid_signature!(format!(
                                        "Could not fetch federated PatchedJWKs at {}",
                                        fed_pk.jwk_addr
                                    ))
                                })?;
                        // 2.a.i If not found in jwk_addr either, then we fail the validation.
                        get_jwk_for_authenticator(&federated_jwks.jwks, pk.inner_keyless_pk(), sig)?
                    },
                    // 2.b: If this is not a federated keyless account, then we fail the validation.
                    AnyKeylessPublicKey::Normal(_) => return Err(e),
                }
            },
        };
```

**File:** types/src/jwks/rsa/mod.rs (L18-25)
```rust
#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize, Object)]
pub struct RSA_JWK {
    pub kid: String,
    pub kty: String,
    pub alg: String,
    pub e: String,
    pub n: String,
}
```
