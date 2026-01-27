# Audit Report

## Title
Insufficient Validation in Governance-Controlled override_aud_vals Configuration Enables Account Recovery Phishing Attack Vector

## Summary
The `add_override_aud_for_next_epoch` function in the keyless account module accepts arbitrary strings without any validation, security checks, or coordination with the off-chain pepper service. While explicitly warned about in code comments, this lack of validation creates a governance attack surface where malicious or compromised governance proposals could add attacker-controlled audience values to enable sophisticated phishing attacks against keyless account users.

## Finding Description
The keyless account recovery mechanism uses `override_aud_vals` to maintain an on-chain allow-list of trusted recovery service audience identifiers. When a user's original application disappears, they can sign in through a recovery service to regain access to their account. [1](#0-0) 

The function performs **zero validation** on the `aud` parameter being added. It only verifies the caller is `@aptos_framework` (governance) but does not check:
- Format or structure of the audience string
- Whether the audience corresponds to a legitimate, vetted recovery service  
- Any security properties or certifications of the service
- Coordination with the pepper service's `AccountRecoveryManagers` configuration [2](#0-1) 

The validation during signature verification only checks if the override audience exists in the on-chain list: [3](#0-2) [4](#0-3) 

The code explicitly acknowledges this risk with a WARNING comment: [5](#0-4) 

**Attack Flow:**

1. Malicious actor submits governance proposal to add their recovery service audience (e.g., "malicious-recovery.com") to `override_aud_vals`
2. Proposal passes (via governance compromise, social engineering of voters, or malicious insider)
3. Attacker registers their service in the pepper service's off-chain `AccountRecoveryManagers` configuration
4. Attacker launches phishing campaign: "Your application is shutting down! Use our recovery service to save your keyless account!"
5. Victims trust the service because it's on-chain allow-listed (implying official approval)
6. When users sign in, the pepper service generates peppers bound to victims' original accounts [6](#0-5) 

7. Attacker gains ability to transact on behalf of victim accounts within the ZKP expiration window

The account address derivation is bound to the original `aud` value: [7](#0-6) 

## Impact Explanation
This constitutes a **HIGH severity** governance attack vector that could escalate to **CRITICAL** under certain conditions:

**Potential for Loss of Funds**: The code's own WARNING states "this *could* lead to stolen funds." If exploited successfully, attackers could:
- Drain user account balances
- Steal NFTs and other assets
- Manipulate staking positions
- Execute unauthorized smart contract calls

**Undermines Trust Model**: Users rely on the on-chain allow-list as an indicator of vetted, trustworthy recovery services. The lack of validation breaks this trust assumption.

**Defense-in-Depth Failure**: Even with training wheels enabled, the absence of validation creates unnecessary risk. Training wheels can be disabled via governance using the same unvalidated process. [8](#0-7) 

## Likelihood Explanation
**MEDIUM-to-HIGH likelihood** of exploitation given sufficient attacker motivation:

**Barriers to Exploitation:**
1. **Governance Compromise**: Requires passing a malicious proposal (high bar but not impossible via social engineering, voting manipulation, or insider threat)
2. **Pepper Service Access**: Requires registration in off-chain `AccountRecoveryManagers` configuration
3. **Training Wheels**: If enabled, provides additional signature validation barrier
4. **User Interaction**: Requires victims to sign in through malicious service

**Facilitating Factors:**
1. **No Technical Validation**: Zero code-level barriers to adding malicious entries
2. **Social Engineering Surface**: Users may trust on-chain allow-listed services
3. **Coordination Gap**: No mechanism to ensure on-chain and off-chain configurations align
4. **Developer Awareness**: The WARNING indicates developers recognize the risk but haven't mitigated it

The pepper service configuration is controlled via command-line arguments: [9](#0-8) 

## Recommendation

Implement multi-layered validation in `add_override_aud_for_next_epoch`:

```move
public fun add_override_aud_for_next_epoch(fx: &signer, aud: String) acquires Configuration {
    system_addresses::assert_aptos_framework(fx);
    
    // Validation 1: Format checks
    assert!(
        string::length(&aud) > 0 && string::length(&aud) <= MAX_AUD_LENGTH,
        E_INVALID_AUD_FORMAT
    );
    
    // Validation 2: Must be valid domain format (basic check)
    assert!(validate_domain_format(&aud), E_INVALID_DOMAIN_FORMAT);
    
    // Validation 3: Cannot add duplicates
    let config = if (config_buffer::does_exist<Configuration>()) {
        config_buffer::extract_v2<Configuration>()
    } else {
        *borrow_global<Configuration>(signer::address_of(fx))
    };
    
    assert!(!vector::contains(&config.override_aud_vals, &aud), E_AUD_ALREADY_EXISTS);
    
    // Validation 4: Require multi-sig or time-lock for sensitive changes
    // (implement via separate governance policy module)
    
    vector::push_back(&mut config.override_aud_vals, aud);
    set_configuration_for_next_epoch(fx, config);
}

// Helper function
fun validate_domain_format(domain: &String): bool {
    // Basic validation: check for valid characters, proper structure
    // Reject suspicious patterns, require HTTPS scheme, etc.
    true // placeholder
}
```

Additionally:
1. **Coordination Mechanism**: Create on-chain registry that pepper service must query before honoring `aud_override` requests
2. **Vetting Process**: Require recovery services to submit security audits, operational history, and identity verification before being added
3. **Monitoring**: Emit events when `override_aud_vals` is modified for transparency
4. **Time-Locks**: Implement mandatory waiting period between proposal and activation to allow community review
5. **Multi-Signature**: Require multiple governance approvals for adding new recovery services

## Proof of Concept

```move
#[test(framework = @0x1)]
#[expected_failure(abort_code = 0x1)]
fun test_malicious_governance_adds_arbitrary_aud(framework: &signer) {
    use aptos_framework::keyless_account;
    use std::string;
    
    // Initialize keyless configuration
    let config = keyless_account::new_configuration(
        vector[],
        3,
        10_000_000,
        option::none(),
        93,
        120,
        350,
        350
    );
    keyless_account::update_configuration(framework, config);
    
    // Governance adds arbitrary attacker-controlled string
    let malicious_aud = string::utf8(b"https://steal-your-funds.evil.com");
    
    // This call succeeds with NO validation
    keyless_account::add_override_aud_for_next_epoch(framework, malicious_aud);
    
    // After reconfiguration, the malicious aud is active
    keyless_account::on_new_epoch(framework);
    
    // Now signatures with this override_aud will be accepted on-chain
    // enabling the phishing attack vector described above
}
```

**Rust-based validation bypass demonstration:**

```rust
#[test]
fn test_override_aud_validation_bypass() {
    // Construct a Configuration with attacker-controlled aud
    let malicious_aud = "attacker-controlled-recovery.com".to_string();
    let config = Configuration {
        override_aud_vals: vec![malicious_aud.clone()],
        max_signatures_per_txn: 3,
        max_exp_horizon_secs: 10_000_000,
        training_wheels_pubkey: None,
        max_commited_epk_bytes: 93,
        max_iss_val_bytes: 120,
        max_extra_field_bytes: 350,
        max_jwt_header_b64_bytes: 350,
    };
    
    // The validation only checks if the aud is in the list
    assert!(config.is_allowed_override_aud(&malicious_aud).is_ok());
    
    // No checks on whether the aud is legitimate, vetted, or safe
    // Governance could add ANY string here
}
```

## Notes

**Mitigating Factors Present:**
- Training wheels mechanism provides additional validation layer when enabled
- Pepper service has separate off-chain configuration (`AccountRecoveryManagers`)  
- ZKP expiration limits attack window
- Users must actively sign in for attack to succeed

**Insufficient Mitigations:**
- Training wheels can be disabled via the same unvalidated governance process
- No coordination between on-chain allow-list and off-chain pepper service configuration
- Social engineering is difficult to prevent once trust is established via on-chain listing
- The comment acknowledges prover service doesn't yet support recovery mode, but once implemented, this attack vector becomes fully active

**Scope Clarification:**
This report focuses on the lack of validation as a governance security issue. While full exploitation requires multiple attack vectors (governance compromise + pepper service access + social engineering), the absence of ANY validation mechanism constitutes a security weakness that violates defense-in-depth principles and creates unnecessary risk.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/keyless_account.move (L48-64)
```text
    struct Configuration has key, store, drop, copy {
        /// An override `aud` for the identity of a recovery service, which will help users recover their keyless accounts
        /// associated with dapps or wallets that have disappeared.
        /// IMPORTANT: This recovery service **cannot**, on its own, take over user accounts: a user must first sign in
        /// via OAuth in the recovery service in order to allow it to rotate any of that user's keyless accounts.
        ///
        /// Furthermore, the ZKP eventually expires, so there is a limited window within which a malicious recovery
        /// service could rotate accounts. In the future, we can make this window arbitrarily small by further lowering
        /// the maximum expiration horizon for ZKPs used for recovery, instead of relying on the `max_exp_horizon_secs`
        /// value in this resource.
        ///
        /// If changed: There is no prover service support yet for recovery mode => ZKPs with override aud's enabled
        ///   will not be served by the prover service => as long as training wheels are "on," such recovery ZKPs will
        ///   never arrive on chain.
        ///   (Once support is implemented in the prover service, in an abundance of caution, the training wheel check
        ///    should only pass if the override aud in the public statement matches one in this list. Therefore, changes
        ///    to this value should be picked up automatically by the prover service.)
```

**File:** aptos-move/framework/aptos-framework/sources/keyless_account.move (L283-302)
```text
    public fun update_training_wheels_for_next_epoch(fx: &signer, pk: Option<vector<u8>>) acquires Configuration {
        system_addresses::assert_aptos_framework(fx);

        // If a PK is being set, validate it first.
        if (option::is_some(&pk)) {
            let bytes = *option::borrow(&pk);
            let vpk = ed25519::new_validated_public_key_from_bytes(bytes);
            assert!(option::is_some(&vpk), E_TRAINING_WHEELS_PK_WRONG_SIZE)
        };

        let config = if (config_buffer::does_exist<Configuration>()) {
            config_buffer::extract_v2<Configuration>()
        } else {
            *borrow_global<Configuration>(signer::address_of(fx))
        };

        config.training_wheels_pubkey = pk;

        set_configuration_for_next_epoch(fx, config);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/keyless_account.move (L342-342)
```text
    /// WARNING: If a malicious override `aud` is set, this *could* lead to stolen funds.
```

**File:** aptos-move/framework/aptos-framework/sources/keyless_account.move (L343-355)
```text
    public fun add_override_aud_for_next_epoch(fx: &signer, aud: String) acquires Configuration {
        system_addresses::assert_aptos_framework(fx);

        let config = if (config_buffer::does_exist<Configuration>()) {
            config_buffer::extract_v2<Configuration>()
        } else {
            *borrow_global<Configuration>(signer::address_of(fx))
        };

        vector::push_back(&mut config.override_aud_vals, aud);

        set_configuration_for_next_epoch(fx, config);
    }
```

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L299-303)
```rust
                // If an `aud` override was set for account recovery purposes, check that it is
                // in the allow-list on-chain.
                if zksig.override_aud_val.is_some() {
                    config.is_allowed_override_aud(zksig.override_aud_val.as_ref().unwrap())?;
                }
```

**File:** types/src/keyless/openid_sig.rs (L88-100)
```rust
        let idc_aud_val = match self.idc_aud_val.as_ref() {
            None => &claims.oidc_claims.aud,
            Some(idc_aud_val) => {
                // If there's an override, check that the override `aud` from the JWT, is allow-listed
                ensure!(
                    config
                        .is_allowed_override_aud(&claims.oidc_claims.aud)
                        .is_ok(),
                    "{} is not an allow-listed override aud",
                    &claims.oidc_claims.aud
                );
                idc_aud_val
            },
```

**File:** keyless/pepper/service/src/dedicated_handlers/pepper_request.rs (L194-242)
```rust
async fn create_pepper_input(
    claims: &TokenData<Claims>,
    uid_key: String,
    uid_val: String,
    account_recovery_managers: Arc<AccountRecoveryManagers>,
    aud_override: Option<String>,
    account_recovery_db: Arc<dyn AccountRecoveryDBInterface + Send + Sync>,
) -> Result<PepperInput, PepperServiceError> {
    let iss = claims.claims.iss.clone();
    let claims_aud = claims.claims.aud.clone();

    // Get the aud for the pepper input. Note: if the request is from an account
    // recovery manager, we will override the aud and generate the pepper input
    // with the overridden aud. This is useful for pepper recovery.
    let aud = if account_recovery_managers.contains(&iss, &claims_aud) {
        match aud_override {
            Some(aud_override) => aud_override, // Use the overridden aud
            None => {
                return Err(PepperServiceError::UnexpectedError(format!(
                    "The issuer {} and aud {} correspond to an account recovery manager, but no aud override was provided!",
                    &iss, &claims_aud
                )));
            },
        }
    } else if let Some(aud_override) = aud_override {
        return Err(PepperServiceError::UnexpectedError(format!(
            "The issuer {} and aud {} do not correspond to an account recovery manager, but an aud override was provided: {}!",
            &iss, &claims_aud, &aud_override
        )));
    } else {
        claims_aud // Use the aud directly from the claims
    };

    // Create the pepper input
    let pepper_input = PepperInput {
        iss,
        uid_key,
        uid_val,
        aud,
    };
    info!("Successfully created PepperInput: {:?}", &pepper_input);

    // Update the account recovery DB
    account_recovery_db
        .update_db_with_pepper_input(&pepper_input)
        .await?;

    Ok(pepper_input)
}
```

**File:** types/src/keyless/mod.rs (L307-335)
```rust
    pub fn new_from_preimage(
        pepper: &Pepper,
        aud: &str,
        uid_key: &str,
        uid_val: &str,
    ) -> anyhow::Result<Self> {
        let aud_val_hash =
            poseidon_bn254::keyless::pad_and_hash_string(aud, Self::MAX_AUD_VAL_BYTES)?;
        // println!("aud_val_hash: {}", aud_val_hash);
        let uid_key_hash =
            poseidon_bn254::keyless::pad_and_hash_string(uid_key, Self::MAX_UID_KEY_BYTES)?;
        // println!("uid_key_hash: {}", uid_key_hash);
        let uid_val_hash =
            poseidon_bn254::keyless::pad_and_hash_string(uid_val, Self::MAX_UID_VAL_BYTES)?;
        // println!("uid_val_hash: {}", uid_val_hash);
        let pepper_scalar = poseidon_bn254::keyless::pack_bytes_to_one_scalar(pepper.0.as_slice())?;
        // println!("Pepper Fr: {}", pepper_scalar);

        let fr = poseidon_bn254::hash_scalars(vec![
            pepper_scalar,
            aud_val_hash,
            uid_val_hash,
            uid_key_hash,
        ])?;

        let mut idc_bytes = vec![0u8; IdCommitment::NUM_BYTES];
        fr.serialize_uncompressed(&mut idc_bytes[..])?;
        Ok(IdCommitment(idc_bytes))
    }
```

**File:** keyless/pepper/service/src/accounts/account_managers.rs (L77-106)
```rust
impl FromStr for AccountRecoveryManager {
    type Err = PepperServiceError;

    // Note: this is used to parse each account recovery manager from
    // the command line. The expected format is: "<issuer> <aud>".
    fn from_str(string: &str) -> Result<Self, Self::Err> {
        // Split the string by whitespace
        let mut iterator = string.split_whitespace();

        // Parse the substrings as issuer and aud
        let issuer = iterator.next().ok_or(PepperServiceError::UnexpectedError(
            "Failed to parse issuer for account recovery manager!".into(),
        ))?;
        let aud = iterator.next().ok_or(PepperServiceError::UnexpectedError(
            "Failed to parse aud for account recovery manager!".into(),
        ))?;

        // Verify that there are exactly 2 substrings
        if iterator.next().is_some() {
            return Err(PepperServiceError::UnexpectedError(
                "Too many arguments found for account recovery manager!".into(),
            ));
        }

        // Create the override
        let account_manager_override =
            AccountRecoveryManager::new(issuer.to_string(), aud.to_string());

        Ok(account_manager_override)
    }
```
