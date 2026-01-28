# Audit Report

## Title
Keyless ZKP Validation Performs Expensive Cryptographic Operations Before Gas Limit Checks

## Summary

The keyless transaction validation process performs computationally expensive zero-knowledge proof (ZKP) verification operations—including elliptic curve point deserialization with subgroup membership checks and Groth16 pairing verification—before validating that the transaction has sufficient gas. This allows attackers to submit keyless transactions with minimal gas that consume significant validator CPU resources before being rejected, enabling a resource exhaustion attack against validator nodes.

## Finding Description

The vulnerability exists in the transaction validation flow where keyless authenticator verification happens before gas limit validation. The documented transaction flow specifies that "check size and gas" should occur before other validation steps, but the implementation violates this ordering for keyless transactions.

**Validation Flow in VMValidator Path:**

In the mempool validation path, `VMValidator::validate_transaction` calls `validate_signed_transaction` without first calling `check_gas`: [1](#0-0) 

Within `validate_signed_transaction`, keyless authenticators are extracted and validated WITHOUT checking gas limits first: [2](#0-1) 

The `validate_authenticators` function does NOT receive a gas_meter parameter and performs expensive cryptographic operations: [3](#0-2) 

**Expensive Cryptographic Operations:**

During keyless validation, `verify_groth16_proof` is called which deserializes elliptic curve points: [4](#0-3) 

This triggers expensive elliptic curve deserialization with subgroup membership checks: [5](#0-4) 

The G1 and G2 point deserialization operations invoke `deserialize_compressed` which performs expensive elliptic curve arithmetic and subgroup membership verification: [6](#0-5) [7](#0-6) 

**Gas Check Happens After:**

In the execution path, `check_gas` is only called within `run_prologue_with_payload`, which occurs AFTER `validate_signed_transaction` completes: [8](#0-7) 

The `check_gas` function validates that the transaction has sufficient gas, including a KEYLESS_BASE_COST of 32,000,000 internal gas units: [9](#0-8) 

**Attack Scenario:**

An attacker can submit keyless transactions with `max_gas_amount` set to 1 (far below the KEYLESS_BASE_COST of 32,000,000). Each transaction will:
1. Pass BCS deserialization
2. Enter validation via `VMValidator::validate_transaction`
3. Trigger expensive G1/G2 elliptic curve point deserialization with subgroup checks
4. Potentially trigger Groth16 pairing verification
5. Finally be rejected for insufficient gas in `check_gas`

The attacker pays minimal or no fees while consuming disproportionate validator CPU resources.

## Impact Explanation

**Severity: High (Validator Node Slowdowns)**

This vulnerability qualifies as **High Severity** per the Aptos Bug Bounty framework: "Validator Node Slowdowns: Significant performance degradation affecting consensus, DoS through resource exhaustion."

- **Validator CPU Exhaustion**: Each malformed keyless transaction forces validators to perform expensive BN254 elliptic curve operations before rejecting the transaction for insufficient gas.

- **Network Throughput Degradation**: An attacker flooding the network can significantly slow down transaction processing and block production.

- **Low Attack Cost**: The attacker pays minimal fees (or none if rejected before prologue) while consuming significant computational resources.

This breaks **Critical Invariant #9**: "All operations must respect gas, storage, and computational limits." The system performs expensive cryptographic operations without first validating that the transaction has sufficient gas to cover them.

This is a protocol-level gas metering bug, distinct from network-layer DoS attacks (which are out of scope). The documented transaction flow explicitly shows "check size and gas" should happen before other validation, but the implementation violates this ordering for keyless transactions.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploited:

1. **No Special Privileges Required**: Any user can submit keyless transactions through the public API.

2. **Easy to Execute**: The attack requires only valid BCS-encoded transaction structures with keyless authenticators and minimal `max_gas_amount` values.

3. **Low Cost for Attacker**: Transactions are rejected before gas payment or the attacker pays minimal fees while consuming disproportionate resources.

4. **Immediate Impact**: Each transaction immediately triggers expensive cryptographic operations on validators.

5. **Scalability**: The attacker can automate submission of thousands of malicious transactions.

## Recommendation

Move the `check_gas` call to occur BEFORE keyless authenticator validation:

1. In `VMValidator::validate_transaction`, call `check_gas` before calling `validate_signed_transaction`
2. Alternatively, pass the gas_meter to `validate_authenticators` and charge gas for expensive operations
3. Ensure all expensive cryptographic operations are gas-metered before execution

The fix should ensure that the documented transaction flow (check signature → check size and gas → run prologue) is respected for keyless transactions.

## Proof of Concept

```rust
// PoC: Submit keyless transaction with minimal gas
// This transaction will trigger expensive ZKP validation before gas check

let keyless_txn = SignedTransaction::new(
    // Valid BCS-serialized keyless authenticator with Groth16 proof
    keyless_authenticator,
    sender,
    payload,
    sequence_number,
    max_gas_amount: 1, // Minimal gas, far below KEYLESS_BASE_COST (32M)
    gas_unit_price: 100,
    expiration_timestamp_secs,
    chain_id,
);

// Submit to validator - will trigger expensive G1/G2 deserialization
// before checking that max_gas_amount (1) < KEYLESS_BASE_COST (32M)
validator.validate_transaction(keyless_txn, state_view, module_storage);

// Transaction consumes significant CPU for elliptic curve operations
// then gets rejected for insufficient gas
```

## Notes

This vulnerability represents a protocol-level gas metering ordering bug where expensive cryptographic operations are performed before validating gas sufficiency. The system already recognizes keyless transactions are expensive (KEYLESS_BASE_COST = 32,000,000 gas units), but this validation occurs too late in the flow. The fix requires reordering validation to check gas limits before performing expensive operations, aligning the implementation with the documented transaction flow.

### Citations

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1798-1811)
```rust
        let keyless_authenticators = aptos_types::keyless::get_authenticators(transaction)
            .map_err(|_| VMStatus::error(StatusCode::INVALID_SIGNATURE, None))?;

        // If there are keyless TXN authenticators, validate them all.
        if !keyless_authenticators.is_empty() && !self.is_simulation {
            keyless_validation::validate_authenticators(
                self.environment().keyless_pvk(),
                self.environment().keyless_configuration(),
                &keyless_authenticators,
                self.features(),
                session.resolver,
                module_storage,
            )?;
        }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2805-2814)
```rust
        check_gas(
            self.gas_params(log_context)?,
            self.gas_feature_version(),
            session.resolver,
            module_storage,
            txn_data,
            self.features(),
            is_approved_gov_script,
            log_context,
        )?;
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3282-3291)
```rust
        let (counter_label, result) = match self.validate_signed_transaction(
            &mut session,
            module_storage,
            &txn,
            &txn_data,
            &log_context,
            is_approved_gov_script,
            &mut TraversalContext::new(&storage),
            &mut gas_meter,
        ) {
```

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L153-160)
```rust
pub(crate) fn validate_authenticators(
    pvk: Option<&PreparedVerifyingKey<Bn254>>,
    configuration: Option<&Configuration>,
    authenticators: &Vec<(AnyKeylessPublicKey, KeylessSignature)>,
    features: &Features,
    resolver: &impl AptosMoveResolver,
    module_storage: &impl ModuleStorage,
) -> Result<(), VMStatus> {
```

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L347-347)
```rust
                        let result = zksig.verify_groth16_proof(public_inputs_hash, pvk.unwrap());
```

**File:** types/src/keyless/groth16_sig.rs (L215-225)
```rust
    pub fn verify_proof(
        &self,
        public_inputs_hash: Fr,
        pvk: &PreparedVerifyingKey<Bn254>,
    ) -> anyhow::Result<()> {
        // let start = std::time::Instant::now();
        let proof: Proof<Bn254> = Proof {
            a: self.a.deserialize_into_affine()?,
            b: self.b.deserialize_into_affine()?,
            c: self.c.deserialize_into_affine()?,
        };
```

**File:** types/src/keyless/bn254_circom.rs (L136-142)
```rust
impl TryInto<G1Projective> for &G1Bytes {
    type Error = CryptoMaterialError;

    fn try_into(self) -> Result<G1Projective, CryptoMaterialError> {
        G1Projective::deserialize_compressed(self.0.as_slice())
            .map_err(|_| CryptoMaterialError::DeserializationError)
    }
```

**File:** types/src/keyless/bn254_circom.rs (L233-239)
```rust
impl TryInto<G2Projective> for &G2Bytes {
    type Error = CryptoMaterialError;

    fn try_into(self) -> Result<G2Projective, CryptoMaterialError> {
        G2Projective::deserialize_compressed(self.0.as_slice())
            .map_err(|_| CryptoMaterialError::DeserializationError)
    }
```

**File:** aptos-move/aptos-vm/src/gas.rs (L144-158)
```rust
    let keyless = if txn_metadata.is_keyless() {
        KEYLESS_BASE_COST.evaluate(gas_feature_version, &gas_params.vm)
    } else {
        InternalGas::zero()
    };
    let slh_dsa_sha2_128s = if txn_metadata.is_slh_dsa_sha2_128s() {
        SLH_DSA_SHA2_128S_BASE_COST.evaluate(gas_feature_version, &gas_params.vm)
    } else {
        InternalGas::zero()
    };
    let intrinsic_gas = txn_gas_params
        .calculate_intrinsic_gas(raw_bytes_len)
        .evaluate(gas_feature_version, &gas_params.vm);
    let total_rounded: Gas =
        (intrinsic_gas + keyless + slh_dsa_sha2_128s).to_unit_round_up_with_params(txn_gas_params);
```
