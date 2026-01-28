# Audit Report

## Title
Keyless Account Groth16 Proof Verification Enables Unmetered DoS Attacks on Validators

## Summary
Groth16 zero-knowledge proof verification for keyless accounts occurs during transaction prologue validation before gas is charged. Attackers can submit transactions with valid ephemeral signatures but invalid Groth16 proofs, forcing validators to perform expensive cryptographic operations without paying gas fees, enabling resource exhaustion attacks against validator nodes.

## Finding Description

The keyless authentication system performs signature verification in two distinct stages, creating an exploitable asymmetry in computational cost:

**Stage 1 - Mempool Admission:** During `check_signature()`, only the ephemeral signature is verified. The code explicitly defers expensive verification: [1](#0-0) 

This allows transactions with valid ephemeral signatures but invalid Groth16 proofs to enter the mempool.

**Stage 2 - Prologue Validation:** During transaction execution, `validate_signed_transaction` calls `validate_authenticators`: [2](#0-1) 

This performs the expensive Groth16 proof verification: [3](#0-2) 

The Groth16 verification involves point deserialization with subgroup checks and pairing operations: [4](#0-3) 

**Critical Vulnerability:** When Groth16 verification fails, it returns `INVALID_SIGNATURE` error. The `unwrap_or_discard!` macro catches this and discards the transaction: [5](#0-4) 

Discarded transactions do NOT charge gas: [6](#0-5) 

The `charge_keyless()` function that would charge gas is only called AFTER successful prologue validation: [7](#0-6) 

**Attack Flow:**
1. Attacker generates ephemeral keypairs and signs transactions (fast operation ~50 microseconds)
2. Attacker crafts invalid Groth16 proofs or reuses the same invalid proof
3. Transactions pass `check_signature()` because only ephemeral signature is verified
4. Transactions enter mempool with valid signatures
5. During block execution, each validator performs expensive Groth16 verification
6. Verification fails, transaction receives `INVALID_SIGNATURE` status code
7. `INVALID_SIGNATURE` has `StatusType::Validation`, resulting in `TransactionStatus::Discard`: [8](#0-7) 

8. **No gas charged** - validator wasted CPU cycles on cryptographic operations
9. Attacker repeats with multiple accounts to bypass per-account mempool limits

## Impact Explanation

This constitutes **High Severity** per Aptos bug bounty criteria under "Validator Node Slowdowns" - significant performance degradation affecting consensus through DoS via resource exhaustion.

**Computational Cost Disparity:**
- Ed25519 signature verification: ~50 microseconds
- Groth16 proof verification: Involves G1/G2 point deserialization and pairing operations (significantly more expensive)

The benchmark infrastructure exists for measuring this: [9](#0-8) 

**Resource Exhaustion Scenario:**
An attacker controlling 100 keyless accounts (bypassing per-account mempool limits of 100 transactions per account) can submit thousands of transactions that:
- Pass mempool admission (cheap ephemeral signature check)
- Force validators to perform expensive Groth16 verification
- Get discarded without gas payment
- Repeat continuously

Each validator must independently verify these transactions during block execution, consuming significant CPU resources without any cost to the attacker beyond minimal balance requirements for gas estimation.

## Likelihood Explanation

**Likelihood: High**

The attack requires minimal resources and complexity:
1. **Creating keyless accounts** - publicly available feature
2. **Generating ephemeral signatures** - trivial cryptographic operation using standard libraries
3. **Crafting invalid proofs** - can reuse the same malformed proof bytes across all transactions
4. **Bypassing rate limits** - attacker can create multiple keyless accounts

The mempool enforces per-account transaction limits: [10](#0-9) 

However, this provides minimal protection as attackers can distribute transactions across many accounts.

**No Economic Deterrent:** Unlike normal transaction spam which incurs gas costs even on failure, this attack imposes zero cost on the attacker while forcing validators to perform expensive cryptographic operations. The cost asymmetry makes this attack economically viable.

## Recommendation

Implement one of the following mitigations:

**Option 1: Charge Minimum Gas Before Prologue Validation**
Charge a base intrinsic gas cost before entering `validate_signed_transaction`, ensuring failed validation still results in gas payment. Modify the flow to charge `charge_keyless()` before keyless validation occurs.

**Option 2: Perform Groth16 Verification at Mempool Admission**
Move Groth16 verification to mempool admission stage. This requires making the verification key and on-chain configuration available to mempool validators, but prevents invalid proofs from consuming validator resources during block execution.

**Option 3: Rate Limit Keyless Validation Failures**
Track keyless validation failures per sender and implement exponential backoff or temporary bans for accounts repeatedly submitting transactions with invalid proofs.

**Option 4: Proof Verification Caching**
Cache negative verification results for (proof, public_inputs_hash) pairs to avoid re-verifying the same invalid proof multiple times across transactions.

The recommended solution is **Option 1** as it maintains the existing architecture while ensuring cost symmetry - failed validation should always result in some gas charge to deter resource exhaustion attacks.

## Proof of Concept

```rust
// Conceptual PoC - demonstrates the attack flow
// In practice, attacker would:
// 1. Create keyless account with valid setup
// 2. Generate ephemeral keypair
// 3. Sign transaction with ephemeral key
// 4. Attach INVALID Groth16 proof (e.g., all zeros or random bytes)
// 5. Submit transaction
// 6. Transaction passes mempool (ephemeral sig valid)
// 7. During execution, Groth16 verification fails
// 8. Transaction discarded, NO GAS CHARGED
// 9. Repeat with multiple accounts/transactions

// The key insight is in the code flow:
// - authenticator.rs:1306-1309: Only ephemeral signature checked at mempool
// - keyless_validation.rs:347: Expensive Groth16 verification in prologue
// - aptos_vm.rs:626-629: Failed validation = Discard = No gas charged
// - aptos_vm.rs:1042: charge_keyless() only called AFTER successful validation
```

### Citations

**File:** types/src/transaction/authenticator.rs (L1319-1331)
```rust
    fn verify_keyless_ephemeral_signature<T: Serialize + CryptoHash>(
        message: &T,
        signature: &KeylessSignature,
    ) -> Result<()> {
        // Verifies the ephemeral signature on (TXN [+ ZKP]). The rest of the verification,
        // i.e., [ZKPoK of] OpenID signature verification is done in
        // `AptosVM::run_prologue`.
        //
        // This is because the JWK, under which the [ZKPoK of an] OpenID signature verifies,
        // can only be fetched from on chain inside the `AptosVM`.
        //
        // This deferred verification is what actually ensures the `signature.ephemeral_pubkey`
        // used below is the right pubkey signed by the OIDC provider.
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L176-189)
```rust
macro_rules! unwrap_or_discard {
    ($res:expr) => {
        match $res {
            Ok(s) => s,
            Err(e) => {
                // covers both VMStatus itself and VMError which can convert to VMStatus
                let s: VMStatus = e.into();

                let o = discarded_output(s.status_code());
                return (s, o);
            },
        }
    };
}
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L626-629)
```rust
            TransactionStatus::Discard(status_code) => {
                let discarded_output = discarded_output(status_code);
                (error_vm_status, discarded_output)
            },
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1040-1043)
```rust
        gas_meter.charge_intrinsic_gas_for_transaction(txn_data.transaction_size())?;
        if txn_data.is_keyless() {
            gas_meter.charge_keyless()?;
        }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1802-1810)
```rust
        if !keyless_authenticators.is_empty() && !self.is_simulation {
            keyless_validation::validate_authenticators(
                self.environment().keyless_pvk(),
                self.environment().keyless_configuration(),
                &keyless_authenticators,
                self.features(),
                session.resolver,
                module_storage,
            )?;
```

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L347-362)
```rust
                        let result = zksig.verify_groth16_proof(public_inputs_hash, pvk.unwrap());

                        result.map_err(|_| {
                            // println!("[aptos-vm][groth16] ZKP verification failed");
                            // println!("[aptos-vm][groth16] PIH: {}", public_inputs_hash);
                            // match zksig.proof {
                            //     ZKP::Groth16(proof) => {
                            //         println!("[aptos-vm][groth16] ZKP: {}", proof.hash());
                            //     },
                            // }
                            // println!(
                            //     "[aptos-vm][groth16] PVK: {}",
                            //     Groth16VerificationKey::from(pvk).hash()
                            // );
                            invalid_signature!("Proof verification failed")
                        })?;
```

**File:** types/src/keyless/groth16_sig.rs (L215-235)
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
        // println!("Deserialization time: {:?}", start.elapsed());

        // let start = std::time::Instant::now();
        let verified = Groth16::<Bn254>::verify_proof(pvk, &proof, &[public_inputs_hash])?;
        // println!("Proof verification time: {:?}", start.elapsed());
        if !verified {
            bail!("groth16 proof verification failed")
        }
        Ok(())
    }
```

**File:** types/src/transaction/mod.rs (L1639-1648)
```rust
            Err(code) => {
                if code.status_type() == StatusType::InvariantViolation
                    && features.is_enabled(FeatureFlag::CHARGE_INVARIANT_VIOLATION)
                {
                    Self::Keep(ExecutionStatus::MiscellaneousError(Some(code)))
                } else {
                    Self::Discard(code)
                }
            },
        }
```

**File:** crates/aptos-crypto/benches/ark_bn254.rs (L521-546)
```rust
fn bench_groth16_verify(b: &mut Bencher) {
    let pvk = ark_groth16::PreparedVerifyingKey {
        vk: ark_groth16::VerifyingKey {
            alpha_g1: rand!(G1Affine),
            beta_g2: rand!(G2Affine),
            gamma_g2: rand!(G2Affine),
            delta_g2: rand!(G2Affine),
            gamma_abc_g1: vec![rand!(G1Affine), rand!(G1Affine)],
        },
        alpha_g1_beta_g2: rand!(ark_bn254::Fq12),
        gamma_g2_neg_pc: rand!(G2Affine).into(),
        delta_g2_neg_pc: rand!(G2Affine).into(),
    };

    b.iter_with_setup(
        || ark_groth16::Proof {
            a: rand!(G1Affine),
            b: rand!(G2Affine),
            c: rand!(G1Affine),
        },
        |proof| {
            let result = Groth16::<Bn254>::verify_proof(&pvk, &proof, &[rand!(Fr)]);
            assert!(matches!(result, Ok(false)))
        },
    )
}
```

**File:** mempool/src/core_mempool/transaction_store.rs (L327-348)
```rust
                                "Mempool over capacity for account. Number of seq number transactions from account: {} Capacity per account: {}",
                                txns.seq_num_txns_len() ,
                                self.capacity_per_user,
                            ),
                        );
                    }
                },
                ReplayProtector::Nonce(_) => {
                    if txns.orderless_txns_len() >= self.orderless_txn_capacity_per_user {
                        return MempoolStatus::new(MempoolStatusCode::TooManyTransactions).with_message(
                            format!(
                                "Mempool over capacity for account. Number of orderless transactions from account: {} Capacity per account: {}",
                                txns.orderless_txns_len(),
                                self.orderless_txn_capacity_per_user,
                            ),
                        );
                    }
                },
            }
            // insert into storage and other indexes
            self.system_ttl_index.insert(&txn);
            self.expiration_time_index.insert(&txn);
```
