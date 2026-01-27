# Audit Report

## Title
Resource Exhaustion via Unmetered Storage Reads in Federated Keyless Signature Validation

## Summary
An attacker can cause validator node slowdown or Denial of Service by submitting transactions with federated keyless authenticators that reference non-existent or unique `jwk_addr` values. Each such transaction triggers up to 3 expensive uncached database reads during mempool validation, before any gas is charged, allowing an attacker to flood the storage layer with read requests.

## Finding Description

The vulnerability exists in the keyless signature validation flow where federated keyless authenticators trigger expensive storage reads during transaction validation in the mempool, prior to gas metering.

**Attack Flow:**

1. **Transaction Submission to Mempool**: When transactions are submitted via API, they flow to mempool which validates them in parallel using `validate_transaction`. [1](#0-0) 

2. **Validation Calls Keyless Authenticator Check**: During validation, `validate_signed_transaction` extracts keyless authenticators and calls `keyless_validation::validate_authenticators` without passing a gas meter. [2](#0-1) 

3. **Per-Authenticator Storage Reads**: For each federated keyless authenticator in the transaction, if the JWK is not found in the main registry at `0x1`, the validation attempts to fetch JWKs from the custom `jwk_addr` specified in the authenticator. [3](#0-2) 

4. **Expensive Database I/O**: The `get_federated_jwks_onchain` function calls `get_resource_on_chain_at_addr`, which performs an expensive `get_resource_bytes_with_metadata_and_layout` call that reads from the database. [4](#0-3) [5](#0-4) 

5. **No Gas Metering**: This storage read happens during mempool validation (line 3282 in aptos_vm.rs), which occurs before gas is charged or the transaction is executed. [6](#0-5) 

**Attacker Control:**

The attacker controls the `jwk_addr` field in the `FederatedKeylessPublicKey`, which specifies where JWKs should be looked up. This is part of the public key structure and can be set to any address. [7](#0-6) 

**Attack Parameters:**

- Maximum keyless signatures per transaction is controlled by `max_signatures_per_txn`, which defaults to 3. [8](#0-7) 

- The limit check is enforced in validation: [9](#0-8) 

**Exploitation Scenario:**

1. Attacker creates transactions with 3 federated keyless authenticators, each with a unique `jwk_addr` (e.g., `0x1001`, `0x1002`, `0x1003`)
2. These addresses either don't exist or don't contain `FederatedJWKs` resources
3. Attacker submits thousands of such transactions to mempool via API
4. Each transaction triggers 3 database reads (one per authenticator) during validation
5. Parallel validation amplifies the load on storage: [1](#0-0) 

6. The storage layer is overwhelmed with read requests for non-existent resources
7. Validator nodes experience slowdown as storage becomes the bottleneck

**Cache Ineffectiveness:**

While `CachedDbStateView` provides caching, it is ineffective against this attack: [10](#0-9) 

Each VMValidator in the pool has its own cache, and the attacker uses unique addresses to bypass caching: [11](#0-10) 

This breaks **Invariant #9 (Resource Limits)**: Operations that consume significant resources (storage I/O) are being performed without gas metering or rate limiting during the mempool validation phase.

## Impact Explanation

This vulnerability falls under **High Severity** per the Aptos bug bounty program criteria:
- **Validator node slowdowns**: The primary impact is that validator nodes experience degraded performance as their storage layer is flooded with read requests
- **Potential DoS**: If sustained, this could make validators unable to process legitimate transactions in a timely manner

The attack does not require privileged access, only the ability to submit transactions to the network. The impact is amplified because:
1. Storage reads are among the most expensive operations in a blockchain node
2. Parallel validation means multiple expensive reads occur simultaneously
3. No gas is charged for failed validations, making the attack essentially free
4. Mempool capacity limits don't prevent the storage exhaustion since validation happens first

## Likelihood Explanation

**Likelihood: High**

The attack is highly likely to be exploited because:

1. **Low barrier to entry**: Attacker only needs to submit transactions via public API
2. **No resource cost**: Failed validations don't charge gas, making the attack free
3. **Simple to execute**: Creating transactions with custom `jwk_addr` values is straightforward
4. **Amplification factor**: Each transaction can trigger 3 storage reads, and parallel validation multiplies the effect
5. **Difficult to detect**: Failed validations from invalid keyless authenticators might appear as legitimate user errors

The only limiting factor is mempool's transaction submission rate limits, but since validation happens before mempool capacity checks are enforced, an attacker can still cause significant damage.

## Recommendation

**Immediate Mitigations:**

1. **Add rate limiting for federated keyless lookups**: Implement per-address rate limiting on `jwk_addr` lookups to prevent repeated queries to the same (non-existent) address.

2. **Implement negative caching**: Cache non-existent resource lookups (StateSlot::ColdVacant) across VMValidator instances to prevent repeated database queries for the same missing resources.

3. **Add early validation**: Check if `jwk_addr` contains a `FederatedJWKs` resource before performing full keyless validation. This could be done with a bloom filter or whitelist of known valid federated JWK addresses.

4. **Reduce max_signatures_per_txn**: Consider lowering the default value from 3 to 1 to reduce the attack surface.

**Proposed Code Fix (in `keyless_validation.rs`):**

```rust
// Add a cache of recently checked non-existent jwk_addr values
static NEGATIVE_CACHE: Lazy<DashMap<AccountAddress, Instant>> = Lazy::new(|| DashMap::new());

fn get_federated_jwks_onchain(
    resolver: &impl AptosMoveResolver,
    jwk_addr: &AccountAddress,
    module_storage: &impl ModuleStorage,
) -> anyhow::Result<FederatedJWKs, VMStatus> {
    // Check negative cache first (addresses known to not have FederatedJWKs)
    if let Some(cached_time) = NEGATIVE_CACHE.get(jwk_addr) {
        if cached_time.elapsed() < Duration::from_secs(60) {
            return Err(invalid_signature!(format!(
                "Could not fetch federated PatchedJWKs at {} (cached miss)",
                jwk_addr
            )));
        }
    }
    
    match get_resource_on_chain_at_addr::<FederatedJWKs>(jwk_addr, resolver, module_storage) {
        Ok(jwks) => Ok(jwks),
        Err(e) => {
            // Cache the negative result
            NEGATIVE_CACHE.insert(*jwk_addr, Instant::now());
            Err(e)
        }
    }
}
```

**Long-term Solution:**

Implement a global federated JWK registry where dapps/wallets must register their `jwk_addr` on-chain before they can be used in transactions. This would allow validators to maintain a whitelist of valid federated keyless addresses.

## Proof of Concept

```rust
// Proof of Concept: Demonstrate storage exhaustion via federated keyless authenticators
// This would be a Rust integration test

#[test]
fn test_storage_exhaustion_via_federated_keyless() {
    use aptos_types::transaction::authenticator::{
        AccountAuthenticator, TransactionAuthenticator,
    };
    use aptos_types::keyless::{FederatedKeylessPublicKey, KeylessPublicKey, KeylessSignature};
    use aptos_crypto::ed25519::Ed25519PrivateKey;
    
    // Create a test validator node setup
    let mut node = create_test_validator_node();
    
    // Generate 1000 transactions, each with 3 federated keyless authenticators
    // using unique jwk_addr values that don't exist on chain
    let mut transactions = vec![];
    for i in 0..1000 {
        let mut authenticators = vec![];
        for j in 0..3 {
            // Each authenticator uses a unique non-existent jwk_addr
            let unique_addr = AccountAddress::from_hex_literal(
                &format!("0x{:x}", 0x10000 + i * 3 + j)
            ).unwrap();
            
            let fed_pk = FederatedKeylessPublicKey {
                jwk_addr: unique_addr,
                pk: create_dummy_keyless_pk(),
            };
            
            // Create a signature (doesn't need to be valid since we're testing 
            // the storage exhaustion before signature verification)
            let sig = create_dummy_keyless_signature();
            
            authenticators.push((
                AnyKeylessPublicKey::Federated(fed_pk),
                sig,
            ));
        }
        
        // Create transaction with these authenticators
        let txn = create_transaction_with_keyless_authenticators(authenticators);
        transactions.push(txn);
    }
    
    // Measure storage read operations before submission
    let initial_storage_reads = node.get_storage_read_count();
    
    // Submit all transactions to mempool
    // This should trigger 3000 storage reads (1000 txns * 3 authenticators each)
    let start_time = Instant::now();
    for txn in transactions {
        node.submit_transaction(txn);
    }
    let duration = start_time.elapsed();
    
    // Measure storage reads after submission
    let final_storage_reads = node.get_storage_read_count();
    let total_reads = final_storage_reads - initial_storage_reads;
    
    // Assert that:
    // 1. Massive number of storage reads occurred (close to 3000)
    assert!(total_reads >= 2500, "Expected ~3000 storage reads, got {}", total_reads);
    
    // 2. This happened quickly due to parallel validation
    assert!(duration.as_secs() < 10, "Validation should be fast due to parallelism");
    
    // 3. No gas was charged (all transactions failed validation)
    let gas_charged = node.get_total_gas_charged();
    assert_eq!(gas_charged, 0, "No gas should be charged for failed validations");
    
    // 4. Validator experienced slowdown (next legitimate transaction is delayed)
    let legitimate_txn = create_legitimate_transaction();
    let legitimate_start = Instant::now();
    node.submit_transaction(legitimate_txn);
    let legitimate_duration = legitimate_start.elapsed();
    
    assert!(
        legitimate_duration > Duration::from_millis(500),
        "Legitimate transaction should be delayed due to storage exhaustion"
    );
}
```

**Notes**

This vulnerability is particularly concerning because:

1. **Zero-cost attack**: The attacker doesn't pay gas for failed validations
2. **Parallel amplification**: The use of `par_iter` in mempool validation means many storage reads happen simultaneously
3. **Bypass of existing limits**: The `max_signatures_per_txn` limit of 3 still allows meaningful damage when multiplied across many transactions
4. **Cache ineffectiveness**: Using unique `jwk_addr` values renders caching useless
5. **Pre-consensus impact**: The attack affects nodes before transactions even reach consensus

The attack exploits a fundamental assumption that validation is lightweight, but federated keyless validation breaks this assumption by performing expensive database I/O without gas metering or proper rate limiting.

### Citations

**File:** mempool/src/shared_mempool/tasks.rs (L490-503)
```rust
    let validation_results = VALIDATION_POOL.install(|| {
        transactions
            .par_iter()
            .map(|t| {
                let result = smp.validator.read().validate_transaction(t.0.clone());
                // Pre-compute the hash and length if the transaction is valid, before locking mempool
                if result.is_ok() {
                    t.0.committed_hash();
                    t.0.txn_bytes_len();
                }
                result
            })
            .collect::<Vec<_>>()
    });
```

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

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L60-71)
```rust
    let bytes = resolver
        .get_resource_bytes_with_metadata_and_layout(addr, &struct_tag, &module.metadata, None)
        .map_err(|e| e.finish(Location::Undefined).into_vm_status())?
        .0
        .ok_or_else(|| {
            value_deserialization_error!(format!(
                "get_resource failed on {}::{}::{}",
                addr.to_hex_literal(),
                T::struct_tag().module,
                T::struct_tag().name
            ))
        })?;
```

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L96-102)
```rust
fn get_federated_jwks_onchain(
    resolver: &impl AptosMoveResolver,
    jwk_addr: &AccountAddress,
    module_storage: &impl ModuleStorage,
) -> anyhow::Result<FederatedJWKs, VMStatus> {
    get_resource_on_chain_at_addr::<FederatedJWKs>(jwk_addr, resolver, module_storage)
}
```

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L202-205)
```rust
    if authenticators.len() > config.max_signatures_per_txn as usize {
        // println!("[aptos-vm][groth16] Too many keyless authenticators");
        return Err(invalid_signature!("Too many keyless authenticators"));
    }
```

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L235-260)
```rust
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

**File:** types/src/keyless/mod.rs (L1-50)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

use crate::{
    keyless::circuit_constants::prepared_vk_for_testing,
    state_store::state_key::StateKey,
    transaction::{
        authenticator::{
            AnyPublicKey, AnySignature, EphemeralPublicKey, EphemeralSignature, MAX_NUM_OF_SIGS,
        },
        SignedTransaction,
    },
};
use anyhow::bail;
use aptos_crypto::{poseidon_bn254, CryptoMaterialError, ValidCryptoMaterial};
use aptos_crypto_derive::{BCSCryptoHash, CryptoHasher};
use ark_bn254::Bn254;
use ark_groth16::PreparedVerifyingKey;
use ark_serialize::CanonicalSerialize;
use base64::URL_SAFE_NO_PAD;
use bytes::Bytes;
use move_core_types::{
    account_address::AccountAddress,
    ident_str,
    identifier::IdentStr,
    language_storage::{StructTag, CORE_CODE_ADDRESS},
    move_resource::{MoveResource, MoveStructType},
};
use once_cell::sync::Lazy;
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize, Serializer};
use std::{
    collections::BTreeMap,
    str,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub mod bn254_circom;
pub mod circuit_constants;
pub mod circuit_testcases;
mod configuration;
mod groth16_sig;
mod groth16_vk;
mod openid_sig;
pub mod proof_simulation;
pub mod test_utils;
mod zkp_sig;

use crate::state_store::StateView;
pub use bn254_circom::{
    g1_projective_str_to_affine, g2_projective_str_to_affine, get_public_inputs_hash, G1Bytes,
```

**File:** types/src/keyless/configuration.rs (L62-73)
```rust
    pub fn new_for_devnet() -> Configuration {
        Configuration {
            override_aud_vals: vec![Self::OVERRIDE_AUD_FOR_TESTING.to_owned()],
            max_signatures_per_txn: 3,
            max_exp_horizon_secs: 10_000_000, // ~115.74 days
            training_wheels_pubkey: None,
            max_commited_epk_bytes: circuit_constants::MAX_COMMITED_EPK_BYTES,
            max_iss_val_bytes: circuit_constants::MAX_ISS_VAL_BYTES,
            max_extra_field_bytes: circuit_constants::MAX_EXTRA_FIELD_BYTES,
            max_jwt_header_b64_bytes: circuit_constants::MAX_JWT_HEADER_B64_BYTES,
        }
    }
```

**File:** storage/storage-interface/src/state_store/state_view/cached_state_view.rs (L308-340)
```rust
pub struct CachedDbStateView {
    db_state_view: DbStateView,
    state_cache: RwLock<HashMap<StateKey, StateSlot>>,
}

impl From<DbStateView> for CachedDbStateView {
    fn from(db_state_view: DbStateView) -> Self {
        Self {
            db_state_view,
            state_cache: RwLock::new(HashMap::new()),
        }
    }
}

impl TStateView for CachedDbStateView {
    type Key = StateKey;

    fn id(&self) -> StateViewId {
        self.db_state_view.id()
    }

    fn get_state_slot(&self, state_key: &Self::Key) -> StateViewResult<StateSlot> {
        // First check if the cache has the state value.
        if let Some(val_opt) = self.state_cache.read().get(state_key) {
            // This can return None, which means the value has been deleted from the DB.
            return Ok(val_opt.clone());
        }
        let state_slot = self.db_state_view.get_state_slot(state_key)?;
        // Update the cache if still empty
        let mut cache = self.state_cache.write();
        let new_value = cache.entry(state_key.clone()).or_insert_with(|| state_slot);
        Ok(new_value.clone())
    }
```

**File:** vm-validator/src/vm_validator.rs (L123-140)
```rust
pub struct PooledVMValidator {
    vm_validators: Vec<Arc<Mutex<VMValidator>>>,
}

impl PooledVMValidator {
    pub fn new(db_reader: Arc<dyn DbReader>, pool_size: usize) -> Self {
        let mut vm_validators = Vec::new();
        for _ in 0..pool_size {
            vm_validators.push(Arc::new(Mutex::new(VMValidator::new(db_reader.clone()))));
        }
        PooledVMValidator { vm_validators }
    }

    fn get_next_vm(&self) -> Arc<Mutex<VMValidator>> {
        let mut rng = thread_rng(); // Create a thread-local random number generator
        let random_index = rng.gen_range(0, self.vm_validators.len()); // Generate random index
        self.vm_validators[random_index].clone() // Return the VM at the random index
    }
```
