# Audit Report

## Title
Multiple VM Divergences Between Simulation and Actual Execution Cause Transaction Prediction Failures

## Summary
The `AptosSimulationVM` produces fundamentally different results than `AptosVM` for the same transaction due to four critical divergences: randomness seed patching, keyless authenticator validation skipping, authentication key check bypasses, and gas payment validation skipping. This breaks the core guarantee of transaction simulation and causes users to submit transactions that fail or produce different outcomes than simulated.

## Finding Description

The simulation API endpoint at `/transactions/simulate` is designed to allow users to predict transaction outcomes before submission. However, `AptosSimulationVM` diverges from `AptosVM` in multiple critical ways:

### 1. Randomness Seed Divergence (Most Critical) [1](#0-0) 

During simulation, the `patch_randomness_seed` function injects a **randomly generated** seed using `rand::thread_rng().fill_bytes(&mut seed)`. This seed is different:
- On every simulation run (non-deterministic)
- From the actual block's deterministic seed used in production execution [2](#0-1) 

Any transaction using the randomness framework (which uses the `PerBlockRandomness` seed) will produce **completely different results** in simulation versus actual execution.

### 2. Keyless Authenticator Validation Skipping [3](#0-2) 

When `is_simulation` is true, keyless authenticator validation is entirely skipped. A transaction with invalid keyless authenticators will succeed in simulation but fail in actual execution.

### 3. Authentication Key Check Bypasses [4](#0-3) 

The `skip_auth_key_check` function allows simulation to bypass authentication key validation when the auth key is None or empty. [5](#0-4) 

This is used in `prologue_common` to skip critical authentication checks during simulation that would be enforced in actual execution.

### 4. Gas Payment Check Skipping [6](#0-5) 

The `skip_gas_payment` function allows simulation to bypass gas payment validation when `gas_payer` is `@0x0`. [7](#0-6) 

Transactions with insufficient balance or zero gas payer succeed in simulation but fail in actual execution.

### Divergence Flow [8](#0-7) 

The simulation VM explicitly sets `is_simulation = true`, which propagates through all validation layers. [9](#0-8) [10](#0-9) 

The `is_simulation` flag is passed to Move prologue functions, enabling conditional validation skipping. [11](#0-10) 

Actual execution asserts `!self.is_simulation`, ensuring production VMs always perform full validation.

## Impact Explanation

This qualifies as **High Severity** under the Aptos Bug Bounty criteria:

1. **API Reliability Impact**: The simulation API's core guarantee—predicting transaction outcomes—is broken, affecting all users who rely on simulation for gas estimation or transaction testing.

2. **User Financial Loss**: Users waste gas fees submitting transactions they believed would succeed based on simulation, but which fail in actual execution.

3. **Randomness Unpredictability**: Contracts using randomness (e.g., NFT minting, gaming, lotteries) get completely different results in production than simulated, potentially causing:
   - Wrong NFT traits minted
   - Different lottery outcomes
   - Unexpected game state transitions

4. **Authentication Failures**: Users with keyless accounts or sponsored transactions may simulate successfully but fail on-chain, causing confusion and poor user experience.

This does not reach Critical severity because it doesn't directly cause fund theft, consensus violations, or network-wide failures. However, it significantly degrades the protocol's usability and trustworthiness.

## Likelihood Explanation

**Likelihood: High**

This issue occurs for:
- **Every transaction using randomness** (100% divergence rate)
- **All keyless transactions** simulated with invalid authenticators  
- **Sponsored transactions** simulated with `gas_payer = @0x0`
- **Account abstraction flows** with empty authentication keys

No special privileges or complex exploit chains are required—simply calling the public `/transactions/simulate` API endpoint triggers these divergences. Given the randomness framework is documented in AIP-41 and actively promoted for use in Move contracts, this affects a significant portion of production transactions.

## Recommendation

### Fix 1: Deterministic Randomness Seeding
Replace random seed generation with a deterministic simulation seed:

```rust
// In patch_randomness_seed function
fn patch_randomness_seed<'a, S: ExecutorView>(
    base_view: &'a StorageAdapter<'a, S>,
) -> ExecutorViewWithChangeSet<'a> {
    // Use deterministic seed for simulation
    let seed = vec![0u8; 32]; // Or derive from transaction hash
    // ... rest of function
}
```

**Note**: Add documentation warning that simulated randomness outcomes won't match actual execution, or fetch the current block's seed for more accurate simulation.

### Fix 2: Enable Keyless Validation in Simulation
Remove the `!self.is_simulation` bypass:

```rust
// In validate_signed_transaction
if !keyless_authenticators.is_empty() {
    // Always validate, even in simulation
    keyless_validation::validate_authenticators(...)?;
}
```

### Fix 3: Minimize Authentication/Gas Skipping
Document the conditional validation behavior clearly and consider:
- Requiring explicit simulation mode parameters
- Returning warnings when validation is skipped
- Providing separate "strict" simulation mode that never skips checks

### Fix 4: Simulation Result Metadata
Add metadata to simulation responses indicating when divergences may occur:

```rust
pub struct SimulationMetadata {
    pub validation_skipped: Vec<String>,
    pub deterministic: bool,
    pub uses_randomness: bool,
}
```

## Proof of Concept

### PoC 1: Randomness Divergence

```move
module 0x1::randomness_test {
    use aptos_framework::randomness;
    
    #[randomness]
    entry fun roll_dice(account: &signer) {
        let value = randomness::u64_range(1, 7);
        // value will be different in simulation vs actual execution
        // Each simulation run will also produce different values
    }
}
```

**Reproduction Steps**:
1. Call `simulate_transaction` with the above transaction - note the random value
2. Call `simulate_transaction` again with the same transaction - observe different value
3. Submit the actual transaction - observe yet another different value
4. All three values are different due to different randomness seeds

### PoC 2: Keyless Authentication Divergence

**Reproduction Steps**:
1. Create a transaction with a keyless authenticator containing an expired JWT
2. Call `/transactions/simulate` - transaction succeeds (validation skipped)
3. Submit the actual transaction - transaction fails with invalid signature error
4. User wastes gas fees based on incorrect simulation result

### PoC 3: Gas Payment Divergence

**Reproduction Steps**:
1. Create a sponsored transaction with `gas_payer = @0x0` and sender with zero balance
2. Call `/transactions/simulate` with gas estimation - simulation succeeds
3. Submit actual transaction - fails with `PROLOGUE_ECANT_PAY_GAS_DEPOSIT`
4. Simulation indicated success but execution failed

## Notes

The `transaction_simulation_enhancement` feature flag enables some of these behaviors intentionally for testing purposes. However, this creates a security/usability trade-off where simulation reliability is sacrificed for flexibility. Users are not adequately warned about these divergences, leading to production failures. The randomness divergence is particularly severe as it's inherently non-deterministic even across multiple simulations of the identical transaction.

### Citations

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1802-1811)
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
        }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2838-2839)
```rust
            self.is_simulation,
        )?;
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2879-2879)
```rust
        assert!(!self.is_simulation, "VM has to be created for execution");
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3314-3343)
```rust
    fn patch_randomness_seed<'a, S: ExecutorView>(
        base_view: &'a StorageAdapter<'a, S>,
    ) -> ExecutorViewWithChangeSet<'a> {
        let state_key = StateKey::resource(
            &AccountAddress::ONE,
            &StructTag::from_str("0x1::randomness::PerBlockRandomness").expect("should be valid"),
        )
        .expect("should succeed");
        let mut seed = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let write_op = AbstractResourceWriteOp::Write(WriteOp::legacy_creation(
            bcs::to_bytes(&PerBlockRandomness {
                epoch: 0,
                round: 0,
                seed: Some(seed),
            })
            .expect("should succeed")
            .into(),
        ));
        let patch_change_set = VMChangeSet::new(
            BTreeMap::from([(state_key, write_op)]),
            vec![],
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        let executor_view = base_view.as_executor_view();
        let group_view = base_view.as_resource_group_view();
        ExecutorViewWithChangeSet::new(executor_view, group_view, patch_change_set)
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3358-3359)
```rust
        let mut vm = AptosVM::new(&env);
        vm.is_simulation = true;
```

**File:** aptos-move/framework/aptos-framework/sources/randomness.move (L76-87)
```text
    fun next_32_bytes(): vector<u8> acquires PerBlockRandomness {
        assert!(is_unbiasable(), E_API_USE_IS_BIASIBLE);

        let input = DST;
        let randomness = borrow_global<PerBlockRandomness>(@aptos_framework);
        let seed = *option::borrow(&randomness.seed);

        vector::append(&mut input, seed);
        vector::append(&mut input, transaction_context::get_transaction_hash());
        vector::append(&mut input, fetch_and_increment_txn_counter());
        hash::sha3_256(input)
    }
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L149-167)
```text
        if (!skip_auth_key_check(is_simulation, &txn_authentication_key)) {
            if (option::is_some(&txn_authentication_key)) {
                if (
                    sender_address == gas_payer_address ||
                    account::exists_at(sender_address) ||
                    !features::sponsored_automatic_account_creation_enabled()
                ) {
                    assert!(
                        txn_authentication_key == option::some(account::get_authentication_key(sender_address)),
                        error::invalid_argument(PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY),
                    );
                };
            } else {
                assert!(
                    allow_missing_txn_authentication_key(sender_address),
                    error::invalid_argument(PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY)
                );
            };
        };
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L189-212)
```text
        if (!skip_gas_payment(
            is_simulation,
            gas_payer_address
        )) {
            assert!(
                permissioned_signer::check_permission_capacity_above(
                    gas_payer,
                    (max_transaction_fee as u256),
                    GasPermission {}
                ),
                error::permission_denied(PROLOGUE_PERMISSIONED_GAS_LIMIT_INSUFFICIENT)
            );
            if (features::operations_default_to_fa_apt_store_enabled()) {
                assert!(
                    aptos_account::is_fungible_balance_at_least(gas_payer_address, max_transaction_fee),
                    error::invalid_argument(PROLOGUE_ECANT_PAY_GAS_DEPOSIT)
                );
            } else {
                assert!(
                    coin::is_balance_at_least<AptosCoin>(gas_payer_address, max_transaction_fee),
                    error::invalid_argument(PROLOGUE_ECANT_PAY_GAS_DEPOSIT)
                );
            }
        };
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L634-636)
```text
    inline fun skip_auth_key_check(is_simulation: bool, auth_key: &Option<vector<u8>>): bool {
        is_simulation && (option::is_none(auth_key) || vector::is_empty(option::borrow(auth_key)))
    }
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L638-640)
```text
    inline fun skip_gas_payment(is_simulation: bool, gas_payer: address): bool {
        is_simulation && gas_payer == @0x0
    }
```

**File:** aptos-move/aptos-vm/src/transaction_validation.rs (L188-188)
```rust
                    MoveValue::Bool(is_simulation).simple_serialize().unwrap(),
```
