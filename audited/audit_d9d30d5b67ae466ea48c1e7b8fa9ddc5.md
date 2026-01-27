# Audit Report

## Title
Time-of-Check-Time-of-Use Race Condition in Object Code Deployment Address Prediction

## Summary
Wallet applications that predict object addresses for code deployment using `create_object_code_deployment_address()` can compute incorrect addresses due to a race condition between querying the account sequence number and transaction execution. This causes users to deploy code to unexpected addresses, breaking package dependencies and potentially losing control of deployed modules.

## Finding Description

The vulnerability exists in the interaction between the off-chain address prediction logic and the on-chain address derivation during code deployment.

The Rust helper function accepts a sequence number as a parameter: [1](#0-0) 

However, the on-chain Move code computes the object address using the account's sequence number **at execution time**: [2](#0-1) 

The race condition occurs as follows:

1. Wallet queries the on-chain sequence number (e.g., N)
2. Wallet predicts object address using `create_object_code_deployment_address(user, N+1)`
3. Wallet displays predicted address to user and compiles package with this address
4. **Before the publish transaction executes**, another transaction from the same account gets executed (from a different wallet, dapp, or concurrent operation)
5. The account's sequence number is now N+1 on-chain
6. The publish transaction is assigned sequence number N+1
7. During execution, the Move code computes the seed using `account::get_sequence_number(publisher) + 1 = (N+1) + 1 = N+2`
8. The code is deployed to a **different address** than predicted

The CLI implementation demonstrates this pattern of predicting addresses before execution: [3](#0-2) 

This breaks the guarantee that wallets can reliably predict deployment addresses for UI display and package compilation. The sequence number is incremented in the transaction epilogue **after** payload execution: [4](#0-3) 

## Impact Explanation

**Severity: Medium** per Aptos bug bounty criteria - "wallet integration bugs" causing users to deploy code to unexpected locations or fail to manage their deployed objects.

Specific impacts:
- **Broken Package Dependencies**: Users compile packages with the predicted address, but code deploys elsewhere, breaking all address references
- **Loss of Module Control**: Users cannot find or manage their deployed modules using the predicted address
- **Failed Upgrades**: Subsequent upgrade attempts using the predicted address will fail
- **User Confusion**: Wallet UIs display incorrect deployment addresses, misleading users
- **Potential Deployment Failures**: If the predicted address was previously used, creation fails with `EOBJECT_EXISTS` error

The object creation validates uniqueness: [5](#0-4) 

## Likelihood Explanation

**Likelihood: Medium to High**

Common scenarios triggering this race condition:
- Users operating multiple wallet instances simultaneously
- Users interacting with dapps while deploying code
- Automated systems submitting transactions concurrently
- Any transaction queued between address prediction and execution

The vulnerability requires no special attacker capabilities - it's a natural consequence of concurrent transaction submission. The CLI code shows this is the expected usage pattern, with no warnings about race conditions.

Test code demonstrates the need to recompute addresses after each transaction: [6](#0-5) 

## Recommendation

Implement one of the following mitigations:

**Option 1: On-Chain Address Validation**
Modify `object_code_deployment::publish()` to accept an expected object address parameter and validate it matches the computed address:

```move
public entry fun publish(
    publisher: &signer,
    metadata_serialized: vector<u8>,
    code: vector<vector<u8>>,
    expected_address: address,  // NEW
) {
    // ... existing checks ...
    
    let object_seed = object_seed(publisher_address);
    let computed_address = object::create_object_address(&publisher_address, object_seed);
    
    // Validate prediction matches actual
    assert!(computed_address == expected_address, error::invalid_argument(EADDRESS_MISMATCH));
    
    let constructor_ref = &object::create_named_object(publisher, object_seed);
    // ... rest of function ...
}
```

**Option 2: Sequence Number Locking**
Provide wallets an API to atomically query sequence number and reserve it for a specific operation.

**Option 3: Documentation and SDK Improvements**
- Document the race condition in wallet integration guides
- Provide SDK methods that atomically build, sign, and submit with sequence number guarantees
- Add warnings when sequence numbers change between prediction and submission

## Proof of Concept

```rust
// Add to aptos-move/e2e-move-tests/src/tests/object_code_deployment.rs

#[test]
fn test_race_condition_wrong_address_prediction() {
    let mut harness = MoveHarness::new();
    let account = harness.new_account_at(AccountAddress::from_hex_literal("0xcafe").unwrap());
    
    // Step 1: Query sequence number
    let seq_num = harness.sequence_number(account.address());
    assert_eq!(seq_num, 0);
    
    // Step 2: Predict object address for next transaction
    let predicted_address = create_object_code_deployment_address(*account.address(), seq_num + 1);
    
    // Step 3: Another transaction executes (simulating concurrent activity)
    let other_txn = harness.create_entry_function(
        &account,
        str::parse("0x1::aptos_account::transfer").unwrap(),
        vec![],
        vec![
            bcs::to_bytes(&account.address()).unwrap(),
            bcs::to_bytes(&1u64).unwrap(),
        ],
    );
    assert_success!(harness.run(other_txn));
    
    // Step 4: Now sequence number is different
    let new_seq_num = harness.sequence_number(account.address());
    assert_eq!(new_seq_num, 1);
    
    // Step 5: Compute actual address that will be used
    let actual_address = create_object_code_deployment_address(*account.address(), new_seq_num + 1);
    
    // The predicted address is now WRONG
    assert_ne!(predicted_address, actual_address);
    
    // Step 6: Deploy code - it will go to actual_address, not predicted_address
    let mut options = BuildOptions::default();
    options.named_addresses.insert("object_addr".to_string(), predicted_address);
    
    // This will either fail or deploy to wrong address
    let result = harness.object_code_deployment_package(
        &account,
        &test_dir_path("object_code_deployment.data/pack_initial"),
        options,
    );
    
    // Code was deployed to actual_address, not predicted_address
    assert!(exists::<ManagingRefs>(actual_address));
    assert!(!exists::<ManagingRefs>(predicted_address));
}
```

## Notes

This vulnerability is inherent to the design of using sequence numbers for deterministic address generation. While the on-chain logic is correct and deterministic, the off-chain prediction creates a TOCTOU window. Wallets must either:
1. Ensure atomic transaction submission with no intermediate transactions
2. Recompute addresses immediately before submission
3. Handle address mismatches gracefully with proper error messaging

The vulnerability affects all wallet integrations that pre-compute and display object addresses for code deployment, making it a systemic wallet integration issue rather than an isolated bug.

### Citations

**File:** types/src/object_address.rs (L9-17)
```rust
pub fn create_object_code_deployment_address(
    creator: AccountAddress,
    creator_sequence_number: u64,
) -> AccountAddress {
    let mut seed = vec![];
    seed.extend(bcs::to_bytes(OBJECT_CODE_DEPLOYMENT_DOMAIN_SEPARATOR).unwrap());
    seed.extend(bcs::to_bytes(&creator_sequence_number).unwrap());
    create_object_address(creator, &seed)
}
```

**File:** aptos-move/framework/aptos-framework/sources/object_code_deployment.move (L94-106)
```text

        let publisher_address = signer::address_of(publisher);
        let object_seed = object_seed(publisher_address);
        let constructor_ref = &object::create_named_object(publisher, object_seed);
        let code_signer = &object::generate_signer(constructor_ref);
        code::publish_package_txn(code_signer, metadata_serialized, code);

        event::emit(Publish { object_address: signer::address_of(code_signer), });

        move_to(code_signer, ManagingRefs {
            extend_ref: object::generate_extend_ref(constructor_ref),
        });
    }
```

**File:** aptos-move/framework/aptos-framework/sources/object_code_deployment.move (L108-114)
```text
    inline fun object_seed(publisher: address): vector<u8> {
        let sequence_number = account::get_sequence_number(publisher) + 1;
        let seeds = vector[];
        vector::append(&mut seeds, bcs::to_bytes(&OBJECT_CODE_DEPLOYMENT_DOMAIN_SEPARATOR));
        vector::append(&mut seeds, bcs::to_bytes(&sequence_number));
        seeds
    }
```

**File:** crates/aptos/src/move_tool/mod.rs (L1181-1202)
```rust
        let sequence_number = if self.chunked_publish_option.chunked_publish {
            // Perform a preliminary build to determine the number of transactions needed for chunked publish mode.
            // This involves building the package with mock account address `0xcafe` to calculate the transaction count.
            let mock_object_address = AccountAddress::from_hex_literal("0xcafe").unwrap();
            self.move_options
                .add_named_address(self.address_name.clone(), mock_object_address.to_string());
            let package = build_package_options(&self.move_options, &self.included_artifacts_args)?;
            let mock_payloads = create_chunked_publish_payloads(
                package,
                PublishType::AccountDeploy,
                None,
                chunked_publish_large_packages_module_address.unwrap(),
                self.chunked_publish_option.chunk_size,
            )?
            .payloads;
            let staging_tx_count = (mock_payloads.len() - 1) as u64;
            self.txn_options.sequence_number(sender_address).await? + staging_tx_count + 1
        } else {
            self.txn_options.sequence_number(sender_address).await? + 1
        };

        let object_address = create_object_code_deployment_address(sender_address, sequence_number);
```

**File:** aptos-move/framework/aptos-framework/sources/object.move (L318-323)
```text
    fun create_object_internal(
        creator_address: address,
        object: address,
        can_delete: bool,
    ): ConstructorRef {
        assert!(!exists<ObjectCore>(object), error::already_exists(EOBJECT_EXISTS));
```

**File:** aptos-move/e2e-move-tests/src/tests/object_code_deployment.rs (L391-393)
```rust
    let sequence_number = context.harness.sequence_number(acc.address());
    context.object_address =
        create_object_code_deployment_address(*acc.address(), sequence_number + 1);
```
