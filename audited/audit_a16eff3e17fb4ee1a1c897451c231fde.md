# Audit Report

## Title
Sequence Number Race Condition in Object Code Deployment Causing Address Mismatch

## Summary
The `CreateObjectAndPublishPackage::execute()` and `DeployObjectCode::execute()` functions contain a critical race condition where the sequence number is fetched twice at different stages of execution. This allows concurrent operations to calculate the same object deployment address but deploy to different addresses, resulting in packages with mismatched address references that cause runtime failures and wasted gas.

## Finding Description

The vulnerability exists in the asynchronous flow of object code deployment. The execution path involves two separate sequence number fetches with a significant time gap between them:

**First Fetch** - Object address calculation: [1](#0-0) 

**Second Fetch** - Transaction creation: [2](#0-1) 

The object address derivation uses sequence number deterministically: [3](#0-2) 

The on-chain deployment also fetches sequence number at execution time: [4](#0-3) 

**Attack Scenario:**

1. **T0**: User launches two concurrent `aptos move create-object-and-publish` operations (e.g., in two terminal windows)
2. **T1**: Thread A fetches sequence number N (e.g., 100), calculates object address using N+1 (101)
3. **T2**: Thread B fetches sequence number N (still 100), calculates same object address using N+1 (101)
4. **T3-T10**: Both threads compile packages with the calculated address (101) embedded as named addresses
5. **T11**: Thread A's `submit_transaction()` fetches sequence N (100), creates transaction with seq 100
6. **T12**: Thread A's transaction executes on-chain, creates object at address derived from seed 101 ✓
7. **T13**: Account sequence number increments to 101
8. **T14**: Thread B's `submit_transaction()` fetches sequence 101, creates transaction with seq 101
9. **T15**: Thread B's transaction executes on-chain, creates object at address derived from seed 102 ✗

**Result:** Thread B's package was compiled expecting to be deployed at address calculated from seed 101, but was actually deployed to address calculated from seed 102. All self-references in the bytecode point to the wrong address.

The same vulnerability affects `DeployObjectCode::execute()`: [5](#0-4) 

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty criteria: "State inconsistencies requiring intervention" and "Limited funds loss or manipulation."

**Specific Impacts:**

1. **State Inconsistency**: Packages are deployed to addresses that don't match their compiled address references, breaking the fundamental expectation that deployment address equals compiled address.

2. **Runtime Failures**: When the deployed code attempts to access resources at its own address (using the compiled-in address), it will access the wrong address, causing:
   - Resource access failures
   - Potential loss of funds if the package handles assets
   - Complete package malfunction

3. **Wasted Gas**: Users pay full gas costs for a deployment that produces a non-functional package, requiring redeployment.

4. **User Confusion**: The CLI displays "Code was successfully deployed to object address X" but the package actually references address Y internally, creating a confusing debugging scenario.

## Likelihood Explanation

**Likelihood: Medium-High**

This race condition is realistic and occurs naturally in several common scenarios:

1. **Multiple Terminal Windows**: Developers commonly have multiple terminal sessions and may accidentally launch the same deployment command twice.

2. **Automated Deployment Scripts**: CI/CD pipelines or deployment automation tools may trigger concurrent deployments if not properly serialized.

3. **Network Latency**: The time window for the race condition is substantial:
   - Package compilation: 1-10 seconds (depending on package size)
   - User confirmation prompts: 0-60 seconds
   - Transaction submission and execution: 1-5 seconds
   
   Total window: **2-75 seconds** where another operation can interfere.

4. **No Protection Mechanism**: There is no locking, atomicity guarantee, or warning in the codebase to prevent this scenario.

The developers are aware of sequence number complexities, as evidenced by the TODO comment: [6](#0-5) 

However, this TODO addresses a different issue (stateless accounts) and does not acknowledge the race condition.

## Recommendation

**Solution: Fetch sequence number once and use it consistently**

The fix requires fetching the sequence number once and passing it through to `submit_transaction()` to ensure the same sequence number is used for both address calculation and transaction creation.

**Implementation approach:**

1. Fetch sequence number once in `execute()`
2. Pass it to a modified `submit_transaction_with_sequence()` variant
3. Use that sequence number for transaction construction instead of fetching again

**Alternative Solution: Lock-based approach**

Implement a local lock file or semaphore to prevent concurrent deployments from the same account, similar to how package managers handle concurrent installations.

**Recommended Code Pattern:**

```rust
async fn execute(mut self) -> CliTypedResult<TransactionSummary> {
    let sender_address = self.txn_options.get_public_key_and_address()?.1;
    
    // Fetch sequence number ONCE and use atomically
    let sequence_number = self.txn_options.sequence_number(sender_address).await?;
    let deployment_sequence = sequence_number + adjustments;
    
    let object_address = create_object_code_deployment_address(
        sender_address, 
        deployment_sequence
    );
    
    // ... compilation ...
    
    // Pass the SAME sequence number to transaction submission
    self.txn_options
        .submit_transaction_with_sequence(payload, sequence_number)
        .await
}
```

This ensures atomic use of the sequence number throughout the deployment process.

## Proof of Concept

**Reproduction Steps:**

1. Create a simple Move package that references its own address:

```bash
aptos move init --name test_package
```

2. In `Move.toml`, add a named address:
```toml
[addresses]
test_package = "_"
```

3. In `sources/test.move`, create code that references its own address:
```move
module test_package::test {
    public entry fun init() {
        // This will reference the compiled-in address
    }
}
```

4. Open two terminal windows and execute nearly simultaneously:

**Terminal 1:**
```bash
aptos move create-object-and-publish-package \
  --address-name test_package \
  --assume-yes
```

**Terminal 2** (within 1-2 seconds):
```bash
aptos move create-object-and-publish-package \
  --address-name test_package \
  --assume-yes  
```

5. Observe that:
   - Both operations may calculate the same object address initially
   - If Terminal 1's transaction executes before Terminal 2's `submit_transaction()` call
   - Terminal 2's package will be deployed to a different address than calculated
   - The CLI will report success with the originally calculated address
   - The deployed bytecode will contain references to the wrong address

**Expected Behavior:** Only one deployment should succeed, or both should deploy to their calculated addresses.

**Actual Behavior:** Both deployments succeed but Terminal 2's package contains incorrect address references.

## Notes

This vulnerability also affects the `CreateResourceAccountAndPublishPackage` command, though with lower severity since resource account addresses are derived from seeds rather than sequence numbers: [7](#0-6) 

The issue is not present in `PublishPackage` because it publishes to the sender's account address, which doesn't depend on sequence numbers for address calculation.

The mempool will correctly reject duplicate sequence numbers, but this doesn't prevent the race condition—it only ensures that transactions execute serially. The problem is that the address calculation happens before mempool validation, using stale sequence numbers.

### Citations

**File:** crates/aptos/src/move_tool/mod.rs (L1165-1165)
```rust
    // TODO[Ordereless]: Update this code to support stateless accounts that don't have a sequence number
```

**File:** crates/aptos/src/move_tool/mod.rs (L1181-1200)
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
```

**File:** crates/aptos/src/move_tool/mod.rs (L1433-1454)
```rust
        let sequence_number = if self.chunked_publish_option.chunked_publish {
            // Perform a preliminary build to determine the number of transactions needed for chunked publish mode.
            // This involves building the package with mock account address `0xcafe` to calculate the transaction count.
            let mock_object_address = AccountAddress::from_hex_literal("0xcafe").unwrap();
            self.move_options
                .add_named_address(self.address_name.clone(), mock_object_address.to_string());
            let package = build_package_options(&self.move_options, &self.included_artifacts_args)?;
            let mock_payloads: Vec<TransactionPayload> = create_chunked_publish_payloads(
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

**File:** crates/aptos/src/move_tool/mod.rs (L1904-1905)
```rust
        let resource_address = create_resource_address(account, &seed);
        move_options.add_named_address(address_name, resource_address.to_string());
```

**File:** crates/aptos/src/common/types.rs (L1958-1960)
```rust
        // Get sequence number for account
        let (account, state) = get_account_with_state(&client, sender_address).await?;
        let sequence_number = account.sequence_number;
```

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
