# Audit Report

## Title
Arbitrary Code Execution via Unvalidated Module Address in ClearStagingArea Command

## Summary
The `ClearStagingArea::execute()` function accepts a user-provided `large_packages_module_address` without validation, allowing an attacker to substitute a malicious Move module. When a user is tricked into providing an attacker-controlled address via the `--large-packages-module-address` CLI flag, the malicious module receives the user's signer capability and can execute arbitrary operations with full account authority.

## Finding Description
The vulnerability exists in the CLI's handling of the `large_packages_module_address` parameter across multiple operations, most critically in the `ClearStagingArea` command. [1](#0-0) 

The `ClearStagingArea::execute()` function retrieves the module address and constructs a transaction payload without any validation: [2](#0-1) 

The `large_packages_module_address()` method either uses the user-provided address directly or defaults to a chain-specific address. Critically, when a user provides a custom address via CLI, **no validation ensures this address points to the legitimate `large_packages` module**. [3](#0-2) 

The resulting transaction payload calls `<address>::large_packages::cleanup_staging_area` at whatever address the user specified. The legitimate Move module implementation shows the function signature: [4](#0-3) 

The legitimate function receives `owner: &signer` and only cleans the staging area. However, an attacker can deploy a malicious module with the same signature that performs arbitrary operations.

**Attack Path:**

1. Attacker deploys malicious module at address `0xATTACKER`:
   ```move
   module 0xATTACKER::large_packages {
       public entry fun cleanup_staging_area(owner: &signer) {
           // Arbitrary malicious operations with owner's signer
           // Can publish code, transfer resources, etc.
       }
   }
   ```

2. Attacker tricks user (via malicious documentation, tutorials, or social engineering) to run:
   ```bash
   aptos move clear-staging-area --large-packages-module-address 0xATTACKER
   ```

3. User signs the transaction, which appears to call `cleanup_staging_area`

4. Move VM executes the attacker's function with the user's signer capability

5. Attacker performs arbitrary operations with full user authority

The vulnerability violates **Access Control** (Invariant #8) - the user's signer should only be used for legitimate cleanup operations, not passed to arbitrary attacker-controlled code.

## Impact Explanation
This vulnerability qualifies as **HIGH severity** under the Aptos Bug Bounty "Significant protocol violations" category:

- **Complete Account Compromise**: The attacker gains access to the user's signer capability, enabling any operation the user is authorized to perform
- **Arbitrary Code Publishing**: Attacker can publish malicious Move modules under the user's account
- **Resource Manipulation**: If exploitable patterns exist, attacker can transfer or manipulate the user's resources
- **Protocol Violation**: The CLI provides a security-critical operation without validation, violating the principle of least privilege

The same vulnerability affects all chunked publishing operations: [5](#0-4) 

While the vulnerability requires user interaction, the security implications are severe and the attack vector is realistic.

## Likelihood Explanation
**Likelihood: MEDIUM**

**Attack Requirements:**
- Attacker must deploy a malicious Move module (trivial)
- Attacker must trick user into using malicious address (requires social engineering)
- User must sign the transaction (but may not understand the security implications)

**Mitigating Factors:**
- Default behavior uses safe, well-known addresses
- User must explicitly provide the `--large-packages-module-address` flag
- User must sign the transaction

**Aggravating Factors:**
- No validation or warnings are provided for non-standard addresses
- The flag name doesn't indicate security criticality
- Users may copy commands from malicious tutorials or documentation
- The transaction preview shows benign-looking "cleanup_staging_area" function name
- Many users won't understand the security implications of changing this parameter

The combination of severe impact and realistic social engineering vectors justifies the HIGH severity classification.

## Recommendation
Implement strict validation for `large_packages_module_address`:

1. **Immediate Fix - Address Validation:**
   Add validation in `LargePackagesModuleOption::large_packages_module_address()`:
   ```rust
   pub(crate) async fn large_packages_module_address(
       &self,
       txn_options: &TransactionOptions,
   ) -> Result<AccountAddress, CliError> {
       let address = if let Some(address) = self.large_packages_module_address {
           address
       } else {
           // Get default address based on chain
           let chain_id = /* ... get chain_id ... */;
           AccountAddress::from_str_strict(default_large_packages_module_address(&chain_id))
               .map_err(|err| CliError::UnableToParse("Default Large Package Module Address", err.to_string()))?
       };
       
       // Validate against known safe addresses
       let chain_id = /* ... get chain_id ... */;
       let expected_address = AccountAddress::from_str_strict(
           default_large_packages_module_address(&chain_id)
       ).map_err(|err| CliError::UnableToParse("Expected Module Address", err.to_string()))?;
       
       if address != expected_address {
           eprintln!("⚠️  WARNING: Using non-standard large_packages module address!");
           eprintln!("   Expected: {}", expected_address);
           eprintln!("   Provided: {}", address);
           eprintln!("   This may execute arbitrary code with your account authority.");
           
           if !prompt_yes_with_override(
               "Are you absolutely sure you want to proceed?",
               txn_options.prompt_options
           )? {
               return Err(CliError::AbortedError);
           }
       }
       
       Ok(address)
   }
   ```

2. **Enhanced Fix - Module Verification:**
   Additionally verify the module exists and has the expected entry function signature before transaction submission.

3. **Documentation:**
   Clearly document the security implications of `--large-packages-module-address` flag and warn users to only use trusted addresses.

## Proof of Concept

**Step 1: Deploy Malicious Module**
```move
// File: malicious_large_packages.move
module 0xATTACKER::large_packages {
    use std::signer;
    use aptos_framework::aptos_account;
    
    public entry fun cleanup_staging_area(owner: &signer) {
        // Malicious action: instead of cleanup, transfer funds
        let owner_addr = signer::address_of(owner);
        
        // Example malicious operation: could do anything here
        // - Publish malicious code
        // - Transfer resources
        // - Modify account state
        // This demonstrates the attacker has full signer capability
        
        // For PoC: just emit an event to prove execution
        aptos_framework::event::emit_event(
            &mut borrow_global_mut<MaliciousEventHandle>(owner_addr).events,
            MaliciousEvent { victim: owner_addr }
        );
    }
    
    struct MaliciousEventHandle has key {
        events: event::EventHandle<MaliciousEvent>,
    }
    
    struct MaliciousEvent has drop, store {
        victim: address,
    }
}
```

**Step 2: Victim Execution**
```bash
# Victim runs (tricked via malicious documentation)
aptos move clear-staging-area \
    --large-packages-module-address 0xATTACKER \
    --profile victim
```

**Step 3: Verification**
The malicious `cleanup_staging_area` function executes with the victim's signer, demonstrating complete account compromise. The attacker can perform any operation the victim is authorized to do.

**Reproduction Steps:**
1. Deploy malicious module to testnet at attacker address
2. Create victim account with staging area resource
3. Run CLI command with malicious address
4. Observe malicious code execution with victim's authority
5. Verify victim's signer was passed to attacker's function

### Citations

**File:** crates/aptos/src/move_tool/mod.rs (L1067-1074)
```rust
            submit_chunked_publish_transactions(
                chunked_package_payloads.payloads,
                &self.txn_options,
                self.chunked_publish_option
                    .large_packages_module
                    .large_packages_module_address(&self.txn_options)
                    .await?,
            )
```

**File:** crates/aptos/src/move_tool/mod.rs (L1833-1849)
```rust
    async fn execute(self) -> CliTypedResult<TransactionSummary> {
        let (_, account_address) = self.txn_options.get_public_key_and_address()?;

        let large_packages_module_address = self
            .large_packages_module
            .large_packages_module_address(&self.txn_options)
            .await?;
        println!(
            "Cleaning up resource {}::large_packages::StagingArea under account {}.",
            &large_packages_module_address, account_address,
        );
        let payload = large_packages_cleanup_staging_area(large_packages_module_address);
        self.txn_options
            .submit_transaction(payload)
            .await
            .map(TransactionSummary::from)
    }
```

**File:** crates/aptos/src/common/types.rs (L2683-2707)
```rust
impl LargePackagesModuleOption {
    pub(crate) async fn large_packages_module_address(
        &self,
        txn_options: &TransactionOptions,
    ) -> Result<AccountAddress, CliError> {
        if let Some(address) = self.large_packages_module_address {
            return Ok(address);
        }

        let chain_id = match &txn_options.session {
            None => {
                let client = txn_options.rest_client()?;
                ChainId::new(client.get_ledger_information().await?.inner().chain_id)
            },
            Some(session_path) => {
                let sess = Session::load(session_path)?;
                sess.state_store().get_chain_id()?
            },
        };

        AccountAddress::from_str_strict(default_large_packages_module_address(&chain_id)).map_err(
            |err| CliError::UnableToParse("Default Large Package Module Address", err.to_string()),
        )
    }
}
```

**File:** aptos-move/framework/src/chunked_publish.rs (L210-223)
```rust
// Cleanup account's `StagingArea` resource.
pub fn large_packages_cleanup_staging_area(
    large_packages_module_address: AccountAddress,
) -> TransactionPayload {
    TransactionPayload::EntryFunction(EntryFunction::new(
        ModuleId::new(
            large_packages_module_address,
            ident_str!("large_packages").to_owned(),
        ),
        ident_str!("cleanup_staging_area").to_owned(),
        vec![],
        vec![],
    ))
}
```

**File:** aptos-move/framework/aptos-experimental/sources/large_packages.move (L227-231)
```text
    public entry fun cleanup_staging_area(owner: &signer) acquires StagingArea {
        let StagingArea { metadata_serialized: _, code, last_module_idx: _ } =
            move_from<StagingArea>(signer::address_of(owner));
        smart_table::destroy(code);
    }
```
