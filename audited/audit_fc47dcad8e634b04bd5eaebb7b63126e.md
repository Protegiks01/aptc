# Audit Report

## Title
Malicious Genesis Framework Injection in Test Networks Allows Unlimited Minting and Backdoored Validators

## Summary
The `create_single_node_test_config()` function accepts arbitrary user-provided genesis frameworks via the `--genesis-framework` flag without any validation or integrity checking. A malicious framework containing backdoored Move modules can be provided to create compromised test networks with unlimited minting capabilities and bypassed validator controls.

## Finding Description

The vulnerability exists in the genesis framework loading and deployment mechanism for test networks. The attack path is as follows:

1. **Framework Loading Without Validation**: [1](#0-0) 

   The user-provided framework is loaded directly using `ReleaseBundle::read(path).unwrap()` with no integrity checks, signature verification, or content validation.

2. **Framework Deserialization**: [2](#0-1) 

   The framework is simply deserialized from BCS bytes without any validation of the module contents or logic.

3. **Genesis Framework Publishing**: [3](#0-2) 

   During genesis, ALL modules from the framework are added to the state view without semantic validation.

4. **Module Address Extraction and Publishing**: [4](#0-3) 

   For each package, the address is extracted from the module's self-declared address and used to publish the modules. The critical issue is in `code_to_writes_for_publishing()`: [5](#0-4) 

   The "sender" parameter passed to `StagingModuleStorage::create()` is the module's own self-declared address, not an authenticated external source.

5. **Bypassed Address Validation**: [6](#0-5) 

   This validation checks if `addr != sender`, but during genesis both are derived from the malicious module itself, allowing any module to publish to any address including `0x1` (CORE_CODE_ADDRESS).

6. **Insufficient Genesis Verification**: [7](#0-6) 

   The verification only checks that module writes are creations, not the semantic correctness or safety of the module logic.

**Attack Scenario - Unlimited Minting:**

An attacker can create a malicious `aptos_coin.move` module that modifies the mint function: [8](#0-7) 

The malicious version would remove the `exists<MintCapStore>(account_addr)` check, allowing any account to mint unlimited coins. Since this module is published to `@aptos_framework` (0x1) during genesis, it becomes the authoritative coin module.

**Attack Scenario - Backdoored Validators:**

Similarly, the attacker can modify `stake.move`, `staking_config.move`, or `aptos_governance.move` to:
- Allow unauthorized accounts to join the validator set
- Bypass stake amount requirements
- Grant elevated governance powers
- Disable security checks

## Impact Explanation

This vulnerability has **CRITICAL** severity based on the Aptos bug bounty criteria:

**Loss of Funds (Unlimited Minting)**: The malicious framework can enable arbitrary minting of coins, completely breaking the economic model of the test network. While these are test networks, they are often used for:
- Integration testing of real applications before mainnet deployment
- Developer sandboxes that may contain valuable test data
- Demo environments for potential users/investors
- CI/CD pipelines for critical infrastructure

**Consensus/Safety Violations**: Backdoored validator logic can:
- Allow unauthorized parties to participate in consensus
- Manipulate voting power calculations
- Bypass slashing conditions
- Create validator sets with known malicious actors

**Deterministic Execution Violation**: Different test networks initialized with different malicious frameworks will produce different state roots for identical transactions, breaking the fundamental blockchain invariant.

**Access Control Failure**: System addresses (`@aptos_framework`, `@core_resources`) are compromised, violating the trust model that these addresses are protected.

## Likelihood Explanation

**Likelihood: MEDIUM**

While this requires the victim to:
1. Run a node with `--test` flag
2. Accept a malicious genesis framework file

The attack is realistic in several scenarios:
- **Supply Chain Attack**: Malicious framework distributed through compromised package repositories or documentation
- **Social Engineering**: Attacker provides "enhanced test framework" to developers
- **Compromised CI/CD**: Automated testing pipelines using attacker-controlled frameworks
- **Insider Threat**: Malicious developer on a team distributing backdoored frameworks

The warning message at [9](#0-8)  is insufficient as it only warns about test mode, not about framework validation.

## Recommendation

Implement comprehensive framework validation before genesis deployment:

```rust
// In aptos-node/src/lib.rs, modify the framework loading:
let genesis_framework = if let Some(path) = self.genesis_framework {
    let loaded_bundle = ReleaseBundle::read(path)?;
    
    // Add validation:
    validate_genesis_framework(&loaded_bundle)?;
    
    loaded_bundle
} else {
    aptos_cached_packages::head_release_bundle().clone()
};

// Add validation function:
fn validate_genesis_framework(framework: &ReleaseBundle) -> anyhow::Result<()> {
    // 1. Verify framework signature from trusted source
    // 2. Validate module addresses match expected framework addresses
    // 3. Check critical module hashes against known-good values
    // 4. Ensure required modules are present and complete
    // 5. Validate no unexpected modules at system addresses
    
    for (module_bytes, module) in framework.code_and_compiled_modules() {
        let expected_hash = get_expected_module_hash(&module.self_id())?;
        let actual_hash = sha3_256(module_bytes);
        
        if actual_hash != expected_hash {
            return Err(anyhow!(
                "Module {} hash mismatch. Expected: {}, Got: {}",
                module.self_id(),
                hex::encode(expected_hash),
                hex::encode(actual_hash)
            ));
        }
    }
    
    Ok(())
}
```

Additionally:
1. Implement framework signing with trusted keys
2. Provide curated, signed framework bundles
3. Add `--allow-custom-framework` flag that requires explicit opt-in
4. Log framework hash and provenance for audit trails

## Proof of Concept

```rust
// Step 1: Create malicious aptos_coin.move module
module aptos_framework::aptos_coin {
    use std::signer;
    use aptos_framework::coin::{Self, MintCapability};
    
    struct AptosCoin has key {}
    
    struct MintCapStore has key {
        mint_cap: MintCapability<AptosCoin>,
    }
    
    // BACKDOOR: Remove capability check, allow anyone to mint
    public entry fun mint(
        account: &signer,
        dst_addr: address,
        amount: u64,
    ) acquires MintCapStore {
        // Original code checks:
        // assert!(exists<MintCapStore>(signer::address_of(account)), ...);
        
        // Malicious code: bypass check, use framework's mint cap
        let mint_cap = &borrow_global<MintCapStore>(@aptos_framework).mint_cap;
        let coins_minted = coin::mint<AptosCoin>(amount, mint_cap);
        coin::deposit<AptosCoin>(dst_addr, coins_minted);
    }
    
    // ... rest of module implementation
}

// Step 2: Compile malicious framework
// $ aptos move compile --save-metadata

// Step 3: Create ReleaseBundle with malicious module
// $ aptos-framework build-release-bundle --output malicious_framework.blob

// Step 4: Start node with malicious framework
// $ aptos-node --test --genesis-framework ./malicious_framework.blob --test-dir ./test_data

// Step 5: From any account, mint unlimited coins
// $ aptos move run \
//     --function-id 0x1::aptos_coin::mint \
//     --args address:0xVICTIM u64:999999999999999
```

The test network will now have a completely compromised coin module where any account can mint unlimited amounts, breaking all economic assumptions and rendering the test environment unreliable for application testing.

**Notes**

This vulnerability specifically affects test network initialization and demonstrates a complete bypass of framework integrity controls. The scope is limited to test networks started with the `--test` flag, but the impact on development workflows, integration testing, and demo environments is significant. Test network compromises can lead to:
- Wasted development time on invalid test results  
- False confidence in application security
- Exploitation of demo environments used for fundraising
- Supply chain attacks on development infrastructure

### Citations

**File:** aptos-node/src/lib.rs (L137-139)
```rust
            println!("WARNING: Entering test mode! This should never be used in production!");
            if self.performance {
                println!("WARNING: Entering performance mode! System utilization may be high!");
```

**File:** aptos-node/src/lib.rs (L143-147)
```rust
            let genesis_framework = if let Some(path) = self.genesis_framework {
                ReleaseBundle::read(path).unwrap()
            } else {
                aptos_cached_packages::head_release_bundle().clone()
            };
```

**File:** aptos-move/framework/src/release_bundle.rs (L45-49)
```rust
    pub fn read(file: PathBuf) -> anyhow::Result<ReleaseBundle> {
        let content =
            std::fs::read(&file).with_context(|| format!("while reading `{}`", file.display()))?;
        Ok(bcs::from_bytes::<ReleaseBundle>(&content)?)
    }
```

**File:** aptos-move/vm-genesis/src/lib.rs (L275-277)
```rust
    for (module_bytes, module) in framework.code_and_compiled_modules() {
        state_view.add_module(&module.self_id(), module_bytes);
    }
```

**File:** aptos-move/vm-genesis/src/lib.rs (L1138-1139)
```rust
    let module_storage_with_staged_modules =
        StagingModuleStorage::create(&addr, &module_storage, code)?;
```

**File:** aptos-move/vm-genesis/src/lib.rs (L1166-1188)
```rust
    for pack in &framework.packages {
        let modules = pack.sorted_code_and_modules();

        let addr = *modules.first().unwrap().1.self_id().address();
        let code = modules
            .into_iter()
            .map(|(c, _)| c.to_vec().into())
            .collect::<Vec<_>>();

        let package_writes = code_to_writes_for_publishing(
            genesis_runtime_environment,
            genesis_vm.genesis_features(),
            &state_view,
            addr,
            code,
        )
        .unwrap_or_else(|e| {
            panic!(
                "Failure publishing package `{}`: {:?}",
                pack.package_metadata().name,
                e
            )
        });
```

**File:** aptos-move/vm-genesis/src/lib.rs (L1260-1265)
```rust
fn verify_genesis_module_write_set(write_set: &WriteSet) {
    for (state_key, write_op) in write_set.expect_write_op_iter() {
        if state_key.is_module_path() {
            assert!(write_op.is_creation())
        }
    }
```

**File:** third_party/move/move-vm/runtime/src/storage/publishing.rs (L159-171)
```rust
            if addr != sender {
                let msg = format!(
                    "Compiled modules address {} does not match the sender {}",
                    addr, sender
                );
                return Err(verification_error(
                    StatusCode::MODULE_ADDRESS_DOES_NOT_MATCH_SENDER,
                    IndexKind::AddressIdentifier,
                    compiled_module.self_handle_idx().0,
                )
                .with_message(msg)
                .finish(Location::Undefined));
            }
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_coin.move (L93-108)
```text
    public entry fun mint(
        account: &signer,
        dst_addr: address,
        amount: u64,
    ) acquires MintCapStore {
        let account_addr = signer::address_of(account);

        assert!(
            exists<MintCapStore>(account_addr),
            error::not_found(ENO_CAPABILITIES),
        );

        let mint_cap = &borrow_global<MintCapStore>(account_addr).mint_cap;
        let coins_minted = coin::mint<AptosCoin>(amount, mint_cap);
        coin::deposit<AptosCoin>(dst_addr, coins_minted);
    }
```
