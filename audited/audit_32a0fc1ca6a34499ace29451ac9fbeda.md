# Audit Report

## Title
Insecure Private Key Memory Management in Indexer Transaction Generator Violates Aptos Secure Coding Standards

## Summary
The `get_account()` function in the indexer transaction generator clones `Account` objects containing private keys stored as plain `String` types, creating multiple unzeroed copies of sensitive cryptographic material in memory. This violates Aptos' documented secure coding guidelines requiring explicit zeroization of private keys.

## Finding Description

The vulnerability exists in the account management system for the indexer transaction generator. The `Account` struct stores private keys as `String` objects and derives the `Clone` trait, while the `get_account()` function returns cloned instances. [1](#0-0) [2](#0-1) 

When `get_account()` is called, it creates a clone of the `Account` object, which includes a full copy of the private key string. Rust's standard `String` type does not zero memory on drop—it simply deallocates. This leaves private key material in memory until that region is overwritten by subsequent allocations.

The vulnerability is confirmed to violate Aptos' secure coding standards, which explicitly state: [3](#0-2) [4](#0-3) 

The codebase contains no usage of the `zeroize` crate despite these guidelines. Furthermore, similar patterns are acknowledged as security violations elsewhere in the codebase: [5](#0-4) 

The cloned accounts are used throughout transaction execution: [6](#0-5) 

## Impact Explanation

This vulnerability creates multiple attack vectors for private key exposure:

1. **Core Dumps**: Process crashes generate core dumps containing unzeroed private keys
2. **Memory Dumps**: Debugging or monitoring tools can capture private key material
3. **Swap Files**: Memory paging to disk writes unencrypted private keys to swap space
4. **Memory Corruption**: Other vulnerabilities could enable reading arbitrary process memory
5. **Cold Boot Attacks**: Memory contents persist briefly after power-off

While the indexer-transaction-generator is documented as a testing tool, it handles real private keys loaded from YAML configuration files that could control accounts with actual funds. [7](#0-6) 

**However**, this issue does **NOT** meet the Aptos bug bounty severity criteria for the following critical reasons:

1. **Scope Limitation**: This component is a testing/development tool, not part of the core blockchain consensus, execution, storage, governance, or staking systems
2. **Exploitability**: Requires memory access privileges beyond the stated threat model of "unprivileged attacker"
3. **Indirect Impact**: Exploitation requires either misuse in production settings or combination with other vulnerabilities

## Likelihood Explanation

**Likelihood: Low to Medium** in the stated threat model, but dependent on deployment context:

- **Low** if used only in development/testing environments as intended
- **Medium** if deployed in production or with accounts holding significant funds
- Requires memory access through crashes, dumps, or secondary vulnerabilities
- Does not provide direct network-accessible exploitation path

The threat model specified in the audit scope focuses on "bugs exploitable without requiring privileged validator access," but this vulnerability requires memory access privileges not enumerated in the untrusted actor model.

## Recommendation

Implement secure memory handling for private keys using the `zeroize` crate as mandated by Aptos secure coding guidelines:

1. Add `zeroize` dependency to `Cargo.toml`
2. Replace `String` with `zeroizing::Zeroizing<String>` for private key storage
3. Remove `Clone` derivation from `Account` or implement secure clone with explicit justification
4. Refactor `get_account()` to return references or use alternative patterns avoiding clones

The core `aptos-crypto` library should be reviewed to ensure all private key types properly implement zeroization on drop, following the pattern used for other cryptographic components.

## Proof of Concept

```rust
// Demonstration that private keys remain in memory after drop
use std::alloc::{alloc, dealloc, Layout};

#[test]
fn test_private_key_memory_retention() {
    let account = Account {
        public_key: "0x123...".to_string(),
        private_key: "0xSECRET_KEY_DATA_HERE".to_string(),
        account: "0xabc...".to_string(),
    };
    
    // Clone creates duplicate in memory
    let cloned = account.clone();
    
    // Get memory addresses
    let original_ptr = account.private_key.as_ptr();
    let cloned_ptr = cloned.private_key.as_ptr();
    
    // Verify different memory locations
    assert_ne!(original_ptr, cloned_ptr);
    
    // Drop cloned account
    drop(cloned);
    
    // Memory at cloned_ptr is deallocated but not zeroed
    // Private key data remains until memory is reused
    // (Cannot safely demonstrate reading deallocated memory in safe Rust)
}
```

---

## Notes

**Critical Clarification**: While this is a **valid violation** of Aptos secure coding standards and represents a **security best practice failure**, it does **NOT** meet the strict criteria for a High Severity bounty-eligible vulnerability because:

- It affects a testing/development tool outside the core blockchain components
- Exploitation requires memory access privileges beyond the specified threat model  
- Impact is contingent on deployment misuse rather than inherent protocol flaws
- Does not directly enable funds theft, consensus violations, or availability attacks

This should be addressed as a **code quality and security hardening issue** to align with documented standards, but it does not constitute an immediately exploitable attack vector meeting the bug bounty program's severity thresholds.

### Citations

**File:** ecosystem/indexer-grpc/indexer-transaction-generator/src/accont_manager.rs (L16-21)
```rust
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Account {
    pub public_key: String,
    pub private_key: String,
    pub account: String,
}
```

**File:** ecosystem/indexer-grpc/indexer-transaction-generator/src/accont_manager.rs (L73-81)
```rust
    pub fn get_account(&mut self, account_address: &str) -> anyhow::Result<Account> {
        match self.accounts.get(account_address) {
            Some(account) => Ok(account.clone()),
            None => anyhow::bail!(
                "[Account Manager] Account not found for address: {}",
                account_address
            ),
        }
    }
```

**File:** RUST_SECURE_CODING.md (L95-96)
```markdown

Do not rely on `Drop` trait in security material treatment after the use, use [zeroize](https://docs.rs/zeroize/latest/zeroize/#) to explicit destroy security material, e.g. private keys.
```

**File:** RUST_SECURE_CODING.md (L143-145)
```markdown
### Zeroing Sensitive Data

Use [zeroize](https://docs.rs/zeroize/latest/zeroize/#) for zeroing memory containing sensitive data.
```

**File:** secure/storage/src/in_memory.rs (L12-14)
```rust
/// Internally, it retains all data, which means that it must make copies of all key material which
/// violates the code base. It violates it because the anticipation is that data stores would
/// securely handle key material. This should not be used in production.
```

**File:** ecosystem/indexer-grpc/indexer-transaction-generator/src/script_transaction_generator.rs (L40-42)
```rust
            let sender_account = account_manager
                .get_account(&transaction.sender_address)
                .unwrap();
```

**File:** ecosystem/indexer-grpc/indexer-transaction-generator/README.md (L33-41)
```markdown
Your testing folder should contain:
- One file called `testing_accounts.yaml`, which contains testing accounts used.
    ```yaml
    accounts:
      a531b7fdd7917f73ca216d89a8d9ce0cf7e7cfb9086ca6f6cbf9521532748d16:
        private_key: "0x99978d48e7b2d50d0a7a3273db0929447ae59635e71118fa256af654c0ce56c9"
        public_key: "0x39b4acc85e026dc056464a5ea00b98f858260eaad2b74dd30b86ae0d4d94ddf5"
        account: a531b7fdd7917f73ca216d89a8d9ce0cf7e7cfb9086ca6f6cbf9521532748d16
    ```
```
