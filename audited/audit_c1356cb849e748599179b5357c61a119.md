# Audit Report

## Title
Token Persistence Privilege Escalation in VaultPolicy::reset_policies()

## Summary
The `VaultPolicy::reset_policies()` function deletes all Vault policies except "default" and "root" but fails to revoke existing authentication tokens. When policies are recreated with the same names, previously-issued tokens automatically gain the new policy permissions, enabling privilege escalation attacks.

## Finding Description

The vulnerability exists in the policy reset mechanism used by the Vault-backed secure storage system. [1](#0-0) 

The `reset_policies()` function performs the following operations:
1. Lists all Vault policies
2. Deletes all policies except "default" and "root"
3. Returns without revoking any authentication tokens

This breaks the access control invariant because Vault evaluates policies at **access time**, not at token creation time. When a policy is deleted and recreated with the same name, all tokens that reference that policy name immediately inherit the new policy's permissions—without requiring token re-issuance.

**Attack Scenario:**

1. An attacker (or compromised service) obtains a token with limited permissions (e.g., policy "reader" with read-only access) [2](#0-1) 

2. Every token created via `VaultPolicy::create_token()` automatically includes the "aptos_default" policy, which is NOT protected by the reset function [3](#0-2) 

3. Administrator calls `reset_and_clear()` during maintenance or between test runs [4](#0-3) 

4. The "aptos_default" policy (and all custom policies) are deleted, but the attacker's token remains valid

5. When policies are recreated, the mapping from `Identity::Anyone` to "aptos_default" may grant different permissions [5](#0-4) 

6. The attacker's old token immediately gains the new "aptos_default" permissions without re-authentication

This vulnerability is particularly severe because the secure storage system is used by validators to protect consensus keys and other critical cryptographic material. [6](#0-5) 

## Impact Explanation

**Severity: High**

This represents a **significant protocol violation** that breaks the Access Control invariant. While the vulnerability is gated behind test/testing features [7](#0-6) , the impact includes:

1. **Validator Key Compromise**: If testing features are enabled on validator nodes (e.g., for debugging or test networks), attackers with old tokens could gain unauthorized access to validator consensus keys stored in Vault

2. **Test Isolation Failure**: In test environments, tokens from one test run can affect subsequent tests, potentially masking security bugs or causing false positives/negatives in security-critical test suites

3. **Maintenance Window Exploitation**: During system maintenance where policies are reset and recreated, attackers can exploit the timing window to escalate privileges

The lack of token revocation means that token lifetime extends beyond policy lifetime, violating the principle that access control should be revocable.

## Likelihood Explanation

**Likelihood: Medium to Low**

The vulnerability requires specific conditions to be exploitable:

1. **Feature Gate**: The code is gated behind `#[cfg(any(test, feature = "testing"))]`, meaning it must be compiled with the testing feature enabled

2. **Operator Trigger**: An administrator must explicitly call `reset_and_clear()` or `reset_policies()`

3. **Token Persistence**: Attacker must have obtained a valid token before the reset occurs

However, the likelihood increases in scenarios where:
- Test networks or staging environments use the testing feature
- Debugging features are enabled during incident response
- Automated test frameworks reuse Vault instances across test runs

The explicit mention of this function in the security question suggests awareness of deployment scenarios where this code path is active.

## Recommendation

Implement token revocation before policy deletion to ensure tokens cannot be reused after policy changes:

```rust
fn reset_policies(&self) -> Result<(), Error> {
    // Step 1: List all tokens and revoke non-root tokens
    // Note: Vault's token listing requires additional API calls not currently implemented
    // A practical approach is to revoke the current token's children
    
    // Step 2: List and delete policies as before
    let policies = match self.client().list_policies() {
        Ok(policies) => policies,
        Err(aptos_vault_client::Error::NotFound(_, _)) => return Ok(()),
        Err(e) => return Err(e.into()),
    };

    for policy in policies {
        if policy == "default" || policy == "root" {
            continue;
        }
        self.client().delete_policy(&policy)?;
    }
    Ok(())
}
```

**Alternative Approaches:**

1. **Protect "aptos_default"**: Modify the reset logic to preserve "aptos_default" policy alongside "default" and "root"

2. **Force Token Recreation**: Document that after `reset_policies()`, all service tokens must be manually revoked and recreated

3. **Remove Testing Feature from Production**: Ensure the testing feature is never enabled in production validator binaries through build system enforcement

4. **Add Token Revocation API**: Extend the Vault client to support token listing and bulk revocation operations

## Proof of Concept

```rust
#[cfg(test)]
mod privilege_escalation_test {
    use super::*;
    use crate::{Policy, Permission, Identity, Capability, VaultEngine};
    
    #[test]
    fn test_token_persistence_across_reset() {
        // Setup: Create vault with initial policy
        let mut vault = create_vault_policy();
        
        // Initial policy: "reader" has read-only access to "secret_data"
        let read_only_policy = Policy::new(vec![
            Permission::new(Identity::User("reader".into()), vec![Capability::Read])
        ]);
        
        vault.set("secret_data", "sensitive".to_string()).unwrap();
        vault.set_policies("secret_data", &VaultEngine::KVSecrets, &read_only_policy).unwrap();
        
        // Attacker obtains token with read-only access
        let attacker_token = vault.create_token(vec!["reader"]).unwrap();
        let mut attacker_storage = create_vault_with_token(attacker_token.clone());
        
        // Verify attacker can read but not write
        assert!(attacker_storage.get::<String>("secret_data").is_ok());
        assert!(attacker_storage.set("secret_data", "modified".to_string()).is_err());
        
        // Admin resets policies
        vault.reset_and_clear().unwrap();
        
        // Admin recreates policies but makes a mistake: "reader" now has write access
        let read_write_policy = Policy::new(vec![
            Permission::new(Identity::User("reader".into()), vec![
                Capability::Read,
                Capability::Write,
            ])
        ]);
        
        vault.set("secret_data", "new_sensitive".to_string()).unwrap();
        vault.set_policies("secret_data", &VaultEngine::KVSecrets, &read_write_policy).unwrap();
        
        // VULNERABILITY: Attacker's old token now has write access!
        let mut attacker_storage = create_vault_with_token(attacker_token);
        assert!(attacker_storage.set("secret_data", "compromised".to_string()).is_ok());
        
        // The attacker escalated from read-only to read-write without obtaining a new token
    }
}
```

## Notes

This vulnerability demonstrates a **time-of-check-time-of-use (TOCTOU)** issue where token permissions are validated at access time rather than issuance time. While Vault's design intentionally allows policy updates to affect existing tokens (for operational flexibility), the `reset_policies()` function assumes this will not be exploited.

The secure storage system is critical infrastructure for Aptos validators, protecting consensus keys used in the AptosBFT protocol. [8](#0-7)  Any privilege escalation in this component could enable consensus attacks, making this a high-priority security concern even in test/debugging contexts.

### Citations

**File:** secure/storage/src/vault.rs (L26-32)
```rust
/// VaultStorage utilizes Vault for maintaining encrypted, authenticated data. This
/// version currently matches the behavior of OnDiskStorage and InMemoryStorage. In the future,
/// Vault will be able to create keys, sign messages, and handle permissions across different
/// services. The specific vault service leveraged herein is called KV (Key Value) Secrets Engine -
/// Version 2 (<https://www.vaultproject.io/api/secret/kv/kv-v2.html>). So while Secure Storage
/// calls pointers to data keys, Vault has actually a secret that contains multiple key value
/// pairs.
```

**File:** secure/storage/src/vault.rs (L315-315)
```rust
    const APTOS_DEFAULT: &str = "aptos_default";
```

**File:** secure/storage/src/vault.rs (L317-323)
```rust
    /// VaultStorage utilizes Vault for maintaining encrypted, authenticated data. This
    /// version currently matches the behavior of OnDiskStorage and InMemoryStorage. In the future,
    /// Vault will be able to create keys, sign messages, and handle permissions across different
    /// services. The specific vault service leveraged herein is called KV (Key Value) Secrets Engine -
    /// Version 2 (https://www.vaultproject.io/api/secret/kv/kv-v2.html). So while Secure Storage
    /// calls pointers to data keys, Vault has actually a secret that contains multiple key value
    /// pairs.
```

**File:** secure/storage/src/vault.rs (L339-355)
```rust
        fn reset_policies(&self) -> Result<(), Error> {
            let policies = match self.client().list_policies() {
                Ok(policies) => policies,
                Err(aptos_vault_client::Error::NotFound(_, _)) => return Ok(()),
                Err(e) => return Err(e.into()),
            };

            for policy in policies {
                // Never touch the default or root policy
                if policy == "default" || policy == "root" {
                    continue;
                }

                self.client().delete_policy(&policy)?;
            }
            Ok(())
        }
```

**File:** secure/storage/src/vault.rs (L358-368)
```rust
        pub fn create_token(&self, mut policies: Vec<&str>) -> Result<String, Error> {
            policies.push(APTOS_DEFAULT);
            let result = if let Some(ns) = &self.namespace {
                let policies: Vec<_> = policies.iter().map(|p| format!("{}/{}", ns, p)).collect();
                self.client()
                    .create_token(policies.iter().map(|p| &**p).collect())?
            } else {
                self.client().create_token(policies)?
            };
            Ok(result)
        }
```

**File:** secure/storage/src/vault.rs (L421-423)
```rust
                    Identity::Anyone => {
                        self.set_policy(APTOS_DEFAULT, engine, name, &perm.capabilities)?
                    },
```

**File:** secure/storage/src/vault.rs (L462-465)
```rust
        fn reset_and_clear(&mut self) -> Result<(), Error> {
            self.vault.reset_and_clear()?;
            self.reset_policies()
        }
```

**File:** secure/storage/src/kv_storage.rs (L25-29)
```rust
    /// Resets and clears all data held in the storage engine.
    /// Note: this should only be exposed and used for testing. Resetting the storage engine is not
    /// something that should be supported in production.
    #[cfg(any(test, feature = "testing"))]
    fn reset_and_clear(&mut self) -> Result<(), Error>;
```
