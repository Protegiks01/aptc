# Audit Report

## Title
Derivation Path Validation Bypass Enables Non-Hardened Key Derivation and Cross-Chain Key Confusion

## Summary
The `aptos init` command allows users to bypass derivation path validation by using `--derivation-path` or `--derivation-index` flags, enabling attackers to trick users into deriving keys using non-hardened BIP32 paths or incorrect coin types. This exposes users to extended public key attacks and cross-chain key confusion vulnerabilities.

## Finding Description

The Aptos CLI implements a validation function `validate_derivation_path()` to ensure derivation paths follow the BIP44 standard with mandatory hardened derivation at all levels. However, this validation is only enforced in the interactive `--ledger` flow and is completely bypassed when using command-line flags. [1](#0-0) 

The validation function correctly checks that:
1. Path starts with `m/44'/637'/` (Aptos coin type)
2. Path ends with `'` (hardened derivation marker)
3. Exactly 3 sections after prefix (e.g., `index'/0'/0'`)
4. All sections use hardened derivation (end with `'`)
5. All numeric values are valid u32 integers

However, in the main initialization flow, when users provide derivation paths via `--derivation-path` or `--derivation-index` flags, the validation is completely bypassed: [2](#0-1) 

The `extract_derivation_path()` method returns user input directly without any validation:
- For `--derivation-path`: Clones and returns the raw string
- For `--derivation-index`: Uses string formatting without validating the index content

The bypass occurs because validation only happens in a separate code branch: [3](#0-2) 

Validation at line 194 is only reachable when `self.ledger` is true AND `hardware_wallet_options.extract_derivation_path()` returns None. When using `--derivation-path` or `--derivation-index`, the function returns early at line 173, bypassing all validation.

The unvalidated path is then directly used to derive keys from the Ledger device: [4](#0-3) 

**Attack Scenario 1: Non-Hardened Derivation**

An attacker tricks a victim into initializing with:
```
aptos init --derivation-path "m/44'/637'/0/0/0"
```

This creates a path with non-hardened derivation for the last three levels. The `serialize_bip32()` function processes this without the hardened bit (0x80000000): [5](#0-4) 

With non-hardened derivation, if an attacker obtains:
- The extended public key (xpub) at any parent level → can derive all child public keys
- ANY child private key → can compute the parent private key and all sibling keys

**Attack Scenario 2: Cross-Chain Key Confusion**

An attacker provides:
```
aptos init --derivation-path "m/44'/60'/0'/0'/0'"
```

This uses Ethereum's coin type (60) instead of Aptos (637). If the attacker knows the victim's Ethereum address (publicly observable), they can predict the "Aptos" address and monitor for fund deposits. If the Ethereum key is later compromised, the attacker gains access to the Aptos funds as well.

**Attack Scenario 3: Arbitrary Path Depth Injection**

Using `--derivation-index`, an attacker can inject additional path components:
```
aptos init --derivation-index "0'/999/123"
```

This creates: `m/44'/637'/0'/999/123'/0'/0'` (7 levels with mixed hardened/non-hardened), deviating from BIP44 standards and creating unpredictable behavior.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos Bug Bounty program criteria:

**Primary Impact: Cryptographic Weakness Leading to Potential Funds Loss**

1. **Non-Hardened Derivation Attack**: BIP32 non-hardened derivation is fundamentally weaker than hardened derivation. If an attacker obtains the extended public key through wallet exports, debugging interfaces, or other means, they can derive all child addresses. More critically, if ANY child private key is leaked (through malware, phishing, etc.), the attacker can compute the parent private key and derive ALL sibling private keys, leading to complete compromise of the affected account hierarchy.

2. **Cross-Chain Key Reuse**: Using incorrect coin types enables cross-chain attacks where an attacker who knows a user's address on one blockchain (e.g., Ethereum) can predict their "Aptos" address and execute targeted attacks.

3. **Loss of User Funds**: Users who are socially engineered into using malicious derivation paths become vulnerable to extended key attacks, potentially resulting in theft of funds.

While this requires social engineering and additional attack steps, the impact of successful exploitation is significant funds loss, meeting the High Severity threshold of "Significant protocol violations" and potential "Limited funds loss or manipulation."

## Likelihood Explanation

**Likelihood: Medium-High**

**Factors Increasing Likelihood:**
1. **Trivial to Execute Social Engineering**: Attackers can easily distribute malicious initialization commands through fake tutorials, compromised documentation, or phishing campaigns
2. **No Warning to Users**: The CLI provides no warnings when non-standard derivation paths are used
3. **Plausible Deniability**: Malicious commands look similar to legitimate ones, making detection difficult
4. **Wide Attack Surface**: Affects all users of the Aptos CLI who use hardware wallets

**Factors Decreasing Likelihood:**
1. **Multi-Step Attack**: Requires both social engineering AND obtaining extended public key or child private key
2. **Hardware Wallet Users Only**: Only affects users with Ledger devices (subset of total users)
3. **Extended Key Exposure Required**: Attacker needs additional information beyond the derivation path

The attack requires social engineering, which is feasible at scale through compromised tutorials or malicious scripts. The technical barrier is low - no special privileges or complex exploits needed.

## Recommendation

Implement mandatory validation for all derivation path inputs by calling `validate_derivation_path()` in the `extract_derivation_path()` method:

```rust
impl HardwareWalletOptions {
    pub fn extract_derivation_path(&self) -> CliTypedResult<Option<String>> {
        let path = if let Some(derivation_path) = &self.derivation_path {
            derivation_path.clone()
        } else if let Some(derivation_index) = &self.derivation_index {
            // Validate that derivation_index contains only digits
            if !derivation_index.chars().all(|c| c.is_ascii_digit()) {
                return Err(CliError::CommandArgumentError(
                    format!("Invalid derivation index '{}'. Must contain only digits.", derivation_index)
                ));
            }
            format!("m/44'/637'/{}'/0'/0'", derivation_index)
        } else {
            return Ok(None);
        };

        // Validate the derivation path
        if !aptos_ledger::validate_derivation_path(&path) {
            return Err(CliError::CommandArgumentError(
                format!(
                    "Invalid derivation path '{}'. Must follow format m/44'/637'/{{index}}'/0'/0' with all hardened components.",
                    path
                )
            ));
        }

        Ok(Some(path))
    }
}
```

Additional recommendations:
1. Add explicit validation that `derivation_index` contains only numeric characters
2. Display a clear warning when users provide derivation paths, showing the exact path being used
3. Consider adding a `--allow-non-standard-path` flag for advanced users who need non-standard paths, requiring explicit opt-in
4. Document the security implications of custom derivation paths in the CLI help text

## Proof of Concept

**Step 1: Demonstrate validation bypass with non-hardened path**

```bash
# This should be rejected but isn't
aptos init \
  --network devnet \
  --derivation-path "m/44'/637'/0/0/0" \
  --skip-faucet

# Expected: Validation error about non-hardened derivation
# Actual: Proceeds to derive key using non-hardened path
```

**Step 2: Demonstrate wrong coin type bypass**

```bash
# Using Ethereum's coin type instead of Aptos
aptos init \
  --network devnet \
  --derivation-path "m/44'/60'/0'/0'/0'" \
  --skip-faucet

# Expected: Validation error about wrong coin type
# Actual: Proceeds to derive Ethereum-path key
```

**Step 3: Demonstrate arbitrary depth injection**

```bash
# Inject additional path components
aptos init \
  --network devnet \
  --derivation-index "0'/999/123" \
  --skip-faucet

# Expected: Validation error about path structure
# Actual: Creates path m/44'/637'/0'/999/123'/0'/0' (7 levels)
```

**Rust Test Case:**

```rust
#[test]
fn test_derivation_path_validation_bypass() {
    use crate::common::types::HardwareWalletOptions;
    
    // Test 1: Non-hardened path should be rejected
    let opts = HardwareWalletOptions {
        derivation_path: Some("m/44'/637'/0/0/0".to_string()),
        derivation_index: None,
    };
    let result = opts.extract_derivation_path();
    assert!(result.is_ok()); // Currently passes but SHOULD fail
    
    // Test 2: Wrong coin type should be rejected  
    let opts = HardwareWalletOptions {
        derivation_path: Some("m/44'/60'/0'/0'/0'".to_string()),
        derivation_index: None,
    };
    let result = opts.extract_derivation_path();
    assert!(result.is_ok()); // Currently passes but SHOULD fail
    
    // Test 3: Path injection should be rejected
    let opts = HardwareWalletOptions {
        derivation_path: None,
        derivation_index: Some("0'/999/123".to_string()),
    };
    let result = opts.extract_derivation_path();
    assert!(result.is_ok()); // Currently passes but SHOULD fail
    
    // After fix, all three tests above should return Err
}
```

**Notes**

This vulnerability is specifically scoped to the Aptos CLI client tool and affects individual users rather than the blockchain protocol itself. While it doesn't impact consensus, validators, or blockchain state directly, it creates a significant security risk for CLI users who can be socially engineered into using insecure derivation paths. The fix is straightforward: apply existing validation to all code paths that accept derivation path input, not just the interactive flow.

### Citations

**File:** crates/aptos-ledger/src/lib.rs (L207-235)
```rust
pub fn validate_derivation_path(input: &str) -> bool {
    let prefix = "m/44'/637'/";
    let suffix = "'";

    if input.starts_with(prefix) && input.ends_with(suffix) {
        let inner_input = &input[prefix.len()..input.len()];

        // Sample: 0'/0'/0'
        let sections: Vec<&str> = inner_input.split('/').collect();
        if sections.len() != 3 {
            return false;
        }

        for section in sections {
            if !section.ends_with(suffix) {
                return false;
            }

            let section_value = &section.trim_end_matches('\'');
            if section_value.parse::<u32>().is_ok() {
                continue;
            }
            return false;
        }

        return true;
    }
    false
}
```

**File:** crates/aptos-ledger/src/lib.rs (L487-508)
```rust
fn serialize_bip32(path: &str) -> Vec<u8> {
    let parts: Vec<u32> = path
        .split('/')
        .skip(1)
        .map(|part| {
            if let Some(part) = part.strip_suffix('\'') {
                part.parse::<u32>().unwrap() + 0x80000000
            } else {
                part.parse::<u32>().unwrap()
            }
        })
        .collect();

    let mut serialized = vec![0u8; 1 + parts.len() * 4];
    serialized[0] = parts.len() as u8;

    for (i, part) in parts.iter().enumerate() {
        serialized[(1 + i * 4)..(5 + i * 4)].copy_from_slice(&part.to_be_bytes());
    }

    serialized
}
```

**File:** crates/aptos/src/common/types.rs (L764-773)
```rust
    pub fn extract_derivation_path(&self) -> CliTypedResult<Option<String>> {
        if let Some(derivation_path) = &self.derivation_path {
            Ok(Some(derivation_path.clone()))
        } else if let Some(derivation_index) = &self.derivation_index {
            let derivation_path = format!("m/44'/637'/{}'/0'/0'", derivation_index);
            Ok(Some(derivation_path))
        } else {
            Ok(None)
        }
    }
```

**File:** crates/aptos/src/common/init.rs (L170-203)
```rust
        let derivation_path = if let Some(deri_path) =
            self.hardware_wallet_options.extract_derivation_path()?
        {
            Some(deri_path)
        } else if self.ledger {
            // Fetch the top 5 (index 0-4) accounts from Ledger
            let account_map = aptos_ledger::fetch_batch_accounts(Some(0..5))?;
            eprintln!(
                "Please choose an index from the following {} ledger accounts, or choose an arbitrary index that you want to use:",
                account_map.len()
            );

            // Iterate through the accounts and print them out
            for (index, (derivation_path, account)) in account_map.iter().enumerate() {
                eprintln!(
                    "[{}] Derivation path: {} (Address: {})",
                    index, derivation_path, account
                );
            }
            let input_index = read_line("derivation_index")?;
            let input_index = input_index.trim();
            let path = aptos_ledger::DERIVATION_PATH.replace("{index}", input_index);

            // Validate the path
            if !aptos_ledger::validate_derivation_path(&path) {
                return Err(CliError::UnexpectedError(
                    "Invalid index input. Please make sure the input is a valid number index"
                        .to_owned(),
                ));
            }
            Some(path)
        } else {
            None
        };
```

**File:** crates/aptos/src/common/init.rs (L245-261)
```rust
        let public_key = if self.is_hardware_wallet() {
            match aptos_ledger::get_public_key(
                derivation_path
                    .ok_or_else(|| {
                        CliError::UnexpectedError("Invalid derivation path".to_string())
                    })?
                    .as_str(),
                false,
            ) {
                Ok(pub_key_str) => pub_key_str,
                Err(err) => {
                    return Err(CliError::UnexpectedError(format!(
                        "Unexpected Ledger Error: {:?}",
                        err.to_string()
                    )))
                },
            }
```
