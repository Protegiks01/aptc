# Audit Report

## Title
Case-Sensitive Vanity Prefix Comparison Causes Infinite Loop in CLI Key Generation

## Summary
The vanity prefix validation in the Aptos CLI key generation accepts case-insensitive hex input but performs case-sensitive comparison during mining, causing an infinite loop when users provide uppercase or mixed-case hex prefixes.

## Finding Description

The `generate_vanity_account_ed25519` function validates vanity prefixes using `hex::decode()`, which accepts both lowercase and uppercase hexadecimal characters. However, the mining loop compares generated addresses using case-sensitive string matching against the original user-provided prefix. [1](#0-0) 

The validation phase accepts any valid hex string regardless of case (e.g., "ABCD", "abcd", "AbCd"). After validation passes, the mining loop generates keys and derives account addresses. [2](#0-1) 

The `short_str_lossless()` method returns lowercase hex representation of addresses. [3](#0-2) 

**Attack Path:**
1. User runs: `aptos key generate --key-type ed25519 --vanity-prefix ABCD --output-file key`
2. Validation strips "0x" leaving "ABCD"
3. `hex::decode("ABCD")` succeeds (valid hex)
4. Mining loop starts generating keys
5. Each address from `short_str_lossless()` returns lowercase like "abcd1234..."
6. String comparison `"abcd1234...".starts_with("ABCD")` fails (case-sensitive)
7. Loop continues indefinitely, never finding a match

## Impact Explanation

This issue causes a **denial of service** condition for the CLI user. When uppercase or mixed-case prefixes are provided, the mining operation enters an infinite loop that can never terminate, requiring manual process termination.

However, this vulnerability does **not** meet the Aptos bug bounty severity criteria:
- **No validator or blockchain impact**: Only affects CLI tool users
- **No consensus violations**: Does not affect blockchain operation
- **No funds at risk**: Cannot cause loss or theft of funds
- **No state corruption**: Does not affect on-chain state
- **Limited scope**: Only impacts the user running the command on their own machine

This is a **CLI usability bug** rather than a blockchain security vulnerability. While it should be fixed, it falls under "non-critical bugs" excluded from the bug bounty program scope.

## Likelihood Explanation

High likelihood of occurrence for users unfamiliar with the case-sensitivity requirement. Users may naturally input uppercase hex (e.g., copy-pasted addresses, aesthetic preferences) without realizing the implementation expects lowercase.

## Recommendation

Normalize the vanity prefix to lowercase after validation and before entering the mining loop:

```rust
pub fn generate_vanity_account_ed25519(
    vanity_prefix_ref: &str,
    multisig: bool,
) -> CliTypedResult<Ed25519PrivateKey> {
    let vanity_prefix_ref = vanity_prefix_ref
        .strip_prefix("0x")
        .unwrap_or(vanity_prefix_ref);
    let mut to_check_if_is_hex = String::from(vanity_prefix_ref);
    if to_check_if_is_hex.len() % 2 != 0 {
        to_check_if_is_hex += "0"
    };
    hex::decode(to_check_if_is_hex).map_err(|error| 
        CliError::CommandArgumentError(format!(
            "The vanity prefix could not be decoded to hex: {}", error)))?;
    
    // ADD THIS LINE: Normalize to lowercase for comparison
    let vanity_prefix_ref = vanity_prefix_ref.to_lowercase();
    
    let mut key_generator = KeyGen::from_os_rng();
    loop {
        // ... rest of the function
    }
}
```

## Proof of Concept

```bash
# This command will hang indefinitely
aptos key generate \
  --key-type ed25519 \
  --vanity-prefix ABCD \
  --output-file test-key.key

# Expected: Infinite loop (process never terminates)
# User must use Ctrl+C to kill the process
```

Alternatively, reproduce in Rust test:
```rust
#[test]
#[ignore] // Ignore by default as it hangs
fn test_uppercase_vanity_prefix_hangs() {
    use std::time::Duration;
    use std::thread;
    
    let handle = thread::spawn(|| {
        generate_vanity_account_ed25519("ABCD", false)
    });
    
    // Give it 5 seconds - should timeout as it never completes
    match handle.join_timeout(Duration::from_secs(5)) {
        Ok(_) => panic!("Should not complete"),
        Err(_) => println!("Confirmed: infinite loop with uppercase prefix"),
    }
}
```

## Notes

While this is a legitimate bug that should be fixed, it **does not qualify as a security vulnerability** under the Aptos bug bounty program criteria. It is a CLI tool usability issue with no impact on blockchain security, consensus, validator operations, or funds. The issue should be addressed through normal development processes rather than the security bug bounty program.

### Citations

**File:** crates/aptos/src/common/utils.rs (L373-383)
```rust
    let vanity_prefix_ref = vanity_prefix_ref
        .strip_prefix("0x")
        .unwrap_or(vanity_prefix_ref); // Optionally strip leading 0x from input string.
    let mut to_check_if_is_hex = String::from(vanity_prefix_ref);
    // If an odd number of characters append a 0 for verifying that prefix contains valid hex.
    if to_check_if_is_hex.len() % 2 != 0 {
        to_check_if_is_hex += "0"
    };
    hex::decode(to_check_if_is_hex).  // Check that the vanity prefix can be decoded into hex.
        map_err(|error| CliError::CommandArgumentError(format!(
            "The vanity prefix could not be decoded to hex: {}", error)))?;
```

**File:** crates/aptos/src/common/utils.rs (L385-399)
```rust
    loop {
        // Generate new keys until finding a match against the vanity prefix.
        let private_key = key_generator.generate_ed25519_private_key();
        let mut account_address =
            account_address_from_public_key(&Ed25519PublicKey::from(&private_key));
        if multisig {
            account_address = create_multisig_account_address(account_address, 0)
        };
        if account_address
            .short_str_lossless()
            .starts_with(vanity_prefix_ref)
        {
            return Ok(private_key);
        };
    }
```

**File:** third_party/move/move-core/types/src/account_address.rs (L138-145)
```rust
    pub fn short_str_lossless(&self) -> String {
        let hex_str = hex::encode(self.0).trim_start_matches('0').to_string();
        if hex_str.is_empty() {
            "0".to_string()
        } else {
            hex_str
        }
    }
```
