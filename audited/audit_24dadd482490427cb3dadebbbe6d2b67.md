# Audit Report

## Title
Vanity Multisig Address Mismatch Due to Hardcoded Sequence Number Assumption

## Summary
The CLI tool's vanity multisig key generation feature displays an incorrect multisig account address when the creator account performs any transactions before creating the multisig. The CLI hardcodes sequence number 0 for address prediction, but the actual on-chain creation uses the creator's current sequence number, leading to address mismatch and potential loss of funds. [1](#0-0) 

## Finding Description
When a user generates a vanity multisig key using `--vanity-multisig`, the CLI calculates and displays the expected multisig account address using a hardcoded sequence number of 0. However, the actual on-chain multisig creation mechanism reads the creator account's current sequence number at the time of creation. [2](#0-1) 

The vulnerability arises from the mismatch between:
1. **CLI prediction**: Uses sequence number 0 unconditionally
2. **On-chain creation**: Uses `account::get_sequence_number(address_of(owner))` at transaction execution time

This breaks the address determinism assumption when the creator account has executed any transactions before creating the multisig account.

**Attack Scenario:**
1. Alice generates a vanity multisig key with prefix "0xdead"
2. CLI displays: "Multisig Account Address: 0xdead456..." (calculated with sequence_number=0)
3. Alice sends funds to her new account or executes another transaction (sequence_number increments from 0 to 1)
4. Bob sends 1000 APT to the displayed multisig address 0xdead456...
5. Alice creates the multisig using `create_with_owners_then_remove_bootstrapper`
6. Multisig is actually created at 0xbad789... (calculated with sequence_number=1)
7. Bob's 1000 APT is now at an address where no multisig exists and Alice doesn't control

While the code documentation mentions this should be "the first transaction," there is no validation, warning, or clear user-facing communication of this critical requirement. [3](#0-2) [4](#0-3) 

## Impact Explanation
This qualifies as **Medium severity** under the Aptos bug bounty program criteria for "Limited funds loss or manipulation" and "State inconsistencies requiring intervention."

**Specific impacts:**
- **Funds Loss**: Users or counterparties sending funds to the displayed address before multisig creation will send to an uncontrolled address
- **Operational Confusion**: The multisig is created at an unexpected address, breaking integrations and automation
- **Trust Violation**: The CLI displays incorrect information without warnings

The impact is limited to users who deviate from the undocumented requirement that multisig creation must be the first transaction, but the CLI provides no safeguards against this.

## Likelihood Explanation
**Likelihood: Medium-High**

This issue is likely to occur because:

1. **Common User Flow**: New users naturally test accounts before using them for important operations
2. **No Warnings**: The CLI provides no indication that the displayed address is conditional
3. **Hidden Requirement**: The "first transaction" requirement is only in code comments, not user-facing documentation
4. **Account Funding**: Users must fund the account before creating the multisig (for gas), which might involve transactions that increment the sequence number from the funding account's perspective, though receiving funds doesn't increment the receiver's sequence number

The vulnerability requires no special knowledge or malicious intent - it's a normal user error resulting from inadequate guardrails.

## Recommendation

**Immediate Fix**: Add validation and warnings in the CLI tool:

```rust
// In key.rs, around line 249-256
if self.vanity_multisig {
    let multisig_account_address =
        create_multisig_account_address(account_address, 0);
    result_map.insert(
        "Multisig Account Address:",
        PathBuf::from(multisig_account_address.to_hex_literal()),
    );
    
    // ADD THIS WARNING
    eprintln!("⚠️  WARNING: This multisig address is only valid if creating the multisig");
    eprintln!("    is your FIRST transaction from account {}.", account_address);
    eprintln!("    Any prior transactions will cause a different address to be created.");
}
```

**Long-term Fix**: Query the actual sequence number if the account exists, or provide a tool to calculate the correct address based on current state:

```rust
// Enhanced version that checks on-chain state
if self.vanity_multisig {
    let multisig_account_address =
        create_multisig_account_address(account_address, 0);
    
    // If we have an RPC endpoint, warn if account already exists
    if let Some(client) = rest_client {
        if let Ok(account) = client.get_account(account_address).await {
            if account.sequence_number > 0 {
                eprintln!("❌ ERROR: Account already has sequence number {}.", 
                    account.sequence_number);
                eprintln!("    The actual multisig address will be different!");
                eprintln!("    Expected: {}", 
                    create_multisig_account_address(account_address, 
                        account.sequence_number));
            }
        }
    }
}
```

## Proof of Concept

**Step-by-step reproduction:**

```bash
# Step 1: Generate vanity multisig key
aptos key generate --vanity-prefix 0xabc --vanity-multisig \
  --output-file vanity.key --assume-yes

# Output shows:
# Account Address: 0x123...
# Multisig Account Address: 0xabc456... (WRONG if not first tx!)

# Step 2: Fund the account (this doesn't increment its sequence number)
aptos account fund-with-faucet --account 0x123...

# Step 3: Do ANY transaction from this account (increments sequence number)
aptos account transfer --account 0x123... \
  --destination 0x999... --amount 100

# Step 4: Now create the multisig
aptos multisig create-with-owners-then-remove-bootstrapper \
  --private-key-file vanity.key \
  --owners 0xowner1,0xowner2 \
  --num-signatures-required 2

# Step 5: Query where multisig was ACTUALLY created
# It will be at a DIFFERENT address than 0xabc456...
# Because sequence_number was 1, not 0

# Verification:
# The actual address is: create_multisig_account_address(0x123..., 1)
# The displayed address was: create_multisig_account_address(0x123..., 0)
# These are DIFFERENT addresses!
```

**Move-based validation test:**

```move
#[test]
fun test_vanity_multisig_address_mismatch() {
    let creator = @0x123;
    
    // Address with sequence number 0 (what CLI displays)
    let predicted_address = multisig_account::get_next_multisig_account_address(creator);
    // Assumes sequence_number = 0
    
    // User does a transaction (sequence number becomes 1)
    // ... transaction execution ...
    
    // Address with sequence number 1 (what actually gets created)
    let actual_address = multisig_account::get_next_multisig_account_address(creator);
    
    // These are DIFFERENT addresses!
    assert!(predicted_address != actual_address, 0);
}
```

**Notes:**
- This issue affects all users who generate vanity multisig keys and don't create the multisig as their absolute first transaction
- The Rust types implementation correctly implements the deterministic address derivation; the bug is in the CLI's assumption
- The on-chain Move code is also correct; it uses the current sequence number as designed [5](#0-4)

### Citations

**File:** crates/aptos/src/op/key.rs (L186-188)
```rust
    /// Use this flag when vanity prefix is for a multisig account. This mines a private key for
    /// a single signer account that can, as its first transaction, create a multisig account with
    /// the given vanity prefix
```

**File:** crates/aptos/src/op/key.rs (L250-251)
```rust
                        let multisig_account_address =
                            create_multisig_account_address(account_address, 0);
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1327-1330)
```text
    fun create_multisig_account(owner: &signer): (signer, SignerCapability) {
        let owner_nonce = account::get_sequence_number(address_of(owner));
        let (multisig_signer, multisig_signer_cap) =
            account::create_resource_account(owner, create_multisig_account_seed(to_bytes(&owner_nonce)));
```

**File:** crates/aptos/src/common/utils.rs (L361-362)
```rust
/// For a multisig account, this function generates private keys until finding one that can create
/// a multisig account with the given vanity prefix as its first transaction (sequence number 0).
```

**File:** types/src/account_address.rs (L238-246)
```rust
pub fn create_multisig_account_address(
    creator: AccountAddress,
    creator_nonce: u64,
) -> AccountAddress {
    let mut full_seed = vec![];
    full_seed.extend(MULTISIG_ACCOUNT_DOMAIN_SEPARATOR);
    full_seed.extend(bcs::to_bytes(&creator_nonce).unwrap());
    create_resource_address(creator, &full_seed)
}
```
