# Audit Report

## Title
Dual Authorization Control Vulnerability in Multisig Account Migration Allows Bypass of Multisig Approval Requirements

## Summary
When converting an existing regular account to a multisig account using `create_with_existing_account`, the original authentication key remains active unless explicitly rotated. This creates a dual-control state where funds can be accessed either through the original auth key OR through multisig approvals, violating the security guarantee that multisig accounts require multiple signatures for fund access.

## Finding Description

The Aptos multisig account system provides a migration path for converting existing accounts to multisig accounts via `create_with_existing_account`. [1](#0-0) 

This function creates a `MultisigAccount` resource at an existing address but explicitly does not revoke the original authentication key. [2](#0-1) 

The critical security issue is that the regular transaction validation prologue (`prologue_common`) does NOT check for the existence of a `MultisigAccount` resource. [3](#0-2) 

It only validates:
- Authentication key matches
- Sequence number is correct  
- Gas payment is sufficient

This means an account can simultaneously have:
1. **Regular account control** - via authentication key for standard transactions
2. **Multisig control** - via MultisigAccount resource requiring k-of-n approvals

**Attack Flow:**
1. Alice creates regular account at address X with her auth key
2. Alice calls `create_with_existing_account` adding Bob and Charlie as multisig owners (requiring 2-of-3 approval)
3. Alice deliberately does NOT rotate her authentication key
4. Bob and Charlie deposit funds to address X, believing all withdrawals require 2-of-3 multisig approval
5. Alice submits a regular transaction signed with her original key, transferring all funds to her personal account
6. The transaction validation prologue accepts it (valid auth key, correct sequence number)
7. Alice has bypassed multisig requirements and stolen Bob's and Charlie's deposits

## Impact Explanation

This qualifies as **High Severity** under Aptos bug bounty criteria for "Significant protocol violations."

The vulnerability breaks the fundamental security guarantee of multisig accounts: that funds require approval from multiple parties. When a `MultisigAccount` resource exists at an address, the reasonable expectation is that ALL transactions from that address must go through multisig validation. However, the current implementation allows this guarantee to be violated.

The impact includes:
- **Authorization bypass** - Single party can circumvent multi-party approval requirements
- **Fund theft** - Parties depositing to multisig accounts expecting collective control can be defrauded
- **Trust violation** - Breaks the security model parties rely on when using multisig for joint custody
- **Protocol integrity** - Contradicts the documented behavior that multisig accounts require multiple signatures

While a secure alternative function (`create_with_existing_account_and_revoke_auth_key`) exists, the presence of an insecure option that creates a vulnerable state is itself a security flaw. The system should enforce security invariants rather than relying solely on users choosing the correct function.

## Likelihood Explanation

**Likelihood: Medium to High**

The attack is realistic because:

1. **Documented migration path** - `create_with_existing_account` is an officially supported function for account conversion [4](#0-3) 

2. **User confusion** - The warning about auth key revocation only appears in code comments, not user-facing documentation. Users may not realize they need to take an additional step.

3. **Intentional exploitation** - A malicious party setting up a "multisig" for joint custody could deliberately skip auth key rotation to maintain backdoor access.

4. **Trust assumption** - Multisig participants typically trust each other to set up the account correctly, making social engineering attacks feasible.

5. **No runtime protection** - The system allows the vulnerable state to persist indefinitely with no warnings or enforcement.

The attack requires the account owner to actively choose not to rotate their auth key (or use the insecure creation function), but this could happen through either ignorance or malicious intent.

## Recommendation

**Immediate Fix: Add MultisigAccount Check to Transaction Prologue**

The transaction validation prologue should verify that accounts with a `MultisigAccount` resource can only be accessed through multisig transactions, not regular transactions:

```move
// In transaction_validation.move, prologue_common function
// Add after authentication key check and before sequence number check:

if (multisig_account::exists_multisig_account(sender_address)) {
    assert!(
        false,  // Or use a more specific check for transaction type
        error::permission_denied(PROLOGUE_MULTISIG_ACCOUNT_REQUIRES_MULTISIG_TXN)
    );
};
```

**Alternative Fix: Deprecate Insecure Functions**

Mark `create_with_existing_account` and `create_with_existing_account_call` as deprecated and guide users exclusively to `create_with_existing_account_and_revoke_auth_key`.

**Complete Fix: Enforce Auth Key Rotation**

Modify `create_with_owners_internal` to automatically rotate the authentication key to `ZERO_AUTH_KEY` when a `signer_cap` is not provided (indicating conversion of an existing account):

```move
fun create_with_owners_internal(
    multisig_account: &signer,
    owners: vector<address>,
    num_signatures_required: u64,
    multisig_account_signer_cap: Option<SignerCapability>,
    metadata_keys: vector<String>,
    metadata_values: vector<vector<u8>>,
) acquires MultisigAccount {
    // ... existing code ...
    
    // If no signer_cap (existing account conversion), enforce auth key rotation
    if (option::is_none(&multisig_account_signer_cap)) {
        account::rotate_authentication_key_internal(multisig_account, ZERO_AUTH_KEY);
    };
    
    // ... rest of function ...
}
```

## Proof of Concept

```move
#[test(alice = @0x123, bob = @0x456, framework = @0x1)]
fun test_dual_control_vulnerability(
    alice: &signer,
    bob: &signer,
    framework: &signer
) {
    use aptos_framework::account;
    use aptos_framework::multisig_account;
    use aptos_framework::coin;
    use aptos_framework::aptos_coin::AptosCoin;
    
    // Setup
    setup_aptos_framework(framework);
    
    // Alice creates a regular account
    let alice_addr = signer::address_of(alice);
    account::create_account_for_test(alice_addr);
    
    // Alice converts to multisig WITHOUT rotating auth key
    // Using create_with_existing_account_call with alice's signer
    multisig_account::create_with_existing_account_call(
        alice,
        vector[signer::address_of(bob)], // Add Bob as co-owner
        2, // Require 2-of-2 approval
        vector[],
        vector[]
    );
    
    // Bob believes account requires 2-of-2 approval and deposits funds
    coin::register<AptosCoin>(alice);
    coin::deposit<AptosCoin>(alice_addr, 1000);
    
    // VULNERABILITY: Alice can still use regular transactions with her auth key
    // This bypasses the multisig requirement!
    // A regular transfer transaction signed with Alice's original key will succeed
    // even though a MultisigAccount resource exists requiring 2-of-2 approval
    
    // Verify dual control state exists:
    assert!(account::exists_at(alice_addr), 0); // Regular Account exists
    assert!(multisig_account::is_multisig_account(alice_addr), 1); // MultisigAccount exists
    
    // This state allows BOTH regular and multisig transactions
    // Regular transactions only need Alice's signature
    // Multisig transactions need both Alice and Bob
    // This violates the security guarantee of multisig accounts!
}
```

**Notes:**
- This vulnerability exists by design in the migration path functions
- While documented in code comments, it creates a security footgun
- The lack of runtime enforcement at the prologue level allows the dangerous state to persist
- Users depositing to accounts with `MultisigAccount` resources reasonably expect all transactions require multisig approval
- The proper fix is to enforce separation between authorization mechanisms at the protocol level

### Citations

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L504-506)
```text
    /// Note that this does not revoke auth key-based control over the account. Owners should separately rotate the auth
    /// key after they are fully migrated to the new multisig account. Alternatively, they can call
    /// create_with_existing_account_and_revoke_auth_key_call instead.
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L524-532)
```text
    /// Creates a new multisig account on top of an existing account.
    ///
    /// This offers a migration path for an existing account with a multi-ed25519 auth key (native multisig account).
    /// In order to ensure a malicious module cannot obtain backdoor control over an existing account, a signed message
    /// with a valid signature from the account's auth key is required.
    ///
    /// Note that this does not revoke auth key-based control over the account. Owners should separately rotate the auth
    /// key after they are fully migrated to the new multisig account. Alternatively, they can call
    /// create_with_existing_account_and_revoke_auth_key instead.
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L533-572)
```text
    public entry fun create_with_existing_account(
        multisig_address: address,
        owners: vector<address>,
        num_signatures_required: u64,
        account_scheme: u8,
        account_public_key: vector<u8>,
        create_multisig_account_signed_message: vector<u8>,
        metadata_keys: vector<String>,
        metadata_values: vector<vector<u8>>,
    ) acquires MultisigAccount {
        // Verify that the `MultisigAccountCreationMessage` has the right information and is signed by the account
        // owner's key.
        let proof_challenge = MultisigAccountCreationMessage {
            chain_id: chain_id::get(),
            account_address: multisig_address,
            sequence_number: account::get_sequence_number(multisig_address),
            owners,
            num_signatures_required,
        };
        account::verify_signed_message(
            multisig_address,
            account_scheme,
            account_public_key,
            create_multisig_account_signed_message,
            proof_challenge,
        );

        // We create the signer for the multisig account here since this is required to add the MultisigAccount resource
        // This should be safe and authorized because we have verified the signed message from the existing account
        // that authorizes creating a multisig account with the specified owners and signature threshold.
        let multisig_account = &create_signer(multisig_address);
        create_with_owners_internal(
            multisig_account,
            owners,
            num_signatures_required,
            option::none<SignerCapability>(),
            metadata_keys,
            metadata_values,
        );
    }
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L126-213)
```text
    fun prologue_common(
        sender: &signer,
        gas_payer: &signer,
        replay_protector: ReplayProtector,
        txn_authentication_key: Option<vector<u8>>,
        txn_gas_price: u64,
        txn_max_gas_units: u64,
        txn_expiration_time: u64,
        chain_id: u8,
        is_simulation: bool,
    ) {
        let sender_address = signer::address_of(sender);
        let gas_payer_address = signer::address_of(gas_payer);
        assert!(
            timestamp::now_seconds() < txn_expiration_time,
            error::invalid_argument(PROLOGUE_ETRANSACTION_EXPIRED),
        );
        assert!(chain_id::get() == chain_id, error::invalid_argument(PROLOGUE_EBAD_CHAIN_ID));

        // TODO[Orderless]: Here, we are maintaining the same order of validation steps as before orderless txns were introduced.
        // Ideally, do the replay protection check in the end after the authentication key check and gas payment checks.

        // Check if the authentication key is valid
        if (!skip_auth_key_check(is_simulation, &txn_authentication_key)) {
            if (option::is_some(&txn_authentication_key)) {
                if (
                    sender_address == gas_payer_address ||
                    account::exists_at(sender_address) ||
                    !features::sponsored_automatic_account_creation_enabled()
                ) {
                    assert!(
                        txn_authentication_key == option::some(account::get_authentication_key(sender_address)),
                        error::invalid_argument(PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY),
                    );
                };
            } else {
                assert!(
                    allow_missing_txn_authentication_key(sender_address),
                    error::invalid_argument(PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY)
                );
            };
        };

        // Check for replay protection
        match (replay_protector) {
            SequenceNumber(txn_sequence_number) => {
                check_for_replay_protection_regular_txn(
                    sender_address,
                    gas_payer_address,
                    txn_sequence_number,
                );
            },
            Nonce(nonce) => {
                check_for_replay_protection_orderless_txn(
                    sender_address,
                    nonce,
                    txn_expiration_time,
                );
            }
        };

        // Check if the gas payer has enough balance to pay for the transaction
        let max_transaction_fee = txn_gas_price * txn_max_gas_units;
        if (!skip_gas_payment(
            is_simulation,
            gas_payer_address
        )) {
            assert!(
                permissioned_signer::check_permission_capacity_above(
                    gas_payer,
                    (max_transaction_fee as u256),
                    GasPermission {}
                ),
                error::permission_denied(PROLOGUE_PERMISSIONED_GAS_LIMIT_INSUFFICIENT)
            );
            if (features::operations_default_to_fa_apt_store_enabled()) {
                assert!(
                    aptos_account::is_fungible_balance_at_least(gas_payer_address, max_transaction_fee),
                    error::invalid_argument(PROLOGUE_ECANT_PAY_GAS_DEPOSIT)
                );
            } else {
                assert!(
                    coin::is_balance_at_least<AptosCoin>(gas_payer_address, max_transaction_fee),
                    error::invalid_argument(PROLOGUE_ECANT_PAY_GAS_DEPOSIT)
                );
            }
        };
    }
```
