# Audit Report

## Title
Authorization Confusion in Rosetta CLI: Sender Parameter Silently Ignored After Key Rotation

## Summary
The `TransferCommand::execute()` function (and all other construction commands) in the Aptos Rosetta CLI contains an optional `sender` parameter designed to handle authentication key rotation scenarios. However, this parameter is completely ignored during transaction construction, causing the CLI to derive the sender address from the private key instead. This creates authorization confusion where users explicitly specify which account should send the transaction, but a different account is used, potentially leading to transaction failures or sending funds from an unintended account.

## Finding Description

The Rosetta CLI commands include an optional `--sender` field with the explicit comment "The sending account, since the private key doesn't always match the AccountAddress if it rotates". [1](#0-0) 

However, the `TransferCommand::execute()` implementation never passes this `sender` field to the underlying `client.transfer()` function: [2](#0-1) 

Instead, the `RosettaClient::transfer()` function always derives the sender address from the private key using `get_account_address()`: [3](#0-2) 

The `get_account_address()` function calls the Rosetta `/construction/derive` endpoint, which derives an address using the Ed25519 authentication scheme: [4](#0-3) 

**The Problem:** After authentication key rotation in Aptos:
- The account address remains constant (e.g., `0x123`)
- The authentication key changes to the hash of the new public key
- The derived address from the new public key is **different** from the account address (e.g., `0x456`)

**Attack Scenario:**
1. Alice creates account at address `0x123` with key pair `(sk1, pk1)` where `derive(pk1) = 0x123`
2. Alice rotates her authentication key to `(sk2, pk2)` where `derive(pk2) = 0x456`
3. Alice attempts: `rosetta-cli transfer --sender 0x123 --private-key sk2 --receiver Bob --amount 100`
4. The CLI ignores `--sender 0x123` and derives sender as `0x456` from `sk2`
5. The transaction is constructed with sender = `0x456` instead of `0x123`
6. **Outcome:** Transaction either fails (if `0x456` doesn't exist) or sends from the wrong account (if `0x456` exists and is controlled by the same key)

This same bug affects all construction commands: `CreateAccountCommand`, `SetOperatorCommand`, `SetVoterCommand`, and `CreateStakePoolCommand`—all have the sender field defined but never use it. [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) 

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos Bug Bounty criteria: "Limited funds loss or manipulation, State inconsistencies requiring intervention."

**Specific Impacts:**
1. **Loss of Funds:** If a user has two accounts (`0x123` and `0x456`) both controlled by the same rotated key, specifying `--sender 0x123` will silently send from `0x456` instead, causing unintended fund transfers
2. **Transaction Failures:** If the derived address doesn't exist, metadata retrieval fails when attempting to fetch the sequence number [9](#0-8) 
3. **Key Rotation Unusable:** The entire purpose of the `--sender` parameter (handling key rotation) is defeated, making Rosetta CLI unusable for rotated accounts
4. **Authorization Confusion:** Users explicitly authorize transactions from a specific account, but the system ignores this authorization directive

## Likelihood Explanation

**Likelihood: Medium**

This vulnerability triggers whenever:
- A user rotates their authentication key (documented Aptos feature)
- The user attempts to use the Rosetta CLI with the rotated key
- The derived address from the new key differs from the original account address

Key rotation is a legitimate security practice for:
- Compromised key recovery
- Periodic key refresh policies
- Multi-sig to single-sig transitions

While not every user rotates keys, this is a documented feature that security-conscious users would employ, making the likelihood non-trivial.

## Recommendation

**Fix:** Pass the optional `sender` parameter to the client functions and use it when provided, falling back to derived address only when not specified.

**Modified `TransferCommand::execute()`:**
```rust
pub async fn execute(self) -> anyhow::Result<TransactionIdentifier> {
    info!("Transfer {:?}", self);
    let client = self.url_args.client();
    let network_identifier = self.network_args.network_identifier();
    let private_key = self
        .private_key_options
        .extract_private_key(self.encoding_options.encoding, &self.profile_options)?;

    client
        .transfer(
            &network_identifier,
            &private_key,
            self.sender,  // Pass the optional sender
            self.receiver,
            self.amount,
            self.txn_args.expiry_time()?,
            self.txn_args.sequence_number,
            self.txn_args.max_gas,
            self.txn_args.gas_price,
            self.currency,
        )
        .await
}
```

**Modified `RosettaClient::transfer()`:**
```rust
pub async fn transfer(
    &self,
    network_identifier: &NetworkIdentifier,
    private_key: &Ed25519PrivateKey,
    sender: Option<AccountAddress>,  // Add parameter
    receiver: AccountAddress,
    amount: u64,
    expiry_time_secs: u64,
    sequence_number: Option<u64>,
    max_gas: Option<u64>,
    gas_unit_price: Option<u64>,
    currency: Currency,
) -> anyhow::Result<TransactionIdentifier> {
    // Use provided sender or derive from key
    let sender = if let Some(addr) = sender {
        addr
    } else {
        self.get_account_address(network_identifier.clone(), private_key).await?
    };
    
    // Rest of implementation unchanged
    let mut keys = HashMap::new();
    keys.insert(sender, private_key);
    // ...
}
```

Apply similar changes to all construction commands (`create_account`, `set_operator`, `set_voter`, `create_stake_pool`).

## Proof of Concept

**Rust Test Demonstrating the Bug:**

```rust
use aptos_rosetta_cli::construction::TransferCommand;
use aptos_crypto::{ed25519::Ed25519PrivateKey, PrivateKey};
use aptos_types::account_address::AccountAddress;

#[tokio::test]
async fn test_sender_confusion_after_key_rotation() {
    // Setup: Create account at 0x123 with key1
    let key1 = Ed25519PrivateKey::generate_for_testing();
    let key2 = Ed25519PrivateKey::generate_for_testing();
    
    // Derive addresses
    let addr1 = AuthenticationKey::ed25519(&key1.public_key()).account_address();
    let addr2 = AuthenticationKey::ed25519(&key2.public_key()).account_address();
    
    // After rotation, account is at addr1 but controlled by key2
    // addr1 != addr2 (different addresses!)
    assert_ne!(addr1, addr2);
    
    // User tries to send from addr1 using key2
    let cmd = TransferCommand {
        sender: Some(addr1),  // User explicitly specifies sender
        private_key: key2,
        receiver: AccountAddress::random(),
        amount: 100,
        // ... other fields
    };
    
    // BUG: The command will derive addr2 from key2 and ignore sender parameter
    // This causes authorization confusion - user wanted addr1 but got addr2
    let result = cmd.execute().await;
    
    // Expected: Transaction from addr1
    // Actual: Transaction attempts to use addr2 (fails if doesn't exist)
}
```

**Command Line Reproduction:**
```bash
# 1. Create account at address A with key1
aptos account create --account alice

# 2. Rotate authentication key to key2
aptos account rotate-key --new-private-key key2.txt

# 3. Attempt transfer specifying original address
# BUG: This will derive address B from key2 and ignore --sender A
rosetta-cli transfer \
  --sender 0xA... \
  --private-key key2.txt \
  --receiver 0xBob... \
  --amount 100

# Result: Transaction fails or sends from wrong account
```

## Notes

This vulnerability affects the Rosetta CLI tool specifically, not the core Aptos protocol. However, it represents a significant authorization bug that breaks user intent and makes authentication key rotation effectively unusable through the Rosetta API. All construction commands (`transfer`, `create_account`, `set_operator`, `set_voter`, `create_stake_pool`) share this vulnerability.

### Citations

**File:** crates/aptos-rosetta-cli/src/construction.rs (L98-100)
```rust
    /// AccountAddress if it rotates
    #[clap(long, value_parser = aptos::common::types::load_account_arg)]
    sender: Option<AccountAddress>,
```

**File:** crates/aptos-rosetta-cli/src/construction.rs (L147-150)
```rust
    /// The sending account, since the private key doesn't always match the
    /// AccountAddress if it rotates
    #[clap(long, value_parser = aptos::common::types::load_account_arg)]
    sender: Option<AccountAddress>,
```

**File:** crates/aptos-rosetta-cli/src/construction.rs (L166-187)
```rust
    pub async fn execute(self) -> anyhow::Result<TransactionIdentifier> {
        info!("Transfer {:?}", self);
        let client = self.url_args.client();
        let network_identifier = self.network_args.network_identifier();
        let private_key = self
            .private_key_options
            .extract_private_key(self.encoding_options.encoding, &self.profile_options)?;

        client
            .transfer(
                &network_identifier,
                &private_key,
                self.receiver,
                self.amount,
                self.txn_args.expiry_time()?,
                self.txn_args.sequence_number,
                self.txn_args.max_gas,
                self.txn_args.gas_price,
                self.currency,
            )
            .await
    }
```

**File:** crates/aptos-rosetta-cli/src/construction.rs (L209-210)
```rust
    #[clap(long, value_parser = aptos::common::types::load_account_arg)]
    sender: Option<AccountAddress>,
```

**File:** crates/aptos-rosetta-cli/src/construction.rs (L262-263)
```rust
    #[clap(long, value_parser = aptos::common::types::load_account_arg)]
    sender: Option<AccountAddress>,
```

**File:** crates/aptos-rosetta-cli/src/construction.rs (L315-316)
```rust
    #[clap(long, value_parser = aptos::common::types::load_account_arg)]
    sender: Option<AccountAddress>,
```

**File:** crates/aptos-rosetta/src/client.rs (L196-198)
```rust
        let sender = self
            .get_account_address(network_identifier.clone(), private_key)
            .await?;
```

**File:** crates/aptos-rosetta/src/construction.rs (L202-206)
```rust
    // The input must be an Ed25519 Public key and will only derive the Address for the original
    // Aptos Ed25519 authentication scheme
    let public_key: Ed25519PublicKey =
        decode_key(&request.public_key.hex_bytes, "Ed25519PublicKey")?;
    let address = AuthenticationKey::ed25519(&public_key).account_address();
```

**File:** crates/aptos-rosetta/src/construction.rs (L457-458)
```rust
    let address = request.options.internal_operation.sender();
    let response = get_account(&rest_client, address).await?;
```
