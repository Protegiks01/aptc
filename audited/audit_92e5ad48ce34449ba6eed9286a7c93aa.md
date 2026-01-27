# Audit Report

## Title
MintFunder Integer Overflow Bypass Allows Unlimited Token Minting via Uncapped Amount Parameter

## Summary
The `MintFunder::get_amount` function contains a logic flaw that allows user-specified amounts to bypass the `amount_to_fund` default cap when `maximum_amount` is not configured, enabling minting of up to u64::MAX tokens and potential gas-draining DoS attacks. [1](#0-0) 

## Finding Description
The vulnerability exists in the amount validation logic of `MintFunder`. When a user specifies an amount via the CLI and the faucet's `maximum_amount` configuration is `None`, the code returns the user-provided amount without comparing it against the `amount_to_fund` default cap (100 billion octas). [2](#0-1) 

The vulnerable match arm at line 546 returns `amount` directly when `maximum_amount` is `None`, bypassing the `self.amount_to_fund` cap. This is inconsistent with the behavior when `amount` is `None` (line 548), which correctly uses `self.amount_to_fund` as the default.

In contrast, `TransferFunder` correctly caps the amount in all cases: [3](#0-2) 

**Attack Flow:**
1. Attacker invokes: `aptos account fund-with-faucet --account 0xVICTIM --amount 18446744073709551615`
2. Amount flows through client to faucet server [4](#0-3) 
3. `MintFunder::get_amount` returns u64::MAX (bypassing amount_to_fund cap) [5](#0-4) 
4. Minter script executes with amount = u64::MAX [6](#0-5) 

**Two exploitation scenarios:**

**Scenario A (New Account):** If the receiver account doesn't exist or has zero balance, the deposit succeeds, creating an account with ~18.4 quintillion octas (184 million APT equivalent). 

**Scenario B (Existing Account):** If the receiver has any existing balance, `store.balance + u64::MAX` causes arithmetic overflow. Move VM aborts the transaction, but the faucet still pays gas for the failed transaction, enabling a gas-draining DoS attack.

## Impact Explanation
This vulnerability allows bypassing intended faucet limits, resulting in:

1. **Unlimited Token Minting:** Attacker can mint up to u64::MAX tokens per request on misconfigured faucets, causing massive token inflation in testnet/devnet environments
2. **Gas-Draining DoS:** Repeated failed transactions (overflow aborts) drain faucet funds through wasted gas costs
3. **Configuration Inconsistency:** The logic inconsistency between MintFunder and TransferFunder creates operational risks

While limited to testnet/devnet environments (faucets don't operate on mainnet), this qualifies as **Medium severity** per bug bounty criteria: "Limited funds loss or manipulation" and "State inconsistencies requiring intervention."

## Likelihood Explanation
**High Likelihood** in misconfigured deployments:
- `maximum_amount` is `Option<u64>` with no default value [7](#0-6) 
- Development/testing faucets frequently omit this configuration
- Attack requires only CLI access with no special permissions
- Exploitation is trivial (single command)

## Recommendation
Apply consistent capping logic matching `TransferFunder` behavior:

```rust
fn get_amount(&self, amount: Option<u64>, did_bypass_checkers: bool) -> u64 {
    match (
        amount,
        self.txn_config.get_maximum_amount(did_bypass_checkers),
    ) {
        (Some(amount), Some(maximum_amount)) => std::cmp::min(amount, maximum_amount),
        (Some(amount), None) => std::cmp::min(amount, self.amount_to_fund), // FIX: Cap against amount_to_fund
        (None, Some(maximum_amount)) => std::cmp::min(self.amount_to_fund, maximum_amount),
        (None, None) => self.amount_to_fund,
    }
}
```

Additionally, consider requiring `maximum_amount` configuration at faucet startup to prevent deployment misconfigurations.

## Proof of Concept

```bash
# Setup: Deploy faucet with MintFunder and maximum_amount = None

# Attack Step 1: Attempt to mint u64::MAX to new account
aptos account fund-with-faucet \
  --account 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef \
  --amount 18446744073709551615 \
  --faucet-url http://localhost:8081

# Expected: Account receives 18,446,744,073,709,551,615 octas (should be capped at 100,000,000,000)

# Attack Step 2: DoS via overflow (if account exists with balance > 0)
for i in {1..100}; do
  aptos account fund-with-faucet \
    --account 0xEXISTING_ACCOUNT \
    --amount 18446744073709551615 \
    --faucet-url http://localhost:8081 &
done
# Expected: 100 failed transactions, faucet pays gas for each
```

**Verification:**
Check minted amount exceeds amount_to_fund default (100 billion octas) when maximum_amount is not configured, demonstrating the cap bypass.

### Citations

**File:** crates/aptos/src/account/fund.rs (L24-29)
```rust
    /// Number of Octas to fund the account from the faucet
    ///
    /// The amount added to the account may be limited by the faucet, and may be less
    /// than the amount requested.
    #[clap(long, default_value_t = DEFAULT_FUNDED_COINS)]
    pub amount: u64,
```

**File:** crates/aptos-faucet/core/src/funder/mint.rs (L488-491)
```rust
                    TransactionPayload::Script(Script::new(MINTER_SCRIPT.to_vec(), vec![], vec![
                        TransactionArgument::Address(receiver_address),
                        TransactionArgument::U64(amount),
                    ]))
```

**File:** crates/aptos-faucet/core/src/funder/mint.rs (L528-528)
```rust
        let amount = self.get_amount(amount, did_bypass_checkers);
```

**File:** crates/aptos-faucet/core/src/funder/mint.rs (L540-550)
```rust
    fn get_amount(&self, amount: Option<u64>, did_bypass_checkers: bool) -> u64 {
        match (
            amount,
            self.txn_config.get_maximum_amount(did_bypass_checkers),
        ) {
            (Some(amount), Some(maximum_amount)) => std::cmp::min(amount, maximum_amount),
            (Some(amount), None) => amount,
            (None, Some(maximum_amount)) => std::cmp::min(self.amount_to_fund, maximum_amount),
            (None, None) => self.amount_to_fund,
        }
    }
```

**File:** crates/aptos-faucet/core/src/funder/transfer.rs (L333-344)
```rust
    fn get_amount(
        &self,
        amount: Option<u64>,
        // Ignored for now with TransferFunder, since generally we don't use Bypassers
        // when using the TransferFunder.
        _did_bypass_checkers: bool,
    ) -> u64 {
        match amount {
            Some(amount) => std::cmp::min(amount, self.amount_to_fund.0),
            None => self.amount_to_fund.0,
        }
    }
```

**File:** crates/aptos-rest-client/src/faucet.rs (L84-88)
```rust
    pub async fn fund(&self, address: AccountAddress, amount: u64) -> Result<()> {
        let mut url = self.faucet_url.clone();
        url.set_path("mint");
        let query = format!("auth_key={}&amount={}&return_txns=true", address, amount);
        url.set_query(Some(&query));
```

**File:** crates/aptos-faucet/core/src/funder/common.rs (L95-96)
```rust
    /// Maximum amount of OCTA to give an account.
    maximum_amount: Option<u64>,
```
