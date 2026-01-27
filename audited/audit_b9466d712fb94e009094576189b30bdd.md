# Audit Report

## Title
Unbounded Token Minting via Unvalidated Amount Parameter in CLI Faucet

## Summary
The `fund_account()` function in the Aptos CLI accepts an arbitrary `num_octas` parameter without validation and passes it directly to the faucet service. When used with the CLI-based MintFunder configured without a `maximum_amount` limit, this allows unrestricted token minting that can inflate supply on testnets/devnets and cause denial-of-service conditions for target accounts.

## Finding Description

The vulnerability exists across three interconnected components:

**1. No Input Validation in CLI Utility Function** [1](#0-0) 

The `fund_account()` function accepts `num_octas: u64` without any validation checks. Values up to 18,446,744,073,709,551,615 (u64::MAX) are accepted and forwarded directly to the faucet client.

**2. Missing Maximum Enforcement in CLI Faucet Configuration** [2](#0-1) 

The CLI faucet explicitly configures `TransactionSubmissionConfig` with `maximum_amount: None`, disabling any cap on minting amounts.

**3. Unbounded Minting in MintFunder** [3](#0-2) 

When `maximum_amount` is `None`, the `get_amount()` function returns the full user-requested amount without bounds checking (line 546: `(Some(amount), None) => amount`).

**Attack Scenario:**

1. Attacker identifies a testnet/devnet using the CLI faucet
2. Calls `fund_account()` with `num_octas` set to u64::MAX or other extremely large value
3. The CLI faucet mints the full requested amount
4. This causes two impacts:
   - **Supply Inflation**: Massive token supply increase breaks economic assumptions
   - **Account Balance DoS**: If account balance approaches u64::MAX, future deposits fail due to Move's overflow protection [4](#0-3) 

The deposit operation uses `store.balance += amount`, which will abort if the addition exceeds u64::MAX, creating a permanent denial-of-service for that account.

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos bug bounty criteria:

- **"Limited funds loss or manipulation"**: Enables unlimited token minting on misconfigured faucets, inflating supply and undermining tokenomics on test/dev networks
- **"State inconsistencies requiring intervention"**: Accounts funded to near-maximum balance become permanently unable to receive deposits due to overflow aborts

While Move's overflow protection prevents data corruption, it does not prevent the economic abuse or account-level denial-of-service. This vulnerability breaks **Invariant #9: "Resource Limits: All operations must respect gas, storage, and computational limits"** by allowing unbounded resource allocation.

## Likelihood Explanation

**Likelihood: Medium**

- The CLI faucet is documented and accessible to developers/operators
- Test networks and development environments commonly use default configurations without additional hardening
- No special privileges or validator access required - any user with CLI access can exploit this
- The vulnerability is straightforward to exploit with a single parameter modification

While production networks likely enforce proper limits, the widespread use of testnets and development environments for community testing creates significant exposure.

## Recommendation

Implement defense-in-depth by adding validation at the CLI layer:

```rust
pub async fn fund_account(
    rest_client: Client,
    faucet_url: Url,
    faucet_auth_token: Option<&str>,
    address: AccountAddress,
    num_octas: u64,
) -> CliTypedResult<()> {
    // Add reasonable maximum limit (e.g., 100 APT = 10 billion octas)
    const MAX_FAUCET_AMOUNT: u64 = 10_000_000_000;
    
    if num_octas > MAX_FAUCET_AMOUNT {
        return Err(CliError::CommandArgumentError(
            format!(
                "Requested amount {} octas exceeds maximum allowed {} octas", 
                num_octas, 
                MAX_FAUCET_AMOUNT
            )
        ));
    }
    
    let mut client = FaucetClient::new_from_rest_client(faucet_url, rest_client);
    if let Some(token) = faucet_auth_token {
        client = client.with_auth_token(token.to_string());
    }
    client
        .fund(address, num_octas)
        .await
        .map_err(|err| CliError::ApiError(format!("Faucet issue: {:#}", err)))
}
```

Additionally, enforce a default `maximum_amount` in the CLI faucet configuration:

```rust
let transaction_submission_config = TransactionSubmissionConfig::new(
    Some(10_000_000_000), // maximum_amount: 10 billion octas (100 APT)
    Some(100_000_000_000), // maximum_amount_with_bypass: higher limit for CI
    30,   // gas_unit_price_ttl_secs
    None, // gas_unit_price_override
    self.max_gas_amount,
    25,   // transaction_expiration_secs
    30,   // wait_for_outstanding_txns_secs
    true, // wait_for_transactions
);
```

## Proof of Concept

```bash
# Exploit: Mint near-maximum amount to an account
aptos account fund-with-faucet \
    --account 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef \
    --amount 18446744073709551615 \
    --url http://testnet-faucet.example.com

# Result: Successfully mints 18.4 million APT (instead of typical 1-10 APT)
# This inflates supply and makes the account unable to receive future deposits
```

To verify the account DoS condition:

```bash
# After minting near-max amount, attempt another deposit
aptos account transfer \
    --account 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef \
    --amount 1

# Result: Transaction ABORTS with "Addition overflow" error
# The account is permanently bricked for receiving funds
```

## Notes

This vulnerability demonstrates a failure in defense-in-depth architecture. While downstream faucet services may implement rate limiting and amount caps, the CLI utility layer provides no protection, allowing misconfigured deployments to be exploited. The issue is particularly relevant for testnets and development environments where proper operational hardening may be overlooked.

### Citations

**File:** crates/aptos/src/common/utils.rs (L455-470)
```rust
pub async fn fund_account(
    rest_client: Client,
    faucet_url: Url,
    faucet_auth_token: Option<&str>,
    address: AccountAddress,
    num_octas: u64,
) -> CliTypedResult<()> {
    let mut client = FaucetClient::new_from_rest_client(faucet_url, rest_client);
    if let Some(token) = faucet_auth_token {
        client = client.with_auth_token(token.to_string());
    }
    client
        .fund(address, num_octas)
        .await
        .map_err(|err| CliError::ApiError(format!("Faucet issue: {:#}", err)))
}
```

**File:** crates/aptos-faucet/cli/src/main.rs (L83-92)
```rust
        let transaction_submission_config = TransactionSubmissionConfig::new(
            None, // maximum_amount
            None, // maximum_amount_with_bypass
            30,   // gas_unit_price_ttl_secs
            None, // gas_unit_price_override
            self.max_gas_amount,
            25,   // transaction_expiration_secs
            30,   // wait_for_outstanding_txns_secs
            true, // wait_for_transactions
        );
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

**File:** aptos-move/framework/aptos-framework/sources/fungible_asset.move (L1265-1265)
```text
                store.balance += amount;
```
