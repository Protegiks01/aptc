# Audit Report

## Title
Faucet Fund Drainage via Missing Maximum Amount Enforcement

## Summary
The Aptos faucet system fails to enforce a maximum funding amount per request when the `maximum_amount` configuration parameter is not set (defaults to `None`). This allows attackers to request arbitrarily large amounts and completely drain the faucet in a single transaction.

## Finding Description

The vulnerability exists in the amount validation logic of the `MintFunder` implementation. When processing funding requests, the system determines the actual amount to fund through the `get_amount()` method, which is supposed to enforce maximum limits. [1](#0-0) 

The critical flaw occurs when `maximum_amount` is `None` in the configuration. In this case, the match arm `(Some(amount), None) => amount` returns the user-supplied amount without any cap or validation.

The default configurations demonstrate this vulnerability: [2](#0-1) [3](#0-2) 

Both set `maximum_amount` to `None`, leaving the faucet completely unprotected.

The `TransactionSubmissionConfig` structure defines `maximum_amount` as optional: [4](#0-3) 

**Attack Flow:**
1. Attacker sends a POST request to `/fund` endpoint with `amount: Some(u64::MAX)` or any large value
2. Request passes through `preprocess_request()` and checker validations
3. `funder.fund()` is called with the attacker's requested amount
4. `get_amount()` returns the full requested amount since `maximum_amount` is `None`
5. The minting transaction is created with the uncapped amount
6. Blockchain mints the full requested amount to the attacker's address

The underlying Move `mint` function has no inherent limits: [5](#0-4) 

## Impact Explanation

This vulnerability qualifies as **Critical Severity** under the Aptos Bug Bounty program criteria:

**Loss of Funds (theft or minting)**: An attacker can drain the entire faucet balance or mint unlimited tokens in testnets/devnets where the faucet has minting capabilities. This represents:

- **Complete fund drainage**: Single request can exhaust all available faucet funds
- **Service disruption**: Legitimate users cannot access the faucet after drainage
- **Economic impact**: In testnets, unlimited token minting breaks the test economy
- **Operational damage**: Requires manual intervention and faucet redeployment

The vulnerability affects any faucet deployment using the default configuration or any configuration where `maximum_amount` is not explicitly set.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is highly likely to be exploited because:

1. **Easy to discover**: The configuration files and default settings are public in the repository
2. **Trivial to exploit**: Requires only a single HTTP POST request with a large amount parameter
3. **No authentication bypass needed**: Works even through all checker validations
4. **Default configuration is vulnerable**: Both CLI and server defaults set `maximum_amount` to `None`
5. **No rate limiting helps**: Even with rate limiting, a single request is sufficient
6. **Immediate impact**: One successful request drains the faucet completely

An attacker only needs to:
```json
POST /fund
Content-Type: application/json

{
  "amount": 18446744073709551615,
  "address": "0x<attacker_address>"
}
```

## Recommendation

**Mandatory Fix**: Enforce a default maximum amount when `maximum_amount` is `None`.

Modify `MintFunder::get_amount()`:

```rust
fn get_amount(&self, amount: Option<u64>, did_bypass_checkers: bool) -> u64 {
    let maximum = self.txn_config.get_maximum_amount(did_bypass_checkers)
        .unwrap_or(self.amount_to_fund); // Use amount_to_fund as default maximum
    
    match amount {
        Some(requested) => std::cmp::min(requested, maximum),
        None => std::cmp::min(self.amount_to_fund, maximum),
    }
}
```

**Additional Recommendations:**
1. Make `maximum_amount` a required configuration field, not optional
2. Add startup validation to ensure `maximum_amount` is always set
3. Update all default configurations to include explicit `maximum_amount` values
4. Add monitoring/alerting for unusually large funding requests
5. Implement a secondary hard limit at the transaction building level as defense-in-depth

## Proof of Concept

**Setup:**
1. Deploy faucet with default configuration (no `maximum_amount` set)
2. Note that `amount_to_fund` is set to `100_000_000_000` OCTA

**Exploitation:**
```bash
# Attacker requests maximum u64 value
curl -X POST http://faucet-endpoint:8081/fund \
  -H "Content-Type: application/json" \
  -d '{
    "amount": 18446744073709551615,
    "address": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
  }'
```

**Expected Result Without Fix:**
- Transaction succeeds
- Attacker receives 18,446,744,073,709,551,615 OCTA (~18.4 quintillion APT)
- Faucet drained if using transfer mode, or unlimited minting in mint mode

**Expected Result With Fix:**
- Amount capped to `amount_to_fund` (100_000_000_000 OCTA)
- Faucet remains operational for other users

**Test Configuration Demonstrating Vulnerability:** [6](#0-5) 

This configuration has no `maximum_amount` field, making it vulnerable.

**Comparison with Secure Configuration:** [7](#0-6) 

This configuration explicitly sets limits and is protected.

## Notes

The vulnerability demonstrates a critical configuration security issue where optional safety parameters create exploitable attack vectors. The `TransferFunder` implementation is safer because it always enforces `amount_to_fund` as the maximum, but `MintFunder` fails when `maximum_amount` is unconfigured. This inconsistency between funder implementations compounds the risk, as developers may assume protection exists based on one implementation while deploying the vulnerable one.

### Citations

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

**File:** crates/aptos-faucet/core/src/server/run.rs (L285-294)
```rust
                transaction_submission_config: TransactionSubmissionConfig::new(
                    None,    // maximum_amount
                    None,    // maximum_amount_with_bypass
                    30,      // gas_unit_price_ttl_secs
                    None,    // gas_unit_price_override
                    500_000, // max_gas_amount
                    30,      // transaction_expiration_secs
                    35,      // wait_for_outstanding_txns_secs
                    false,   // wait_for_transactions
                ),
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

**File:** crates/aptos-faucet/core/src/funder/common.rs (L93-103)
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TransactionSubmissionConfig {
    /// Maximum amount of OCTA to give an account.
    maximum_amount: Option<u64>,

    /// With this it is possible to set a different maximum amount for requests that
    /// were allowed to skip the Checkers by a Bypasser. This can be helpful for CI,
    /// where we might need to mint a greater amount than is normally required in the
    /// standard case. If not given, maximum_amount is used whether the request
    /// bypassed the checks or not.
    maximum_amount_with_bypass: Option<u64>,
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_coin.move (L100-108)
```text
        assert!(
            exists<MintCapStore>(account_addr),
            error::not_found(ENO_CAPABILITIES),
        );

        let mint_cap = &borrow_global<MintCapStore>(account_addr).mint_cap;
        let coins_minted = coin::mint<AptosCoin>(amount, mint_cap);
        coin::deposit<AptosCoin>(dst_addr, coins_minted);
    }
```

**File:** crates/aptos-faucet/configs/testing_mint_funder_local.yaml (L1-19)
```yaml
---
server_config:
  api_path_base: ""
metrics_server_config:
  listen_port: 9105
bypasser_configs: []
checker_configs: []
funder_config:
  type: "MintFunder"
  node_url: "http://127.0.0.1:8080"
  chain_id: 4
  assets:
    apt:
      do_not_delegate: false
      key_file_path: "/tmp/mint.key"
      mint_account_address: "0xA550C18"
handler_config:
  use_helpful_errors: true
  return_rejections_early: false
```

**File:** crates/aptos-faucet/configs/testing_mint_funder_local_wait_for_txns.yaml (L14-16)
```yaml
  wait_for_transactions: true
  maximum_amount: 100
  maximum_amount_with_bypass: 10000
```
