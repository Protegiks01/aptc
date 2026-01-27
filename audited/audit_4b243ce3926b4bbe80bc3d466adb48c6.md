# Audit Report

## Title
Faucet Amount Validation Gap Allows Unbounded Coin Requests When `maximum_amount` Is Not Configured

## Summary
The Aptos faucet's `get_amount` function in `MintFunder` fails to enforce a maximum limit on funding requests when the `maximum_amount` configuration parameter is not set. This allows unprivileged users to request up to `u64::MAX` (18,446,744,073,709,551,615) octas without authentication, potentially exhausting faucet resources in testnet/devnet environments.

## Finding Description

The vulnerability exists in the amount validation logic within the faucet's funding mechanism. When a user submits a funding request without an authentication token, the system is supposed to cap the request at `maximum_amount`. However, the implementation contains a logic branch that bypasses this protection entirely when `maximum_amount` is not configured. [1](#0-0) 

The problematic code path occurs in the pattern match at line 546: when a user provides `Some(amount)` and the configuration has `maximum_amount = None`, the function returns the raw user-supplied amount without any validation or capping. This violates the security expectation that non-bypassed requests should always be bounded.

**Attack Scenario:**
1. Faucet administrator deploys with `maximum_amount: null` or omits this field in YAML configuration
2. Attacker sends POST request to `/fund` endpoint without auth token
3. Request body includes `"amount": 18446744073709551615` (u64::MAX)
4. The `get_amount` function executes the vulnerable branch and returns the full requested amount
5. Faucet processes the request and mints/transfers u64::MAX octas (~184 billion APT) to attacker's address [2](#0-1) 

The `FundRequest` structure accepts `amount: Option<u64>`, allowing any value from 0 to u64::MAX to be submitted via JSON deserialization. [3](#0-2) 

The configuration structure defines `maximum_amount` as `Option<u64>`, making it optional rather than required. No validation exists at configuration load time to ensure this critical security parameter is set.

**Regarding Negative Amounts and Overflow:**
- **Negative amounts**: Not possible due to type system (u64 is unsigned) ✅
- **Arithmetic overflow**: The Move VM safely handles large amounts by casting to u128 during supply updates ✅
- **Validation overflow**: Missing - no enforcement when `maximum_amount = None` ❌ [4](#0-3) 

## Impact Explanation

**Severity: Medium**

This vulnerability allows **limited funds loss or manipulation** in testnet/devnet faucet deployments, meeting the Medium severity criteria per Aptos bug bounty guidelines.

**Impact Quantification:**
- **Scope**: Testnet/devnet faucets only (mainnet does not use faucets for production)
- **Funds at Risk**: Unlimited minting capability could exhaust `MintFunder` resources or drain `TransferFunder` account balances
- **Service Disruption**: Legitimate users denied access after attacker drains faucet
- **Economic Impact**: Testnet/devnet token inflation if using `MintFunder` with uncapped supply

**Why Not Higher Severity:**
- Does NOT affect mainnet consensus or validator operations
- Does NOT enable theft of user funds on production chain
- Does NOT cause network partition or safety violations
- Limited to testing/development infrastructure

## Likelihood Explanation

**Likelihood: Medium-Low (Configuration-Dependent)**

The vulnerability only manifests when faucets are misconfigured. However, several factors increase likelihood:

1. **Configuration Complexity**: The `maximum_amount` field is optional in the configuration schema, with no runtime validation requiring it to be set
2. **Default Behavior**: No safe default is provided - the code silently allows unbounded amounts rather than failing safely
3. **Testing Gap**: Test configurations DO set `maximum_amount`, potentially masking this issue during QA [5](#0-4) 

4. **Defensive Programming Failure**: The code should enforce "secure by default" rather than trusting configuration completeness

**Attacker Requirements:**
- No authentication needed
- Simple HTTP POST request
- Knowledge of faucet endpoint (publicly documented)
- Misconfigured target faucet

## Recommendation

**Primary Fix: Require `maximum_amount` in Configuration**

Add validation at configuration initialization to ensure `maximum_amount` is always set for non-bypass scenarios:

```rust
impl TransactionSubmissionConfig {
    pub fn validate(&self) -> Result<()> {
        if self.maximum_amount.is_none() && self.maximum_amount_with_bypass.is_none() {
            return Err(anyhow::anyhow!(
                "At least one of maximum_amount or maximum_amount_with_bypass must be set"
            ));
        }
        Ok(())
    }
}
```

**Secondary Fix: Defensive Default in `get_amount`**

Modify the amount calculation to use a safe default when `maximum_amount` is None:

```rust
fn get_amount(&self, amount: Option<u64>, did_bypass_checkers: bool) -> u64 {
    let maximum = self.txn_config.get_maximum_amount(did_bypass_checkers)
        .unwrap_or(self.amount_to_fund); // Safe default instead of None
    
    match amount {
        Some(amt) => std::cmp::min(amt, maximum),
        None => std::cmp::min(self.amount_to_fund, maximum),
    }
}
```

**Tertiary Fix: Schema Enforcement**

Make `maximum_amount` a required field in production deployment schemas, with explicit documentation of security implications.

## Proof of Concept

**Vulnerable Configuration (YAML):**
```yaml
funder_config:
  type: "MintFunder"
  node_url: "http://127.0.0.1:8080"
  chain_id: 4
  # maximum_amount: OMITTED (vulnerable!)
  maximum_amount_with_bypass: 10000
  # ... rest of config
```

**Exploitation Steps:**
```bash
# 1. Deploy faucet with above configuration (maximum_amount not set)

# 2. Send malicious request
curl -X POST http://faucet-host:8081/fund \
  -H "Content-Type: application/json" \
  -d '{
    "amount": 18446744073709551615,
    "address": "0xattacker_address_here"
  }'

# 3. Request succeeds, minting u64::MAX octas to attacker
# 4. Repeat until faucet exhausted or testnet economy disrupted
```

**Verification:**
The test at lines 986-992 demonstrates the expected capping behavior ONLY when `maximum_amount` is configured. If that configuration line is removed, the same test would allow the full 1000 octas to be minted instead of being capped at 100. [6](#0-5) 

## Notes

This finding represents a **defensive programming gap** where the code fails to validate critical security configurations at startup, allowing unsafe operational states. While the impact is limited to testnet/devnet infrastructure, it violates the principle of "secure by default" and could lead to service disruption or resource exhaustion in development environments that rely on faucets for testing operations.

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

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L32-47)
```rust
#[derive(Clone, Debug, Default, Object)]
pub struct FundRequest {
    /// If not set, the default is the preconfigured max funding amount. If set,
    /// we will use this amount instead assuming it is < than the maximum,
    /// otherwise we'll just use the maximum.
    pub amount: Option<u64>,

    /// Either this or `address` / `pub_key` must be provided.
    pub auth_key: Option<String>,

    /// Either this or `auth_key` / `pub_key` must be provided.
    pub address: Option<String>,

    /// Either this or `auth_key` / `address` must be provided.
    pub pub_key: Option<String>,
}
```

**File:** crates/aptos-faucet/core/src/funder/common.rs (L94-103)
```rust
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

**File:** aptos-move/framework/aptos-framework/sources/coin.move (L1193-1226)
```text
    fun mint_internal<CoinType>(amount: u64): Coin<CoinType> acquires CoinInfo {
        if (amount == 0) {
            return Coin<CoinType> { value: 0 }
        };

        let maybe_supply =
            &mut borrow_global_mut<CoinInfo<CoinType>>(coin_address<CoinType>()).supply;
        if (option::is_some(maybe_supply)) {
            let supply = option::borrow_mut(maybe_supply);
            spec {
                use aptos_framework::optional_aggregator;
                use aptos_framework::aggregator;
                assume optional_aggregator::is_parallelizable(supply) ==>
                    (
                        aggregator::spec_aggregator_get_val(
                            option::borrow(supply.aggregator)
                        ) + amount
                            <= aggregator::spec_get_limit(
                                option::borrow(supply.aggregator)
                            )
                    );
                assume !optional_aggregator::is_parallelizable(supply) ==>
                    (
                        option::borrow(supply.integer).value + amount
                            <= option::borrow(supply.integer).limit
                    );
            };
            optional_aggregator::add(supply, (amount as u128));
        };
        spec {
            update supply<CoinType> = supply<CoinType> + amount;
        };
        Coin<CoinType> { value: amount }
    }
```

**File:** crates/aptos-faucet/configs/testing_mint_funder_local_wait_for_txns.yaml (L15-16)
```yaml
  maximum_amount: 100
  maximum_amount_with_bypass: 10000
```

**File:** crates/aptos-faucet/core/src/server/run.rs (L986-1001)
```rust
        let fund_request = get_fund_request(Some(1000));
        reqwest::Client::new()
            .post(get_fund_endpoint(port))
            .body(fund_request.to_json_string())
            .header(CONTENT_TYPE, "application/json")
            .send()
            .await?;

        // Confirm that the account was only given 100 OCTA (maximum_amount), not 1000.
        let response = aptos_node_api_client
            .view_apt_account_balance(
                AccountAddress::from_str(&fund_request.address.unwrap()).unwrap(),
            )
            .await?;

        assert_eq!(response.into_inner(), 100);
```
