# Audit Report

## Title
Delegated Account Initialization Bypasses Configured Maximum Amount Limits

## Summary
The `MintFunder::use_delegated_account()` function funds newly created delegated accounts with a hardcoded 100,000,000,000 OCTA amount, completely bypassing the operator's configured `maximum_amount` and `maximum_amount_with_bypass` security limits. [1](#0-0) 

## Finding Description

During faucet initialization, when `do_not_delegate` is set to `false`, the system creates a delegated account to handle mint operations. The vulnerability occurs in the initial funding of this delegated account.

**Normal Funding Flow (Respects Limits):**
When users request funds via the `/fund` endpoint, the amount is validated through `get_amount()`, which enforces `maximum_amount` limits: [2](#0-1) 

This ensures requested amounts are capped to the configured maximum (e.g., 100 OCTA in test configurations).

**Delegated Account Flow (Bypasses Limits):**
However, `use_delegated_account()` directly calls `process()` with a hardcoded 100 billion OCTA amount without any validation: [1](#0-0) 

**Concrete Example from Test Configuration:** [3](#0-2) 

In this configuration:
- Configured `maximum_amount`: 100 OCTA
- Configured `maximum_amount_with_bypass`: 10,000 OCTA  
- **Actual delegated account funding**: 100,000,000,000 OCTA (1 million times the limit)

The delegated account is created during initialization: [4](#0-3) 

## Impact Explanation

This is a **Medium Severity** issue per Aptos bug bounty criteria for the following reasons:

1. **Limited Funds Loss or Manipulation**: If the delegated account's private key is compromised (via server breach, memory dump, or other attack vectors), an attacker can drain the full 100 billion OCTA instead of the operator's intended maximum limit.

2. **Security Policy Violation**: Operators configure `maximum_amount` specifically to limit risk exposure. The hardcoded initialization amount completely bypasses this security control, creating a 100,000,000,000 OCTA "honey pot" that violates the operator's risk management policy.

3. **Defense-in-Depth Failure**: Even if the delegated account requires initial funding for gas fees, it only needs approximately 400-1000 gas units for the delegation transactions, which translates to at most a few thousand OCTA—not 100 billion.

## Likelihood Explanation

**Occurrence**: This issue occurs automatically during every faucet initialization where `do_not_delegate: false` is configured. It is not conditional—it happens 100% of the time.

**Exploitability**: While the overfunding happens automatically, actual exploitation requires:
- Compromise of the faucet server or delegated account's private key
- Knowledge that the delegated account contains significantly more funds than the configured limits suggest

The likelihood increases when:
- Operators believe they've limited exposure via `maximum_amount` configuration
- Attackers specifically target faucet servers knowing about this high-value account
- The delegated account persists across faucet restarts

## Recommendation

The initial funding amount should respect the operator's configured security limits. Here's the recommended fix:

```rust
pub async fn use_delegated_account(&self, asset_name: &str) -> Result<LocalAccount> {
    let client = self.get_api_client();
    let delegated_account = LocalAccount::generate(&mut rand::rngs::OsRng);
    
    // Calculate a reasonable initial funding amount for gas fees
    // Using get_amount with a small requested amount ensures we respect
    // maximum_amount_with_bypass if configured
    let initial_funding = self.get_amount(Some(10_000_000), true).min(10_000_000);
    
    self.process(
        &client,
        initial_funding,  // Use validated amount instead of hardcoded value
        delegated_account
            .authentication_key()
            .clone()
            .account_address(),
        false,
        true,
        asset_name,
    )
    .await
    .context("Failed to create new account")?;
    
    // ... rest of function unchanged
}
```

Alternatively, add explicit validation:

```rust
// Ensure initial funding respects configured limits
let initial_funding = match self.txn_config.get_maximum_amount(true) {
    Some(max) => 100_000_000_000.min(max),
    None => 100_000_000_000,
};
```

## Proof of Concept

**Setup**: Deploy a faucet with the test configuration: [5](#0-4) 

**Steps to Reproduce**:

1. Start the faucet service with the configuration above
2. During initialization, `build_funder()` is called
3. For the `apt` asset with `do_not_delegate: false`, `use_delegated_account()` executes
4. Query the delegated account balance on-chain

**Expected Result**: Account funded with ≤10,000 OCTA (respecting `maximum_amount_with_bypass`)

**Actual Result**: Account funded with 100,000,000,000 OCTA (10,000× the configured limit)

**Verification Code**:
```rust
#[tokio::test]
async fn test_delegated_account_overfunding() {
    // Start faucet with maximum_amount: 100, maximum_amount_with_bypass: 10000
    let config = include_str!("../configs/testing_mint_funder_local_wait_for_txns.yaml");
    let funder = MintFunderConfig::from_yaml(config).build_funder().await.unwrap();
    
    // Get the delegated account address
    let delegated_addr = funder.get_asset_account("apt").unwrap().read().await.address();
    
    // Query balance
    let client = funder.get_api_client();
    let balance = client.get_account_bcs(delegated_addr).await.unwrap();
    
    // Balance should be ≤ 10,000 but is actually 100,000,000,000
    assert!(balance.coin > 10_000, "Account overfunded: {} > 10,000", balance.coin);
    assert_eq!(balance.coin, 100_000_000_000, "Hardcoded amount used instead of configured limit");
}
```

## Notes

This vulnerability specifically affects the Aptos Faucet service used in testnet environments. While testnet tokens have no direct monetary value, the security configuration bypass represents a significant defense-in-depth failure that increases risk exposure beyond operator intent.

### Citations

**File:** crates/aptos-faucet/core/src/funder/mint.rs (L171-178)
```rust
            if !asset_config.do_not_delegate {
                // Delegate permissions to a new account
                let delegated_account = minter
                    .use_delegated_account(&asset_name)
                    .await
                    .with_context(|| {
                        format!("Failed to delegate account for asset '{}'", asset_name)
                    })?;
```

**File:** crates/aptos-faucet/core/src/funder/mint.rs (L287-299)
```rust
        self.process(
            &client,
            100_000_000_000,
            delegated_account
                .authentication_key()
                .clone()
                .account_address(),
            false,
            true,
            asset_name,
        )
        .await
        .context("Failed to create new account")?;
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

**File:** crates/aptos-faucet/configs/testing_mint_funder_local_wait_for_txns.yaml (L1-24)
```yaml
---
server_config:
  api_path_base: ""
metrics_server_config:
  listen_port: 9105
bypasser_configs:
  - type: "AuthToken"
    file: "/tmp/auth_tokens.txt"
checker_configs: []
funder_config:
  type: "MintFunder"
  node_url: "http://127.0.0.1:8080"
  chain_id: 4
  wait_for_transactions: true
  maximum_amount: 100
  maximum_amount_with_bypass: 10000
  assets:
    apt:
      do_not_delegate: false
      key_file_path: "/tmp/mint.key"
      mint_account_address: "0xA550C18"
handler_config:
  use_helpful_errors: true
  return_rejections_early: false
```
