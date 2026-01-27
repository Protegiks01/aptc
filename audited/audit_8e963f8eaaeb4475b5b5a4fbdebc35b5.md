# Audit Report

## Title
Missing Upper Bounds Validation in Local Testnet Faucet Configuration Allows Excessive Minting

## Summary
The `RunConfig::build_for_cli()` function used by `FaucetManager::new()` sets both `maximum_amount` and `maximum_amount_with_bypass` to `None`, allowing users to request arbitrary minting amounts up to `u64::MAX` (approximately 184 billion APT) per request without Rust-level validation. This bypasses the intended default of 100 billion OCTA and enables potential resource exhaustion and state bloat in shared local testnet environments.

## Finding Description
When a local testnet faucet is initialized via `FaucetManager::new()`, it calls `RunConfig::build_for_cli()` which configures a `MintFunderConfig` with `TransactionSubmissionConfig` parameters: [1](#0-0) 

Both `maximum_amount` and `maximum_amount_with_bypass` are explicitly set to `None`. The `amount_to_fund` is hardcoded to 100 billion OCTA, which serves only as a default when users don't specify an amount: [2](#0-1) 

When a funding request arrives, the `MintFunder::get_amount()` function determines the final amount to mint: [3](#0-2) 

When `maximum_amount` is `None` and a user provides an `amount`, the function returns that amount directly without any upper bound validation (line 546: `(Some(amount), None) => amount`). This allows requests with `amount` values up to `u64::MAX` (18,446,744,073,709,551,615 OCTA ≈ 184 billion APT).

**Attack Flow:**
1. Attacker sends POST request to `/fund` endpoint with `amount: u64::MAX`
2. `MintFunder::fund()` calls `get_amount(Some(u64::MAX), false)`
3. Function returns `u64::MAX` without validation
4. Faucet mints 184 billion APT to the specified account
5. Attacker can repeat for multiple accounts until Move-level supply limit is reached

While Move-level protections exist via `optional_aggregator::add()` checking against `MAX_U128` total supply: [4](#0-3) 

This only prevents total supply overflow, not excessive per-request minting amounts.

## Impact Explanation
**Severity: Low (Not Medium)**

While the security question suggests Medium severity, this issue does **not** meet the Aptos bug bounty criteria for Medium severity or higher because:

1. **Limited Scope**: Affects only local testnet faucets used for development, not production networks or public testnets
2. **No Real Economic Impact**: Local testnet coins have no value; this is development tooling
3. **No Consensus/Security Impact**: Does not affect consensus safety, Move VM security, state integrity, or any critical blockchain invariants
4. **Easily Mitigated**: Local testnets are ephemeral and can be instantly reset

The potential impacts are limited to:
- State bloat in local testnet storage (minor, easily resolved)
- Resource consumption during large mints (limited to developer's local machine)
- Disruption in shared team testing environments (inconvenience, not security)

This would qualify as **Low Severity** at best under "Non-critical implementation bugs" but realistically falls below bug bounty thresholds as it's a configuration choice in development tooling rather than a blockchain security vulnerability.

## Likelihood Explanation
**Likelihood: High (in affected environments)**

Exploitation is trivial:
- Requires only HTTP access to the local faucet API
- No authentication or authorization checks beyond configured Checkers/Bypassers
- Single API call with `amount` parameter
- Works by default in any local testnet setup using `aptos node run-local-testnet`

However, the **opportunity** is limited because:
- Local testnets typically run on `localhost` (127.0.0.1)
- Only accessible to the developer running the testnet
- Shared testnets are uncommon outside CI/CD environments

## Recommendation
Add explicit maximum amount validation to `RunConfig::build_for_cli()`:

```rust
pub fn build_for_cli(
    api_url: Url,
    listen_address: String,
    listen_port: u16,
    funder_key: FunderKeyEnum,
    do_not_delegate: bool,
    chain_id: Option<ChainId>,
) -> Self {
    // Define reasonable limits for local testnet
    const MAX_MINT_AMOUNT: u64 = 1_000_000_000_000; // 10,000 APT
    const MAX_MINT_AMOUNT_WITH_BYPASS: u64 = 10_000_000_000_000; // 100,000 APT
    
    // ... existing code ...
    
    transaction_submission_config: TransactionSubmissionConfig::new(
        Some(MAX_MINT_AMOUNT),              // maximum_amount
        Some(MAX_MINT_AMOUNT_WITH_BYPASS),  // maximum_amount_with_bypass
        30,
        None,
        500_000,
        30,
        35,
        false,
    ),
    
    // ... rest of config ...
}
```

This provides defense-in-depth while maintaining generous limits for testing scenarios.

## Proof of Concept

**Setup:**
```bash
# Start local testnet
aptos node run-local-testnet --with-faucet
```

**Exploitation:**
```bash
# Request excessive minting (18.4 billion APT)
curl -X POST http://127.0.0.1:8081/fund \
  -H "Content-Type: application/json" \
  -d '{
    "amount": 18446744073709551615,
    "address": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
  }'
```

**Expected Result:** Transaction succeeds, minting 184 billion APT to the address (until total supply limit is reached).

**Verification:**
```bash
aptos account list --account 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
# Shows balance of 18446744073709551615 OCTA
```

## Notes
This finding, while technically valid as a missing validation, does not constitute a security vulnerability per the Aptos bug bounty program criteria because it affects only local development tooling with no impact on production networks, consensus, or real economic value. The issue is better classified as a quality-of-life improvement for the local testnet developer experience rather than a security concern requiring immediate remediation.

### Citations

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

**File:** crates/aptos-faucet/core/src/server/run.rs (L304-304)
```rust
                amount_to_fund: 100_000_000_000,
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

**File:** aptos-move/framework/aptos-framework/sources/aggregator/optional_aggregator.move (L39-45)
```text
    fun add_integer(integer: &mut Integer, value: u128) {
        assert!(
            value <= (integer.limit - integer.value),
            error::out_of_range(EAGGREGATOR_OVERFLOW)
        );
        integer.value = integer.value + value;
    }
```
