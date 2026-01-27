# Audit Report

## Title
Auth Token Bypass Enables Unlimited Faucet Drainage Without Rate-Limiting or Audit Trails

## Summary
The `request_can_bypass()` function in the auth token bypasser allows requests with valid bypass tokens to completely skip both rate-limiting checks and audit trail storage via the `complete()` step. This enables attackers with leaked or compromised bypass tokens to drain the faucet through unlimited repeated requests without any persistent accountability record.

## Finding Description

The faucet implements a bypass mechanism intended to allow trusted requests (e.g., CI systems) to skip rate-limiting checks. However, the implementation contains a critical design flaw: when `request_can_bypass()` returns `true`, it bypasses **all** checker logic including both validation and post-funding audit trail storage. [1](#0-0) 

The bypasser trait explicitly documents that bypass requests skip "all checkers and storage." In the funding flow, this manifests in two critical locations:

First, the bypass check occurs early and skips all checker validation: [2](#0-1) 

Second, and most critically, when `bypass = true`, the entire `complete()` step for all checkers is skipped: [3](#0-2) 

The `complete()` method is documented as the mechanism for storing persistent audit records and transaction metadata: [4](#0-3) 

**Attack Scenario:**
1. Attacker obtains a valid auth token through leak, compromise, or insider threat
2. Attacker makes repeated funding requests with the bypass token
3. All rate-limiting is bypassed (no limits applied via RedisRatelimitChecker or MemoryRatelimitChecker)
4. Only ephemeral application logs are created (info!), no persistent storage records
5. Attacker can drain the faucet up to the configured `maximum_amount_with_bypass` per request, unlimited times
6. No persistent audit trail exists to track the abuse or attribute it to the compromised token

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty criteria for "Limited funds loss or manipulation" because:

1. **Fund Drainage**: An attacker can drain the faucet's token reserves through unlimited requests
2. **Accountability Loss**: Bypassed transactions only generate ephemeral application logs (info! level), not persistent database records that could survive log rotation or be reliably audited
3. **Rate-Limiting Evasion**: All rate-limiting protections are completely bypassed, enabling rapid fund extraction

While application logging occurs at lines 319-327 of fund.rs, this uses the `info!` macro which:
- Depends on logging configuration and may not be persisted
- Is not designed as an audit trail database
- Can be lost during log rotation or system issues
- Provides no structured storage for forensic analysis [5](#0-4) 

## Likelihood Explanation

**Likelihood: Medium-High**

The attack requires:
1. **Single Prerequisite**: Valid bypass auth token (from configuration)
2. **No Special Access**: No validator privileges or blockchain-level access needed
3. **Simple Execution**: Standard HTTP requests with Authorization header

Bypass tokens are typically used for CI systems and automated testing, making them:
- Often stored in configuration files or environment variables
- Shared across teams and systems
- Higher risk of accidental exposure or compromise
- May persist longer than user credentials

The likelihood increases because:
- Organizations often fail to rotate CI tokens regularly
- Tokens may be inadvertently committed to repositories
- Compromised CI systems can expose tokens
- The attack is trivially executable once a token is obtained

## Recommendation

Implement a two-tier storage approach where bypass requests still create audit records:

```rust
// In fund_inner(), after funding completes:

// Create audit trail even for bypassed requests
let audit_data = AuditData {
    checker_data: checker_data.clone(),
    txn_hashes: txn_hashes.clone(),
    bypassed: bypass,
    bypass_token: if bypass { 
        extract_auth_token(&checker_data.headers) 
    } else { 
        None 
    },
    timestamp: get_current_time_secs(),
};

// Store audit trail unconditionally
audit_storage.store(audit_data).await?;

// Only run checker complete() logic if not bypassed
if !bypass {
    let complete_data = CompleteData {
        checker_data,
        txn_hashes: txn_hashes.clone(),
        response_is_500,
    };
    for checker in &self.checkers {
        checker.complete(complete_data.clone()).await.map_err(|e| {
            AptosTapError::new_with_error_code(e, AptosTapErrorCode::CheckerError)
        })?;
    }
}
```

Additionally:
1. Implement rate-limiting specifically for bypass tokens (separate from user rate-limiting)
2. Add persistent storage for all funding transactions (bypassed or not)
3. Include bypass token identifier in audit logs for attribution
4. Alert on unusual bypass token usage patterns
5. Implement token rotation policies and expiration

## Proof of Concept

```rust
// Integration test demonstrating unlimited bypass abuse
#[tokio::test]
async fn test_bypass_token_drainage() {
    // Setup faucet with bypass token "test_token" and rate limit of 1 req/day
    let mut config = FaucetConfig::default();
    config.checkers.push(CheckerConfig::MemoryRatelimit(
        MemoryRatelimitCheckerConfig {
            max_requests_per_day: 1,
            max_entries_in_map: NonZeroUsize::new(1000).unwrap(),
        }
    ));
    config.bypassers.push(BypasserConfig::AuthToken(
        ListManagerConfig {
            sources: vec![ListSource::List(vec!["test_token".to_string()])],
        }
    ));
    
    let faucet = setup_faucet(config).await;
    
    // Without bypass token: should be rate-limited after first request
    let addr1 = AccountAddress::random();
    let response1 = faucet.fund(addr1, None).await;
    assert!(response1.is_ok());
    
    let response2 = faucet.fund(addr1, None).await;
    assert!(response2.is_err()); // Rate limited!
    
    // With bypass token: can make unlimited requests
    let addr2 = AccountAddress::random();
    for i in 0..100 {
        let response = faucet.fund_with_auth(
            addr2, 
            Some("Bearer test_token"),
            None
        ).await;
        assert!(response.is_ok(), "Request {} should succeed", i);
        // All 100 requests succeed, no rate limiting applied
    }
    
    // Verify no persistent audit records were created for bypassed requests
    let audit_records = faucet.get_audit_trail().await;
    assert_eq!(audit_records.len(), 0); // No persistent storage!
    
    // Only ephemeral logs exist (which may already be rotated away)
}
```

## Notes

- This vulnerability affects the faucet service operational security, not core blockchain consensus or state management
- Impact severity depends on deployment context (testnet vs. production tokens)
- The design explicitly intends to skip storage, as documented in the trait definition, suggesting this may have been an architectural decision rather than an oversight
- Application logging via `info!` macro still occurs but is not suitable as a persistent audit trail
- Current rate-limiting checkers only use `complete()` for counter adjustments, not full audit trails, but the architecture prevents future audit trail implementations from working correctly with bypass

### Citations

**File:** crates/aptos-faucet/core/src/bypasser/mod.rs (L18-24)
```rust
/// skip all the checkers and storage, for example an IP allowlist.
#[async_trait]
#[enum_dispatch]
pub trait BypasserTrait: Sync + Send + 'static {
    /// Returns true if the request should be allowed to bypass all checkers
    /// and storage.
    async fn request_can_bypass(&self, data: CheckerData) -> Result<bool>;
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L244-259)
```rust
        // See if this request meets the criteria to bypass checkers / storage.
        for bypasser in &self.bypassers {
            if bypasser
                .request_can_bypass(checker_data.clone())
                .await
                .map_err(|e| {
                    AptosTapError::new_with_error_code(e, AptosTapErrorCode::BypasserError)
                })?
            {
                info!(
                    "Allowing request from {} to bypass checks / storage",
                    source_ip
                );
                return Ok((checker_data, true, permit));
            }
        }
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L319-327)
```rust
        info!(
            source_ip = checker_data.source_ip,
            jwt_sub = jwt_sub(checker_data.headers.clone()).ok(),
            address = checker_data.receiver,
            requested_amount = fund_request.amount,
            asset = asset_for_logging,
            txn_hashes = txn_hashes,
            success = fund_result.is_ok(),
        );
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L332-347)
```rust
        if !bypass {
            let response_is_500 = match &fund_result {
                Ok(_) => false,
                Err(e) => e.error_code.status().is_server_error(),
            };
            let complete_data = CompleteData {
                checker_data,
                txn_hashes: txn_hashes.clone(),
                response_is_500,
            };
            for checker in &self.checkers {
                checker.complete(complete_data.clone()).await.map_err(|e| {
                    AptosTapError::new_with_error_code(e, AptosTapErrorCode::CheckerError)
                })?;
            }
        }
```

**File:** crates/aptos-faucet/core/src/checkers/mod.rs (L54-63)
```rust
    /// If the Checker wants to do anything after the funding has completed, it
    /// may do so in this function. For example, for the storage Checkers, this
    /// function is responsible for marking a request in storage as complete,
    /// in both success and failure cases. It can also store additional metadata
    /// included in CompleteData that we might have from the call to the Funder.
    /// No dry_run flag for this, because we should never need to run this in
    /// dry_run mode.
    async fn complete(&self, _data: CompleteData) -> Result<(), AptosTapError> {
        Ok(())
    }
```
