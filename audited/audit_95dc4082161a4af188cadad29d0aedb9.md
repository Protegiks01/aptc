# Audit Report

## Title
Rosetta Client Vulnerable to Gas Price Manipulation via Malicious Server

## Summary
The Rosetta client in `crates/aptos-rosetta/src/client.rs` explicitly sets `gas_price_multiplier` to `None` but fails to validate the server's response, allowing a malicious Rosetta server to inject arbitrary gas price multipliers that cause users to overpay transaction fees by orders of magnitude.

## Finding Description

The vulnerability exists in the Rosetta client's transaction construction flow. When a user initiates a transaction through the Rosetta CLI or API, the client follows this sequence:

1. **Client sends preprocess request** with `gas_price_multiplier: None` [1](#0-0) 

2. **Server returns preprocess response** containing `MetadataOptions` which includes the `gas_price_multiplier` field [2](#0-1) 

3. **Client blindly trusts server response** and uses the returned options verbatim for the metadata request [3](#0-2) 

4. **Gas price calculation uses injected multiplier** - The server's `simulate_transaction` function multiplies the estimated gas price by the multiplier and divides by 100 [4](#0-3) 

5. **Transaction submitted with inflated gas** - The client signs and submits the transaction with the manipulated gas price, causing overpayment [5](#0-4) 

**Attack Scenario:**
A malicious Rosetta server can inject `gas_price_multiplier: 10000` (100x multiplier) in the preprocess response. If the estimated gas price is 100 octas/unit, this becomes 10,000 octas/unit. For a transaction consuming 1,000 gas units, the user pays 10,000,000 octas (0.1 APT) instead of 100,000 octas (0.001 APT) - a 100x overpayment.

The only validation performed is an overflow check [6](#0-5) , with no bounds checking on reasonable multiplier values. While the VM enforces a maximum gas price of 10,000,000,000 octas/unit [7](#0-6)  and minimum of 100 octas/unit in production [8](#0-7) , these bounds still allow for extreme overpayment scenarios.

## Impact Explanation

This vulnerability falls under **Medium Severity** per the Aptos bug bounty criteria ("Limited funds loss or manipulation"). The financial impact includes:

1. **Direct Financial Loss**: Users overpay transaction fees by factors of 10x-100,000x depending on the malicious multiplier injected
2. **Limited Scope**: Only affects users of the Rosetta CLI tool [9](#0-8)  and test infrastructure
3. **Bounded Loss**: Maximum loss is constrained by the user's account balance and the VM's maximum gas price validation [10](#0-9) 

The vulnerability violates the **Resource Limits** invariant - while operations respect absolute gas limits, they do not prevent unnecessary overpayment beyond what's required for transaction execution.

## Likelihood Explanation

**Likelihood: Medium**

The attack requires:
- User connecting their Rosetta client to a malicious server (not the default trusted setup)
- User initiating a transaction through the affected client
- No technical sophistication required from the attacker (simple JSON response manipulation)

Mitigating factors:
- Users typically run their own Rosetta servers or connect to trusted providers
- The Rosetta architecture assumes server trust by design
- Limited usage of the Rosetta CLI in production scenarios

However, the vulnerability is easily exploitable once the prerequisites are met, and there are no warnings or validation to alert users to suspicious gas price multipliers.

## Recommendation

Implement validation of the `gas_price_multiplier` returned by the server:

```rust
// In metadata_for_ops() after receiving preprocess_response
const MAX_REASONABLE_MULTIPLIER: u32 = 500; // 5x cap for safety margin

if let Some(multiplier) = preprocess_response.options.gas_price_multiplier {
    if multiplier > MAX_REASONABLE_MULTIPLIER {
        return Err(anyhow!(
            "Server returned suspicious gas_price_multiplier: {}. Maximum allowed: {}",
            multiplier,
            MAX_REASONABLE_MULTIPLIER
        ));
    }
}

// Or alternatively, reject any multiplier if we didn't request one
if preprocess_response.options.gas_price_multiplier.is_some() {
    return Err(anyhow!(
        "Server injected gas_price_multiplier but client did not request one"
    ));
}
```

Additionally, add logging to warn users when connecting to non-standard Rosetta endpoints, and document the trust assumptions in the CLI tool.

## Proof of Concept

Create a malicious Rosetta server that modifies the preprocess response:

```rust
// Malicious Rosetta server handler
async fn malicious_preprocess(request: ConstructionPreprocessRequest) 
    -> ConstructionPreprocessResponse 
{
    let mut response = legitimate_preprocess_handler(request).await;
    
    // Inject malicious 100x multiplier
    response.options.gas_price_multiplier = Some(10000);
    
    return response;
}

// Client usage (existing code vulnerable)
let client = RosettaClient::new("http://malicious-server:8082".parse()?);
// User initiates transfer - will overpay by 100x
client.transfer(
    &network_id,
    &private_key,
    receiver,
    1_000_000,  // 0.01 APT transfer
    expiry,
    None, None, None, None,
    native_coin()
).await?;  // Pays 100x more in gas than necessary
```

The transaction succeeds with the inflated gas price because it passes VM validation [11](#0-10) , but the user loses significant funds to overpayment.

## Notes

This vulnerability specifically affects the Rosetta API implementation and does not impact the core Aptos blockchain consensus, execution, or state management. The blockchain itself correctly processes transactions with any valid gas price within bounds. The issue is a client-side trust boundary violation in the Rosetta integration layer.

### Citations

**File:** crates/aptos-rosetta/src/client.rs (L673-684)
```rust
        // Should have a fee in the native coin
        let suggested_fee = metadata.suggested_fee.first().expect("Expected fee");
        let expected_fee = u64::from_str(&suggested_fee.value).expect("Expected u64 for fee");
        assert_eq!(
            suggested_fee.currency,
            native_coin(),
            "Fee should always be the native coin"
        );
        assert!(
            metadata.metadata.max_gas_amount.0 * metadata.metadata.gas_price_per_unit.0
                >= expected_fee
        );
```

**File:** crates/aptos-rosetta/src/client.rs (L752-752)
```rust
                    gas_price_multiplier: None,
```

**File:** crates/aptos-rosetta/src/client.rs (L769-774)
```rust
        self.metadata(&ConstructionMetadataRequest {
            network_identifier,
            options: preprocess_response.options,
        })
        .await
        .map(|response| (response, public_keys))
```

**File:** crates/aptos-rosetta/src/types/requests.rs (L221-225)
```rust
    /// Taking the estimated gas price, and multiplying it
    /// times this number divided by 100 e.g. 120 is 120%
    /// of the estimated price
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_price_multiplier: Option<u32>,
```

**File:** crates/aptos-rosetta/src/construction.rs (L341-351)
```rust
        if let Some(gas_multiplier) = options.gas_price_multiplier {
            let gas_multiplier = gas_multiplier as u64;
            if let Some(multiplied_price) = gas_price.checked_mul(gas_multiplier) {
                gas_price = multiplied_price.saturating_div(100)
            } else {
                return Err(ApiError::InvalidInput(Some(format!(
                    "Gas price multiplier {} causes overflow on the price",
                    gas_multiplier
                ))));
            }
        }
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L66-71)
```rust
        // The maximum gas unit price that a transaction can be submitted with.
        [
            max_price_per_gas_unit: FeePerGasUnit,
            "max_price_per_gas_unit",
            10_000_000_000
        ],
```

**File:** config/global-constants/src/lib.rs (L23-26)
```rust
#[cfg(any(test, feature = "testing"))]
pub const GAS_UNIT_PRICE: u64 = 0;
#[cfg(not(any(test, feature = "testing")))]
pub const GAS_UNIT_PRICE: u64 = 100;
```

**File:** crates/aptos-rosetta-cli/src/common.rs (L54-57)
```rust
    /// Retrieve a [`RosettaClient`]
    pub fn client(self) -> RosettaClient {
        RosettaClient::new(self.rosetta_api_url)
    }
```

**File:** aptos-move/aptos-vm/src/gas.rs (L174-208)
```rust
    // The submitted gas price is less than the minimum gas unit price set by the VM.
    // NB: MIN_PRICE_PER_GAS_UNIT may equal zero, but need not in the future. Hence why
    // we turn off the clippy warning.
    #[allow(clippy::absurd_extreme_comparisons)]
    let below_min_bound = txn_metadata.gas_unit_price() < txn_gas_params.min_price_per_gas_unit;
    if below_min_bound {
        speculative_warn!(
            log_context,
            format!(
                "[VM] Gas unit error; min {}, submitted {}",
                txn_gas_params.min_price_per_gas_unit,
                txn_metadata.gas_unit_price()
            ),
        );
        return Err(VMStatus::error(
            StatusCode::GAS_UNIT_PRICE_BELOW_MIN_BOUND,
            None,
        ));
    }

    // The submitted gas price is greater than the maximum gas unit price set by the VM.
    if txn_metadata.gas_unit_price() > txn_gas_params.max_price_per_gas_unit {
        speculative_warn!(
            log_context,
            format!(
                "[VM] Gas unit error; max {}, submitted {}",
                txn_gas_params.max_price_per_gas_unit,
                txn_metadata.gas_unit_price()
            ),
        );
        return Err(VMStatus::error(
            StatusCode::GAS_UNIT_PRICE_ABOVE_MAX_BOUND,
            None,
        ));
    }
```
