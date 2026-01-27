# Audit Report

## Title
View Function Response Size Not Bounded - Potential Memory Exhaustion via Unbounded JSON Deserialization

## Summary
The Aptos REST API's view function endpoint lacks an explicit response size limit, and when combined with inaccurate memory tracking during Move VM execution, could potentially allow resource exhaustion attacks through oversized view function responses.

## Finding Description

The `get_delegation_stake_balances()` function in the Rosetta implementation calls view functions that return `Vec<serde_json::Value>`. The investigation reveals multiple defensive gaps:

**1. No Response Size Limit in HTTP Layer**

The API enforces request size limits via `PostSizeLimit` middleware (default 8 MB), but there is no corresponding limit on response sizes: [1](#0-0) 

**2. Client-Side Unbounded Deserialization**

The REST client's `view()` method deserializes the entire response without size checks: [2](#0-1) [3](#0-2) 

The `response.json().await` call from reqwest will attempt to deserialize arbitrary-sized responses into memory.

**3. Flawed Memory Tracking During Execution**

The Move VM's memory tracking uses `abstract_packed_size` for vector and struct operations, which returns only a constant value (40) regardless of actual contents: [4](#0-3) [5](#0-4) [6](#0-5) 

**4. Gas Limit Exists But May Be Insufficient**

View functions have a gas limit (default 2,000,000 units) and memory quota (10,000,000 units): [7](#0-6) [8](#0-7) 

However, the execution completes and returns values without validating their serialized size.

## Impact Explanation

**Severity: Medium** - This represents a **resource exhaustion** vulnerability that could cause:

1. **Rosetta API Memory Exhaustion**: The Rosetta server attempting to deserialize gigabyte-sized responses would exhaust memory, causing crashes
2. **Validator Node API Slowdown**: Serializing and transmitting massive responses could slow down API services
3. **Client Application DoS**: Any application calling view functions could be DoS'd by malicious responses

However, this does NOT directly affect:
- Consensus safety or liveness
- Fund theft or manipulation  
- Core blockchain state integrity

Per the Aptos bug bounty criteria, this aligns with **Medium Severity** ($10k range) as it represents "state inconsistencies requiring intervention" and "API crashes/slowdowns."

## Likelihood Explanation

**Likelihood: Low-to-Medium**

**Attack Requirements:**
1. Attacker must deploy a malicious Move module containing a crafted view function
2. Victim must call this view function (either directly or through application logic)
3. The response must bypass gas/memory limits during execution but serialize to large size

**Mitigating Factors:**
- Gas limit (2M units) constrains computation during execution
- Memory quota (10M units) limits heap allocation during execution  
- Individual element creation still consumes tracked memory
- The specific `delegation_pool::get_stake` function returns only 3 u64 values (fixed size)

**Exploitation Difficulty:** The abstract_packed_size flaw creates a theoretical attack surface, but actual exploitation requires bypassing multiple layers of protection and careful crafting of nested data structures.

## Recommendation

Implement multiple layers of defense:

**1. Add Response Size Limit** - Add configuration for maximum view function response size:

```rust
pub struct ApiConfig {
    // ... existing fields ...
    /// Maximum size of view function response in bytes
    pub max_view_response_size: usize,
}

const DEFAULT_MAX_VIEW_RESPONSE_SIZE: usize = 10 * 1024 * 1024; // 10 MB
```

**2. Check Response Size Before Serialization** - In `api/src/view_function.rs`, validate serialized size before sending:

```rust
let move_vals = /* ... existing conversion ... */;

// Check serialized size before returning
let serialized = serde_json::to_vec(&move_vals)?;
if serialized.len() > context.node_config.api.max_view_response_size {
    return Err(BasicErrorWith404::bad_request_with_code(
        anyhow::anyhow!("View function response too large"),
        AptosErrorCode::InvalidInput,
        &ledger_info,
    ));
}
```

**3. Fix abstract_packed_size Calculation** - Update the visitor to properly recurse into vectors and structs for size calculation (longer-term fix).

**4. Add Response Size Limit in REST Client** - Add a configurable limit when deserializing responses to prevent OOM on client side.

## Proof of Concept

Due to the complexity and defensive layers, a full working PoC would require:

```move
module attacker::memory_bomb {
    use std::vector;
    
    struct LargeStruct has copy, drop {
        data: vector<vector<u8>>
    }
    
    #[view]
    public fun create_large_response(): vector<LargeStruct> {
        let result = vector::empty();
        let i = 0;
        // Create nested structure that may bypass memory tracking
        while (i < 1000) {
            let inner_vec = vector::empty();
            let j = 0;
            while (j < 1000) {
                vector::push_back(&mut inner_vec, vector::empty<u8>());
                j = j + 1;
            };
            vector::push_back(&mut result, LargeStruct { data: inner_vec });
            i = i + 1;
        };
        result
    }
}
```

However, whether this would actually bypass all protections requires empirical testing on a running node.

## Notes

The investigation specifically examined `get_delegation_stake_balances()` which calls the framework's `delegation_pool::get_stake` function. This particular function returns only `(u64, u64, u64)` - a fixed, small size that poses no risk. [9](#0-8) 

The broader vulnerability concern applies to arbitrary view functions that could be deployed by attackers, not the specific delegation pool function mentioned in the security question.

### Citations

**File:** api/src/check_size.rs (L13-59)
```rust
pub struct PostSizeLimit {
    max_size: u64,
}

impl PostSizeLimit {
    pub fn new(max_size: u64) -> Self {
        Self { max_size }
    }
}

impl<E: Endpoint> Middleware<E> for PostSizeLimit {
    type Output = PostSizeLimitEndpoint<E>;

    fn transform(&self, ep: E) -> Self::Output {
        PostSizeLimitEndpoint {
            inner: ep,
            max_size: self.max_size,
        }
    }
}

/// Endpoint for PostSizeLimit middleware.
pub struct PostSizeLimitEndpoint<E> {
    inner: E,
    max_size: u64,
}

impl<E: Endpoint> Endpoint for PostSizeLimitEndpoint<E> {
    type Output = E::Output;

    async fn call(&self, req: Request) -> Result<Self::Output> {
        if req.method() != Method::POST {
            return self.inner.call(req).await;
        }

        let content_length = req
            .headers()
            .typed_get::<headers::ContentLength>()
            .ok_or(SizedLimitError::MissingContentLength)?;

        if content_length.0 > self.max_size {
            return Err(SizedLimitError::PayloadTooLarge.into());
        }

        self.inner.call(req).await
    }
}
```

**File:** crates/aptos-rest-client/src/lib.rs (L416-436)
```rust
    pub async fn view(
        &self,
        request: &ViewRequest,
        version: Option<u64>,
    ) -> AptosResult<Response<Vec<serde_json::Value>>> {
        let request = serde_json::to_string(request)?;
        let mut url = self.build_path("view")?;
        if let Some(version) = version {
            url.set_query(Some(format!("ledger_version={}", version).as_str()));
        }

        let response = self
            .inner
            .post(url)
            .header(CONTENT_TYPE, JSON)
            .body(request)
            .send()
            .await?;

        self.json(response).await
    }
```

**File:** crates/aptos-rest-client/src/lib.rs (L1658-1665)
```rust
    async fn json<T: serde::de::DeserializeOwned>(
        &self,
        response: reqwest::Response,
    ) -> AptosResult<Response<T>> {
        let (response, state) = self.check_response(response).await?;
        let json = response.json().await.map_err(anyhow::Error::from)?;
        Ok(Response::new(json, state))
    }
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/misc.rs (L47-49)
```rust
        [struct_: AbstractValueSize, "struct", 40],
        [closure: AbstractValueSize, { RELEASE_V1_33.. => "closure" }, 40],
        [vector: AbstractValueSize, "vector", 40],
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/misc.rs (L864-868)
```rust
            fn visit_vec(&mut self, depth: u64, _len: usize) -> PartialVMResult<bool> {
                self.check_depth(depth)?;
                self.res = Some(self.params.vector);
                Ok(false)
            }
```

**File:** aptos-move/aptos-memory-usage-tracker/src/lib.rs (L608-617)
```rust
    fn charge_vec_push_back(&mut self, val: impl ValueView) -> PartialVMResult<()> {
        self.use_heap_memory(
            self.vm_gas_params()
                .misc
                .abs_val
                .abstract_packed_size(&val)?,
        )?;

        self.base.charge_vec_push_back(val)
    }
```

**File:** config/src/config/api_config.rs (L102-102)
```rust
const DEFAULT_MAX_VIEW_GAS: u64 = 2_000_000; // We keep this value the same as the max number of gas allowed for one single transaction defined in aptos-gas.
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2628-2670)
```rust
    pub fn execute_view_function(
        state_view: &impl StateView,
        module_id: ModuleId,
        func_name: Identifier,
        type_args: Vec<TypeTag>,
        arguments: Vec<Vec<u8>>,
        max_gas_amount: u64,
    ) -> ViewFunctionOutput {
        let env = AptosEnvironment::new(state_view);
        let vm = AptosVM::new(&env);

        let log_context = AdapterLogSchema::new(state_view.id(), 0);

        let vm_gas_params = match vm.gas_params(&log_context) {
            Ok(gas_params) => gas_params.vm.clone(),
            Err(err) => {
                return ViewFunctionOutput::new_error_message(
                    format!("{}", err),
                    Some(err.status_code()),
                    0,
                )
            },
        };
        let storage_gas_params = match vm.storage_gas_params(&log_context) {
            Ok(gas_params) => gas_params.clone(),
            Err(err) => {
                return ViewFunctionOutput::new_error_message(
                    format!("{}", err),
                    Some(err.status_code()),
                    0,
                )
            },
        };

        let mut gas_meter = make_prod_gas_meter(
            vm.gas_feature_version(),
            vm_gas_params,
            storage_gas_params,
            /* is_approved_gov_script */ false,
            max_gas_amount.into(),
            &NoopBlockSynchronizationKillSwitch {},
        );

```

**File:** crates/aptos-rosetta/src/types/misc.rs (L383-435)
```rust
/// Retrieve delegation stake balances for a given owner, pool, and version
pub async fn get_delegation_stake_balances(
    rest_client: &aptos_rest_client::Client,
    account_identifier: &AccountIdentifier,
    owner_address: AccountAddress,
    pool_address: AccountAddress,
    version: u64,
) -> ApiResult<Option<BalanceResult>> {
    // get requested_balance
    let balances_response = rest_client
        .view(
            &ViewRequest {
                function: DELEGATION_POOL_GET_STAKE_FUNCTION.clone(),
                type_arguments: vec![],
                arguments: vec![
                    serde_json::Value::String(pool_address.to_string()),
                    serde_json::Value::String(owner_address.to_string()),
                ],
            },
            Some(version),
        )
        .await?;

    let requested_balance =
        parse_requested_balance(account_identifier, balances_response.into_inner());

    // get lockup_secs
    let lockup_secs_response = rest_client
        .view(
            &ViewRequest {
                function: STAKE_GET_LOCKUP_SECS_FUNCTION.clone(),
                type_arguments: vec![],
                arguments: vec![serde_json::Value::String(pool_address.to_string())],
            },
            Some(version),
        )
        .await?;
    let lockup_expiration = parse_lockup_expiration(lockup_secs_response.into_inner());

    if let Some(balance) = requested_balance {
        Ok(Some(BalanceResult {
            balance: Some(Amount {
                value: balance,
                currency: native_coin(),
            }),
            lockup_expiration,
        }))
    } else {
        Err(ApiError::InternalError(Some(
            "Unable to construct BalanceResult instance".to_string(),
        )))
    }
}
```
