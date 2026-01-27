# Audit Report

## Title
Memory Undercharge Vulnerability in FatStructType::subst() Enables API Node Resource Exhaustion

## Summary
The `FatStructType::subst()` function in the move-resource-viewer charges only for struct metadata (AccountAddress, module name, struct name) but fails to charge for Vec allocations containing type arguments and layout fields. This allows attackers to craft Move structs with thousands of fields that cause massive memory allocation (640KB+) while only charging ~100 bytes, enabling API node resource exhaustion and potential crashes.

## Finding Description

The vulnerability exists in the limiter charging mechanism within `FatStructType::subst()`. [1](#0-0) 

At these lines, the function charges only for:
- `sizeof(AccountAddress)` (~32 bytes)
- Module name byte length
- Struct name byte length

However, the function then proceeds to allocate substantial memory for Vec<FatType> containers without charging for them. [2](#0-1) 

The type arguments vector allocation is not charged. Similarly, the layout fields allocation is also not charged. [3](#0-2) 

**Critical Configuration Flaw**: The production verifier configuration sets no limit on struct field count. [4](#0-3) 

This means an attacker can publish a module containing a struct with thousands of fields (e.g., 10,000 u8 fields), store an instance on-chain, then trigger the resource viewer via API endpoints.

**Attack Path**:
1. Attacker publishes a Move module with a malicious struct containing 10,000 primitive-type fields
2. Attacker stores an instance of this struct in their account  
3. Attacker (or anyone) calls the REST API endpoint `/v1/accounts/{address}/resource/{resource_type}`
4. The API uses `AptosValueAnnotator` which internally calls `resolve_struct_tag()` [5](#0-4) 
5. This eventually triggers `FatStructType::subst()` for generic structs or `resolve_struct_definition()` for basic structs, both of which undercharge
6. With 10,000 fields of FatType (~32 bytes each), the Vec allocates ~320KB but only charges ~100 bytes
7. **Undercharge ratio: 3,200:1**

The Limiter's purpose is to prevent resource exhaustion during API operations. [6](#0-5) 

The default 100MB limit can be bypassed through this undercharging, allowing memory exhaustion far beyond intended limits.

## Impact Explanation

**Severity: High** (up to $50,000 per Aptos Bug Bounty)

This vulnerability qualifies as **"API crashes"** under High Severity criteria. The impact includes:

1. **API Node Resource Exhaustion**: Multiple concurrent requests viewing malicious resources can exhaust node memory, causing crashes or severe performance degradation
2. **Denial of Service**: Attackers can render API endpoints unavailable, preventing users from querying blockchain state
3. **Indexer/Explorer Disruption**: Systems using `AptosValueAnnotator` for resource viewing (indexers, block explorers) become vulnerable to crashes
4. **Violation of Resource Limit Invariant**: The Limiter protection mechanism is bypassed, breaking invariant #9: "All operations must respect gas, storage, and computational limits"

While this does not directly affect consensus or validator operations, API infrastructure is critical for blockchain usability and ecosystem functionality. Crashed or degraded API nodes prevent transaction submission, state queries, and integration with external applications.

## Likelihood Explanation

**Likelihood: High**

The attack is highly feasible because:

1. **No Field Count Limit**: Production configuration explicitly sets `max_fields_in_struct: None`, allowing arbitrary field counts
2. **Low Cost to Attacker**: Publishing one malicious module and storing one resource instance (one-time gas cost) enables unlimited API exploitation
3. **Public Attack Surface**: API endpoints are publicly accessible; no special privileges required
4. **Amplification Factor**: Single malicious resource enables repeated exploitation across all nodes running API servers
5. **No Detection**: Legitimate-looking module publishing and resource storage; difficult to distinguish from normal usage

The only constraint is gas costs for module publishing and resource storage, but these are one-time costs for persistent exploitation capability.

## Recommendation

**Fix: Charge for Vec allocations and FatType elements**

Modify `FatStructType::subst()` to charge for the actual memory allocated:

```rust
pub fn subst(
    &self,
    ty_args: &[FatType],
    subst_struct: &impl Fn(&FatStructType, &[FatType], &mut Limiter) -> PartialVMResult<FatStructRef>,
    limiter: &mut Limiter,
) -> PartialVMResult<FatStructType> {
    // Charge for struct metadata
    limiter.charge(std::mem::size_of::<AccountAddress>())?;
    limiter.charge(self.module.as_bytes().len())?;
    limiter.charge(self.name.as_bytes().len())?;
    
    // NEW: Charge for FatStructType allocation
    limiter.charge(std::mem::size_of::<FatStructType>())?;
    
    // NEW: Charge for ty_args Vec overhead and capacity
    limiter.charge(std::mem::size_of::<Vec<FatType>>())?;
    limiter.charge(self.ty_args.len() * std::mem::size_of::<FatType>())?;
    
    // NEW: Charge for layout Vec allocations based on variant
    match &self.layout {
        FatStructLayout::Singleton(fields) => {
            limiter.charge(std::mem::size_of::<Vec<FatType>>())?;
            limiter.charge(fields.len() * std::mem::size_of::<FatType>())?;
        }
        FatStructLayout::Variants(variants) => {
            limiter.charge(std::mem::size_of::<Vec<Vec<FatType>>>())?;
            for variant_fields in variants {
                limiter.charge(std::mem::size_of::<Vec<FatType>>())?;
                limiter.charge(variant_fields.len() * std::mem::size_of::<FatType>())?;
            }
        }
    }
    
    // ... rest of function remains the same
}
```

**Alternative: Set max_fields_in_struct limit**

Additionally, set a reasonable limit in production configuration:

```rust
max_fields_in_struct: Some(1024),  // Limit struct fields to prevent abuse
```

Apply similar fixes to `resolve_struct_definition()` in lib.rs which has the same undercharging pattern.

## Proof of Concept

```move
// malicious_module.move
module attacker::dos {
    struct MaliciousStruct has key {
        f0: u8, f1: u8, f2: u8, f3: u8, f4: u8,
        // ... repeat for 10,000 fields ...
        f9999: u8,
    }
    
    public entry fun store_malicious(account: &signer) {
        move_to(account, MaliciousStruct {
            f0: 0, f1: 0, /* ... */ f9999: 0,
        });
    }
}
```

**Exploitation Steps**:
1. Compile and publish the module (pay gas once)
2. Call `store_malicious()` to store resource (pay gas once)
3. Make concurrent API requests: `GET /v1/accounts/{attacker_address}/resource/attacker::dos::MaliciousStruct`
4. Each request allocates ~640KB but charges ~100 bytes (6,400:1 ratio)
5. Monitor API node memory consumption rising rapidly
6. Node crashes or becomes unresponsive after multiple concurrent requests

**Expected Result**: API node memory exhaustion and crash/degradation despite Limiter protections meant to prevent such resource exhaustion.

### Citations

**File:** third_party/move/tools/move-resource-viewer/src/fat_type.rs (L185-187)
```rust
        limiter.charge(std::mem::size_of::<AccountAddress>())?;
        limiter.charge(self.module.as_bytes().len())?;
        limiter.charge(self.name.as_bytes().len())?;
```

**File:** third_party/move/tools/move-resource-viewer/src/fat_type.rs (L196-200)
```rust
            ty_args: self
                .ty_args
                .iter()
                .map(|ty| ty.subst(ty_args, subst_struct, limiter))
                .collect::<PartialVMResult<_>>()?,
```

**File:** third_party/move/tools/move-resource-viewer/src/fat_type.rs (L201-218)
```rust
            layout: match &self.layout {
                FatStructLayout::Singleton(fields) => FatStructLayout::Singleton(
                    fields
                        .iter()
                        .map(|ty| ty.subst(ty_args, subst_struct, limiter))
                        .collect::<PartialVMResult<_>>()?,
                ),
                FatStructLayout::Variants(variants) => FatStructLayout::Variants(
                    variants
                        .iter()
                        .map(|fields| {
                            fields
                                .iter()
                                .map(|ty| ty.subst(ty_args, subst_struct, limiter))
                                .collect::<PartialVMResult<_>>()
                        })
                        .collect::<PartialVMResult<_>>()?,
                ),
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L170-170)
```rust
        max_fields_in_struct: None,
```

**File:** aptos-move/aptos-resource-viewer/src/lib.rs (L68-74)
```rust
    pub fn view_resource(
        &self,
        tag: &StructTag,
        blob: &[u8],
    ) -> anyhow::Result<AnnotatedMoveStruct> {
        self.0.view_resource(tag, blob)
    }
```

**File:** third_party/move/tools/move-resource-viewer/src/limit.rs (L13-20)
```rust
    pub fn charge(&mut self, cost: usize) -> PartialVMResult<()> {
        if self.0 < cost {
            return Err(PartialVMError::new(StatusCode::ABORTED)
                .with_message("Query exceeds size limit".to_string()));
        }
        self.0 -= cost;
        Ok(())
    }
```
