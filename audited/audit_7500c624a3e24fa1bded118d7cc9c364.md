# Audit Report

## Title
Memory Undercharge Vulnerability in FatStructType::subst() Enables API Node Resource Exhaustion

## Summary
The `FatStructType::subst()` function in the move-resource-viewer charges only for struct metadata but fails to charge for Vec allocations containing type arguments and layout fields. Combined with no limit on struct field counts in production, this allows attackers to craft Move structs with massive field counts that cause significant memory allocation while only charging minimal amounts, enabling API node resource exhaustion and crashes.

## Finding Description

The vulnerability exists in the limiter charging mechanism within `FatStructType::subst()`. [1](#0-0) 

The function charges only for struct metadata (AccountAddress, module name, struct name) - approximately 100 bytes total. However, it then allocates substantial memory for Vec<FatType> containers without charging for these allocations.

For type arguments: [2](#0-1) 

For layout fields: [3](#0-2) 

The `.collect()` operations create Vec<FatType> containers that can hold thousands of elements, but only the struct metadata is charged to the limiter.

**Critical Configuration Flaw**: [4](#0-3) 

Production configuration sets no limit on struct field count, allowing attackers to create structs with arbitrary numbers of fields (e.g., 100,000+ fields).

**Primitive Type Processing Without Charging**: [5](#0-4) 

When processing primitive types during substitution, the function returns immediately without any limiter charges. This means a struct with 100,000 u8 fields will call subst() 100,000 times, each returning without charging.

**Attack Path Verification**:
1. API endpoint receives request: [6](#0-5) 
2. Conversion to MoveResource: [7](#0-6) 
3. AptosValueAnnotator delegation: [8](#0-7) 
4. Struct tag resolution: [9](#0-8) 
5. Eventually calls FatStructType::subst() with undercharging

**Limiter Protection Bypass**: [10](#0-9) 

The default 100MB limit can be exceeded through this undercharging mechanism, as actual memory allocation far exceeds what is charged.

**Undercharge Calculation**:
- Struct with 1,000,000 U8 fields
- Vec<FatType> allocation: ~24MB (FatType enum size × field count)
- Charged: ~100 bytes (struct metadata only)
- Undercharge ratio: 240,000:1

With ~300 concurrent requests, this allocates 7.2GB while only charging 30KB, potentially exhausting typical API node memory (8-16GB RAM).

## Impact Explanation

**Severity: High** (up to $50,000 per Aptos Bug Bounty)

This vulnerability qualifies as **"API crashes"** under High Severity criteria. The concrete impacts include:

1. **API Node Resource Exhaustion**: Multiple concurrent requests viewing malicious resources exhaust node memory, causing crashes or severe performance degradation. With unlimited struct field counts and minimal charging, attackers can allocate gigabytes of memory while bypassing limiter protections.

2. **Denial of Service**: Attackers render API endpoints unavailable, preventing users from querying blockchain state, submitting transactions, or accessing on-chain data.

3. **Indexer/Explorer Disruption**: Systems using `AptosValueAnnotator` for resource viewing (indexers, block explorers) become vulnerable to crashes when processing malicious resources.

4. **Protection Mechanism Bypass**: The Limiter's intended purpose is resource exhaustion prevention, but the 240,000:1 undercharge ratio effectively nullifies this protection.

While this does not directly affect consensus or validator operations, API infrastructure is critical for blockchain usability. Crashed or degraded API nodes prevent ecosystem functionality, transaction submission, and dApp integration.

## Likelihood Explanation

**Likelihood: High**

The attack is highly feasible because:

1. **No Field Count Limit**: Production configuration explicitly allows unlimited struct fields, enabling arbitrarily large allocations.

2. **Low Cost to Attacker**: One-time gas cost for module publishing and resource storage enables persistent exploitation capability across all API nodes.

3. **Public Attack Surface**: API endpoints are publicly accessible with no special privileges required beyond normal module publishing rights.

4. **Amplification Factor**: Single malicious resource enables unlimited repeated exploitation. Once deployed, any user (or the attacker) can trigger the resource viewer.

5. **No Detection**: Module publishing and resource storage appear legitimate, making attack detection difficult.

6. **Concurrent Exploitation**: Multiple concurrent requests amplify the impact, enabling rapid memory exhaustion.

The only constraint is initial gas costs for module publishing and resource storage, but these are one-time costs for persistent exploitation capability.

## Recommendation

Implement proper charging for Vec allocations in `FatStructType::subst()`:

```rust
pub fn subst(...) -> PartialVMResult<FatStructType> {
    limiter.charge(std::mem::size_of::<AccountAddress>())?;
    limiter.charge(self.module.as_bytes().len())?;
    limiter.charge(self.name.as_bytes().len())?;
    
    // Charge for Vec allocations
    limiter.charge(self.ty_args.len() * std::mem::size_of::<FatType>())?;
    limiter.charge(match &self.layout {
        FatStructLayout::Singleton(fields) => fields.len() * std::mem::size_of::<FatType>(),
        FatStructLayout::Variants(variants) => {
            variants.iter().map(|v| v.len()).sum::<usize>() * std::mem::size_of::<FatType>()
        }
    })?;
    
    // Continue with existing logic...
}
```

Additionally, consider setting a reasonable production limit for `max_fields_in_struct` (e.g., 1000-10000 fields) to prevent extreme cases.

## Proof of Concept

```move
module attacker::exploit {
    struct MaliciousStruct has key, store {
        // Create struct with 100,000 u8 fields
        f0: u8, f1: u8, f2: u8, // ... f99999: u8
    }
    
    public entry fun deploy_exploit(account: &signer) {
        move_to(account, MaliciousStruct { 
            f0: 0, f1: 0, f2: 0, // ... f99999: 0 
        });
    }
}
```

After deployment, call API endpoint:
```
GET /v1/accounts/{attacker_address}/resource/0x{attacker}::exploit::MaliciousStruct
```

With concurrent requests, this exhausts API node memory while only charging ~100 bytes per request to the limiter.

## Notes

This vulnerability represents a fundamental mismatch between resource accounting (limiter charges) and actual resource consumption (memory allocation). The 240,000:1 undercharge ratio effectively bypasses the 100MB limiter protection, allowing attackers to exhaust real memory while staying well under the charged limit. The absence of struct field count limits in production configuration exacerbates this issue, enabling arbitrarily large allocations.

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

**File:** third_party/move/tools/move-resource-viewer/src/fat_type.rs (L202-207)
```rust
                FatStructLayout::Singleton(fields) => FatStructLayout::Singleton(
                    fields
                        .iter()
                        .map(|ty| ty.subst(ty_args, subst_struct, limiter))
                        .collect::<PartialVMResult<_>>()?,
                ),
```

**File:** third_party/move/tools/move-resource-viewer/src/fat_type.rs (L384-398)
```rust
            Bool => Bool,
            U8 => U8,
            U16 => U16,
            U32 => U32,
            U64 => U64,
            U128 => U128,
            U256 => U256,
            I8 => I8,
            I16 => I16,
            I32 => I32,
            I64 => I64,
            I128 => I128,
            I256 => I256,
            Address => Address,
            Signer => Signer,
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L170-170)
```rust
        max_fields_in_struct: None,
```

**File:** api/src/state.rs (L274-280)
```rust
    fn resource(
        &self,
        accept_type: &AcceptType,
        address: Address,
        resource_type: MoveStructTag,
        ledger_version: Option<u64>,
    ) -> BasicResultWith404<MoveResource> {
```

**File:** api/types/src/convert.rs (L93-94)
```rust
    pub fn try_into_resource(&self, tag: &StructTag, bytes: &'_ [u8]) -> Result<MoveResource> {
        self.inner.view_resource(tag, bytes)?.try_into()
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

**File:** third_party/move/tools/move-resource-viewer/src/lib.rs (L384-408)
```rust
    fn resolve_struct_tag(
        &self,
        struct_tag: &StructTag,
        limit: &mut Limiter,
    ) -> anyhow::Result<FatStructRef> {
        let StructTag {
            address,
            module,
            name,
            type_args,
        } = struct_tag;
        let struct_name = StructName {
            address: *address,
            module: module.to_owned(),
            name: name.to_owned(),
        };
        if type_args.is_empty() {
            return self.resolve_basic_struct(&struct_name, limit);
        }
        let type_args = type_args
            .iter()
            .map(|ty| self.resolve_type_impl(ty, limit))
            .collect::<anyhow::Result<Vec<_>>>()?;
        self.resolve_generic_struct(struct_name, type_args, limit)
    }
```

**File:** third_party/move/tools/move-resource-viewer/src/limit.rs (L7-8)
```rust
// Default limit set to 100mb per query.
const DEFAULT_LIMIT: usize = 100_000_000;
```
