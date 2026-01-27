# Audit Report

## Title
Memory Exhaustion via Unbounded StateValue Serialization in Genesis/WriteSet Transactions

## Summary
The `encode_value()` function in `StateValueByKeyHashSchema` performs BCS serialization of `StateValue` objects without size validation when processing genesis or WriteSet transactions that bypass normal size limits. A 4GB StateValue would trigger multiple large memory allocations (~16GB+ total) across encoding, batching, and database write phases, causing memory exhaustion and potential node crashes.

## Finding Description

The vulnerability exists in the interaction between three components:

1. **Size Limit Bypass**: Genesis transactions and `WriteSetPayload::Script` transactions use `ChangeSetConfigs::unlimited_at_gas_feature_version()` which sets `max_bytes_per_write_op` to `u64::MAX`, bypassing the normal 1MB limit: [1](#0-0) [2](#0-1) 

2. **Unbounded Serialization**: The `encode_value()` function performs BCS serialization without checking the size of the `StateValue` before allocating memory: [3](#0-2) 

3. **Multiple Memory Copies**: The serialized data is copied through multiple layers:
   - Original `StateValue` with 4GB `Bytes` field
   - BCS-encoded `Vec<u8>` (4GB+)
   - `WriteOp::Value` in `SchemaBatch`
   - `rocksdb::WriteBatch` [4](#0-3) 

**Attack Scenario**:
A governance proposal could include a WriteSet transaction that creates a StateValue with a 4GB data field. When validators execute this transaction, each node would attempt to allocate 16GB+ memory during encoding and database writing, causing memory exhaustion, node crashes, or extreme slowdowns network-wide.

## Impact Explanation

This qualifies as **High Severity** per the Aptos bug bounty criteria:

- **Validator node slowdowns**: Attempting to serialize and write 4GB values would cause severe performance degradation
- **Potential consensus disruption**: If multiple validators crash simultaneously during transaction execution, consensus could stall
- **Deterministic execution violation**: Memory exhaustion behavior may be non-deterministic across nodes with different available memory, potentially causing state divergence

The impact is mitigated by requiring governance approval, but remains severe as it affects all validator nodes simultaneously when the transaction is executed.

## Likelihood Explanation

**Medium Likelihood** - Requires governance proposal approval (trusted role), but:
- Governance proposals are a standard mechanism for network upgrades
- A malicious or buggy proposal could inadvertently create oversized StateValues
- Once approved, the transaction executes automatically on all validators
- No additional safeguards exist to prevent memory exhaustion during execution

## Recommendation

Add size validation in `encode_value()` before attempting BCS serialization:

```rust
impl ValueCodec<StateValueByKeyHashSchema> for Option<StateValue> {
    fn encode_value(&self) -> Result<Vec<u8>> {
        // Add size check before serialization
        const MAX_STATE_VALUE_SIZE: usize = 100 << 20; // 100MB reasonable limit
        
        if let Some(ref sv) = self {
            if sv.bytes().len() > MAX_STATE_VALUE_SIZE {
                return Err(anyhow::anyhow!(
                    "StateValue size {} exceeds maximum allowed size {}",
                    sv.bytes().len(),
                    MAX_STATE_VALUE_SIZE
                ));
            }
        }
        
        bcs::to_bytes(self).map_err(Into::into)
    }
    
    fn decode_value(data: &[u8]) -> Result<Self> {
        bcs::from_bytes(data).map_err(Into::into)
    }
}
```

Additionally, consider adding a separate size limit for genesis/WriteSet transactions to prevent abuse even when normal limits are bypassed.

## Proof of Concept

```rust
#[cfg(test)]
mod memory_exhaustion_test {
    use super::*;
    use aptos_types::state_store::state_value::StateValue;
    use bytes::Bytes;
    
    #[test]
    #[should_panic(expected = "memory allocation")]
    fn test_encode_large_state_value() {
        // Attempt to create and encode a 4GB StateValue
        // This would cause memory exhaustion in production
        let large_data = vec![0u8; 4 * 1024 * 1024 * 1024]; // 4GB
        let state_value = StateValue::from(large_data);
        let option_value = Some(state_value);
        
        // This should fail or be bounded
        let _encoded = <Option<StateValue> as ValueCodec<StateValueByKeyHashSchema>>::encode_value(&option_value);
    }
}
```

**Notes**: While this vulnerability requires governance approval to exploit (making it require privileged access), it represents a significant defensive programming gap. The lack of size validation in critical serialization paths could lead to network-wide validator crashes if a malicious or buggy governance proposal is approved. The system should implement defense-in-depth by validating sizes even for "trusted" transaction types, as governance compromise or bugs could have catastrophic consequences. The 1MB limit exists for normal transactions [5](#0-4)  but is completely bypassed for genesis and WriteSet transactions, creating this edge case vulnerability.

### Citations

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2317-2319)
```rust
                let change_set_configs =
                    ChangeSetConfigs::unlimited_at_gas_feature_version(self.gas_feature_version());
                let change_set = tmp_session.finish(&change_set_configs, code_storage)?;
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/vm.rs (L111-113)
```rust
    pub fn genesis_change_set_configs(&self) -> ChangeSetConfigs {
        ChangeSetConfigs::unlimited_at_gas_feature_version(LATEST_GAS_FEATURE_VERSION)
    }
```

**File:** storage/aptosdb/src/schema/state_value_by_key_hash/mod.rs (L56-58)
```rust
    fn encode_value(&self) -> Result<Vec<u8>> {
        bcs::to_bytes(self).map_err(Into::into)
    }
```

**File:** storage/schemadb/src/batch.rs (L99-106)
```rust
    fn put<S: Schema>(&mut self, key: &S::Key, value: &S::Value) -> DbResult<()> {
        let key = <S::Key as KeyCodec<S>>::encode_key(key)?;
        let value = <S::Value as ValueCodec<S>>::encode_value(value)?;

        self.stats()
            .put(S::COLUMN_FAMILY_NAME, key.len() + value.len());
        self.raw_put(S::COLUMN_FAMILY_NAME, key, value)
    }
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L154-157)
```rust
            max_bytes_per_write_op: NumBytes,
            { 5.. => "max_bytes_per_write_op" },
            1 << 20, // a single state item is 1MB max
        ],
```
