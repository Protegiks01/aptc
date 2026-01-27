# Audit Report

## Title
State View Version Mismatch in Historical Transaction API Conversion

## Summary
The API's `get_transaction_inner()` function uses the **latest** state view to deserialize historical transaction data (events, write sets), but this data was serialized using module definitions from the transaction's **original version**. This version mismatch can cause `try_into_onchain_transaction()` to fail with "Module can't be found" errors when querying valid committed transactions, resulting in API failures (500 Internal Server Error).

## Finding Description
When retrieving historical transactions via the REST API, the conversion process has a critical architectural flaw: [1](#0-0) 

The code obtains the **latest** state view, regardless of which version the transaction was executed at. [2](#0-1) 

When converting on-chain transactions to API format, this latest state view is used to resolve module definitions for events. [3](#0-2) 

The `try_into_onchain_transaction()` function calls `try_into_events()` which requires resolving event type definitions. [4](#0-3) 

Event conversion calls `view_value()` which must resolve struct types from modules. [5](#0-4) 

The resolution chain proceeds through `resolve_type_impl` → `resolve_struct_tag` → `resolve_basic_struct`. [6](#0-5) 

At this point, `view_existing_module()` is called, which fails if the module doesn't exist in the **latest** state view. [7](#0-6) 

**The developers are aware of this issue:** [8](#0-7) [9](#0-8) 

Both TODO comments explicitly state: "the resource value is interpreted by the type definition at the version of the converter, not the version of the tx: **must be fixed before we allow module updates**"

**Importantly, write set changes have fallback error handling:** [10](#0-9) 

The `.ok()` on line 265 swallows conversion errors for write set changes. However, event conversion has no such fallback, causing errors to propagate to the API layer.

## Impact Explanation
This issue falls under **Medium Severity** per the Aptos bug bounty criteria as it causes:
- **API crashes**: Valid committed transactions become unqueryable, returning 500 Internal Server Error
- **State inconsistencies requiring intervention**: Historical data retrieval fails for transactions referencing upgraded/deleted modules

The impact is limited to API availability rather than consensus or fund safety, but it breaks the fundamental expectation that all committed transactions should be queryable.

## Likelihood Explanation
Likelihood is **MODERATE** because:

**Triggering conditions:**
1. A transaction at version V₁ emits an event of type `Module::Struct`
2. Module is later deleted via admin write set OR significantly modified
3. User queries the V₁ transaction via API endpoints (`/transactions/by_hash`, `/transactions/by_version`)
4. API attempts to deserialize event using latest state view where module doesn't exist/differs

**Realistic scenarios:**
- Genesis modules with `upgrade_policy_arbitrary()` can be upgraded with breaking changes
- Admin write sets can delete modules during governance operations
- Framework upgrades could affect historical transaction queryability
- Note: Regular packages cannot use arbitrary policy (explicitly disabled), limiting user module impact [11](#0-10) 

## Recommendation
Implement version-aware state view resolution for historical transactions:

1. **Short-term fix:** Add error handling fallback for event conversion similar to write sets:
```rust
let events = self.try_into_events(&data.events).unwrap_or_else(|_| {
    // Fallback: return events with hex-encoded data
    data.events.iter().map(|e| Event::from_raw(e)).collect()
});
```

2. **Long-term fix:** Use `state_view_at_version()` for the transaction's actual version:
```rust
let state_view = self.context.state_view_at_version(txn_version)?;
``` [12](#0-11) 

This method already exists but is not used in `get_transaction_inner()`.

## Proof of Concept

**Scenario:** Module deleted after transaction execution

```rust
// 1. Deploy module with event-emitting function
module 0xcafe::MyModule {
    struct MyEvent has drop, store { value: u64 }
    
    public entry fun emit_event() {
        event::emit(MyEvent { value: 42 });
    }
}

// 2. Execute transaction that emits MyEvent at version V1
// Transaction succeeds and is committed

// 3. Admin write set deletes module 0xcafe::MyModule at version V2

// 4. Query transaction from V1 via API:
// GET /v1/transactions/by_version/<V1>
// 
// Expected: Returns transaction data
// Actual: Returns 500 Internal Server Error
// Error: "Module 0xcafe::MyModule can't be found"
```

**Reproduction steps:**
1. Create testnet account and deploy module with event emission
2. Execute transaction calling event-emitting function
3. Record transaction hash
4. Delete module via governance proposal (if permissions allow)
5. Query original transaction: `curl https://testnet.aptoslabs.com/v1/transactions/by_hash/<hash>`
6. Observe 500 error instead of transaction data

## Notes
While this is a known issue per the TODO comments, it represents a **state consistency violation**: the API cannot reliably serve historical blockchain data, which is a core requirement for blockchain explorers, indexers, and auditing tools. The issue has existed since module upgrades were enabled, but the explicit "must be fixed" language indicates it's an unresolved defect rather than accepted behavior.

### Citations

**File:** api/src/transactions.rs (L1017-1017)
```rust
                let state_view = self.context.latest_state_view_poem(ledger_info)?;
```

**File:** api/src/transactions.rs (L1027-1035)
```rust
                            .try_into_onchain_transaction(timestamp, txn)
                            .context("Failed to convert on chain transaction to Transaction")
                            .map_err(|err| {
                                BasicErrorWith404::internal_with_code(
                                    err,
                                    AptosErrorCode::InternalError,
                                    ledger_info,
                                )
                            })?
```

**File:** api/types/src/convert.rs (L173-192)
```rust
    pub fn try_into_onchain_transaction(
        &self,
        timestamp: u64,
        data: TransactionOnChainData,
    ) -> Result<Transaction> {
        use aptos_types::transaction::Transaction::{
            BlockEpilogue, BlockMetadata, BlockMetadataExt, GenesisTransaction, StateCheckpoint,
            UserTransaction,
        };
        let aux_data = self
            .db
            .get_transaction_auxiliary_data_by_version(data.version)?;
        let info = self.into_transaction_info(
            data.version,
            &data.info,
            data.accumulator_root_hash,
            data.changes,
            aux_data,
        );
        let events = self.try_into_events(&data.events)?;
```

**File:** api/types/src/convert.rs (L262-262)
```rust
            // TODO: the resource value is interpreted by the type definition at the version of the converter, not the version of the tx: must be fixed before we allow module updates
```

**File:** api/types/src/convert.rs (L263-267)
```rust
            changes: write_set
                .into_write_op_iter()
                .filter_map(|(sk, wo)| self.try_into_write_set_changes(sk, wo).ok())
                .flatten()
                .collect(),
```

**File:** api/types/src/convert.rs (L432-432)
```rust
                        // TODO: the resource value is interpreted by the type definition at the version of the converter, not the version of the tx: must be fixed before we allow module updates
```

**File:** api/types/src/convert.rs (L601-609)
```rust
    pub fn try_into_events(&self, events: &[ContractEvent]) -> Result<Vec<Event>> {
        let mut ret = vec![];
        for event in events {
            let data = self
                .inner
                .view_value(event.type_tag(), event.event_data())?;
            ret.push((event, MoveValue::try_from(data)?.json()?).into());
        }
        Ok(ret)
```

**File:** third_party/move/tools/move-resource-viewer/src/lib.rs (L146-150)
```rust
    pub fn view_existing_module(&self, id: &ModuleId) -> anyhow::Result<V::Item> {
        match self.view_module(id)? {
            Some(module) => Ok(module),
            None => bail!("Module {:?} can't be found", id),
        }
```

**File:** third_party/move/tools/move-resource-viewer/src/lib.rs (L443-445)
```rust
        let module_id = ModuleId::new(struct_name.address, struct_name.module.clone());
        let module = self.view_existing_module(&module_id)?;
        let module = module.borrow();
```

**File:** third_party/move/tools/move-resource-viewer/src/lib.rs (L685-689)
```rust
    pub fn view_value(&self, ty_tag: &TypeTag, blob: &[u8]) -> anyhow::Result<AnnotatedMoveValue> {
        let mut limit = Limiter::default();
        let ty = self.resolve_type_impl(ty_tag, &mut limit)?;
        self.view_value_by_fat_type(&ty, blob, &mut limit)
    }
```

**File:** aptos-move/framework/aptos-framework/sources/code.move (L170-174)
```text
        // Disallow incompatible upgrade mode. Governance can decide later if this should be reconsidered.
        assert!(
            pack.upgrade_policy.policy > upgrade_policy_arbitrary().policy,
            error::invalid_argument(EINCOMPATIBLE_POLICY_DISABLED),
        );
```

**File:** api/src/context.rs (L193-195)
```rust
    pub fn state_view_at_version(&self, version: Version) -> Result<DbStateView> {
        Ok(self.db.state_view_at_version(Some(version))?)
    }
```
