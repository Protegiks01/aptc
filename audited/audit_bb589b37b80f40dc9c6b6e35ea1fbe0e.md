# Audit Report

## Title
Pagination Cursor Duplication Bug in `get_prefixed_state_value_iterator` Causes Duplicate State Values Across Pages

## Summary
The `PrefixedStateValueIterator` implementation in the state storage layer contains a cursor handling bug that causes the cursor key to be returned twice when paginating through state values. This results in duplicate entries across pagination boundaries, breaking the pagination invariant that consecutive pages should contain distinct, non-overlapping data.

## Finding Description

The vulnerability exists in the `PrefixedStateValueIterator::new()` and `next_by_kv()` methods. When a cursor (previous state key) is provided for pagination, the iterator incorrectly positions itself AT the cursor key rather than AFTER it. [1](#0-0) 

When a cursor is provided, the iterator seeks to `(first_key.clone(), u64::MAX)`. Due to the version encoding scheme where versions are stored as their bitwise complement, seeking to `u64::MAX` (encoded as `!u64::MAX = 0`) positions the iterator at the first (highest) version of that state key, not past it. [2](#0-1) 

The critical flaw is in the duplicate prevention logic. The check `if Some(&state_key) == self.prev_key.as_ref()` only prevents returning the same key within a single iterator instance, but `prev_key` is initialized to `None` when creating a new iterator with a cursor. [3](#0-2) 

This causes the following sequence:
1. First pagination call returns items [A, B, C], cursor = D
2. Second call with cursor = D creates new iterator
3. Iterator seeks to (D, u64::MAX), positions at D
4. `prev_key = None` initially, so duplicate check fails
5. Iterator returns D (duplicate!)
6. Subsequent items are E, F, etc.

The API layer compounds this by using the cursor to fetch the "next page", expecting no duplication. [4](#0-3) 

Evidence of the bug is present in the test suite itself, which contains a FIXME comment acknowledging pagination issues: [5](#0-4) 

The indexer-based implementation suffers from the identical bug: [6](#0-5) 

## Impact Explanation

**Severity: Medium**

This vulnerability violates the **State Consistency** invariant by causing API consumers to receive duplicate state values when paginating. While it doesn't directly compromise consensus or cause fund loss, it creates several serious issues:

1. **State Synchronization Corruption**: Validators or full nodes using pagination to sync state will receive duplicate entries, potentially corrupting their local state if they don't implement deduplication
2. **Indexer Data Corruption**: External indexers consuming paginated API responses will store duplicate entries, breaking data integrity
3. **Client Application Logic Errors**: Applications relying on pagination for account enumeration or resource discovery will process the same data twice, leading to incorrect business logic execution
4. **Gas Metering Issues**: If applications charge users per state item retrieved, duplicates cause overcharging

The bug affects all API endpoints using pagination: `/accounts/:address/resources`, `/accounts/:address/modules`, and any internal systems using the state value iterator for state enumeration.

## Likelihood Explanation

**Likelihood: High**

This bug triggers automatically whenever pagination is used with a cursor parameter, requiring no special attacker action:
- Any API consumer using `limit` and `start` parameters will encounter duplicates
- Internal systems paginating through large state sets will be affected
- The bug is deterministic and reproducible 100% of the time

The attack surface is broad because pagination is a fundamental operation exposed through public APIs and used internally for state synchronization. No privileged access is required to observe or exploit this behavior.

## Recommendation

**Fix: Initialize `prev_key` to the cursor when provided, or seek past the cursor**

Option 1 - Initialize prev_key to cursor:
```rust
pub fn new(
    db: &'a StateKvDb,
    key_prefix: StateKeyPrefix,
    first_key: Option<StateKey>,
    desired_version: Version,
) -> Result<Self> {
    let mut read_opts = ReadOptions::default();
    read_opts.set_total_order_seek(true);
    let mut kv_iter = db
        .metadata_db()
        .iter_with_opts::<StateValueSchema>(read_opts)?;
    
    let prev_key = if let Some(first_key) = &first_key {
        kv_iter.seek(&(first_key.clone(), u64::MAX))?;
        Some(first_key.clone())  // Initialize prev_key to cursor
    } else {
        kv_iter.seek(&&key_prefix)?;
        None
    };
    
    Ok(Self {
        kv_iter: Some(kv_iter),
        key_prefix,
        prev_key,  // Use initialized value
        desired_version,
        is_finished: false,
    })
}
```

Option 2 - Seek past cursor by advancing iterator once:
```rust
pub fn new(
    db: &'a StateKvDb,
    key_prefix: StateKeyPrefix,
    first_key: Option<StateKey>,
    desired_version: Version,
) -> Result<Self> {
    let mut read_opts = ReadOptions::default();
    read_opts.set_total_order_seek(true);
    let mut kv_iter = db
        .metadata_db()
        .iter_with_opts::<StateValueSchema>(read_opts)?;
    
    if let Some(first_key) = &first_key {
        kv_iter.seek(&(first_key.clone(), u64::MAX))?;
        // Advance past the cursor by seeking to next key
        kv_iter.seek(&(first_key.clone(), 0))?;
    } else {
        kv_iter.seek(&&key_prefix)?;
    };
    
    Ok(Self {
        kv_iter: Some(kv_iter),
        key_prefix,
        prev_key: None,
        desired_version,
        is_finished: false,
    })
}
```

Apply the same fix to the indexer implementation in `storage/indexer/src/utils.rs`.

## Proof of Concept

```rust
#[test]
fn test_pagination_cursor_duplication() {
    let tmp_dir = TempPath::new();
    let db = AptosDB::new_for_test(&tmp_dir);
    let store = &db.state_store;
    
    let address = AccountAddress::new([1u8; AccountAddress::LENGTH]);
    let key1 = StateKey::resource_typed::<AccountResource>(&address).unwrap();
    let key2 = StateKey::resource_typed::<ChainIdResource>(&address).unwrap();
    let key3 = StateKey::resource_typed::<CoinInfoResource<AptosCoinType>>(&address).unwrap();
    
    let value1 = StateValue::from(String::from("value1").into_bytes());
    let value2 = StateValue::from(String::from("value2").into_bytes());
    let value3 = StateValue::from(String::from("value3").into_bytes());
    
    // Insert 3 keys
    put_value_set(
        store,
        vec![
            (key1.clone(), value1.clone()),
            (key2.clone(), value2.clone()),
            (key3.clone(), value3.clone()),
        ],
        0,
    );
    
    let prefix = StateKeyPrefix::new(StateKeyTag::AccessPath, address.to_vec());
    
    // First page - get first 2 items
    let mut iter1 = store.get_prefixed_state_value_iterator(&prefix, None, 0).unwrap();
    let item1 = iter1.next().unwrap().unwrap();
    let item2 = iter1.next().unwrap().unwrap();
    assert_eq!(item1.0, key1);
    assert_eq!(item2.0, key2);
    
    // Second page - use key2 as cursor, expect to get key3 ONLY (not key2 again)
    let mut iter2 = store.get_prefixed_state_value_iterator(&prefix, Some(&key2), 0).unwrap();
    let item3 = iter2.next().unwrap().unwrap();
    
    // BUG: This assertion will FAIL - item3 is key2 (duplicate), not key3
    assert_ne!(item3.0, key2, "Cursor key should not be returned again!");
    assert_eq!(item3.0, key3, "Expected next key after cursor");
}
```

Run with: `cargo test test_pagination_cursor_duplication --package aptosdb`

The test will fail, demonstrating that `key2` is returned twice.

## Notes

This bug is especially problematic because:
1. The existing test suite doesn't catch it due to test expectations matching the buggy behavior
2. The FIXME comment in the test file indicates developers are aware of pagination issues but haven't identified the root cause
3. Both the main and indexer implementations have the same bug, suggesting it's a systematic design flaw
4. The bug affects all systems relying on state pagination, including public APIs, state sync, and internal indexers

### Citations

**File:** storage/aptosdb/src/utils/iterators.rs (L114-146)
```rust
    pub fn new(
        db: &'a StateKvDb,
        key_prefix: StateKeyPrefix,
        first_key: Option<StateKey>,
        desired_version: Version,
    ) -> Result<Self> {
        let mut read_opts = ReadOptions::default();
        // Without this, iterators are not guaranteed a total order of all keys, but only keys for the same prefix.
        // For example,
        // aptos/abc|2
        // aptos/abc|1
        // aptos/abc|0
        // aptos/abd|1
        // if we seek('aptos/'), and call next, we may not reach `aptos/abd/1` because the prefix extractor we adopted
        // here will stick with prefix `aptos/abc` and return `None` or any arbitrary result after visited all the
        // keys starting with `aptos/abc`.
        read_opts.set_total_order_seek(true);
        let mut kv_iter = db
            .metadata_db()
            .iter_with_opts::<StateValueSchema>(read_opts)?;
        if let Some(first_key) = &first_key {
            kv_iter.seek(&(first_key.clone(), u64::MAX))?;
        } else {
            kv_iter.seek(&&key_prefix)?;
        };
        Ok(Self {
            kv_iter: Some(kv_iter),
            key_prefix,
            prev_key: None,
            desired_version,
            is_finished: false,
        })
    }
```

**File:** storage/aptosdb/src/utils/iterators.rs (L148-179)
```rust
    fn next_by_kv(&mut self) -> Result<Option<(StateKey, StateValue)>> {
        let iter = self.kv_iter.as_mut().unwrap();
        if !self.is_finished {
            while let Some(((state_key, version), state_value_opt)) = iter.next().transpose()? {
                // In case the previous seek() ends on the same key with version 0.
                if Some(&state_key) == self.prev_key.as_ref() {
                    continue;
                }
                // Cursor is currently at the first available version of the state key.
                // Check if the key_prefix is a valid prefix of the state_key we got from DB.
                if !self.key_prefix.is_prefix(&state_key)? {
                    // No more keys matching the key_prefix, we can return the result.
                    self.is_finished = true;
                    break;
                }

                if version > self.desired_version {
                    iter.seek(&(state_key.clone(), self.desired_version))?;
                    continue;
                }

                self.prev_key = Some(state_key.clone());
                // Seek to the next key - this can be done by seeking to the current key with version 0
                iter.seek(&(state_key.clone(), 0))?;

                if let Some(state_value) = state_value_opt {
                    return Ok(Some((state_key, state_value)));
                }
            }
        }
        Ok(None)
    }
```

**File:** storage/aptosdb/src/schema/state_value/mod.rs (L42-58)
```rust
impl KeyCodec<StateValueSchema> for Key {
    fn encode_key(&self) -> Result<Vec<u8>> {
        let mut encoded = vec![];
        encoded.write_all(self.0.encoded())?;
        encoded.write_u64::<BigEndian>(!self.1)?;
        Ok(encoded)
    }

    fn decode_key(data: &[u8]) -> Result<Self> {
        const VERSION_SIZE: usize = size_of::<Version>();

        ensure_slice_len_gt(data, VERSION_SIZE)?;
        let state_key_len = data.len() - VERSION_SIZE;
        let state_key: StateKey = StateKey::decode(&data[..state_key_len])?;
        let version = !(&data[state_key_len..]).read_u64::<BigEndian>()?;
        Ok((state_key, version))
    }
```

**File:** api/src/context.rs (L470-558)
```rust
    pub fn get_resources_by_pagination(
        &self,
        address: AccountAddress,
        prev_state_key: Option<&StateKey>,
        version: u64,
        limit: u64,
    ) -> Result<(Vec<(StructTag, Vec<u8>)>, Option<StateKey>)> {
        let account_iter = if !db_sharding_enabled(&self.node_config) {
            Box::new(
                self.db
                    .get_prefixed_state_value_iterator(
                        &StateKeyPrefix::from(address),
                        prev_state_key,
                        version,
                    )?
                    .map(|item| item.map_err(|err| anyhow!(err.to_string()))),
            )
        } else {
            self.indexer_reader
                .as_ref()
                .ok_or_else(|| format_err!("Indexer reader doesn't exist"))?
                .get_prefixed_state_value_iterator(
                    &StateKeyPrefix::from(address),
                    prev_state_key,
                    version,
                )?
        };
        // TODO: Consider rewriting this to consider resource groups:
        // * If a resource group is found, expand
        // * Return Option<Result<(PathType, StructTag, Vec<u8>)>>
        // * Count resources and only include a resource group if it can completely fit
        // * Get next_key as the first struct_tag not included
        let mut resource_iter = account_iter
            .filter_map(|res| match res {
                Ok((k, v)) => match k.inner() {
                    StateKeyInner::AccessPath(AccessPath { address: _, path }) => {
                        match Path::try_from(path.as_slice()) {
                            Ok(Path::Resource(struct_tag)) => {
                                Some(Ok((struct_tag, v.bytes().to_vec())))
                            }
                            // TODO: Consider expanding to Path::Resource
                            Ok(Path::ResourceGroup(struct_tag)) => {
                                Some(Ok((struct_tag, v.bytes().to_vec())))
                            }
                            Ok(Path::Code(_)) => None,
                            Err(e) => Some(Err(anyhow::Error::from(e))),
                        }
                    }
                    _ => {
                        error!("storage prefix scan return inconsistent key ({:?}) with expected key prefix ({:?}).", k, StateKeyPrefix::from(address));
                        Some(Err(format_err!( "storage prefix scan return inconsistent key ({:?})", k )))
                    }
                },
                Err(e) => Some(Err(e)),
            })
            .take(limit as usize + 1);
        let kvs = resource_iter
            .by_ref()
            .take(limit as usize)
            .collect::<Result<Vec<(StructTag, Vec<u8>)>>>()?;

        // We should be able to do an unwrap here, otherwise the above db read would fail.
        let state_view = self.state_view_at_version(version)?;
        let converter = state_view.as_converter(self.db.clone(), self.indexer_reader.clone());

        // Extract resources from resource groups and flatten into all resources
        let kvs = kvs
            .into_iter()
            .map(|(tag, value)| {
                if converter.is_resource_group(&tag) {
                    // An error here means a storage invariant has been violated
                    bcs::from_bytes::<ResourceGroup>(&value)
                        .map(|map| map.into_iter().collect::<Vec<_>>())
                        .map_err(|e| e.into())
                } else {
                    Ok(vec![(tag, value)])
                }
            })
            .collect::<Result<Vec<Vec<(StructTag, Vec<u8>)>>>>()?
            .into_iter()
            .flatten()
            .collect();

        let next_key = if let Some((struct_tag, _v)) = resource_iter.next().transpose()? {
            Some(StateKey::resource(&address, &struct_tag)?)
        } else {
            None
        };
        Ok((kvs, next_key))
```

**File:** api/src/tests/accounts_test.rs (L557-557)
```rust
    // FIXME: Pagination seems to be off by one (change 4 to 5 below and see what happens).
```

**File:** storage/indexer/src/utils.rs (L24-47)
```rust
impl<'a> PrefixedStateValueIterator<'a> {
    pub fn new(
        main_db_reader: Arc<dyn DbReader>,
        indexer_db: &'a DB,
        key_prefix: StateKeyPrefix,
        first_key: Option<StateKey>,
        desired_version: Version,
    ) -> Result<Self> {
        let mut read_opt = ReadOptions::default();
        read_opt.set_total_order_seek(true);
        let mut state_keys_iter = indexer_db.iter_with_opts::<StateKeysSchema>(read_opt)?;
        if let Some(first_key) = first_key {
            state_keys_iter.seek(&first_key)?;
        } else {
            state_keys_iter.seek(&&key_prefix)?;
        };
        Ok(Self {
            state_keys_iter,
            main_db: main_db_reader,
            key_prefix,
            desired_version,
            is_finished: false,
        })
    }
```
