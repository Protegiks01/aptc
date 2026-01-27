# Audit Report

## Title
RandStorage Error Handling Inconsistency Causes Validator Crashes and Liveness Failures

## Summary

The `RandStorage` trait returns `anyhow::Result` without specifying error semantics, allowing implementations to have fundamentally different failure behaviors. The persistent storage implementation (`RandDb`) can return database errors, while the in-memory implementation (`InMemRandDb`) never errors. Callers handle these inconsistently: some use `.expect()` causing validator crashes, while others silently swallow errors without sending RPC responses, breaking the randomness generation protocol. [1](#0-0) 

## Finding Description

The `RandStorage` trait defines storage operations for the consensus randomness subsystem but provides no error semantics. Two implementations exist with drastically different failure modes:

**Implementation 1: InMemRandDb** - Returns `Ok(())` for all operations, never producing errors: [2](#0-1) 

**Implementation 2: RandDb** - Performs database operations that can fail with various errors (serialization, disk I/O, corruption): [3](#0-2) 

The `DbError` wrapper type used by RandDb wraps any `anyhow::Error`: [4](#0-3) 

Callers handle these errors inconsistently in three critical locations:

**Vulnerability 1: Panic on Self-Broadcast**
When a validator broadcasts its own augmented data, it uses `.expect()` which causes a panic if storage fails: [5](#0-4) 

**Vulnerability 2: Silent RPC Failure**
When receiving augmented data from peers via RPC, storage errors are logged but no response is sent back, causing the sender to timeout: [6](#0-5) 

Compare this to the success case which properly sends a response: [7](#0-6) 

**Vulnerability 3: Silent Data Loss on Initialization**
During `AugDataStore` initialization, database read errors are silently ignored, causing the node to start with empty state: [8](#0-7) 

**Attack Scenario:**
1. Validator node uses `RandDb` for persistent randomness storage
2. Attacker fills disk space through resource exhaustion or triggers database corruption
3. When the validator attempts to broadcast its augmented data, `save_aug_data()` returns a database error
4. The `.expect()` at line 312 causes the node to panic and crash (DoS)
5. Alternatively, during RPC handling, storage failures cause no responses to be sent, breaking the randomness protocol and preventing quorum formation

## Impact Explanation

**Medium Severity** per Aptos bug bounty criteria:

This vulnerability causes **state inconsistencies requiring intervention** and affects **validator availability**. Specifically:

- **Liveness Impact**: Validators can crash during randomness generation, reducing available validators and potentially preventing the 2f+1 quorum needed for consensus randomness
- **Protocol Violation**: RPC requests are dropped without response when storage fails, violating the reliable broadcast protocol expectations
- **State Corruption**: Silent failures during initialization cause validators to lose previously collected augmented data
- **Consensus Randomness Disruption**: The randomness generation subsystem is critical for block proposals and VRF-based leader selection; failures here affect overall consensus liveness

While this doesn't directly cause fund loss or consensus safety violations, it can force validators offline and disrupt randomness generation, requiring manual intervention to restore normal operation.

## Likelihood Explanation

**Moderate Likelihood:**

This vulnerability can be triggered through multiple realistic scenarios:

1. **Resource Exhaustion**: Attacker floods the validator with state-growing transactions to fill disk space, causing database write failures
2. **Disk Failures**: Hardware failures or filesystem corruption naturally trigger database errors
3. **Configuration Issues**: Validators with insufficient disk space or incorrect permissions will hit storage errors during normal operation
4. **Concurrent Operations**: Heavy load on the database can cause timeouts or lock contention errors

The vulnerability affects all validators using persistent storage (RandDb), which is the default production configuration. Test environments using InMemRandDb are unaffected, meaning this discrepancy may not be caught during testing.

The `.expect()` panic is deterministic once storage errors occur, making exploitation reliable.

## Recommendation

**Fix 1: Remove panic in broadcast_aug_data()**

Replace the `.expect()` with proper error handling that attempts recovery or gracefully degrades:

```rust
async fn broadcast_aug_data(&mut self) -> anyhow::Result<DropGuard> {
    let data = self
        .aug_data_store
        .get_my_aug_data()
        .unwrap_or_else(|| D::generate(&self.config, &self.fast_config));
    
    // Attempt to persist, but don't panic if it fails
    if let Err(e) = self.aug_data_store.add_aug_data(data.clone()) {
        error!("[RandManager] Failed to persist self aug data: {}", e);
        // Continue with in-memory only operation or return error to caller
        return Err(e);
    }
    
    // ... rest of broadcast logic
}
```

**Fix 2: Send error response in RPC handler**

When storage fails during RPC message handling, send an error response instead of silently dropping the request:

```rust
RandMessage::AugData(aug_data) => {
    info!(LogSchema::new(LogEvent::ReceiveAugData)
        .author(self.author)
        .epoch(aug_data.epoch())
        .remote_peer(*aug_data.author()));
    match self.aug_data_store.add_aug_data(aug_data) {
        Ok(sig) => self.process_response(protocol, response_sender, RandMessage::AugDataSignature(sig)),
        Err(e) => {
            error!("[RandManager] Failed to add aug data: {}", e);
            // Send error response instead of dropping
            let _ = response_sender.send(Err(RpcError::Error(
                format!("Storage error: {}", e).into()
            )));
        },
    }
}
```

**Fix 3: Propagate errors during initialization**

Replace `unwrap_or_default()` with proper error propagation:

```rust
pub fn new(
    epoch: u64,
    signer: Arc<ValidatorSigner>,
    config: RandConfig,
    fast_config: Option<RandConfig>,
    db: Arc<dyn RandStorage<D>>,
) -> anyhow::Result<Self> {
    let all_data = db.get_all_aug_data()
        .context("Failed to load augmented data from storage")?;
    
    // ... rest of initialization
    
    Ok(Self { /* ... */ })
}
```

**Fix 4: Document trait error semantics**

Add documentation to the `RandStorage` trait specifying when errors can occur and how callers should handle them.

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use std::sync::Arc;
    
    // Mock implementation that fails on save
    struct FailingRandStorage;
    
    impl<D: TAugmentedData> RandStorage<D> for FailingRandStorage {
        fn save_aug_data(&self, _: &AugData<D>) -> anyhow::Result<()> {
            anyhow::bail!("Simulated database error: disk full")
        }
        
        fn save_certified_aug_data(&self, _: &CertifiedAugData<D>) -> anyhow::Result<()> {
            anyhow::bail!("Simulated database error: disk full")
        }
        
        fn save_key_pair_bytes(&self, _: u64, _: Vec<u8>) -> anyhow::Result<()> {
            anyhow::bail!("Simulated database error: disk full")
        }
        
        fn get_key_pair_bytes(&self) -> anyhow::Result<Option<(u64, Vec<u8>)>> {
            Ok(None)
        }
        
        fn get_all_aug_data(&self) -> anyhow::Result<Vec<(AugDataId, AugData<D>)>> {
            Ok(vec![])
        }
        
        fn get_all_certified_aug_data(&self) -> anyhow::Result<Vec<(AugDataId, CertifiedAugData<D>)>> {
            Ok(vec![])
        }
        
        fn remove_aug_data(&self, _: Vec<AugData<D>>) -> anyhow::Result<()> {
            Ok(())
        }
        
        fn remove_certified_aug_data(&self, _: Vec<CertifiedAugData<D>>) -> anyhow::Result<()> {
            Ok(())
        }
    }
    
    #[test]
    #[should_panic(expected = "Add self aug data should succeed")]
    fn test_panic_on_storage_failure() {
        // Create RandManager with failing storage
        let failing_storage = Arc::new(FailingRandStorage);
        let mut rand_manager = RandManager::new(
            /* ... */
            failing_storage,
            /* ... */
        );
        
        // This will panic when broadcast_aug_data calls .expect()
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                rand_manager.broadcast_aug_data().await;
            });
    }
}
```

## Notes

This vulnerability highlights a broader pattern in the codebase where trait-based abstractions use `anyhow::Result` without specifying error semantics. While `anyhow` is convenient for error propagation, using it in public trait APIs creates implicit contracts that different implementations may violate. Production code (RandDb) can fail in ways that test code (InMemRandDb) never does, leading to uncaught bugs.

The randomness generation subsystem is critical for Aptos consensus, as it provides unpredictable randomness for leader election and on-chain randomness beacons. Failures in this subsystem directly impact consensus liveness and validator participation.

### Citations

**File:** consensus/src/rand/rand_gen/storage/interface.rs (L6-23)
```rust
pub trait RandStorage<D>: Send + Sync + 'static {
    fn save_key_pair_bytes(&self, epoch: u64, key_pair: Vec<u8>) -> anyhow::Result<()>;
    fn save_aug_data(&self, aug_data: &AugData<D>) -> anyhow::Result<()>;
    fn save_certified_aug_data(
        &self,
        certified_aug_data: &CertifiedAugData<D>,
    ) -> anyhow::Result<()>;

    fn get_key_pair_bytes(&self) -> anyhow::Result<Option<(u64, Vec<u8>)>>;
    fn get_all_aug_data(&self) -> anyhow::Result<Vec<(AugDataId, AugData<D>)>>;
    fn get_all_certified_aug_data(&self) -> anyhow::Result<Vec<(AugDataId, CertifiedAugData<D>)>>;

    fn remove_aug_data(&self, aug_data: Vec<AugData<D>>) -> anyhow::Result<()>;
    fn remove_certified_aug_data(
        &self,
        certified_aug_data: Vec<CertifiedAugData<D>>,
    ) -> anyhow::Result<()>;
}
```

**File:** consensus/src/rand/rand_gen/storage/in_memory.rs (L27-78)
```rust
impl<D: TAugmentedData> RandStorage<D> for InMemRandDb<D> {
    fn save_key_pair_bytes(&self, epoch: u64, key_pair: Vec<u8>) -> anyhow::Result<()> {
        self.key_pair.write().replace((epoch, key_pair));
        Ok(())
    }

    fn save_aug_data(&self, aug_data: &AugData<D>) -> anyhow::Result<()> {
        self.aug_data
            .write()
            .insert(aug_data.id(), aug_data.clone());
        Ok(())
    }

    fn save_certified_aug_data(
        &self,
        certified_aug_data: &CertifiedAugData<D>,
    ) -> anyhow::Result<()> {
        self.certified_aug_data
            .write()
            .insert(certified_aug_data.id(), certified_aug_data.clone());
        Ok(())
    }

    fn get_key_pair_bytes(&self) -> anyhow::Result<Option<(u64, Vec<u8>)>> {
        Ok(self.key_pair.read().clone())
    }

    fn get_all_aug_data(&self) -> anyhow::Result<Vec<(AugDataId, AugData<D>)>> {
        Ok(self.aug_data.read().clone().into_iter().collect())
    }

    fn get_all_certified_aug_data(&self) -> anyhow::Result<Vec<(AugDataId, CertifiedAugData<D>)>> {
        Ok(self.certified_aug_data.read().clone().into_iter().collect())
    }

    fn remove_aug_data(&self, aug_data: Vec<AugData<D>>) -> anyhow::Result<()> {
        for data in aug_data {
            self.aug_data.write().remove(&data.id());
        }
        Ok(())
    }

    fn remove_certified_aug_data(
        &self,
        certified_aug_data: Vec<CertifiedAugData<D>>,
    ) -> anyhow::Result<()> {
        for data in certified_aug_data {
            self.certified_aug_data.write().remove(&data.id());
        }
        Ok(())
    }
}
```

**File:** consensus/src/rand/rand_gen/storage/db.rs (L85-121)
```rust
impl<D: TAugmentedData> RandStorage<D> for RandDb {
    fn save_key_pair_bytes(&self, epoch: u64, key_pair: Vec<u8>) -> Result<()> {
        Ok(self.put::<KeyPairSchema>(&(), &(epoch, key_pair))?)
    }

    fn save_aug_data(&self, aug_data: &AugData<D>) -> Result<()> {
        Ok(self.put::<AugDataSchema<D>>(&aug_data.id(), aug_data)?)
    }

    fn save_certified_aug_data(&self, certified_aug_data: &CertifiedAugData<D>) -> Result<()> {
        Ok(self.put::<CertifiedAugDataSchema<D>>(&certified_aug_data.id(), certified_aug_data)?)
    }

    fn get_key_pair_bytes(&self) -> Result<Option<(u64, Vec<u8>)>> {
        Ok(self.get_all::<KeyPairSchema>()?.pop().map(|(_, v)| v))
    }

    fn get_all_aug_data(&self) -> Result<Vec<(AugDataId, AugData<D>)>> {
        Ok(self.get_all::<AugDataSchema<D>>()?)
    }

    fn get_all_certified_aug_data(&self) -> Result<Vec<(AugDataId, CertifiedAugData<D>)>> {
        Ok(self.get_all::<CertifiedAugDataSchema<D>>()?)
    }

    fn remove_aug_data(&self, aug_data: Vec<AugData<D>>) -> Result<()> {
        Ok(self.delete::<AugDataSchema<D>>(aug_data.into_iter().map(|d| d.id()))?)
    }

    fn remove_certified_aug_data(
        &self,
        certified_aug_data: Vec<CertifiedAugData<D>>,
    ) -> Result<()> {
        Ok(self
            .delete::<CertifiedAugDataSchema<D>>(certified_aug_data.into_iter().map(|d| d.id()))?)
    }
}
```

**File:** consensus/src/error.rs (L7-18)
```rust
#[derive(Debug, Error)]
#[error(transparent)]
pub struct DbError {
    #[from]
    inner: anyhow::Error,
}

impl From<aptos_storage_interface::AptosDbError> for DbError {
    fn from(e: aptos_storage_interface::AptosDbError) -> Self {
        DbError { inner: e.into() }
    }
}
```

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L208-219)
```rust
    fn process_response(
        &self,
        protocol: ProtocolId,
        sender: oneshot::Sender<Result<Bytes, RpcError>>,
        message: RandMessage<S, D>,
    ) {
        let msg = message.into_network_message();
        let _ = sender.send(Ok(protocol
            .to_bytes(&msg)
            .expect("Message should be serializable into protocol")
            .into()));
    }
```

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L311-313)
```rust
        self.aug_data_store
            .add_aug_data(data.clone())
            .expect("Add self aug data should succeed");
```

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L441-450)
```rust
                            match self.aug_data_store.add_aug_data(aug_data) {
                                Ok(sig) => self.process_response(protocol, response_sender, RandMessage::AugDataSignature(sig)),
                                Err(e) => {
                                    if e.to_string().contains("[AugDataStore] equivocate data") {
                                        warn!("[RandManager] Failed to add aug data: {}", e);
                                    } else {
                                        error!("[RandManager] Failed to add aug data: {}", e);
                                    }
                                },
                            }
```

**File:** consensus/src/rand/rand_gen/aug_data_store.rs (L51-65)
```rust
        let all_data = db.get_all_aug_data().unwrap_or_default();
        let (to_remove, aug_data) = Self::filter_by_epoch(epoch, all_data.into_iter());
        if let Err(e) = db.remove_aug_data(to_remove) {
            error!("[AugDataStore] failed to remove aug data: {:?}", e);
        }

        let all_certified_data = db.get_all_certified_aug_data().unwrap_or_default();
        let (to_remove, certified_data) =
            Self::filter_by_epoch(epoch, all_certified_data.into_iter());
        if let Err(e) = db.remove_certified_aug_data(to_remove) {
            error!(
                "[AugDataStore] failed to remove certified aug data: {:?}",
                e
            );
        }
```
