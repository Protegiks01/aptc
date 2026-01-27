> Searching codebase... [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8) [10](#0-9) [11](#0-10) [12](#0-11) [13](#0-12)

### Citations

**File:** third_party/move/move-vm/runtime/src/native_extensions.rs (L6-7)
```rust
use better_any::{Tid, TidAble, TidExt};
use std::{any::TypeId, collections::HashMap};
```

**File:** third_party/move/move-vm/runtime/src/native_extensions.rs (L29-35)
```rust
/// Any native extension should implement its interaction with the [SessionListener]. This way when
/// a new extension gets added there is a compile-time error when one tries to add it to the native
/// context.
pub trait NativeSessionListener<'a>: SessionListener + Tid<'a> {}

impl<'a, T> NativeSessionListener<'a> for T where T: SessionListener + Tid<'a> {}

```

**File:** third_party/move/move-vm/runtime/src/native_extensions.rs (L72-78)
```rust
#[derive(Default)]
pub struct NativeContextExtensions<'a> {
    map: HashMap<TypeId, Box<dyn NativeSessionListener<'a>>>,
    /// To enable runtime reference checks, we include models for native functions that
    /// return references. See documentation for `NativeRuntimeRefChecksModel` for details.
    native_runtime_ref_checks_model: NativeRuntimeRefChecksModel,
}
```

**File:** third_party/move/move-vm/runtime/src/native_extensions.rs (L81-147)
```rust
    pub fn add<T: SessionListener + TidAble<'a> + NativeRuntimeRefCheckModelsCompleted>(
        &mut self,
        ext: T,
    ) {
        assert!(
            self.map.insert(T::id(), Box::new(ext)).is_none(),
            "multiple extensions of the same type not allowed"
        )
    }

    pub fn get<T: SessionListener + TidAble<'a>>(&self) -> &T {
        self.map
            .get(&T::id())
            .expect("extension unknown")
            .as_ref()
            .downcast_ref::<T>()
            .unwrap()
    }

    pub fn get_mut<T: SessionListener + TidAble<'a>>(&mut self) -> &mut T {
        self.map
            .get_mut(&T::id())
            .expect("extension unknown")
            .as_mut()
            .downcast_mut::<T>()
            .unwrap()
    }

    pub fn remove<T: SessionListener + TidAble<'a>>(&mut self) -> T {
        // can't use expect below because it requires `T: Debug`.
        match self
            .map
            .remove(&T::id())
            .expect("extension unknown")
            .downcast_box::<T>()
        {
            Ok(val) => *val,
            Err(_) => panic!("downcast error"),
        }
    }

    pub fn for_each_mut<F>(&mut self, f: F)
    where
        F: Fn(&mut dyn SessionListener),
    {
        for extension in self.map.values_mut() {
            f(extension.as_mut());
        }
    }

    /// Get all the native runtime ref checks models.
    pub fn get_native_runtime_ref_checks_model(&self) -> NativeRuntimeRefChecksModel {
        self.native_runtime_ref_checks_model.clone()
    }

    /// Add a runtime ref checks model for the given native function.
    #[allow(dead_code)]
    pub fn add_native_runtime_ref_checks_model(
        &mut self,
        module_name: &'static str,
        function_name: &'static str,
        model: Vec<usize>,
    ) {
        self.native_runtime_ref_checks_model
            .add_model_for_native_function(module_name, function_name, model);
    }
}
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/mod.rs (L73-78)
```rust
pub struct SessionExt<'r, R> {
    data_cache: TransactionDataCache,
    extensions: NativeContextExtensions<'r>,
    pub(crate) resolver: &'r R,
    is_storage_slot_metadata_enabled: bool,
}
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/mod.rs (L84-107)
```rust
    pub(crate) fn new(
        session_id: SessionId,
        chain_id: ChainId,
        features: &Features,
        vm_config: &VMConfig,
        maybe_user_transaction_context: Option<UserTransactionContext>,
        resolver: &'r R,
    ) -> Self {
        let extensions = make_aptos_extensions(
            resolver,
            chain_id,
            vm_config,
            session_id,
            maybe_user_transaction_context,
        );

        let is_storage_slot_metadata_enabled = features.is_storage_slot_metadata_enabled();
        Self {
            data_cache: TransactionDataCache::empty(),
            extensions,
            resolver,
            is_storage_slot_metadata_enabled,
        }
    }
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/mod.rs (L109-138)
```rust
    pub fn execute_function_bypass_visibility(
        &mut self,
        module_id: &ModuleId,
        function_name: &IdentStr,
        ty_args: Vec<TypeTag>,
        args: Vec<impl Borrow<[u8]>>,
        gas_meter: &mut impl GasMeter,
        traversal_context: &mut TraversalContext,
        module_storage: &impl ModuleStorage,
    ) -> VMResult<SerializedReturnValues> {
        dispatch_loader!(module_storage, loader, {
            let func = loader.load_instantiated_function(
                &LegacyLoaderConfig::unmetered(),
                gas_meter,
                traversal_context,
                module_id,
                function_name,
                &ty_args,
            )?;
            MoveVM::execute_loaded_function(
                func,
                args,
                &mut MoveVmDataCacheAdapter::new(&mut self.data_cache, self.resolver, &loader),
                gas_meter,
                traversal_context,
                &mut self.extensions,
                &loader,
            )
        })
    }
```

**File:** third_party/move/move-model/src/model.rs (L733-733)
```rust
        let id = TypeId::of::<T>();
```

**File:** third_party/move/move-model/src/model.rs (L743-743)
```rust
        let id = TypeId::of::<T>();
```

**File:** third_party/move/move-model/src/model.rs (L752-752)
```rust
        let id = TypeId::of::<T>();
```

**File:** third_party/move/move-model/src/model.rs (L767-767)
```rust
        let id = TypeId::of::<T>();
```

**File:** third_party/move/move-model/src/model.rs (L783-783)
```rust
        let id = TypeId::of::<T>();
```

**File:** third_party/move/move-model/src/model.rs (L791-791)
```rust
        let id = TypeId::of::<T>();
```
