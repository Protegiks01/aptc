# Audit Report

## Title
Feature-Dependent StateKey Deserialization Causes Non-Deterministic State Sync Across Nodes

## Summary
The `StateKey` deserialization logic contains compile-time feature-dependent behavior that causes nodes with different build configurations to deserialize identical state data differently, violating the deterministic execution invariant and potentially causing state sync failures and consensus divergence.

## Finding Description

The `StateKey::from_deserialized()` method in [1](#0-0)  contains conditional compilation logic that behaves differently based on whether the `fuzzing` feature is enabled: [2](#0-1) 

When deserializing a `StateKey` with an invalid `AccessPath`:
- Nodes compiled **with** `fuzzing` feature: Convert to `Raw` variant
- Nodes compiled **without** `fuzzing` feature: Return an error

This method is invoked through the BCS deserialization trait implementation: [3](#0-2) 

The critical data flow occurs during state synchronization, where `TransactionOutput` structures (containing `WriteSet`) are serialized and transmitted between nodes: [4](#0-3) 

The `WriteSet` internally uses `BTreeMap<StateKey, WriteOp>`: [5](#0-4) 

During state sync, nodes exchange `TransactionOutputsWithProof` messages that undergo BCS serialization/deserialization, triggering the feature-dependent `StateKey` deserialization logic.

**Breaking the Invariant:**
This violates the **Deterministic Execution** invariant: "All validators must produce identical state roots for identical blocks." If validators have inconsistent build configurations, they will deserialize the same state data into different internal representations, leading to state divergence.

## Impact Explanation

**Severity: Critical** (but unlikely in practice)

If exploited, this vulnerability would cause:
- **State Sync Failures**: Nodes with different build configurations would fail to synchronize state
- **Consensus Splits**: Validators would compute different state roots from identical transaction outputs
- **Network Partition**: The network could split into incompatible validator subsets based on build configuration

This meets the **Critical Severity** criteria of "Consensus/Safety violations" and "Non-recoverable network partition (requires hardfork)."

## Likelihood Explanation

**Likelihood: Very Low**

The vulnerability requires one of the following scenarios:
1. **Operational Error**: A validator operator accidentally compiles their node with `--features fuzzing`
2. **Compromised Build Pipeline**: An attacker compromises the build/CI system to enable fuzzing in production binaries
3. **Insider Threat**: A malicious developer intentionally deploys misconfigured binaries

Production validator builds explicitly exclude the fuzzing feature: [6](#0-5) 

The coding guidelines explicitly prohibit fuzzing in production: [7](#0-6) 

**Critical Validation Failure**: This vulnerability does **NOT** meet the bug bounty criterion: "Exploitable by unprivileged attacker (no validator insider access required)." It requires privileged access to the build/deployment infrastructure or operational misconfiguration by validator operators.

## Recommendation

Despite the low likelihood, the code should be hardened to prevent feature-dependent behavior in consensus-critical paths:

1. **Remove feature-dependent logic from StateKey deserialization**:
   - Remove the `cfg!(feature = "fuzzing")` conditional in `from_deserialized()`
   - Always return an error for invalid AccessPath data
   - Move fuzzing-specific test helpers to test-only modules

2. **Add runtime assertions**:
   ```rust
   // In validator startup code
   #[cfg(feature = "fuzzing")]
   compile_error!("The 'fuzzing' feature must not be enabled in production builds");
   ```

3. **CI/CD enforcement**:
   - Add CI checks to verify production builds don't have test-only features enabled
   - Implement build signature verification to detect unauthorized build configurations

## Proof of Concept

This is a configuration vulnerability that cannot be demonstrated through a standard Move or Rust test without building multiple node binaries with different feature flags. However, the vulnerable code path can be traced as follows:

1. Create a `TransactionOutput` with an invalid `AccessPath` in a `StateKey`
2. Serialize it using BCS on Node A (with fuzzing enabled)
3. Transmit to Node B (without fuzzing enabled) via state sync
4. Node B attempts deserialization and fails, while Node A succeeds

The vulnerability is present in the code but requires specific build misconfiguration to trigger.

---

**Note**: While this represents a genuine design flaw where feature flags affect consensus-critical deserialization logic, it fails the validation criterion of being "exploitable by unprivileged attacker." The vulnerability requires either operational error, compromised infrastructure, or insider access to manifest, placing it outside the scope of typical bug bounty submissions focused on externally exploitable vulnerabilities.

### Citations

**File:** types/src/state_store/state_key/mod.rs (L110-137)
```rust
    pub fn from_deserialized(deserialized: StateKeyInner) -> Result<Self> {
        use access_path::Path;

        let myself = match deserialized {
            StateKeyInner::AccessPath(AccessPath { address, path }) => {
                match bcs::from_bytes::<Path>(&path) {
                    Err(err) => {
                        if cfg!(feature = "fuzzing") {
                            // note: to make analyze-serde-formats test happy, do not error out
                            //       alternative is to wrap `AccessPath::path: Vec<u8>` in an enum
                            Self::raw(&bcs::to_bytes(&(address, path)).unwrap())
                        } else {
                            return Err(err.into());
                        }
                    },
                    Ok(Path::Code(module_id)) => Self::module_id(&module_id),
                    Ok(Path::Resource(struct_tag)) => Self::resource(&address, &struct_tag)?,
                    Ok(Path::ResourceGroup(struct_tag)) => {
                        Self::resource_group(&address, &struct_tag)
                    },
                }
            },
            StateKeyInner::TableItem { handle, key } => Self::table_item(&handle, &key),
            StateKeyInner::Raw(bytes) => Self::raw(&bytes),
        };

        Ok(myself)
    }
```

**File:** types/src/state_store/state_key/mod.rs (L251-259)
```rust
impl<'de> Deserialize<'de> for StateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let inner = StateKeyInner::deserialize(deserializer)?;
        Self::from_deserialized(inner).map_err(Error::custom)
    }
}
```

**File:** types/src/transaction/mod.rs (L1766-1783)
```rust
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransactionOutput {
    /// The list of writes this transaction intends to do.
    write_set: WriteSet,

    /// The list of events emitted during this transaction.
    events: Vec<ContractEvent>,

    /// The amount of gas used during execution.
    gas_used: u64,

    /// The execution status. The detailed error info will not be stored here instead will be stored in the auxiliary data.
    status: TransactionStatus,

    /// The transaction auxiliary data that includes detail error info that is not used for calculating the hash
    #[serde(skip)]
    auxiliary_data: TransactionAuxiliaryData,
}
```

**File:** types/src/write_set.rs (L745-749)
```rust
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct WriteSetMut {
    // TODO: Change to HashMap with a stable iterator for serialization.
    write_set: BTreeMap<StateKey, WriteOp>,
}
```

**File:** docker/release-images.mjs (L56-74)
```javascript
const IMAGES_TO_RELEASE = {
  validator: {
    [CargoBuildProfiles.Performance]: [CargoBuildFeatures.Default],
    [CargoBuildProfiles.Release]: [CargoBuildFeatures.Default],
  },
  "validator-testing": {
    [CargoBuildProfiles.Performance]: [CargoBuildFeatures.Default],
    [CargoBuildProfiles.Release]: [CargoBuildFeatures.Default],
  },
  faucet: {
    [CargoBuildProfiles.Release]: [CargoBuildFeatures.Default],
  },
  tools: {
    [CargoBuildProfiles.Release]: [CargoBuildFeatures.Default],
  },
  "indexer-grpc": {
    [CargoBuildProfiles.Release]: [CargoBuildFeatures.Default],
  },
};
```

**File:** RUST_CODING_STYLE.md (L295-298)
```markdown
- the `fuzzing` custom feature, which is used to enable fuzzing and testing
  related code in downstream crates. Note that this must be passed explicitly to
  `cargo xtest` and `cargo x bench`. Never use this in `[dependencies]` unless
  the crate is only for testing.
```
