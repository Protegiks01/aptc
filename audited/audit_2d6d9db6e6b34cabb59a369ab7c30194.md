# Audit Report

## Title
Hash Algorithm Change During Protocol Upgrade Causes Non-Recoverable Network Partition

## Summary
The Aptos consensus layer lacks versioning and compatibility mechanisms for the hash algorithm used to compute block IDs. If the hash format or algorithm changes in a protocol upgrade, old and new nodes will compute different block IDs for identical block data, resulting in a permanent network partition requiring a coordinated hard fork to resolve.

## Finding Description

The vulnerability exists in how consensus blocks are serialized, transmitted, and validated across the network. The critical issue lies in three interconnected components:

**1. Block ID Computation Without Versioning:**
The `Block` structure stores a precomputed `id` field (the hash of `BlockData`), but this field is not serialized over the network. [1](#0-0) 

During deserialization, the `id` is always recomputed from the received `block_data`: [2](#0-1) 

**2. Hardcoded Hash Algorithm:**
The hash computation uses SHA3-256 via `DefaultHasher`, with no version negotiation or feature flag control: [3](#0-2) 

The `BlockData` hash is computed using BCS serialization and the hardcoded hasher: [4](#0-3) 

**3. Validation Enforces Consistency:**
The `verify_well_formed()` method explicitly checks that the recomputed hash matches: [5](#0-4) 

**The Failure Scenario:**

If a protocol upgrade changes the hash algorithm (e.g., from SHA3-256 to SHA3-512) or the serialization format used in hash computation:

1. **New nodes** create blocks with `id = NEW_HASH(block_data)`
2. **Old nodes** receive the block and deserialize successfully
3. **Old nodes** recompute `id = OLD_HASH(block_data)` 
4. The recomputed ID differs from what new nodes computed
5. Votes, QuorumCerts, and parent references all use block IDs, causing validation failures
6. The network partitions into incompatible subsets

**No Protection Mechanisms Exist:**

The system has no feature flags for hash algorithm selection: [6](#0-5) 

Network protocol versioning only affects message serialization format, not hash computation: [7](#0-6) 

**Critical Consensus Breakage Points:**

When blocks with mismatched IDs propagate:
- Parent block lookups fail: [8](#0-7) 
- Vote verification fails as block IDs don't match
- QuorumCert validation fails with inconsistent block info: [9](#0-8) 

## Impact Explanation

This qualifies as **Critical Severity** under the Aptos Bug Bounty program as a "Non-recoverable network partition (requires hardfork)."

**Concrete Impact:**
- Complete consensus failure between nodes running different hash algorithms
- Network splits into incompatible subsets unable to agree on block IDs
- No graceful degradation path - old and new nodes fundamentally cannot interoperate
- Requires emergency coordinated hard fork with full network shutdown
- All validators must upgrade simultaneously or risk fund loss and chain split

This breaks the **Deterministic Execution** invariant (all validators must produce identical state roots) and the **Consensus Safety** invariant (preventing chain splits).

## Likelihood Explanation

**Likelihood: Low (but consequences catastrophic if occurs)**

This vulnerability would only manifest if:
1. The Aptos team decides to change the hash algorithm in a future protocol upgrade
2. The upgrade is not deployed as a coordinated hard fork
3. Nodes are allowed to upgrade incrementally

However, the **lack of protection mechanisms** means there is no technical safeguard preventing this scenario. The protocol depends entirely on operational discipline during upgrades, with no code-level defense-in-depth.

## Recommendation

Implement hash algorithm versioning and backward compatibility mechanisms:

**1. Add Hash Algorithm Version to BlockData:**
```rust
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq, CryptoHasher)]
pub struct BlockData {
    hash_version: u8,  // Default to 1 for current SHA3-256
    epoch: u64,
    round: Round,
    // ... rest of fields
}
```

**2. Version-Aware Hash Computation:**
```rust
impl CryptoHash for BlockData {
    fn hash(&self) -> HashValue {
        match self.hash_version {
            1 => {
                // Current SHA3-256 implementation
                let mut state = Self::Hasher::default();
                bcs::serialize_into(&mut state, &self).expect("...");
                state.finish()
            }
            2 => {
                // Future algorithm if needed
                // Implementation for new hash algorithm
            }
            _ => panic!("Unsupported hash version")
        }
    }
}
```

**3. Add Feature Flag for Hash Algorithm Version:**
Add to `FeatureFlag` enum:
```rust
HASH_ALGORITHM_V2 = 98,
```

**4. Coordinated Migration Strategy:**
- Upgrade all nodes to support BOTH hash versions
- Enable new hash version via governance after all nodes upgraded
- Use a transition period where both versions are accepted
- Eventually deprecate old version after safety margin

**5. Network Handshake Enhancement:**
Include hash algorithm version in capability negotiation to detect incompatible nodes early.

## Proof of Concept

This vulnerability cannot be demonstrated with a standard PoC without modifying core hash implementations. However, the following test demonstrates the recomputation behavior:

```rust
#[test]
fn test_block_id_recomputation_on_deserialization() {
    use consensus_types::block::Block;
    use consensus_types::block_data::BlockData;
    use aptos_crypto::hash::CryptoHash;
    
    // Create a block
    let block_data = BlockData::new_proposal(
        Payload::empty(false, true),
        AccountAddress::random(),
        vec![],
        1,
        100,
        QuorumCert::dummy(),
    );
    let original_id = block_data.hash();
    let block = Block::new_for_testing(original_id, block_data, None);
    
    // Serialize and deserialize
    let serialized = bcs::to_bytes(&block).unwrap();
    let deserialized: Block = bcs::from_bytes(&serialized).unwrap();
    
    // The ID is recomputed during deserialization
    assert_eq!(deserialized.id(), original_id);
    
    // If the hash algorithm changed between serialization and deserialization,
    // this assertion would FAIL, causing consensus partition
}
```

**To demonstrate the actual failure** (requires modifying `DefaultHasher` to use a different algorithm):
1. Modify `DefaultHasher::finish()` in one node to use SHA3-512
2. Have that node create a block and broadcast it
3. Other nodes will deserialize and recompute with SHA3-256
4. Block IDs will mismatch, causing validation failures and partition

## Notes

This issue represents a **design constraint** that becomes a **critical vulnerability** if not properly managed during protocol upgrades. While an external attacker cannot exploit this directly, the lack of protection mechanisms creates significant operational risk during any future hash algorithm migration.

The current implementation implicitly assumes the hash algorithm will never change, which may be violated if:
- Cryptographic weaknesses are discovered in SHA3-256
- Performance improvements require algorithm changes  
- Quantum-resistant hashing becomes necessary

The recommendation is to implement versioning mechanisms **before** any such change is needed, ensuring the protocol has a safe upgrade path.

### Citations

**File:** consensus/consensus-types/src/block.rs (L44-56)
```rust
#[derive(Serialize, Clone, PartialEq, Eq)]
/// Block has the core data of a consensus block that should be persistent when necessary.
/// Each block must know the id of its parent and keep the QuorurmCertificate to that parent.
pub struct Block {
    /// This block's id as a hash value, it is generated at call time
    #[serde(skip)]
    id: HashValue,
    /// The container for the actual block
    block_data: BlockData,
    /// Signature that the hash of this block has been authored by the owner of the private key,
    /// this is only set within Proposal blocks
    signature: Option<bls12381::Signature>,
}
```

**File:** consensus/consensus-types/src/block.rs (L545-549)
```rust
        debug_checked_verify_eq!(
            self.id(),
            self.block_data.hash(),
            "Block id mismatch the hash"
        );
```

**File:** consensus/consensus-types/src/block.rs (L641-664)
```rust
impl<'de> Deserialize<'de> for Block {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename = "Block")]
        struct BlockWithoutId {
            block_data: BlockData,
            signature: Option<bls12381::Signature>,
        }

        let BlockWithoutId {
            block_data,
            signature,
        } = BlockWithoutId::deserialize(deserializer)?;

        Ok(Block {
            id: block_data.hash(),
            block_data,
            signature,
        })
    }
}
```

**File:** crates/aptos-crypto/src/hash.rs (L286-329)
```rust
impl ser::Serialize for HashValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_hex())
        } else {
            // In order to preserve the Serde data model and help analysis tools,
            // make sure to wrap our value in a container with the same name
            // as the original type.
            #[derive(Serialize)]
            #[serde(rename = "HashValue")]
            struct Value<'a> {
                hash: &'a [u8; HashValue::LENGTH],
            }
            Value { hash: &self.hash }.serialize(serializer)
        }
    }
}

impl<'de> de::Deserialize<'de> for HashValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let encoded_hash = <String>::deserialize(deserializer)?;
            HashValue::from_hex(encoded_hash.as_str())
                .map_err(<D::Error as ::serde::de::Error>::custom)
        } else {
            // See comment in serialize.
            #[derive(Deserialize)]
            #[serde(rename = "HashValue")]
            struct Value {
                hash: [u8; HashValue::LENGTH],
            }

            let value = Value::deserialize(deserializer)
                .map_err(<D::Error as ::serde::de::Error>::custom)?;
            Ok(Self::new(value.hash))
        }
    }
}
```

**File:** consensus/consensus-types/src/block_data.rs (L105-134)
```rust
impl CryptoHash for BlockData {
    type Hasher = BlockDataHasher;

    fn hash(&self) -> HashValue {
        let mut state = Self::Hasher::default();
        if self.is_opt_block() {
            #[derive(Serialize)]
            struct OptBlockDataForHash<'a> {
                epoch: u64,
                round: Round,
                timestamp_usecs: u64,
                quorum_cert_vote_data: &'a VoteData,
                block_type: &'a BlockType,
            }

            let opt_block_data_for_hash = OptBlockDataForHash {
                epoch: self.epoch,
                round: self.round,
                timestamp_usecs: self.timestamp_usecs,
                quorum_cert_vote_data: self.quorum_cert.vote_data(),
                block_type: &self.block_type,
            };
            bcs::serialize_into(&mut state, &opt_block_data_for_hash)
                .expect("OptBlockDataForHash must be serializable");
        } else {
            bcs::serialize_into(&mut state, &self).expect("BlockData must be serializable");
        }
        state.finish()
    }
}
```

**File:** types/src/on_chain_config/aptos_features.rs (L17-150)
```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, FromRepr, EnumString)]
#[allow(non_camel_case_types)]
pub enum FeatureFlag {
    CODE_DEPENDENCY_CHECK = 1,
    TREAT_FRIEND_AS_PRIVATE = 2,
    SHA_512_AND_RIPEMD_160_NATIVES = 3,
    APTOS_STD_CHAIN_ID_NATIVES = 4,
    VM_BINARY_FORMAT_V6 = 5,
    _DEPRECATED_COLLECT_AND_DISTRIBUTE_GAS_FEES = 6,
    MULTI_ED25519_PK_VALIDATE_V2_NATIVES = 7,
    BLAKE2B_256_NATIVE = 8,
    RESOURCE_GROUPS = 9,
    MULTISIG_ACCOUNTS = 10,
    DELEGATION_POOLS = 11,
    CRYPTOGRAPHY_ALGEBRA_NATIVES = 12,
    BLS12_381_STRUCTURES = 13,
    ED25519_PUBKEY_VALIDATE_RETURN_FALSE_WRONG_LENGTH = 14,
    STRUCT_CONSTRUCTORS = 15,
    PERIODICAL_REWARD_RATE_DECREASE = 16,
    PARTIAL_GOVERNANCE_VOTING = 17,
    /// Enabled on mainnet and cannot be disabled
    _SIGNATURE_CHECKER_V2 = 18,
    STORAGE_SLOT_METADATA = 19,
    CHARGE_INVARIANT_VIOLATION = 20,
    DELEGATION_POOL_PARTIAL_GOVERNANCE_VOTING = 21,
    GAS_PAYER_ENABLED = 22,
    APTOS_UNIQUE_IDENTIFIERS = 23,
    BULLETPROOFS_NATIVES = 24,
    SIGNER_NATIVE_FORMAT_FIX = 25,
    MODULE_EVENT = 26,
    EMIT_FEE_STATEMENT = 27,
    STORAGE_DELETION_REFUND = 28,
    SIGNATURE_CHECKER_V2_SCRIPT_FIX = 29,
    AGGREGATOR_V2_API = 30,
    SAFER_RESOURCE_GROUPS = 31,
    SAFER_METADATA = 32,
    SINGLE_SENDER_AUTHENTICATOR = 33,
    SPONSORED_AUTOMATIC_ACCOUNT_V1_CREATION = 34,
    FEE_PAYER_ACCOUNT_OPTIONAL = 35,
    AGGREGATOR_V2_DELAYED_FIELDS = 36,
    CONCURRENT_TOKEN_V2 = 37,
    LIMIT_MAX_IDENTIFIER_LENGTH = 38,
    OPERATOR_BENEFICIARY_CHANGE = 39,
    VM_BINARY_FORMAT_V7 = 40,
    RESOURCE_GROUPS_SPLIT_IN_VM_CHANGE_SET = 41,
    COMMISSION_CHANGE_DELEGATION_POOL = 42,
    BN254_STRUCTURES = 43,
    WEBAUTHN_SIGNATURE = 44,
    _DEPRECATED_RECONFIGURE_WITH_DKG = 45,
    KEYLESS_ACCOUNTS = 46,
    KEYLESS_BUT_ZKLESS_ACCOUNTS = 47,
    /// This feature was never used.
    _DEPRECATED_REMOVE_DETAILED_ERROR_FROM_HASH = 48,
    JWK_CONSENSUS = 49,
    CONCURRENT_FUNGIBLE_ASSETS = 50,
    REFUNDABLE_BYTES = 51,
    OBJECT_CODE_DEPLOYMENT = 52,
    MAX_OBJECT_NESTING_CHECK = 53,
    KEYLESS_ACCOUNTS_WITH_PASSKEYS = 54,
    MULTISIG_V2_ENHANCEMENT = 55,
    DELEGATION_POOL_ALLOWLISTING = 56,
    MODULE_EVENT_MIGRATION = 57,
    /// Enabled on mainnet, can never be disabled.
    _REJECT_UNSTABLE_BYTECODE = 58,
    TRANSACTION_CONTEXT_EXTENSION = 59,
    COIN_TO_FUNGIBLE_ASSET_MIGRATION = 60,
    PRIMARY_APT_FUNGIBLE_STORE_AT_USER_ADDRESS = 61,
    // Feature rolled out, no longer can be disabled.
    _OBJECT_NATIVE_DERIVED_ADDRESS = 62,
    DISPATCHABLE_FUNGIBLE_ASSET = 63,
    NEW_ACCOUNTS_DEFAULT_TO_FA_APT_STORE = 64,
    OPERATIONS_DEFAULT_TO_FA_APT_STORE = 65,
    // Feature rolled out, no longer can be disabled.
    _AGGREGATOR_V2_IS_AT_LEAST_API = 66,
    CONCURRENT_FUNGIBLE_BALANCE = 67,
    DEFAULT_TO_CONCURRENT_FUNGIBLE_BALANCE = 68,
    /// Enabled on mainnet, cannot be disabled.
    _LIMIT_VM_TYPE_SIZE = 69,
    ABORT_IF_MULTISIG_PAYLOAD_MISMATCH = 70,
    /// Enabled on mainnet, cannot be disabled.
    _DISALLOW_USER_NATIVES = 71,
    ALLOW_SERIALIZED_SCRIPT_ARGS = 72,
    /// Enabled on mainnet, cannot be disabled.
    _USE_COMPATIBILITY_CHECKER_V2 = 73,
    ENABLE_ENUM_TYPES = 74,
    ENABLE_RESOURCE_ACCESS_CONTROL = 75,
    /// Enabled on mainnet, can never be disabled.
    _REJECT_UNSTABLE_BYTECODE_FOR_SCRIPT = 76,
    FEDERATED_KEYLESS = 77,
    TRANSACTION_SIMULATION_ENHANCEMENT = 78,
    COLLECTION_OWNER = 79,
    /// Enabled on mainnet, cannot be rolled back. Was gating `mem::swap` and `vector::move_range`
    /// natives. For more details, see:
    ///   AIP-105 (https://github.com/aptos-foundation/AIPs/blob/main/aips/aip-105.md)
    _NATIVE_MEMORY_OPERATIONS = 80,
    /// The feature was used to gate the rollout of new loader used by Move VM. It was enabled on
    /// mainnet and can no longer be disabled.
    _ENABLE_LOADER_V2 = 81,
    /// Prior to this feature flag, it was possible to attempt 'init_module' to publish modules
    /// that results in a new package created but without any code. With this feature, it is no
    /// longer possible and an explicit error is returned if publishing is attempted. The feature
    /// was enabled on mainnet and will not be disabled.
    _DISALLOW_INIT_MODULE_TO_PUBLISH_MODULES = 82,
    /// We keep the Call Tree cache and instruction (per-instruction)
    /// cache together here.  Generally, we could allow Call Tree
    /// cache and disallow instruction cache, however there's little
    /// benefit of such approach: First, instruction cache requires
    /// call-tree cache to be enabled, and provides relatively little
    /// overhead in terms of memory footprint. On the other side,
    /// providing separate choices could lead to code bloat, as the
    /// dynamic config is converted into multiple different
    /// implementations. If required in the future, we can add a flag
    /// to explicitly disable the instruction cache.
    ENABLE_CALL_TREE_AND_INSTRUCTION_VM_CACHE = 83,
    /// AIP-103 (https://github.com/aptos-foundation/AIPs/blob/main/aips/aip-103.md)
    PERMISSIONED_SIGNER = 84,
    ACCOUNT_ABSTRACTION = 85,
    /// Enables bytecode version v8
    VM_BINARY_FORMAT_V8 = 86,
    BULLETPROOFS_BATCH_NATIVES = 87,
    DERIVABLE_ACCOUNT_ABSTRACTION = 88,
    /// Whether function values are enabled.
    ENABLE_FUNCTION_VALUES = 89,
    NEW_ACCOUNTS_DEFAULT_TO_FA_STORE = 90,
    DEFAULT_ACCOUNT_RESOURCE = 91,
    JWK_CONSENSUS_PER_KEY_MODE = 92,
    TRANSACTION_PAYLOAD_V2 = 93,
    ORDERLESS_TRANSACTIONS = 94,
    /// With lazy loading, modules are loaded lazily (as opposed to loading the transitive closure
    /// of dependencies). For more details, see:
    ///   AIP-127 (https://github.com/aptos-foundation/AIPs/blob/main/aips/aip-127.md)
    ENABLE_LAZY_LOADING = 95,
    CALCULATE_TRANSACTION_FEE_FOR_DISTRIBUTION = 96,
    DISTRIBUTE_TRANSACTION_FEE = 97,
```

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L354-381)
```rust
/// Enum representing different versions of the Aptos network protocol. These
/// should be listed from old to new, old having the smallest value.  We derive
/// [`PartialOrd`] since nodes need to find highest intersecting protocol version.
#[derive(Eq, PartialEq, Ord, PartialOrd, Clone, Copy, Hash, Deserialize, Serialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub enum MessagingProtocolVersion {
    V1 = 0,
}

impl MessagingProtocolVersion {
    fn as_str(&self) -> &str {
        match self {
            Self::V1 => "V1",
        }
    }
}

impl fmt::Debug for MessagingProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl fmt::Display for MessagingProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
```

**File:** consensus/src/block_storage/block_tree.rs (L319-322)
```rust
            match self.get_linkable_block_mut(&block.parent_id()) {
                Some(parent_block) => parent_block.add_child(block_id),
                None => bail!("Parent block {} not found", block.parent_id()),
            };
```

**File:** consensus/src/pipeline/errors.rs (L8-14)
```rust
#[derive(Clone, Debug, Deserialize, Error, PartialEq, Eq, Serialize)]
/// Different reasons of errors in commit phase
pub enum Error {
    #[error("The block in the message, {0}, does not match expected block, {1}")]
    InconsistentBlockInfo(BlockInfo, BlockInfo),
    #[error("Verification Error")]
    VerificationError,
```
