# Audit Report

## Title
Missing Cryptographic Integrity Verification for Framework Release Bundles Enables Supply Chain Attacks During Genesis Generation

## Summary
The Aptos framework release bundle files (`testnet.mrb`, `mainnet.mrb`, `framework.mrb`) loaded during genesis generation lack cryptographic signature verification or hash-based integrity checks. An attacker who compromises the build pipeline or distribution mechanism can replace these files with malicious Move bytecode that would be deployed to system addresses during genesis, completely compromising the blockchain from inception.

## Finding Description

The `testnet_release_bundle()` function loads the testnet framework bundle from disk without any integrity verification: [1](#0-0) 

The function simply reads the file and deserializes it using BCS. There is no cryptographic signature verification, no hash comparison against known-good values, and no other integrity checking mechanism.

This framework bundle is subsequently used in genesis generation for both testnet and mainnet: [2](#0-1) 

The bytecode from these bundles is published during genesis at system addresses with full privileges: [3](#0-2) 

The only verification performed is Move bytecode structural verification via `StagingModuleStorage::create()`, which validates that bytecode is well-formed but does NOT verify its authenticity or provenance: [4](#0-3) 

**Attack Path:**
1. Attacker compromises CI/CD pipeline or build environment
2. Attacker replaces `testnet.mrb` or `framework.mrb` with malicious version containing:
   - Modified `aptos_coin.move` to enable unauthorized minting
   - Modified `aptos_governance.move` to bypass voting requirements
   - Modified `stake.move` to manipulate validator rewards
   - Backdoors in any system module at address `0x1`
3. The malicious bytecode passes Move's structural verification (it's valid bytecode)
4. Genesis is generated using the CLI tool: [5](#0-4) 

5. The framework is loaded from the git repository or local filesystem: [6](#0-5) 

6. All validators execute the malicious genesis, deploying compromised framework modules
7. The attacker now controls system-level functionality across the entire network

This breaks multiple critical invariants:
- **Deterministic Execution**: Malicious code could introduce non-determinism
- **State Consistency**: Backdoors could corrupt state
- **Access Control**: System addresses (@aptos_framework) are compromised
- **Governance Integrity**: Voting and proposal mechanisms can be manipulated

## Impact Explanation

This vulnerability meets **Critical Severity** criteria per the Aptos bug bounty program:

1. **Loss of Funds**: Attacker can modify coin minting logic to create unlimited APT tokens or steal from any account via backdoored transfer functions

2. **Consensus/Safety Violations**: Malicious bytecode could introduce consensus-breaking logic, causing chain splits between validators who detect the issue and those who don't

3. **Non-recoverable Network Partition**: If the malicious genesis is widely deployed, recovery requires a complete chain restart with trusted genesis, effectively a hard fork that discards all state

4. **Remote Code Execution**: While not direct RCE, malicious Move bytecode executing at system privilege level provides equivalent control over blockchain state and validator behavior

The impact extends to all validators and all users of the network, as the compromise occurs at genesis before any legitimate transactions are processed.

## Likelihood Explanation

**Likelihood: Medium-High**

Supply chain attacks targeting build pipelines are increasingly common:
- SolarWinds (2020)
- CodeCov (2021)
- UA-Parser-JS npm package (2021)

The attack requires:
- Compromise of CI/CD infrastructure (GitHub Actions, build servers)
- OR compromise of developer workstation used for release generation
- OR man-in-the-middle attack on framework distribution (if downloaded from GitHub)

Factors increasing likelihood:
- `.mrb` files are binary blobs, making manual inspection difficult
- No automated integrity verification in the codebase
- Genesis generation happens infrequently, reducing scrutiny
- The malicious code could be subtle (e.g., off-by-one in reward calculation)

Factors decreasing likelihood:
- Requires sophisticated attacker with build infrastructure access
- Aptos Foundation likely has security controls around release processes
- Community review of genesis before mainnet launch

However, the complete lack of integrity verification means ANY compromise of the distribution path succeeds without detection.

## Recommendation

Implement cryptographic integrity verification for all framework release bundles:

**1. Sign release bundles with an offline key during official releases:**

```rust
// In release_builder.rs
use aptos_crypto::{ed25519::Ed25519PrivateKey, Signature, SigningKey};

pub struct SignedReleaseBundle {
    pub bundle: ReleaseBundle,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl ReleaseOptions {
    pub fn create_signed_release(self, signing_key: &Ed25519PrivateKey) -> anyhow::Result<SignedReleaseBundle> {
        // Create bundle as before
        let bundle = self.create_release_internal()?;
        
        // Sign the serialized bundle
        let bundle_bytes = bcs::to_bytes(&bundle)?;
        let signature = signing_key.sign(&bundle_bytes);
        
        Ok(SignedReleaseBundle {
            bundle,
            signature: signature.to_bytes().to_vec(),
            public_key: signing_key.public_key().to_bytes().to_vec(),
        })
    }
}
```

**2. Embed trusted public keys in the codebase:**

```rust
// In released_framework.rs
use aptos_crypto::{ed25519::Ed25519PublicKey, Signature, VerifyingKey};

// Hardcoded public keys for official releases (managed via governance for updates)
const TESTNET_RELEASE_PUBKEY: &str = "0x..."; // Official testnet signing key
const MAINNET_RELEASE_PUBKEY: &str = "0x..."; // Official mainnet signing key

static TESTNET_RELEASE_BUNDLE: Lazy<ReleaseBundle> = Lazy::new(|| {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("releases")
        .join("testnet.mrb");
    let bytes = std::fs::read(path).expect("testnet.mrb exists");
    
    // Verify signature before deserializing
    let signed: SignedReleaseBundle = bcs::from_bytes(&bytes)
        .expect("Invalid signed bundle format");
    
    let pubkey = Ed25519PublicKey::try_from(signed.public_key.as_slice())
        .expect("Invalid public key");
    
    // Verify this is an official release key
    assert_eq!(
        hex::encode(pubkey.to_bytes()),
        TESTNET_RELEASE_PUBKEY,
        "Release bundle not signed with trusted key"
    );
    
    // Verify signature
    let bundle_bytes = bcs::to_bytes(&signed.bundle).expect("serialization succeeds");
    let signature = Ed25519Signature::try_from(signed.signature.as_slice())
        .expect("Invalid signature");
    
    pubkey.verify(&bundle_bytes, &signature)
        .expect("Release bundle signature verification failed");
    
    signed.bundle
});
```

**3. For additional defense-in-depth, add hash verification:**

```rust
// Store expected hashes in version control
const TESTNET_RELEASE_HASH: &str = "sha256:abcdef...";

// Verify hash matches before using
let computed_hash = aptos_crypto::HashValue::sha3_256_of(&bundle_bytes);
assert_eq!(computed_hash.to_hex(), TESTNET_RELEASE_HASH);
```

**4. Document the signing process in release procedures:**
- Generate releases only on air-gapped machines
- Use hardware security modules (HSM) for signing keys
- Require multi-signature for mainnet releases
- Publish signed bundles with detached signatures for public verification

## Proof of Concept

```rust
// Proof of Concept: Demonstrate unsigned bundle loading

use aptos_framework::{testnet_release_bundle, ReleaseBundle};
use std::path::PathBuf;

#[test]
fn test_malicious_bundle_replacement() {
    // 1. Compile malicious Move code
    // (Assume we have malicious Move modules that pass verification)
    
    // 2. Create malicious ReleaseBundle
    let malicious_bundle = ReleaseBundle::new(
        vec![/* malicious packages */],
        vec![/* source paths */]
    );
    
    // 3. Write malicious bundle to testnet.mrb location
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("releases")
        .join("testnet.mrb");
    malicious_bundle.write(path).unwrap();
    
    // 4. Load bundle - NO VERIFICATION OCCURS
    let loaded = testnet_release_bundle();
    
    // 5. This malicious bundle would be used in genesis generation
    // without any integrity checks catching the substitution
    assert!(loaded.packages.len() > 0);
    
    // Expected: Signature verification should fail
    // Actual: Malicious bundle loads successfully
}

// Demonstration of supply chain attack vector:
// 1. Attacker modifies .github/workflows/framework-release.yml
// 2. Injects step to replace .mrb file before artifact upload
// 3. Modified artifact is distributed to operators
// 4. Genesis generation uses compromised framework
// 5. All validators deploy backdoored genesis
```

**Notes:**

This vulnerability exists because the codebase prioritizes convenience over security for framework distribution. While Move bytecode verification ensures structural correctness, it cannot detect malicious logic in otherwise valid bytecode. The attack requires supply chain compromise but provides complete control over the blockchain, making this a critical supply chain vulnerability that should be addressed before mainnet launch or testnet deployments.

### Citations

**File:** aptos-move/framework/src/released_framework.rs (L8-14)
```rust
static TESTNET_RELEASE_BUNDLE: Lazy<ReleaseBundle> = Lazy::new(|| {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("releases")
        .join("testnet.mrb");
    let bytes = std::fs::read(path).expect("testnet.mrb exists");
    bcs::from_bytes::<ReleaseBundle>(&bytes).expect("bcs succeeds")
});
```

**File:** aptos-move/vm-genesis/src/lib.rs (L1128-1150)
```rust
fn code_to_writes_for_publishing(
    genesis_runtime_environment: &RuntimeEnvironment,
    genesis_features: &Features,
    genesis_state_view: &GenesisStateView,
    addr: AccountAddress,
    code: Vec<Bytes>,
) -> VMResult<BTreeMap<StateKey, ModuleWrite<WriteOp>>> {
    let module_storage = genesis_state_view.as_aptos_code_storage(genesis_runtime_environment);
    let resolver = genesis_state_view.as_move_resolver();

    let module_storage_with_staged_modules =
        StagingModuleStorage::create(&addr, &module_storage, code)?;
    let verified_module_bundle =
        module_storage_with_staged_modules.release_verified_module_bundle();

    convert_modules_into_write_ops(
        &resolver,
        genesis_features,
        &module_storage,
        verified_module_bundle,
    )
    .map_err(|e| e.finish(Location::Undefined))
}
```

**File:** aptos-move/vm-genesis/src/lib.rs (L1155-1194)
```rust
fn publish_framework(
    genesis_vm: &GenesisMoveVm,
    genesis_runtime_environment: &RuntimeEnvironment,
    hash_value: HashValue,
    framework: &ReleaseBundle,
) -> (VMChangeSet, ModuleWriteSet) {
    // Reset state view to be empty, to make sure all module write ops are creations.
    let mut state_view = GenesisStateView::new();

    // First, publish modules.
    let mut writes = BTreeMap::new();
    for pack in &framework.packages {
        let modules = pack.sorted_code_and_modules();

        let addr = *modules.first().unwrap().1.self_id().address();
        let code = modules
            .into_iter()
            .map(|(c, _)| c.to_vec().into())
            .collect::<Vec<_>>();

        let package_writes = code_to_writes_for_publishing(
            genesis_runtime_environment,
            genesis_vm.genesis_features(),
            &state_view,
            addr,
            code,
        )
        .unwrap_or_else(|e| {
            panic!(
                "Failure publishing package `{}`: {:?}",
                pack.package_metadata().name,
                e
            )
        });

        // Add write ops so that we can later create a module write set. Also add them to the state
        // view so that modules in subsequent packages can link to them.
        writes.extend(package_writes.clone());
        state_view.add_module_write_ops(package_writes);
    }
```

**File:** aptos-move/vm-genesis/src/lib.rs (L1309-1316)
```rust
    let framework = match genesis_options {
        GenesisOptions::Head => aptos_cached_packages::head_release_bundle(),
        GenesisOptions::Testnet => aptos_framework::testnet_release_bundle(),
        GenesisOptions::Mainnet => {
            // We don't yet have mainnet, so returning testnet here
            aptos_framework::testnet_release_bundle()
        },
    };
```

**File:** crates/aptos/src/genesis/mod.rs (L116-126)
```rust
        let (genesis_bytes, waypoint) = if self.mainnet {
            let mut mainnet_genesis = fetch_mainnet_genesis_info(self.git_options)?;
            let genesis_bytes = bcs::to_bytes(mainnet_genesis.clone().get_genesis())
                .map_err(|e| CliError::BCS(GENESIS_FILE, e))?;
            (genesis_bytes, mainnet_genesis.generate_waypoint()?)
        } else {
            let mut test_genesis = fetch_genesis_info(self.git_options)?;
            let genesis_bytes = bcs::to_bytes(test_genesis.clone().get_genesis())
                .map_err(|e| CliError::BCS(GENESIS_FILE, e))?;
            (genesis_bytes, test_genesis.generate_waypoint()?)
        };
```

**File:** crates/aptos/src/genesis/git.rs (L229-247)
```rust
    /// Retrieve framework release bundle.
    pub fn get_framework(&self) -> CliTypedResult<ReleaseBundle> {
        match self {
            Client::Local(local_repository_path) => {
                let path = local_repository_path.join(FRAMEWORK_NAME);
                if !path.exists() {
                    return Err(CliError::UnableToReadFile(
                        path.display().to_string(),
                        "File not found".to_string(),
                    ));
                }
                Ok(ReleaseBundle::read(path)?)
            },
            Client::Github(client) => {
                let bytes = base64::decode(client.get_file(FRAMEWORK_NAME)?)?;
                Ok(bcs::from_bytes::<ReleaseBundle>(&bytes)?)
            },
        }
    }
```
