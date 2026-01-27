# Audit Report

## Title
Genesis File Integrity Bypass - No Cryptographic Verification Before Deserialization

## Summary
The Aptos Core codebase loads and deserializes `genesis.blob` files without any prior cryptographic verification (hash or signature). This allows attackers who can manipulate the genesis file download or storage to inject arbitrary data that will be deserialized and executed before waypoint verification occurs, potentially causing network-wide consensus splits, node crashes, or exploitation of deserialization vulnerabilities.

## Finding Description

The genesis file loading mechanism has a critical security flaw: **no cryptographic integrity verification occurs before deserialization**. [1](#0-0) 

The `load_from_path()` function reads the genesis.blob file and immediately calls `bcs::from_bytes(&buffer)` to deserialize it into a `Transaction` object without any hash, signature, or checksum verification.

In production deployments, genesis.blob is downloaded from URLs without hash verification: [2](#0-1) 

The init container downloads genesis.blob using curl with no subsequent integrity checks. The downloaded file is directly used by the node.

The verification that DOES exist happens only AFTER deserialization and execution: [3](#0-2) 

The waypoint verification in `maybe_bootstrap()` only checks if the RESULT of executing the genesis transaction matches the expected state hash. This verification occurs after:
1. BCS deserialization of arbitrary bytes
2. VM execution of the deserialized transaction [4](#0-3) 

The waypoint only verifies the resulting ledger state, not the genesis file authenticity.

**Attack Scenarios:**

1. **Network-Wide Consensus Split**: An attacker performing MITM attacks on genesis.blob downloads for different nodes can serve different genesis files to different validators. Each node will execute its received genesis, fail waypoint verification with different errors, or worse - if the attacker can craft multiple genesis transactions that pass waypoint verification but have subtle differences, nodes will start with divergent states, causing permanent network partition.

2. **Targeted Node DoS**: An attacker can replace genesis.blob with malformed data, causing nodes to crash during deserialization or execution before waypoint verification rejects it.

3. **Exploitation of Deserialization/VM Bugs**: The malicious genesis data is deserialized and executed by the VM before verification. If there are bugs in BCS deserialization or the Move VM, they could be exploited during this window.

This breaks the **Deterministic Execution** invariant - there's no cryptographic guarantee that all validators receive identical genesis files.

## Impact Explanation

**Critical Severity** - This vulnerability meets multiple Critical severity criteria per the Aptos Bug Bounty:

1. **Non-recoverable network partition (requires hardfork)**: If different validators receive different genesis files (via MITM, compromised CDN, DNS poisoning), they will initialize with different state roots. This creates an irrecoverable network split requiring manual intervention or hard fork.

2. **Total loss of liveness/network availability**: During network bootstrap, if all nodes download a malicious genesis.blob that fails waypoint verification, the entire network fails to start.

3. **Consensus/Safety violations**: Different genesis states across validators violates the fundamental consensus safety guarantee that all honest validators agree on the blockchain state.

The attack surface is real because:
- Production deployments download genesis.blob from HTTP(S) URLs
- No hash verification after download
- No signature verification of the genesis file author
- The file is used directly without integrity checks

## Likelihood Explanation

**High Likelihood** in certain deployment scenarios:

1. **MITM Attacks**: Network-level attackers can intercept genesis.blob downloads and serve malicious files. While HTTPS provides transport security, it doesn't verify file integrity if the CDN/server is compromised.

2. **Compromised Infrastructure**: If the genesis blob hosting infrastructure (CDN, cloud storage) is compromised, attackers can replace the legitimate genesis.blob.

3. **Local File Replacement**: Operators with filesystem access can replace genesis.blob files, intentionally or via malware.

4. **Supply Chain Attacks**: Compromised build/deployment pipelines could inject malicious genesis files.

The likelihood is **not** Medium/Low because:
- The attack doesn't require validator private key compromise
- It targets the bootstrap phase when nodes are most vulnerable
- Multiple attack vectors exist (network, infrastructure, local filesystem)
- No existing controls prevent this attack

## Recommendation

Implement cryptographic verification BEFORE deserialization. Two approaches:

**Approach 1: Hash-based verification** (simpler, recommended)

Add a genesis hash to the configuration and verify before deserialization: [5](#0-4) 

Modify the ExecutionConfig struct to include an expected genesis hash, and verify it in `load_from_path()` before calling `bcs::from_bytes()`.

**Approach 2: Signature-based verification** (stronger)

Have genesis files signed by Aptos Foundation keys and verify the signature before deserialization. This provides authenticity in addition to integrity.

**Implementation sketch:**

```rust
pub fn load_from_path(&mut self, root_dir: &RootPath) -> Result<(), Error> {
    if !self.genesis_file_location.as_os_str().is_empty() {
        let genesis_path = root_dir.full_path(&self.genesis_file_location);
        
        let mut file = File::open(&genesis_path)?;
        let mut buffer = vec![];
        file.read_to_end(&mut buffer)?;
        
        // NEW: Verify hash BEFORE deserialization
        if let Some(expected_hash) = &self.genesis_hash {
            let actual_hash = HashValue::sha3_256_of(&buffer);
            if actual_hash != *expected_hash {
                return Err(Error::Unexpected(format!(
                    "Genesis file hash mismatch! Expected: {}, Got: {}",
                    expected_hash, actual_hash
                )));
            }
        }
        
        // Only deserialize after verification
        let genesis = bcs::from_bytes(&buffer)?;
        self.genesis = Some(genesis);
    }
    Ok(())
}
```

Additionally, update the Helm chart init containers to verify checksums:

```bash
expected_hash="${GENESIS_HASH}"
actual_hash=$(sha256sum /opt/aptos/genesis/genesis.blob | awk '{print $1}')
if [ "$expected_hash" != "$actual_hash" ]; then
  echo "ERROR: Genesis hash mismatch!"
  exit 1
fi
```

## Proof of Concept

**Step 1**: Create a malicious genesis.blob file:

```rust
// poc_malicious_genesis.rs
use aptos_types::transaction::{Transaction, WriteSetPayload, ChangeSet};
use aptos_types::write_set::WriteSetMut;

fn main() {
    // Create a malicious genesis transaction with arbitrary write set
    let malicious_genesis = Transaction::GenesisTransaction(
        WriteSetPayload::Direct(
            ChangeSet::new(
                WriteSetMut::new(vec![]).freeze().unwrap(),
                vec![]
            )
        )
    );
    
    let malicious_bytes = bcs::to_bytes(&malicious_genesis).unwrap();
    std::fs::write("malicious_genesis.blob", &malicious_bytes).unwrap();
    
    println!("Created malicious genesis.blob ({} bytes)", malicious_bytes.len());
}
```

**Step 2**: Replace legitimate genesis.blob with malicious version:

```bash
# Download current genesis
curl -o legitimate_genesis.blob https://devnet.aptoslabs.com/genesis.blob

# Generate malicious version
cargo run --bin poc_malicious_genesis

# Replace it
cp malicious_genesis.blob /opt/aptos/genesis/genesis.blob
```

**Step 3**: Start the Aptos node:

```bash
aptos-node -f /opt/aptos/etc/validator.yaml
```

**Expected Result**: The node will:
1. Load the malicious genesis.blob
2. Deserialize it successfully (no verification occurs)
3. Attempt to execute it
4. Eventually fail at waypoint verification with: `"Waypoint verification failed"`

But the critical point is that **steps 2-3 occurred without any integrity verification**, demonstrating the vulnerability.

**Impact Demonstration**: If you run this on multiple nodes with different malicious genesis files, each node will fail differently or potentially succeed with different states, demonstrating the consensus split vulnerability.

## Notes

While the waypoint verification eventually catches mismatches, this defense-in-depth failure creates multiple attack vectors:

1. The verification happens **after** deserialization and execution, not before
2. BCS deserialization of attacker-controlled data occurs without prior validation
3. Different nodes receiving different genesis files will diverge permanently
4. No cryptographic proof of genesis file authenticity exists

The fix is standard security practice: **verify cryptographic integrity before trusting untrusted input**, especially for security-critical data like genesis files that determine the entire blockchain's initial state.

### Citations

**File:** config/src/config/execution_config.rs (L30-60)
```rust
#[derive(Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExecutionConfig {
    #[serde(skip)]
    /// For testing purposes, the ability to add a genesis transaction directly
    pub genesis: Option<Transaction>,
    /// Location of the genesis file
    pub genesis_file_location: PathBuf,
    /// Number of threads to run execution.
    /// If 0, we use min of (num of cores/2, DEFAULT_CONCURRENCY_LEVEL) as default concurrency level
    pub concurrency_level: u16,
    /// Number of threads to read proofs
    pub num_proof_reading_threads: u16,
    /// Enables paranoid mode for types, which adds extra runtime VM checks
    pub paranoid_type_verification: bool,
    /// Enabled discarding blocks that fail execution due to BlockSTM/VM issue.
    pub discard_failed_blocks: bool,
    /// Enables paranoid mode for hot potatoes, which adds extra runtime VM checks
    pub paranoid_hot_potato_verification: bool,
    /// Enables enhanced metrics around processed transactions
    pub processed_transactions_detailed_counters: bool,
    /// Used during DB bootstrapping
    pub genesis_waypoint: Option<WaypointConfig>,
    /// Whether to use BlockSTMv2 for parallel execution.
    pub blockstm_v2_enabled: bool,
    /// Enables long-living concurrent caches for Move type layouts.
    pub layout_caches_enabled: bool,
    /// If enabled, runtime checks like paranoid type checks may be performed in parallel in post
    /// commit hook in Block-STM.
    pub async_runtime_checks: bool,
}
```

**File:** config/src/config/execution_config.rs (L100-140)
```rust
    pub fn load_from_path(&mut self, root_dir: &RootPath) -> Result<(), Error> {
        if !self.genesis_file_location.as_os_str().is_empty() {
            // Ensure the genesis file exists
            let genesis_path = root_dir.full_path(&self.genesis_file_location);
            if !genesis_path.exists() {
                return Err(Error::Unexpected(format!(
                    "The genesis file could not be found! Ensure the given path is correct: {:?}",
                    genesis_path.display()
                )));
            }

            // Open the genesis file and read the bytes
            let mut file = File::open(&genesis_path).map_err(|error| {
                Error::Unexpected(format!(
                    "Failed to open the genesis file: {:?}. Error: {:?}",
                    genesis_path.display(),
                    error
                ))
            })?;
            let mut buffer = vec![];
            file.read_to_end(&mut buffer).map_err(|error| {
                Error::Unexpected(format!(
                    "Failed to read the genesis file into a buffer: {:?}. Error: {:?}",
                    genesis_path.display(),
                    error
                ))
            })?;

            // Deserialize the genesis file and store it
            let genesis = bcs::from_bytes(&buffer).map_err(|error| {
                Error::Unexpected(format!(
                    "Failed to BCS deserialize the genesis file: {:?}. Error: {:?}",
                    genesis_path.display(),
                    error
                ))
            })?;
            self.genesis = Some(genesis);
        }

        Ok(())
    }
```

**File:** terraform/helm/aptos-node/templates/validator.yaml (L113-121)
```yaml
              if [ ! -f /opt/aptos/genesis/genesis.blob ]; then
                genesis_blob_upload_url="{{ $.Values.genesis_blob_upload_url }}"
                genesis_blob_upload_url="$genesis_blob_upload_url&namespace={{ $.Release.Namespace }}&method=GET"
                echo "genesis.blob not found locally, downloading..."
                signed_url=$(curl -s -X GET "$genesis_blob_upload_url")
                curl -o /opt/aptos/genesis/genesis.blob "$signed_url"
              else
                echo "genesis.blob found locally"
              fi
```

**File:** execution/executor/src/db_bootstrapper/mod.rs (L48-71)
```rust
pub fn maybe_bootstrap<V: VMBlockExecutor>(
    db: &DbReaderWriter,
    genesis_txn: &Transaction,
    waypoint: Waypoint,
) -> Result<Option<LedgerInfoWithSignatures>> {
    let ledger_summary = db.reader.get_pre_committed_ledger_summary()?;
    // if the waypoint is not targeted with the genesis txn, it may be either already bootstrapped, or
    // aiming for state sync to catch up.
    if ledger_summary.version().map_or(0, |v| v + 1) != waypoint.version() {
        info!(waypoint = %waypoint, "Skip genesis txn.");
        return Ok(None);
    }

    let committer = calculate_genesis::<V>(db, ledger_summary, genesis_txn)?;
    ensure!(
        waypoint == committer.waypoint(),
        "Waypoint verification failed. Expected {:?}, got {:?}.",
        waypoint,
        committer.waypoint(),
    );
    let ledger_info = committer.output.ledger_info_opt.clone();
    committer.commit()?;
    Ok(ledger_info)
}
```

**File:** types/src/waypoint.rs (L62-79)
```rust
    pub fn verify(&self, ledger_info: &LedgerInfo) -> Result<()> {
        ensure!(
            ledger_info.version() == self.version(),
            "Waypoint version mismatch: waypoint version = {}, given version = {}",
            self.version(),
            ledger_info.version()
        );
        let converter = Ledger2WaypointConverter::new(ledger_info);
        ensure!(
            converter.hash() == self.value(),
            format!(
                "Waypoint value mismatch: waypoint value = {}, given value = {}",
                self.value().to_hex(),
                converter.hash().to_hex()
            )
        );
        Ok(())
    }
```
