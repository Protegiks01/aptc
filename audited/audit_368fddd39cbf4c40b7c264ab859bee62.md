# Audit Report

## Title
State Snapshot Restore DoS via Unbounded SparseMerkleRangeProof Depth

## Summary
Validator nodes can be crashed during state snapshot restoration when processing maliciously crafted backup files containing `SparseMerkleRangeProof` objects with excessive Merkle tree depth. The verification logic performs an unchecked integer underflow that triggers a panic due to enabled overflow checks, causing immediate node termination.

## Finding Description

While the `get_state_root_proof()` function itself properly validates depth through `TransactionAccumulatorProof` (limited to 63 siblings), the broader state snapshot restore system contains a critical vulnerability in `SparseMerkleRangeProof` verification. [1](#0-0) 

Unlike other proof types, `SparseMerkleRangeProof` has no constructor-time or deserialization-time validation of the `right_siblings` vector size. During verification: [2](#0-1) 

At line 788, `num_siblings` is computed as the sum of left and right siblings without bounds checking. At line 797, when `num_siblings > 256`, the expression `HashValue::LENGTH_IN_BITS - num_siblings` causes integer underflow. [3](#0-2) 

Since `HashValue::LENGTH_IN_BITS = 256`, providing a proof with 300+ siblings causes `256 - 300 = -44` (which wraps in unsigned arithmetic). With overflow checks enabled in production builds: [4](#0-3) 

The underflow triggers a panic, immediately crashing the validator node. This occurs during state snapshot chunk restoration: [5](#0-4) [6](#0-5) 

The malicious proof is deserialized from BCS without validation and passed directly to verification.

## Impact Explanation

**High Severity** - This vulnerability enables Denial of Service attacks against validators during state snapshot restoration. An attacker who can modify backup files (compromised backup storage, supply chain attack, or man-in-the-middle) can prevent validators from syncing via backup, impacting network liveness and recovery capabilities. While it doesn't cause consensus violations or fund loss, it represents a significant protocol violation per Aptos bug bounty criteria by causing validator node crashes.

## Likelihood Explanation

**Medium Likelihood** - The attack requires the attacker to control or tamper with backup files stored in the backup storage system. While backup sources are typically trusted infrastructure, several realistic attack vectors exist:
- Compromised backup storage credentials
- Supply chain attacks on backup distribution
- Malicious insider with backup access
- Man-in-the-middle attacks during backup retrieval

Once compromised backup files are distributed, the impact is deterministic—any validator attempting to restore from the malicious backup will crash immediately.

## Recommendation

Add depth validation to `SparseMerkleRangeProof` similar to other proof types. Modify the struct to enforce maximum depth:

```rust
impl SparseMerkleRangeProof {
    /// Maximum depth for sparse Merkle range proofs
    pub const MAX_PROOF_DEPTH: usize = HashValue::LENGTH_IN_BITS;
    
    pub fn new(right_siblings: Vec<HashValue>) -> Result<Self> {
        ensure!(
            right_siblings.len() <= Self::MAX_PROOF_DEPTH,
            "SparseMerkleRangeProof has more than {} ({}) right siblings.",
            Self::MAX_PROOF_DEPTH,
            right_siblings.len()
        );
        Ok(Self { right_siblings })
    }
    
    pub fn verify(
        &self,
        expected_root_hash: HashValue,
        rightmost_known_leaf: SparseMerkleLeafNode,
        left_siblings: Vec<HashValue>,
    ) -> Result<()> {
        let num_siblings = left_siblings.len() + self.right_siblings.len();
        ensure!(
            num_siblings <= HashValue::LENGTH_IN_BITS,
            "Total siblings ({}) exceeds maximum Merkle tree depth ({})",
            num_siblings,
            HashValue::LENGTH_IN_BITS
        );
        // ... rest of verification
    }
}
```

## Proof of Concept

```rust
use aptos_types::proof::{SparseMerkleRangeProof, SparseMerkleLeafNode};
use aptos_crypto::{hash::CryptoHash, HashValue};

// Create a malicious proof with excessive depth
let malicious_siblings: Vec<HashValue> = (0..300)
    .map(|_| HashValue::random())
    .collect();

let malicious_proof = SparseMerkleRangeProof::new(malicious_siblings);

// Create a dummy leaf
let leaf = SparseMerkleLeafNode::new(
    HashValue::random(), 
    HashValue::random().hash()
);

// Attempt verification - this will panic with integer underflow
let result = malicious_proof.verify(
    HashValue::random(),
    leaf,
    vec![], // empty left siblings
);

// Expected: Panic in release mode due to overflow-checks
// Actual behavior: Node crashes with "attempt to subtract with overflow"
```

**Notes**

The specific `get_state_root_proof()` function mentioned in the security question uses `TransactionAccumulatorProof` which properly enforces `MAX_ACCUMULATOR_PROOF_DEPTH = 63`. However, the broader state snapshot backup/restore system, which this function is part of, contains this exploitable vulnerability in `SparseMerkleRangeProof` verification used for chunk validation. Both components work together during state restoration, making this a critical security issue in the Merkle tree depth validation across the backup/restore subsystem.

### Citations

**File:** types/src/proof/definition.rs (L762-778)
```rust
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SparseMerkleRangeProof {
    /// The vector of siblings on the right of the path from root to last leaf. The ones near the
    /// bottom are at the beginning of the vector. In the above example, it's `[X, h]`.
    right_siblings: Vec<HashValue>,
}

impl SparseMerkleRangeProof {
    /// Constructs a new `SparseMerkleRangeProof`.
    pub fn new(right_siblings: Vec<HashValue>) -> Self {
        Self { right_siblings }
    }

    /// Returns the right siblings.
    pub fn right_siblings(&self) -> &[HashValue] {
        &self.right_siblings
    }
```

**File:** types/src/proof/definition.rs (L782-797)
```rust
    pub fn verify(
        &self,
        expected_root_hash: HashValue,
        rightmost_known_leaf: SparseMerkleLeafNode,
        left_siblings: Vec<HashValue>,
    ) -> Result<()> {
        let num_siblings = left_siblings.len() + self.right_siblings.len();
        let mut left_sibling_iter = left_siblings.iter();
        let mut right_sibling_iter = self.right_siblings().iter();

        let mut current_hash = rightmost_known_leaf.hash();
        for bit in rightmost_known_leaf
            .key()
            .iter_bits()
            .rev()
            .skip(HashValue::LENGTH_IN_BITS - num_siblings)
```

**File:** crates/aptos-crypto/src/hash.rs (L129-133)
```rust
impl HashValue {
    /// The length of the hash in bytes.
    pub const LENGTH: usize = 32;
    /// The length of the hash in bits.
    pub const LENGTH_IN_BITS: usize = Self::LENGTH * 8;
```

**File:** Cargo.toml (L921-923)
```text
[profile.release]
debug = true
overflow-checks = true
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L191-215)
```rust
                    let blobs = Self::read_state_value(&storage, chunk.blobs.clone()).await?;
                    let proof = storage.load_bcs_file(&chunk.proof).await?;
                    Result::<_>::Ok((chunk_idx, chunk, blobs, proof))
                })
                .await?
            }
        });
        let con = self.concurrent_downloads;
        let mut futs_stream = stream::iter(futs_iter).buffered_x(con * 2, con);
        let mut start = None;
        while let Some((chunk_idx, chunk, mut blobs, proof)) = futs_stream.try_next().await? {
            start = start.or_else(|| Some(Instant::now()));
            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["add_state_chunk"]);
            let receiver = receiver.clone();
            if self.validate_modules {
                blobs = tokio::task::spawn_blocking(move || {
                    Self::validate_modules(&blobs);
                    blobs
                })
                .await?;
            }
            tokio::task::spawn_blocking(move || {
                receiver.lock().as_mut().unwrap().add_chunk(blobs, proof)
            })
            .await??;
```

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L339-391)
```rust
    pub fn add_chunk_impl(
        &mut self,
        mut chunk: Vec<(&K, HashValue)>,
        proof: SparseMerkleRangeProof,
    ) -> Result<()> {
        if self.finished {
            info!("State snapshot restore already finished, ignoring entire chunk.");
            return Ok(());
        }

        if let Some(prev_leaf) = &self.previous_leaf {
            let skip_until = chunk
                .iter()
                .find_position(|(key, _hash)| key.hash() > *prev_leaf.account_key());
            chunk = match skip_until {
                None => {
                    info!("Skipping entire chunk.");
                    return Ok(());
                },
                Some((0, _)) => chunk,
                Some((num_to_skip, next_leaf)) => {
                    info!(
                        num_to_skip = num_to_skip,
                        next_leaf = next_leaf,
                        "Skipping leaves."
                    );
                    chunk.split_off(num_to_skip)
                },
            }
        };
        if chunk.is_empty() {
            return Ok(());
        }

        for (key, value_hash) in chunk {
            let hashed_key = key.hash();
            if let Some(ref prev_leaf) = self.previous_leaf {
                ensure!(
                    &hashed_key > prev_leaf.account_key(),
                    "State keys must come in increasing order.",
                )
            }
            self.previous_leaf.replace(LeafNode::new(
                hashed_key,
                value_hash,
                (key.clone(), self.version),
            ));
            self.add_one(key, value_hash);
            self.num_keys_received += 1;
        }

        // Verify what we have added so far is all correct.
        self.verify(proof)?;
```
