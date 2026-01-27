# Audit Report

## Title
Chain ID Validation Bypass in Indexer File Checker Allows Wrong-Chain Data Acceptance

## Summary
The `indexer-grpc-file-checker` validates that metadata chain IDs match between two buckets but does not verify they are the correct chain ID for the intended network. An attacker with bucket access or through operator misconfiguration can provide matching but incorrect chain IDs in both buckets, causing the file checker to accept and validate data from the wrong blockchain (e.g., testnet data accepted as mainnet data). [1](#0-0) 

## Finding Description

The `Processor::init()` function downloads metadata from both the existing and new GCS buckets, then validates that their chain IDs match each other. However, it never validates that these chain IDs are **correct** for the intended blockchain network. [2](#0-1) 

The configuration structure lacks an `expected_chain_id` field to specify what the correct chain ID should be: [3](#0-2) 

In contrast, other components in the indexer system **do** validate against an expected chain ID. For example, the GCS file store operator checks: [4](#0-3) 

**Attack Scenario:**
1. The file checker is configured to verify mainnet data (chain_id: 1)
2. An attacker with GCS bucket access modifies both `metadata.json` files to specify chain_id: 2 (testnet)
3. The attacker populates both buckets with testnet transaction data
4. The file checker reads both metadata files, sees matching chain_id: 2, and passes validation
5. The file checker proceeds to verify testnet data as if it were mainnet data
6. Downstream indexers consume this wrong-chain data, corrupting their state

Valid chain IDs in Aptos are: [5](#0-4) 

## Impact Explanation

This vulnerability meets **High Severity** criteria under the Aptos bug bounty program:

- **API crashes**: Indexer APIs consuming wrong-chain data may crash or return inconsistent results when the data doesn't match expected schemas or validation rules
- **Significant protocol violations**: Data integrity is violated when indexers serve data from the wrong blockchain as if it were from the intended chain
- **State inconsistencies requiring intervention**: Indexer state becomes corrupted with wrong-chain data, requiring manual intervention to restore correct state

The impact affects all downstream consumers of the indexer data:
- Wallets may display incorrect balances from the wrong chain
- Dapps may query wrong transaction history
- Analytics platforms may report incorrect metrics
- Users may make financial decisions based on fraudulent data

## Likelihood Explanation

**Likelihood: Medium to High**

This vulnerability can be exploited through multiple realistic scenarios:

1. **Security Breach**: An attacker compromises GCS bucket credentials through phishing, leaked service accounts, or cloud misconfigurations. Once they have write access to both buckets, they can modify metadata.json files.

2. **Operator Misconfiguration**: During deployment or migration, an operator accidentally configures the file checker to point to buckets from different chains (e.g., existing_bucket from mainnet, new_bucket from testnet). Since validation only checks matching, not correctness, this configuration error would go undetected.

3. **Supply Chain Attack**: Compromised deployment scripts or configuration management tools could inject incorrect bucket names, causing the file checker to validate data from the wrong chain.

The absence of any configuration field for expected chain ID makes this easier to exploit, as there's no mechanism for operators to specify and enforce the correct chain.

## Recommendation

Add an `expected_chain_id` field to the configuration and validate that both metadata files match this expected value:

```rust
// In lib.rs
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IndexerGrpcFileCheckerConfig {
    pub existing_bucket_name: String,
    pub new_bucket_name: String,
    pub starting_version: u64,
    pub expected_chain_id: u64,  // NEW FIELD
}

// In processor.rs
impl Processor {
    pub expected_chain_id: u64,  // NEW FIELD
}

// Update init() validation
pub async fn init(&self) -> Result<(Client, ProgressFile)> {
    let client = Client::new();

    let existing_metadata = download_file::<MetadataFile>(&client, &self.existing_bucket_name, METADATA_FILE_NAME)
        .await?
        .expect("Failed to download metadata file");
    let new_metadata = download_file::<MetadataFile>(&client, &self.new_bucket_name, METADATA_FILE_NAME)
        .await?
        .expect("Failed to download metadata file");

    // Validate against expected chain ID
    ensure!(
        existing_metadata.chain_id == self.expected_chain_id,
        "Existing bucket chain ID {} does not match expected chain ID {}",
        existing_metadata.chain_id,
        self.expected_chain_id
    );
    
    ensure!(
        new_metadata.chain_id == self.expected_chain_id,
        "New bucket chain ID {} does not match expected chain ID {}",
        new_metadata.chain_id,
        self.expected_chain_id
    );

    // Existing validation still applies
    ensure!(
        existing_metadata.chain_id == new_metadata.chain_id,
        "Chain IDs do not match: {} != {}",
        existing_metadata.chain_id,
        new_metadata.chain_id
    );
    
    // ... rest of init() ...
}
```

## Proof of Concept

```rust
// Test demonstrating the vulnerability
#[tokio::test]
async fn test_chain_id_validation_bypass() {
    // Setup: Create two GCS buckets with matching but incorrect chain IDs
    let test_bucket_1 = "test-existing-bucket";
    let test_bucket_2 = "test-new-bucket";
    
    // Create metadata.json files with chain_id: 2 (testnet) when mainnet is expected
    let wrong_chain_metadata = MetadataFile { chain_id: 2 };
    
    // Upload wrong metadata to both buckets
    upload_metadata(test_bucket_1, &wrong_chain_metadata).await;
    upload_metadata(test_bucket_2, &wrong_chain_metadata).await;
    
    // Populate buckets with testnet transaction data
    upload_testnet_transactions(test_bucket_1).await;
    upload_testnet_transactions(test_bucket_2).await;
    
    // Create processor configured to check these buckets
    let processor = Processor {
        existing_bucket_name: test_bucket_1.to_string(),
        new_bucket_name: test_bucket_2.to_string(),
        starting_version: 0,
    };
    
    // Vulnerability: init() passes because chain IDs match (2 == 2)
    // even though the expected chain ID should be 1 (mainnet)
    let result = processor.init().await;
    assert!(result.is_ok(), "Init should pass with matching but wrong chain IDs");
    
    // The processor will now verify testnet data as if it were mainnet data
    // This would cause downstream indexers to accept wrong-chain data
}

// Expected behavior with fix:
#[tokio::test]
async fn test_chain_id_validation_with_fix() {
    let processor = Processor {
        existing_bucket_name: "test-existing-bucket".to_string(),
        new_bucket_name: "test-new-bucket".to_string(),
        starting_version: 0,
        expected_chain_id: 1, // Mainnet expected
    };
    
    // Both buckets have chain_id: 2 (testnet)
    let result = processor.init().await;
    
    // Should fail: chain_id 2 != expected chain_id 1
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("does not match expected chain ID"));
}
```

## Notes

This vulnerability is specific to the indexer infrastructure component and does not directly affect core blockchain consensus or validator operations. However, it has significant impact on data integrity for all users and applications relying on the indexer for blockchain data queries. The fix is straightforward and follows the pattern already established in other indexer components that validate against an expected chain ID.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-file-checker/src/processor.rs (L119-163)
```rust
    pub async fn init(&self) -> Result<(Client, ProgressFile)> {
        let client = Client::new();

        // All errors are considered fatal: files must exist for the processor to work.
        let existing_metadata =
            download_file::<MetadataFile>(&client, &self.existing_bucket_name, METADATA_FILE_NAME)
                .await
                .context("Failed to get metadata.")?
                .expect("Failed to download metadata file");
        let new_metadata =
            download_file::<MetadataFile>(&client, &self.new_bucket_name, METADATA_FILE_NAME)
                .await
                .context("Failed to get metadata.")?
                .expect("Failed to download metadata file");

        // Ensure the chain IDs match.
        ensure!(
            existing_metadata.chain_id == new_metadata.chain_id,
            "Chain IDs do not match: {} != {}",
            existing_metadata.chain_id,
            new_metadata.chain_id
        );

        let progress_file =
            download_file::<ProgressFile>(&client, &self.new_bucket_name, PROGRESS_FILE_NAME)
                .await
                .context("Failed to get progress file.")?
                .unwrap_or(ProgressFile {
                    file_checker_version: self.starting_version,
                    file_checker_chain_id: existing_metadata.chain_id,
                });
        // Ensure the chain IDs match.
        ensure!(
            existing_metadata.chain_id == progress_file.file_checker_chain_id,
            "Chain IDs do not match: {} != {}",
            existing_metadata.chain_id,
            progress_file.file_checker_chain_id
        );
        tracing::info!(
            starting_version = self.starting_version,
            "Processor initialized.",
        );

        Ok((client, progress_file))
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-file-checker/src/lib.rs (L11-17)
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IndexerGrpcFileCheckerConfig {
    pub existing_bucket_name: String,
    pub new_bucket_name: String,
    pub starting_version: u64,
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator/gcs.rs (L162-182)
```rust
    async fn update_file_store_metadata_with_timeout(
        &mut self,
        expected_chain_id: u64,
        version: u64,
    ) -> anyhow::Result<()> {
        if let Some(metadata) = self.get_file_store_metadata().await {
            assert_eq!(metadata.chain_id, expected_chain_id, "Chain ID mismatch.");
            assert_eq!(
                metadata.storage_format, self.storage_format,
                "Storage format mismatch."
            );
        }
        if self.file_store_metadata_last_updated.elapsed().as_millis()
            < FILE_STORE_METADATA_TIMEOUT_MILLIS
        {
            bail!("File store metadata is updated too frequently.")
        }
        self.update_file_store_metadata_internal(expected_chain_id, version)
            .await?;
        Ok(())
    }
```

**File:** types/src/chain_id.rs (L11-24)
```rust
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NamedChain {
    /// Users might accidentally initialize the ChainId field to 0, hence reserving ChainId 0 for accidental
    /// initialization.
    /// MAINNET is the Aptos mainnet production chain and is reserved for 1
    MAINNET = 1,
    // Even though these CHAIN IDs do not correspond to MAINNET, changing them should be avoided since they
    // can break test environments for various organisations.
    TESTNET = 2,
    DEVNET = 3,
    TESTING = 4,
    PREMAINNET = 5,
}
```
