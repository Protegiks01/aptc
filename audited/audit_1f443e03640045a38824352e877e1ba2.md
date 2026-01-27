# Audit Report

## Title
Lack of Early Validation for Secondary Signers in Transaction Encoding API Causes Wasted Resources

## Summary
The `/transactions/encode_submission` API endpoint does not validate secondary signer addresses for uniqueness or correctness before generating signing messages. This causes users to obtain signatures for transactions that will inevitably fail, and forces validator nodes to perform expensive cryptographic signature verification before detecting the validation error.

## Finding Description

The `get_signing_message()` function in `api/src/transactions.rs` accepts an `EncodeSubmissionRequest` containing optional secondary signer addresses for multi-agent transactions. [1](#0-0) 

The `EncodeSubmissionRequest` struct's `verify()` method only validates the transaction field but does not validate the `secondary_signers` field: [2](#0-1) 

When secondary signers are provided, the code directly creates a `RawTransactionWithData::new_multi_agent()` without any validation: [3](#0-2) 

The `new_multi_agent()` constructor performs no validation: [4](#0-3) 

The actual validation for duplicate signers only occurs during transaction execution in the VM's `validate_signed_transaction()` function: [5](#0-4) 

However, this validation happens AFTER expensive signature verification: [6](#0-5) 

**Attack Flow:**
1. Attacker requests signing message with duplicate secondary signers or with sender in secondary signers list via `/transactions/encode_submission`
2. API returns valid signing message without error
3. All parties sign the transaction (wasted effort)
4. Transaction is submitted to network
5. Validator nodes verify all signatures (expensive crypto operations)
6. Only then does duplicate signer check fail with `SIGNERS_CONTAIN_DUPLICATES`

## Impact Explanation

This issue falls under **Low Severity** per the Aptos bug bounty criteria as a "Non-critical implementation bug." While it causes resource waste, it does not meet the Medium severity threshold because:

- **No funds loss or manipulation occurs** - transactions are correctly rejected
- **No state inconsistencies** - validation prevents execution
- **No consensus violations** - the check works correctly, just inefficiently
- **No security bypass** - all validation eventually happens

The impact is limited to:
1. Poor user experience (late error detection)
2. Wasted computational resources (signature verification before duplicate check)
3. Potential for mild resource exhaustion if exploited at scale

This does NOT constitute a security vulnerability that meets Medium or higher severity, as the system's security guarantees remain intact.

## Likelihood Explanation

This is easy to trigger - any user can submit an `EncodeSubmissionRequest` with duplicate secondary signers. However, the impact is minimal as the transaction will be rejected before execution, preserving all security invariants.

## Recommendation

Add validation in the `EncodeSubmissionRequest::verify()` method or in `get_signing_message()` to check secondary signers before generating the signing message:

```rust
// In api/types/src/transaction.rs, enhance EncodeSubmissionRequest::verify()
impl VerifyInput for EncodeSubmissionRequest {
    fn verify(&self) -> anyhow::Result<()> {
        self.transaction.verify()?;
        
        // Validate secondary signers if present
        if let Some(ref secondary_signers) = self.secondary_signers {
            // Check for duplicates
            let mut seen = std::collections::BTreeSet::new();
            for signer in secondary_signers {
                if !seen.insert(signer) {
                    anyhow::bail!("Duplicate address in secondary signers");
                }
            }
            
            // Check sender not in secondary signers (requires access to transaction.sender)
            // This check would need the sender from the transaction field
        }
        
        Ok(())
    }
}
```

## Proof of Concept

```rust
// Test demonstrating the issue
#[tokio::test]
async fn test_duplicate_secondary_signers_not_rejected_early() {
    use aptos_api_types::{EncodeSubmissionRequest, Address};
    
    // Create request with duplicate secondary signers
    let duplicate_addr = Address::from_hex_literal("0xCAFE").unwrap();
    let mut request = EncodeSubmissionRequest {
        transaction: create_test_transaction(), // Helper function
        secondary_signers: Some(vec![duplicate_addr.clone(), duplicate_addr.clone()]),
    };
    
    // This should fail but currently passes
    assert!(request.verify().is_ok()); // PASSES - This is the bug!
    
    // The error only occurs later when transaction is submitted
    // after all signatures have been collected
}
```

---

**Final Assessment**: While this is a valid code quality issue that should be fixed, it does **NOT** meet the Medium severity threshold for the Aptos bug bounty program. It represents inefficient validation ordering rather than a security vulnerability. The system's security invariants remain intact as the validation correctly rejects invalid transactions before execution.

### Citations

**File:** api/src/transactions.rs (L1784-1838)
```rust
    pub fn get_signing_message(
        &self,
        accept_type: &AcceptType,
        request: EncodeSubmissionRequest,
    ) -> BasicResult<HexEncodedBytes> {
        // We don't want to encourage people to use this API if they can sign the request directly
        if accept_type == &AcceptType::Bcs {
            return Err(BasicError::bad_request_with_code_no_info(
                "BCS is not supported for encode submission",
                AptosErrorCode::BcsNotSupported,
            ));
        }

        let ledger_info = self.context.get_latest_ledger_info()?;
        let state_view = self.context.latest_state_view_poem(&ledger_info)?;
        let raw_txn: RawTransaction = state_view
            .as_converter(self.context.db.clone(), self.context.indexer_reader.clone())
            .try_into_raw_transaction_poem(request.transaction, self.context.chain_id())
            .context("The given transaction is invalid")
            .map_err(|err| {
                BasicError::bad_request_with_code(err, AptosErrorCode::InvalidInput, &ledger_info)
            })?;

        let raw_message = match request.secondary_signers {
            Some(secondary_signer_addresses) => signing_message(
                &RawTransactionWithData::new_multi_agent(
                    raw_txn,
                    secondary_signer_addresses
                        .into_iter()
                        .map(|v| v.into())
                        .collect(),
                ),
            )
            .context("Invalid transaction to generate signing message")
            .map_err(|err| {
                BasicError::bad_request_with_code(err, AptosErrorCode::InvalidInput, &ledger_info)
            })?,
            None => raw_txn
                .signing_message()
                .context("Invalid transaction to generate signing message")
                .map_err(|err| {
                    BasicError::bad_request_with_code(
                        err,
                        AptosErrorCode::InvalidInput,
                        &ledger_info,
                    )
                })?,
        };

        BasicResponse::try_from_json((
            HexEncodedBytes::from(raw_message),
            &ledger_info,
            BasicResponseStatus::Ok,
        ))
    }
```

**File:** api/types/src/transaction.rs (L531-545)
```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Object)]
pub struct EncodeSubmissionRequest {
    #[serde(flatten)]
    #[oai(flatten)]
    pub transaction: UserTransactionRequestInner,
    /// Secondary signer accounts of the request for Multi-agent
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secondary_signers: Option<Vec<Address>>,
}

impl VerifyInput for EncodeSubmissionRequest {
    fn verify(&self) -> anyhow::Result<()> {
        self.transaction.verify()
    }
}
```

**File:** types/src/transaction/mod.rs (L669-677)
```rust
    pub fn new_multi_agent(
        raw_txn: RawTransaction,
        secondary_signer_addresses: Vec<AccountAddress>,
    ) -> Self {
        Self::MultiAgent {
            raw_txn,
            secondary_signer_addresses,
        }
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1790-1796)
```rust
        // Check transaction format.
        if transaction.contains_duplicate_signers() {
            return Err(VMStatus::error(
                StatusCode::SIGNERS_CONTAIN_DUPLICATES,
                None,
            ));
        }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3232-3237)
```rust
        let txn = match transaction.check_signature() {
            Ok(t) => t,
            _ => {
                return VMValidatorResult::error(StatusCode::INVALID_SIGNATURE);
            },
        };
```
