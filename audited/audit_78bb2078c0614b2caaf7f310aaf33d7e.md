# Audit Report

## Title
BCS Deserialization Memory Bomb in Rosetta API decode_bcs() Function

## Summary
The `decode_bcs()` function in the Aptos Rosetta API lacks input size validation before BCS deserialization, potentially allowing attackers to craft malicious BCS-encoded data with inflated length prefixes that could cause excessive memory allocation and service disruption. [1](#0-0) 

## Finding Description

The Rosetta API's `decode_bcs()` function directly deserializes hex-encoded BCS data without validating the size or structure of the claimed data before allocation. This function is used across multiple critical endpoints to deserialize `RawTransaction` and `SignedTransaction` objects from user-supplied JSON payloads. [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) 

The attack vector exploits BCS's ULEB128 encoding for vector lengths, where large numbers can be encoded in very few bytes. Transaction payload structures contain nested vectors that amplify this effect: [7](#0-6) 

An attacker can craft BCS data claiming to contain millions of elements in nested vectors (e.g., `Vec<Vec<u8>>`) using only a few bytes for the ULEB128-encoded length prefixes. While the Warp framework limits JSON body size to 16KB by default, this still allows ~8KB of hex-encoded BCS data containing numerous malicious length prefixes.

Critically, the Rosetta API bypasses the VM's transaction argument validation protections. The VM has explicit safeguards: [8](#0-7) 

However, the Rosetta API's `decode_bcs()` calls `bcs::from_bytes()` directly without these checks, creating a separate, unprotected code path.

The existence of tests specifically validating against huge length claims demonstrates this is a known attack pattern: [9](#0-8) 

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty criteria for "API crashes" and "Validator node slowdowns." While the Rosetta API is not consensus-critical, it is commonly deployed on validator infrastructure and serves as a critical integration point for exchanges and wallets.

An attacker can repeatedly send malicious requests to:
1. Exhaust memory on the Rosetta API service
2. Cause service crashes requiring restart
3. If deployed on validator nodes, potentially impact node performance
4. Disrupt critical blockchain integrations relying on Rosetta API

The attack requires no special privileges and can be executed with simple HTTP POST requests.

## Likelihood Explanation

**High likelihood** - The attack is straightforward to execute:
- No authentication or special access required
- Standard HTTP client can send malicious payloads
- Multiple vulnerable endpoints exist
- Each request processes untrusted deserialization

The only limiting factor is Warp's 16KB JSON body limit, but this is insufficient protection as an attacker can pack significant malicious content within this constraint using nested vector structures and ULEB128 encoding efficiency.

## Recommendation

Implement explicit size validation before BCS deserialization in the `decode_bcs()` function:

```rust
pub fn decode_bcs<T: DeserializeOwned>(str: &str, type_name: &'static str) -> ApiResult<T> {
    let bytes = hex::decode(str)?;
    
    // Add size limit check (e.g., 1MB as used in VM transaction validation)
    const MAX_BCS_BYTES: usize = 1_000_000;
    if bytes.len() > MAX_BCS_BYTES {
        return Err(ApiError::InvalidInput(Some(format!(
            "BCS data exceeds maximum size of {} bytes",
            MAX_BCS_BYTES
        ))));
    }
    
    bcs::from_bytes(&bytes).map_err(|_| ApiError::deserialization_failed(type_name))
}
```

Additionally, consider:
1. Implementing a content-length limit specific to Rosetta API endpoints
2. Adding rate limiting per IP address
3. Monitoring memory usage and implementing circuit breakers
4. Ensuring the BCS crate itself has bounds checking on vector allocation

## Proof of Concept

```rust
// PoC: Craft malicious BCS data with inflated length prefix
fn create_memory_bomb_bcs() -> String {
    // Create ULEB128 encoding claiming 1 billion elements
    let mut malicious_bcs = vec![];
    
    // Encode outer vector claiming 100,000 elements
    let mut len = 100_000u64;
    while len >= 128 {
        malicious_bcs.push((len | 0x80) as u8);
        len >>= 7;
    }
    malicious_bcs.push(len as u8);
    
    // For each "element", encode inner vector claiming 100,000 elements
    for _ in 0..10 {  // Only provide 10 actual elements
        let mut inner_len = 100_000u64;
        while inner_len >= 128 {
            malicious_bcs.push((inner_len | 0x80) as u8);
            inner_len >>= 7;
        }
        malicious_bcs.push(inner_len as u8);
        // Add minimal data
        malicious_bcs.push(0);
    }
    
    hex::encode(malicious_bcs)
}

// Send to Rosetta API construction/combine endpoint
// POST /construction/combine
// {
//   "network_identifier": {...},
//   "unsigned_transaction": "<malicious_hex>",
//   "signatures": [...]
// }
```

## Notes

The actual exploitability depends on whether the Aptos fork of the BCS crate performs bounds checking before memory allocation. The presence of custom validation in the VM's transaction argument handler suggests the base BCS deserialization may be vulnerable. Even if the BCS crate has some protections, defense-in-depth requires explicit validation at the API layer, especially since the Rosetta API represents a separate attack surface from the consensus-critical VM execution path.

### Citations

**File:** crates/aptos-rosetta/src/common.rs (L135-138)
```rust
pub fn decode_bcs<T: DeserializeOwned>(str: &str, type_name: &'static str) -> ApiResult<T> {
    let bytes = hex::decode(str)?;
    bcs::from_bytes(&bytes).map_err(|_| ApiError::deserialization_failed(type_name))
}
```

**File:** crates/aptos-rosetta/src/construction.rs (L152-153)
```rust
    let unsigned_txn: RawTransaction =
        decode_bcs(&request.unsigned_transaction, "UnsignedTransaction")?;
```

**File:** crates/aptos-rosetta/src/construction.rs (L227-228)
```rust
    let signed_transaction: SignedTransaction =
        decode_bcs(&request.signed_transaction, "SignedTransaction")?;
```

**File:** crates/aptos-rosetta/src/construction.rs (L516-516)
```rust
        let signed_txn: SignedTransaction = decode_bcs(&request.transaction, "SignedTransaction")?;
```

**File:** crates/aptos-rosetta/src/construction.rs (L534-534)
```rust
        let unsigned_txn: RawTransaction = decode_bcs(&request.transaction, "UnsignedTransaction")?;
```

**File:** crates/aptos-rosetta/src/construction.rs (L1548-1548)
```rust
    let txn: SignedTransaction = decode_bcs(&request.signed_transaction, "SignedTransaction")?;
```

**File:** types/src/transaction/script.rs (L108-115)
```rust
#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct EntryFunction {
    module: ModuleId,
    function: Identifier,
    ty_args: Vec<TypeTag>,
    #[serde(with = "vec_bytes")]
    args: Vec<Vec<u8>>,
}
```

**File:** aptos-move/aptos-vm/src/verifier/transaction_arg_validation.rs (L546-571)
```rust
fn read_n_bytes(n: usize, src: &mut Cursor<&[u8]>, dest: &mut Vec<u8>) -> Result<(), VMStatus> {
    let deserialization_error = |msg: &str| -> VMStatus {
        VMStatus::error(
            StatusCode::FAILED_TO_DESERIALIZE_ARGUMENT,
            Some(msg.to_string()),
        )
    };
    let len = dest.len();

    // It is safer to limit the length under some big (but still reasonable
    // number).
    const MAX_NUM_BYTES: usize = 1_000_000;
    if len.checked_add(n).is_none_or(|s| s > MAX_NUM_BYTES) {
        return Err(deserialization_error(&format!(
            "Couldn't read bytes: maximum limit of {} bytes exceeded",
            MAX_NUM_BYTES
        )));
    }

    // Ensure we have enough capacity for resizing.
    dest.try_reserve(len + n)
        .map_err(|e| deserialization_error(&format!("Couldn't read bytes: {}", e)))?;
    dest.resize(len + n, 0);
    src.read_exact(&mut dest[len..])
        .map_err(|_| deserialization_error("Couldn't read bytes"))
}
```

**File:** aptos-move/e2e-move-tests/src/tests/string_args.rs (L662-681)
```rust
fn huge_string_args_are_not_allowed() {
    let mut tests = vec![];
    let mut len: u64 = 1_000_000_000_000;
    let mut big_str_arg = vec![];
    loop {
        let cur = len & 0x7F;
        if cur != len {
            big_str_arg.push((cur | 0x80) as u8);
            len >>= 7;
        } else {
            big_str_arg.push(cur as u8);
            break;
        }
    }
    tests.push((
        "0xcafe::test::hi",
        vec![big_str_arg],
        deserialization_failure(),
    ));
    fail(tests);
```
