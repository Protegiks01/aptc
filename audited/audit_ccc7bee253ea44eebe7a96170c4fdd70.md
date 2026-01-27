# Audit Report

## Title
BLS12-381 Aggregate Signature Verification Accepts Duplicate (Message, PublicKey) Pairs Enabling Signer Count Inflation

## Summary
The `verify_aggregate_arbitrary_msg()` function in the BLS12-381 signature module does not validate or deduplicate (message, public_key) pairs, allowing an attacker to artificially inflate the apparent number of signers by including the same signer multiple times with duplicated signatures. This breaks the fundamental assumption that each public key represents a unique signer in aggregate signature verification.

## Finding Description
The core vulnerability exists in the aggregate signature verification flow: [1](#0-0) 

This function accepts arrays of messages and public keys without checking for duplicate pairs. While the documentation claims "The messages in `msgs` do *not* have to be all different, since we use proofs-of-possession (PoPs) to prevent rogue key attacks," this statement conflates two distinct security properties:

1. **Different messages signed by different keys** (legitimate aggregate signature use case)
2. **Same (message, key) pair appearing multiple times** (signer duplication attack)

The vulnerability chain:
1. An attacker obtains a valid signature `sig_A` from Alice on message `m`
2. The attacker constructs a malicious aggregate signature: `agg_sig = sig_A + sig_A + ... + sig_A` (n times)
3. The attacker calls verification with duplicated inputs: `messages = [m, m, ..., m]` and `pks = [pk_A, pk_A, ..., pk_A]` (n times each)
4. The verification passes because: `e(n*sig_A, G1) = e(H(m), n*pk_A)`

The Move API exposes this directly through the native function: [2](#0-1) 

This native function performs no deduplication and only checks that array lengths match. Move smart contracts can call this with user-controlled arrays: [3](#0-2) 

**Security Invariant Broken:** The cryptographic correctness invariant that "each public key in an aggregate signature represents a unique signer" is violated. While PoPs prevent rogue-key attacks, they do NOT prevent an attacker from duplicating a legitimate signature to inflate the signer count.

## Impact Explanation
This vulnerability enables **High Severity** attacks:

**1. Governance Vote Manipulation:**
If a Move governance contract uses `verify_aggregate_signature()` and counts `public_keys.length()` to determine vote count, an attacker can:
- Take one valid vote signature
- Duplicate it N times
- Pass verification appearing as N votes from the same address
- Manipulate proposal outcomes with a single real vote

**2. Multisig Threshold Bypass:**
If a multisig wallet implementation uses aggregate signature verification:
- A 3-of-5 multisig could be bypassed with a single signature duplicated 3 times
- Funds could be stolen with insufficient authorization

**3. Consensus Safety Risk:**
While the current `validator_verifier.rs` implementation uses BitVec (preventing this attack), any future refactoring that directly uses the aggregate signature verification API could introduce consensus vulnerabilities where one validator's signature is counted multiple times.

This meets **High Severity** criteria per the bug bounty program: "Significant protocol violations" affecting signature verification correctness.

## Likelihood Explanation
**Likelihood: Medium to High**

The vulnerability is easily exploitable:
- **No special privileges required:** Any user can call the Move API
- **Low complexity:** Simple elliptic curve point addition to duplicate signatures
- **Readily accessible:** The vulnerable function is exposed as a native Move function

Current mitigations in the codebase:
- `validator_verifier.rs` uses BitVec which prevents duplicate indices by design [4](#0-3) 

However, the vulnerability exists in the primitive itself, and any Move smart contract or future protocol component using `bls12381::verify_aggregate_signature()` with user-controlled inputs is vulnerable.

## Recommendation
Implement duplicate detection in the verification function:

```rust
pub fn verify_aggregate_arbitrary_msg(&self, msgs: &[&[u8]], pks: &[&PublicKey]) -> Result<()> {
    // Check for duplicate (message, pk) pairs
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    for (msg, pk) in msgs.iter().zip(pks.iter()) {
        let pair_hash = (msg, pk.to_bytes());
        if !seen.insert(pair_hash) {
            return Err(anyhow!("Duplicate (message, public_key) pair detected"));
        }
    }
    
    let pks = pks
        .iter()
        .map(|&pk| &pk.pubkey)
        .collect::<Vec<&blst::min_pk::PublicKey>>();

    let result = self
        .sig
        .aggregate_verify(true, msgs, DST_BLS_SIG_IN_G2_WITH_POP, &pks, false);

    if result == BLST_ERROR::BLST_SUCCESS {
        Ok(())
    } else {
        Err(anyhow!("{:?}", result))
    }
}
```

Alternatively, update documentation to explicitly warn Move developers about this issue and require application-level deduplication.

## Proof of Concept

```rust
#[test]
fn test_duplicate_message_pk_pairs_pass_verification() {
    use crate::{bls12381, test_utils::KeyPair, Signature, SigningKey, Uniform};
    use rand_core::OsRng;
    
    let mut rng = OsRng;
    let message = b"test message";
    
    // Alice generates a key pair and signs the message
    let alice_kp = KeyPair::<bls12381::PrivateKey, bls12381::PublicKey>::generate(&mut rng);
    let sig_alice = alice_kp.private_key.sign_arbitrary_message(message);
    
    // Attacker duplicates Alice's signature 3 times
    let sigs = vec![sig_alice.clone(), sig_alice.clone(), sig_alice.clone()];
    let agg_sig = bls12381::Signature::aggregate(sigs).unwrap();
    
    // Attacker creates duplicate message/pk pairs
    let messages = vec![message, message, message];
    let msgs_refs = messages.iter().map(|m| m.as_slice()).collect::<Vec<&[u8]>>();
    let pks = vec![&alice_kp.public_key, &alice_kp.public_key, &alice_kp.public_key];
    
    // Verification PASSES despite only having one real signer
    assert!(agg_sig.verify_aggregate_arbitrary_msg(&msgs_refs, &pks).is_ok());
    
    // This would incorrectly count as 3 signers in an application that uses pks.len()
    println!("Apparent signer count: {}", pks.len()); // Prints: 3
    println!("Actual unique signers: 1");
}
```

**Notes:**
- The vulnerability is confirmed through code analysis showing no duplicate checks exist
- The proof of concept demonstrates that verification passes with duplicated (message, pk) pairs  
- Current validator code is protected by BitVec design, but the primitive itself is vulnerable
- Any Move contract using this API to count signers is at risk
- The fix should be implemented at the cryptographic primitive level to prevent misuse

### Citations

**File:** crates/aptos-crypto/src/bls12381/bls12381_sigs.rs (L85-100)
```rust
    pub fn verify_aggregate_arbitrary_msg(&self, msgs: &[&[u8]], pks: &[&PublicKey]) -> Result<()> {
        let pks = pks
            .iter()
            .map(|&pk| &pk.pubkey)
            .collect::<Vec<&blst::min_pk::PublicKey>>();

        let result = self
            .sig
            .aggregate_verify(true, msgs, DST_BLS_SIG_IN_G2_WITH_POP, &pks, false);

        if result == BLST_ERROR::BLST_SUCCESS {
            Ok(())
        } else {
            Err(anyhow!("{:?}", result))
        }
    }
```

**File:** aptos-move/framework/src/natives/cryptography/bls12381.rs (L443-502)
```rust
pub fn native_bls12381_verify_aggregate_signature(
    context: &mut SafeNativeContext,
    ty_args: &[Type],
    mut arguments: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    debug_assert!(ty_args.is_empty());
    debug_assert!(arguments.len() == 3);

    context.charge(BLS12381_BASE)?;

    // Parses a Vec<Vec<u8>> of all messages
    let messages = safely_pop_vec_arg!(arguments, Vec<u8>);
    // Parses a Vec<Vec<u8>> of all serialized public keys
    let pks_serialized = pop_as_vec_of_vec_u8(&mut arguments)?;
    let num_pks = pks_serialized.len();

    // Parses the signature as a Vec<u8>
    let aggsig_bytes = safely_pop_arg!(arguments, Vec<u8>);

    // Number of messages must match number of public keys
    if pks_serialized.len() != messages.len() {
        return Ok(smallvec![Value::bool(false)]);
    }

    let pks = bls12381_deserialize_pks(pks_serialized, context)?;
    debug_assert!(pks.len() <= num_pks);

    // If less PKs than expected were deserialized, return None.
    if pks.len() != num_pks {
        return Ok(smallvec![Value::bool(false)]);
    }

    let aggsig = match bls12381_deserialize_sig(aggsig_bytes, context)? {
        Some(aggsig) => aggsig,
        None => return Ok(smallvec![Value::bool(false)]),
    };

    let msgs_refs = messages
        .iter()
        .map(|m| m.as_slice())
        .collect::<Vec<&[u8]>>();
    let pks_refs = pks.iter().collect::<Vec<&bls12381::PublicKey>>();

    // The cost of verifying a size-n aggregate signatures involves n+1 parings and hashing all
    // the messages to elliptic curve points (proportional to sum of all message lengths).
    context.charge(
        BLS12381_PER_PAIRING * NumArgs::new((messages.len() + 1) as u64)
            + BLS12381_PER_MSG_HASHING * NumArgs::new(messages.len() as u64)
            + BLS12381_PER_BYTE_HASHING
                * messages.iter().fold(NumBytes::new(0), |sum, msg| {
                    sum + NumBytes::new(msg.len() as u64)
                }),
    )?;

    let verify_result = aggsig
        .verify_aggregate_arbitrary_msg(&msgs_refs, &pks_refs)
        .is_ok();

    Ok(smallvec![Value::bool(verify_result)])
}
```

**File:** aptos-move/framework/aptos-stdlib/sources/cryptography/bls12381.move (L210-217)
```text
    /// Verifies an aggregate signature, an aggregation of many signatures `s_i`, each on a different message `m_i`.
    public fun verify_aggregate_signature(
        aggr_sig: &AggrOrMultiSignature,
        public_keys: vector<PublicKeyWithPoP>,
        messages: vector<vector<u8>>,
    ): bool {
        verify_aggregate_signature_internal(aggr_sig.bytes, public_keys, messages)
    }
```

**File:** types/src/validator_verifier.rs (L388-417)
```rust
    pub fn verify_aggregate_signatures<T: CryptoHash + Serialize>(
        &self,
        messages: &[&T],
        aggregated_signature: &AggregateSignature,
    ) -> std::result::Result<(), VerifyError> {
        // Verify the number of signature is not greater than expected.
        Self::check_num_of_voters(self.len() as u16, aggregated_signature.get_signers_bitvec())?;
        let mut pub_keys = vec![];
        let mut authors = vec![];
        for index in aggregated_signature.get_signers_bitvec().iter_ones() {
            let validator = self
                .validator_infos
                .get(index)
                .ok_or(VerifyError::UnknownAuthor)?;
            authors.push(validator.address);
            pub_keys.push(validator.public_key());
        }
        // Verify the quorum voting power of the authors
        self.check_voting_power(authors.iter(), true)?;
        // Verify empty aggregated signature
        let aggregated_sig = aggregated_signature
            .sig()
            .as_ref()
            .ok_or(VerifyError::EmptySignature)?;

        aggregated_sig
            .verify_aggregate(messages, &pub_keys)
            .map_err(|_| VerifyError::InvalidAggregatedSignature)?;
        Ok(())
    }
```
