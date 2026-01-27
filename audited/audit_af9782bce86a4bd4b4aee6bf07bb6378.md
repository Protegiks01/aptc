# Audit Report

## Title
2-Chain Timeout Signature Does Not Bind to QuorumCert Content, Only to Round Number

## Summary
The 2-chain timeout signature verification only validates the round number of the highest quorum certificate (hqc_round) but does not cryptographically bind to the actual QuorumCert content. This allows substitution of different QCs with the same round number while maintaining signature validity.

## Finding Description

The vulnerability exists in how timeout signatures are created and verified in the 2-chain consensus protocol.

**Signature Creation**: [1](#0-0) 

The `signing_format()` method creates a `TimeoutSigningRepr` containing only `(epoch, round, hqc_round)` where `hqc_round` is extracted from the QuorumCert's round number: [2](#0-1) 

**Signature Verification**: [3](#0-2) 

During verification, the signature is checked against `timeout.signing_format()` which recomputes the `hqc_round` from the timeout's current QuorumCert.

**The TimeoutSigningRepr structure**: [4](#0-3) 

This structure contains NO hash or identifier of the actual QuorumCert content—only the round number.

**Attack Scenario**:
1. Validator V creates a timeout for round 12 with QuorumCert QC_A (certifying Block X at round 10)
2. V signs `TimeoutSigningRepr{epoch: 1, round: 12, hqc_round: 10}`
3. Attacker intercepts the vote and replaces QC_A with QC_B (certifying Block Y, also at round 10)
4. Verification passes: `timeout.verify()` validates QC_B is valid, and signature verification passes because `hqc_round` is still 10
5. The timeout certificate aggregation uses QC_B instead of QC_A that the validator actually certified

**Where this matters**: [5](#0-4) 

The `safe_to_vote` function uses the timeout certificate's highest QC round to make safety decisions about which blocks can be voted on.

## Impact Explanation

**Severity Assessment: Does NOT meet High/Critical criteria**

While this represents a cryptographic weakness where signatures don't fully bind to what they're certifying, the practical exploitability is extremely limited:

1. **Requires Pre-existing Safety Violation**: The attack requires two different valid QuorumCerts for the same round to exist simultaneously. Under BFT consensus safety guarantees with <1/3 Byzantine validators, only ONE valid QC should exist per round.

2. **No Direct Consensus Break**: The vulnerability doesn't directly cause consensus safety violations—it only allows manipulation IF consensus safety is already compromised.

3. **Defense-in-Depth Issue**: This is primarily a defense-in-depth concern rather than a directly exploitable vulnerability.

## Likelihood Explanation

**Likelihood: Very Low**

Exploitation requires:
- Two different valid QuorumCerts for the same round (violates BFT safety)
- Network-level interception and modification of vote messages
- Precise timing to substitute QCs before verification

Under normal operations with honest 2f+1 validators, this scenario cannot occur. It only becomes possible if >1/3 validators are Byzantine and actively equivocating, at which point consensus safety is already broken.

## Recommendation

Include a cryptographic hash of the QuorumCert in the `TimeoutSigningRepr` to bind signatures to the actual QC content:

```rust
#[derive(Serialize, Deserialize, Debug, CryptoHasher, BCSCryptoHash)]
pub struct TimeoutSigningRepr {
    pub epoch: u64,
    pub round: Round,
    pub hqc_round: Round,
    pub hqc_hash: HashValue,  // Add: Hash of the QuorumCert
}
```

Update `signing_format()`:
```rust
pub fn signing_format(&self) -> TimeoutSigningRepr {
    TimeoutSigningRepr {
        epoch: self.epoch(),
        round: self.round(),
        hqc_round: self.hqc_round(),
        hqc_hash: self.quorum_cert.hash(),  // Bind to QC content
    }
}
```

## Proof of Concept

This vulnerability cannot be exploited in a realistic scenario without first breaking BFT consensus safety assumptions. A PoC would require:

1. Creating two different valid QCs for the same round (requires >1/3 Byzantine validators)
2. Intercepting vote messages (network-level attack)
3. Substituting QCs while maintaining valid signatures

**Conclusion**: While the signature scheme is cryptographically weaker than ideal, this does NOT constitute an exploitable vulnerability under the Aptos bug bounty criteria because:
- It requires pre-existing consensus safety violations to exploit
- It does not meet the "exploitable by unprivileged attacker" criterion
- No realistic attack path exists under normal BFT operation with <1/3 Byzantine validators

**Note**: This is a valuable defense-in-depth improvement but not a bounty-eligible vulnerability.

### Citations

**File:** consensus/consensus-types/src/timeout_2chain.rs (L51-53)
```rust
    pub fn hqc_round(&self) -> Round {
        self.quorum_cert.certified_block().round()
    }
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L66-72)
```rust
    pub fn signing_format(&self) -> TimeoutSigningRepr {
        TimeoutSigningRepr {
            epoch: self.epoch(),
            round: self.round(),
            hqc_round: self.hqc_round(),
        }
    }
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L98-103)
```rust
#[derive(Serialize, Deserialize, Debug, CryptoHasher, BCSCryptoHash)]
pub struct TimeoutSigningRepr {
    pub epoch: u64,
    pub round: Round,
    pub hqc_round: Round,
}
```

**File:** consensus/consensus-types/src/vote.rs (L161-171)
```rust
        if let Some((timeout, signature)) = &self.two_chain_timeout {
            ensure!(
                (timeout.epoch(), timeout.round())
                    == (self.epoch(), self.vote_data.proposed().round()),
                "2-chain timeout has different (epoch, round) than Vote"
            );
            timeout.verify(validator)?;
            validator
                .verify(self.author(), &timeout.signing_format(), signature)
                .context("Failed to verify 2-chain timeout signature")?;
        }
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L147-166)
```rust
    /// Core safety voting rule for 2-chain protocol. Return success if 1 or 2 is true
    /// 1. block.round == block.qc.round + 1
    /// 2. block.round == tc.round + 1 && block.qc.round >= tc.highest_hqc.round
    fn safe_to_vote(
        &self,
        block: &Block,
        maybe_tc: Option<&TwoChainTimeoutCertificate>,
    ) -> Result<(), Error> {
        let round = block.round();
        let qc_round = block.quorum_cert().certified_block().round();
        let tc_round = maybe_tc.map_or(0, |tc| tc.round());
        let hqc_round = maybe_tc.map_or(0, |tc| tc.highest_hqc_round());
        if round == next_round(qc_round)?
            || (round == next_round(tc_round)? && qc_round >= hqc_round)
        {
            Ok(())
        } else {
            Err(Error::NotSafeToVote(round, qc_round, tc_round, hqc_round))
        }
    }
```
