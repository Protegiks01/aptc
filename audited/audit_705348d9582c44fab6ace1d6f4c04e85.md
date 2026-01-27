# Audit Report

## Title
Missing Minimum Protocol Version Enforcement Enables Future Version Downgrade Attacks

## Summary
The network handshake protocol negotiation lacks minimum version enforcement, creating an architectural vulnerability that will enable protocol version downgrade attacks once newer `MessagingProtocolVersion` values (V2, V3, etc.) are introduced. Currently, only V1 exists, making this a latent vulnerability.

## Finding Description

The protocol negotiation mechanism in `HandshakeMsg::perform_handshake()` selects the highest **common** `MessagingProtocolVersion` between two peers without enforcing any minimum version requirement. [1](#0-0) 

The negotiation iterates through supported protocols in reverse order (highest to lowest) and accepts the first common version found. [2](#0-1) 

**Attack Scenario (when V2+ are introduced):**

1. Assume V2 is released that fixes critical security vulnerabilities present in V1
2. Honest validators upgrade and advertise support for both V1 and V2: `{V1: protocols, V2: protocols}`
3. A malicious peer deliberately omits V2 from their handshake, advertising only: `{V1: protocols}`
4. The negotiation finds V1 as the highest common version and accepts it
5. Connection proceeds using V1, enabling exploitation of vulnerabilities that were fixed in V2

The connection upgrade functions accept whatever version is negotiated without validating it meets a minimum requirement. [3](#0-2) 

**Current State:** Only `MessagingProtocolVersion::V1` exists. [4](#0-3) 

The constant `SUPPORTED_MESSAGING_PROTOCOL` is hardcoded to V1. [5](#0-4) 

## Impact Explanation

**Current Impact: None** - This vulnerability is not currently exploitable because only V1 exists.

**Future Impact: HIGH Severity** - Once V2+ are introduced:
- Enables exploitation of known vulnerabilities in older protocol versions
- Affects all network communication including consensus messages between validators
- Could lead to consensus safety violations if V1 has vulnerabilities that enable equivocation or Byzantine behavior
- No validator privileges required - any network peer can force the downgrade
- Violates the "Cryptographic Correctness" invariant if older protocols have known cryptographic weaknesses

## Likelihood Explanation

**Current Likelihood: Zero** - Cannot occur until V2+ are introduced to the codebase.

**Future Likelihood: High** - Once V2 is added:
- Attack is trivial - simply omit newer versions from the handshake message
- No special network position or validator status required
- Downgrade is silent and may go undetected
- All network peers are potential targets

## Recommendation

Implement minimum protocol version enforcement in the handshake negotiation:

```rust
// In UpgradeContext
pub struct UpgradeContext {
    noise: NoiseUpgrader,
    handshake_version: u8,
    supported_protocols: BTreeMap<MessagingProtocolVersion, ProtocolIdSet>,
    minimum_required_protocol: MessagingProtocolVersion, // Add this field
    chain_id: ChainId,
    network_id: NetworkId,
}

// In HandshakeMsg::perform_handshake()
pub fn perform_handshake(
    &self,
    other: &HandshakeMsg,
    minimum_required_version: MessagingProtocolVersion,
) -> Result<(MessagingProtocolVersion, ProtocolIdSet), HandshakeError> {
    // ... existing chain_id and network_id checks ...

    // Find the greatest common MessagingProtocolVersion
    for (our_handshake_version, our_protocols) in self.supported_protocols.iter().rev() {
        if let Some(their_protocols) = other.supported_protocols.get(our_handshake_version) {
            let common_protocols = our_protocols.intersect(their_protocols);

            if !common_protocols.is_empty() {
                // NEW: Validate minimum version requirement
                if *our_handshake_version < minimum_required_version {
                    return Err(HandshakeError::ProtocolVersionTooOld(
                        *our_handshake_version,
                        minimum_required_version,
                    ));
                }
                return Ok((*our_handshake_version, common_protocols));
            }
        }
    }

    Err(HandshakeError::NoCommonProtocols)
}
```

Add configuration-based minimum version that can be updated via on-chain governance when V2+ are deployed.

## Proof of Concept

**Cannot currently demonstrate** - Only V1 exists in the codebase, making downgrade impossible. The vulnerability will become exploitable when V2 is introduced.

A future PoC would involve:
1. Creating a malicious peer that advertises only V1 support
2. Connecting to an honest peer that supports V1 and V2
3. Observing that the connection succeeds with V1 despite V2 being available
4. Exploiting a hypothetical V1-specific vulnerability

---

## Notes

**Critical Clarification:** This is an **architectural vulnerability** that is **not currently exploitable** because only `MessagingProtocolVersion::V1` exists in the codebase. There is no older version to downgrade to, and no V2 with security fixes.

However, the architecture **lacks defense-in-depth** against version downgrade attacks. When V2+ are added in the future (especially if they fix security issues in V1), this missing enforcement will become a **HIGH severity vulnerability**.

The finding satisfies most validation criteria except "currently exploitable with demonstrable PoC" - making this a **design flaw requiring remediation before V2 deployment** rather than an immediate security issue.

**Recommendation priority:** Address this during V2 protocol design, before deployment.

### Citations

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L359-361)
```rust
pub enum MessagingProtocolVersion {
    V1 = 0,
}
```

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L451-461)
```rust
        // find the greatest common MessagingProtocolVersion where we both support
        // at least one common ProtocolId.
        for (our_handshake_version, our_protocols) in self.supported_protocols.iter().rev() {
            if let Some(their_protocols) = other.supported_protocols.get(our_handshake_version) {
                let common_protocols = our_protocols.intersect(their_protocols);

                if !common_protocols.is_empty() {
                    return Ok((*our_handshake_version, common_protocols));
                }
            }
        }
```

**File:** network/framework/src/transport/mod.rs (L45-45)
```rust
pub const SUPPORTED_MESSAGING_PROTOCOL: MessagingProtocolVersion = MessagingProtocolVersion::V1;
```

**File:** network/framework/src/transport/mod.rs (L308-317)
```rust
    let (messaging_protocol, application_protocols) = handshake_msg
        .perform_handshake(&remote_handshake)
        .map_err(|err| {
            let err = format!(
                "handshake negotiation with peer {} failed: {}",
                remote_peer_id.short_str(),
                err
            );
            add_pp_addr(proxy_protocol_enabled, io::Error::other(err), &addr)
        })?;
```
