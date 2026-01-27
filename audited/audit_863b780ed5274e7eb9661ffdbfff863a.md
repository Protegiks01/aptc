# Audit Report

## Title
Governance Proposal Simulation Accepts Unverified State Data from Remote Nodes Leading to Incorrect Simulation Results

## Summary
The `simulate_multistep_proposal()` function fetches blockchain state from a remote REST API endpoint without performing any cryptographic validation (Merkle proofs, state root verification, or signature verification). A compromised or malicious node can provide arbitrary state data, causing governance proposal simulations to produce incorrect results and potentially leading to deployment of flawed or malicious governance proposals on-chain.

## Finding Description

The governance proposal simulation infrastructure in Aptos Core is designed to test multi-step governance proposals before on-chain submission. However, the implementation has a critical flaw in how it fetches and validates remote state data.

**Vulnerable Code Path:** [1](#0-0) 

The simulation creates a REST client connected to `remote_url`, retrieves the current ledger version, and creates a state view without any cryptographic validation: [2](#0-1) 

The `AptosDebugger` wraps a `RestDebuggerInterface` which fetches state values via HTTP: [3](#0-2) 

This calls the REST API endpoint which returns only the raw state value: [4](#0-3) 

**Missing Security Controls:**

1. **No Merkle Proof Verification**: While Aptos storage supports proof verification, the REST API endpoint only returns raw state values without proofs
2. **No State Root Validation**: The ledger information returned contains no cryptographic commitment that can be verified
3. **No Validator Signature Verification**: There's no `LedgerInfoWithSignatures` validation to ensure the state comes from a quorum of validators
4. **Complete Trust Model**: The simulation blindly trusts whatever data the remote node returns

**Attack Scenario:**

An attacker can exploit this by:
1. Running a malicious Aptos node with modified REST API responses
2. Having proposal developers point their simulation to this compromised node
3. Providing manipulated state data:
   - Modified gas schedules to hide gas-related failures
   - Fake framework code to bypass security checks in simulation
   - Incorrect on-chain configurations
   - Manipulated account balances or resource data

The simulation would then produce false results, causing:
- Proposals that should fail to appear successful in simulation
- Hidden exploits or bugs that aren't caught during testing
- Incorrect gas estimations leading to transaction failures on-chain

**Invariant Violation:**

This breaks the **State Consistency** invariant (#4): "State transitions must be atomic and verifiable via Merkle proofs." The simulation accepts unverifiable state data that could be completely fabricated.

## Impact Explanation

**Severity: CRITICAL** (up to $1,000,000)

This vulnerability falls under the "Significant protocol violations" category and has severe implications for governance integrity:

1. **Governance Compromise**: Malicious governance proposals could be simulated to appear safe when they're actually exploitable
2. **Hidden Bugs**: Critical bugs in governance scripts could be hidden from developers during simulation
3. **Network-Wide Impact**: Incorrect proposals deployed on-chain could affect the entire Aptos network
4. **Consensus Safety Risk**: If governance proposals modify consensus parameters based on false simulation results, it could lead to consensus violations

While this doesn't directly cause immediate fund loss, it undermines the security validation process for governance proposals, which control critical network parameters, validator operations, and can execute arbitrary Move code with elevated privileges.

## Likelihood Explanation

**Likelihood: HIGH**

The attack is highly feasible because:

1. **Low Barrier to Entry**: Anyone can run an Aptos node and modify the REST API responses
2. **Common Usage Pattern**: Developers frequently use remote nodes for simulation rather than local nodes
3. **No Warning Signs**: The simulation provides no indication that state validation is missing
4. **Trust Assumption**: Users naturally assume the simulation performs proper validation
5. **No Authentication Required**: The `remote_url` parameter accepts any URL without requiring credentials or trust establishment

An attacker only needs to:
- Set up a fake Aptos node or compromise an existing one
- Convince a proposal developer to use their node (via social engineering or by running a "public" node)
- Modify specific state values to hide vulnerabilities or cause false positives

## Recommendation

Implement cryptographic validation of all state data fetched from remote sources:

**Option 1: Add Proof Verification**

Modify the REST API to return state values with Merkle proofs and verify them:

```rust
// In simulate.rs, after fetching state
pub async fn simulate_multistep_proposal(
    remote_url: Url,
    proposal_dir: &Path,
    proposal_scripts: &[PathBuf],
    profile_gas: bool,
    node_api_key: Option<String>,
) -> Result<()> {
    // ... existing code ...
    
    let client = client_builder.build();
    
    // NEW: Fetch and verify ledger info with validator signatures
    let ledger_info_with_sigs = client
        .get_ledger_info_with_signatures()
        .await?
        .into_inner();
    
    // NEW: Verify quorum signatures
    verify_ledger_info_signatures(&ledger_info_with_sigs, &validator_verifier)?;
    
    let trusted_state_root = ledger_info_with_sigs.ledger_info().state_root();
    
    // Use a verified state view that checks proofs
    let debugger = AptosDebugger::rest_client_with_verification(
        client.clone(),
        trusted_state_root,
    )?;
    
    // ... rest of simulation ...
}
```

**Option 2: Require Local Node**

Add a safety check that requires using a local node or explicitly trusted node:

```rust
pub async fn simulate_multistep_proposal(
    remote_url: Url,
    proposal_dir: &Path,
    proposal_scripts: &[PathBuf],
    profile_gas: bool,
    node_api_key: Option<String>,
) -> Result<()> {
    // NEW: Warn about untrusted remote state
    if !remote_url.host_str().map_or(false, |h| h == "localhost" || h == "127.0.0.1") {
        eprintln!("WARNING: Fetching state from remote node without cryptographic verification.");
        eprintln!("A compromised node could provide malicious state data.");
        eprintln!("For production governance proposals, use a local trusted node.");
        eprintln!("Continue? [y/N]: ");
        
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            bail!("Simulation cancelled by user");
        }
    }
    
    // ... existing code ...
}
```

**Option 3: Add State Proof API Endpoint**

Extend the REST API to return state values with proofs and verify them in the debugger interface.

## Proof of Concept

**Setup for Malicious Node:**

```rust
// malicious_node.rs - Simulates a compromised Aptos node
use actix_web::{post, web, App, HttpResponse, HttpServer, Result};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct StateValueRequest {
    key: String,
}

#[post("/experimental/state_values/raw")]
async fn malicious_state_value(req: web::Json<StateValueRequest>) -> Result<HttpResponse> {
    // Return fake gas schedule that hides high gas costs
    let fake_gas_schedule = create_manipulated_gas_schedule();
    
    Ok(HttpResponse::Ok()
        .content_type("application/x-bcs")
        .body(bcs::to_bytes(&fake_gas_schedule).unwrap()))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Starting malicious Aptos node on localhost:8080");
    HttpServer::new(|| {
        App::new()
            .service(malicious_state_value)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

**Exploitation Steps:**

1. Run the malicious node: `cargo run --bin malicious_node`
2. Execute simulation pointing to the compromised node:
```bash
aptos-release-builder simulate-proposal \
    --remote-url http://localhost:8080 \
    --proposal-dir ./malicious_proposal
```
3. The simulation fetches fake state data from the malicious node
4. Governance proposal appears to succeed with manipulated gas costs
5. Real on-chain execution fails or behaves unexpectedly

**Verification:**

Monitor network traffic during simulation:
```bash
tcpdump -i lo -A 'tcp port 8080'
```

You'll see the simulation making POST requests to `/experimental/state_values/raw` and accepting whatever data is returned without any validation.

## Notes

This vulnerability is particularly concerning because:

1. **Silent Failure**: There's no indication to users that state validation is missing
2. **Production Use**: This simulation tool is intended for validating critical governance proposals
3. **Wide Attack Surface**: Any public Aptos node could be compromised to serve malicious data
4. **Trust Chain Break**: Even if the node operator is honest, a network MITM attack could inject fake responses

The Aptos blockchain correctly implements Merkle proof verification in its core storage layer, but this simulation tool bypasses these security mechanisms by using an unverified REST API interface.

### Citations

**File:** aptos-move/aptos-release-builder/src/simulate.rs (L401-411)
```rust
    let mut client_builder = Client::builder(AptosBaseUrl::Custom(remote_url));
    if let Some(api_key) = node_api_key.clone() {
        client_builder = client_builder.api_key(&api_key)?;
    }
    let client = client_builder.build();

    let debugger =
        AptosDebugger::rest_client(client.clone()).context("failed to create AptosDebugger")?;
    let state = client.get_ledger_information().await?.into_inner();

    let state_view = DeltaStateStore::new_with_base(debugger.state_view_at_version(state.version));
```

**File:** aptos-move/aptos-debugger/src/aptos_debugger.rs (L44-46)
```rust
    pub fn rest_client(rest_client: Client) -> anyhow::Result<Self> {
        Ok(Self::new(Arc::new(RestDebuggerInterface::new(rest_client))))
    }
```

**File:** aptos-move/aptos-validator-interface/src/rest_interface.rs (L199-219)
```rust
    async fn get_state_value_by_version(
        &self,
        state_key: &StateKey,
        version: Version,
    ) -> Result<Option<StateValue>> {
        match self.0.get_raw_state_value(state_key, version).await {
            Ok(resp) => Ok(Some(bcs::from_bytes(&resp.into_inner())?)),
            Err(err) => match err {
                RestError::Api(AptosErrorResponse {
                    error:
                        AptosError {
                            error_code:
                                AptosErrorCode::StateValueNotFound | AptosErrorCode::TableItemNotFound, /* bug in pre 1.9 nodes */
                            ..
                        },
                    ..
                }) => Ok(None),
                _ => Err(anyhow!(err)),
            },
        }
    }
```

**File:** api/src/state.rs (L548-568)
```rust
        let state_value = state_view
            .get_state_value(&state_key)
            .context(format!("Failed fetching state value. key: {}", request.key,))
            .map_err(|err| {
                BasicErrorWith404::internal_with_code(
                    err,
                    AptosErrorCode::InternalError,
                    &ledger_info,
                )
            })?
            .ok_or_else(|| {
                build_not_found(
                    "Raw State Value",
                    format!(
                        "StateKey({}) and Ledger version({})",
                        request.key, ledger_version
                    ),
                    AptosErrorCode::StateValueNotFound,
                    &ledger_info,
                )
            })?;
```
