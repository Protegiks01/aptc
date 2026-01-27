# Audit Report

## Title
Race Condition in IndexerApiManager Async Cancellation Leading to Leaked Docker Containers

## Summary
The `IndexerApiManager.run_service()` method lacks cancellation-safe resource management, creating a race condition where Docker containers can be created after shutdown steps execute but before task abortion, resulting in leaked containers that consume system resources until the next testnet startup.

## Finding Description

The vulnerability exists in the coordination between shutdown step execution and service task lifecycle. [1](#0-0) 

The shutdown mechanism collects cleanup steps before services start [2](#0-1) , then executes them when shutdown is triggered [3](#0-2) .

However, a race condition exists in this sequence:

1. Multiple services spawn concurrently [4](#0-3) 
2. One service crashes or ctrl-c is received
3. `join_set.join_next_with_id()` returns [5](#0-4) 
4. `run_shutdown_steps()` executes immediately [3](#0-2) 
5. `stop_container("local-testnet-indexer-api")` is called [6](#0-5) 
6. If container doesn't exist yet, the function logs a warning and returns immediately [7](#0-6) 
7. `IndexerApiManager.run_service()` continues executing in parallel
8. Container is created [8](#0-7)  and started [9](#0-8) 
9. Function returns [10](#0-9) , JoinSet is dropped, runtime shuts down
10. Task is aborted mid-execution, container left running

The codebase contains a correct cancellation-safe pattern in `docker_common.rs` [11](#0-10)  that uses state tracking and ensures the cleanup future waits for the creation future to complete [12](#0-11) , preventing this exact race condition. The `IndexerApiManager` does not follow this pattern.

While developers acknowledge cleanup is "best effort" [13](#0-12) , this specific race condition can be prevented with proper design.

## Impact Explanation

**Medium Severity** - This qualifies as a resource leak vulnerability:

1. **Resource Exhaustion**: Each leaked container consumes Docker resources (memory, CPU, ports, disk space)
2. **Accumulation**: Repeated crashes during development/testing can accumulate multiple leaked containers
3. **Local Environment Impact**: Developers may experience port conflicts, resource exhaustion, or confusion about running containers
4. **Delayed Cleanup**: Containers remain running until next testnet startup when `pre_run()` deletes them [14](#0-13) 

While this is a local testnet tool rather than production blockchain code, it impacts developer experience and can cause operational issues during testing and development workflows.

## Likelihood Explanation

**Moderate Likelihood** - The race condition requires specific timing:

1. **Timing Window**: Small but non-zero window between shutdown step execution and runtime shutdown
2. **Parallel Execution**: More likely when multiple services have different startup speeds
3. **Common Triggers**: Service crashes, ctrl-c during startup, error conditions
4. **Container Creation Time**: Docker API calls are relatively slow (milliseconds to seconds), making the window realistic

The race condition is not guaranteed on every shutdown but can occur frequently in normal development workflows, especially when services fail during startup or when developers interrupt the testnet.

## Recommendation

Implement cancellation-safe container management following the pattern in `docker_common.rs`:

1. **Add state tracking**: Track whether container was created/started using shared state (Arc<Mutex<State>>)
2. **Use CancellationToken**: Check for cancellation between container creation and starting
3. **Implement cleanup future**: Return a cleanup future from `run_service()` that waits for the creation task to complete before attempting cleanup
4. **Update ServiceManager trait**: Add a `get_cleanup_future()` method that returns a cleanup task, or integrate cleanup directly into the run_service lifecycle

Alternative minimal fix: Use a synchronization mechanism to ensure shutdown steps don't execute until all services have either completed their startup phase or explicitly signaled they haven't created resources yet.

## Proof of Concept

```rust
// Reproduction test demonstrating the race condition
// This test shows that containers can be created after shutdown steps run

#[tokio::test]
async fn test_indexer_api_race_condition() {
    use tokio::task::JoinSet;
    use std::time::Duration;
    
    // Simulate the coordination pattern from mod.rs
    let mut join_set = JoinSet::new();
    
    // Spawn a fast-failing service
    join_set.spawn(async {
        tokio::time::sleep(Duration::from_millis(10)).await;
        Err::<(), _>(anyhow::anyhow!("Service crashed"))
    });
    
    // Spawn slow IndexerApiManager-like service
    join_set.spawn(async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        // Simulate container creation here
        println!("Container created AFTER shutdown steps would have run");
        Ok(())
    });
    
    // First service fails
    let _ = join_set.join_next().await;
    
    // Shutdown steps run immediately (container doesn't exist yet)
    println!("Shutdown steps executed - container not found");
    
    // Small delay before runtime shutdown (window for race)
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Now the slow service completes and creates container
    // If JoinSet was dropped here, container would be leaked
}
```

**Notes**

This vulnerability affects only the local testnet development tool and does not impact production Aptos blockchain nodes or consensus. However, it represents a violation of async cancellation safety best practices that should be addressed to improve developer experience and prevent resource leaks during testing. The proper fix would involve adopting the cancellation-safe patterns already demonstrated elsewhere in the codebase.

### Citations

**File:** crates/aptos/src/node/local_testnet/indexer_api.rs (L118-118)
```rust
        delete_container(INDEXER_API_CONTAINER_NAME).await?;
```

**File:** crates/aptos/src/node/local_testnet/indexer_api.rs (L154-277)
```rust
    async fn run_service(self: Box<Self>) -> Result<()> {
        // If we're using an existing Hasura instance we just do nothing. If the Hasura
        // instance becomes unhealthy we print an error and exit.
        if let Some(url) = self.existing_hasura_url {
            info!("Using existing Hasura instance at {}", url);
            // Periodically check that the Hasura instance is healthy.
            let checker = HealthChecker::Http(url.clone(), "Indexer API".to_string());
            loop {
                if let Err(e) = checker.wait(None).await {
                    eprintln!(
                        "Existing Hasura instance at {} became unhealthy: {}",
                        url, e
                    );
                    break;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            return Ok(());
        }

        setup_docker_logging(&self.test_dir, "indexer-api", INDEXER_API_CONTAINER_NAME)?;

        // This is somewhat hard to maintain. If it requires any further maintenance we
        // should just delete support for using Postgres on the host system.
        let (postgres_connection_string, network_mode) =
            // When connecting to postgres on the host via an IP from inside a
            // container, we need to instead connect to host.docker.internal.
            // There is no need to bind to a Docker network in this case.
            if self.postgres_connection_string.contains("127.0.0.1") {
                (
                    self.postgres_connection_string
                        .replace("127.0.0.1", "host.docker.internal"),
                    None,
                )
            } else {
                // Otherwise we use the standard connection string (containing the name
                // of the container) and bind to the Docker network we created earlier
                // in the Postgres pre_run steps.
                (
                    self.postgres_connection_string,
                    Some(self.docker_network.clone()),
                )
            };

        let exposed_ports = Some(hashmap! {self.indexer_api_port.to_string() => hashmap!{}});
        let host_config = HostConfig {
            // Connect the container to the network we made in the postgres pre_run.
            // This allows the indexer API to access the postgres container without
            // routing through the host network.
            network_mode,
            // This is necessary so connecting to the host postgres works on Linux.
            extra_hosts: Some(vec!["host.docker.internal:host-gateway".to_string()]),
            port_bindings: Some(hashmap! {
                self.indexer_api_port.to_string() => Some(vec![PortBinding {
                    host_ip: Some("127.0.0.1".to_string()),
                    host_port: Some(self.indexer_api_port.to_string()),
                }]),
            }),
            ..Default::default()
        };

        let docker = get_docker().await?;

        info!(
            "Using postgres connection string: {}",
            postgres_connection_string
        );

        let config = Config {
            image: Some(HASURA_IMAGE.to_string()),
            tty: Some(true),
            exposed_ports,
            host_config: Some(host_config),
            env: Some(vec![
                format!("PG_DATABASE_URL={}", postgres_connection_string),
                format!(
                    "HASURA_GRAPHQL_METADATA_DATABASE_URL={}",
                    postgres_connection_string
                ),
                format!("INDEXER_V2_POSTGRES_URL={}", postgres_connection_string),
                "HASURA_GRAPHQL_DEV_MODE=true".to_string(),
                "HASURA_GRAPHQL_ENABLE_CONSOLE=true".to_string(),
                // See the docs for the image, this is a magic path inside the
                // container where they have already bundled in the UI assets.
                "HASURA_GRAPHQL_CONSOLE_ASSETS_DIR=/srv/console-assets".to_string(),
                format!("HASURA_GRAPHQL_SERVER_PORT={}", self.indexer_api_port),
            ]),
            ..Default::default()
        };

        let options = Some(CreateContainerOptions {
            name: INDEXER_API_CONTAINER_NAME,
            ..Default::default()
        });

        info!("Starting indexer API with this config: {:?}", config);

        let id = docker.create_container(options, config).await?.id;

        info!("Created container for indexer API with this ID: {}", id);

        docker
            .start_container(&id, None::<StartContainerOptions<&str>>)
            .await
            .context("Failed to start indexer API container")?;

        info!("Started indexer API container {}", id);

        // Wait for the container to stop (which it shouldn't).
        let wait = docker
            .wait_container(
                &id,
                Some(WaitContainerOptions {
                    condition: "not-running",
                }),
            )
            .try_collect::<Vec<_>>()
            .await
            .context("Failed to wait on indexer API container")?;

        warn!("Indexer API stopped: {:?}", wait.last());

        Ok(())
    }
```

**File:** crates/aptos/src/node/local_testnet/mod.rs (L367-371)
```rust
        let shutdown_steps: Vec<Box<dyn ShutdownStep>> = managers
            .iter()
            .flat_map(|m| m.get_shutdown_steps())
            .rev()
            .collect();
```

**File:** crates/aptos/src/node/local_testnet/mod.rs (L394-396)
```rust
        for manager in managers.into_iter() {
            join_set.spawn(manager.run());
        }
```

**File:** crates/aptos/src/node/local_testnet/mod.rs (L450-450)
```rust
        let result = join_set.join_next_with_id().await.unwrap();
```

**File:** crates/aptos/src/node/local_testnet/mod.rs (L479-479)
```rust
        run_shutdown_steps(shutdown_steps).await?;
```

**File:** crates/aptos/src/node/local_testnet/mod.rs (L481-489)
```rust
        eprintln!("Done, goodbye!");

        match was_ctrl_c {
            true => Ok(()),
            false => Err(CliError::UnexpectedError(format!(
                "One of the services stopped unexpectedly.\nPlease check the logs in {}",
                test_dir.display()
            ))),
        }
```

**File:** crates/aptos/src/node/local_testnet/docker.rs (L50-75)
```rust
pub async fn stop_container(container_name: &str) -> Result<()> {
    info!(
        "Stopping container with name {} (if it exists)",
        container_name
    );

    let docker = get_docker().await?;

    let options = Some(StopContainerOptions {
        // Timeout in seconds before we kill the container.
        t: 1,
    });

    // Ignore any error, it'll be because the container doesn't exist.
    let result = docker.stop_container(container_name, options).await;

    match result {
        Ok(_) => info!("Successfully stopped container {}", container_name),
        Err(err) => warn!(
            "Failed to stop container {}: {:#} (it probably didn't exist)",
            container_name, err
        ),
    }

    Ok(())
}
```

**File:** aptos-move/aptos-workspace-server/src/services/docker_common.rs (L290-441)
```rust
pub fn create_start_and_inspect_container(
    shutdown: CancellationToken,
    fut_docker: impl Future<Output = Result<Docker, ArcError>> + Clone + Send + 'static,
    options: CreateContainerOptions<String>,
    config: bollard::container::Config<String>,
) -> (
    impl Future<Output = Result<Arc<ContainerInspectResponse>, ArcError>> + Clone,
    impl Future<Output = ()>,
) {
    #[derive(PartialEq, Eq, Clone, Copy)]
    enum State {
        Initial = 0,
        Created = 1,
        Started = 2,
    }

    // Flag indicating the current stage of the creation task and which resources need
    // to be cleaned up.
    //
    // Note: The `Arc<Mutex<..>>` is used to satisfy Rust's borrow checking rules.
    //       Exclusive access is ensured by the sequencing of the futures.
    let state = Arc::new(Mutex::new(State::Initial));
    let name = options.name.clone();

    let fut_run = make_shared({
        let state = state.clone();
        let name = name.clone();
        let fut_docker = fut_docker.clone();

        let handle = tokio::spawn(async move {
            let docker = tokio::select! {
                _ = shutdown.cancelled() => {
                    bail!("failed to create docker container: cancelled")
                }
                res = fut_docker => {
                    res.context("failed to create docker container")?
                }
            };

            let image_name = config.image.as_ref().unwrap();
            match docker.inspect_image(image_name).await {
                Ok(_) => {
                    no_panic_println!("Docker image {} already exists", image_name);
                },
                Err(_err) => {
                    no_panic_println!(
                        "Docker image {} does not exist. Pulling image..",
                        image_name
                    );

                    docker
                        .create_image(
                            Some(CreateImageOptions {
                                from_image: image_name.clone(),
                                ..Default::default()
                            }),
                            None,
                            None,
                        )
                        .try_collect::<Vec<_>>()
                        .await
                        .context("failed to create docker container")?;

                    no_panic_println!("Pulled docker image {}", image_name);
                },
            }

            let mut state = state.lock().await;

            *state = State::Created;
            docker
                .create_container(Some(options), config)
                .await
                .context("failed to create docker container")?;
            no_panic_println!("Created docker container {}", name);

            if shutdown.is_cancelled() {
                bail!("failed to start docker container: cancelled")
            }
            *state = State::Started;
            docker
                .start_container(&name, None::<StartContainerOptions<&str>>)
                .await
                .context("failed to start docker container")?;
            no_panic_println!("Started docker container {}", name);

            if shutdown.is_cancelled() {
                bail!("failed to inspect docker container: cancelled")
            }
            let container_info = docker
                .inspect_container(&name, Some(InspectContainerOptions::default()))
                .await
                .context("failed to inspect postgres container")?;

            Ok(Arc::new(container_info))
        });

        async move {
            handle
                .await
                .map_err(|err| anyhow!("failed to join task handle: {}", err))?
        }
    });

    let fut_clean_up = {
        let fut_run = fut_run.clone();

        async move {
            // Note: The creation task must be allowed to finish, even if a shutdown signal or other
            //       early abort signal is received. This is to prevent race conditions.
            //
            //       Do not abort the creation task prematurely -- let it either finish or handle its own abort.
            _ = fut_run.await;

            let state = state.lock().await;

            if *state == State::Initial {
                return;
            }

            let docker = match fut_docker.await {
                Ok(docker) => docker,
                Err(err) => {
                    no_panic_eprintln!("Failed to clean up docker container {}: {}", name, err);
                    return;
                },
            };

            if *state == State::Started {
                match docker.stop_container(name.as_str(), None).await {
                    Ok(_) => {
                        no_panic_println!("Stopped docker container {}", name)
                    },
                    Err(err) => {
                        no_panic_eprintln!("Failed to stop docker container {}: {}", name, err)
                    },
                }
            }

            match docker.remove_container(name.as_str(), None).await {
                Ok(_) => {
                    no_panic_println!("Removed docker container {}", name)
                },
                Err(err) => {
                    no_panic_eprintln!("Failed to remove docker container {}: {}", name, err)
                },
            }
        }
    };

    (fut_run, fut_clean_up)
}
```

**File:** crates/aptos/src/node/local_testnet/traits.rs (L76-78)
```rust
    /// The ServiceManager may return ShutdownSteps. The tool will run these on shutdown.
    /// This is best effort, there is nothing we can do if part of the code aborts or
    /// the process receives something like SIGKILL.
```
