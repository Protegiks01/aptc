import json
import os

from decouple import config


def get_cyclic_index(run_number, max_index=100):
    """Convert run number to a cyclic index between 1 and max_index"""
    return (int(run_number) - 1) % max_index + 1


# Get the run number from environment
run_number = os.environ.get('GITHUB_RUN_NUMBER', '0')

if run_number == "0":
    BASE_URL = "https://deepwiki.com/aptos-labs/aptos-core"
else:
    # Convert to cyclic index (1-100)
    run_index = get_cyclic_index(run_number)
    # Format the URL with leading zeros
    repo_number = f"{run_index:03d}"
    BASE_URL = f"https://deepwiki.com/grass-dev-pa/aptos-core-{repo_number}"

SOURCE_REPO = "aptos-labs/aptos-core"

scope_files = [
    'aptos-core/api/openapi-spec-generator/src/fake_context.rs',
    'aptos-core/api/openapi-spec-generator/src/main.rs',
    'aptos-core/api/src/accept_type.rs',
    'aptos-core/api/src/accounts.rs',
    'aptos-core/api/src/basic.rs',
    'aptos-core/api/src/bcs_payload.rs',
    'aptos-core/api/src/blocks.rs',
    'aptos-core/api/src/check_size.rs',
    'aptos-core/api/src/context.rs',
    'aptos-core/api/src/error_converter.rs',
    'aptos-core/api/src/events.rs',
    'aptos-core/api/src/failpoint.rs',
    'aptos-core/api/src/index.rs',
    'aptos-core/api/src/lib.rs',
    'aptos-core/api/src/log.rs',
    'aptos-core/api/src/metrics.rs',
    'aptos-core/api/src/page.rs',
    'aptos-core/api/src/response.rs',
    'aptos-core/api/src/runtime.rs',
    'aptos-core/api/src/set_failpoints.rs',
    'aptos-core/api/src/spec.rs',
    'aptos-core/api/src/state.rs',
    'aptos-core/api/src/transactions.rs',
    'aptos-core/api/src/view_function.rs',
    'aptos-core/api/test-context/src/golden_output.rs',
    'aptos-core/api/test-context/src/lib.rs',
    'aptos-core/api/types/src/account.rs',
    'aptos-core/api/types/src/address.rs',
    'aptos-core/api/types/src/block.rs',
    'aptos-core/api/types/src/bytecode.rs',
    'aptos-core/api/types/src/convert.rs',
    'aptos-core/api/types/src/derives.rs',
    'aptos-core/api/types/src/error.rs',
    'aptos-core/api/types/src/hash.rs',
    'aptos-core/api/types/src/headers.rs',
    'aptos-core/api/types/src/index.rs',
    'aptos-core/api/types/src/ledger_info.rs',
    'aptos-core/api/types/src/lib.rs',
    'aptos-core/api/types/src/mime_types.rs',
    'aptos-core/api/types/src/move_types.rs',
    'aptos-core/api/types/src/state.rs',
    'aptos-core/api/types/src/table.rs',
    'aptos-core/api/types/src/transaction.rs',
    'aptos-core/api/types/src/view.rs',
    'aptos-core/api/types/src/wrappers.rs',
    'aptos-core/aptos-move/aptos-abstract-gas-usage/src/algebra.rs',
    'aptos-core/aptos-move/aptos-abstract-gas-usage/src/algebra_helpers.rs',
    'aptos-core/aptos-move/aptos-abstract-gas-usage/src/lib.rs',
    'aptos-core/aptos-move/aptos-aggregator/src/aggregator_v1_extension.rs',
    'aptos-core/aptos-move/aptos-aggregator/src/bounded_math.rs',
    'aptos-core/aptos-move/aptos-aggregator/src/delayed_change.rs',
    'aptos-core/aptos-move/aptos-aggregator/src/delayed_field_extension.rs',
    'aptos-core/aptos-move/aptos-aggregator/src/delta_change_set.rs',
    'aptos-core/aptos-move/aptos-aggregator/src/delta_math.rs',
    'aptos-core/aptos-move/aptos-aggregator/src/lib.rs',
    'aptos-core/aptos-move/aptos-aggregator/src/resolver.rs',
    'aptos-core/aptos-move/aptos-aggregator/src/types.rs',
    'aptos-core/aptos-move/aptos-debugger/src/aptos_debugger.rs',
    'aptos-core/aptos-move/aptos-debugger/src/bcs_txn_decoder.rs',
    'aptos-core/aptos-move/aptos-debugger/src/bin/remote-gas-profiler.rs',
    'aptos-core/aptos-move/aptos-debugger/src/common.rs',
    'aptos-core/aptos-move/aptos-debugger/src/execute_past_transactions.rs',
    'aptos-core/aptos-move/aptos-debugger/src/execute_pending_block.rs',
    'aptos-core/aptos-move/aptos-debugger/src/lib.rs',
    'aptos-core/aptos-move/aptos-gas-algebra/src/abstract_algebra.rs',
    'aptos-core/aptos-move/aptos-gas-algebra/src/algebra.rs',
    'aptos-core/aptos-move/aptos-gas-algebra/src/lib.rs',
    'aptos-core/aptos-move/aptos-gas-calibration/src/main.rs',
    'aptos-core/aptos-move/aptos-gas-calibration/src/math.rs',
    'aptos-core/aptos-move/aptos-gas-calibration/src/math_interface.rs',
    'aptos-core/aptos-move/aptos-gas-calibration/src/measurements.rs',
    'aptos-core/aptos-move/aptos-gas-calibration/src/measurements_helpers.rs',
    'aptos-core/aptos-move/aptos-gas-calibration/src/solve.rs',
    'aptos-core/aptos-move/aptos-gas-meter/src/algebra.rs',
    'aptos-core/aptos-move/aptos-gas-meter/src/lib.rs',
    'aptos-core/aptos-move/aptos-gas-meter/src/meter.rs',
    'aptos-core/aptos-move/aptos-gas-meter/src/traits.rs',
    'aptos-core/aptos-move/aptos-gas-profiling/src/aggregate.rs',
    'aptos-core/aptos-move/aptos-gas-profiling/src/erased.rs',
    'aptos-core/aptos-move/aptos-gas-profiling/src/flamegraph.rs',
    'aptos-core/aptos-move/aptos-gas-profiling/src/lib.rs',
    'aptos-core/aptos-move/aptos-gas-profiling/src/log.rs',
    'aptos-core/aptos-move/aptos-gas-profiling/src/misc.rs',
    'aptos-core/aptos-move/aptos-gas-profiling/src/profiler.rs',
    'aptos-core/aptos-move/aptos-gas-profiling/src/render.rs',
    'aptos-core/aptos-move/aptos-gas-profiling/src/report.rs',
    'aptos-core/aptos-move/aptos-gas-profiling/src/unique_stack.rs',
    'aptos-core/aptos-move/aptos-gas-schedule-updator/src/lib.rs',
    'aptos-core/aptos-move/aptos-gas-schedule-updator/src/main.rs',
    'aptos-core/aptos-move/aptos-gas-schedule/src/gas_schedule/aptos_framework.rs',
    'aptos-core/aptos-move/aptos-gas-schedule/src/gas_schedule/instr.rs',
    'aptos-core/aptos-move/aptos-gas-schedule/src/gas_schedule/macros.rs',
    'aptos-core/aptos-move/aptos-gas-schedule/src/gas_schedule/misc.rs',
    'aptos-core/aptos-move/aptos-gas-schedule/src/gas_schedule/mod.rs',
    'aptos-core/aptos-move/aptos-gas-schedule/src/gas_schedule/move_stdlib.rs',
    'aptos-core/aptos-move/aptos-gas-schedule/src/gas_schedule/table.rs',
    'aptos-core/aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs',
    'aptos-core/aptos-move/aptos-gas-schedule/src/lib.rs',
    'aptos-core/aptos-move/aptos-gas-schedule/src/traits.rs',
    'aptos-core/aptos-move/aptos-gas-schedule/src/ver.rs',
    'aptos-core/aptos-move/aptos-memory-usage-tracker/src/lib.rs',
    'aptos-core/aptos-move/aptos-native-interface/src/builder.rs',
    'aptos-core/aptos-move/aptos-native-interface/src/context.rs',
    'aptos-core/aptos-move/aptos-native-interface/src/errors.rs',
    'aptos-core/aptos-move/aptos-native-interface/src/helpers.rs',
    'aptos-core/aptos-move/aptos-native-interface/src/lib.rs',
    'aptos-core/aptos-move/aptos-native-interface/src/native.rs',
    'aptos-core/aptos-move/aptos-native-interface/src/reexports.rs',
    'aptos-core/aptos-move/aptos-release-builder/src/components/consensus_config.rs',
    'aptos-core/aptos-move/aptos-release-builder/src/components/execution_config.rs',
    'aptos-core/aptos-move/aptos-release-builder/src/components/feature_flags.rs',
    'aptos-core/aptos-move/aptos-release-builder/src/components/framework.rs',
    'aptos-core/aptos-move/aptos-release-builder/src/components/gas.rs',
    'aptos-core/aptos-move/aptos-release-builder/src/components/jwk_consensus_config.rs',
    'aptos-core/aptos-move/aptos-release-builder/src/components/mod.rs',
    'aptos-core/aptos-move/aptos-release-builder/src/components/oidc_providers.rs',
    'aptos-core/aptos-move/aptos-release-builder/src/components/randomness_config.rs',
    'aptos-core/aptos-move/aptos-release-builder/src/components/transaction_fee.rs',
    'aptos-core/aptos-move/aptos-release-builder/src/components/version.rs',
    'aptos-core/aptos-move/aptos-release-builder/src/lib.rs',
    'aptos-core/aptos-move/aptos-release-builder/src/main.rs',
    'aptos-core/aptos-move/aptos-release-builder/src/simulate.rs',
    'aptos-core/aptos-move/aptos-release-builder/src/utils.rs',
    'aptos-core/aptos-move/aptos-release-builder/src/validate.rs',
    'aptos-core/aptos-move/aptos-resource-viewer/src/lib.rs',
    'aptos-core/aptos-move/aptos-resource-viewer/src/module_view.rs',
    'aptos-core/aptos-move/aptos-sdk-builder/examples/rust/script_fun_demo.rs',
    'aptos-core/aptos-move/aptos-sdk-builder/src/common.rs',
    'aptos-core/aptos-move/aptos-sdk-builder/src/golang.rs',
    'aptos-core/aptos-move/aptos-sdk-builder/src/lib.rs',
    'aptos-core/aptos-move/aptos-sdk-builder/src/main.rs',
    'aptos-core/aptos-move/aptos-sdk-builder/src/rust.rs',
    'aptos-core/aptos-move/aptos-transaction-benchmarks/benches/transaction_benches.rs',
    'aptos-core/aptos-move/aptos-transaction-benchmarks/src/benchmark_runner.rs',
    'aptos-core/aptos-move/aptos-transaction-benchmarks/src/lib.rs',
    'aptos-core/aptos-move/aptos-transaction-benchmarks/src/main.rs',
    'aptos-core/aptos-move/aptos-transaction-benchmarks/src/measurement.rs',
    'aptos-core/aptos-move/aptos-transaction-benchmarks/src/transaction_bench_state.rs',
    'aptos-core/aptos-move/aptos-transaction-benchmarks/src/transactions.rs',
    'aptos-core/aptos-move/aptos-transaction-simulation-session/src/config.rs',
    'aptos-core/aptos-move/aptos-transaction-simulation-session/src/delta.rs',
    'aptos-core/aptos-move/aptos-transaction-simulation-session/src/lib.rs',
    'aptos-core/aptos-move/aptos-transaction-simulation-session/src/session.rs',
    'aptos-core/aptos-move/aptos-transaction-simulation-session/src/state_store.rs',
    'aptos-core/aptos-move/aptos-transaction-simulation-session/src/txn_output.rs',
    'aptos-core/aptos-move/aptos-transaction-simulation/src/account.rs',
    'aptos-core/aptos-move/aptos-transaction-simulation/src/genesis.rs',
    'aptos-core/aptos-move/aptos-transaction-simulation/src/lib.rs',
    'aptos-core/aptos-move/aptos-transaction-simulation/src/state_store.rs',
    'aptos-core/aptos-move/aptos-transactional-test-harness/src/aptos_test_harness.rs',
    'aptos-core/aptos-move/aptos-transactional-test-harness/src/lib.rs',
    'aptos-core/aptos-move/aptos-validator-interface/src/lib.rs',
    'aptos-core/aptos-move/aptos-validator-interface/src/rest_interface.rs',
    'aptos-core/aptos-move/aptos-validator-interface/src/storage_interface.rs',
    'aptos-core/aptos-move/aptos-vm-benchmarks/src/helper.rs',
    'aptos-core/aptos-move/aptos-vm-benchmarks/src/main.rs',
    'aptos-core/aptos-move/aptos-vm-environment/src/environment.rs',
    'aptos-core/aptos-move/aptos-vm-environment/src/gas.rs',
    'aptos-core/aptos-move/aptos-vm-environment/src/lib.rs',
    'aptos-core/aptos-move/aptos-vm-environment/src/natives.rs',
    'aptos-core/aptos-move/aptos-vm-environment/src/prod_configs.rs',
    'aptos-core/aptos-move/aptos-vm-logging/src/counters.rs',
    'aptos-core/aptos-move/aptos-vm-logging/src/lib.rs',
    'aptos-core/aptos-move/aptos-vm-logging/src/log_schema.rs',
    'aptos-core/aptos-move/aptos-vm-profiling/src/bins/run_aptos_p2p.rs',
    'aptos-core/aptos-move/aptos-vm-profiling/src/bins/run_move.rs',
    'aptos-core/aptos-move/aptos-vm-profiling/src/main.rs',
    'aptos-core/aptos-move/aptos-vm-profiling/src/profile_aptos_vm.rs',
    'aptos-core/aptos-move/aptos-vm-profiling/src/profile_move_vm.rs',
    'aptos-core/aptos-move/aptos-vm-profiling/src/valgrind.rs',
    'aptos-core/aptos-move/aptos-vm-types/src/abstract_write_op.rs',
    'aptos-core/aptos-move/aptos-vm-types/src/change_set.rs',
    'aptos-core/aptos-move/aptos-vm-types/src/lib.rs',
    'aptos-core/aptos-move/aptos-vm-types/src/module_and_script_storage/code_storage.rs',
    'aptos-core/aptos-move/aptos-vm-types/src/module_and_script_storage/mod.rs',
    'aptos-core/aptos-move/aptos-vm-types/src/module_and_script_storage/module_storage.rs',
    'aptos-core/aptos-move/aptos-vm-types/src/module_and_script_storage/state_view_adapter.rs',
    'aptos-core/aptos-move/aptos-vm-types/src/module_write_set.rs',
    'aptos-core/aptos-move/aptos-vm-types/src/output.rs',
    'aptos-core/aptos-move/aptos-vm-types/src/resolver.rs',
    'aptos-core/aptos-move/aptos-vm-types/src/resource_group_adapter.rs',
    'aptos-core/aptos-move/aptos-vm-types/src/storage/change_set_configs.rs',
    'aptos-core/aptos-move/aptos-vm-types/src/storage/io_pricing.rs',
    'aptos-core/aptos-move/aptos-vm-types/src/storage/mod.rs',
    'aptos-core/aptos-move/aptos-vm-types/src/storage/space_pricing.rs',
    'aptos-core/aptos-move/aptos-vm/src/aptos_vm.rs',
    'aptos-core/aptos-move/aptos-vm/src/block_executor/mod.rs',
    'aptos-core/aptos-move/aptos-vm/src/block_executor/vm_wrapper.rs',
    'aptos-core/aptos-move/aptos-vm/src/counters.rs',
    'aptos-core/aptos-move/aptos-vm/src/data_cache.rs',
    'aptos-core/aptos-move/aptos-vm/src/errors.rs',
    'aptos-core/aptos-move/aptos-vm/src/gas.rs',
    'aptos-core/aptos-move/aptos-vm/src/keyless_validation.rs',
    'aptos-core/aptos-move/aptos-vm/src/lib.rs',
    'aptos-core/aptos-move/aptos-vm/src/move_vm_ext/mod.rs',
    'aptos-core/aptos-move/aptos-vm/src/move_vm_ext/resolver.rs',
    'aptos-core/aptos-move/aptos-vm/src/move_vm_ext/session/mod.rs',
    'aptos-core/aptos-move/aptos-vm/src/move_vm_ext/session/respawned_session.rs',
    'aptos-core/aptos-move/aptos-vm/src/move_vm_ext/session/session_id.rs',
    'aptos-core/aptos-move/aptos-vm/src/move_vm_ext/session/user_transaction_sessions/abort_hook.rs',
    'aptos-core/aptos-move/aptos-vm/src/move_vm_ext/session/user_transaction_sessions/epilogue.rs',
    'aptos-core/aptos-move/aptos-vm/src/move_vm_ext/session/user_transaction_sessions/mod.rs',
    'aptos-core/aptos-move/aptos-vm/src/move_vm_ext/session/user_transaction_sessions/prologue.rs',
    'aptos-core/aptos-move/aptos-vm/src/move_vm_ext/session/user_transaction_sessions/session_change_sets.rs',
    'aptos-core/aptos-move/aptos-vm/src/move_vm_ext/session/user_transaction_sessions/user.rs',
    'aptos-core/aptos-move/aptos-vm/src/move_vm_ext/session/view_with_change_set.rs',
    'aptos-core/aptos-move/aptos-vm/src/move_vm_ext/vm.rs',
    'aptos-core/aptos-move/aptos-vm/src/move_vm_ext/write_op_converter.rs',
    'aptos-core/aptos-move/aptos-vm/src/natives.rs',
    'aptos-core/aptos-move/aptos-vm/src/sharded_block_executor/aggr_overridden_state_view.rs',
    'aptos-core/aptos-move/aptos-vm/src/sharded_block_executor/coordinator_client.rs',
    'aptos-core/aptos-move/aptos-vm/src/sharded_block_executor/counters.rs',
    'aptos-core/aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_client.rs',
    'aptos-core/aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_state_view.rs',
    'aptos-core/aptos-move/aptos-vm/src/sharded_block_executor/executor_client.rs',
    'aptos-core/aptos-move/aptos-vm/src/sharded_block_executor/global_executor.rs',
    'aptos-core/aptos-move/aptos-vm/src/sharded_block_executor/local_executor_shard.rs',
    'aptos-core/aptos-move/aptos-vm/src/sharded_block_executor/messages.rs',
    'aptos-core/aptos-move/aptos-vm/src/sharded_block_executor/mod.rs',
    'aptos-core/aptos-move/aptos-vm/src/sharded_block_executor/remote_state_value.rs',
    'aptos-core/aptos-move/aptos-vm/src/sharded_block_executor/sharded_aggregator_service.rs',
    'aptos-core/aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs',
    'aptos-core/aptos-move/aptos-vm/src/system_module_names.rs',
    'aptos-core/aptos-move/aptos-vm/src/testing.rs',
    'aptos-core/aptos-move/aptos-vm/src/transaction_metadata.rs',
    'aptos-core/aptos-move/aptos-vm/src/transaction_validation.rs',
    'aptos-core/aptos-move/aptos-vm/src/validator_txns/dkg.rs',
    'aptos-core/aptos-move/aptos-vm/src/validator_txns/jwk.rs',
    'aptos-core/aptos-move/aptos-vm/src/validator_txns/mod.rs',
    'aptos-core/aptos-move/aptos-vm/src/verifier/event_validation.rs',
    'aptos-core/aptos-move/aptos-vm/src/verifier/mod.rs',
    'aptos-core/aptos-move/aptos-vm/src/verifier/module_init.rs',
    'aptos-core/aptos-move/aptos-vm/src/verifier/native_validation.rs',
    'aptos-core/aptos-move/aptos-vm/src/verifier/resource_groups.rs',
    'aptos-core/aptos-move/aptos-vm/src/verifier/transaction_arg_validation.rs',
    'aptos-core/aptos-move/aptos-vm/src/verifier/view_function.rs',
    'aptos-core/aptos-move/aptos-workspace-server/src/common.rs',
    'aptos-core/aptos-move/aptos-workspace-server/src/lib.rs',
    'aptos-core/aptos-move/aptos-workspace-server/src/main.rs',
    'aptos-core/aptos-move/aptos-workspace-server/src/services/docker_common.rs',
    'aptos-core/aptos-move/aptos-workspace-server/src/services/faucet.rs',
    'aptos-core/aptos-move/aptos-workspace-server/src/services/indexer_api.rs',
    'aptos-core/aptos-move/aptos-workspace-server/src/services/mod.rs',
    'aptos-core/aptos-move/aptos-workspace-server/src/services/node.rs',
    'aptos-core/aptos-move/aptos-workspace-server/src/services/postgres.rs',
    'aptos-core/aptos-move/aptos-workspace-server/src/services/processors.rs',
    'aptos-core/aptos-move/block-executor/benches/scheduler_benches.rs',
    'aptos-core/aptos-move/block-executor/src/captured_reads.rs',
    'aptos-core/aptos-move/block-executor/src/code_cache.rs',
    'aptos-core/aptos-move/block-executor/src/code_cache_global.rs',
    'aptos-core/aptos-move/block-executor/src/code_cache_global_manager.rs',
    'aptos-core/aptos-move/block-executor/src/cold_validation.rs',
    'aptos-core/aptos-move/block-executor/src/combinatorial_tests/baseline.rs',
    'aptos-core/aptos-move/block-executor/src/combinatorial_tests/bencher.rs',
    'aptos-core/aptos-move/block-executor/src/combinatorial_tests/delayed_field_tests.rs',
    'aptos-core/aptos-move/block-executor/src/combinatorial_tests/delta_tests.rs',
    'aptos-core/aptos-move/block-executor/src/combinatorial_tests/group_tests.rs',
    'aptos-core/aptos-move/block-executor/src/combinatorial_tests/mock_executor.rs',
    'aptos-core/aptos-move/block-executor/src/combinatorial_tests/mod.rs',
    'aptos-core/aptos-move/block-executor/src/combinatorial_tests/module_tests.rs',
    'aptos-core/aptos-move/block-executor/src/combinatorial_tests/resource_tests.rs',
    'aptos-core/aptos-move/block-executor/src/combinatorial_tests/types.rs',
    'aptos-core/aptos-move/block-executor/src/counters.rs',
    'aptos-core/aptos-move/block-executor/src/errors.rs',
    'aptos-core/aptos-move/block-executor/src/executor.rs',
    'aptos-core/aptos-move/block-executor/src/executor_utilities.rs',
    'aptos-core/aptos-move/block-executor/src/explicit_sync_wrapper.rs',
    'aptos-core/aptos-move/block-executor/src/hot_state_op_accumulator.rs',
    'aptos-core/aptos-move/block-executor/src/lib.rs',
    'aptos-core/aptos-move/block-executor/src/limit_processor.rs',
    'aptos-core/aptos-move/block-executor/src/scheduler.rs',
    'aptos-core/aptos-move/block-executor/src/scheduler_status.rs',
    'aptos-core/aptos-move/block-executor/src/scheduler_v2.rs',
    'aptos-core/aptos-move/block-executor/src/scheduler_wrapper.rs',
    'aptos-core/aptos-move/block-executor/src/task.rs',
    'aptos-core/aptos-move/block-executor/src/txn_commit_hook.rs',
    'aptos-core/aptos-move/block-executor/src/txn_last_input_output.rs',
    'aptos-core/aptos-move/block-executor/src/txn_provider/blocking_txns_provider.rs',
    'aptos-core/aptos-move/block-executor/src/txn_provider/default.rs',
    'aptos-core/aptos-move/block-executor/src/txn_provider/mod.rs',
    'aptos-core/aptos-move/block-executor/src/types.rs',
    'aptos-core/aptos-move/block-executor/src/unit_tests/code_cache_tests.rs',
    'aptos-core/aptos-move/block-executor/src/unit_tests/mod.rs',
    'aptos-core/aptos-move/block-executor/src/value_exchange.rs',
    'aptos-core/aptos-move/block-executor/src/view.rs',
    'aptos-core/aptos-move/e2e-benchmark/src/bin/locals_bench.rs',
    'aptos-core/aptos-move/e2e-benchmark/src/gas_profiling.rs',
    'aptos-core/aptos-move/e2e-benchmark/src/lib.rs',
    'aptos-core/aptos-move/e2e-benchmark/src/main.rs',
    'aptos-core/aptos-move/e2e-move-tests/src/aggregator.rs',
    'aptos-core/aptos-move/e2e-move-tests/src/aggregator_v2.rs',
    'aptos-core/aptos-move/e2e-move-tests/src/aptos_governance.rs',
    'aptos-core/aptos-move/e2e-move-tests/src/harness.rs',
    'aptos-core/aptos-move/e2e-move-tests/src/lib.rs',
    'aptos-core/aptos-move/e2e-move-tests/src/resource_groups.rs',
    'aptos-core/aptos-move/e2e-move-tests/src/stake.rs',
    'aptos-core/aptos-move/framework/cached-packages/build.rs',
    'aptos-core/aptos-move/framework/cached-packages/src/aptos_framework_sdk_builder.rs',
    'aptos-core/aptos-move/framework/cached-packages/src/aptos_stdlib.rs',
    'aptos-core/aptos-move/framework/cached-packages/src/aptos_token_objects_sdk_builder.rs',
    'aptos-core/aptos-move/framework/cached-packages/src/aptos_token_sdk_builder.rs',
    'aptos-core/aptos-move/framework/cached-packages/src/lib.rs',
    'aptos-core/aptos-move/framework/move-stdlib/src/lib.rs',
    'aptos-core/aptos-move/framework/move-stdlib/src/natives/bcs.rs',
    'aptos-core/aptos-move/framework/move-stdlib/src/natives/cmp.rs',
    'aptos-core/aptos-move/framework/move-stdlib/src/natives/hash.rs',
    'aptos-core/aptos-move/framework/move-stdlib/src/natives/mem.rs',
    'aptos-core/aptos-move/framework/move-stdlib/src/natives/mod.rs',
    'aptos-core/aptos-move/framework/move-stdlib/src/natives/reflect.rs',
    'aptos-core/aptos-move/framework/move-stdlib/src/natives/result.rs',
    'aptos-core/aptos-move/framework/move-stdlib/src/natives/signer.rs',
    'aptos-core/aptos-move/framework/move-stdlib/src/natives/string.rs',
    'aptos-core/aptos-move/framework/move-stdlib/src/natives/vector.rs',
    'aptos-core/aptos-move/framework/src/aptos.rs',
    'aptos-core/aptos-move/framework/src/built_package.rs',
    'aptos-core/aptos-move/framework/src/chunked_publish.rs',
    'aptos-core/aptos-move/framework/src/docgen.rs',
    'aptos-core/aptos-move/framework/src/extended_checks.rs',
    'aptos-core/aptos-move/framework/src/lib.rs',
    'aptos-core/aptos-move/framework/src/main.rs',
    'aptos-core/aptos-move/framework/src/natives/account.rs',
    'aptos-core/aptos-move/framework/src/natives/account_abstraction.rs',
    'aptos-core/aptos-move/framework/src/natives/aggregator_natives/aggregator.rs',
    'aptos-core/aptos-move/framework/src/natives/aggregator_natives/aggregator_factory.rs',
    'aptos-core/aptos-move/framework/src/natives/aggregator_natives/aggregator_v2.rs',
    'aptos-core/aptos-move/framework/src/natives/aggregator_natives/context.rs',
    'aptos-core/aptos-move/framework/src/natives/aggregator_natives/helpers_v1.rs',
    'aptos-core/aptos-move/framework/src/natives/aggregator_natives/helpers_v2.rs',
    'aptos-core/aptos-move/framework/src/natives/aggregator_natives/mod.rs',
    'aptos-core/aptos-move/framework/src/natives/code.rs',
    'aptos-core/aptos-move/framework/src/natives/consensus_config.rs',
    'aptos-core/aptos-move/framework/src/natives/create_signer.rs',
    'aptos-core/aptos-move/framework/src/natives/cryptography/algebra/arithmetics/add.rs',
    'aptos-core/aptos-move/framework/src/natives/cryptography/algebra/arithmetics/div.rs',
    'aptos-core/aptos-move/framework/src/natives/cryptography/algebra/arithmetics/double.rs',
    'aptos-core/aptos-move/framework/src/natives/cryptography/algebra/arithmetics/inv.rs',
    'aptos-core/aptos-move/framework/src/natives/cryptography/algebra/arithmetics/mod.rs',
    'aptos-core/aptos-move/framework/src/natives/cryptography/algebra/arithmetics/mul.rs',
    'aptos-core/aptos-move/framework/src/natives/cryptography/algebra/arithmetics/neg.rs',
    'aptos-core/aptos-move/framework/src/natives/cryptography/algebra/arithmetics/scalar_mul.rs',
    'aptos-core/aptos-move/framework/src/natives/cryptography/algebra/arithmetics/sqr.rs',
    'aptos-core/aptos-move/framework/src/natives/cryptography/algebra/arithmetics/sub.rs',
    'aptos-core/aptos-move/framework/src/natives/cryptography/algebra/casting.rs',
    'aptos-core/aptos-move/framework/src/natives/cryptography/algebra/constants.rs',
    'aptos-core/aptos-move/framework/src/natives/cryptography/algebra/eq.rs',
    'aptos-core/aptos-move/framework/src/natives/cryptography/algebra/hash_to_structure.rs',
    'aptos-core/aptos-move/framework/src/natives/cryptography/algebra/mod.rs',
    'aptos-core/aptos-move/framework/src/natives/cryptography/algebra/new.rs',
    'aptos-core/aptos-move/framework/src/natives/cryptography/algebra/pairing.rs',
    'aptos-core/aptos-move/framework/src/natives/cryptography/algebra/rand.rs',
    'aptos-core/aptos-move/framework/src/natives/cryptography/algebra/serialization.rs',
    'aptos-core/aptos-move/framework/src/natives/cryptography/bls12381.rs',
    'aptos-core/aptos-move/framework/src/natives/cryptography/bulletproofs.rs',
    'aptos-core/aptos-move/framework/src/natives/cryptography/ed25519.rs',
    'aptos-core/aptos-move/framework/src/natives/cryptography/helpers.rs',
    'aptos-core/aptos-move/framework/src/natives/cryptography/mod.rs',
    'aptos-core/aptos-move/framework/src/natives/cryptography/multi_ed25519.rs',
    'aptos-core/aptos-move/framework/src/natives/cryptography/ristretto255.rs',
    'aptos-core/aptos-move/framework/src/natives/cryptography/ristretto255_point.rs',
    'aptos-core/aptos-move/framework/src/natives/cryptography/ristretto255_scalar.rs',
    'aptos-core/aptos-move/framework/src/natives/cryptography/secp256k1.rs',
    'aptos-core/aptos-move/framework/src/natives/debug.rs',
    'aptos-core/aptos-move/framework/src/natives/dispatchable_fungible_asset.rs',
    'aptos-core/aptos-move/framework/src/natives/event.rs',
    'aptos-core/aptos-move/framework/src/natives/function_info.rs',
    'aptos-core/aptos-move/framework/src/natives/hash.rs',
    'aptos-core/aptos-move/framework/src/natives/mod.rs',
    'aptos-core/aptos-move/framework/src/natives/object.rs',
    'aptos-core/aptos-move/framework/src/natives/object_code_deployment.rs',
    'aptos-core/aptos-move/framework/src/natives/permissioned_signer.rs',
    'aptos-core/aptos-move/framework/src/natives/randomness.rs',
    'aptos-core/aptos-move/framework/src/natives/state_storage.rs',
    'aptos-core/aptos-move/framework/src/natives/string_utils.rs',
    'aptos-core/aptos-move/framework/src/natives/transaction_context.rs',
    'aptos-core/aptos-move/framework/src/natives/type_info.rs',
    'aptos-core/aptos-move/framework/src/natives/util.rs',
    'aptos-core/aptos-move/framework/src/prover.rs',
    'aptos-core/aptos-move/framework/src/release_builder.rs',
    'aptos-core/aptos-move/framework/src/release_bundle.rs',
    'aptos-core/aptos-move/framework/src/released_framework.rs',
    'aptos-core/aptos-move/framework/table-natives/src/lib.rs',
    'aptos-core/aptos-move/mvhashmap/src/lib.rs',
    'aptos-core/aptos-move/mvhashmap/src/registered_dependencies.rs',
    'aptos-core/aptos-move/mvhashmap/src/types.rs',
    'aptos-core/aptos-move/mvhashmap/src/unit_tests/dependencies.rs',
    'aptos-core/aptos-move/mvhashmap/src/unit_tests/mod.rs',
    'aptos-core/aptos-move/mvhashmap/src/unit_tests/proptest_types.rs',
    'aptos-core/aptos-move/mvhashmap/src/unsync_map.rs',
    'aptos-core/aptos-move/mvhashmap/src/versioned_data.rs',
    'aptos-core/aptos-move/mvhashmap/src/versioned_delayed_fields.rs',
    'aptos-core/aptos-move/mvhashmap/src/versioned_group_data.rs',
    'aptos-core/aptos-move/package-builder/src/lib.rs',
    'aptos-core/aptos-move/script-composer/src/builder.rs',
    'aptos-core/aptos-move/script-composer/src/decompiler.rs',
    'aptos-core/aptos-move/script-composer/src/helpers.rs',
    'aptos-core/aptos-move/script-composer/src/lib.rs',
    'aptos-core/aptos-move/vm-genesis/src/genesis_context.rs',
    'aptos-core/aptos-move/vm-genesis/src/lib.rs',
    'aptos-core/aptos-node/src/consensus.rs',
    'aptos-core/aptos-node/src/indexer.rs',
    'aptos-core/aptos-node/src/lib.rs',
    'aptos-core/aptos-node/src/logger.rs',
    'aptos-core/aptos-node/src/main.rs',
    'aptos-core/aptos-node/src/network.rs',
    'aptos-core/aptos-node/src/services.rs',
    'aptos-core/aptos-node/src/state_sync.rs',
    'aptos-core/aptos-node/src/storage.rs',
    'aptos-core/aptos-node/src/utils.rs',
    'aptos-core/config/global-constants/src/lib.rs',
    'aptos-core/config/src/config/admin_service_config.rs',
    'aptos-core/config/src/config/api_config.rs',
    'aptos-core/config/src/config/base_config.rs',
    'aptos-core/config/src/config/config_optimizer.rs',
    'aptos-core/config/src/config/config_sanitizer.rs',
    'aptos-core/config/src/config/consensus_config.rs',
    'aptos-core/config/src/config/consensus_observer_config.rs',
    'aptos-core/config/src/config/dag_consensus_config.rs',
    'aptos-core/config/src/config/dkg_config.rs',
    'aptos-core/config/src/config/error.rs',
    'aptos-core/config/src/config/execution_config.rs',
    'aptos-core/config/src/config/gas_estimation_config.rs',
    'aptos-core/config/src/config/identity_config.rs',
    'aptos-core/config/src/config/indexer_config.rs',
    'aptos-core/config/src/config/indexer_grpc_config.rs',
    'aptos-core/config/src/config/indexer_table_info_config.rs',
    'aptos-core/config/src/config/inspection_service_config.rs',
    'aptos-core/config/src/config/internal_indexer_db_config.rs',
    'aptos-core/config/src/config/jwk_consensus_config.rs',
    'aptos-core/config/src/config/logger_config.rs',
    'aptos-core/config/src/config/mempool_config.rs',
    'aptos-core/config/src/config/mod.rs',
    'aptos-core/config/src/config/netbench_config.rs',
    'aptos-core/config/src/config/network_config.rs',
    'aptos-core/config/src/config/node_config.rs',
    'aptos-core/config/src/config/node_config_loader.rs',
    'aptos-core/config/src/config/node_startup_config.rs',
    'aptos-core/config/src/config/override_node_config.rs',
    'aptos-core/config/src/config/peer_monitoring_config.rs',
    'aptos-core/config/src/config/persistable_config.rs',
    'aptos-core/config/src/config/quorum_store_config.rs',
    'aptos-core/config/src/config/safety_rules_config.rs',
    'aptos-core/config/src/config/secure_backend_config.rs',
    'aptos-core/config/src/config/state_sync_config.rs',
    'aptos-core/config/src/config/storage_config.rs',
    'aptos-core/config/src/config/transaction_filters_config.rs',
    'aptos-core/config/src/config/utils.rs',
    'aptos-core/config/src/generator.rs',
    'aptos-core/config/src/keys.rs',
    'aptos-core/config/src/lib.rs',
    'aptos-core/config/src/network_id.rs',
    'aptos-core/config/src/utils.rs',
    'aptos-core/consensus/consensus-types/src/block.rs',
    'aptos-core/consensus/consensus-types/src/block_data.rs',
    'aptos-core/consensus/consensus-types/src/block_retrieval.rs',
    'aptos-core/consensus/consensus-types/src/block_test_utils.rs',
    'aptos-core/consensus/consensus-types/src/common.rs',
    'aptos-core/consensus/consensus-types/src/epoch_retrieval.rs',
    'aptos-core/consensus/consensus-types/src/lib.rs',
    'aptos-core/consensus/consensus-types/src/opt_block_data.rs',
    'aptos-core/consensus/consensus-types/src/opt_proposal_msg.rs',
    'aptos-core/consensus/consensus-types/src/order_vote.rs',
    'aptos-core/consensus/consensus-types/src/order_vote_msg.rs',
    'aptos-core/consensus/consensus-types/src/order_vote_proposal.rs',
    'aptos-core/consensus/consensus-types/src/payload.rs',
    'aptos-core/consensus/consensus-types/src/payload_pull_params.rs',
    'aptos-core/consensus/consensus-types/src/pipeline/commit_decision.rs',
    'aptos-core/consensus/consensus-types/src/pipeline/commit_vote.rs',
    'aptos-core/consensus/consensus-types/src/pipeline/mod.rs',
    'aptos-core/consensus/consensus-types/src/pipelined_block.rs',
    'aptos-core/consensus/consensus-types/src/proof_of_store.rs',
    'aptos-core/consensus/consensus-types/src/proposal_ext.rs',
    'aptos-core/consensus/consensus-types/src/proposal_msg.rs',
    'aptos-core/consensus/consensus-types/src/quorum_cert.rs',
    'aptos-core/consensus/consensus-types/src/randomness.rs',
    'aptos-core/consensus/consensus-types/src/request_response.rs',
    'aptos-core/consensus/consensus-types/src/round_timeout.rs',
    'aptos-core/consensus/consensus-types/src/safety_data.rs',
    'aptos-core/consensus/consensus-types/src/sync_info.rs',
    'aptos-core/consensus/consensus-types/src/timeout_2chain.rs',
    'aptos-core/consensus/consensus-types/src/utils.rs',
    'aptos-core/consensus/consensus-types/src/vote.rs',
    'aptos-core/consensus/consensus-types/src/vote_data.rs',
    'aptos-core/consensus/consensus-types/src/vote_msg.rs',
    'aptos-core/consensus/consensus-types/src/vote_proposal.rs',
    'aptos-core/consensus/consensus-types/src/wrapped_ledger_info.rs',
    'aptos-core/consensus/safety-rules/benches/safety_rules.rs',
    'aptos-core/consensus/safety-rules/src/consensus_state.rs',
    'aptos-core/consensus/safety-rules/src/counters.rs',
    'aptos-core/consensus/safety-rules/src/error.rs',
    'aptos-core/consensus/safety-rules/src/fuzzing_utils.rs',
    'aptos-core/consensus/safety-rules/src/lib.rs',
    'aptos-core/consensus/safety-rules/src/local_client.rs',
    'aptos-core/consensus/safety-rules/src/logging.rs',
    'aptos-core/consensus/safety-rules/src/persistent_safety_storage.rs',
    'aptos-core/consensus/safety-rules/src/process.rs',
    'aptos-core/consensus/safety-rules/src/remote_service.rs',
    'aptos-core/consensus/safety-rules/src/safety_rules.rs',
    'aptos-core/consensus/safety-rules/src/safety_rules_2chain.rs',
    'aptos-core/consensus/safety-rules/src/safety_rules_manager.rs',
    'aptos-core/consensus/safety-rules/src/serializer.rs',
    'aptos-core/consensus/safety-rules/src/t_safety_rules.rs',
    'aptos-core/consensus/safety-rules/src/thread.rs',
    'aptos-core/consensus/src/block_preparer.rs',
    'aptos-core/consensus/src/block_storage/block_store.rs',
    'aptos-core/consensus/src/block_storage/block_tree.rs',
    'aptos-core/consensus/src/block_storage/execution_pool/mod.rs',
    'aptos-core/consensus/src/block_storage/mod.rs',
    'aptos-core/consensus/src/block_storage/pending_blocks.rs',
    'aptos-core/consensus/src/block_storage/sync_manager.rs',
    'aptos-core/consensus/src/block_storage/tracing.rs',
    'aptos-core/consensus/src/consensus_observer/common/error.rs',
    'aptos-core/consensus/src/consensus_observer/common/logging.rs',
    'aptos-core/consensus/src/consensus_observer/common/metrics.rs',
    'aptos-core/consensus/src/consensus_observer/common/mod.rs',
    'aptos-core/consensus/src/consensus_observer/mod.rs',
    'aptos-core/consensus/src/consensus_observer/network/mod.rs',
    'aptos-core/consensus/src/consensus_observer/network/network_events.rs',
    'aptos-core/consensus/src/consensus_observer/network/network_handler.rs',
    'aptos-core/consensus/src/consensus_observer/network/observer_client.rs',
    'aptos-core/consensus/src/consensus_observer/network/observer_message.rs',
    'aptos-core/consensus/src/consensus_observer/observer/block_data.rs',
    'aptos-core/consensus/src/consensus_observer/observer/consensus_observer.rs',
    'aptos-core/consensus/src/consensus_observer/observer/epoch_state.rs',
    'aptos-core/consensus/src/consensus_observer/observer/execution_pool.rs',
    'aptos-core/consensus/src/consensus_observer/observer/fallback_manager.rs',
    'aptos-core/consensus/src/consensus_observer/observer/mod.rs',
    'aptos-core/consensus/src/consensus_observer/observer/ordered_blocks.rs',
    'aptos-core/consensus/src/consensus_observer/observer/payload_store.rs',
    'aptos-core/consensus/src/consensus_observer/observer/pending_blocks.rs',
    'aptos-core/consensus/src/consensus_observer/observer/state_sync_manager.rs',
    'aptos-core/consensus/src/consensus_observer/observer/subscription.rs',
    'aptos-core/consensus/src/consensus_observer/observer/subscription_manager.rs',
    'aptos-core/consensus/src/consensus_observer/observer/subscription_utils.rs',
    'aptos-core/consensus/src/consensus_observer/publisher/consensus_publisher.rs',
    'aptos-core/consensus/src/consensus_observer/publisher/mod.rs',
    'aptos-core/consensus/src/consensus_provider.rs',
    'aptos-core/consensus/src/consensusdb/mod.rs',
    'aptos-core/consensus/src/consensusdb/schema/block/mod.rs',
    'aptos-core/consensus/src/consensusdb/schema/dag/mod.rs',
    'aptos-core/consensus/src/consensusdb/schema/mod.rs',
    'aptos-core/consensus/src/consensusdb/schema/quorum_certificate/mod.rs',
    'aptos-core/consensus/src/consensusdb/schema/single_entry/mod.rs',
    'aptos-core/consensus/src/counters.rs',
    'aptos-core/consensus/src/epoch_manager.rs',
    'aptos-core/consensus/src/error.rs',
    'aptos-core/consensus/src/lib.rs',
    'aptos-core/consensus/src/liveness/cached_proposer_election.rs',
    'aptos-core/consensus/src/liveness/leader_reputation.rs',
    'aptos-core/consensus/src/liveness/mod.rs',
    'aptos-core/consensus/src/liveness/proposal_generator.rs',
    'aptos-core/consensus/src/liveness/proposal_status_tracker.rs',
    'aptos-core/consensus/src/liveness/proposer_election.rs',
    'aptos-core/consensus/src/liveness/rotating_proposer_election.rs',
    'aptos-core/consensus/src/liveness/round_proposer_election.rs',
    'aptos-core/consensus/src/liveness/round_state.rs',
    'aptos-core/consensus/src/liveness/unequivocal_proposer_election.rs',
    'aptos-core/consensus/src/logging.rs',
    'aptos-core/consensus/src/metrics_safety_rules.rs',
    'aptos-core/consensus/src/network.rs',
    'aptos-core/consensus/src/network_interface.rs',
    'aptos-core/consensus/src/network_tests.rs',
    'aptos-core/consensus/src/payload_client/mixed.rs',
    'aptos-core/consensus/src/payload_client/mod.rs',
    'aptos-core/consensus/src/payload_client/user/mod.rs',
    'aptos-core/consensus/src/payload_client/user/quorum_store_client.rs',
    'aptos-core/consensus/src/payload_client/validator.rs',
    'aptos-core/consensus/src/payload_manager/co_payload_manager.rs',
    'aptos-core/consensus/src/payload_manager/direct_mempool_payload_manager.rs',
    'aptos-core/consensus/src/payload_manager/mod.rs',
    'aptos-core/consensus/src/payload_manager/quorum_store_payload_manager.rs',
    'aptos-core/consensus/src/pending_order_votes.rs',
    'aptos-core/consensus/src/pending_votes.rs',
    'aptos-core/consensus/src/persistent_liveness_storage.rs',
    'aptos-core/consensus/src/pipeline/buffer.rs',
    'aptos-core/consensus/src/pipeline/buffer_item.rs',
    'aptos-core/consensus/src/pipeline/buffer_manager.rs',
    'aptos-core/consensus/src/pipeline/commit_reliable_broadcast.rs',
    'aptos-core/consensus/src/pipeline/decoupled_execution_utils.rs',
    'aptos-core/consensus/src/pipeline/decryption_pipeline_builder.rs',
    'aptos-core/consensus/src/pipeline/errors.rs',
    'aptos-core/consensus/src/pipeline/execution_client.rs',
    'aptos-core/consensus/src/pipeline/execution_phase.rs',
    'aptos-core/consensus/src/pipeline/execution_schedule_phase.rs',
    'aptos-core/consensus/src/pipeline/execution_wait_phase.rs',
    'aptos-core/consensus/src/pipeline/hashable.rs',
    'aptos-core/consensus/src/pipeline/linkedlist.rs',
    'aptos-core/consensus/src/pipeline/mod.rs',
    'aptos-core/consensus/src/pipeline/persisting_phase.rs',
    'aptos-core/consensus/src/pipeline/pipeline_builder.rs',
    'aptos-core/consensus/src/pipeline/pipeline_phase.rs',
    'aptos-core/consensus/src/pipeline/signing_phase.rs',
    'aptos-core/consensus/src/quorum_store/batch_coordinator.rs',
    'aptos-core/consensus/src/quorum_store/batch_generator.rs',
    'aptos-core/consensus/src/quorum_store/batch_proof_queue.rs',
    'aptos-core/consensus/src/quorum_store/batch_requester.rs',
    'aptos-core/consensus/src/quorum_store/batch_store.rs',
    'aptos-core/consensus/src/quorum_store/counters.rs',
    'aptos-core/consensus/src/quorum_store/direct_mempool_quorum_store.rs',
    'aptos-core/consensus/src/quorum_store/mod.rs',
    'aptos-core/consensus/src/quorum_store/network_listener.rs',
    'aptos-core/consensus/src/quorum_store/proof_coordinator.rs',
    'aptos-core/consensus/src/quorum_store/proof_manager.rs',
    'aptos-core/consensus/src/quorum_store/quorum_store_builder.rs',
    'aptos-core/consensus/src/quorum_store/quorum_store_coordinator.rs',
    'aptos-core/consensus/src/quorum_store/quorum_store_db.rs',
    'aptos-core/consensus/src/quorum_store/schema.rs',
    'aptos-core/consensus/src/quorum_store/tracing.rs',
    'aptos-core/consensus/src/quorum_store/types.rs',
    'aptos-core/consensus/src/quorum_store/utils.rs',
    'aptos-core/consensus/src/rand/dkg/mod.rs',
    'aptos-core/consensus/src/rand/mod.rs',
    'aptos-core/consensus/src/rand/rand_gen/aug_data_store.rs',
    'aptos-core/consensus/src/rand/rand_gen/block_queue.rs',
    'aptos-core/consensus/src/rand/rand_gen/mod.rs',
    'aptos-core/consensus/src/rand/rand_gen/network_messages.rs',
    'aptos-core/consensus/src/rand/rand_gen/rand_manager.rs',
    'aptos-core/consensus/src/rand/rand_gen/rand_store.rs',
    'aptos-core/consensus/src/rand/rand_gen/reliable_broadcast_state.rs',
    'aptos-core/consensus/src/rand/rand_gen/storage/db.rs',
    'aptos-core/consensus/src/rand/rand_gen/storage/in_memory.rs',
    'aptos-core/consensus/src/rand/rand_gen/storage/interface.rs',
    'aptos-core/consensus/src/rand/rand_gen/storage/mod.rs',
    'aptos-core/consensus/src/rand/rand_gen/storage/schema.rs',
    'aptos-core/consensus/src/rand/rand_gen/types.rs',
    'aptos-core/consensus/src/rand/secret_sharing/block_queue.rs',
    'aptos-core/consensus/src/rand/secret_sharing/mod.rs',
    'aptos-core/consensus/src/rand/secret_sharing/network_messages.rs',
    'aptos-core/consensus/src/rand/secret_sharing/reliable_broadcast_state.rs',
    'aptos-core/consensus/src/rand/secret_sharing/secret_share_manager.rs',
    'aptos-core/consensus/src/rand/secret_sharing/secret_share_store.rs',
    'aptos-core/consensus/src/rand/secret_sharing/types.rs',
    'aptos-core/consensus/src/recovery_manager.rs',
    'aptos-core/consensus/src/round_manager.rs',
    'aptos-core/consensus/src/round_manager_fuzzing.rs',
    'aptos-core/consensus/src/round_manager_tests/mod.rs',
    'aptos-core/consensus/src/state_computer.rs',
    'aptos-core/consensus/src/state_replication.rs',
    'aptos-core/consensus/src/transaction_deduper.rs',
    'aptos-core/consensus/src/transaction_shuffler/mod.rs',
    'aptos-core/consensus/src/transaction_shuffler/use_case_aware/delayed_queue.rs',
    'aptos-core/consensus/src/transaction_shuffler/use_case_aware/iterator.rs',
    'aptos-core/consensus/src/transaction_shuffler/use_case_aware/mod.rs',
    'aptos-core/consensus/src/transaction_shuffler/use_case_aware/types.rs',
    'aptos-core/consensus/src/transaction_shuffler/use_case_aware/utils.rs',
    'aptos-core/consensus/src/twins/mod.rs',
    'aptos-core/consensus/src/twins/twins_node.rs',
    'aptos-core/consensus/src/txn_hash_and_authenticator_deduper.rs',
    'aptos-core/consensus/src/txn_notifier.rs',
    'aptos-core/consensus/src/util/db_tool.rs',
    'aptos-core/consensus/src/util/mock_time_service.rs',
    'aptos-core/consensus/src/util/mod.rs',
    'aptos-core/consensus/src/util/time_service.rs',
    'aptos-core/crates/aptos-admin-service/src/lib.rs',
    'aptos-core/crates/aptos-admin-service/src/server/consensus/mod.rs',
    'aptos-core/crates/aptos-admin-service/src/server/malloc.rs',
    'aptos-core/crates/aptos-admin-service/src/server/mempool/mod.rs',
    'aptos-core/crates/aptos-admin-service/src/server/mod.rs',
    'aptos-core/crates/aptos-api-tester/src/consts.rs',
    'aptos-core/crates/aptos-api-tester/src/counters.rs',
    'aptos-core/crates/aptos-api-tester/src/macros.rs',
    'aptos-core/crates/aptos-api-tester/src/main.rs',
    'aptos-core/crates/aptos-api-tester/src/persistent_check.rs',
    'aptos-core/crates/aptos-api-tester/src/strings.rs',
    'aptos-core/crates/aptos-api-tester/src/tokenv1_client.rs',
    'aptos-core/crates/aptos-api-tester/src/utils.rs',
    'aptos-core/crates/aptos-batch-encryption/benches/fk_algorithm.rs',
    'aptos-core/crates/aptos-batch-encryption/benches/fptx.rs',
    'aptos-core/crates/aptos-batch-encryption/benches/fptx_succinct.rs',
    'aptos-core/crates/aptos-batch-encryption/benches/msm.rs',
    'aptos-core/crates/aptos-batch-encryption/benches/multi_point_eval.rs',
    'aptos-core/crates/aptos-batch-encryption/src/errors.rs',
    'aptos-core/crates/aptos-batch-encryption/src/group.rs',
    'aptos-core/crates/aptos-batch-encryption/src/lib.rs',
    'aptos-core/crates/aptos-batch-encryption/src/schemes/fptx.rs',
    'aptos-core/crates/aptos-batch-encryption/src/schemes/fptx_succinct.rs',
    'aptos-core/crates/aptos-batch-encryption/src/schemes/fptx_weighted.rs',
    'aptos-core/crates/aptos-batch-encryption/src/schemes/mod.rs',
    'aptos-core/crates/aptos-batch-encryption/src/shared/algebra/differentiate.rs',
    'aptos-core/crates/aptos-batch-encryption/src/shared/algebra/fk_algorithm.rs',
    'aptos-core/crates/aptos-batch-encryption/src/shared/algebra/interpolate.rs',
    'aptos-core/crates/aptos-batch-encryption/src/shared/algebra/mod.rs',
    'aptos-core/crates/aptos-batch-encryption/src/shared/algebra/mult_tree.rs',
    'aptos-core/crates/aptos-batch-encryption/src/shared/algebra/multi_point_eval.rs',
    'aptos-core/crates/aptos-batch-encryption/src/shared/ark_serialize.rs',
    'aptos-core/crates/aptos-batch-encryption/src/shared/ciphertext/bibe.rs',
    'aptos-core/crates/aptos-batch-encryption/src/shared/ciphertext/bibe_succinct.rs',
    'aptos-core/crates/aptos-batch-encryption/src/shared/ciphertext/mod.rs',
    'aptos-core/crates/aptos-batch-encryption/src/shared/digest.rs',
    'aptos-core/crates/aptos-batch-encryption/src/shared/encryption_key.rs',
    'aptos-core/crates/aptos-batch-encryption/src/shared/ids/mod.rs',
    'aptos-core/crates/aptos-batch-encryption/src/shared/key_derivation.rs',
    'aptos-core/crates/aptos-batch-encryption/src/shared/mod.rs',
    'aptos-core/crates/aptos-batch-encryption/src/shared/symmetric.rs',
    'aptos-core/crates/aptos-batch-encryption/src/traits.rs',
    'aptos-core/crates/aptos-bcs-utils/src/lib.rs',
    'aptos-core/crates/aptos-bitvec/src/lib.rs',
    'aptos-core/crates/aptos-build-info/build.rs',
    'aptos-core/crates/aptos-build-info/src/lib.rs',
    'aptos-core/crates/aptos-cli-common/src/lib.rs',
    'aptos-core/crates/aptos-collections/src/bounded_vec_deque.rs',
    'aptos-core/crates/aptos-collections/src/lib.rs',
    'aptos-core/crates/aptos-compression/src/client.rs',
    'aptos-core/crates/aptos-compression/src/lib.rs',
    'aptos-core/crates/aptos-compression/src/metrics.rs',
    'aptos-core/crates/aptos-crypto-derive/src/hasher.rs',
    'aptos-core/crates/aptos-crypto-derive/src/lib.rs',
    'aptos-core/crates/aptos-crypto-derive/src/unions.rs',
    'aptos-core/crates/aptos-crypto/benches/ark_bls12_381.rs',
    'aptos-core/crates/aptos-crypto/benches/ark_bn254.rs',
    'aptos-core/crates/aptos-crypto/benches/ark_groth16.rs',
    'aptos-core/crates/aptos-crypto/benches/ark_rand.rs',
    'aptos-core/crates/aptos-crypto/benches/bench_utils.rs',
    'aptos-core/crates/aptos-crypto/benches/bls12381.rs',
    'aptos-core/crates/aptos-crypto/benches/bulletproofs.rs',
    'aptos-core/crates/aptos-crypto/benches/ed25519.rs',
    'aptos-core/crates/aptos-crypto/benches/hash.rs',
    'aptos-core/crates/aptos-crypto/benches/noise.rs',
    'aptos-core/crates/aptos-crypto/benches/random.rs',
    'aptos-core/crates/aptos-crypto/benches/ristretto255.rs',
    'aptos-core/crates/aptos-crypto/benches/secp256k1.rs',
    'aptos-core/crates/aptos-crypto/benches/slh_dsa_sha2_128s.rs',
    'aptos-core/crates/aptos-crypto/examples/is_blstrs_constant_time.rs',
    'aptos-core/crates/aptos-crypto/examples/is_zkcrypto_constant_time.rs',
    'aptos-core/crates/aptos-crypto/src/arkworks/differentiate.rs',
    'aptos-core/crates/aptos-crypto/src/arkworks/hashing.rs',
    'aptos-core/crates/aptos-crypto/src/arkworks/mod.rs',
    'aptos-core/crates/aptos-crypto/src/arkworks/msm.rs',
    'aptos-core/crates/aptos-crypto/src/arkworks/random.rs',
    'aptos-core/crates/aptos-crypto/src/arkworks/scrape.rs',
    'aptos-core/crates/aptos-crypto/src/arkworks/serialization.rs',
    'aptos-core/crates/aptos-crypto/src/arkworks/shamir.rs',
    'aptos-core/crates/aptos-crypto/src/arkworks/srs.rs',
    'aptos-core/crates/aptos-crypto/src/arkworks/vanishing_poly.rs',
    'aptos-core/crates/aptos-crypto/src/arkworks/weighted_sum.rs',
    'aptos-core/crates/aptos-crypto/src/asymmetric_encryption/elgamal_curve25519_aes256_gcm.rs',
    'aptos-core/crates/aptos-crypto/src/asymmetric_encryption/mod.rs',
    'aptos-core/crates/aptos-crypto/src/bls12381/bls12381_keys.rs',
    'aptos-core/crates/aptos-crypto/src/bls12381/bls12381_pop.rs',
    'aptos-core/crates/aptos-crypto/src/bls12381/bls12381_sigs.rs',
    'aptos-core/crates/aptos-crypto/src/bls12381/bls12381_validatable.rs',
    'aptos-core/crates/aptos-crypto/src/bls12381/mod.rs',
    'aptos-core/crates/aptos-crypto/src/blstrs/evaluation_domain.rs',
    'aptos-core/crates/aptos-crypto/src/blstrs/fft.rs',
    'aptos-core/crates/aptos-crypto/src/blstrs/lagrange.rs',
    'aptos-core/crates/aptos-crypto/src/blstrs/mod.rs',
    'aptos-core/crates/aptos-crypto/src/blstrs/polynomials.rs',
    'aptos-core/crates/aptos-crypto/src/blstrs/random.rs',
    'aptos-core/crates/aptos-crypto/src/blstrs/scalar_secret_key.rs',
    'aptos-core/crates/aptos-crypto/src/blstrs/threshold_config.rs',
    'aptos-core/crates/aptos-crypto/src/bulletproofs/mod.rs',
    'aptos-core/crates/aptos-crypto/src/compat.rs',
    'aptos-core/crates/aptos-crypto/src/constant_time/blstrs_scalar_mul.rs',
    'aptos-core/crates/aptos-crypto/src/constant_time/mod.rs',
    'aptos-core/crates/aptos-crypto/src/constant_time/zkcrypto_scalar_mul.rs',
    'aptos-core/crates/aptos-crypto/src/ed25519/ed25519_keys.rs',
    'aptos-core/crates/aptos-crypto/src/ed25519/ed25519_sigs.rs',
    'aptos-core/crates/aptos-crypto/src/ed25519/mod.rs',
    'aptos-core/crates/aptos-crypto/src/elgamal/curve25519.rs',
    'aptos-core/crates/aptos-crypto/src/elgamal/mod.rs',
    'aptos-core/crates/aptos-crypto/src/encoding_type.rs',
    'aptos-core/crates/aptos-crypto/src/hash.rs',
    'aptos-core/crates/aptos-crypto/src/hkdf.rs',
    'aptos-core/crates/aptos-crypto/src/input_secret.rs',
    'aptos-core/crates/aptos-crypto/src/lib.rs',
    'aptos-core/crates/aptos-crypto/src/multi_ed25519.rs',
    'aptos-core/crates/aptos-crypto/src/noise.rs',
    'aptos-core/crates/aptos-crypto/src/player.rs',
    'aptos-core/crates/aptos-crypto/src/poseidon_bn254/alt_fr.rs',
    'aptos-core/crates/aptos-crypto/src/poseidon_bn254/constants.rs',
    'aptos-core/crates/aptos-crypto/src/poseidon_bn254/keyless.rs',
    'aptos-core/crates/aptos-crypto/src/poseidon_bn254/mod.rs',
    'aptos-core/crates/aptos-crypto/src/secp256k1_ecdsa.rs',
    'aptos-core/crates/aptos-crypto/src/secp256r1_ecdsa/mod.rs',
    'aptos-core/crates/aptos-crypto/src/secp256r1_ecdsa/secp256r1_ecdsa_keys.rs',
    'aptos-core/crates/aptos-crypto/src/secp256r1_ecdsa/secp256r1_ecdsa_sigs.rs',
    'aptos-core/crates/aptos-crypto/src/slh_dsa_sha2_128s/mod.rs',
    'aptos-core/crates/aptos-crypto/src/slh_dsa_sha2_128s/slh_dsa_keys.rs',
    'aptos-core/crates/aptos-crypto/src/slh_dsa_sha2_128s/slh_dsa_sigs.rs',
    'aptos-core/crates/aptos-crypto/src/traits/mod.rs',
    'aptos-core/crates/aptos-crypto/src/unit_tests/arkworks_upgrade.rs',
    'aptos-core/crates/aptos-crypto/src/unit_tests/compilation/cross_test_trait_obj.rs',
    'aptos-core/crates/aptos-crypto/src/unit_tests/compilation/cross_test_trait_obj_pub.rs',
    'aptos-core/crates/aptos-crypto/src/unit_tests/compilation/cross_test_trait_obj_sig.rs',
    'aptos-core/crates/aptos-crypto/src/unit_tests/compilation/small_kdf.rs',
    'aptos-core/crates/aptos-crypto/src/unit_tests/cryptohasher.rs',
    'aptos-core/crates/aptos-crypto/src/unit_tests/mod.rs',
    'aptos-core/crates/aptos-crypto/src/utils.rs',
    'aptos-core/crates/aptos-crypto/src/validatable.rs',
    'aptos-core/crates/aptos-crypto/src/weighted_config.rs',
    'aptos-core/crates/aptos-crypto/src/x25519.rs',
    'aptos-core/crates/aptos-debugger/src/lib.rs',
    'aptos-core/crates/aptos-debugger/src/main.rs',
    'aptos-core/crates/aptos-dkg/src/dlog/bsgs.rs',
    'aptos-core/crates/aptos-dkg/src/dlog/mod.rs',
    'aptos-core/crates/aptos-dkg/src/dlog/table.rs',
    'aptos-core/crates/aptos-dkg/src/fiat_shamir.rs',
    'aptos-core/crates/aptos-dkg/src/lib.rs',
    'aptos-core/crates/aptos-dkg/src/pcs/mod.rs',
    'aptos-core/crates/aptos-dkg/src/pcs/traits.rs',
    'aptos-core/crates/aptos-dkg/src/pcs/univariate_hiding_kzg.rs',
    'aptos-core/crates/aptos-dkg/src/pcs/univariate_kzg.rs',
    'aptos-core/crates/aptos-dkg/src/pcs/zeromorph.rs',
    'aptos-core/crates/aptos-dkg/src/pvss/chunky/chunked_elgamal.rs',
    'aptos-core/crates/aptos-dkg/src/pvss/chunky/chunked_scalar_mul.rs',
    'aptos-core/crates/aptos-dkg/src/pvss/chunky/chunks.rs',
    'aptos-core/crates/aptos-dkg/src/pvss/chunky/hkzg_chunked_elgamal.rs',
    'aptos-core/crates/aptos-dkg/src/pvss/chunky/hkzg_chunked_elgamal_commit.rs',
    'aptos-core/crates/aptos-dkg/src/pvss/chunky/input_secret.rs',
    'aptos-core/crates/aptos-dkg/src/pvss/chunky/keys.rs',
    'aptos-core/crates/aptos-dkg/src/pvss/chunky/mod.rs',
    'aptos-core/crates/aptos-dkg/src/pvss/chunky/public_parameters.rs',
    'aptos-core/crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs',
    'aptos-core/crates/aptos-dkg/src/pvss/chunky/weighted_transcriptv2.rs',
    'aptos-core/crates/aptos-dkg/src/pvss/contribution.rs',
    'aptos-core/crates/aptos-dkg/src/pvss/das/enc.rs',
    'aptos-core/crates/aptos-dkg/src/pvss/das/input_secret.rs',
    'aptos-core/crates/aptos-dkg/src/pvss/das/mod.rs',
    'aptos-core/crates/aptos-dkg/src/pvss/das/public_parameters.rs',
    'aptos-core/crates/aptos-dkg/src/pvss/das/unweighted_protocol.rs',
    'aptos-core/crates/aptos-dkg/src/pvss/das/weighted_protocol.rs',
    'aptos-core/crates/aptos-dkg/src/pvss/dealt_pub_key.rs',
    'aptos-core/crates/aptos-dkg/src/pvss/dealt_pub_key_share.rs',
    'aptos-core/crates/aptos-dkg/src/pvss/dealt_secret_key.rs',
    'aptos-core/crates/aptos-dkg/src/pvss/dealt_secret_key_share.rs',
    'aptos-core/crates/aptos-dkg/src/pvss/encryption_dlog.rs',
    'aptos-core/crates/aptos-dkg/src/pvss/encryption_elgamal.rs',
    'aptos-core/crates/aptos-dkg/src/pvss/insecure_field/mod.rs',
    'aptos-core/crates/aptos-dkg/src/pvss/insecure_field/transcript.rs',
    'aptos-core/crates/aptos-dkg/src/pvss/mod.rs',
    'aptos-core/crates/aptos-dkg/src/pvss/schnorr.rs',
    'aptos-core/crates/aptos-dkg/src/pvss/signed/generic_signing.rs',
    'aptos-core/crates/aptos-dkg/src/pvss/signed/mod.rs',
    'aptos-core/crates/aptos-dkg/src/pvss/traits/mod.rs',
    'aptos-core/crates/aptos-dkg/src/pvss/traits/transcript.rs',
    'aptos-core/crates/aptos-dkg/src/pvss/weighted/generic_weighting.rs',
    'aptos-core/crates/aptos-dkg/src/pvss/weighted/mod.rs',
    'aptos-core/crates/aptos-dkg/src/range_proofs/dekart_univariate.rs',
    'aptos-core/crates/aptos-dkg/src/range_proofs/dekart_univariate_v2.rs',
    'aptos-core/crates/aptos-dkg/src/range_proofs/mod.rs',
    'aptos-core/crates/aptos-dkg/src/range_proofs/traits.rs',
    'aptos-core/crates/aptos-dkg/src/sigma_protocol/homomorphism/fixed_base_msms.rs',
    'aptos-core/crates/aptos-dkg/src/sigma_protocol/homomorphism/mod.rs',
    'aptos-core/crates/aptos-dkg/src/sigma_protocol/homomorphism/tuple.rs',
    'aptos-core/crates/aptos-dkg/src/sigma_protocol/mod.rs',
    'aptos-core/crates/aptos-dkg/src/sigma_protocol/traits.rs',
    'aptos-core/crates/aptos-dkg/src/utils/mod.rs',
    'aptos-core/crates/aptos-dkg/src/utils/parallel_multi_pairing.rs',
    'aptos-core/crates/aptos-dkg/src/utils/random.rs',
    'aptos-core/crates/aptos-dkg/src/weighted_vuf/bls/mod.rs',
    'aptos-core/crates/aptos-dkg/src/weighted_vuf/mod.rs',
    'aptos-core/crates/aptos-dkg/src/weighted_vuf/pinkas/mod.rs',
    'aptos-core/crates/aptos-dkg/src/weighted_vuf/traits.rs',
    'aptos-core/crates/aptos-drop-helper/src/async_concurrent_dropper.rs',
    'aptos-core/crates/aptos-drop-helper/src/async_drop_queue.rs',
    'aptos-core/crates/aptos-drop-helper/src/lib.rs',
    'aptos-core/crates/aptos-drop-helper/src/metrics.rs',
    'aptos-core/crates/aptos-enum-conversion-derive/src/lib.rs',
    'aptos-core/crates/aptos-faucet/cli/src/main.rs',
    'aptos-core/crates/aptos-faucet/core/src/build.rs',
    'aptos-core/crates/aptos-faucet/core/src/bypasser/auth_token.rs',
    'aptos-core/crates/aptos-faucet/core/src/bypasser/ip_allowlist.rs',
    'aptos-core/crates/aptos-faucet/core/src/bypasser/mod.rs',
    'aptos-core/crates/aptos-faucet/core/src/checkers/auth_token.rs',
    'aptos-core/crates/aptos-faucet/core/src/checkers/google_captcha.rs',
    'aptos-core/crates/aptos-faucet/core/src/checkers/ip_blocklist.rs',
    'aptos-core/crates/aptos-faucet/core/src/checkers/magic_header.rs',
    'aptos-core/crates/aptos-faucet/core/src/checkers/memory_ratelimit.rs',
    'aptos-core/crates/aptos-faucet/core/src/checkers/mod.rs',
    'aptos-core/crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs',
    'aptos-core/crates/aptos-faucet/core/src/checkers/referer_blocklist.rs',
    'aptos-core/crates/aptos-faucet/core/src/checkers/tap_captcha.rs',
    'aptos-core/crates/aptos-faucet/core/src/common/ip_range_manager.rs',
    'aptos-core/crates/aptos-faucet/core/src/common/list_manager.rs',
    'aptos-core/crates/aptos-faucet/core/src/common/mod.rs',
    'aptos-core/crates/aptos-faucet/core/src/endpoints/api.rs',
    'aptos-core/crates/aptos-faucet/core/src/endpoints/basic.rs',
    'aptos-core/crates/aptos-faucet/core/src/endpoints/captcha.rs',
    'aptos-core/crates/aptos-faucet/core/src/endpoints/error_converter.rs',
    'aptos-core/crates/aptos-faucet/core/src/endpoints/errors.rs',
    'aptos-core/crates/aptos-faucet/core/src/endpoints/fund.rs',
    'aptos-core/crates/aptos-faucet/core/src/endpoints/mod.rs',
    'aptos-core/crates/aptos-faucet/core/src/firebase_jwt.rs',
    'aptos-core/crates/aptos-faucet/core/src/funder/common.rs',
    'aptos-core/crates/aptos-faucet/core/src/funder/fake.rs',
    'aptos-core/crates/aptos-faucet/core/src/funder/mint.rs',
    'aptos-core/crates/aptos-faucet/core/src/funder/mod.rs',
    'aptos-core/crates/aptos-faucet/core/src/funder/transfer.rs',
    'aptos-core/crates/aptos-faucet/core/src/helpers.rs',
    'aptos-core/crates/aptos-faucet/core/src/lib.rs',
    'aptos-core/crates/aptos-faucet/core/src/middleware/log.rs',
    'aptos-core/crates/aptos-faucet/core/src/middleware/metrics.rs',
    'aptos-core/crates/aptos-faucet/core/src/middleware/mod.rs',
    'aptos-core/crates/aptos-faucet/core/src/server/generate_openapi.rs',
    'aptos-core/crates/aptos-faucet/core/src/server/mod.rs',
    'aptos-core/crates/aptos-faucet/core/src/server/run.rs',
    'aptos-core/crates/aptos-faucet/core/src/server/server_args.rs',
    'aptos-core/crates/aptos-faucet/core/src/server/validate_config.rs',
    'aptos-core/crates/aptos-faucet/metrics-server/src/config.rs',
    'aptos-core/crates/aptos-faucet/metrics-server/src/gather_metrics.rs',
    'aptos-core/crates/aptos-faucet/metrics-server/src/lib.rs',
    'aptos-core/crates/aptos-faucet/metrics-server/src/server.rs',
    'aptos-core/crates/aptos-faucet/service/src/main.rs',
    'aptos-core/crates/aptos-genesis/src/builder.rs',
    'aptos-core/crates/aptos-genesis/src/config.rs',
    'aptos-core/crates/aptos-genesis/src/keys.rs',
    'aptos-core/crates/aptos-genesis/src/lib.rs',
    'aptos-core/crates/aptos-genesis/src/mainnet.rs',
    'aptos-core/crates/aptos-github-client/src/lib.rs',
    'aptos-core/crates/aptos-id-generator/src/lib.rs',
    'aptos-core/crates/aptos-in-memory-cache/src/caches/mod.rs',
    'aptos-core/crates/aptos-in-memory-cache/src/caches/sync_mutex.rs',
    'aptos-core/crates/aptos-in-memory-cache/src/lib.rs',
    'aptos-core/crates/aptos-infallible/src/lib.rs',
    'aptos-core/crates/aptos-infallible/src/math.rs',
    'aptos-core/crates/aptos-infallible/src/mutex.rs',
    'aptos-core/crates/aptos-infallible/src/nonzero.rs',
    'aptos-core/crates/aptos-infallible/src/rwlock.rs',
    'aptos-core/crates/aptos-infallible/src/time.rs',
    'aptos-core/crates/aptos-inspection-service/src/inspection_client.rs',
    'aptos-core/crates/aptos-inspection-service/src/lib.rs',
    'aptos-core/crates/aptos-inspection-service/src/server/configuration.rs',
    'aptos-core/crates/aptos-inspection-service/src/server/identity_information.rs',
    'aptos-core/crates/aptos-inspection-service/src/server/index.rs',
    'aptos-core/crates/aptos-inspection-service/src/server/json_encoder.rs',
    'aptos-core/crates/aptos-inspection-service/src/server/metrics.rs',
    'aptos-core/crates/aptos-inspection-service/src/server/mod.rs',
    'aptos-core/crates/aptos-inspection-service/src/server/peer_information.rs',
    'aptos-core/crates/aptos-inspection-service/src/server/system_information.rs',
    'aptos-core/crates/aptos-inspection-service/src/server/utils.rs',
    'aptos-core/crates/aptos-jwk-consensus/src/counters.rs',
    'aptos-core/crates/aptos-jwk-consensus/src/epoch_manager.rs',
    'aptos-core/crates/aptos-jwk-consensus/src/jwk_manager/mod.rs',
    'aptos-core/crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs',
    'aptos-core/crates/aptos-jwk-consensus/src/jwk_observer.rs',
    'aptos-core/crates/aptos-jwk-consensus/src/lib.rs',
    'aptos-core/crates/aptos-jwk-consensus/src/mode/mod.rs',
    'aptos-core/crates/aptos-jwk-consensus/src/mode/per_issuer.rs',
    'aptos-core/crates/aptos-jwk-consensus/src/mode/per_key.rs',
    'aptos-core/crates/aptos-jwk-consensus/src/network.rs',
    'aptos-core/crates/aptos-jwk-consensus/src/network_interface.rs',
    'aptos-core/crates/aptos-jwk-consensus/src/observation_aggregation/mod.rs',
    'aptos-core/crates/aptos-jwk-consensus/src/types.rs',
    'aptos-core/crates/aptos-jwk-consensus/src/update_certifier.rs',
    'aptos-core/crates/aptos-keygen/src/lib.rs',
    'aptos-core/crates/aptos-keygen/src/main.rs',
    'aptos-core/crates/aptos-ledger/src/lib.rs',
    'aptos-core/crates/aptos-localnet/src/docker.rs',
    'aptos-core/crates/aptos-localnet/src/health_checker.rs',
    'aptos-core/crates/aptos-localnet/src/indexer_api.rs',
    'aptos-core/crates/aptos-localnet/src/lib.rs',
    'aptos-core/crates/aptos-localnet/src/processors.rs',
    'aptos-core/crates/aptos-log-derive/src/lib.rs',
    'aptos-core/crates/aptos-logger/src/aptos_logger.rs',
    'aptos-core/crates/aptos-logger/src/counters.rs',
    'aptos-core/crates/aptos-logger/src/event.rs',
    'aptos-core/crates/aptos-logger/src/filter.rs',
    'aptos-core/crates/aptos-logger/src/kv.rs',
    'aptos-core/crates/aptos-logger/src/lib.rs',
    'aptos-core/crates/aptos-logger/src/logger.rs',
    'aptos-core/crates/aptos-logger/src/macros.rs',
    'aptos-core/crates/aptos-logger/src/metadata.rs',
    'aptos-core/crates/aptos-logger/src/sample.rs',
    'aptos-core/crates/aptos-logger/src/security.rs',
    'aptos-core/crates/aptos-logger/src/telemetry_log_writer.rs',
    'aptos-core/crates/aptos-logger/src/tracing_adapter.rs',
    'aptos-core/crates/aptos-metrics-core/src/avg_counter.rs',
    'aptos-core/crates/aptos-metrics-core/src/const_metric.rs',
    'aptos-core/crates/aptos-metrics-core/src/lib.rs',
    'aptos-core/crates/aptos-metrics-core/src/op_counters.rs',
    'aptos-core/crates/aptos-metrics-core/src/thread_local.rs',
    'aptos-core/crates/aptos-network-checker/src/args.rs',
    'aptos-core/crates/aptos-network-checker/src/check_endpoint.rs',
    'aptos-core/crates/aptos-network-checker/src/lib.rs',
    'aptos-core/crates/aptos-node-identity/src/lib.rs',
    'aptos-core/crates/aptos-openapi/src/helpers.rs',
    'aptos-core/crates/aptos-openapi/src/lib.rs',
    'aptos-core/crates/aptos-profiler/src/cpu_profiler.rs',
    'aptos-core/crates/aptos-profiler/src/lib.rs',
    'aptos-core/crates/aptos-profiler/src/memory_profiler.rs',
    'aptos-core/crates/aptos-profiler/src/utils.rs',
    'aptos-core/crates/aptos-proptest-helpers/src/growing_subset.rs',
    'aptos-core/crates/aptos-proptest-helpers/src/lib.rs',
    'aptos-core/crates/aptos-proptest-helpers/src/repeat_vec.rs',
    'aptos-core/crates/aptos-proptest-helpers/src/unit_tests.rs',
    'aptos-core/crates/aptos-proptest-helpers/src/unit_tests/growing_subset_tests.rs',
    'aptos-core/crates/aptos-proptest-helpers/src/unit_tests/pick_idx_tests.rs',
    'aptos-core/crates/aptos-proptest-helpers/src/unit_tests/repeat_vec_tests.rs',
    'aptos-core/crates/aptos-proptest-helpers/src/value_generator.rs',
    'aptos-core/crates/aptos-push-metrics/src/lib.rs',
    'aptos-core/crates/aptos-rate-limiter/src/async_lib.rs',
    'aptos-core/crates/aptos-rate-limiter/src/lib.rs',
    'aptos-core/crates/aptos-rate-limiter/src/main.rs',
    'aptos-core/crates/aptos-rate-limiter/src/rate_limit.rs',
    'aptos-core/crates/aptos-rest-client/examples/account/main.rs',
    'aptos-core/crates/aptos-rest-client/src/aptos.rs',
    'aptos-core/crates/aptos-rest-client/src/client_builder.rs',
    'aptos-core/crates/aptos-rest-client/src/error.rs',
    'aptos-core/crates/aptos-rest-client/src/faucet.rs',
    'aptos-core/crates/aptos-rest-client/src/lib.rs',
    'aptos-core/crates/aptos-rest-client/src/response.rs',
    'aptos-core/crates/aptos-rest-client/src/state.rs',
    'aptos-core/crates/aptos-rest-client/src/types.rs',
    'aptos-core/crates/aptos-retrier/src/lib.rs',
    'aptos-core/crates/aptos-rosetta-cli/src/account.rs',
    'aptos-core/crates/aptos-rosetta-cli/src/block.rs',
    'aptos-core/crates/aptos-rosetta-cli/src/common.rs',
    'aptos-core/crates/aptos-rosetta-cli/src/construction.rs',
    'aptos-core/crates/aptos-rosetta-cli/src/main.rs',
    'aptos-core/crates/aptos-rosetta-cli/src/network.rs',
    'aptos-core/crates/aptos-rosetta/src/account.rs',
    'aptos-core/crates/aptos-rosetta/src/block.rs',
    'aptos-core/crates/aptos-rosetta/src/client.rs',
    'aptos-core/crates/aptos-rosetta/src/common.rs',
    'aptos-core/crates/aptos-rosetta/src/construction.rs',
    'aptos-core/crates/aptos-rosetta/src/error.rs',
    'aptos-core/crates/aptos-rosetta/src/lib.rs',
    'aptos-core/crates/aptos-rosetta/src/main.rs',
    'aptos-core/crates/aptos-rosetta/src/network.rs',
    'aptos-core/crates/aptos-rosetta/src/test/mod.rs',
    'aptos-core/crates/aptos-rosetta/src/types/identifiers.rs',
    'aptos-core/crates/aptos-rosetta/src/types/misc.rs',
    'aptos-core/crates/aptos-rosetta/src/types/mod.rs',
    'aptos-core/crates/aptos-rosetta/src/types/move_types.rs',
    'aptos-core/crates/aptos-rosetta/src/types/objects.rs',
    'aptos-core/crates/aptos-rosetta/src/types/requests.rs',
    'aptos-core/crates/aptos-runtimes/src/lib.rs',
    'aptos-core/crates/aptos-speculative-state-helper/src/lib.rs',
    'aptos-core/crates/aptos-system-utils/src/lib.rs',
    'aptos-core/crates/aptos-system-utils/src/profiling.rs',
    'aptos-core/crates/aptos-system-utils/src/thread_dump.rs',
    'aptos-core/crates/aptos-system-utils/src/utils.rs',
    'aptos-core/crates/aptos-telemetry-service/e2e-test/test-client/src/main.rs',
    'aptos-core/crates/aptos-telemetry-service/src/allowlist_cache.rs',
    'aptos-core/crates/aptos-telemetry-service/src/auth.rs',
    'aptos-core/crates/aptos-telemetry-service/src/challenge_cache.rs',
    'aptos-core/crates/aptos-telemetry-service/src/clients/humio.rs',
    'aptos-core/crates/aptos-telemetry-service/src/clients/loki.rs',
    'aptos-core/crates/aptos-telemetry-service/src/clients/mod.rs',
    'aptos-core/crates/aptos-telemetry-service/src/clients/prometheus_remote_write.rs',
    'aptos-core/crates/aptos-telemetry-service/src/clients/victoria_metrics.rs',
    'aptos-core/crates/aptos-telemetry-service/src/constants.rs',
    'aptos-core/crates/aptos-telemetry-service/src/context.rs',
    'aptos-core/crates/aptos-telemetry-service/src/custom_contract_auth.rs',
    'aptos-core/crates/aptos-telemetry-service/src/custom_contract_ingest.rs',
    'aptos-core/crates/aptos-telemetry-service/src/custom_event.rs',
    'aptos-core/crates/aptos-telemetry-service/src/errors.rs',
    'aptos-core/crates/aptos-telemetry-service/src/gcp_logger.rs',
    'aptos-core/crates/aptos-telemetry-service/src/index.rs',
    'aptos-core/crates/aptos-telemetry-service/src/jwt_auth.rs',
    'aptos-core/crates/aptos-telemetry-service/src/lib.rs',
    'aptos-core/crates/aptos-telemetry-service/src/log_ingest.rs',
    'aptos-core/crates/aptos-telemetry-service/src/main.rs',
    'aptos-core/crates/aptos-telemetry-service/src/metrics.rs',
    'aptos-core/crates/aptos-telemetry-service/src/peer_location.rs',
    'aptos-core/crates/aptos-telemetry-service/src/prometheus_push_metrics.rs',
    'aptos-core/crates/aptos-telemetry-service/src/remote_config.rs',
    'aptos-core/crates/aptos-telemetry-service/src/types/auth.rs',
    'aptos-core/crates/aptos-telemetry-service/src/types/mod.rs',
    'aptos-core/crates/aptos-telemetry-service/src/types/telemetry.rs',
    'aptos-core/crates/aptos-telemetry-service/src/validator_cache.rs',
    'aptos-core/crates/aptos-telemetry/src/cli_metrics.rs',
    'aptos-core/crates/aptos-telemetry/src/constants.rs',
    'aptos-core/crates/aptos-telemetry/src/core_metrics.rs',
    'aptos-core/crates/aptos-telemetry/src/lib.rs',
    'aptos-core/crates/aptos-telemetry/src/metrics.rs',
    'aptos-core/crates/aptos-telemetry/src/network_metrics.rs',
    'aptos-core/crates/aptos-telemetry/src/sender.rs',
    'aptos-core/crates/aptos-telemetry/src/service.rs',
    'aptos-core/crates/aptos-telemetry/src/system_information.rs',
    'aptos-core/crates/aptos-telemetry/src/telemetry_log_sender.rs',
    'aptos-core/crates/aptos-telemetry/src/utils.rs',
    'aptos-core/crates/aptos-temppath/src/lib.rs',
    'aptos-core/crates/aptos-time-service/src/interval.rs',
    'aptos-core/crates/aptos-time-service/src/lib.rs',
    'aptos-core/crates/aptos-time-service/src/mock.rs',
    'aptos-core/crates/aptos-time-service/src/real.rs',
    'aptos-core/crates/aptos-time-service/src/timeout.rs',
    'aptos-core/crates/aptos-transaction-filters/src/batch_transaction_filter.rs',
    'aptos-core/crates/aptos-transaction-filters/src/block_transaction_filter.rs',
    'aptos-core/crates/aptos-transaction-filters/src/lib.rs',
    'aptos-core/crates/aptos-transaction-filters/src/transaction_filter.rs',
    'aptos-core/crates/aptos-warp-webserver/src/error.rs',
    'aptos-core/crates/aptos-warp-webserver/src/lib.rs',
    'aptos-core/crates/aptos-warp-webserver/src/log.rs',
    'aptos-core/crates/aptos-warp-webserver/src/response.rs',
    'aptos-core/crates/aptos-warp-webserver/src/webserver.rs',
    'aptos-core/crates/aptos/build.rs',
    'aptos-core/crates/aptos/src/account/balance.rs',
    'aptos-core/crates/aptos/src/account/create.rs',
    'aptos-core/crates/aptos/src/account/create_resource_account.rs',
    'aptos-core/crates/aptos/src/account/derive_resource_account.rs',
    'aptos-core/crates/aptos/src/account/fund.rs',
    'aptos-core/crates/aptos/src/account/key_rotation.rs',
    'aptos-core/crates/aptos/src/account/list.rs',
    'aptos-core/crates/aptos/src/account/mod.rs',
    'aptos-core/crates/aptos/src/account/multisig_account.rs',
    'aptos-core/crates/aptos/src/account/transfer.rs',
    'aptos-core/crates/aptos/src/common/init.rs',
    'aptos-core/crates/aptos/src/common/local_simulation.rs',
    'aptos-core/crates/aptos/src/common/mod.rs',
    'aptos-core/crates/aptos/src/common/transactions.rs',
    'aptos-core/crates/aptos/src/common/types.rs',
    'aptos-core/crates/aptos/src/common/utils.rs',
    'aptos-core/crates/aptos/src/config/mod.rs',
    'aptos-core/crates/aptos/src/genesis/git.rs',
    'aptos-core/crates/aptos/src/genesis/keys.rs',
    'aptos-core/crates/aptos/src/genesis/mod.rs',
    'aptos-core/crates/aptos/src/genesis/tools.rs',
    'aptos-core/crates/aptos/src/governance/delegation_pool.rs',
    'aptos-core/crates/aptos/src/governance/mod.rs',
    'aptos-core/crates/aptos/src/governance/utils.rs',
    'aptos-core/crates/aptos/src/lib.rs',
    'aptos-core/crates/aptos/src/main.rs',
    'aptos-core/crates/aptos/src/move_tool/aptos_debug_natives.rs',
    'aptos-core/crates/aptos/src/move_tool/bytecode.rs',
    'aptos-core/crates/aptos/src/move_tool/coverage.rs',
    'aptos-core/crates/aptos/src/move_tool/fmt.rs',
    'aptos-core/crates/aptos/src/move_tool/lint.rs',
    'aptos-core/crates/aptos/src/move_tool/manifest.rs',
    'aptos-core/crates/aptos/src/move_tool/mod.rs',
    'aptos-core/crates/aptos/src/move_tool/package_hooks.rs',
    'aptos-core/crates/aptos/src/move_tool/show.rs',
    'aptos-core/crates/aptos/src/move_tool/sim.rs',
    'aptos-core/crates/aptos/src/move_tool/stored_package.rs',
    'aptos-core/crates/aptos/src/node/analyze/analyze_validators.rs',
    'aptos-core/crates/aptos/src/node/analyze/fetch_metadata.rs',
    'aptos-core/crates/aptos/src/node/analyze/mod.rs',
    'aptos-core/crates/aptos/src/node/local_testnet/docker.rs',
    'aptos-core/crates/aptos/src/node/local_testnet/faucet.rs',
    'aptos-core/crates/aptos/src/node/local_testnet/health_checker.rs',
    'aptos-core/crates/aptos/src/node/local_testnet/indexer_api.rs',
    'aptos-core/crates/aptos/src/node/local_testnet/logging.rs',
    'aptos-core/crates/aptos/src/node/local_testnet/mod.rs',
    'aptos-core/crates/aptos/src/node/local_testnet/node.rs',
    'aptos-core/crates/aptos/src/node/local_testnet/postgres.rs',
    'aptos-core/crates/aptos/src/node/local_testnet/processors.rs',
    'aptos-core/crates/aptos/src/node/local_testnet/ready_server.rs',
    'aptos-core/crates/aptos/src/node/local_testnet/traits.rs',
    'aptos-core/crates/aptos/src/node/local_testnet/utils.rs',
    'aptos-core/crates/aptos/src/node/mod.rs',
    'aptos-core/crates/aptos/src/op/key.rs',
    'aptos-core/crates/aptos/src/op/mod.rs',
    'aptos-core/crates/aptos/src/stake/mod.rs',
    'aptos-core/crates/aptos/src/test/mod.rs',
    'aptos-core/crates/aptos/src/update/aptos.rs',
    'aptos-core/crates/aptos/src/update/helpers.rs',
    'aptos-core/crates/aptos/src/update/mod.rs',
    'aptos-core/crates/aptos/src/update/movefmt.rs',
    'aptos-core/crates/aptos/src/update/prover_dependencies.rs',
    'aptos-core/crates/aptos/src/update/prover_dependency_installer.rs',
    'aptos-core/crates/aptos/src/update/revela.rs',
    'aptos-core/crates/aptos/src/update/tool.rs',
    'aptos-core/crates/aptos/src/update/update_helper.rs',
    'aptos-core/crates/aptos/src/workspace/mod.rs',
    'aptos-core/crates/bounded-executor/src/concurrent_stream.rs',
    'aptos-core/crates/bounded-executor/src/executor.rs',
    'aptos-core/crates/bounded-executor/src/lib.rs',
    'aptos-core/crates/channel/src/aptos_channel.rs',
    'aptos-core/crates/channel/src/lib.rs',
    'aptos-core/crates/channel/src/message_queues.rs',
    'aptos-core/crates/crash-handler/src/lib.rs',
    'aptos-core/crates/fallible/src/copy_from_slice.rs',
    'aptos-core/crates/fallible/src/lib.rs',
    'aptos-core/crates/indexer/src/counters.rs',
    'aptos-core/crates/indexer/src/database.rs',
    'aptos-core/crates/indexer/src/indexer/errors.rs',
    'aptos-core/crates/indexer/src/indexer/fetcher.rs',
    'aptos-core/crates/indexer/src/indexer/mod.rs',
    'aptos-core/crates/indexer/src/indexer/processing_result.rs',
    'aptos-core/crates/indexer/src/indexer/tailer.rs',
    'aptos-core/crates/indexer/src/indexer/transaction_processor.rs',
    'aptos-core/crates/indexer/src/lib.rs',
    'aptos-core/crates/indexer/src/models/block_metadata_transactions.rs',
    'aptos-core/crates/indexer/src/models/coin_models/account_transactions.rs',
    'aptos-core/crates/indexer/src/models/coin_models/coin_activities.rs',
    'aptos-core/crates/indexer/src/models/coin_models/coin_balances.rs',
    'aptos-core/crates/indexer/src/models/coin_models/coin_infos.rs',
    'aptos-core/crates/indexer/src/models/coin_models/coin_supply.rs',
    'aptos-core/crates/indexer/src/models/coin_models/coin_utils.rs',
    'aptos-core/crates/indexer/src/models/coin_models/mod.rs',
    'aptos-core/crates/indexer/src/models/coin_models/v2_fungible_asset_utils.rs',
    'aptos-core/crates/indexer/src/models/events.rs',
    'aptos-core/crates/indexer/src/models/ledger_info.rs',
    'aptos-core/crates/indexer/src/models/mod.rs',
    'aptos-core/crates/indexer/src/models/move_modules.rs',
    'aptos-core/crates/indexer/src/models/move_resources.rs',
    'aptos-core/crates/indexer/src/models/move_tables.rs',
    'aptos-core/crates/indexer/src/models/processor_status.rs',
    'aptos-core/crates/indexer/src/models/processor_statuses.rs',
    'aptos-core/crates/indexer/src/models/property_map.rs',
    'aptos-core/crates/indexer/src/models/signatures.rs',
    'aptos-core/crates/indexer/src/models/stake_models/delegator_activities.rs',
    'aptos-core/crates/indexer/src/models/stake_models/delegator_balances.rs',
    'aptos-core/crates/indexer/src/models/stake_models/delegator_pools.rs',
    'aptos-core/crates/indexer/src/models/stake_models/mod.rs',
    'aptos-core/crates/indexer/src/models/stake_models/proposal_votes.rs',
    'aptos-core/crates/indexer/src/models/stake_models/stake_utils.rs',
    'aptos-core/crates/indexer/src/models/stake_models/staking_pool_voter.rs',
    'aptos-core/crates/indexer/src/models/token_models/ans_lookup.rs',
    'aptos-core/crates/indexer/src/models/token_models/collection_datas.rs',
    'aptos-core/crates/indexer/src/models/token_models/mod.rs',
    'aptos-core/crates/indexer/src/models/token_models/nft_points.rs',
    'aptos-core/crates/indexer/src/models/token_models/token_activities.rs',
    'aptos-core/crates/indexer/src/models/token_models/token_claims.rs',
    'aptos-core/crates/indexer/src/models/token_models/token_datas.rs',
    'aptos-core/crates/indexer/src/models/token_models/token_ownerships.rs',
    'aptos-core/crates/indexer/src/models/token_models/token_utils.rs',
    'aptos-core/crates/indexer/src/models/token_models/tokens.rs',
    'aptos-core/crates/indexer/src/models/token_models/v2_collections.rs',
    'aptos-core/crates/indexer/src/models/token_models/v2_token_activities.rs',
    'aptos-core/crates/indexer/src/models/token_models/v2_token_datas.rs',
    'aptos-core/crates/indexer/src/models/token_models/v2_token_metadata.rs',
    'aptos-core/crates/indexer/src/models/token_models/v2_token_ownerships.rs',
    'aptos-core/crates/indexer/src/models/token_models/v2_token_utils.rs',
    'aptos-core/crates/indexer/src/models/transactions.rs',
    'aptos-core/crates/indexer/src/models/user_transactions.rs',
    'aptos-core/crates/indexer/src/models/v2_objects.rs',
    'aptos-core/crates/indexer/src/models/write_set_changes.rs',
    'aptos-core/crates/indexer/src/processors/coin_processor.rs',
    'aptos-core/crates/indexer/src/processors/default_processor.rs',
    'aptos-core/crates/indexer/src/processors/mod.rs',
    'aptos-core/crates/indexer/src/processors/stake_processor.rs',
    'aptos-core/crates/indexer/src/processors/token_processor.rs',
    'aptos-core/crates/indexer/src/runtime.rs',
    'aptos-core/crates/indexer/src/schema.rs',
    'aptos-core/crates/indexer/src/util.rs',
    'aptos-core/crates/jwk-utils/src/lib.rs',
    'aptos-core/crates/node-resource-metrics/src/collectors/basic_node_info_collector.rs',
    'aptos-core/crates/node-resource-metrics/src/collectors/common.rs',
    'aptos-core/crates/node-resource-metrics/src/collectors/cpu_metrics_collector.rs',
    'aptos-core/crates/node-resource-metrics/src/collectors/disk_metrics_collector.rs',
    'aptos-core/crates/node-resource-metrics/src/collectors/linux_collectors.rs',
    'aptos-core/crates/node-resource-metrics/src/collectors/loadavg_collector.rs',
    'aptos-core/crates/node-resource-metrics/src/collectors/memory_metrics_collector.rs',
    'aptos-core/crates/node-resource-metrics/src/collectors/mod.rs',
    'aptos-core/crates/node-resource-metrics/src/collectors/network_metrics_collector.rs',
    'aptos-core/crates/node-resource-metrics/src/collectors/process_metrics_collector.rs',
    'aptos-core/crates/node-resource-metrics/src/lib.rs',
    'aptos-core/crates/num-variants/src/lib.rs',
    'aptos-core/crates/proxy/src/lib.rs',
    'aptos-core/crates/reliable-broadcast/src/lib.rs',
    'aptos-core/crates/short-hex-str/src/lib.rs',
    'aptos-core/crates/transaction-emitter-lib/src/args.rs',
    'aptos-core/crates/transaction-emitter-lib/src/cluster.rs',
    'aptos-core/crates/transaction-emitter-lib/src/emitter/account_minter.rs',
    'aptos-core/crates/transaction-emitter-lib/src/emitter/local_account_generator.rs',
    'aptos-core/crates/transaction-emitter-lib/src/emitter/mod.rs',
    'aptos-core/crates/transaction-emitter-lib/src/emitter/stats.rs',
    'aptos-core/crates/transaction-emitter-lib/src/emitter/submission_worker.rs',
    'aptos-core/crates/transaction-emitter-lib/src/emitter/transaction_executor.rs',
    'aptos-core/crates/transaction-emitter-lib/src/instance.rs',
    'aptos-core/crates/transaction-emitter-lib/src/lib.rs',
    'aptos-core/crates/transaction-emitter-lib/src/wrappers.rs',
    'aptos-core/crates/transaction-emitter/src/diag.rs',
    'aptos-core/crates/transaction-emitter/src/main.rs',
    'aptos-core/crates/transaction-generator-lib/src/account_generator.rs',
    'aptos-core/crates/transaction-generator-lib/src/accounts_pool_wrapper.rs',
    'aptos-core/crates/transaction-generator-lib/src/batch_transfer.rs',
    'aptos-core/crates/transaction-generator-lib/src/bounded_batch_wrapper.rs',
    'aptos-core/crates/transaction-generator-lib/src/call_custom_modules.rs',
    'aptos-core/crates/transaction-generator-lib/src/entry_points.rs',
    'aptos-core/crates/transaction-generator-lib/src/lib.rs',
    'aptos-core/crates/transaction-generator-lib/src/p2p_transaction_generator.rs',
    'aptos-core/crates/transaction-generator-lib/src/publish_modules.rs',
    'aptos-core/crates/transaction-generator-lib/src/publishing/entry_point_trait.rs',
    'aptos-core/crates/transaction-generator-lib/src/publishing/mod.rs',
    'aptos-core/crates/transaction-generator-lib/src/publishing/prebuild_packages.rs',
    'aptos-core/crates/transaction-generator-lib/src/publishing/publish_util.rs',
    'aptos-core/crates/transaction-generator-lib/src/transaction_mix_generator.rs',
    'aptos-core/crates/transaction-generator-lib/src/workflow_delegator.rs',
    'aptos-core/crates/transaction-workloads-lib/src/args.rs',
    'aptos-core/crates/transaction-workloads-lib/src/lib.rs',
    'aptos-core/crates/transaction-workloads-lib/src/move_workloads.rs',
    'aptos-core/crates/transaction-workloads-lib/src/prebuilt_packages.rs',
    'aptos-core/crates/transaction-workloads-lib/src/token_workflow.rs',
    'aptos-core/crates/validator-transaction-pool/src/lib.rs',
    'aptos-core/dkg/src/agg_trx_producer.rs',
    'aptos-core/dkg/src/counters.rs',
    'aptos-core/dkg/src/dkg_manager/mod.rs',
    'aptos-core/dkg/src/epoch_manager.rs',
    'aptos-core/dkg/src/lib.rs',
    'aptos-core/dkg/src/network.rs',
    'aptos-core/dkg/src/network_interface.rs',
    'aptos-core/dkg/src/transcript_aggregation/mod.rs',
    'aptos-core/dkg/src/types.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/lib.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/main.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/metrics.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/config.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/connection_manager.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/historical_data_service.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/lib.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/data_client.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/data_manager.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/fetch_manager.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/in_memory_cache.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/mod.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/main.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/metrics.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/service.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/status_page.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-data-service/src/config.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-data-service/src/lib.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-data-service/src/main.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-data-service/src/metrics.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-data-service/src/service.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-file-checker/src/lib.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-file-checker/src/main.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-file-checker/src/processor.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-file-store-backfiller/src/lib.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-file-store-backfiller/src/main.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-file-store-backfiller/src/processor.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-file-store/src/lib.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-file-store/src/main.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-file-store/src/metrics.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-file-store/src/processor.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-fullnode/src/convert.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-fullnode/src/counters.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-fullnode/src/fullnode_data_service.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-fullnode/src/lib.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-fullnode/src/localnet_data_service.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-fullnode/src/runtime.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-gateway/src/config.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-gateway/src/gateway.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-gateway/src/lib.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-gateway/src/main.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-in-memory-cache-benchmark/src/main.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-manager/src/config.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-manager/src/data_manager.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-manager/src/file_store_uploader.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-manager/src/grpc_manager.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-manager/src/lib.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-manager/src/main.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-manager/src/metrics.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-manager/src/service.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-manager/src/status_page.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-server-framework/src/lib.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-table-info/src/backup_restore/fs_ops.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-table-info/src/backup_restore/gcs.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-table-info/src/backup_restore/mod.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-table-info/src/internal_indexer_db_service.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-table-info/src/lib.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-table-info/src/metrics.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-table-info/src/runtime.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-table-info/src/table_info_service.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-utils/src/cache_operator.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-utils/src/compression_util.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-utils/src/config.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-utils/src/constants.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-utils/src/counters.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator/gcs.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator/local.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator/mod.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator_v2/common.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator_v2/file_store_operator.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator_v2/file_store_reader.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator_v2/gcs.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator_v2/local.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator_v2/mod.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-utils/src/filter_utils.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-utils/src/in_memory_cache.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-utils/src/lib.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-utils/src/status_page/html.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-utils/src/status_page/mod.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-utils/src/storage.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-utils/src/types.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-v2-file-store-backfiller/src/lib.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-v2-file-store-backfiller/src/main.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-grpc-v2-file-store-backfiller/src/processor.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-test-transactions/src/json_transactions/generated_transactions.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-test-transactions/src/json_transactions/mod.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-test-transactions/src/lib.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-transaction-generator/src/accont_manager.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-transaction-generator/src/config.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-transaction-generator/src/lib.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-transaction-generator/src/main.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-transaction-generator/src/managed_node.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-transaction-generator/src/script_transaction_generator.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-transaction-generator/src/transaction_code_builder.rs',
    'aptos-core/ecosystem/indexer-grpc/indexer-transaction-generator/src/transaction_importer.rs',
    'aptos-core/ecosystem/indexer-grpc/transaction-filter/src/boolean_transaction_filter.rs',
    'aptos-core/ecosystem/indexer-grpc/transaction-filter/src/errors.rs',
    'aptos-core/ecosystem/indexer-grpc/transaction-filter/src/filters/event.rs',
    'aptos-core/ecosystem/indexer-grpc/transaction-filter/src/filters/mod.rs',
    'aptos-core/ecosystem/indexer-grpc/transaction-filter/src/filters/move_module.rs',
    'aptos-core/ecosystem/indexer-grpc/transaction-filter/src/filters/transaction_root.rs',
    'aptos-core/ecosystem/indexer-grpc/transaction-filter/src/filters/user_transaction.rs',
    'aptos-core/ecosystem/indexer-grpc/transaction-filter/src/lib.rs',
    'aptos-core/ecosystem/indexer-grpc/transaction-filter/src/traits.rs',
    'aptos-core/ecosystem/indexer-grpc/transaction-filter/src/utils.rs',
    'aptos-core/ecosystem/nft-metadata-crawler/src/asset_uploader/api/get_status.rs',
    'aptos-core/ecosystem/nft-metadata-crawler/src/asset_uploader/api/mod.rs',
    'aptos-core/ecosystem/nft-metadata-crawler/src/asset_uploader/api/upload_batch.rs',
    'aptos-core/ecosystem/nft-metadata-crawler/src/asset_uploader/config.rs',
    'aptos-core/ecosystem/nft-metadata-crawler/src/asset_uploader/mod.rs',
    'aptos-core/ecosystem/nft-metadata-crawler/src/asset_uploader/throttler/config.rs',
    'aptos-core/ecosystem/nft-metadata-crawler/src/asset_uploader/throttler/mod.rs',
    'aptos-core/ecosystem/nft-metadata-crawler/src/asset_uploader/worker/config.rs',
    'aptos-core/ecosystem/nft-metadata-crawler/src/asset_uploader/worker/mod.rs',
    'aptos-core/ecosystem/nft-metadata-crawler/src/config.rs',
    'aptos-core/ecosystem/nft-metadata-crawler/src/lib.rs',
    'aptos-core/ecosystem/nft-metadata-crawler/src/main.rs',
    'aptos-core/ecosystem/nft-metadata-crawler/src/models/asset_uploader_request_statuses.rs',
    'aptos-core/ecosystem/nft-metadata-crawler/src/models/asset_uploader_request_statuses_query.rs',
    'aptos-core/ecosystem/nft-metadata-crawler/src/models/ledger_info.rs',
    'aptos-core/ecosystem/nft-metadata-crawler/src/models/mod.rs',
    'aptos-core/ecosystem/nft-metadata-crawler/src/models/parsed_asset_uris.rs',
    'aptos-core/ecosystem/nft-metadata-crawler/src/models/parsed_asset_uris_query.rs',
    'aptos-core/ecosystem/nft-metadata-crawler/src/parser/config.rs',
    'aptos-core/ecosystem/nft-metadata-crawler/src/parser/mod.rs',
    'aptos-core/ecosystem/nft-metadata-crawler/src/parser/worker.rs',
    'aptos-core/ecosystem/nft-metadata-crawler/src/schema.rs',
    'aptos-core/ecosystem/nft-metadata-crawler/src/utils/constants.rs',
    'aptos-core/ecosystem/nft-metadata-crawler/src/utils/counters.rs',
    'aptos-core/ecosystem/nft-metadata-crawler/src/utils/database.rs',
    'aptos-core/ecosystem/nft-metadata-crawler/src/utils/gcs.rs',
    'aptos-core/ecosystem/nft-metadata-crawler/src/utils/image_optimizer.rs',
    'aptos-core/ecosystem/nft-metadata-crawler/src/utils/json_parser.rs',
    'aptos-core/ecosystem/nft-metadata-crawler/src/utils/mod.rs',
    'aptos-core/ecosystem/nft-metadata-crawler/src/utils/uri_parser.rs',
    'aptos-core/ecosystem/node-checker/fn-check-client/src/big_query.rs',
    'aptos-core/ecosystem/node-checker/fn-check-client/src/check.rs',
    'aptos-core/ecosystem/node-checker/fn-check-client/src/get_pfns.rs',
    'aptos-core/ecosystem/node-checker/fn-check-client/src/get_vfns.rs',
    'aptos-core/ecosystem/node-checker/fn-check-client/src/helpers.rs',
    'aptos-core/ecosystem/node-checker/fn-check-client/src/main.rs',
    'aptos-core/ecosystem/node-checker/src/bin/aptos-node-checker.rs',
    'aptos-core/ecosystem/node-checker/src/checker/build_version.rs',
    'aptos-core/ecosystem/node-checker/src/checker/consensus_proposals.rs',
    'aptos-core/ecosystem/node-checker/src/checker/consensus_round.rs',
    'aptos-core/ecosystem/node-checker/src/checker/consensus_timeouts.rs',
    'aptos-core/ecosystem/node-checker/src/checker/handshake.rs',
    'aptos-core/ecosystem/node-checker/src/checker/hardware.rs',
    'aptos-core/ecosystem/node-checker/src/checker/latency.rs',
    'aptos-core/ecosystem/node-checker/src/checker/minimum_peers.rs',
    'aptos-core/ecosystem/node-checker/src/checker/mod.rs',
    'aptos-core/ecosystem/node-checker/src/checker/node_identity.rs',
    'aptos-core/ecosystem/node-checker/src/checker/state_sync_version.rs',
    'aptos-core/ecosystem/node-checker/src/checker/tps.rs',
    'aptos-core/ecosystem/node-checker/src/checker/traits.rs',
    'aptos-core/ecosystem/node-checker/src/checker/transaction_correctness.rs',
    'aptos-core/ecosystem/node-checker/src/checker/types.rs',
    'aptos-core/ecosystem/node-checker/src/common/common_args.rs',
    'aptos-core/ecosystem/node-checker/src/common/helpers.rs',
    'aptos-core/ecosystem/node-checker/src/common/mod.rs',
    'aptos-core/ecosystem/node-checker/src/configuration/common.rs',
    'aptos-core/ecosystem/node-checker/src/configuration/mod.rs',
    'aptos-core/ecosystem/node-checker/src/configuration/node_address.rs',
    'aptos-core/ecosystem/node-checker/src/configuration/types.rs',
    'aptos-core/ecosystem/node-checker/src/configuration/validate.rs',
    'aptos-core/ecosystem/node-checker/src/lib.rs',
    'aptos-core/ecosystem/node-checker/src/provider/api_index.rs',
    'aptos-core/ecosystem/node-checker/src/provider/cache.rs',
    'aptos-core/ecosystem/node-checker/src/provider/helpers.rs',
    'aptos-core/ecosystem/node-checker/src/provider/metrics.rs',
    'aptos-core/ecosystem/node-checker/src/provider/mod.rs',
    'aptos-core/ecosystem/node-checker/src/provider/noise.rs',
    'aptos-core/ecosystem/node-checker/src/provider/provider_collection.rs',
    'aptos-core/ecosystem/node-checker/src/provider/system_information.rs',
    'aptos-core/ecosystem/node-checker/src/provider/traits.rs',
    'aptos-core/ecosystem/node-checker/src/runner/mod.rs',
    'aptos-core/ecosystem/node-checker/src/runner/sync_runner.rs',
    'aptos-core/ecosystem/node-checker/src/runner/traits.rs',
    'aptos-core/ecosystem/node-checker/src/server/api.rs',
    'aptos-core/ecosystem/node-checker/src/server/build.rs',
    'aptos-core/ecosystem/node-checker/src/server/common.rs',
    'aptos-core/ecosystem/node-checker/src/server/generate_openapi.rs',
    'aptos-core/ecosystem/node-checker/src/server/mod.rs',
    'aptos-core/ecosystem/node-checker/src/server/node_information.rs',
    'aptos-core/ecosystem/node-checker/src/server/run.rs',
    'aptos-core/execution/block-partitioner/benches/v2.rs',
    'aptos-core/execution/block-partitioner/src/lib.rs',
    'aptos-core/execution/block-partitioner/src/main.rs',
    'aptos-core/execution/block-partitioner/src/pre_partition/connected_component/config.rs',
    'aptos-core/execution/block-partitioner/src/pre_partition/connected_component/mod.rs',
    'aptos-core/execution/block-partitioner/src/pre_partition/mod.rs',
    'aptos-core/execution/block-partitioner/src/pre_partition/uniform_partitioner/config.rs',
    'aptos-core/execution/block-partitioner/src/pre_partition/uniform_partitioner/mod.rs',
    'aptos-core/execution/block-partitioner/src/sharded_block_partitioner/config.rs',
    'aptos-core/execution/block-partitioner/src/v2/build_edge.rs',
    'aptos-core/execution/block-partitioner/src/v2/config.rs',
    'aptos-core/execution/block-partitioner/src/v2/conflicting_txn_tracker.rs',
    'aptos-core/execution/block-partitioner/src/v2/counters.rs',
    'aptos-core/execution/block-partitioner/src/v2/init.rs',
    'aptos-core/execution/block-partitioner/src/v2/load_balance.rs',
    'aptos-core/execution/block-partitioner/src/v2/mod.rs',
    'aptos-core/execution/block-partitioner/src/v2/partition_to_matrix.rs',
    'aptos-core/execution/block-partitioner/src/v2/state.rs',
    'aptos-core/execution/block-partitioner/src/v2/types.rs',
    'aptos-core/execution/block-partitioner/src/v2/union_find.rs',
    'aptos-core/execution/executor-benchmark/src/account_generator.rs',
    'aptos-core/execution/executor-benchmark/src/block_preparation.rs',
    'aptos-core/execution/executor-benchmark/src/db_access.rs',
    'aptos-core/execution/executor-benchmark/src/db_generator.rs',
    'aptos-core/execution/executor-benchmark/src/db_reliable_submitter.rs',
    'aptos-core/execution/executor-benchmark/src/indexer_grpc_waiter.rs',
    'aptos-core/execution/executor-benchmark/src/ledger_update_stage.rs',
    'aptos-core/execution/executor-benchmark/src/lib.rs',
    'aptos-core/execution/executor-benchmark/src/main.rs',
    'aptos-core/execution/executor-benchmark/src/measurements.rs',
    'aptos-core/execution/executor-benchmark/src/metrics.rs',
    'aptos-core/execution/executor-benchmark/src/native/aptos_vm_uncoordinated.rs',
    'aptos-core/execution/executor-benchmark/src/native/mod.rs',
    'aptos-core/execution/executor-benchmark/src/native/native_config.rs',
    'aptos-core/execution/executor-benchmark/src/native/native_transaction.rs',
    'aptos-core/execution/executor-benchmark/src/native/native_vm.rs',
    'aptos-core/execution/executor-benchmark/src/native/parallel_uncoordinated_block_executor.rs',
    'aptos-core/execution/executor-benchmark/src/pipeline.rs',
    'aptos-core/execution/executor-benchmark/src/transaction_committer.rs',
    'aptos-core/execution/executor-benchmark/src/transaction_executor.rs',
    'aptos-core/execution/executor-benchmark/src/transaction_generator.rs',
    'aptos-core/execution/executor-service/src/error.rs',
    'aptos-core/execution/executor-service/src/lib.rs',
    'aptos-core/execution/executor-service/src/local_executor_helper.rs',
    'aptos-core/execution/executor-service/src/main.rs',
    'aptos-core/execution/executor-service/src/metrics.rs',
    'aptos-core/execution/executor-service/src/process_executor_service.rs',
    'aptos-core/execution/executor-service/src/remote_cordinator_client.rs',
    'aptos-core/execution/executor-service/src/remote_cross_shard_client.rs',
    'aptos-core/execution/executor-service/src/remote_executor_client.rs',
    'aptos-core/execution/executor-service/src/remote_executor_service.rs',
    'aptos-core/execution/executor-service/src/remote_state_view.rs',
    'aptos-core/execution/executor-service/src/remote_state_view_service.rs',
    'aptos-core/execution/executor-service/src/thread_executor_service.rs',
    'aptos-core/execution/executor-test-helpers/src/integration_test_impl.rs',
    'aptos-core/execution/executor-test-helpers/src/lib.rs',
    'aptos-core/execution/executor-types/benches/default.rs',
    'aptos-core/execution/executor-types/src/error.rs',
    'aptos-core/execution/executor-types/src/execution_output.rs',
    'aptos-core/execution/executor-types/src/ledger_update_output.rs',
    'aptos-core/execution/executor-types/src/lib.rs',
    'aptos-core/execution/executor-types/src/metrics.rs',
    'aptos-core/execution/executor-types/src/planned.rs',
    'aptos-core/execution/executor-types/src/state_checkpoint_output.rs',
    'aptos-core/execution/executor-types/src/state_compute_result.rs',
    'aptos-core/execution/executor-types/src/transactions_with_output.rs',
    'aptos-core/execution/executor/benches/data_collection.rs',
    'aptos-core/execution/executor/src/block_executor/block_tree/mod.rs',
    'aptos-core/execution/executor/src/block_executor/mod.rs',
    'aptos-core/execution/executor/src/chunk_executor/chunk_commit_queue.rs',
    'aptos-core/execution/executor/src/chunk_executor/chunk_result_verifier.rs',
    'aptos-core/execution/executor/src/chunk_executor/mod.rs',
    'aptos-core/execution/executor/src/chunk_executor/transaction_chunk.rs',
    'aptos-core/execution/executor/src/db_bootstrapper/mod.rs',
    'aptos-core/execution/executor/src/fuzzing.rs',
    'aptos-core/execution/executor/src/lib.rs',
    'aptos-core/execution/executor/src/logging.rs',
    'aptos-core/execution/executor/src/metrics.rs',
    'aptos-core/execution/executor/src/types/executed_chunk.rs',
    'aptos-core/execution/executor/src/types/mod.rs',
    'aptos-core/execution/executor/src/types/partial_state_compute_result.rs',
    'aptos-core/execution/executor/src/workflow/do_get_execution_output.rs',
    'aptos-core/execution/executor/src/workflow/do_ledger_update.rs',
    'aptos-core/execution/executor/src/workflow/do_state_checkpoint.rs',
    'aptos-core/execution/executor/src/workflow/mod.rs',
    'aptos-core/mempool/src/core_mempool/index.rs',
    'aptos-core/mempool/src/core_mempool/mempool.rs',
    'aptos-core/mempool/src/core_mempool/mod.rs',
    'aptos-core/mempool/src/core_mempool/transaction.rs',
    'aptos-core/mempool/src/core_mempool/transaction_store.rs',
    'aptos-core/mempool/src/counters.rs',
    'aptos-core/mempool/src/lib.rs',
    'aptos-core/mempool/src/logging.rs',
    'aptos-core/mempool/src/shared_mempool/coordinator.rs',
    'aptos-core/mempool/src/shared_mempool/mod.rs',
    'aptos-core/mempool/src/shared_mempool/network.rs',
    'aptos-core/mempool/src/shared_mempool/priority.rs',
    'aptos-core/mempool/src/shared_mempool/runtime.rs',
    'aptos-core/mempool/src/shared_mempool/tasks.rs',
    'aptos-core/mempool/src/shared_mempool/types.rs',
    'aptos-core/mempool/src/shared_mempool/use_case_history.rs',
    'aptos-core/mempool/src/thread_pool.rs',
    'aptos-core/network/benchmark/src/lib.rs',
    'aptos-core/network/builder/src/builder.rs',
    'aptos-core/network/builder/src/dummy.rs',
    'aptos-core/network/builder/src/lib.rs',
    'aptos-core/network/discovery/src/counters.rs',
    'aptos-core/network/discovery/src/file.rs',
    'aptos-core/network/discovery/src/lib.rs',
    'aptos-core/network/discovery/src/rest.rs',
    'aptos-core/network/discovery/src/validator_set.rs',
    'aptos-core/network/framework/src/application/error.rs',
    'aptos-core/network/framework/src/application/interface.rs',
    'aptos-core/network/framework/src/application/metadata.rs',
    'aptos-core/network/framework/src/application/mod.rs',
    'aptos-core/network/framework/src/application/storage.rs',
    'aptos-core/network/framework/src/connectivity_manager/builder.rs',
    'aptos-core/network/framework/src/connectivity_manager/mod.rs',
    'aptos-core/network/framework/src/connectivity_manager/selection.rs',
    'aptos-core/network/framework/src/constants.rs',
    'aptos-core/network/framework/src/counters.rs',
    'aptos-core/network/framework/src/error.rs',
    'aptos-core/network/framework/src/fuzzing.rs',
    'aptos-core/network/framework/src/lib.rs',
    'aptos-core/network/framework/src/logging.rs',
    'aptos-core/network/framework/src/noise/error.rs',
    'aptos-core/network/framework/src/noise/fuzzing.rs',
    'aptos-core/network/framework/src/noise/handshake.rs',
    'aptos-core/network/framework/src/noise/mod.rs',
    'aptos-core/network/framework/src/noise/stream.rs',
    'aptos-core/network/framework/src/peer/fuzzing.rs',
    'aptos-core/network/framework/src/peer/mod.rs',
    'aptos-core/network/framework/src/peer_manager/builder.rs',
    'aptos-core/network/framework/src/peer_manager/conn_notifs_channel.rs',
    'aptos-core/network/framework/src/peer_manager/error.rs',
    'aptos-core/network/framework/src/peer_manager/mod.rs',
    'aptos-core/network/framework/src/peer_manager/senders.rs',
    'aptos-core/network/framework/src/peer_manager/transport.rs',
    'aptos-core/network/framework/src/peer_manager/types.rs',
    'aptos-core/network/framework/src/protocols/direct_send/mod.rs',
    'aptos-core/network/framework/src/protocols/health_checker/builder.rs',
    'aptos-core/network/framework/src/protocols/health_checker/interface.rs',
    'aptos-core/network/framework/src/protocols/health_checker/mod.rs',
    'aptos-core/network/framework/src/protocols/identity.rs',
    'aptos-core/network/framework/src/protocols/mod.rs',
    'aptos-core/network/framework/src/protocols/network/mod.rs',
    'aptos-core/network/framework/src/protocols/rpc/error.rs',
    'aptos-core/network/framework/src/protocols/rpc/mod.rs',
    'aptos-core/network/framework/src/protocols/stream/mod.rs',
    'aptos-core/network/framework/src/protocols/wire/handshake.rs',
    'aptos-core/network/framework/src/protocols/wire/handshake/v1/mod.rs',
    'aptos-core/network/framework/src/protocols/wire/messaging.rs',
    'aptos-core/network/framework/src/protocols/wire/messaging/v1/mod.rs',
    'aptos-core/network/framework/src/protocols/wire/mod.rs',
    'aptos-core/network/framework/src/testutils/builder.rs',
    'aptos-core/network/framework/src/testutils/fake_socket.rs',
    'aptos-core/network/framework/src/testutils/mod.rs',
    'aptos-core/network/framework/src/transport/mod.rs',
    'aptos-core/network/memsocket/src/lib.rs',
    'aptos-core/network/netcore/src/framing.rs',
    'aptos-core/network/netcore/src/lib.rs',
    'aptos-core/network/netcore/src/transport/and_then.rs',
    'aptos-core/network/netcore/src/transport/boxed.rs',
    'aptos-core/network/netcore/src/transport/memory.rs',
    'aptos-core/network/netcore/src/transport/mod.rs',
    'aptos-core/network/netcore/src/transport/proxy_protocol.rs',
    'aptos-core/network/netcore/src/transport/tcp.rs',
    'aptos-core/peer-monitoring-service/client/src/error.rs',
    'aptos-core/peer-monitoring-service/client/src/lib.rs',
    'aptos-core/peer-monitoring-service/client/src/logging.rs',
    'aptos-core/peer-monitoring-service/client/src/metrics.rs',
    'aptos-core/peer-monitoring-service/client/src/network.rs',
    'aptos-core/peer-monitoring-service/client/src/peer_states/key_value.rs',
    'aptos-core/peer-monitoring-service/client/src/peer_states/latency_info.rs',
    'aptos-core/peer-monitoring-service/client/src/peer_states/mod.rs',
    'aptos-core/peer-monitoring-service/client/src/peer_states/network_info.rs',
    'aptos-core/peer-monitoring-service/client/src/peer_states/node_info.rs',
    'aptos-core/peer-monitoring-service/client/src/peer_states/peer_state.rs',
    'aptos-core/peer-monitoring-service/client/src/peer_states/request_tracker.rs',
    'aptos-core/peer-monitoring-service/server/src/error.rs',
    'aptos-core/peer-monitoring-service/server/src/lib.rs',
    'aptos-core/peer-monitoring-service/server/src/logging.rs',
    'aptos-core/peer-monitoring-service/server/src/metrics.rs',
    'aptos-core/peer-monitoring-service/server/src/network.rs',
    'aptos-core/peer-monitoring-service/server/src/storage.rs',
    'aptos-core/peer-monitoring-service/types/src/lib.rs',
    'aptos-core/peer-monitoring-service/types/src/request.rs',
    'aptos-core/peer-monitoring-service/types/src/response.rs',
    'aptos-core/protos/rust/src/lib.rs',
    'aptos-core/protos/rust/src/pb/aptos.bigquery_schema.transaction.v1.rs',
    'aptos-core/protos/rust/src/pb/aptos.bigquery_schema.transaction.v1.serde.rs',
    'aptos-core/protos/rust/src/pb/aptos.indexer.v1.rs',
    'aptos-core/protos/rust/src/pb/aptos.indexer.v1.serde.rs',
    'aptos-core/protos/rust/src/pb/aptos.indexer.v1.tonic.rs',
    'aptos-core/protos/rust/src/pb/aptos.internal.fullnode.v1.rs',
    'aptos-core/protos/rust/src/pb/aptos.internal.fullnode.v1.serde.rs',
    'aptos-core/protos/rust/src/pb/aptos.internal.fullnode.v1.tonic.rs',
    'aptos-core/protos/rust/src/pb/aptos.remote_executor.v1.rs',
    'aptos-core/protos/rust/src/pb/aptos.remote_executor.v1.serde.rs',
    'aptos-core/protos/rust/src/pb/aptos.remote_executor.v1.tonic.rs',
    'aptos-core/protos/rust/src/pb/aptos.transaction.v1.rs',
    'aptos-core/protos/rust/src/pb/aptos.transaction.v1.serde.rs',
    'aptos-core/protos/rust/src/pb/aptos.util.timestamp.rs',
    'aptos-core/protos/rust/src/pb/aptos.util.timestamp.serde.rs',
    'aptos-core/protos/rust/src/pb/mod.rs',
    'aptos-core/sdk/examples/transfer-coin.rs',
    'aptos-core/sdk/src/coin_client.rs',
    'aptos-core/sdk/src/lib.rs',
    'aptos-core/sdk/src/transaction_builder.rs',
    'aptos-core/sdk/src/types.rs',
    'aptos-core/secure/net/src/grpc_network_service/mod.rs',
    'aptos-core/secure/net/src/lib.rs',
    'aptos-core/secure/net/src/network_controller/error.rs',
    'aptos-core/secure/net/src/network_controller/inbound_handler.rs',
    'aptos-core/secure/net/src/network_controller/metrics.rs',
    'aptos-core/secure/net/src/network_controller/mod.rs',
    'aptos-core/secure/net/src/network_controller/outbound_handler.rs',
    'aptos-core/secure/storage/src/crypto_kv_storage.rs',
    'aptos-core/secure/storage/src/crypto_storage.rs',
    'aptos-core/secure/storage/src/error.rs',
    'aptos-core/secure/storage/src/in_memory.rs',
    'aptos-core/secure/storage/src/kv_storage.rs',
    'aptos-core/secure/storage/src/lib.rs',
    'aptos-core/secure/storage/src/namespaced.rs',
    'aptos-core/secure/storage/src/on_disk.rs',
    'aptos-core/secure/storage/src/policy.rs',
    'aptos-core/secure/storage/src/storage.rs',
    'aptos-core/secure/storage/src/vault.rs',
    'aptos-core/secure/storage/vault/src/dev.rs',
    'aptos-core/secure/storage/vault/src/fuzzing.rs',
    'aptos-core/secure/storage/vault/src/lib.rs',
    'aptos-core/state-sync/aptos-data-client/src/client.rs',
    'aptos-core/state-sync/aptos-data-client/src/error.rs',
    'aptos-core/state-sync/aptos-data-client/src/global_summary.rs',
    'aptos-core/state-sync/aptos-data-client/src/interface.rs',
    'aptos-core/state-sync/aptos-data-client/src/latency_monitor.rs',
    'aptos-core/state-sync/aptos-data-client/src/lib.rs',
    'aptos-core/state-sync/aptos-data-client/src/logging.rs',
    'aptos-core/state-sync/aptos-data-client/src/metrics.rs',
    'aptos-core/state-sync/aptos-data-client/src/peer_states.rs',
    'aptos-core/state-sync/aptos-data-client/src/poller.rs',
    'aptos-core/state-sync/aptos-data-client/src/priority.rs',
    'aptos-core/state-sync/aptos-data-client/src/utils.rs',
    'aptos-core/state-sync/data-streaming-service/src/data_notification.rs',
    'aptos-core/state-sync/data-streaming-service/src/data_stream.rs',
    'aptos-core/state-sync/data-streaming-service/src/dynamic_prefetching.rs',
    'aptos-core/state-sync/data-streaming-service/src/error.rs',
    'aptos-core/state-sync/data-streaming-service/src/lib.rs',
    'aptos-core/state-sync/data-streaming-service/src/logging.rs',
    'aptos-core/state-sync/data-streaming-service/src/metrics.rs',
    'aptos-core/state-sync/data-streaming-service/src/stream_engine.rs',
    'aptos-core/state-sync/data-streaming-service/src/streaming_client.rs',
    'aptos-core/state-sync/data-streaming-service/src/streaming_service.rs',
    'aptos-core/state-sync/inter-component/consensus-notifications/src/lib.rs',
    'aptos-core/state-sync/inter-component/event-notifications/src/lib.rs',
    'aptos-core/state-sync/inter-component/mempool-notifications/src/lib.rs',
    'aptos-core/state-sync/inter-component/storage-service-notifications/src/lib.rs',
    'aptos-core/state-sync/state-sync-driver/src/bootstrapper.rs',
    'aptos-core/state-sync/state-sync-driver/src/continuous_syncer.rs',
    'aptos-core/state-sync/state-sync-driver/src/driver.rs',
    'aptos-core/state-sync/state-sync-driver/src/driver_client.rs',
    'aptos-core/state-sync/state-sync-driver/src/driver_factory.rs',
    'aptos-core/state-sync/state-sync-driver/src/error.rs',
    'aptos-core/state-sync/state-sync-driver/src/lib.rs',
    'aptos-core/state-sync/state-sync-driver/src/logging.rs',
    'aptos-core/state-sync/state-sync-driver/src/metadata_storage.rs',
    'aptos-core/state-sync/state-sync-driver/src/metrics.rs',
    'aptos-core/state-sync/state-sync-driver/src/notification_handlers.rs',
    'aptos-core/state-sync/state-sync-driver/src/storage_synchronizer.rs',
    'aptos-core/state-sync/state-sync-driver/src/utils.rs',
    'aptos-core/state-sync/storage-service/client/src/lib.rs',
    'aptos-core/state-sync/storage-service/server/src/error.rs',
    'aptos-core/state-sync/storage-service/server/src/handler.rs',
    'aptos-core/state-sync/storage-service/server/src/lib.rs',
    'aptos-core/state-sync/storage-service/server/src/logging.rs',
    'aptos-core/state-sync/storage-service/server/src/metrics.rs',
    'aptos-core/state-sync/storage-service/server/src/moderator.rs',
    'aptos-core/state-sync/storage-service/server/src/network.rs',
    'aptos-core/state-sync/storage-service/server/src/optimistic_fetch.rs',
    'aptos-core/state-sync/storage-service/server/src/storage.rs',
    'aptos-core/state-sync/storage-service/server/src/subscription.rs',
    'aptos-core/state-sync/storage-service/server/src/utils.rs',
    'aptos-core/state-sync/storage-service/types/src/lib.rs',
    'aptos-core/state-sync/storage-service/types/src/requests.rs',
    'aptos-core/state-sync/storage-service/types/src/responses.rs',
    'aptos-core/storage/accumulator/src/lib.rs',
    'aptos-core/storage/aptosdb/src/backup/backup_handler.rs',
    'aptos-core/storage/aptosdb/src/backup/mod.rs',
    'aptos-core/storage/aptosdb/src/backup/restore_handler.rs',
    'aptos-core/storage/aptosdb/src/backup/restore_utils.rs',
    'aptos-core/storage/aptosdb/src/common.rs',
    'aptos-core/storage/aptosdb/src/db/aptosdb_internal.rs',
    'aptos-core/storage/aptosdb/src/db/aptosdb_reader.rs',
    'aptos-core/storage/aptosdb/src/db/aptosdb_testonly.rs',
    'aptos-core/storage/aptosdb/src/db/aptosdb_writer.rs',
    'aptos-core/storage/aptosdb/src/db/fake_aptosdb.rs',
    'aptos-core/storage/aptosdb/src/db/mod.rs',
    'aptos-core/storage/aptosdb/src/db_debugger/checkpoint/mod.rs',
    'aptos-core/storage/aptosdb/src/db_debugger/common/mod.rs',
    'aptos-core/storage/aptosdb/src/db_debugger/examine/mod.rs',
    'aptos-core/storage/aptosdb/src/db_debugger/examine/print_db_versions.rs',
    'aptos-core/storage/aptosdb/src/db_debugger/examine/print_raw_data_by_version.rs',
    'aptos-core/storage/aptosdb/src/db_debugger/ledger/check_range_proof.rs',
    'aptos-core/storage/aptosdb/src/db_debugger/ledger/check_txn_info_hashes.rs',
    'aptos-core/storage/aptosdb/src/db_debugger/ledger/mod.rs',
    'aptos-core/storage/aptosdb/src/db_debugger/mod.rs',
    'aptos-core/storage/aptosdb/src/db_debugger/state_kv/get_value.rs',
    'aptos-core/storage/aptosdb/src/db_debugger/state_kv/mod.rs',
    'aptos-core/storage/aptosdb/src/db_debugger/state_kv/scan_snapshot.rs',
    'aptos-core/storage/aptosdb/src/db_debugger/state_tree/get_leaf.rs',
    'aptos-core/storage/aptosdb/src/db_debugger/state_tree/get_path.rs',
    'aptos-core/storage/aptosdb/src/db_debugger/state_tree/get_snapshots.rs',
    'aptos-core/storage/aptosdb/src/db_debugger/state_tree/mod.rs',
    'aptos-core/storage/aptosdb/src/db_debugger/truncate/mod.rs',
    'aptos-core/storage/aptosdb/src/db_debugger/validation.rs',
    'aptos-core/storage/aptosdb/src/db_debugger/watch/mod.rs',
    'aptos-core/storage/aptosdb/src/db_debugger/watch/opened.rs',
    'aptos-core/storage/aptosdb/src/db_options.rs',
    'aptos-core/storage/aptosdb/src/event_store/mod.rs',
    'aptos-core/storage/aptosdb/src/fast_sync_storage_wrapper.rs',
    'aptos-core/storage/aptosdb/src/get_restore_handler.rs',
    'aptos-core/storage/aptosdb/src/ledger_counters/mod.rs',
    'aptos-core/storage/aptosdb/src/ledger_db/event_db.rs',
    'aptos-core/storage/aptosdb/src/ledger_db/ledger_metadata_db.rs',
    'aptos-core/storage/aptosdb/src/ledger_db/mod.rs',
    'aptos-core/storage/aptosdb/src/ledger_db/persisted_auxiliary_info_db.rs',
    'aptos-core/storage/aptosdb/src/ledger_db/transaction_accumulator_db.rs',
    'aptos-core/storage/aptosdb/src/ledger_db/transaction_auxiliary_data_db.rs',
    'aptos-core/storage/aptosdb/src/ledger_db/transaction_db.rs',
    'aptos-core/storage/aptosdb/src/ledger_db/transaction_info_db.rs',
    'aptos-core/storage/aptosdb/src/ledger_db/write_set_db.rs',
    'aptos-core/storage/aptosdb/src/lib.rs',
    'aptos-core/storage/aptosdb/src/lru_node_cache.rs',
    'aptos-core/storage/aptosdb/src/metrics.rs',
    'aptos-core/storage/aptosdb/src/pruner/db_pruner.rs',
    'aptos-core/storage/aptosdb/src/pruner/db_sub_pruner.rs',
    'aptos-core/storage/aptosdb/src/pruner/ledger_pruner/event_store_pruner.rs',
    'aptos-core/storage/aptosdb/src/pruner/ledger_pruner/ledger_metadata_pruner.rs',
    'aptos-core/storage/aptosdb/src/pruner/ledger_pruner/ledger_pruner_manager.rs',
    'aptos-core/storage/aptosdb/src/pruner/ledger_pruner/mod.rs',
    'aptos-core/storage/aptosdb/src/pruner/ledger_pruner/persisted_auxiliary_info_pruner.rs',
    'aptos-core/storage/aptosdb/src/pruner/ledger_pruner/transaction_accumulator_pruner.rs',
    'aptos-core/storage/aptosdb/src/pruner/ledger_pruner/transaction_auxiliary_data_pruner.rs',
    'aptos-core/storage/aptosdb/src/pruner/ledger_pruner/transaction_info_pruner.rs',
    'aptos-core/storage/aptosdb/src/pruner/ledger_pruner/transaction_pruner.rs',
    'aptos-core/storage/aptosdb/src/pruner/ledger_pruner/write_set_pruner.rs',
    'aptos-core/storage/aptosdb/src/pruner/mod.rs',
    'aptos-core/storage/aptosdb/src/pruner/pruner_manager.rs',
    'aptos-core/storage/aptosdb/src/pruner/pruner_utils.rs',
    'aptos-core/storage/aptosdb/src/pruner/pruner_worker.rs',
    'aptos-core/storage/aptosdb/src/pruner/state_kv_pruner/mod.rs',
    'aptos-core/storage/aptosdb/src/pruner/state_kv_pruner/state_kv_metadata_pruner.rs',
    'aptos-core/storage/aptosdb/src/pruner/state_kv_pruner/state_kv_pruner_manager.rs',
    'aptos-core/storage/aptosdb/src/pruner/state_kv_pruner/state_kv_shard_pruner.rs',
    'aptos-core/storage/aptosdb/src/pruner/state_merkle_pruner/generics.rs',
    'aptos-core/storage/aptosdb/src/pruner/state_merkle_pruner/mod.rs',
    'aptos-core/storage/aptosdb/src/pruner/state_merkle_pruner/state_merkle_metadata_pruner.rs',
    'aptos-core/storage/aptosdb/src/pruner/state_merkle_pruner/state_merkle_pruner_manager.rs',
    'aptos-core/storage/aptosdb/src/pruner/state_merkle_pruner/state_merkle_shard_pruner.rs',
    'aptos-core/storage/aptosdb/src/rocksdb_property_reporter.rs',
    'aptos-core/storage/aptosdb/src/schema/block_by_version/mod.rs',
    'aptos-core/storage/aptosdb/src/schema/block_info/mod.rs',
    'aptos-core/storage/aptosdb/src/schema/db_metadata/mod.rs',
    'aptos-core/storage/aptosdb/src/schema/epoch_by_version/mod.rs',
    'aptos-core/storage/aptosdb/src/schema/event/mod.rs',
    'aptos-core/storage/aptosdb/src/schema/event_accumulator/mod.rs',
    'aptos-core/storage/aptosdb/src/schema/hot_state_value_by_key_hash/mod.rs',
    'aptos-core/storage/aptosdb/src/schema/jellyfish_merkle_node/mod.rs',
    'aptos-core/storage/aptosdb/src/schema/ledger_info/mod.rs',
    'aptos-core/storage/aptosdb/src/schema/mod.rs',
    'aptos-core/storage/aptosdb/src/schema/persisted_auxiliary_info/mod.rs',
    'aptos-core/storage/aptosdb/src/schema/stale_node_index/mod.rs',
    'aptos-core/storage/aptosdb/src/schema/stale_node_index_cross_epoch/mod.rs',
    'aptos-core/storage/aptosdb/src/schema/stale_state_value_index/mod.rs',
    'aptos-core/storage/aptosdb/src/schema/stale_state_value_index_by_key_hash/mod.rs',
    'aptos-core/storage/aptosdb/src/schema/state_value/mod.rs',
    'aptos-core/storage/aptosdb/src/schema/state_value_by_key_hash/mod.rs',
    'aptos-core/storage/aptosdb/src/schema/transaction/mod.rs',
    'aptos-core/storage/aptosdb/src/schema/transaction_accumulator/mod.rs',
    'aptos-core/storage/aptosdb/src/schema/transaction_accumulator_root_hash/mod.rs',
    'aptos-core/storage/aptosdb/src/schema/transaction_auxiliary_data/mod.rs',
    'aptos-core/storage/aptosdb/src/schema/transaction_by_hash/mod.rs',
    'aptos-core/storage/aptosdb/src/schema/transaction_info/mod.rs',
    'aptos-core/storage/aptosdb/src/schema/transaction_summaries_by_account/mod.rs',
    'aptos-core/storage/aptosdb/src/schema/version_data/mod.rs',
    'aptos-core/storage/aptosdb/src/schema/write_set/mod.rs',
    'aptos-core/storage/aptosdb/src/state_kv_db.rs',
    'aptos-core/storage/aptosdb/src/state_merkle_db.rs',
    'aptos-core/storage/aptosdb/src/state_restore/mod.rs',
    'aptos-core/storage/aptosdb/src/state_store/buffered_state.rs',
    'aptos-core/storage/aptosdb/src/state_store/hot_state.rs',
    'aptos-core/storage/aptosdb/src/state_store/mod.rs',
    'aptos-core/storage/aptosdb/src/state_store/persisted_state.rs',
    'aptos-core/storage/aptosdb/src/state_store/state_merkle_batch_committer.rs',
    'aptos-core/storage/aptosdb/src/state_store/state_snapshot_committer.rs',
    'aptos-core/storage/aptosdb/src/transaction_store/mod.rs',
    'aptos-core/storage/aptosdb/src/utils/iterators.rs',
    'aptos-core/storage/aptosdb/src/utils/mod.rs',
    'aptos-core/storage/aptosdb/src/utils/truncation_helper.rs',
    'aptos-core/storage/aptosdb/src/versioned_node_cache.rs',
    'aptos-core/storage/backup/backup-cli/src/backup_types/epoch_ending/backup.rs',
    'aptos-core/storage/backup/backup-cli/src/backup_types/epoch_ending/manifest.rs',
    'aptos-core/storage/backup/backup-cli/src/backup_types/epoch_ending/mod.rs',
    'aptos-core/storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs',
    'aptos-core/storage/backup/backup-cli/src/backup_types/mod.rs',
    'aptos-core/storage/backup/backup-cli/src/backup_types/state_snapshot/backup.rs',
    'aptos-core/storage/backup/backup-cli/src/backup_types/state_snapshot/manifest.rs',
    'aptos-core/storage/backup/backup-cli/src/backup_types/state_snapshot/mod.rs',
    'aptos-core/storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs',
    'aptos-core/storage/backup/backup-cli/src/backup_types/transaction/analysis.rs',
    'aptos-core/storage/backup/backup-cli/src/backup_types/transaction/backup.rs',
    'aptos-core/storage/backup/backup-cli/src/backup_types/transaction/manifest.rs',
    'aptos-core/storage/backup/backup-cli/src/backup_types/transaction/mod.rs',
    'aptos-core/storage/backup/backup-cli/src/backup_types/transaction/restore.rs',
    'aptos-core/storage/backup/backup-cli/src/coordinators/backup.rs',
    'aptos-core/storage/backup/backup-cli/src/coordinators/mod.rs',
    'aptos-core/storage/backup/backup-cli/src/coordinators/replay_verify.rs',
    'aptos-core/storage/backup/backup-cli/src/coordinators/restore.rs',
    'aptos-core/storage/backup/backup-cli/src/coordinators/verify.rs',
    'aptos-core/storage/backup/backup-cli/src/lib.rs',
    'aptos-core/storage/backup/backup-cli/src/metadata/cache.rs',
    'aptos-core/storage/backup/backup-cli/src/metadata/mod.rs',
    'aptos-core/storage/backup/backup-cli/src/metadata/view.rs',
    'aptos-core/storage/backup/backup-cli/src/metrics/backup.rs',
    'aptos-core/storage/backup/backup-cli/src/metrics/metadata.rs',
    'aptos-core/storage/backup/backup-cli/src/metrics/mod.rs',
    'aptos-core/storage/backup/backup-cli/src/metrics/restore.rs',
    'aptos-core/storage/backup/backup-cli/src/metrics/verify.rs',
    'aptos-core/storage/backup/backup-cli/src/storage/command_adapter/command.rs',
    'aptos-core/storage/backup/backup-cli/src/storage/command_adapter/config.rs',
    'aptos-core/storage/backup/backup-cli/src/storage/command_adapter/mod.rs',
    'aptos-core/storage/backup/backup-cli/src/storage/local_fs/mod.rs',
    'aptos-core/storage/backup/backup-cli/src/storage/mod.rs',
    'aptos-core/storage/backup/backup-cli/src/utils/backup_service_client.rs',
    'aptos-core/storage/backup/backup-cli/src/utils/error_notes.rs',
    'aptos-core/storage/backup/backup-cli/src/utils/mod.rs',
    'aptos-core/storage/backup/backup-cli/src/utils/read_record_bytes.rs',
    'aptos-core/storage/backup/backup-cli/src/utils/storage_ext.rs',
    'aptos-core/storage/backup/backup-cli/src/utils/stream/buffered_x.rs',
    'aptos-core/storage/backup/backup-cli/src/utils/stream/futures_ordered_x.rs',
    'aptos-core/storage/backup/backup-cli/src/utils/stream/futures_unordered_x.rs',
    'aptos-core/storage/backup/backup-cli/src/utils/stream/mod.rs',
    'aptos-core/storage/backup/backup-cli/src/utils/stream/try_buffered_x.rs',
    'aptos-core/storage/backup/backup-service/src/handlers/bytes_sender.rs',
    'aptos-core/storage/backup/backup-service/src/handlers/mod.rs',
    'aptos-core/storage/backup/backup-service/src/handlers/utils.rs',
    'aptos-core/storage/backup/backup-service/src/lib.rs',
    'aptos-core/storage/db-tool/src/backup.rs',
    'aptos-core/storage/db-tool/src/backup_maintenance.rs',
    'aptos-core/storage/db-tool/src/bootstrap.rs',
    'aptos-core/storage/db-tool/src/gen_replay_verify_jobs.rs',
    'aptos-core/storage/db-tool/src/lib.rs',
    'aptos-core/storage/db-tool/src/replay_on_archive.rs',
    'aptos-core/storage/db-tool/src/replay_verify.rs',
    'aptos-core/storage/db-tool/src/restore.rs',
    'aptos-core/storage/db-tool/src/utils.rs',
    'aptos-core/storage/indexer/src/db.rs',
    'aptos-core/storage/indexer/src/db_indexer.rs',
    'aptos-core/storage/indexer/src/db_ops.rs',
    'aptos-core/storage/indexer/src/db_v2.rs',
    'aptos-core/storage/indexer/src/event_v2_translator.rs',
    'aptos-core/storage/indexer/src/indexer_reader.rs',
    'aptos-core/storage/indexer/src/lib.rs',
    'aptos-core/storage/indexer/src/metrics.rs',
    'aptos-core/storage/indexer/src/utils.rs',
    'aptos-core/storage/indexer_schemas/src/lib.rs',
    'aptos-core/storage/indexer_schemas/src/metadata.rs',
    'aptos-core/storage/indexer_schemas/src/schema/event_by_key/mod.rs',
    'aptos-core/storage/indexer_schemas/src/schema/event_by_version/mod.rs',
    'aptos-core/storage/indexer_schemas/src/schema/event_sequence_number/mod.rs',
    'aptos-core/storage/indexer_schemas/src/schema/indexer_metadata/mod.rs',
    'aptos-core/storage/indexer_schemas/src/schema/mod.rs',
    'aptos-core/storage/indexer_schemas/src/schema/ordered_transaction_by_account/mod.rs',
    'aptos-core/storage/indexer_schemas/src/schema/state_keys/mod.rs',
    'aptos-core/storage/indexer_schemas/src/schema/table_info/mod.rs',
    'aptos-core/storage/indexer_schemas/src/schema/translated_v1_event/mod.rs',
    'aptos-core/storage/indexer_schemas/src/utils.rs',
    'aptos-core/storage/jellyfish-merkle/src/iterator/mod.rs',
    'aptos-core/storage/jellyfish-merkle/src/lib.rs',
    'aptos-core/storage/jellyfish-merkle/src/metrics.rs',
    'aptos-core/storage/jellyfish-merkle/src/mock_tree_store.rs',
    'aptos-core/storage/jellyfish-merkle/src/node_type/mod.rs',
    'aptos-core/storage/jellyfish-merkle/src/restore/mod.rs',
    'aptos-core/storage/rocksdb-options/src/lib.rs',
    'aptos-core/storage/schemadb/src/batch.rs',
    'aptos-core/storage/schemadb/src/iterator.rs',
    'aptos-core/storage/schemadb/src/lib.rs',
    'aptos-core/storage/schemadb/src/metrics.rs',
    'aptos-core/storage/schemadb/src/schema.rs',
    'aptos-core/storage/scratchpad/benches/sparse_merkle.rs',
    'aptos-core/storage/scratchpad/src/lib.rs',
    'aptos-core/storage/scratchpad/src/sparse_merkle/dropper.rs',
    'aptos-core/storage/scratchpad/src/sparse_merkle/metrics.rs',
    'aptos-core/storage/scratchpad/src/sparse_merkle/mod.rs',
    'aptos-core/storage/scratchpad/src/sparse_merkle/node.rs',
    'aptos-core/storage/scratchpad/src/sparse_merkle/updater.rs',
    'aptos-core/storage/scratchpad/src/sparse_merkle/utils.rs',
    'aptos-core/storage/storage-interface/src/block_info.rs',
    'aptos-core/storage/storage-interface/src/chunk_to_commit.rs',
    'aptos-core/storage/storage-interface/src/errors.rs',
    'aptos-core/storage/storage-interface/src/ledger_summary.rs',
    'aptos-core/storage/storage-interface/src/lib.rs',
    'aptos-core/storage/storage-interface/src/metrics.rs',
    'aptos-core/storage/storage-interface/src/mock.rs',
    'aptos-core/storage/storage-interface/src/state_store/hot_state.rs',
    'aptos-core/storage/storage-interface/src/state_store/mod.rs',
    'aptos-core/storage/storage-interface/src/state_store/state.rs',
    'aptos-core/storage/storage-interface/src/state_store/state_delta.rs',
    'aptos-core/storage/storage-interface/src/state_store/state_summary.rs',
    'aptos-core/storage/storage-interface/src/state_store/state_update_refs.rs',
    'aptos-core/storage/storage-interface/src/state_store/state_view/cached_state_view.rs',
    'aptos-core/storage/storage-interface/src/state_store/state_view/db_state_view.rs',
    'aptos-core/storage/storage-interface/src/state_store/state_view/hot_state_view.rs',
    'aptos-core/storage/storage-interface/src/state_store/state_view/mod.rs',
    'aptos-core/storage/storage-interface/src/state_store/state_with_summary.rs',
    'aptos-core/storage/storage-interface/src/state_store/versioned_state_value.rs',
    'aptos-core/third_party/move/extensions/move-table-extension/src/lib.rs',
    'aptos-core/third_party/move/move-binary-format/serializer-tests/src/lib.rs',
    'aptos-core/third_party/move/move-binary-format/src/access.rs',
    'aptos-core/third_party/move/move-binary-format/src/binary_views.rs',
    'aptos-core/third_party/move/move-binary-format/src/builders.rs',
    'aptos-core/third_party/move/move-binary-format/src/check_bounds.rs',
    'aptos-core/third_party/move/move-binary-format/src/check_complexity.rs',
    'aptos-core/third_party/move/move-binary-format/src/compatibility.rs',
    'aptos-core/third_party/move/move-binary-format/src/constant.rs',
    'aptos-core/third_party/move/move-binary-format/src/control_flow_graph.rs',
    'aptos-core/third_party/move/move-binary-format/src/deserializer.rs',
    'aptos-core/third_party/move/move-binary-format/src/errors.rs',
    'aptos-core/third_party/move/move-binary-format/src/file_format.rs',
    'aptos-core/third_party/move/move-binary-format/src/file_format_common.rs',
    'aptos-core/third_party/move/move-binary-format/src/internals.rs',
    'aptos-core/third_party/move/move-binary-format/src/lib.rs',
    'aptos-core/third_party/move/move-binary-format/src/module_script_conversion.rs',
    'aptos-core/third_party/move/move-binary-format/src/proptest_types.rs',
    'aptos-core/third_party/move/move-binary-format/src/proptest_types/constants.rs',
    'aptos-core/third_party/move/move-binary-format/src/proptest_types/functions.rs',
    'aptos-core/third_party/move/move-binary-format/src/proptest_types/metadata.rs',
    'aptos-core/third_party/move/move-binary-format/src/proptest_types/signature.rs',
    'aptos-core/third_party/move/move-binary-format/src/proptest_types/types.rs',
    'aptos-core/third_party/move/move-binary-format/src/serializer.rs',
    'aptos-core/third_party/move/move-binary-format/src/unit_tests/binary_tests.rs',
    'aptos-core/third_party/move/move-binary-format/src/unit_tests/compatibility_tests.rs',
    'aptos-core/third_party/move/move-binary-format/src/unit_tests/control_flow_graph_tests.rs',
    'aptos-core/third_party/move/move-binary-format/src/unit_tests/deserializer_tests.rs',
    'aptos-core/third_party/move/move-binary-format/src/unit_tests/mod.rs',
    'aptos-core/third_party/move/move-binary-format/src/unit_tests/number_tests.rs',
    'aptos-core/third_party/move/move-binary-format/src/unit_tests/signature_token_tests.rs',
    'aptos-core/third_party/move/move-binary-format/src/views.rs',
    'aptos-core/third_party/move/move-borrow-graph/src/graph.rs',
    'aptos-core/third_party/move/move-borrow-graph/src/lib.rs',
    'aptos-core/third_party/move/move-borrow-graph/src/paths.rs',
    'aptos-core/third_party/move/move-borrow-graph/src/references.rs',
    'aptos-core/third_party/move/move-borrow-graph/src/shared.rs',
    'aptos-core/third_party/move/move-bytecode-spec/src/lib.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/bytecode-verifier-tests/src/lib.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/bytecode-verifier-tests/src/support/mod.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/bytecode-verifier-tests/src/unit_tests/binary_samples.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/bytecode-verifier-tests/src/unit_tests/bounds_tests.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/bytecode-verifier-tests/src/unit_tests/catch_unwind.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/bytecode-verifier-tests/src/unit_tests/code_unit_tests.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/bytecode-verifier-tests/src/unit_tests/constants_tests.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/bytecode-verifier-tests/src/unit_tests/control_flow_tests.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/bytecode-verifier-tests/src/unit_tests/dependencies_tests.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/bytecode-verifier-tests/src/unit_tests/duplication_tests.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/bytecode-verifier-tests/src/unit_tests/generic_ops_tests.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/bytecode-verifier-tests/src/unit_tests/limit_tests.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/bytecode-verifier-tests/src/unit_tests/locals.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/bytecode-verifier-tests/src/unit_tests/loop_summary_tests.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/bytecode-verifier-tests/src/unit_tests/many_back_edges.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/bytecode-verifier-tests/src/unit_tests/mod.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/bytecode-verifier-tests/src/unit_tests/multi_pass_tests.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/bytecode-verifier-tests/src/unit_tests/negative_stack_size_tests.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/bytecode-verifier-tests/src/unit_tests/reference_safety_tests.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/bytecode-verifier-tests/src/unit_tests/signature_tests.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/bytecode-verifier-tests/src/unit_tests/struct_defs_tests.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/bytecode-verifier-tests/src/unit_tests/vec_pack_tests.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/invalid-mutations/src/bounds.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/invalid-mutations/src/bounds/code_unit.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/invalid-mutations/src/helpers.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/invalid-mutations/src/lib.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/invalid-mutations/src/signature.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/src/absint.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/src/acquires_list_verifier.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/src/check_duplication.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/src/code_unit_verifier.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/src/constants.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/src/control_flow.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/src/control_flow_v5.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/src/cyclic_dependencies.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/src/dependencies.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/src/features.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/src/friends.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/src/instantiation_loops.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/src/instruction_consistency.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/src/lib.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/src/limits.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/src/locals_safety/abstract_state.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/src/locals_safety/mod.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/src/loop_summary.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/src/meter.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/src/reference_safety/abstract_state.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/src/reference_safety/mod.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/src/regression_tests/bounds_check.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/src/regression_tests/mod.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/src/regression_tests/reference_analysis.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/src/script_signature.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/src/signature_v2.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/src/stack_usage_verifier.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/src/struct_defs.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/src/type_safety.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/src/verifier.rs',
    'aptos-core/third_party/move/move-bytecode-verifier/transactional-tests/src/lib.rs',
    'aptos-core/third_party/move/move-command-line-common/src/address.rs',
    'aptos-core/third_party/move/move-command-line-common/src/character_sets.rs',
    'aptos-core/third_party/move/move-command-line-common/src/env.rs',
    'aptos-core/third_party/move/move-command-line-common/src/files.rs',
    'aptos-core/third_party/move/move-command-line-common/src/lib.rs',
    'aptos-core/third_party/move/move-command-line-common/src/movey_constants.rs',
    'aptos-core/third_party/move/move-command-line-common/src/parser.rs',
    'aptos-core/third_party/move/move-command-line-common/src/testing.rs',
    'aptos-core/third_party/move/move-command-line-common/src/types.rs',
    'aptos-core/third_party/move/move-command-line-common/src/values.rs',
    'aptos-core/third_party/move/move-compiler-v2/legacy-move-compiler/src/command_line/compiler.rs',
    'aptos-core/third_party/move/move-compiler-v2/legacy-move-compiler/src/command_line/mod.rs',
    'aptos-core/third_party/move/move-compiler-v2/legacy-move-compiler/src/compiled_unit.rs',
    'aptos-core/third_party/move/move-compiler-v2/legacy-move-compiler/src/diagnostics/codes.rs',
    'aptos-core/third_party/move/move-compiler-v2/legacy-move-compiler/src/diagnostics/mod.rs',
    'aptos-core/third_party/move/move-compiler-v2/legacy-move-compiler/src/expansion/aliases.rs',
    'aptos-core/third_party/move/move-compiler-v2/legacy-move-compiler/src/expansion/ast.rs',
    'aptos-core/third_party/move/move-compiler-v2/legacy-move-compiler/src/expansion/byte_string.rs',
    'aptos-core/third_party/move/move-compiler-v2/legacy-move-compiler/src/expansion/dependency_ordering.rs',
    'aptos-core/third_party/move/move-compiler-v2/legacy-move-compiler/src/expansion/hex_string.rs',
    'aptos-core/third_party/move/move-compiler-v2/legacy-move-compiler/src/expansion/mod.rs',
    'aptos-core/third_party/move/move-compiler-v2/legacy-move-compiler/src/expansion/translate.rs',
    'aptos-core/third_party/move/move-compiler-v2/legacy-move-compiler/src/interface_generator.rs',
    'aptos-core/third_party/move/move-compiler-v2/legacy-move-compiler/src/ir_translation.rs',
    'aptos-core/third_party/move/move-compiler-v2/legacy-move-compiler/src/lib.rs',
    'aptos-core/third_party/move/move-compiler-v2/legacy-move-compiler/src/parser/ast.rs',
    'aptos-core/third_party/move/move-compiler-v2/legacy-move-compiler/src/parser/comments.rs',
    'aptos-core/third_party/move/move-compiler-v2/legacy-move-compiler/src/parser/filter.rs',
    'aptos-core/third_party/move/move-compiler-v2/legacy-move-compiler/src/parser/keywords.rs',
    'aptos-core/third_party/move/move-compiler-v2/legacy-move-compiler/src/parser/lexer.rs',
    'aptos-core/third_party/move/move-compiler-v2/legacy-move-compiler/src/parser/merge_spec_modules.rs',
    'aptos-core/third_party/move/move-compiler-v2/legacy-move-compiler/src/parser/mod.rs',
    'aptos-core/third_party/move/move-compiler-v2/legacy-move-compiler/src/parser/syntax.rs',
    'aptos-core/third_party/move/move-compiler-v2/legacy-move-compiler/src/shared/ast_debug.rs',
    'aptos-core/third_party/move/move-compiler-v2/legacy-move-compiler/src/shared/builtins.rs',
    'aptos-core/third_party/move/move-compiler-v2/legacy-move-compiler/src/shared/mod.rs',
    'aptos-core/third_party/move/move-compiler-v2/legacy-move-compiler/src/shared/remembering_unique_map.rs',
    'aptos-core/third_party/move/move-compiler-v2/legacy-move-compiler/src/shared/unique_map.rs',
    'aptos-core/third_party/move/move-compiler-v2/legacy-move-compiler/src/shared/unique_set.rs',
    'aptos-core/third_party/move/move-compiler-v2/legacy-move-compiler/src/unit_test/filter_test_members.rs',
    'aptos-core/third_party/move/move-compiler-v2/legacy-move-compiler/src/unit_test/mod.rs',
    'aptos-core/third_party/move/move-compiler-v2/legacy-move-compiler/src/verification/ast_filter.rs',
    'aptos-core/third_party/move/move-compiler-v2/legacy-move-compiler/src/verification/mod.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/bytecode_generator.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/diagnostics/human.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/diagnostics/json.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/diagnostics/mod.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/env_pipeline/acquires_checker.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/env_pipeline/ast_simplifier.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/env_pipeline/closure_checker.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/env_pipeline/cmp_rewriter.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/env_pipeline/cyclic_instantiation_checker.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/env_pipeline/flow_insensitive_checkers.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/env_pipeline/function_checker.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/env_pipeline/inliner.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/env_pipeline/inlining_optimization.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/env_pipeline/lambda_lifter.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/env_pipeline/mod.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/env_pipeline/model_ast_lints.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/env_pipeline/recursive_struct_checker.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/env_pipeline/rewrite_target.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/env_pipeline/seqs_in_binop_checker.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/env_pipeline/spec_checker.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/env_pipeline/spec_rewriter.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/env_pipeline/unused_params_checker.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/experiments.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/external_checks.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/file_format_generator/function_generator.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/file_format_generator/mod.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/file_format_generator/module_generator.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/file_format_generator/peephole_optimizer.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/file_format_generator/peephole_optimizer/inefficient_loads.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/file_format_generator/peephole_optimizer/optimizers.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/file_format_generator/peephole_optimizer/reducible_pairs.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/lib.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/lint_common.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/logging.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/options.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/pipeline/ability_processor.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/pipeline/control_flow_graph_simplifier.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/pipeline/dead_store_elimination.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/pipeline/exit_state_analysis.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/pipeline/flush_writes_processor.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/pipeline/lint_processor.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/pipeline/livevar_analysis_processor.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/pipeline/mod.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/pipeline/reference_safety/mod.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/pipeline/reference_safety/reference_safety_processor_v2.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/pipeline/reference_safety/reference_safety_processor_v3.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/pipeline/split_critical_edges_processor.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/pipeline/uninitialized_use_checker.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/pipeline/unreachable_code_analysis.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/pipeline/unreachable_code_remover.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/pipeline/unused_assignment_checker.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/pipeline/variable_coalescing.rs',
    'aptos-core/third_party/move/move-compiler-v2/src/plan_builder.rs',
    'aptos-core/third_party/move/move-compiler-v2/transactional-tests/src/lib.rs',
    'aptos-core/third_party/move/move-core/types/src/abi.rs',
    'aptos-core/third_party/move/move-core/types/src/ability.rs',
    'aptos-core/third_party/move/move-core/types/src/account_address.rs',
    'aptos-core/third_party/move/move-core/types/src/effects.rs',
    'aptos-core/third_party/move/move-core/types/src/errmap.rs',
    'aptos-core/third_party/move/move-core/types/src/function.rs',
    'aptos-core/third_party/move/move-core/types/src/gas_algebra.rs',
    'aptos-core/third_party/move/move-core/types/src/identifier.rs',
    'aptos-core/third_party/move/move-core/types/src/int256.rs',
    'aptos-core/third_party/move/move-core/types/src/language_storage.rs',
    'aptos-core/third_party/move/move-core/types/src/lib.rs',
    'aptos-core/third_party/move/move-core/types/src/metadata.rs',
    'aptos-core/third_party/move/move-core/types/src/move_resource.rs',
    'aptos-core/third_party/move/move-core/types/src/parser.rs',
    'aptos-core/third_party/move/move-core/types/src/proptest_types.rs',
    'aptos-core/third_party/move/move-core/types/src/safe_serialize.rs',
    'aptos-core/third_party/move/move-core/types/src/state.rs',
    'aptos-core/third_party/move/move-core/types/src/transaction_argument.rs',
    'aptos-core/third_party/move/move-core/types/src/unit_tests/mod.rs',
    'aptos-core/third_party/move/move-core/types/src/value.rs',
    'aptos-core/third_party/move/move-core/types/src/vm_status.rs',
    'aptos-core/third_party/move/move-examples/diem-framework/crates/cli/src/main.rs',
    'aptos-core/third_party/move/move-examples/diem-framework/crates/crypto-derive/src/hasher.rs',
    'aptos-core/third_party/move/move-examples/diem-framework/crates/crypto-derive/src/lib.rs',
    'aptos-core/third_party/move/move-examples/diem-framework/crates/crypto-derive/src/unions.rs',
    'aptos-core/third_party/move/move-examples/diem-framework/crates/crypto/benches/ed25519.rs',
    'aptos-core/third_party/move/move-examples/diem-framework/crates/crypto/benches/noise.rs',
    'aptos-core/third_party/move/move-examples/diem-framework/crates/crypto/src/compat.rs',
    'aptos-core/third_party/move/move-examples/diem-framework/crates/crypto/src/ed25519.rs',
    'aptos-core/third_party/move/move-examples/diem-framework/crates/crypto/src/error.rs',
    'aptos-core/third_party/move/move-examples/diem-framework/crates/crypto/src/hash.rs',
    'aptos-core/third_party/move/move-examples/diem-framework/crates/crypto/src/hkdf.rs',
    'aptos-core/third_party/move/move-examples/diem-framework/crates/crypto/src/lib.rs',
    'aptos-core/third_party/move/move-examples/diem-framework/crates/crypto/src/multi_ed25519.rs',
    'aptos-core/third_party/move/move-examples/diem-framework/crates/crypto/src/noise.rs',
    'aptos-core/third_party/move/move-examples/diem-framework/crates/crypto/src/tags.rs',
    'aptos-core/third_party/move/move-examples/diem-framework/crates/crypto/src/traits.rs',
    'aptos-core/third_party/move/move-examples/diem-framework/crates/crypto/src/unit_tests/compilation/cross_test_trait_obj.rs',
    'aptos-core/third_party/move/move-examples/diem-framework/crates/crypto/src/unit_tests/compilation/cross_test_trait_obj_pub.rs',
    'aptos-core/third_party/move/move-examples/diem-framework/crates/crypto/src/unit_tests/compilation/cross_test_trait_obj_sig.rs',
    'aptos-core/third_party/move/move-examples/diem-framework/crates/crypto/src/unit_tests/compilation/small_kdf.rs',
    'aptos-core/third_party/move/move-examples/diem-framework/crates/crypto/src/unit_tests/cryptohasher.rs',
    'aptos-core/third_party/move/move-examples/diem-framework/crates/crypto/src/unit_tests/mod.rs',
    'aptos-core/third_party/move/move-examples/diem-framework/crates/crypto/src/validatable.rs',
    'aptos-core/third_party/move/move-examples/diem-framework/crates/crypto/src/x25519.rs',
    'aptos-core/third_party/move/move-examples/diem-framework/crates/natives/src/account.rs',
    'aptos-core/third_party/move/move-examples/diem-framework/crates/natives/src/lib.rs',
    'aptos-core/third_party/move/move-examples/diem-framework/crates/natives/src/signature.rs',
    'aptos-core/third_party/move/move-examples/src/lib.rs',
    'aptos-core/third_party/move/move-ir-compiler/move-bytecode-source-map/src/lib.rs',
    'aptos-core/third_party/move/move-ir-compiler/move-bytecode-source-map/src/mapping.rs',
    'aptos-core/third_party/move/move-ir-compiler/move-bytecode-source-map/src/marking.rs',
    'aptos-core/third_party/move/move-ir-compiler/move-bytecode-source-map/src/source_map.rs',
    'aptos-core/third_party/move/move-ir-compiler/move-bytecode-source-map/src/utils.rs',
    'aptos-core/third_party/move/move-ir-compiler/move-ir-to-bytecode/src/compiler.rs',
    'aptos-core/third_party/move/move-ir-compiler/move-ir-to-bytecode/src/context.rs',
    'aptos-core/third_party/move/move-ir-compiler/move-ir-to-bytecode/src/lib.rs',
    'aptos-core/third_party/move/move-ir-compiler/move-ir-to-bytecode/src/parser.rs',
    'aptos-core/third_party/move/move-ir-compiler/move-ir-to-bytecode/syntax/src/lexer.rs',
    'aptos-core/third_party/move/move-ir-compiler/move-ir-to-bytecode/syntax/src/lib.rs',
    'aptos-core/third_party/move/move-ir-compiler/move-ir-to-bytecode/syntax/src/syntax.rs',
    'aptos-core/third_party/move/move-ir-compiler/src/lib.rs',
    'aptos-core/third_party/move/move-ir-compiler/src/main.rs',
    'aptos-core/third_party/move/move-ir-compiler/src/unit_tests/cfg_tests.rs',
    'aptos-core/third_party/move/move-ir-compiler/src/unit_tests/function_tests.rs',
    'aptos-core/third_party/move/move-ir-compiler/src/unit_tests/mod.rs',
    'aptos-core/third_party/move/move-ir-compiler/src/unit_tests/testutils.rs',
    'aptos-core/third_party/move/move-ir-compiler/src/util.rs',
    'aptos-core/third_party/move/move-ir/types/src/ast.rs',
    'aptos-core/third_party/move/move-ir/types/src/lib.rs',
    'aptos-core/third_party/move/move-ir/types/src/location.rs',
    'aptos-core/third_party/move/move-ir/types/src/spec_language_ast.rs',
    'aptos-core/third_party/move/move-model/bytecode-test-utils/src/lib.rs',
    'aptos-core/third_party/move/move-model/bytecode/abstract_domain_derive/src/lib.rs',
    'aptos-core/third_party/move/move-model/bytecode/ast-generator-tests/src/lib.rs',
    'aptos-core/third_party/move/move-model/bytecode/src/annotations.rs',
    'aptos-core/third_party/move/move-model/bytecode/src/astifier.rs',
    'aptos-core/third_party/move/move-model/bytecode/src/borrow_analysis.rs',
    'aptos-core/third_party/move/move-model/bytecode/src/compositional_analysis.rs',
    'aptos-core/third_party/move/move-model/bytecode/src/dataflow_analysis.rs',
    'aptos-core/third_party/move/move-model/bytecode/src/dataflow_domains.rs',
    'aptos-core/third_party/move/move-model/bytecode/src/debug_instrumentation.rs',
    'aptos-core/third_party/move/move-model/bytecode/src/fat_loop.rs',
    'aptos-core/third_party/move/move-model/bytecode/src/function_data_builder.rs',
    'aptos-core/third_party/move/move-model/bytecode/src/function_target.rs',
    'aptos-core/third_party/move/move-model/bytecode/src/function_target_pipeline.rs',
    'aptos-core/third_party/move/move-model/bytecode/src/graph.rs',
    'aptos-core/third_party/move/move-model/bytecode/src/lib.rs',
    'aptos-core/third_party/move/move-model/bytecode/src/livevar_analysis.rs',
    'aptos-core/third_party/move/move-model/bytecode/src/reaching_def_analysis.rs',
    'aptos-core/third_party/move/move-model/bytecode/src/stackless_bytecode.rs',
    'aptos-core/third_party/move/move-model/bytecode/src/stackless_bytecode_generator.rs',
    'aptos-core/third_party/move/move-model/bytecode/src/stackless_control_flow_graph.rs',
    'aptos-core/third_party/move/move-model/bytecode/src/usage_analysis.rs',
    'aptos-core/third_party/move/move-model/src/ast.rs',
    'aptos-core/third_party/move/move-model/src/builder/binary_module_loader.rs',
    'aptos-core/third_party/move/move-model/src/builder/builtins.rs',
    'aptos-core/third_party/move/move-model/src/builder/exp_builder.rs',
    'aptos-core/third_party/move/move-model/src/builder/macros.rs',
    'aptos-core/third_party/move/move-model/src/builder/mod.rs',
    'aptos-core/third_party/move/move-model/src/builder/model_builder.rs',
    'aptos-core/third_party/move/move-model/src/builder/module_builder.rs',
    'aptos-core/third_party/move/move-model/src/code_writer.rs',
    'aptos-core/third_party/move/move-model/src/constant_folder.rs',
    'aptos-core/third_party/move/move-model/src/exp_builder.rs',
    'aptos-core/third_party/move/move-model/src/exp_generator.rs',
    'aptos-core/third_party/move/move-model/src/exp_rewriter.rs',
    'aptos-core/third_party/move/move-model/src/intrinsics.rs',
    'aptos-core/third_party/move/move-model/src/lib.rs',
    'aptos-core/third_party/move/move-model/src/metadata.rs',
    'aptos-core/third_party/move/move-model/src/model.rs',
    'aptos-core/third_party/move/move-model/src/options.rs',
    'aptos-core/third_party/move/move-model/src/pragmas.rs',
    'aptos-core/third_party/move/move-model/src/pureness_checker.rs',
    'aptos-core/third_party/move/move-model/src/sourcifier.rs',
    'aptos-core/third_party/move/move-model/src/spec_translator.rs',
    'aptos-core/third_party/move/move-model/src/symbol.rs',
    'aptos-core/third_party/move/move-model/src/ty.rs',
    'aptos-core/third_party/move/move-model/src/ty_invariant_analysis.rs',
    'aptos-core/third_party/move/move-model/src/well_known.rs',
    'aptos-core/third_party/move/move-prover/boogie-backend/src/boogie_helpers.rs',
    'aptos-core/third_party/move/move-prover/boogie-backend/src/boogie_wrapper.rs',
    'aptos-core/third_party/move/move-prover/boogie-backend/src/bytecode_translator.rs',
    'aptos-core/third_party/move/move-prover/boogie-backend/src/lib.rs',
    'aptos-core/third_party/move/move-prover/boogie-backend/src/options.rs',
    'aptos-core/third_party/move/move-prover/boogie-backend/src/prover_task_runner.rs',
    'aptos-core/third_party/move/move-prover/boogie-backend/src/spec_translator.rs',
    'aptos-core/third_party/move/move-prover/bytecode-pipeline/src/clean_and_optimize.rs',
    'aptos-core/third_party/move/move-prover/bytecode-pipeline/src/data_invariant_instrumentation.rs',
    'aptos-core/third_party/move/move-prover/bytecode-pipeline/src/eliminate_imm_refs.rs',
    'aptos-core/third_party/move/move-prover/bytecode-pipeline/src/global_invariant_analysis.rs',
    'aptos-core/third_party/move/move-prover/bytecode-pipeline/src/global_invariant_instrumentation.rs',
    'aptos-core/third_party/move/move-prover/bytecode-pipeline/src/inconsistency_check.rs',
    'aptos-core/third_party/move/move-prover/bytecode-pipeline/src/lib.rs',
    'aptos-core/third_party/move/move-prover/bytecode-pipeline/src/loop_analysis.rs',
    'aptos-core/third_party/move/move-prover/bytecode-pipeline/src/memory_instrumentation.rs',
    'aptos-core/third_party/move/move-prover/bytecode-pipeline/src/mono_analysis.rs',
    'aptos-core/third_party/move/move-prover/bytecode-pipeline/src/mut_ref_instrumentation.rs',
    'aptos-core/third_party/move/move-prover/bytecode-pipeline/src/number_operation.rs',
    'aptos-core/third_party/move/move-prover/bytecode-pipeline/src/number_operation_analysis.rs',
    'aptos-core/third_party/move/move-prover/bytecode-pipeline/src/options.rs',
    'aptos-core/third_party/move/move-prover/bytecode-pipeline/src/pipeline_factory.rs',
    'aptos-core/third_party/move/move-prover/bytecode-pipeline/src/spec_instrumentation.rs',
    'aptos-core/third_party/move/move-prover/bytecode-pipeline/src/verification_analysis.rs',
    'aptos-core/third_party/move/move-prover/bytecode-pipeline/src/well_formed_instrumentation.rs',
    'aptos-core/third_party/move/move-prover/lab/src/benchmark.rs',
    'aptos-core/third_party/move/move-prover/lab/src/lib.rs',
    'aptos-core/third_party/move/move-prover/lab/src/main.rs',
    'aptos-core/third_party/move/move-prover/lab/src/plot.rs',
    'aptos-core/third_party/move/move-prover/lab/src/z3log.rs',
    'aptos-core/third_party/move/move-prover/move-abigen/src/abigen.rs',
    'aptos-core/third_party/move/move-prover/move-abigen/src/lib.rs',
    'aptos-core/third_party/move/move-prover/move-docgen/src/docgen.rs',
    'aptos-core/third_party/move/move-prover/move-docgen/src/lib.rs',
    'aptos-core/third_party/move/move-prover/move-errmapgen/src/errmapgen.rs',
    'aptos-core/third_party/move/move-prover/move-errmapgen/src/lib.rs',
    'aptos-core/third_party/move/move-prover/src/cli.rs',
    'aptos-core/third_party/move/move-prover/src/lib.rs',
    'aptos-core/third_party/move/move-prover/src/main.rs',
    'aptos-core/third_party/move/move-prover/test-utils/src/lib.rs',
    'aptos-core/third_party/move/move-stdlib/src/lib.rs',
    'aptos-core/third_party/move/move-stdlib/src/main.rs',
    'aptos-core/third_party/move/move-stdlib/src/natives/bcs.rs',
    'aptos-core/third_party/move/move-stdlib/src/natives/debug.rs',
    'aptos-core/third_party/move/move-stdlib/src/natives/event.rs',
    'aptos-core/third_party/move/move-stdlib/src/natives/hash.rs',
    'aptos-core/third_party/move/move-stdlib/src/natives/helpers.rs',
    'aptos-core/third_party/move/move-stdlib/src/natives/mod.rs',
    'aptos-core/third_party/move/move-stdlib/src/natives/signer.rs',
    'aptos-core/third_party/move/move-stdlib/src/natives/string.rs',
    'aptos-core/third_party/move/move-stdlib/src/natives/type_name.rs',
    'aptos-core/third_party/move/move-stdlib/src/utils.rs',
    'aptos-core/third_party/move/move-symbol-pool/src/lib.rs',
    'aptos-core/third_party/move/move-symbol-pool/src/pool.rs',
    'aptos-core/third_party/move/move-symbol-pool/src/symbol.rs',
    'aptos-core/third_party/move/move-vm/integration-tests/src/compiler.rs',
    'aptos-core/third_party/move/move-vm/integration-tests/src/lib.rs',
    'aptos-core/third_party/move/move-vm/metrics/src/lib.rs',
    'aptos-core/third_party/move/move-vm/profiler/src/lib.rs',
    'aptos-core/third_party/move/move-vm/profiler/src/probe.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/access_control.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/config.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/data_cache.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/debug.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/execution_tracing/mod.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/execution_tracing/recorders.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/execution_tracing/trace.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/frame.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/frame_type_cache.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/interpreter.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/interpreter_caches.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/lib.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/loader/access_specifier_loader.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/loader/function.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/loader/mod.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/loader/modules.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/loader/script.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/loader/single_signature_loader.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/loader/type_loader.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/logging.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/module_traversal.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/move_vm.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/native_extensions.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/native_functions.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/native_models_for_runtime_ref_checks.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/reentrancy_checker.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/runtime_ref_checks.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/runtime_type_checks.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/runtime_type_checks_async.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/storage/code_storage.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/storage/dependencies_gas_charging.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/storage/environment.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/storage/implementations/mod.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/storage/implementations/unsync_code_storage.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/storage/implementations/unsync_module_storage.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/storage/layout_cache.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/storage/loader/eager.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/storage/loader/lazy.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/storage/loader/mod.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/storage/loader/traits.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/storage/mod.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/storage/module_storage.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/storage/publishing.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/storage/ty_depth_checker.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/storage/ty_layout_converter.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/storage/ty_tag_converter.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/storage/verified_module_cache.rs',
    'aptos-core/third_party/move/move-vm/runtime/src/tracing.rs',
    'aptos-core/third_party/move/move-vm/test-utils/src/gas_schedule.rs',
    'aptos-core/third_party/move/move-vm/test-utils/src/lib.rs',
    'aptos-core/third_party/move/move-vm/test-utils/src/storage.rs',
    'aptos-core/third_party/move/move-vm/transactional-tests/src/lib.rs',
    'aptos-core/third_party/move/move-vm/types/src/code/cache/mod.rs',
    'aptos-core/third_party/move/move-vm/types/src/code/cache/module_cache.rs',
    'aptos-core/third_party/move/move-vm/types/src/code/cache/script_cache.rs',
    'aptos-core/third_party/move/move-vm/types/src/code/cache/types.rs',
    'aptos-core/third_party/move/move-vm/types/src/code/errors.rs',
    'aptos-core/third_party/move/move-vm/types/src/code/mod.rs',
    'aptos-core/third_party/move/move-vm/types/src/code/storage.rs',
    'aptos-core/third_party/move/move-vm/types/src/delayed_values/delayed_field_id.rs',
    'aptos-core/third_party/move/move-vm/types/src/delayed_values/derived_string_snapshot.rs',
    'aptos-core/third_party/move/move-vm/types/src/delayed_values/error.rs',
    'aptos-core/third_party/move/move-vm/types/src/delayed_values/mod.rs',
    'aptos-core/third_party/move/move-vm/types/src/gas.rs',
    'aptos-core/third_party/move/move-vm/types/src/instr.rs',
    'aptos-core/third_party/move/move-vm/types/src/interner.rs',
    'aptos-core/third_party/move/move-vm/types/src/lib.rs',
    'aptos-core/third_party/move/move-vm/types/src/loaded_data/mod.rs',
    'aptos-core/third_party/move/move-vm/types/src/loaded_data/runtime_access_specifier.rs',
    'aptos-core/third_party/move/move-vm/types/src/loaded_data/runtime_access_specifiers_prop_tests.rs',
    'aptos-core/third_party/move/move-vm/types/src/loaded_data/runtime_types.rs',
    'aptos-core/third_party/move/move-vm/types/src/loaded_data/struct_name_indexing.rs',
    'aptos-core/third_party/move/move-vm/types/src/module_id_interner.rs',
    'aptos-core/third_party/move/move-vm/types/src/natives/function.rs',
    'aptos-core/third_party/move/move-vm/types/src/natives/mod.rs',
    'aptos-core/third_party/move/move-vm/types/src/resolver.rs',
    'aptos-core/third_party/move/move-vm/types/src/ty_interner.rs',
    'aptos-core/third_party/move/move-vm/types/src/unit_tests/identifier_prop_tests.rs',
    'aptos-core/third_party/move/move-vm/types/src/unit_tests/mod.rs',
    'aptos-core/third_party/move/move-vm/types/src/value_serde.rs',
    'aptos-core/third_party/move/move-vm/types/src/value_traversal.rs',
    'aptos-core/third_party/move/move-vm/types/src/values/function_values_impl.rs',
    'aptos-core/third_party/move/move-vm/types/src/values/mod.rs',
    'aptos-core/third_party/move/move-vm/types/src/values/serialization_tests.rs',
    'aptos-core/third_party/move/move-vm/types/src/values/value_depth_tests.rs',
    'aptos-core/third_party/move/move-vm/types/src/values/value_prop_tests.rs',
    'aptos-core/third_party/move/move-vm/types/src/values/value_tests.rs',
    'aptos-core/third_party/move/move-vm/types/src/values/values_impl.rs',
    'aptos-core/third_party/move/move-vm/types/src/views.rs',
    'aptos-core/third_party/move/testing-infra/transactional-test-runner/src/framework.rs',
    'aptos-core/third_party/move/testing-infra/transactional-test-runner/src/lib.rs',
    'aptos-core/third_party/move/testing-infra/transactional-test-runner/src/tasks.rs',
    'aptos-core/third_party/move/testing-infra/transactional-test-runner/src/templates.rs',
    'aptos-core/third_party/move/testing-infra/transactional-test-runner/src/transactional_ops.rs',
    'aptos-core/third_party/move/testing-infra/transactional-test-runner/src/vm_test_harness.rs',
    'aptos-core/third_party/move/tools/move-asm/src/assembler.rs',
    'aptos-core/third_party/move/tools/move-asm/src/disassembler.rs',
    'aptos-core/third_party/move/tools/move-asm/src/lib.rs',
    'aptos-core/third_party/move/tools/move-asm/src/main.rs',
    'aptos-core/third_party/move/tools/move-asm/src/module_builder.rs',
    'aptos-core/third_party/move/tools/move-asm/src/syntax.rs',
    'aptos-core/third_party/move/tools/move-asm/src/value.rs',
    'aptos-core/third_party/move/tools/move-bytecode-utils/src/compiled_module_viewer.rs',
    'aptos-core/third_party/move/tools/move-bytecode-utils/src/dependency_graph.rs',
    'aptos-core/third_party/move/tools/move-bytecode-utils/src/layout.rs',
    'aptos-core/third_party/move/tools/move-bytecode-utils/src/lib.rs',
    'aptos-core/third_party/move/tools/move-bytecode-viewer/src/bytecode_viewer.rs',
    'aptos-core/third_party/move/tools/move-bytecode-viewer/src/interfaces.rs',
    'aptos-core/third_party/move/tools/move-bytecode-viewer/src/lib.rs',
    'aptos-core/third_party/move/tools/move-bytecode-viewer/src/main.rs',
    'aptos-core/third_party/move/tools/move-bytecode-viewer/src/source_viewer.rs',
    'aptos-core/third_party/move/tools/move-bytecode-viewer/src/tui/mod.rs',
    'aptos-core/third_party/move/tools/move-bytecode-viewer/src/tui/text_builder.rs',
    'aptos-core/third_party/move/tools/move-bytecode-viewer/src/tui/tui_interface.rs',
    'aptos-core/third_party/move/tools/move-bytecode-viewer/src/viewer.rs',
    'aptos-core/third_party/move/tools/move-cli/src/base/build.rs',
    'aptos-core/third_party/move/tools/move-cli/src/base/coverage.rs',
    'aptos-core/third_party/move/tools/move-cli/src/base/disassemble.rs',
    'aptos-core/third_party/move/tools/move-cli/src/base/docgen.rs',
    'aptos-core/third_party/move/tools/move-cli/src/base/errmap.rs',
    'aptos-core/third_party/move/tools/move-cli/src/base/mod.rs',
    'aptos-core/third_party/move/tools/move-cli/src/base/new.rs',
    'aptos-core/third_party/move/tools/move-cli/src/base/prove.rs',
    'aptos-core/third_party/move/tools/move-cli/src/lib.rs',
    'aptos-core/third_party/move/tools/move-cli/src/main.rs',
    'aptos-core/third_party/move/tools/move-cli/src/test/mod.rs',
    'aptos-core/third_party/move/tools/move-coverage/src/bin/coverage-summaries.rs',
    'aptos-core/third_party/move/tools/move-coverage/src/bin/move-trace-conversion.rs',
    'aptos-core/third_party/move/tools/move-coverage/src/bin/source-coverage.rs',
    'aptos-core/third_party/move/tools/move-coverage/src/coverage_map.rs',
    'aptos-core/third_party/move/tools/move-coverage/src/lib.rs',
    'aptos-core/third_party/move/tools/move-coverage/src/source_coverage.rs',
    'aptos-core/third_party/move/tools/move-coverage/src/summary.rs',
    'aptos-core/third_party/move/tools/move-decompiler/src/lib.rs',
    'aptos-core/third_party/move/tools/move-decompiler/src/main.rs',
    'aptos-core/third_party/move/tools/move-disassembler/src/disassembler.rs',
    'aptos-core/third_party/move/tools/move-disassembler/src/lib.rs',
    'aptos-core/third_party/move/tools/move-disassembler/src/main.rs',
    'aptos-core/third_party/move/tools/move-linter/src/lib.rs',
    'aptos-core/third_party/move/tools/move-linter/src/model_ast_lints.rs',
    'aptos-core/third_party/move/tools/move-linter/src/model_ast_lints/aborting_overflow_checks.rs',
    'aptos-core/third_party/move/tools/move-linter/src/model_ast_lints/almost_swapped.rs',
    'aptos-core/third_party/move/tools/move-linter/src/model_ast_lints/assert_const.rs',
    'aptos-core/third_party/move/tools/move-linter/src/model_ast_lints/blocks_in_conditions.rs',
    'aptos-core/third_party/move/tools/move-linter/src/model_ast_lints/collapsible_if.rs',
    'aptos-core/third_party/move/tools/move-linter/src/model_ast_lints/cyclomatic_complexity.rs',
    'aptos-core/third_party/move/tools/move-linter/src/model_ast_lints/empty_if.rs',
    'aptos-core/third_party/move/tools/move-linter/src/model_ast_lints/equal_operands_in_bin_op.rs',
    'aptos-core/third_party/move/tools/move-linter/src/model_ast_lints/known_to_abort.rs',
    'aptos-core/third_party/move/tools/move-linter/src/model_ast_lints/needless_bool.rs',
    'aptos-core/third_party/move/tools/move-linter/src/model_ast_lints/needless_deref_ref.rs',
    'aptos-core/third_party/move/tools/move-linter/src/model_ast_lints/needless_ref_deref.rs',
    'aptos-core/third_party/move/tools/move-linter/src/model_ast_lints/needless_ref_in_field_access.rs',
    'aptos-core/third_party/move/tools/move-linter/src/model_ast_lints/needless_return.rs',
    'aptos-core/third_party/move/tools/move-linter/src/model_ast_lints/nonminimal_bool.rs',
    'aptos-core/third_party/move/tools/move-linter/src/model_ast_lints/self_assignment.rs',
    'aptos-core/third_party/move/tools/move-linter/src/model_ast_lints/simpler_bool_expression.rs',
    'aptos-core/third_party/move/tools/move-linter/src/model_ast_lints/simpler_numeric_expression.rs',
    'aptos-core/third_party/move/tools/move-linter/src/model_ast_lints/unnecessary_boolean_identity_comparison.rs',
    'aptos-core/third_party/move/tools/move-linter/src/model_ast_lints/unnecessary_cast.rs',
    'aptos-core/third_party/move/tools/move-linter/src/model_ast_lints/unnecessary_numerical_extreme_comparison.rs',
    'aptos-core/third_party/move/tools/move-linter/src/model_ast_lints/while_true.rs',
    'aptos-core/third_party/move/tools/move-linter/src/stackless_bytecode_lints.rs',
    'aptos-core/third_party/move/tools/move-linter/src/stackless_bytecode_lints/avoid_copy_on_identity_comparison.rs',
    'aptos-core/third_party/move/tools/move-linter/src/stackless_bytecode_lints/needless_mutable_reference.rs',
    'aptos-core/third_party/move/tools/move-linter/src/utils.rs',
    'aptos-core/third_party/move/tools/move-package-cache/src/canonical.rs',
    'aptos-core/third_party/move/tools/move-package-cache/src/file_lock.rs',
    'aptos-core/third_party/move/tools/move-package-cache/src/lib.rs',
    'aptos-core/third_party/move/tools/move-package-cache/src/listener.rs',
    'aptos-core/third_party/move/tools/move-package-cache/src/main.rs',
    'aptos-core/third_party/move/tools/move-package-cache/src/package_cache.rs',
    'aptos-core/third_party/move/tools/move-package-manifest/src/lib.rs',
    'aptos-core/third_party/move/tools/move-package-manifest/src/manifest.rs',
    'aptos-core/third_party/move/tools/move-package-manifest/src/named_address.rs',
    'aptos-core/third_party/move/tools/move-package-manifest/src/package_name.rs',
    'aptos-core/third_party/move/tools/move-package-manifest/src/util.rs',
    'aptos-core/third_party/move/tools/move-package-resolver/src/graph.rs',
    'aptos-core/third_party/move/tools/move-package-resolver/src/identity.rs',
    'aptos-core/third_party/move/tools/move-package-resolver/src/lib.rs',
    'aptos-core/third_party/move/tools/move-package-resolver/src/lock.rs',
    'aptos-core/third_party/move/tools/move-package-resolver/src/path.rs',
    'aptos-core/third_party/move/tools/move-package-resolver/src/resolver.rs',
    'aptos-core/third_party/move/tools/move-package/src/compilation/build_plan.rs',
    'aptos-core/third_party/move/tools/move-package/src/compilation/compiled_package.rs',
    'aptos-core/third_party/move/tools/move-package/src/compilation/mod.rs',
    'aptos-core/third_party/move/tools/move-package/src/compilation/model_builder.rs',
    'aptos-core/third_party/move/tools/move-package/src/compilation/package_layout.rs',
    'aptos-core/third_party/move/tools/move-package/src/lib.rs',
    'aptos-core/third_party/move/tools/move-package/src/package_hooks.rs',
    'aptos-core/third_party/move/tools/move-package/src/package_lock.rs',
    'aptos-core/third_party/move/tools/move-package/src/resolution/digest.rs',
    'aptos-core/third_party/move/tools/move-package/src/resolution/git.rs',
    'aptos-core/third_party/move/tools/move-package/src/resolution/mod.rs',
    'aptos-core/third_party/move/tools/move-package/src/resolution/resolution_graph.rs',
    'aptos-core/third_party/move/tools/move-package/src/source_package/layout.rs',
    'aptos-core/third_party/move/tools/move-package/src/source_package/manifest_parser.rs',
    'aptos-core/third_party/move/tools/move-package/src/source_package/mod.rs',
    'aptos-core/third_party/move/tools/move-package/src/source_package/parsed_manifest.rs',
    'aptos-core/third_party/move/tools/move-package/src/source_package/std_lib.rs',
    'aptos-core/third_party/move/tools/move-resource-viewer/src/fat_type.rs',
    'aptos-core/third_party/move/tools/move-resource-viewer/src/lib.rs',
    'aptos-core/third_party/move/tools/move-resource-viewer/src/limit.rs',
    'aptos-core/third_party/move/tools/move-unit-test/src/extensions.rs',
    'aptos-core/third_party/move/tools/move-unit-test/src/lib.rs',
    'aptos-core/third_party/move/tools/move-unit-test/src/main.rs',
    'aptos-core/tools/calc-dep-sizes/src/main.rs',
    'aptos-core/tools/compute-module-expansion-size/src/main.rs',
    'aptos-core/types/benches/keyless.rs',
    'aptos-core/types/benches/state_key.rs',
    'aptos-core/types/src/access_path.rs',
    'aptos-core/types/src/account_address.rs',
    'aptos-core/types/src/account_config/constants/account.rs',
    'aptos-core/types/src/account_config/constants/addresses.rs',
    'aptos-core/types/src/account_config/constants/mod.rs',
    'aptos-core/types/src/account_config/events/burn.rs',
    'aptos-core/types/src/account_config/events/burn_event.rs',
    'aptos-core/types/src/account_config/events/burn_token.rs',
    'aptos-core/types/src/account_config/events/burn_token_event.rs',
    'aptos-core/types/src/account_config/events/cancel_offer.rs',
    'aptos-core/types/src/account_config/events/claim.rs',
    'aptos-core/types/src/account_config/events/coin_deposit.rs',
    'aptos-core/types/src/account_config/events/coin_register.rs',
    'aptos-core/types/src/account_config/events/coin_register_event.rs',
    'aptos-core/types/src/account_config/events/coin_withdraw.rs',
    'aptos-core/types/src/account_config/events/collection_description_mutate.rs',
    'aptos-core/types/src/account_config/events/collection_description_mutate_event.rs',
    'aptos-core/types/src/account_config/events/collection_maximum_mutate.rs',
    'aptos-core/types/src/account_config/events/collection_maximum_mutate_event.rs',
    'aptos-core/types/src/account_config/events/collection_mutation.rs',
    'aptos-core/types/src/account_config/events/collection_mutation_event.rs',
    'aptos-core/types/src/account_config/events/collection_uri_mutate.rs',
    'aptos-core/types/src/account_config/events/collection_uri_mutate_event.rs',
    'aptos-core/types/src/account_config/events/create_collection.rs',
    'aptos-core/types/src/account_config/events/create_collection_event.rs',
    'aptos-core/types/src/account_config/events/create_token_data_event.rs',
    'aptos-core/types/src/account_config/events/default_property_mutate.rs',
    'aptos-core/types/src/account_config/events/default_property_mutate_event.rs',
    'aptos-core/types/src/account_config/events/deposit_event.rs',
    'aptos-core/types/src/account_config/events/description_mutate.rs',
    'aptos-core/types/src/account_config/events/description_mutate_event.rs',
    'aptos-core/types/src/account_config/events/fungible_asset.rs',
    'aptos-core/types/src/account_config/events/key_rotation.rs',
    'aptos-core/types/src/account_config/events/key_rotation_event.rs',
    'aptos-core/types/src/account_config/events/maximum_mutate.rs',
    'aptos-core/types/src/account_config/events/maximum_mutate_event.rs',
    'aptos-core/types/src/account_config/events/mint.rs',
    'aptos-core/types/src/account_config/events/mint_event.rs',
    'aptos-core/types/src/account_config/events/mint_token.rs',
    'aptos-core/types/src/account_config/events/mint_token_event.rs',
    'aptos-core/types/src/account_config/events/mod.rs',
    'aptos-core/types/src/account_config/events/mutate_property_map.rs',
    'aptos-core/types/src/account_config/events/mutate_token_property_map_event.rs',
    'aptos-core/types/src/account_config/events/new_block.rs',
    'aptos-core/types/src/account_config/events/new_epoch.rs',
    'aptos-core/types/src/account_config/events/offer.rs',
    'aptos-core/types/src/account_config/events/opt_in_transfer.rs',
    'aptos-core/types/src/account_config/events/opt_in_transfer_event.rs',
    'aptos-core/types/src/account_config/events/randomness_event.rs',
    'aptos-core/types/src/account_config/events/royalty_mutate.rs',
    'aptos-core/types/src/account_config/events/royalty_mutate_event.rs',
    'aptos-core/types/src/account_config/events/token_cancel_offer_event.rs',
    'aptos-core/types/src/account_config/events/token_claim_event.rs',
    'aptos-core/types/src/account_config/events/token_data_creation.rs',
    'aptos-core/types/src/account_config/events/token_deposit.rs',
    'aptos-core/types/src/account_config/events/token_deposit_event.rs',
    'aptos-core/types/src/account_config/events/token_mutation.rs',
    'aptos-core/types/src/account_config/events/token_mutation_event.rs',
    'aptos-core/types/src/account_config/events/token_offer_event.rs',
    'aptos-core/types/src/account_config/events/token_withdraw.rs',
    'aptos-core/types/src/account_config/events/token_withdraw_event.rs',
    'aptos-core/types/src/account_config/events/transfer.rs',
    'aptos-core/types/src/account_config/events/transfer_event.rs',
    'aptos-core/types/src/account_config/events/uri_mutation.rs',
    'aptos-core/types/src/account_config/events/uri_mutation_event.rs',
    'aptos-core/types/src/account_config/events/withdraw_event.rs',
    'aptos-core/types/src/account_config/mod.rs',
    'aptos-core/types/src/account_config/resources/aggregator.rs',
    'aptos-core/types/src/account_config/resources/any.rs',
    'aptos-core/types/src/account_config/resources/chain_id.rs',
    'aptos-core/types/src/account_config/resources/challenge.rs',
    'aptos-core/types/src/account_config/resources/coin_info.rs',
    'aptos-core/types/src/account_config/resources/coin_store.rs',
    'aptos-core/types/src/account_config/resources/collection.rs',
    'aptos-core/types/src/account_config/resources/collections.rs',
    'aptos-core/types/src/account_config/resources/core_account.rs',
    'aptos-core/types/src/account_config/resources/fixed_supply.rs',
    'aptos-core/types/src/account_config/resources/fungible_asset_metadata.rs',
    'aptos-core/types/src/account_config/resources/fungible_store.rs',
    'aptos-core/types/src/account_config/resources/mod.rs',
    'aptos-core/types/src/account_config/resources/object.rs',
    'aptos-core/types/src/account_config/resources/pending_claims.rs',
    'aptos-core/types/src/account_config/resources/token.rs',
    'aptos-core/types/src/account_config/resources/token_event_store_v1.rs',
    'aptos-core/types/src/account_config/resources/token_store.rs',
    'aptos-core/types/src/account_config/resources/type_info.rs',
    'aptos-core/types/src/account_config/resources/unlimited_supply.rs',
    'aptos-core/types/src/aggregate_signature.rs',
    'aptos-core/types/src/block_executor/config.rs',
    'aptos-core/types/src/block_executor/mod.rs',
    'aptos-core/types/src/block_executor/partitioner.rs',
    'aptos-core/types/src/block_executor/transaction_slice_metadata.rs',
    'aptos-core/types/src/block_info.rs',
    'aptos-core/types/src/block_metadata.rs',
    'aptos-core/types/src/block_metadata_ext.rs',
    'aptos-core/types/src/bytes.rs',
    'aptos-core/types/src/chain_id.rs',
    'aptos-core/types/src/contract_event.rs',
    'aptos-core/types/src/delayed_fields.rs',
    'aptos-core/types/src/dkg/dummy_dkg/mod.rs',
    'aptos-core/types/src/dkg/mod.rs',
    'aptos-core/types/src/dkg/real_dkg/mod.rs',
    'aptos-core/types/src/dkg/real_dkg/rounding/mod.rs',
    'aptos-core/types/src/epoch_change.rs',
    'aptos-core/types/src/epoch_state.rs',
    'aptos-core/types/src/error.rs',
    'aptos-core/types/src/event.rs',
    'aptos-core/types/src/executable.rs',
    'aptos-core/types/src/fee_statement.rs',
    'aptos-core/types/src/function_info.rs',
    'aptos-core/types/src/governance.rs',
    'aptos-core/types/src/indexer/indexer_db_reader.rs',
    'aptos-core/types/src/indexer/mod.rs',
    'aptos-core/types/src/jwks/jwk/mod.rs',
    'aptos-core/types/src/jwks/mod.rs',
    'aptos-core/types/src/jwks/patch/mod.rs',
    'aptos-core/types/src/jwks/rsa/mod.rs',
    'aptos-core/types/src/jwks/unsupported/mod.rs',
    'aptos-core/types/src/keyless/bn254_circom.rs',
    'aptos-core/types/src/keyless/circuit_constants.rs',
    'aptos-core/types/src/keyless/circuit_testcases.rs',
    'aptos-core/types/src/keyless/configuration.rs',
    'aptos-core/types/src/keyless/groth16_sig.rs',
    'aptos-core/types/src/keyless/groth16_vk.rs',
    'aptos-core/types/src/keyless/mod.rs',
    'aptos-core/types/src/keyless/openid_sig.rs',
    'aptos-core/types/src/keyless/proof_simulation.rs',
    'aptos-core/types/src/keyless/zkp_sig.rs',
    'aptos-core/types/src/ledger_info.rs',
    'aptos-core/types/src/lib.rs',
    'aptos-core/types/src/mempool_status.rs',
    'aptos-core/types/src/move_any.rs',
    'aptos-core/types/src/move_fixed_point.rs',
    'aptos-core/types/src/move_utils/as_move_value.rs',
    'aptos-core/types/src/move_utils/mod.rs',
    'aptos-core/types/src/move_utils/move_event_v1.rs',
    'aptos-core/types/src/move_utils/move_event_v2.rs',
    'aptos-core/types/src/network_address/mod.rs',
    'aptos-core/types/src/nibble/mod.rs',
    'aptos-core/types/src/nibble/nibble_path/mod.rs',
    'aptos-core/types/src/object_address.rs',
    'aptos-core/types/src/on_chain_config/approved_execution_hashes.rs',
    'aptos-core/types/src/on_chain_config/aptos_features.rs',
    'aptos-core/types/src/on_chain_config/aptos_version.rs',
    'aptos-core/types/src/on_chain_config/chain_id.rs',
    'aptos-core/types/src/on_chain_config/commit_history.rs',
    'aptos-core/types/src/on_chain_config/consensus_config.rs',
    'aptos-core/types/src/on_chain_config/execution_config.rs',
    'aptos-core/types/src/on_chain_config/gas_schedule.rs',
    'aptos-core/types/src/on_chain_config/jwk_consensus_config.rs',
    'aptos-core/types/src/on_chain_config/mod.rs',
    'aptos-core/types/src/on_chain_config/randomness_api_v0_config.rs',
    'aptos-core/types/src/on_chain_config/randomness_config.rs',
    'aptos-core/types/src/on_chain_config/timed_features.rs',
    'aptos-core/types/src/on_chain_config/timestamp.rs',
    'aptos-core/types/src/on_chain_config/transaction_fee.rs',
    'aptos-core/types/src/on_chain_config/validator_set.rs',
    'aptos-core/types/src/proof/accumulator/mock.rs',
    'aptos-core/types/src/proof/accumulator/mod.rs',
    'aptos-core/types/src/proof/definition.rs',
    'aptos-core/types/src/proof/mod.rs',
    'aptos-core/types/src/proof/position/mod.rs',
    'aptos-core/types/src/proof/proptest_proof.rs',
    'aptos-core/types/src/proof/unit_tests/mod.rs',
    'aptos-core/types/src/proptest_types.rs',
    'aptos-core/types/src/quorum_store/mod.rs',
    'aptos-core/types/src/randomness.rs',
    'aptos-core/types/src/secret_sharing.rs',
    'aptos-core/types/src/serde_helper/bcs_utils.rs',
    'aptos-core/types/src/serde_helper/mod.rs',
    'aptos-core/types/src/serde_helper/vec_bytes.rs',
    'aptos-core/types/src/stake_pool.rs',
    'aptos-core/types/src/staking_contract.rs',
    'aptos-core/types/src/state_proof.rs',
    'aptos-core/types/src/state_store/errors.rs',
    'aptos-core/types/src/state_store/hot_state.rs',
    'aptos-core/types/src/state_store/mod.rs',
    'aptos-core/types/src/state_store/state_key/inner.rs',
    'aptos-core/types/src/state_store/state_key/mod.rs',
    'aptos-core/types/src/state_store/state_key/prefix.rs',
    'aptos-core/types/src/state_store/state_key/registry.rs',
    'aptos-core/types/src/state_store/state_slot.rs',
    'aptos-core/types/src/state_store/state_storage_usage.rs',
    'aptos-core/types/src/state_store/state_value.rs',
    'aptos-core/types/src/state_store/table.rs',
    'aptos-core/types/src/timestamp.rs',
    'aptos-core/types/src/transaction/analyzed_transaction.rs',
    'aptos-core/types/src/transaction/authenticator.rs',
    'aptos-core/types/src/transaction/block_epilogue.rs',
    'aptos-core/types/src/transaction/block_output.rs',
    'aptos-core/types/src/transaction/change_set.rs',
    'aptos-core/types/src/transaction/encrypted_payload.rs',
    'aptos-core/types/src/transaction/mod.rs',
    'aptos-core/types/src/transaction/module.rs',
    'aptos-core/types/src/transaction/multisig.rs',
    'aptos-core/types/src/transaction/script.rs',
    'aptos-core/types/src/transaction/signature_verified_transaction.rs',
    'aptos-core/types/src/transaction/use_case.rs',
    'aptos-core/types/src/transaction/user_transaction_context.rs',
    'aptos-core/types/src/transaction/webauthn.rs',
    'aptos-core/types/src/trusted_state.rs',
    'aptos-core/types/src/unit_tests/mod.rs',
    'aptos-core/types/src/utility_coin.rs',
    'aptos-core/types/src/validator_config.rs',
    'aptos-core/types/src/validator_info.rs',
    'aptos-core/types/src/validator_performances.rs',
    'aptos-core/types/src/validator_signer.rs',
    'aptos-core/types/src/validator_txn.rs',
    'aptos-core/types/src/validator_verifier.rs',
    'aptos-core/types/src/vesting.rs',
    'aptos-core/types/src/vm/code.rs',
    'aptos-core/types/src/vm/mod.rs',
    'aptos-core/types/src/vm/module_metadata.rs',
    'aptos-core/types/src/vm/modules.rs',
    'aptos-core/types/src/vm_status.rs',
    'aptos-core/types/src/waypoint.rs',
    'aptos-core/types/src/write_set.rs',
    'aptos-core/vm-validator/src/lib.rs',
    'aptos-core/vm-validator/src/mocks/mock_vm_validator.rs',
    'aptos-core/vm-validator/src/mocks/mod.rs',
    'aptos-core/vm-validator/src/vm_validator.rs',
]


def question_format(question: str) -> str:
    """
    Generates a comprehensive security audit prompt for Aptos Blockchain.

    Args:
        question: A specific security question to investigate

    Returns:
        A formatted prompt string for vulnerability analysis
    """
    prompt = f"""      
You are an **Elite Aptos Blockchain Security Auditor** specializing in       
consensus vulnerabilities, Move VM implementation bugs,       
state management attacks, and on-chain governance security. Your task is to analyze the **Aptos Core**       
codebase—the official Aptos blockchain implementation—through the lens of this single security question:       
      
**Security Question (scope for this run):** {question}      
      
**APTOS BLOCKCHAIN CONTEXT:**      
      
**Architecture**: Aptos is a high-performance Layer 1 blockchain using the Move programming language.       
It implements the AptosBFT consensus protocol, AptosVM for Move bytecode execution, and maintains       
state through AptosDB with Jellyfish Merkle Trees. Critical components include the consensus engine,       
Move VM, state management, on-chain governance, and validator staking subsystems.      
      
Think in invariant violations      
Check every logic entry that could affect consensus or node security based on the question provided       
Look at the exact files provided and other places also if they can cause severe vulnerabilities       
Think in an elite way because there is always a logic vulnerability that could occur      
      
**Key Components**:       
      
* **Consensus Layer**: `consensus/` (AptosBFT protocol, RoundManager, EpochManager, SafetyRules),       
  `consensus-types/` (quorum certificates, block data types)      
      
* **Execution Engine**: `aptos-move/aptos-vm/` (AptosVM, MoveVM integration),       
  `aptos-move/framework/` (Aptos Framework in Move), `aptos-move/vm-genesis/` (genesis initialization)      
      
* **Storage System**: `storage/aptosdb/` (AptosDB, StateStore, StateMerkleDb),       
  `storage/state-sync/` (state synchronization)      
      
* **Network Layer**: `network/` (P2P networking, consensus messaging),       
  `mempool/` (transaction pool management)      
      
* **On-Chain Governance**: `aptos-move/framework/aptos-framework/sources/aptos_governance.move` (voting, proposals)      
      
* **Staking System**: `aptos-move/framework/aptos-framework/sources/stake.move` (validator operations)      
      
**Files in Scope**: All source files in the repository, excluding test files and documentation.       
Focus on consensus, execution, storage, governance, and staking components.      
      
**CRITICAL INVARIANTS (derived from Aptos specification and implementation):**      
      
1. **Deterministic Execution**: All validators must produce identical state roots for identical blocks      
2. **Consensus Safety**: AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine      
3. **Move VM Safety**: Bytecode execution must respect gas limits and memory constraints      
4. **State Consistency**: State transitions must be atomic and verifiable via Merkle proofs      
5. **Governance Integrity**: Voting power must be correctly calculated from stake      
6. **Staking Security**: Validator rewards and penalties must be calculated correctly      
7. **Transaction Validation**: Prologue/epilogue checks must enforce all invariants      
8. **Access Control**: System addresses (@aptos_framework, @core_resources) must be protected      
9. **Resource Limits**: All operations must respect gas, storage, and computational limits      
10. **Cryptographic Correctness**: BLS signatures, VRF, and hash operations must be secure      
      
**YOUR INVESTIGATION MISSION:**      
      
Accept the premise of the security question and explore **all** relevant       
code paths, data structures, state transitions, and system interactions related to it.       
Trace execution flows through transaction submission → mempool → consensus → execution → state commitment.      
      
Your goal is to find **one** concrete, exploitable vulnerability tied to       
the question that an attacker, malicious validator, or transaction sender could exploit.       
Focus on:       
      
* Consensus violations (safety breaks, equivocation, ledger forks)      
* Move VM bugs (incorrect bytecode execution, gas miscalculation)      
* State manipulation (Merkle tree corruption, storage inconsistencies)      
* Governance attacks (voting power manipulation, proposal execution bypass)      
* Staking exploits (reward calculation errors, validator set manipulation)      
* Transaction validation bypasses (signature verification, sequence number)      
* Resource exhaustion (gas metering, storage bombing)      
* Access control failures (system address compromise)      
* Cryptographic weaknesses (BLS, VRF, hash collisions)      
* Network protocol attacks (malicious peer handling)      
      
**ATTACK SURFACE EXPLORATION:**      
      
1. **Consensus Protocol** (`consensus/`):      
   - Voting rule violations allowing safety breaks      
   - Round state manipulation causing liveness failures      
   - Quorum certificate forgery or replay attacks      
   - Leader election manipulation via VRF weaknesses      
   - Epoch transition vulnerabilities      
      
2. **Move VM Execution** (`aptos-move/aptos-vm/`):      
   - Bytecode interpretation errors causing consensus splits      
   - Gas calculation miscalculations enabling free computation      
   - Native function implementation bugs      
   - Resource access control bypasses      
   - Module loading and linking vulnerabilities      
      
3. **State Management** (`storage/aptosdb/`):      
   - Jellyfish Merkle tree manipulation      
   - StateKV database corruption      
   - Snapshot consistency vulnerabilities      
   - Pruning and garbage collection bugs      
   - State sync manipulation attacks      
      
4. **On-Chain Governance** (`aptos-move/framework/aptos-framework/sources/aptos_governance.move`):      
   - Voting power calculation errors      
   - Proposal execution bypasses      
   - Multi-step proposal vulnerabilities      
   - Signer capability mishandling      
   - Feature flag manipulation      
      
5. **Staking System** (`aptos-move/framework/aptos-framework/sources/stake.move`):      
   - Reward calculation vulnerabilities      
   - Validator set manipulation      
   - Stake pool state corruption      
   - Lockup and unlocking bugs      
   - Performance tracking manipulation      
      
6. **Transaction Validation** (`aptos-move/framework/aptos-framework/sources/transaction_validation.move`):      
   - Signature verification bypasses      
   - Sequence number manipulation      
   - Gas payment validation failures      
   - Multi-agent transaction vulnerabilities      
   - Prologue/epilogue invariant violations      
      
**APTOS-SPECIFIC ATTACK VECTORS:**      
      
- **Move Bytecode Exploits**: Can attackers craft malicious Move modules to break VM invariants?      
- **Consensus Safety Violations**: Can malicious validators cause different nodes to commit different blocks?      
- **Governance Power Manipulation**: Can attackers manipulate voting power through stake pool bugs?      
- **State Merkle Tree Attacks**: Can attackers corrupt the Jellyfish Merkle tree or cause inconsistencies?      
- **Gas Metering Bypasses**: Can attackers bypass gas limits or cause undercharging in Move VM?      
- **Validator Set Manipulation**: Can attackers manipulate the active validator set through staking bugs?      
- **Resource Access Bypasses**: Can attackers access protected resources or system addresses?      
- **Epoch Transition Attacks**: Can attackers exploit vulnerabilities during epoch changes?      
- **Native Function Bugs**: Can attackers exploit bugs in Move native functions?      
- **Feature Flag Abuse**: Can attackers enable/disable features to bypass security controls?      
      
**TRUST MODEL:**      
      
**Trusted Roles**: Aptos core developers, validator operators, governance participants.       
Do **not** assume these actors behave maliciously unless the question explicitly explores insider threats.      
      
**Untrusted Actors**: Any network peer, transaction sender, Move module deployer, or       
malicious actor attempting to exploit protocol vulnerabilities. Focus on bugs exploitable       
without requiring privileged validator access or collusion.      
      
**KNOWN ISSUES / EXCLUSIONS:**      
      
- Cryptographic primitives (Rust crypto crates, BLS implementations) are assumed secure      
- Network-level DoS attacks are out of scope per bug bounty rules      
- Social engineering, phishing, or key theft      
- Performance optimizations unless they introduce security vulnerabilities      
- Code style, documentation, or non-critical bugs      
- Test file issues (tests are out of scope)      
- Economic attacks requiring market manipulation      
- 51% attacks or stake majority attacks      
      
**VALID IMPACT CATEGORIES (per Aptos Bug Bounty):**      
      
**Critical Severity** (up to $1,000,000):      
- Loss of Funds (theft or minting)      
- Consensus/Safety violations      
- Non-recoverable network partition (requires hardfork)      
- Total loss of liveness/network availability      
- Permanent freezing of funds (requires hardfork)      
- Remote Code Execution on validator node      
      
**High Severity** (up to $50,000):      
- Validator node slowdowns      
- API crashes      
- Significant protocol violations      
      
**Medium Severity** (up to $10,000):      
- Limited funds loss or manipulation      
- State inconsistencies requiring intervention      
      
**Low Severity** (up to $1,000):      
- Minor information leaks      
- Non-critical implementation bugs      
      
**OUTPUT REQUIREMENTS:**      
      
If you discover a valid vulnerability related to the security question,       
produce a **full report** following the format below. Your report must include:       
- Exact file paths and function names      
- Code quotations from the relevant source files      
- Step-by-step exploitation path with realistic parameters      
- Clear explanation of which invariant is broken      
- Impact quantification (affected nodes, potential damage)      
- Likelihood assessment (attacker requirements, complexity)      
- Concrete recommendation with code fix      
- Proof of Concept (Move test or Rust reproduction steps)      
      
If **no** valid vulnerability emerges after thorough investigation, state exactly:       
`#NoVulnerability found for this question.`      
      
**Do not fabricate or exaggerate issues.** Only concrete, exploitable bugs with       
clear attack paths and realistic impact count.      
      
**VALIDATION CHECKLIST (Before Reporting):**      
- [ ] Vulnerability lies within the Aptos Core codebase (not tests or docs)      
- [ ] Exploitable by unprivileged attacker (no validator insider access required)      
- [ ] Attack path is realistic with correct parameters and feasible execution      
- [ ] Impact meets Critical, High, or Medium severity criteria per bounty program      
- [ ] PoC can be implemented as Move test or Rust reproduction steps      
- [ ] Issue breaks at least one documented invariant      
- [ ] Not a known issue from previous security audits      
- [ ] Clear security harm demonstrated (funds, consensus, availability)      
      
---      
      
**AUDIT REPORT FORMAT** (if vulnerability found):      
      
Audit Report      
      
## Title       
The Title Of the Report       
      
## Summary      
A short summary of the issue, keep it brief.      
      
## Finding Description      
A more detailed explanation of the issue. Describe which security guarantees it breaks and how it breaks them. If this bug does not automatically happen, showcase how a malicious input would propagate through the system to the part of the code where the issue occurs.      
      
## Impact Explanation      
Elaborate on why you've chosen a particular impact assessment, referencing the Aptos bug bounty severity categories.      
      
## Likelihood Explanation      
Explain how likely this is to occur and why.      
      
## Recommendation      
How can the issue be fixed or solved. Preferably, you can also add a snippet of the fixed code here.      
      
## Proof of Concept      
A proof of concept demonstrating the vulnerability. Must be able to compile and run successfully.      
      
**Remember**: False positives harm credibility more than missed findings. Assume claims are invalid until overwhelming evidence proves otherwise.      
      
**Now perform STRICT validation of the claim above.**      
      
**Output ONLY:**      
- A full audit report (if genuinely valid after passing **all** checks above) following the specified format      
- `#NoVulnerability found for this question.` (if **any** check fails)      
      
**Be ruthlessly skeptical. The bar for validity is EXTREMELY high.**      
"""
    return prompt


def validation_format(report: str) -> str:
    """
    Generates a comprehensive validation prompt for Aptos Blockchain security claims.

    Args:
        report: A security vulnerability report to validate

    Returns:
        A formatted validation prompt string for ruthless technical scrutiny
    """
    prompt = f"""    
You are an **Elite Aptos Blockchain Security Judge** with deep expertise in consensus vulnerabilities, Move VM implementation bugs, state management security, and blockchain client validation. Your ONLY task is **ruthless technical validation** of security claims against the Aptos Core codebase.    
    
Note: Aptos core developers, validator operators, and governance participants are trusted roles.    
    
**SECURITY CLAIM TO VALIDATE:**    
{report}    
    
================================================================================    
## **APTOS BLOCKCHAIN VALIDATION FRAMEWORK**    
    
### **PHASE 1: IMMEDIATE DISQUALIFICATION CHECKS**    
Reject immediately (`#NoVulnerability`) if **ANY** apply:    

Note before a vulnerability can be considered valid it must have a valid impact and also a valid likelihood that can be triggered 
or trigger validly on its own, if a vulnerability cant be triggered then its invalid, except there is a logic vuln this is very important 

And your return must either be the report or `#NoVulnerability` because this is automated and that's the only way i can understand 


Note before a vulnerability can be considered valid it must have a valid impact and also a valid likelihood that can be triggered 
or trigger validly on its own, if a vulnerability cant be triggered then its invalid, except there is a logic vuln this is very important 

And your return must either be the report or `#NoVulnerability` because this is automated and thats the only way i can understand 

#### **A. Scope Violations**    
- ❌ Affects files **not** in Aptos Core source code (`consensus/`, `aptos-move/`, `storage/`, `network/`, `api/`, `types/`)    
- ❌ Targets any file under test directories (`*_test.go`, `*_test.move`, `tests/`) - tests are out of scope    
- ❌ Claims about documentation, comments, code style, or logging (not security issues)    
- ❌ Focuses on external tools: CLI standalone tools, development utilities    
    
**In-Scope Components:**    
- **Consensus Layer**: `consensus/` (AptosBFT protocol, RoundManager, EpochManager, SafetyRules)    
- **Execution Engine**: `aptos-move/aptos-vm/` (AptosVM, MoveVM integration)    
- **Aptos Framework**: `aptos-move/framework/aptos-framework/sources/` (Move modules)    
- **Storage System**: `storage/aptosdb/` (AptosDB, StateStore, StateMerkleDb)    
- **Network Layer**: `network/` (P2P networking, consensus messaging)    
- **API Layer**: `api/` (REST API, transaction submission)    
- **Types**: `types/` (core data structures, validator verifier)    
    
**Verify**: Check that every file path cited in the report matches the Aptos source structure.    
    
#### **B. Threat Model Violations**    
- ❌ Requires compromised Aptos core developers or foundation members    
- ❌ Assumes majority stake collusion (>1/3 Byzantine validators)    
- ❌ Needs blockchain consensus compromise or network-level attacks    
- ❌ Assumes cryptographic primitives in Rust crypto crates are broken    
- ❌ Depends on social engineering, phishing, or key theft    
- ❌ Relies on infrastructure attacks: DDoS, BGP hijacking, DNS poisoning    
- ❌ **Network DoS attacks are explicitly out of scope per bounty rules**    
    
**Trusted Roles**: Aptos core developers, validator operators, governance participants. Do **not** assume these actors behave maliciously.    
    
**Untrusted Actors**: Any network peer, transaction sender, Move module deployer, or malicious actor attempting to exploit protocol vulnerabilities.    
    
#### **C. Known Issues / Exclusions**    
- ❌ Any finding already documented in security postmortems or advisories    
- ❌ Issues in external dependencies (unless proven impact on Aptos)    
- ❌ Performance optimizations unless they introduce security vulnerabilities    
- ❌ Gas optimization or efficiency improvements without security impact    
- ❌ Code style, documentation, or non-critical bugs    
- ❌ Test infrastructure attacks (explicitly out of scope)    
    
#### **D. Non-Security Issues**    
- ❌ Performance improvements, memory optimizations, or micro-optimizations    
- ❌ Code style, naming conventions, or refactoring suggestions    
- ❌ Missing events, logs, error messages, or better user experience    
- ❌ Documentation improvements, README updates, or comment additions    
- ❌ "Best practices" recommendations with no concrete exploit scenario    
- ❌ Minor precision errors with negligible impact (<0.01%)    
    
#### **E. Invalid Exploit Scenarios**    
- ❌ Requires impossible inputs: invalid Move bytecode, malformed transactions    
- ❌ Cannot be triggered through any realistic API call or transaction submission    
- ❌ Depends on calling internal functions not exposed through any API    
- ❌ Relies on race conditions prevented by blockchain's atomic nature    
- ❌ Needs multiple coordinated blocks with no economic incentive    
- ❌ Requires attacker to control majority of validator stake    
- ❌ Depends on timestamp manipulation beyond consensus rules    
    
### **PHASE 2: APTOS-SPECIFIC DEEP CODE VALIDATION**    
    
#### **Step 1: TRACE COMPLETE EXECUTION PATH THROUGH APTOS ARCHITECTURE**    
    
**Aptos Flow Patterns:**    
    
1. **Transaction Processing Flow**:    
   REST API → `api/transactions.rs` → `mempool/` → consensus ordering → `aptos-move/aptos-vm/` → state update → `storage/aptosdb/`    
    
2. **Block Execution Flow**:    
   Block proposal → `consensus/round_manager.rs` → `aptos-move/aptos-vm/aptos_vm.rs` → execute_block() → state commitment → storage persistence    
    
3. **Move VM Execution Flow**:    
   Transaction → PrologueSession → UserSession → EpilogueSession → VMChangeSet → StateStore update    
    
4. **Consensus Message Flow**:    
   Network message → `consensus/network_interface.rs` → validation → voting → quorum certificate    
    
For each claim, reconstruct the entire execution path:    
    
1. **Identify Entry Point**: Which API endpoint, network message, or Move function triggers the issue?    
2. **Follow Internal Calls**: Trace through all function calls in the execution path    
3. **State Before Exploit**: Document initial state (blockchain state, gas, sequence numbers)    
4. **State Transitions**: Enumerate all changes (state updates, resource modifications)    
5. **Check Protections**: Verify if existing validations prevent the exploit    
6. **Final State**: Show how the exploit results in incorrect state or crash    
    
#### **Step 2: VALIDATE EVERY CLAIM WITH CODE EVIDENCE**    
    
For **each assertion** in the report, demand:    
    
**✅ Required Evidence:**    
- Exact file path and line numbers (e.g., `aptos-move/aptos-vm/src/aptos_vm.rs:304-396`)    
- Direct Rust/Move code quotes showing the vulnerable logic    
- Call traces with actual parameter values demonstrating execution path    
- Calculations showing gas, state, or resource changes incorrectly    
- References to specific consensus rule violations or Move specification breaks    
    
**🚩 RED FLAGS (indicate INVALID):**    
    
1. **"Missing Validation" Claims**:    
   - ❌ Invalid unless report shows input bypasses *all* validation layers:    
     - API parameter validation in `api/`    
     - Transaction validation in `aptos-move/framework/aptos-framework/sources/transaction_validation.move`    
     - Prologue/epilogue checks in `aptos-move/aptos-vm/src/move_vm_ext/session/`    
     - Move VM bytecode verification    
   - ✅ Valid if a specific input type genuinely has no validation path    
    
2. **"Consensus Violation" Claims**:    
   - ❌ Invalid unless report demonstrates:    
     - Different validators produce different state roots for same block    
     - AptosBFT safety violations (< 1/3 Byzantine)    
     - Block validation bypasses consensus rules    
   - ✅ Valid if consensus split can be triggered with < 1/3 Byzantine    
    
3. **"Move VM Bug" Claims**:    
   - ❌ Invalid unless report demonstrates:    
     - Bytecode interpretation errors causing consensus splits    
     - Gas calculation miscalculations enabling free computation    
     - Resource access control bypasses    
   - ✅ Valid if VM bugs affect consensus or enable fund theft    
    
4. **"State Corruption" Claims**:    
   - ❌ Invalid unless report demonstrates:    
     - Jellyfish Merkle tree manipulation in `storage/aptosdb/src/state_merkle_db.rs`    
     - StateKV database corruption    
     - Resource layout inconsistencies    
   - ✅ Valid if state corruption leads to consensus failure or fund loss    
    
5. **"Governance Attack" Claims**:    
   - ❌ Invalid unless report demonstrates:    
     - Voting power calculation errors in `aptos-move/framework/aptos-framework/sources/aptos_governance.move`    
     - Proposal execution bypasses    
     - Signer capability mishandling    
   - ✅ Valid if governance attacks enable fund theft or consensus breaks    
    
6. **"Staking Exploit" Claims**:    
   - ❌ Invalid unless report demonstrates:    
     - Reward calculation vulnerabilities in `aptos-move/framework/aptos-framework/sources/stake.move`    
     - Validator set manipulation    
     - Lockup/unlocking bugs    
   - ✅ Valid if staking bugs affect consensus or enable fund theft    
    
7. **"Access Control" Claims**:    
   - ❌ Invalid unless report demonstrates:    
     - Unauthorized access to @aptos_framework or @core_resources addresses    
     - Privilege escalation through Move modules    
     - Bypass of system address protections    
   - ✅ Valid if access control bypass enables fund theft or minting    
    
8. **"Cryptographic" Claims**:    
   - ❌ Invalid unless report demonstrates:    
     - BLS signature verification failures    
     - VRF manipulation in leader election    
     - Hash collisions in state commitment    
   - ✅ Valid if crypto breaks enable consensus violations or fund theft    
    
#### **Step 3: CROSS-REFERENCE WITH APTOS SECURITY POSTMORTEMS**    
    
Check against known Aptos vulnerabilities and security advisories:    
    
1. **Historical Patterns**: Does this match known vulnerability types?    
   - Move VM bytecode interpretation bugs    
   - Consensus timing attacks    
   - State Merkle tree inconsistencies    
    
2. **Fixed Issues**: Is this already fixed in current versions?    
   - Check git history for related fixes    
   - Verify if the report affects current mainnet codebase    
    
3. **Test Coverage**: Would existing tests catch this?    
   - Check `aptos-move/e2e-tests/`    
   - Review consensus test suites    
   - Examine Move specification tests in `*.spec.move` files    
    
**Test Case Realism Check**: PoCs must use realistic blockchain state, valid transactions, respect Move type system, and follow Aptos consensus rules.    
    
### **PHASE 3: IMPACT & EXPLOITABILITY VALIDATION (APTOS BUG BOUNTY ALIGNMENT)**    
    
#### **Impact Must Be CONCRETE and ALIGN WITH APTOS BUG BOUNTY CATEGORIES**    
    
**✅ Valid CRITICAL Severity Impacts (up to $1,000,000):**    
    
1. **Loss of Funds (Critical)**:    
   - Direct theft of APT or other tokens    
   - Unlimited minting capabilities    
   - Bypass of coin transfer restrictions    
   - Example: "Move VM bug allows unlimited APT minting"    
    
2. **Consensus/Safety Violations (Critical)**:    
   - Different validators commit different blocks    
   - Double-spending achievable with < 1/3 Byzantine    
   - Chain splits without hardfork requirement    
   - Example: "AptosBFT voting rule bypass enables double-spending"    
    
3. **Non-recoverable Network Partition (Critical)**:    
   - Network split requiring hardfork to resolve    
   - Permanent consensus divergence    
   - Example: "Epoch transition bug causes permanent partition"    
    
4. **Total Loss of Liveness/Network Availability (Critical)**:    
   - Network halts due to protocol bug    
   - All validators unable to progress    
   - Example: "Round manager deadlock stops all block production"    
    
5. **Permanent Freezing of Funds (Critical)**:    
   - Funds permanently inaccessible without hardfork    
   - Account or resource lockup without recovery    
   - Example: "State corruption freezes all user accounts"    
    
6. **Remote Code Execution on Validator Node (Critical)**:    
   - Complete validator compromise through vulnerability    
   - Arbitrary code execution in validator process    
   - Example: "Move native function bug allows RCE on validators"    
    
7. **Cryptographic Vulnerabilities (Critical)**:    
   - Practical breaks in BLS, VRF, or hash functions    
   - Signature forgery capabilities    
   - Example: "BLS aggregation flaw enables signature forgery"    
    
**✅ Valid HIGH Severity Impacts (up to $50,000):**    
    
8. **Validator Node Slowdowns (High)**:    
   - Significant performance degradation affecting consensus    
   - DoS through resource exhaustion    
   - Example: "Gas calculation bug causes validator slowdowns"    
    
9. **API Crashes (High)**:    
   - REST API crashes affecting network participation    
   - Transaction submission failures    
   - Example: "Malformed transaction crashes API nodes"    
    
**✅ Valid MEDIUM Severity Impacts (up to $10,000):**    
    
10. **Limited Protocol Violations**:    
    - State inconsistencies requiring manual intervention    
    - Limited funds loss or manipulation    
    - Temporary liveness issues    
    
**❌ Invalid "Impacts" (OUT OF SCOPE):**    
- Network DoS attacks (explicitly excluded)    
- Test/build infrastructure issues    
- Social engineering vulnerabilities    
- Performance optimizations without security impact    
- Minor gas overpayment (<0.1% of transaction)    
- Theoretical vulnerabilities without concrete exploit    
    
#### **Likelihood Reality Check**    
    
Assess exploit feasibility in Aptos context:    
    
1. **Attacker Profile**:    
   - Any Aptos user? ✅ Likely    
   - Move developer? ✅ Possible    
   - Network peer? ✅ Possible    
   - Validator? ⚠️ Higher access but still untrusted    
    
2. **Preconditions**:    
   - Normal network operation? ✅ High likelihood    
   - Specific epoch? ✅ Attacker can wait    
   - Specific Move module deployed? ✅ Attacker can deploy    
   - Specific governance state? ✅ Possible but not required    
    
3. **Execution Complexity**:    
   - Single transaction? ✅ Simple    
   - Multiple blocks? ✅ Moderate    
   - Complex Move interaction? ✅ Attacker can create    
   - Precise timing during epoch change? ⚠️ Higher complexity    
    
4. **Economic Cost**:    
   - Gas costs for attack? ✅ Attacker-controlled    
   - Stake requirements? ✅ Varies by attack    
   - Potential profit vs. cost? ✅ Must be positive    
   - Initial capital required? ✅ Varies by attack    
    
### **PHASE 4: FINAL VALIDATION CHECKLIST**    
    
Before accepting any vulnerability, verify:    
    
1. **Scope Compliance**: Vulnerability affects Aptos Core codebase (not tests/docs)    
2. **Not Known Issue**: Check against security advisories and git history    
3. **Trust Model**: Exploit doesn't require trusted role compromise    
4. **Impact Severity**: Meets Critical/High/Medium criteria per bounty program    
5. **Technical Feasibility**: Exploit can be reproduced without modifications    
6. **Consensus Impact**: Clearly breaks AptosBFT consensus or Move VM invariants    
7. **PoC Completeness**: Move test or Rust code compiles and runs successfully    
8. **Reproducibility**: Can be reproduced on current mainnet configuration    
9. **No Network DoS**: Explicitly excluded per bounty rules    
    
**Remember**: False positives harm credibility. Assume claims are invalid until overwhelming evidence proves otherwise.    
    
---    
    
**AUDIT REPORT FORMAT** (if vulnerability found):    
    
Audit Report    
    
## Title    
The Title Of the Report    
    
## Summary    
A short summary of the issue, keep it brief.    
    
## Finding Description    
A more detailed explanation of the issue. Poorly written or incorrect findings may result in rejection and a decrease of reputation score.    
    
Describe which security guarantees it breaks and how it breaks them. If this bug does not automatically happen, showcase how a malicious input would propagate through the system to the part of the code where the issue occurs.    
    
## Impact Explanation    
Elaborate on why you've chosen a particular impact assessment, referencing the Aptos bug bounty severity categories.    
    
## Likelihood Explanation    
Explain how likely this is to occur and why.    
    
## Recommendation    
How can the issue be fixed or solved. Preferably, you can also add a snippet of the fixed code here.    
    
## Proof of Concept    
A proof of concept demonstrating the vulnerability. Must be able to compile and run successfully. Use Move tests for Move-level issues and Rust tests for infrastructure issues.    
    
**Remember**: False positives harm credibility more than missed findings. Assume claims are invalid until overwhelming evidence proves otherwise.    
    
**Now perform STRICT validation of the claim above.**    
    
**Output ONLY:**    
- A full audit report (if genuinely valid after passing **all** checks above) following the specified format    
- `#NoVulnerability found for this question.` (if **any** check fails) very important    
- Note if u cant validate the claim or dont understand just send #NoVulnerability    
- Only show full report when u know this is actually and truly a   """
    return prompt


def question_generator(target_file: str) -> str:
    """
    Generates targeted security audit questions for a specific Aptos Core file.

    Args:
        target_file: The specific file path to focus question generation on
                    (e.g., "consensus/src/round_manager.rs" or "aptos-move/aptos-vm/src/aptos_vm.rs")

    Returns:
        A formatted prompt string for generating security questions
    """
    prompt = f"""  
# **Generate 150+ Targeted Security Audit Questions for Aptos Core**  
  
## **Context**  
  
The target project is **Aptos Core**, a high-performance Layer 1 blockchain implementing the AptosBFT consensus protocol and Move smart contract language. Aptos provides parallel execution, sub-second finality, and high throughput while maintaining security guarantees through Byzantine Fault Tolerant consensus.  
  
Aptos uses the Move programming language for smart contracts, which provides resource-oriented programming and formal verification capabilities. The blockchain maintains state through AptosDB with Jellyfish Merkle Trees and implements a comprehensive governance system for on-chain protocol upgrades.  
  
## **Scope**  
  
**CRITICAL TARGET FILE**: Focus question generation EXCLUSIVELY on `{target_file}`  
  
Note: The questions must be generated from **`{target_file}`** only. If you cannot generate enough questions from this single file, provide as many quality questions as you can extract from the file's logic and interactions. **DO NOT return empty results** - give whatever questions you can derive from the target file.  
  
If you cannot reach 150 questions from this file alone, generate as many high-quality questions as the file's complexity allows (minimum target: 50-100 questions for large critical files, 20-50 for smaller files).  
  
**Full Context - Critical Aptos Components (for reference only):**  
If a file is more than a thousand lines you can generate as many as 300+ questions as you can, but always generate as many as you can - don't give other responses.  
If there are cryptographic operations, math logic, or state transition functions, generate comprehensive questions covering all edge cases and attack vectors.  
  
### **Core Aptos Components**  
  
```python  
core_components = [  
    # Consensus Layer  
    "consensus/src/round_manager.rs",           # AptosBFT round management  
    "consensus/src/epoch_manager.rs",          # Epoch transition logic  
    "consensus/src/liveness/round_state.rs",   # Round state machine  
    "consensus/src/liveness/proposal_generator.rs", # Block proposal generation  
    "consensus/src/safety_rules.rs",           # Safety rule enforcement  
      
    # Execution Engine  
    "aptos-move/aptos-vm/src/aptos_vm.rs",     # AptosVM implementation  
    "aptos-move/aptos-vm/src/gas.rs",          # Gas metering  
    "aptos-move/aptos-vm/src/data_cache.rs",   # Data access layer  
    "aptos-move/aptos-vm/src/move_vm_ext/",    # MoveVM extensions  
      
    # Aptos Framework (Move)  
    "aptos-move/framework/aptos-framework/sources/aptos_governance.move", # Governance  
    "aptos-move/framework/aptos-framework/sources/stake.move",            # Staking  
    "aptos-move/framework/aptos-framework/sources/coin.move",             # Coin operations  
    "aptos-move/framework/aptos-framework/sources/transaction_validation.move", # TX validation  
    "aptos-move/framework/aptos-framework/sources/aptos_account.move",    # Account management  
      
    # Storage System  
    "storage/aptosdb/src/state_store/mod.rs",    # State store coordinator  
    "storage/aptosdb/src/state_merkle_db.rs",    # Jellyfish Merkle tree  
    "storage/aptosdb/src/state_kv_db.rs",        # Key-value storage  
    "storage/aptosdb/src/ledger_db/mod.rs",      # Transaction storage  
      
    # Network Layer  
    "network/src/network_interface.rs",          # P2P networking  
    "consensus/src/network.rs",                  # Consensus messaging  
    "mempool/src/mempool.rs",                    # Transaction pool  
      
    # API Layer  
    "api/src/transactions.rs",                   # Transaction API  
    "api/src/accounts.rs",                       # Account API  
    "api/src/state.rs",                          # State query API  
      
    # Types & Config  
    "types/src/validator_verifier.rs",           # Validator verification  
    "config/src/config/consensus_config.rs",     # Consensus configuration  
]
```
  
### **Aptos Architecture & Critical Security Layers**  
  
1. **Consensus Layer (AptosBFT)**  
   - **Validator Management**: Dynamic validator set through staking and governance  
   - **Block Proposal**: Rotating leader election with VRF-based randomness  
   - **Voting Rules**: 3-chain commit rule for safety guarantees  
   - **Epoch Management**: Periodic validator set updates and reconfiguration  
   - **Safety Rules**: Persistent safety data preventing double-signing  
   - **Byzantine Tolerance**: Secure with < 1/3 malicious validators  
  
2. **Execution Engine (AptosVM & Move)**  
   - **Transaction Execution**: Move bytecode execution with resource safety  
   - **Gas Metering**: Precise gas calculation preventing DoS  
   - **Parallel Execution**: Block-STM for concurrent transaction processing  
   - **State Commitment**: Jellyfish Merkle tree for state verification  
   - **Prologue/Epilogue**: Transaction validation and finalization  
   - **Resource Model**: Move's type-safe resource management  
  
3. **Storage System (AptosDB)**  
   - **State Storage**: Sharded key-value and Merkle tree storage  
   - **Pruning**: Configurable history pruning for storage efficiency  
   - **Snapshots**: State snapshots for fast synchronization  
   - **Buffered Writes**: Asynchronous commit pipeline  
   - **Merkle Proofs**: Cryptographic state verification  
  
4. **On-Chain Governance**  
   - **Proposal System**: Multi-step governance proposals  
   - **Voting Power**: Stake-based voting with delegation  
   - **Feature Flags**: Gradual feature rollout mechanism  
   - **Protocol Upgrades**: On-chain code deployment and upgrades  
   - **Treasury Management**: Community fund management  
  
5. **Staking System**  
   - **Validator Registration**: Stake requirements and performance bonds  
   - **Reward Distribution**: Inflation-based rewards and fees  
   - **Penalty System**: Slashing for misbehavior  
   - **Delegation**: Stake delegation to validators  
   - **Performance Tracking**: Validator performance monitoring  
  
### **Critical Security Invariants**  
  
**Consensus Security**  
- **Validator Authority**: Only authorized validators can propose blocks  
- **Block Signing**: Blocks must have valid quorum certificates  
- **Safety Guarantees**: No double-spending with < 1/3 Byzantine  
- **Liveness**: Network progresses with honest majority  
- **Epoch Transitions**: Safe validator set changes without forks  
  
**State Integrity**  
- **Deterministic Execution**: All validators produce identical state roots  
- **Resource Safety**: Move's resource model prevents double-spending  
- **Gas Consistency**: Gas calculations are deterministic across nodes  
- **Merkle Integrity**: State commitment matches actual state  
- **Atomic Transitions**: State changes are all-or-nothing  
  
**Transaction Security**  
- **Signature Validation**: All transactions require valid signatures  
- **Sequence Numbers**: Nonce-based replay protection  
- **Gas Limits**: Transactions cannot exceed gas limits  
- **Access Control**: System addresses are protected  
- **Type Safety**: Move's type system prevents invalid operations  
  
**Economic Security**  
- **Stake Requirements**: Economic barriers to validator entry  
- **Slashing Penalties**: Economic disincentives for misbehavior  
- **Reward Distribution**: Fair and predictable reward allocation  
- **Gas Economics**: Proper gas pricing for resource allocation  
- **Treasury Controls**: Community fund protection mechanisms  
  
### **In-Scope Vulnerability Categories (Aptos Bug Bounty)**  
  
**Critical Severity (up to $1,000,000)**  
- **Loss of Funds**: Direct theft or unlimited minting of APT/tokens  
- **Consensus/Safety Violations**: Double-spending, chain splits, safety breaks  
- **Network Partition**: Non-recoverable splits requiring hardfork  
- **Loss of Liveness**: Total network halt or unavailability  
- **Permanent Freezing**: Funds locked without recovery (requires hardfork)  
- **Remote Code Execution**: RCE on validator nodes  
- **Cryptographic Vulnerabilities**: Practical breaks in crypto primitives  
  
**High Severity (up to $50,000)**  
- **Validator Slowdowns**: Performance degradation affecting consensus  
- **API Crashes**: REST API failures affecting network participation  
- **Protocol Violations**: Significant consensus or implementation bugs  
  
**Medium Severity (up to $10,000)**  
- **Limited Funds Loss**: Small-scale theft or manipulation  
- **State Inconsistencies**: Recoverable state corruption issues  
  
**Out of Scope**  
- Network DoS attacks (explicitly excluded)  
- Social engineering vulnerabilities  
- Test/build infrastructure attacks  
- Performance optimizations without security impact  
  
### **Goals for Question Generation**  
  
- **Real Exploit Scenarios**: Each question describes a plausible attack by malicious validators, transaction senders, or network peers  
- **Concrete & Actionable**: Reference specific functions, structs, or logic flows in `{target_file}`  
- **High Impact**: Prioritize questions leading to Critical/High/Medium bounty impacts  
- **Deep Technical Detail**: Focus on subtle bugs: race conditions, consensus edge cases, state transitions, Move VM bugs  
- **Breadth Within Target File**: Cover all major functions and edge cases in `{target_file}`  
- **Respect Trust Model**: Assume validators may be Byzantine (< 1/3); focus on protocol security  
- **No Generic Questions**: Avoid "are there access control issues?" → Instead: "In `{target_file}: functionName()`, can attacker exploit X to cause Y?"  
  
### **Question Format Template**  
  
Each question MUST follow this Python list format:  
  
```python  
questions = [  
    "[File: {target_file}] [Function: functionName()] [Vulnerability Type] Specific question describing attack vector, preconditions, and impact with severity category?",  
      
    "[File: {target_file}] [Function: anotherFunction()] [Vulnerability Type] Another specific question with concrete exploit scenario?",  
      
    # ... continue with all generated questions  
]  
```  
  
**Example Format** (if target_file is consensus/src/round_manager.rs):  
  
```python  
questions = [  
    "[File: consensus/src/round_manager.rs] [Function: process_proposal()] [Consensus bypass] Can an attacker craft a malicious proposal with manipulated round numbers that bypasses voting rules, allowing them to commit conflicting blocks and cause double-spending? (Critical)",  
      
    "[File: consensus/src/round_manager.rs] [Function: process_vote()] [Safety violation] Does vote validation properly check for equivocation, or can a validator sign conflicting votes for different blocks at the same round, breaking AptosBFT safety guarantees? (Critical)",  
      
    "[File: consensus/src/round_manager.rs] [Function: handle_timeout()] [Liveness attack] Can timeout certificates be forged or manipulated to force unnecessary round changes, potentially halting consensus progress and causing total loss of liveness? (High)",  
      
    "[File: consensus/src/round_manager.rs] [Function: new_round()] [State inconsistency] Are round state transitions atomic, or can race conditions during concurrent round changes lead to inconsistent state across validators causing network partition? (High)",  
]  
```  
  
### **Output Requirements**  
  
Generate security audit questions focusing EXCLUSIVELY on `{target_file}` that:  
  
- **Target ONLY `{target_file}`** - all questions must reference this file  
- **Reference specific functions, methods, structs, or logic sections** within `{target_file}`  
- **Describe concrete attack vectors** (not "could there be a bug?" but "can attacker do X by exploiting Y in `{target_file}`?")  
- **Tie to impact categories** (consensus failure, fund loss, liveness issues, validator manipulation, state corruption)  
- **Include severity classification** (Critical/High/Medium/Low) based on Aptos bounty impact  
- **Respect trust model** (assume < 1/3 Byzantine validators; focus on protocol security)  
- **Cover diverse attack surfaces** within `{target_file}`: validation logic, state transitions, error handling, edge cases, concurrent access, cryptographic operations, integer math  
- **Focus on high-severity bugs**: prioritize Critical > High > Medium > Low  
- **Avoid out-of-scope issues**: network DoS, social engineering, performance optimizations  
- **Use the exact Python list format** shown above  
- **Be detailed and technical**: assume auditor has deep blockchain/Move knowledge  
- **Consider Rust/Move-specific issues**: race conditions, unsafe blocks, integer overflow, borrow checker issues, resource safety violations  
  
### **Target Question Count**  
  
- **Large critical files** (>1000 lines like aptos_vm.rs, round_manager.rs): Aim for 150-300 questions  
- **Medium files** (500-1000 lines like epoch_manager.rs, governance.move): Aim for 80-150 questions  
- **Smaller files** (<500 lines like config.rs, account.move): Aim for 30-80 questions  
- **Provide as many quality questions as the file's complexity allows** - do NOT return empty results  
  
### **Special Considerations for Aptos Code**  
  
- **Rust concurrency**: Race conditions in async/await, Arc/Mutex usage, channel operations  
- **Move VM**: Bytecode interpretation bugs, gas metering errors, resource access violations  
- **Consensus timing**: Timeout handling, round synchronization, leader election  
- **State storage**: Merkle tree inconsistencies, sharding issues, snapshot corruption  
- **Cryptography**: BLS signature aggregation, VRF randomness, hash collisions  
- **Governance**: Voting power calculation, proposal execution, feature flag abuse  
- **Staking**: Reward calculation errors, validator set manipulation, performance tracking  
  
Begin generating questions for `{target_file}` now.  
"""
    return prompt
