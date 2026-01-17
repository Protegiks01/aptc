import json

BASE_URL = "https://deepwiki.com/whitebit-exchange/wbt"


def get_questions():
    try:
        with open("all_questions.json", "r") as f:
            return json.load(f)

    except:
        return []


questions = get_questions()

questions_generator  = [
    "accounts/abi/abi.go",
    "accounts/abi/argument.go",
    "accounts/abi/bind/auth.go",
    "accounts/abi/bind/backend.go",
    "accounts/abi/bind/base.go",
    "accounts/abi/bind/bind.go",
    "accounts/abi/bind/util.go",
    "accounts/abi/error_handling.go",
    "accounts/abi/error.go",
    "accounts/abi/event.go",
    "accounts/abi/method.go",
    "accounts/abi/pack.go",
    "accounts/abi/reflect.go",
    "accounts/abi/selector_parser.go",
    "accounts/abi/topics.go",
    "accounts/abi/type.go",
    "accounts/abi/unpack.go",
    "accounts/abi/utils.go",
    "accounts/accounts.go",
    "accounts/errors.go",
    "accounts/external/backend.go",
    "accounts/hd.go",
    "accounts/keystore/account_cache.go",
    "accounts/keystore/file_cache.go",
    "accounts/keystore/key.go",
    "accounts/keystore/keystore.go",
    "accounts/keystore/passphrase.go",
    "accounts/keystore/plain.go",
    "accounts/keystore/presale.go",
    "accounts/keystore/wallet.go",
    "accounts/keystore/watch_fallback.go",
    "accounts/keystore/watch.go",
    "accounts/manager.go",
    "accounts/scwallet/apdu.go",
    "accounts/scwallet/hub.go",
    "accounts/scwallet/securechannel.go",
    "accounts/scwallet/wallet.go",
    "accounts/sort.go",
    "accounts/url.go",
    "accounts/usbwallet/hub.go",
    "accounts/usbwallet/ledger.go",
    "accounts/usbwallet/trezor.go",
    "accounts/usbwallet/trezor/trezor.go",
    "accounts/usbwallet/wallet.go",
    "beacon/engine/errors.go",
    "beacon/engine/types.go",
    "cmd/clef/main.go",
    "cmd/geth/accountcmd.go",
    "cmd/geth/chaincmd.go",
    "cmd/geth/config.go",
    "cmd/geth/consolecmd.go",
    "cmd/geth/dbcmd.go",
    "cmd/geth/main.go",
    "cmd/geth/misccmd.go",
    "cmd/geth/snapshot.go",
    "cmd/geth/verkle.go",
    "cmd/geth/version_check.go",
    "common/big.go",
    "common/bitutil/bitutil.go",
    "common/bitutil/compress.go",
    "common/bytes.go",
    "common/compiler/helpers.go",
    "common/compiler/solidity.go",
    "common/debug.go",
    "common/fdlimit/fdlimit_unix.go",
    "common/format.go",
    "common/hexutil/hexutil.go",
    "common/hexutil/json.go",
    "common/lru/basiclru.go",
    "common/lru/blob_lru.go",
    "common/lru/lru.go",
    "common/math/big.go",
    "common/math/integer.go",
    "common/mclock/alarm.go",
    "common/mclock/mclock.go",
    "common/path.go",
    "common/prque/lazyqueue.go",
    "common/prque/prque.go",
    "common/prque/sstack.go",
    "common/size.go",
    "common/types.go",
    "consensus/beacon/consensus.go",
    "consensus/clique/api.go",
    "consensus/clique/clique.go",
    "consensus/clique/snapshot.go",
    "consensus/consensus.go",
    "consensus/errors.go",
    "consensus/ethash/algorithm.go",
    "consensus/ethash/api.go",
    "consensus/ethash/consensus.go",
    "consensus/ethash/difficulty.go",
    "consensus/ethash/ethash.go",
    "consensus/ethash/mmap_help_other.go",
    "consensus/ethash/sealer.go",
    "consensus/merger.go",
    "consensus/misc/dao.go",
    "consensus/misc/eip1559.go",
    "consensus/misc/eip4844.go",
    "consensus/misc/gaslimit.go",
    "console/bridge.go",
    "console/console.go",
    "console/prompt/prompter.go",
    "contracts/checkpointoracle/contract/oracle.go",
    "contracts/checkpointoracle/oracle.go",
    "core/asm/asm.go",
    "core/asm/compiler.go",
    "core/asm/lexer.go",
    "core/block_validator.go",
    "core/blockchain_insert.go",
    "core/blockchain_reader.go",
    "core/blockchain.go",
    "core/blocks.go",
    "core/bloom_indexer.go",
    "core/bloombits/generator.go",
    "core/bloombits/matcher.go",
    "core/bloombits/scheduler.go",
    "core/chain_indexer.go",
    "core/chain_makers.go",
    "core/error.go",
    "core/events.go",
    "core/evm.go",
    "core/forkchoice.go",
    "core/forkid/forkid.go",
    "core/gaspool.go",
    "core/genesis_alloc.go",
    "core/genesis.go",
    "core/headerchain.go",
    "core/mint/contract.go",
    "core/mint/strings.go",
    "core/mkalloc.go",
    "core/rawdb/accessors_chain.go",
    "core/rawdb/accessors_indexes.go",
    "core/rawdb/accessors_metadata.go",
    "core/rawdb/accessors_snapshot.go",
    "core/rawdb/accessors_state.go",
    "core/rawdb/accessors_sync.go",
    "core/rawdb/accessors_trie.go",
    "core/rawdb/ancient_scheme.go",
    "core/rawdb/ancient_utils.go",
    "core/rawdb/chain_freezer.go",
    "core/rawdb/chain_iterator.go",
    "core/rawdb/database.go",
    "core/rawdb/databases_non64bit.go",
    "core/rawdb/freezer_batch.go",
    "core/rawdb/freezer_meta.go",
    "core/rawdb/freezer_resettable.go",
    "core/rawdb/freezer_table.go",
    "core/rawdb/freezer_utils.go",
    "core/rawdb/freezer.go",
    "core/rawdb/key_length_iterator.go",
    "core/rawdb/schema.go",
    "core/rawdb/table.go",
    "core/sender_cacher.go",
    "core/state_prefetcher.go",
    "core/state_processor.go",
    "core/state_transition.go",
    "core/state/access_list.go",
    "core/state/database.go",
    "core/state/dump.go",
    "core/state/iterator.go",
    "core/state/journal.go",
    "core/state/metrics.go",
    "core/state/migrations.go",
    "core/state/migrations/cassiopeia.go",
    "core/state/migrations/mint_contract.go",
    "core/state/pruner/bloom.go",
    "core/state/pruner/pruner.go",
    "core/state/snapshot/account.go",
    "core/state/snapshot/context.go",
    "core/state/snapshot/conversion.go",
    "core/state/snapshot/difflayer.go",
    "core/state/snapshot/disklayer.go",
    "core/state/snapshot/generate.go",
    "core/state/snapshot/holdable_iterator.go",
    "core/state/snapshot/iterator_binary.go",
    "core/state/snapshot/iterator_fast.go",
    "core/state/snapshot/iterator.go",
    "core/state/snapshot/journal.go",
    "core/state/snapshot/metrics.go",
    "core/state/snapshot/snapshot.go",
    "core/state/snapshot/sort.go",
    "core/state/snapshot/utils.go",
    "core/state/state_object.go",
    "core/state/statedb.go",
    "core/state/sync.go",
    "core/state/transient_storage.go",
    "core/state/trie_prefetcher.go",
    "core/txpool/journal.go",
    "core/txpool/list.go",
    "core/txpool/noncer.go",
    "core/txpool/txpool.go",
    "core/types.go",
    "core/types/block.go",
    "core/types/bloom9.go",
    "core/types/hashes.go",
    "core/types/hashing.go",
    "core/types/log.go",
    "core/types/receipt.go",
    "core/types/state_account.go",
    "core/types/transaction_marshalling.go",
    "core/types/transaction_signing.go",
    "core/types/transaction.go",
    "core/types/tx_access_list.go",
    "core/types/tx_dynamic_fee.go",
    "core/types/tx_legacy.go",
    "core/types/withdrawal.go",
    "core/vm/analysis.go",
    "core/vm/common.go",
    "core/vm/contract.go",
    "core/vm/contracts.go",
    "core/vm/eips.go",
    "core/vm/errors.go",
    "core/vm/evm.go",
    "core/vm/gas_table.go",
    "core/vm/gas.go",
    "core/vm/instructions.go",
    "core/vm/interface.go",
    "core/vm/interpreter.go",
    "core/vm/jump_table_export.go",
    "core/vm/jump_table.go",
    "core/vm/logger.go",
    "core/vm/memory_table.go",
    "core/vm/memory.go",
    "core/vm/opcodes.go",
    "core/vm/operations_acl.go",
    "core/vm/runtime/env.go",
    "core/vm/runtime/runtime.go",
    "core/vm/stack_table.go",
    "core/vm/stack.go",
    "crypto/blake2b/blake2b_generic.go",
    "crypto/blake2b/blake2b_ref.go",
    "crypto/blake2b/blake2b.go",
    "crypto/blake2b/blake2x.go",
    "crypto/blake2b/register.go",
    "crypto/bls12381/arithmetic_decl.go",
    "crypto/bls12381/arithmetic_fallback.go",
    "crypto/bls12381/bls12_381.go",
    "crypto/bls12381/field_element.go",
    "crypto/bls12381/fp.go",
    "crypto/bls12381/fp12.go",
    "crypto/bls12381/fp2.go",
    "crypto/bls12381/fp6.go",
    "crypto/bls12381/g1.go",
    "crypto/bls12381/g2.go",
    "crypto/bls12381/gt.go",
    "crypto/bls12381/isogeny.go",
    "crypto/bls12381/pairing.go",
    "crypto/bls12381/swu.go",
    "crypto/bls12381/utils.go",
    "crypto/bn256/bn256_slow.go",
    "crypto/bn256/cloudflare/bn256.go",
    "crypto/bn256/cloudflare/constants.go",
    "crypto/bn256/cloudflare/curve.go",
    "crypto/bn256/cloudflare/gfp_decl.go",
    "crypto/bn256/cloudflare/gfp_generic.go",
    "crypto/bn256/cloudflare/gfp.go",
    "crypto/bn256/cloudflare/gfp12.go",
    "crypto/bn256/cloudflare/gfp2.go",
    "crypto/bn256/cloudflare/gfp6.go",
    "crypto/bn256/cloudflare/lattice.go",
    "crypto/bn256/cloudflare/optate.go",
    "crypto/bn256/cloudflare/twist.go",
    "crypto/bn256/google/bn256.go",
    "crypto/bn256/google/constants.go",
    "crypto/bn256/google/curve.go",
    "crypto/bn256/google/gfp12.go",
    "crypto/bn256/google/gfp2.go",
    "crypto/bn256/google/gfp6.go",
    "crypto/bn256/google/optate.go",
    "crypto/bn256/google/twist.go",
    "crypto/crypto.go",
    "crypto/ecies/ecies.go",
    "crypto/ecies/params.go",
    "crypto/secp256k1/curve.go",
    "crypto/secp256k1/panic_cb.go",
    "crypto/secp256k1/scalar_mult_nocgo.go",
    "crypto/secp256k1/secp256.go",
    "crypto/signature_nocgo.go",
    "crypto/signify/signify.go",
    "eth/api_backend.go",
    "eth/api.go",
    "eth/backend.go",
    "eth/bloombits.go",
    "eth/catalyst/api.go",
    "eth/catalyst/queue.go",
    "eth/catalyst/tester.go",
    "eth/downloader/api.go",
    "eth/downloader/beaconsync.go",
    "eth/downloader/downloader.go",
    "eth/downloader/events.go",
    "eth/downloader/fetchers_concurrent_bodies.go",
    "eth/downloader/fetchers_concurrent_headers.go",
    "eth/downloader/fetchers_concurrent_receipts.go",
    "eth/downloader/fetchers_concurrent.go",
    "eth/downloader/fetchers.go",
    "eth/downloader/metrics.go",
    "eth/downloader/modes.go",
    "eth/downloader/peer.go",
    "eth/downloader/queue.go",
    "eth/downloader/resultstore.go",
    "eth/downloader/skeleton.go",
    "eth/downloader/statesync.go",
    "eth/ethconfig/config.go",
    "eth/fetcher/block_fetcher.go",
    "eth/fetcher/tx_fetcher.go",
    "eth/filters/api.go",
    "eth/filters/filter_system.go",
    "eth/filters/filter.go",
    "eth/gasprice/feehistory.go",
    "eth/gasprice/gasprice.go",
    "eth/handler_eth.go",
    "eth/handler_snap.go",
    "eth/handler.go",
    "eth/peer.go",
    "eth/peerset.go",
    "eth/protocols/eth/broadcast.go",
    "eth/protocols/eth/discovery.go",
    "eth/protocols/eth/dispatcher.go",
    "eth/protocols/eth/handler.go",
    "eth/protocols/eth/handlers.go",
    "eth/protocols/eth/handshake.go",
    "eth/protocols/eth/peer.go",
    "eth/protocols/eth/protocol.go",
    "eth/protocols/eth/tracker.go",
    "eth/protocols/snap/discovery.go",
    "eth/protocols/snap/handler.go",
    "eth/protocols/snap/peer.go",
    "eth/protocols/snap/protocol.go",
    "eth/protocols/snap/range.go",
    "eth/protocols/snap/sync.go",
    "eth/protocols/snap/tracker.go",
    "eth/state_accessor.go",
    "eth/sync.go",
    "eth/tracers/api.go",
    "eth/tracers/js/bigint.go",
    "eth/tracers/js/goja.go",
    "eth/tracers/js/internal/tracers/tracers.go",
    "eth/tracers/logger/access_list_tracer.go",
    "eth/tracers/logger/logger_json.go",
    "eth/tracers/logger/logger.go",
    "eth/tracers/native/4byte.go",
    "eth/tracers/native/call_flat.go",
    "eth/tracers/native/call.go",
    "eth/tracers/native/mux.go",
    "eth/tracers/native/noop.go",
    "eth/tracers/native/prestate.go",
    "eth/tracers/tracers.go",
    "eth/tracers/tracker.go",
    "ethclient/ethclient.go",
    "ethclient/gethclient/gethclient.go",
    "ethclient/signer.go",
    "ethdb/batch.go",
    "ethdb/database.go",
    "ethdb/iterator.go",
    "ethdb/leveldb/leveldb.go",
    "ethdb/memorydb/memorydb.go",
    "ethdb/pebble/pebble.go",
    "ethdb/remotedb/remotedb.go",
    "ethdb/snapshot.go",
    "ethstats/ethstats.go",
    "event/event.go",
    "event/feed.go",
    "event/feedof.go",
    "event/subscription.go",
    "graphql/graphql.go",
    "graphql/schema.go",
    "graphql/service.go",
    "interfaces.go",
    "internal/debug/api.go",
    "internal/debug/flags.go",
    "internal/debug/loudpanic_fallback.go",
    "internal/debug/loudpanic.go",
    "internal/debug/trace_fallback.go",
    "internal/debug/trace.go",
    "internal/ethapi/addrlock.go",
    "internal/ethapi/api.go",
    "internal/ethapi/backend.go",
    "internal/ethapi/dbapi.go",
    "internal/ethapi/transaction_args.go",
    "internal/flags/categories.go",
    "internal/flags/flags.go",
    "internal/flags/helpers.go",
    "internal/guide/guide.go",
    "internal/jsre/completion.go",
    "internal/jsre/deps/deps.go",
    "internal/jsre/jsre.go",
    "internal/jsre/pretty.go",
    "internal/shutdowncheck/shutdown_tracker.go",
    "internal/syncx/mutex.go",
    "internal/version/vcs.go",
    "internal/version/version.go",
    "internal/web3ext/web3ext.go",
    "les/api_backend.go",
    "les/api.go",
    "les/benchmark.go",
    "les/bloombits.go",
    "les/catalyst/api.go",
    "les/checkpointoracle/oracle.go",
    "les/client_handler.go",
    "les/client.go",
    "les/commons.go",
    "les/costtracker.go",
    "les/distributor.go",
    "les/downloader/api.go",
    "les/downloader/downloader.go",
    "les/downloader/events.go",
    "les/downloader/metrics.go",
    "les/downloader/modes.go",
    "les/downloader/peer.go",
    "les/downloader/queue.go",
    "les/downloader/resultstore.go",
    "les/downloader/statesync.go",
    "les/downloader/types.go",
    "les/enr_entry.go",
    "les/fetcher.go",
    "les/fetcher/block_fetcher.go",
    "les/flowcontrol/control.go",
    "les/flowcontrol/logger.go",
    "les/flowcontrol/manager.go",
    "les/metrics.go",
    "les/odr_requests.go",
    "les/odr.go",
    "les/peer.go",
    "les/protocol.go",
    "les/pruner.go",
    "les/retrieve.go",
    "les/server_handler.go",
    "les/server_requests.go",
    "les/server.go",
    "les/servingqueue.go",
    "les/state_accessor.go",
    "les/sync.go",
    "les/txrelay.go",
    "les/ulc.go",
    "les/utils/exec_queue.go",
    "les/utils/exec_queue.go",
    "les/utils/expiredvalue.go",
    "les/utils/limiter.go",
    "les/utils/timeutils.go",
    "les/utils/weighted_select.go",
    "les/vflux/client/api.go",
    "les/vflux/client/fillset.go",
    "les/vflux/client/queueiterator.go",
    "les/vflux/client/requestbasket.go",
    "les/vflux/client/serverpool.go",
    "les/vflux/client/timestats.go",
    "les/vflux/client/valuetracker.go",
    "les/vflux/client/wrsiterator.go",
    "les/vflux/requests.go",
    "les/vflux/server/balance_tracker.go",
    "les/vflux/server/balance.go",
    "les/vflux/server/clientdb.go",
    "les/vflux/server/clientpool.go",
    "les/vflux/server/metrics.go",
    "les/vflux/server/prioritypool.go",
    "les/vflux/server/service.go",
    "les/vflux/server/status.go",
    "light/lightchain.go",
    "light/nodeset.go",
    "light/odr_util.go",
    "light/odr.go",
    "light/postprocess.go",
    "light/trie.go",
    "light/txpool.go",
    "log/format.go",
    "log/handler_glog.go",
    "log/handler_go13.go",
    "log/handler_go14.go",
    "log/handler.go",
    "log/logger.go",
    "log/root.go",
    "log/syslog.go",
    "metrics/config.go",
    "metrics/counter_float64.go",
    "metrics/counter.go",
    "metrics/cpu_enabled.go",
    "metrics/cpu.go",
    "metrics/cputime_unix.go",
    "metrics/debug.go",
    "metrics/disk.go",
    "metrics/ewma.go",
    "metrics/exp/exp.go",
    "metrics/gauge_float64.go",
    "metrics/gauge.go",
    "metrics/graphite.go",
    "metrics/healthcheck.go",
    "metrics/histogram.go",
    "metrics/influxdb/influxdb.go",
    "metrics/influxdb/influxdbv1.go",
    "metrics/influxdb/influxdbv2.go",
    "metrics/json.go",
    "metrics/librato/client.go",
    "metrics/librato/librato.go",
    "metrics/log.go",
    "metrics/meter.go",
    "metrics/metrics.go",
    "metrics/opentsdb.go",
    "metrics/prometheus/collector.go",
    "metrics/prometheus/prometheus.go",
    "metrics/registry.go",
    "metrics/resetting_sample.go",
    "metrics/resetting_timer.go",
    "metrics/runtimehistogram.go",
    "metrics/sample.go",
    "metrics/syslog.go",
    "metrics/timer.go",
    "metrics/writer.go",
    "miner/miner.go",
    "miner/payload_building.go",
    "miner/unconfirmed.go",
    "miner/worker.go",
    "node/api.go",
    "node/config.go",
    "node/defaults.go",
    "node/endpoints.go",
    "node/errors.go",
    "node/jwt_auth.go",
    "node/jwt_handler.go",
    "node/lifecycle.go",
    "node/node.go",
    "node/rpcstack.go",
    "p2p/dial.go",
    "p2p/discover/common.go",
    "p2p/discover/lookup.go",
    "p2p/discover/node.go",
    "p2p/discover/ntp.go",
    "p2p/discover/table.go",
    "p2p/discover/v4_udp.go",
    "p2p/discover/v4wire/v4wire.go",
    "p2p/discover/v5_udp.go",
    "p2p/discover/v5wire/crypto.go",
    "p2p/discover/v5wire/encoding.go",
    "p2p/discover/v5wire/msg.go",
    "p2p/discover/v5wire/session.go",
    "p2p/dnsdisc/client.go",
    "p2p/dnsdisc/error.go",
    "p2p/dnsdisc/sync.go",
    "p2p/dnsdisc/tree.go",
    "p2p/enode/idscheme.go",
    "p2p/enode/iter.go",
    "p2p/enode/localnode.go",
    "p2p/enode/node.go",
    "p2p/enode/nodedb.go",
    "p2p/enode/urlv4.go",
    "p2p/enr/enr.go",
    "p2p/enr/entries.go",
    "p2p/message.go",
    "p2p/metrics.go",
    "p2p/msgrate/msgrate.go",
    "p2p/nat/nat.go",
    "p2p/nat/natpmp.go",
    "p2p/nat/natupnp.go",
    "p2p/netutil/addrutil.go",
    "p2p/netutil/error.go",
    "p2p/netutil/iptrack.go",
    "p2p/netutil/net.go",
    "p2p/netutil/toobig_windows.go",
    "p2p/nodestate/nodestate.go",
    "p2p/peer_error.go",
    "p2p/peer.go",
    "p2p/protocol.go",
    "p2p/rlpx/buffer.go",
    "p2p/rlpx/rlpx.go",
    "p2p/server.go",
    "p2p/tracker/tracker.go",
    "p2p/transport.go",
    "p2p/util.go",
    "params/bootnodes.go",
    "params/config.go",
    "params/dao.go",
    "params/denomination.go",
    "params/network_params.go",
    "params/protocol_params.go",
    "params/version.go",
    "rlp/decode.go",
    "rlp/encbuffer.go",
    "rlp/encode.go",
    "rlp/internal/rlpstruct/rlpstruct.go",
    "rlp/iterator.go",
    "rlp/raw.go",
    "rlp/safe.go",
    "rlp/typecache.go",
    "rlp/unsafe.go",
    "rpc/client_opt.go",
    "rpc/client.go",
    "rpc/constants_unix.go",
    "rpc/context_headers.go",
    "rpc/endpoints.go",
    "rpc/errors.go",
    "rpc/handler.go",
    "rpc/http.go",
    "rpc/inproc.go",
    "rpc/ipc_unix.go",
    "rpc/ipc.go",
    "rpc/json.go",
    "rpc/metrics.go",
    "rpc/server.go",
    "rpc/service.go",
    "rpc/stdio.go",
    "rpc/subscription.go",
    "rpc/types.go",
    "rpc/websocket.go",
    "signer/core/api.go",
    "signer/core/apitypes/types.go",
    "signer/core/auditlog.go",
    "signer/core/cliui.go",
    "signer/core/gnosis_safe.go",
    "signer/core/signed_data.go",
    "signer/core/stdioui.go",
    "signer/core/uiapi.go",
    "signer/core/validation.go",
    "signer/fourbyte/abi.go",
    "signer/fourbyte/fourbyte.go",
    "signer/fourbyte/validation.go",
    "signer/rules/rules.go",
    "signer/storage/aes_gcm_storage.go",
    "signer/storage/storage.go",
    "trie/committer.go",
    "trie/database.go",
    "trie/encoding.go",
    "trie/errors.go",
    "trie/hasher.go",
    "trie/iterator.go",
    "trie/node_enc.go",
    "trie/node.go",
    "trie/nodeset.go",
    "trie/preimages.go",
    "trie/proof.go",
    "trie/secure_trie.go",
    "trie/stacktrie.go",
    "trie/sync.go",
    "trie/tracer.go",
    "trie/trie_id.go",
    "trie/trie_reader.go",
    "trie/trie.go"
]

def question_format(question: str) -> str:
    """
    Generates a comprehensive security audit prompt for Go Ethereum Client.

    Args:
        question: A specific security question to investigate

    Returns:
        A formatted prompt string for vulnerability analysis
    """
    prompt = f"""    
You are an **Elite Ethereum Client Security Auditor** specializing in     
consensus vulnerabilities, denial-of-service attacks, EVM implementation bugs,     
and network protocol security. Your task is to analyze the **Go Ethereum (Geth)**     
codebase—the official Ethereum execution client—through the lens of this single security question:     
    
**Security Question (scope for this run):** {question}    
    
**GETH CLIENT CONTEXT:**    
    
**Architecture**: Geth is the most widely used Ethereum execution client, responsible for     
block validation, transaction execution, state management, and peer-to-peer networking.     
It implements the Ethereum Virtual Machine (EVM), handles consensus rules, and maintains     
the blockchain state. Critical components include the EVM interpreter, state trie,     
network protocol handlers, and mining subsystem.    
    
Think in invariant violations    
Check every logic entry that could affect consensus or node security based on the question provided     
Look at the exact files provided and other places also if they can cause severe vulnerabilities     
Think in an elite way because there is always a logic vulnerability that could occur    
    
**Key Components**:     
    
* **EVM Implementation**: `core/vm/` (EVM interpreter, precompiles, gas calculation),     
  `core/state/` (state management, trie operations), `core/` (block processing, transaction execution)    
    
* **Network Layer**: `p2p/` (peer discovery, protocol negotiation), `eth/` (eth protocol handler),     
  `snap/` (snapshot protocol), `les/` (light client protocol)    
    
* **Mining & Consensus**: `miner/` (block mining, work submission), `consensus/` (consensus engines)    
    
* **Precompiles**: `core/vm/contracts.go` (native contract implementations)    
    
**Files in Scope**: All source files in the repository, excluding test files and documentation.     
Focus on core execution, networking, and consensus components.    
    
**CRITICAL INVARIANTS (derived from Ethereum specification and Geth implementation):**    
    
1. **Deterministic Execution**: All nodes must produce identical state roots for identical blocks    
2. **Gas Accounting**: Total gas consumed must never exceed block gas limit or transaction gas limit    
3. **Memory Safety**: No buffer overflows, underflows, or out-of-bounds accesses in EVM operations    
4. **Consensus Rules**: Block validation must enforce all Ethereum consensus rules strictly    
5. **Network Protocol Compliance**: P2P messages must be validated according to protocol specifications    
6. **State Consistency**: State transitions must be atomic and reversible on failure    
7. **Precompile Security**: Precompiled contracts must handle edge cases safely    
8. **Access Control**: Administrative functions must be properly protected    
9. **Resource Limits**: All operations must respect memory, CPU, and network limits    
10. **Cryptographic Correctness**: All cryptographic operations must be implemented correctly    
    
**YOUR INVESTIGATION MISSION:**    
    
Accept the premise of the security question and explore **all** relevant     
code paths, data structures, state transitions, and system interactions related to it.     
Trace execution flows through transaction processing → EVM execution → state updates →     
block validation → network propagation.    
    
Your goal is to find **one** concrete, exploitable vulnerability tied to     
the question that an attacker, malicious peer, or transaction sender could exploit.     
Focus on:     
    
* Consensus violations (state root mismatches, block validation bypasses)    
* EVM implementation bugs (incorrect opcode behavior, gas calculation errors)    
* Memory corruption (buffer overflows, use-after-free, race conditions)    
* Network protocol attacks (malicious peer handling, DoS vulnerabilities)    
* Precompile vulnerabilities (edge cases, overflow/underflow, incorrect results)    
* State manipulation bugs (trie corruption, storage inconsistencies)    
* Access control bypasses (admin function exposure, privilege escalation)    
* Resource exhaustion attacks (memory bombs, CPU DoS, network flooding)    
* Cryptographic weaknesses (hash collisions, signature verification bugs)    
* Mining vulnerabilities (block manipulation, reward calculation errors)    
    
**ATTACK SURFACE EXPLORATION:**    
    
1. **EVM Operations** (`core/vm/`):    
   - Incorrect opcode implementations causing consensus splits    
   - Gas calculation miscalculations enabling DoS or free computation    
   - Stack/memory/storage manipulation bugs    
   - Precompile vulnerabilities in native contracts    
   - Reentrancy and call depth handling errors    
    
2. **Transaction Processing** (`core/`):    
   - Transaction validation bypasses    
   - Signature verification vulnerabilities    
   - Nonce handling errors    
   - Gas price manipulation opportunities    
   - Access list processing bugs    
    
3. **Network Protocol** (`p2p/`, `eth/`, `snap/`):    
   - Malicious message handling leading to crashes or corruption    
   - Peer authentication bypasses    
   - Protocol downgrade attacks    
   - Resource exhaustion through malicious peers    
   - Message flooding and amplification attacks    
    
4. **State Management** (`core/state/`):    
   - Trie manipulation vulnerabilities    
   - Storage slot corruption    
   - State root calculation errors    
   - Account state inconsistencies    
   - Contract creation/destruction bugs    
    
5. **Block Processing** (`core/`):    
   - Block validation bypasses    
   - Uncle handling vulnerabilities    
   - Difficulty calculation errors    
   - Reward distribution bugs    
   - Gas limit manipulation    
    
6. **Mining Operations** (`miner/`):    
   - Block manipulation opportunities    
   - Work submission vulnerabilities    
   - Mining pool coordination attacks    
   - Reward calculation exploits    
    
**GETH-SPECIFIC ATTACK VECTORS:**    
    
- **RETURNDATA Corruption**: Can attackers trigger memory corruption in EVM operations like the historical datacopy vulnerability?    
- **Consensus Split Exploits**: Can malicious transactions cause different nodes to compute different state roots?    
- **Precompile Edge Cases**: Can attackers exploit boundary conditions in precompiled contracts?    
- **Network DoS Attacks**: Can malicious peers crash nodes through crafted protocol messages?    
- **Gas Calculation Bugs**: Can attackers bypass gas limits or cause undercharging?    
- **State Trie Manipulation**: Can attackers corrupt the state trie or cause inconsistencies?    
- **Mining Reward Exploits**: Can attackers manipulate block rewards or uncle rewards?    
- **Memory Safety Issues**: Can attackers trigger buffer overflows or use-after-free bugs?    
- **Cryptographic Failures**: Can attackers exploit weaknesses in hash or signature verification?    
- **Protocol Upgrade Bugs**: Can attackers exploit vulnerabilities during network upgrades?    
    
**TRUST MODEL:**    
    
**Trusted Roles**: Ethereum core developers, client release managers, reputable miners.     
Do **not** assume these actors behave maliciously unless the question explicitly explores insider threats.    
    
**Untrusted Actors**: Any peer on the network, transaction sender, contract deployer, or     
malicious actor attempting to exploit client vulnerabilities. Focus on bugs exploitable     
without requiring privileged access or collusion.    
    
**KNOWN ISSUES / EXCLUSIONS:**    
    
- Cryptographic primitives (Go standard library crypto functions) are assumed secure    
- Network-level attacks (DDoS, BGP hijacking) at infrastructure level    
- Social engineering, phishing, or key theft    
- Performance optimizations unless they introduce security vulnerabilities    
- Code style, documentation, or non-critical bugs    
- Test file issues (tests are out of scope)    
- Economic attacks requiring market manipulation    
- 51% attacks or hash power attacks    
    
**VALID IMPACT CATEGORIES:**    
    
**Critical Severity**:    
- Chain splits or consensus failures    
- Remote code execution or complete node compromise    
- Unlimited funds theft or creation    
- Network-wide DoS affecting majority of nodes    
    
**High Severity**:    
- Single node compromise or crash    
- Transaction replay or double-spending    
- Significant funds loss (user or protocol)    
- Partial network disruption    
    
**Medium Severity**:    
- Resource exhaustion attacks    
- State inconsistency requiring manual intervention    
- Limited funds loss or manipulation    
- Protocol violations not causing consensus failure    
    
**Low Severity**:    
- Minor information leaks    
- Non-critical DoS affecting limited functionality    
- Minor implementation bugs without security impact    
    
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
- Proof of Concept (Go test or reproduction steps)    
    
If **no** valid vulnerability emerges after thorough investigation, state exactly:     
`#NoVulnerability found for this question.`    
    
**Do not fabricate or exaggerate issues.** Only concrete, exploitable bugs with     
clear attack paths and realistic impact count.    
    
**VALIDATION CHECKLIST (Before Reporting):**    
- [ ] Vulnerability lies within the Geth codebase (not tests or docs)    
- [ ] Exploitable by unprivileged attacker (no insider access required)    
- [ ] Attack path is realistic with correct parameters and feasible execution    
- [ ] Impact meets Critical, High, or Medium severity criteria    
- [ ] PoC can be implemented as Go test or clear reproduction steps    
- [ ] Issue breaks at least one documented invariant    
- [ ] Not a known issue from previous security audits    
- [ ] Clear security harm demonstrated (consensus, funds, availability)    
    
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
Elaborate on why you've chosen a particular impact assessment.    
    
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
    Generates a comprehensive validation prompt for Go Ethereum Client security claims.

    Args:
        report: A security vulnerability report to validate

    Returns:
        A formatted validation prompt string for ruthless technical scrutiny
    """
    prompt = f"""  
You are an **Elite Ethereum Client Security Judge** with deep expertise in consensus vulnerabilities, EVM implementation bugs, network protocol security, and blockchain client validation. Your ONLY task is **ruthless technical validation** of security claims against the Go Ethereum (Geth) codebase.  
  
Note: Ethereum core developers, client release managers, and reputable miners are trusted roles.  
  
**SECURITY CLAIM TO VALIDATE:**  
{report}  
  
================================================================================  
## **GETH CLIENT VALIDATION FRAMEWORK**  
  
### **PHASE 1: IMMEDIATE DISQUALIFICATION CHECKS**  
Reject immediately (`#NoVulnerability`) if **ANY** apply:  
  
#### **A. Scope Violations**  
- ❌ Affects files **not** in the Geth source code (`core/`, `eth/`, `p2p/`, `miner/`, `consensus/`, `cmd/`)  
- ❌ Targets any file under test directories (`*_test.go`, `testdata/`) - tests are out of scope  
- ❌ Claims about documentation, comments, code style, or logging (not security issues)  
- ❌ Focuses on external tools: `clef`, `devp2p`, `evm` standalone tools  
  
**In-Scope Components:**  
- **Core Execution**: `core/` (block processing, state management, transaction execution)  
- **EVM Implementation**: `core/vm/` (interpreter, precompiles, gas calculation)  
- **Network Layer**: `p2p/`, `eth/`, `snap/`, `les/` (peer discovery, protocol handlers)  
- **Mining & Consensus**: `miner/`, `consensus/` (block production, validation engines)  
- **Command Line**: `cmd/geth/` (main entry point, CLI commands)  
  
**Verify**: Check that every file path cited in the report matches the Geth source structure.  
  
#### **B. Threat Model Violations**  
- ❌ Requires compromised Ethereum core developers or release managers  
- ❌ Assumes majority hash power collusion (51% attack)  
- ❌ Needs blockchain consensus compromise or network-level attacks  
- ❌ Assumes cryptographic primitives in Go standard library are broken  
- ❌ Depends on social engineering, phishing, or key theft  
- ❌ Relies on infrastructure attacks: DDoS, BGP hijacking, DNS poisoning  
  
**Trusted Roles**: Ethereum core developers, client release managers, reputable miners. Do **not** assume these actors behave maliciously.  
  
**Untrusted Actors**: Any peer on the network, transaction sender, contract deployer, or malicious actor attempting to exploit client vulnerabilities.  
  
#### **C. Known Issues / Exclusions**  
- ❌ Any finding already listed in `cmd/geth/testdata/vcheck/vulnerabilities.json`  
- ❌ Issues documented in `docs/postmortems/` (e.g., RETURNDATA corruption)  
- ❌ Performance optimizations unless they introduce security vulnerabilities  
- ❌ Gas optimization or efficiency improvements without security impact  
- ❌ Code style, documentation, or non-critical bugs  
  
#### **D. Non-Security Issues**  
- ❌ Performance improvements, memory optimizations, or micro-optimizations  
- ❌ Code style, naming conventions, or refactoring suggestions  
- ❌ Missing events, logs, error messages, or better user experience  
- ❌ Documentation improvements, README updates, or comment additions  
- ❌ "Best practices" recommendations with no concrete exploit scenario  
- ❌ Minor precision errors with negligible impact (<0.01%)  
  
#### **E. Invalid Exploit Scenarios**  
- ❌ Requires impossible inputs: negative block numbers, invalid transaction formats  
- ❌ Cannot be triggered through any realistic RPC call or transaction  
- ❌ Depends on calling internal functions not exposed through any API  
- ❌ Relies on race conditions prevented by blockchain's atomic nature  
- ❌ Needs multiple coordinated blocks with no economic incentive  
- ❌ Requires attacker to control majority of network hash power  
- ❌ Depends on block timestamp manipulation beyond consensus rules  
  
### **PHASE 2: GETH-SPECIFIC DEEP CODE VALIDATION**  
  
#### **Step 1: TRACE COMPLETE EXECUTION PATH THROUGH ETHEREUM ARCHITECTURE**  
  
**Geth Flow Patterns:**  
  
1. **Transaction Processing Flow**:  
   RPC call → `eth/api.go` → `tx_pool.go` → `state_transition.go` → EVM execution → state update  
  
2. **Block Validation Flow**:  
   New block received → `block_validator.go` → header validation → body validation → state execution → consensus check  
  
3. **EVM Execution Flow**:  
   Transaction → `vm/evm.go` → interpreter → opcode execution → precompile calls → memory/gas updates  
  
4. **Network Message Flow**:  
   Peer message → protocol handler → validation → state update → broadcast  
  
For each claim, reconstruct the entire execution path:  
  
1. **Identify Entry Point**: Which API endpoint or network message triggers the issue?  
2. **Follow Internal Calls**: Trace through all function calls in the execution path  
3. **State Before Exploit**: Document initial state (blockchain state, memory, gas)  
4. **State Transitions**: Enumerate all changes (state updates, memory modifications)  
5. **Check Protections**: Verify if existing validations prevent the exploit  
6. **Final State**: Show how the exploit results in incorrect state or crash  
  
#### **Step 2: VALIDATE EVERY CLAIM WITH CODE EVIDENCE**  
  
For **each assertion** in the report, demand:  
  
**✅ Required Evidence:**  
- Exact file path and line numbers (e.g., `core/vm/instructions.go:669-673`)  
- Direct Go code quotes showing the vulnerable logic  
- Call traces with actual parameter values demonstrating execution path  
- Calculations showing gas, state, or memory changes incorrectly  
- References to specific consensus rule violations  
  
**🚩 RED FLAGS (indicate INVALID):**  
  
1. **"Missing Validation" Claims**:  
   - ❌ Invalid unless report shows input bypasses *all* validation layers:  
     - RPC parameter validation in `eth/api.go`  
     - Transaction validation in `core/transaction_pool.go`  
     - Block validation in `core/block_validator.go`  
     - EVM stack/memory bounds checking  
   - ✅ Valid if a specific input type genuinely has no validation path  
  
2. **"Consensus Violation" Claims**:  
   - ❌ Invalid unless report demonstrates:  
     - Different nodes produce different state roots for same block  
     - Block validation bypasses consensus rules  
     - Transaction execution deviates from EVM specification  
   - ✅ Valid if consensus split can be triggered  
  
3. **"Memory Corruption" Claims**:  
   - ❌ Invalid unless report demonstrates:  
     - Buffer overflow/underflow in EVM operations  
     - Use-after-free in memory management  
     - Out-of-bounds access in arrays/slices  
   - ✅ Valid if memory corruption leads to consensus failure or crash  
  
4. **"DoS Vulnerability" Claims**:  
   - ❌ Invalid unless report demonstrates:  
     - Resource exhaustion (CPU, memory, network) through malicious input  
     - Infinite loops or unbounded operations  
     - Crash through malformed messages or transactions  
   - ✅ Valid if DoS affects majority of nodes  
  
5. **"Gas Calculation" Claims**:  
   - ❌ Invalid unless report demonstrates:  
     - Undercharging gas for operations  
     - Gas refund calculation errors  
     - Bypassing gas limits through specific operations  
   - ✅ Valid if gas miscalculation enables free computation  
  
6. **"Precompile Vulnerability" Claims**:  
   - ❌ Invalid unless report demonstrates:  
     - Incorrect results from precompiled contracts  
     - Edge cases causing crashes or incorrect outputs  
     - Gas calculation errors in precompiles  
   - ✅ Valid if precompile bugs affect consensus  
  
7. **"Network Protocol" Claims**:  
   - ❌ Invalid unless report demonstrates:  
     - Malicious peer messages causing crashes  
     - Protocol downgrade attacks  
     - Message amplification or flooding attacks  
   - ✅ Valid if network bugs enable node compromise  
  
8. **"Access Control" Claims**:  
   - ❌ Invalid unless report demonstrates:  
     - Unauthorized access to admin functions  
     - Privilege escalation through API endpoints  
     - Bypass of authentication mechanisms  
   - ✅ Valid if access control bypass enables fund theft  
  
#### **Step 3: CROSS-REFERENCE WITH VULNERABILITY DATABASE**  
  
Check against known Geth vulnerabilities in `cmd/geth/testdata/vcheck/vulnerabilities.json`:  
  
1. **Historical Patterns**: Does this match known vulnerability types?  
   - RETURNDATA corruption (GETH-2021-02)  
   - MULMOD DoS (GETH-2020-04)  
   - SELFDESTRUCT consensus flaw (GETH-2020-06)  
  
2. **Fixed Issues**: Is this already fixed in current versions?  
   - Check `introduced` and `fixed` version ranges  
   - Verify if the report affects current codebase  
  
3. **Test Coverage**: Would existing tests catch this?  
   - Check `core/block_validator_test.go`  
   - Review EVM test suites  
   - Examine integration tests  
  
**Test Case Realism Check**: PoCs must use realistic blockchain state, valid transactions, and respect consensus rules.  
  
### **PHASE 3: IMPACT & EXPLOITABILITY VALIDATION**  
  
#### **Impact Must Be CONCRETE and ALIGN WITH ETHEREUM SECURITY SCOPE**  
  
**✅ Valid CRITICAL Severity Impacts:**  
  
1. **Chain Splits (Critical)**:  
   - Different nodes compute different state roots  
   - Consensus failure causing network partition  
   - Example: "RETURNDATA corruption vulnerability caused chain split at block 13107518"  
  
2. **Remote Code Execution (Critical)**:  
   - Complete node compromise through vulnerability  
   - Arbitrary code execution in Geth process  
   - Example: "Buffer overflow in EVM allows RCE"  
  
3. **Unlimited Funds Theft (Critical)**:  
   - Ability to create ether or steal from any account  
   - Bypass of cryptographic protections  
   - Example: "Signature verification bug allows theft of any account"  
  
4. **Network-Wide DoS (Critical)**:  
   - Vulnerability crashes majority of nodes  
   - Network halts due to client bug  
   - Example: "MULMOD with zero divisor crashes all nodes"  
  
**✅ Valid HIGH Severity Impacts:**  
  
5. **Single Node Compromise (High)**:  
   - Individual node crash or compromise  
   - Transaction replay or double-spending  
   - Significant funds loss from specific accounts  
  
**✅ Valid MEDIUM Severity Impacts:**  
  
6. **Resource Exhaustion (Medium)**:  
   - DoS affecting individual nodes  
   - State inconsistency requiring manual intervention  
   - Limited funds loss or manipulation  
  
**❌ Invalid "Impacts":**  
  
- Minor performance degradation  
- Theoretical vulnerabilities without exploit  
- Market risk or price manipulation  
- "Could be problematic if..." without concrete path  
- Minor gas overpayment (<0.1% of transaction)  
  
#### **Likelihood Reality Check**  
  
Assess exploit feasibility:  
  
1. **Attacker Profile**:  
   - Any Ethereum user? ✅ Likely  
   - Contract developer? ✅ Possible  
   - Network peer? ✅ Possible  
   - Miner? ✅ Possible  
  
2. **Preconditions**:  
   - Normal network operation? ✅ High likelihood  
   - Specific block height? ✅ Attacker can wait  
   - Specific contract deployed? ✅ Attacker can deploy  
   - Specific network conditions? ✅ Possible but not required  
  
3. **Execution Complexity**:  
   - Single transaction? ✅ Simple  
   - Multiple blocks? ✅ Moderate  
   - Complex contract interaction? ✅ Attacker can create  
   - Precise timing? ⚠️ Higher complexity  
  
4. **Economic Cost**:  
   - Gas costs for attack? ✅ Attacker-controlled  
   - Potential profit vs. cost? ✅ Must be positive  
   - Initial capital required? ✅ Varies by attack  
  
### **PHASE 4: FINAL VALIDATION CHECKLIST**  
  
Before accepting any vulnerability, verify:  
  
1. **Scope Compliance**: Vulnerability affects Geth source code (not tests/docs)  
2. **Not Known Issue**: Check against `vulnerabilities.json` and postmortems  
3. **Trust Model**: Exploit doesn't require trusted role compromise  
4. **Impact Severity**: Meets Critical/High/Medium criteria  
5. **Technical Feasibility**: Exploit can be reproduced without modifications  
6. **Consensus Impact**: Clearly breaks Ethereum consensus rules  
7. **PoC Completeness**: Go test compiles and runs successfully  
  
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
Elaborate on why you've chosen a particular impact assessment.  
  
## Likelihood Explanation  
Explain how likely this is to occur and why.  
  
## Recommendation  
How can the issue be fixed or solved. Preferably, you can also add a snippet of the fixed code here.  
  
## Proof of Concept  
A proof of concept is normally required for Critical, High and Medium Submissions for reviewers under 80 reputation points. Please check the competition page for more details, otherwise your submission may be rejected by the judges.  
Very important the test function using their test must be provided in here and pls it must be able to compile and run successfully  
  
**Remember**: False positives harm credibility more than missed findings. Assume claims are invalid until overwhelming evidence proves otherwise.  
  
**Now perform STRICT validation of the claim above.**  
  
**Output ONLY:**  
- A full audit report (if genuinely valid after passing **all** checks above) following the specified format  
- `#NoVulnerability found for this question.` (if **any** check fails) very important  
- Note if u cant validate the claim or dont understand just send #NoVulnerability 
- Only show full report when u know this is actually and truly a valid vuln 
- Never show anything output apart from the valid vulnerability 

**Be ruthlessly skeptical. The bar for validity is EXTREMELY high.**  
"""
    return prompt

def question_generator(target_file: str) -> str:
    """
    Generates targeted security audit questions for a specific WBT (Whitechain) file.

    Args:
        target_file: The specific file path to focus question generation on
                    (e.g., "consensus/clique/clique.go" or "core/state_transition.go")

    Returns:
        A formatted prompt string for generating security questions
    """
    prompt = f"""  
# **Generate 150+ Targeted Security Audit Questions for WBT (Whitechain)**  
  
## **Context**  
  
The target project is **WBT (Whitechain)**, an EVM-compatible blockchain built as a go-ethereum fork implementing Proof of Authority (PoA) consensus through the Clique algorithm. Whitechain provides shorter block times and reduced fees compared to Ethereum mainnet while maintaining full compatibility with Ethereum smart contracts, tooling, and the EVM. [1](#0-0)   
  
Whitechain uses pre-authenticated validator nodes in a PoA consensus mechanism where authorized validators generate blocks in a predictable sequence. The blockchain maintains the list of validators in the blockchain registry, and the order determines block generation sequence. The system is tolerant to compromised nodes as long as 51% remain honest. [2](#0-1)   
  
WBT includes custom modifications to the standard go-ethereum implementation, including a specialized minting contract system for cross-chain asset bridging. [3](#0-2)   
  
## **Scope**  
  
**CRITICAL TARGET FILE**: Focus question generation EXCLUSIVELY on `{target_file}`  
  
Note: The questions must be generated from **`{target_file}`** only. If you cannot generate enough questions from this single file, provide as many quality questions as you can extract from the file's logic and interactions. **DO NOT return empty results** - give whatever questions you can derive from the target file.  
  
If you cannot reach 150 questions from this file alone, generate as many high-quality questions as the file's complexity allows (minimum target: 50-100 questions for large critical files, 20-50 for smaller files).  
  
**Full Context - Critical WBT Components (for reference only):**  
If a file is more than a thousand lines you can generate as many as 300+ questions as you can, but always generate as many as you can - don't give other responses.  
If there are cryptographic operations, math logic, or state transition functions, generate comprehensive questions covering all edge cases and attack vectors.  
  
### **Core WBT Components**  
  
```python  
core_components = [  
    # Consensus Layer  
    "consensus/clique/clique.go",           # PoA consensus implementation  
    "consensus/clique/snapshot.go",         # Validator snapshot management  
    "consensus/clique/api.go",              # Consensus API endpoints  
      
    # Core Blockchain Layer  
    "core/blockchain.go",                   # Main blockchain logic  
    "core/state_transition.go",             # State transition execution  
    "core/state_processor.go",              # Block state processing  
    "core/block_validator.go",              # Block validation  
    "core/genesis.go",                      # Genesis block handling  
      
    # State Management  
    "core/state/state_object.go",           # Account state management  
    "core/state/statedb.go",                # State database  
    "core/state/journal.go",                # State change journaling  
      
    # Transaction Processing  
    "core/txpool/txpool.go",                # Transaction pool  
    "core/txpool/validation.go",            # Transaction validation  
      
    # EVM Execution  
    "core/vm/evm.go",                       # EVM interpreter  
    "core/vm/instructions.go",              # EVM opcodes  
    "core/vm/gas.go",                       # Gas calculations  
    "core/vm/jump_table.go",                # Opcode jump tables  
      
    # Custom WBT Features  
    "core/mint/contract.go",                # Minting contract  
      
    # Mining/Block Production  
    "miner/worker.go",                      # Block builder  
    "miner/miner.go",                       # Mining coordinator  
      
    # Chain Configuration  
    "params/config.go",                     # Chain parameters  
    "params/protocol_params.go",            # Protocol parameters  
      
    # Networking  
    "p2p/peer.go",                          # Peer management  
    "eth/handler.go",                       # Ethereum protocol handler  
]
WBT Architecture & Critical Security Layers
1. Consensus Layer (Clique PoA)
Validator Management: Pre-authorized validators stored in blockchain registry
Block Signing: Validators sign blocks in round-robin sequence
Snapshot System: Periodic snapshots track validator set changes
Seal Verification: Block seals must be from authorized validators
Voting Mechanism: Validators can vote to add/remove other validators
51% Tolerance: System secure as long as >50% validators are honest
2. State Transition & Execution Layer
Transaction Execution: EVM processes transactions modifying world state
Gas Metering: All operations consume gas preventing DoS
State Root Validation: Merkle Patricia Trie ensures state integrity
Revert Handling: Failed transactions revert state changes atomically
Precompiled Contracts: Native contracts for cryptographic operations
Account Nonce: Sequential nonce prevents replay attacks
3. Block Validation & Consensus Rules
Header Validation: Block headers follow consensus rules
Transaction Validation: All transactions must be valid before inclusion
State Root Matching: Post-execution state must match block header
Receipt Root Matching: Transaction receipts must match declared root
Gas Limit Enforcement: Block gas usage cannot exceed limit
Timestamp Validation: Block timestamps must be sequential and valid
4. Custom WBT Features
Mint Contract: Predefined contract for cross-chain minting
Burn Event Handling: Tracks burns on external networks (Ethereum, Tron)
Mint Limits: Configurable limits on minting operations
Owner Controls: Administrative functions for mint contract contract.go:9-50
5. Transaction Pool & Mempool
Pending Transactions: Valid transactions awaiting inclusion
Transaction Ordering: Nonce-based ordering per account
Gas Price Limits: Minimum gas price enforcement
Spam Protection: Various anti-DoS measures
Replace-by-fee: Higher gas price transactions can replace pending ones
6. P2P Networking & Synchronization
Peer Discovery: Finding and connecting to network peers
Block Propagation: Broadcasting new blocks to network
State Synchronization: Syncing blockchain state from peers
Transaction Broadcasting: Distributing transactions to peers
Chain Reorganization: Handling competing chain forks
Critical Security Invariants
Consensus Security
Validator Authority: Only authorized validators can produce valid blocks
Block Signing: Each block must have valid signature from current validator
Difficulty Adjustments: Difficulty correctly reflects validator turn (INTURN vs NOTURN)
Validator Limits: Cannot have too many consecutive blocks from same validator
Snapshot Consistency: Validator snapshots must be deterministically derived
State Integrity
State Root Correctness: Block state root must match actual post-execution state
Account Nonce Ordering: Transactions must have sequential nonces per account
Balance Consistency: Account balances cannot go negative
Storage Isolation: Contracts cannot access arbitrary storage slots
Code Immutability: Contract code cannot change after deployment (unless self-destruct)
Transaction Security
Signature Validation: All transactions must have valid ECDSA signatures
Gas Limit Enforcement: Transaction gas usage cannot exceed declared limit
Nonce Uniqueness: Each nonce can only be used once per account
Value Transfers: Value transfers require sufficient balance
Gas Price Sufficiency: Transactions must meet minimum gas price
EVM Execution Security
Stack Depth Limits: Call stack cannot exceed 1024 depth
Gas Metering Accuracy: All operations consume correct gas amounts
Opcode Validity: Only valid opcodes can execute
Memory Expansion: Memory costs scale quadratically preventing abuse
Reentrancy Protection: External calls follow check-effects-interaction
Economic Security
Gas Economics: Block gas limits prevent computational DoS
Fee Market: Transaction fees create economic spam deterrent
Validator Economics: Validators have economic incentive to behave honestly
Mint Limits: Minting operations respect configured limits
In-Scope Vulnerability Categories
Focus questions on vulnerabilities that lead to these impacts:

Critical Severity
Consensus Failure
Validator signature forgery allowing unauthorized block production
Snapshot manipulation enabling attacker to become validator
Double-spending through consensus rule violations
Chain split causing network partition
Fund Loss
Unauthorized minting of tokens bypassing limits
Balance manipulation through state corruption
Theft of user funds through EVM bugs
Forced ether transfers without proper authorization
State Corruption
State root manipulation causing invalid state acceptance
Storage slot corruption through unsafe operations
Account state inconsistencies after reorg
Permanent blockchain state corruption
High Severity
DoS Attacks
Gas metering errors allowing infinite loops
Memory exhaustion through malicious transactions
Transaction pool flooding overwhelming nodes
Block validation DoS through expensive operations
Validator Attacks
Unauthorized validator addition through voting manipulation
Validator removal causing network disruption
Block withholding attacks reducing network liveness
Censorship attacks preventing valid transactions
Synchronization Issues
Peer manipulation causing invalid chain acceptance
Reorg handling errors causing chain inconsistency
State sync failures corrupting local state
Block propagation issues causing network splits
Medium Severity
Economic Manipulation
Gas price manipulation affecting transaction ordering
MEV extraction beyond normal validator profits
Transaction replacement attacks
Fee market manipulation
Protocol Violations
Header validation bypasses accepting invalid blocks
Transaction validation errors allowing invalid txs
Nonce handling errors enabling replay attacks
Timestamp manipulation attacks
Implementation Bugs
Integer overflow/underflow in critical calculations
Race conditions in concurrent operations
Memory leaks causing node crashes
Panic conditions causing node failures
Low Severity
Information Leaks
Private key leakage through side channels
Account privacy violations
Network topology exposure
Validator identity correlation
Valid Impact Categories (for WBT)
Critical
Consensus failure enabling unauthorized block production or double-spending
Direct theft of user funds from accounts
Permanent network halt requiring hard fork
Unlimited token minting breaking economic model
Complete state corruption requiring network relaunch
High
Network-wide DoS affecting all nodes
Validator set manipulation enabling attacker control
Temporary fund freezing with economic loss
Chain split causing sustained network partition
Critical service disruption (>24 hours downtime)
Medium
Single-node DoS or crash
Transaction censorship affecting specific users
Economic manipulation for profit
Protocol rule violations with limited impact
Minor state inconsistencies recoverable through reorg
Low
Information disclosure without direct harm
Performance degradation without service disruption
Non-critical protocol deviations
Edge case bugs with unlikely triggers
Out of Scope
Gas optimization inefficiencies
Code style or formatting issues
Theoretical attacks without practical exploitation
Known Ethereum vulnerabilities already fixed in upstream
Issues requiring sustained 51% validator control
External network issues (DDoS, routing attacks)
Smart contract vulnerabilities (focus on protocol layer)
Goals for Question Generation
Real Exploit Scenarios: Each question describes a plausible attack an attacker, malicious validator, or compromised node could perform
Concrete & Actionable: Reference specific functions, variables, structs, or logic flows in {target_file}
High Impact: Prioritize questions leading to Critical/High/Medium impacts
Deep Technical Detail: Focus on subtle bugs: race conditions, integer overflows, consensus edge cases, state transitions, cryptographic failures
Breadth Within Target File: Cover all major functions, edge cases, and state-changing operations in {target_file}
Respect Trust Model: Assume validators may be Byzantine (up to 49%); focus on protocol-level security
No Generic Questions: Avoid "are there access control issues?" → Instead: "In {target_file}: functionName(), if condition X occurs during validator voting, can attacker exploit Y to become unauthorized validator, leading to consensus failure?"
Question Format Template
Each question MUST follow this Python list format:

questions = [  
    "[File: {target_file}] [Function: functionName()] [Vulnerability Type] Specific question describing attack vector, preconditions, and impact with severity category?",  
      
    "[File: {target_file}] [Function: anotherFunction()] [Vulnerability Type] Another specific question with concrete exploit scenario?",  
      
    # ... continue with all generated questions  
]
Example Format (if target_file is consensus/clique/clique.go):

questions = [  
    "[File: consensus/clique/clique.go] [Function: Seal()] [Consensus bypass] Can an attacker craft a block with manipulated difficulty that passes validation but violates INTURN/NOTURN rules, allowing them to produce blocks out of sequence and potentially enable double-spending attacks? (Critical)",  
      
    "[File: consensus/clique/clique.go] [Function: verifySeal()] [Signature forgery] Does the signature verification properly validate the ecrecover result against the authorized validator list, or can an attacker exploit signature malleability to forge validator signatures and produce unauthorized blocks? (Critical)",  
      
    "[File: consensus/clique/clique.go] [Function: Prepare()] [Validator manipulation] Can malicious validator votes be crafted during block preparation that manipulate the validator set in an unauthorized way, potentially allowing attackers to gain validator status or remove honest validators? (High)",  
      
    "[File: consensus/clique/clique.go] [Function: snapshot()] [State inconsistency] Are snapshot calculations deterministic across all nodes, or can race conditions during concurrent snapshot creation lead to inconsistent validator sets across the network causing chain splits? (High)",  
]
Output Requirements
Generate security audit questions focusing EXCLUSIVELY on {target_file} that:

Target ONLY {target_file} - all questions must reference this file
Reference specific functions, methods, structs, or logic sections within {target_file}
Describe concrete attack vectors (not "could there be a bug?" but "can attacker do X by exploiting Y in {target_file}?")
Tie to impact categories (consensus failure, fund loss, DoS, validator manipulation, state corruption)
Include severity classification (Critical/High/Medium/Low) based on impact
Respect trust model (assume up to 49% Byzantine validators; focus on protocol security)
Cover diverse attack surfaces within {target_file}: validation logic, state transitions, error handling, edge cases, concurrent access, cryptographic operations, integer math
Focus on high-severity bugs: prioritize Critical > High > Medium > Low
Avoid out-of-scope issues: gas optimization, code style, already-fixed upstream bugs, smart contract issues
Use the exact Python list format shown above
Be detailed and technical: assume auditor has deep blockchain/Ethereum knowledge; use precise terminology
Consider Go-specific issues: race conditions, panic/recover, nil pointer dereference, integer overflow, slice bounds, goroutine leaks
Target Question Count:

For large critical files (>1000 lines like clique.go, blockchain.go, evm.go): Aim for 150-300 questions
For medium files (500-1000 lines like state_transition.go, worker.go): Aim for 80-150 questions
For smaller files (<500 lines like config.go, snapshot.go): Aim for 30-80 questions
Provide as many quality questions as the file's complexity allows - do NOT return empty results
Special Considerations for Go Code:

Race conditions in concurrent access (goroutines, channels, mutexes)
Panic conditions that could crash nodes
Nil pointer dereferences causing panics
Integer overflow/underflow in uint64, big.Int operations
Slice out-of-bounds access
Map concurrent access without locks
Resource leaks (goroutines, file handles, memory)
Improper error handling masking critical failures
Begin generating questions for {target_file} now.
"""
    return prompt
